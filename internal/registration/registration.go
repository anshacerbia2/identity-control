// Package registration holds desired state for protocol clients and protected resources, and is
// the only path that creates their Keycloak clients (TDD-identity-control-003).
//
// The path mirrors Principal creation. Desired state is written as a pending row before the kernel
// call, so a crash between the call and the commit leaves a row recovery can resolve, not a client
// nobody owns. The pending row is then activated with the kernel's identifier.
//
// Two profiles are built: public, a browser or native client holding no secret, and resource, a
// protected resource that is only an audience. Confidential and workload profiles authenticate
// with a registered public key (private_key_jwt, ADR-IAM-001 §5.12). Registering, rotating and
// revoking those keys (TDD-identity-control-003 §Client Key Rotation) is not built, so they are
// refused rather than created with a credential nobody tracks.
package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

const (
	ProfilePublic       = "public"
	ProfileResource     = "resource"
	ProfileConfidential = "confidential"
	ProfileWorkload     = "workload"
)

// managedScopes maps an audience class to the one managed client scope a registration attaches.
// They are identity-kernel's names (realm/client-scopes.json). The privileged class is the
// provider-scope form, the only privileged form the kernel declares. A class whose scope the realm
// does not declare is refused at registration, never registered without its claim surface.
var managedScopes = map[string]string{
	"internal":   "scnehaux-internal",
	"privileged": "scnehaux-provider",
	"external":   "scnehaux-external",
	"workload":   "scnehaux-workload",
}

var (
	// ErrInvalid is a request a validation rule refuses. Its message names the rule.
	ErrInvalid = errors.New("registration: invalid request")

	// ErrProfileNotBuilt is a confidential or workload registration, which needs client key
	// registration.
	ErrProfileNotBuilt = errors.New("registration: confidential and workload clients need client key registration, which is not built")

	// ErrScopeUndeclared is an audience class whose managed scope the realm does not declare.
	ErrScopeUndeclared = errors.New("registration: the realm declares no managed scope for this audience class")

	// ErrKeyTaken is a client_key already registered and active in this realm, or held by a
	// Keycloak client no registration describes. Adopting such a client is not built: it would
	// take over a client someone else configured.
	ErrKeyTaken = errors.New("registration: the client_key is already in use")

	ErrNotFound = errors.New("registration: no such registration")
)

// Transactor is the transaction source this package needs.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Request is one registration.
type Request struct {
	// CallerScope and IdempotencyKey make the creation retryable, as Principal creation is.
	CallerScope    string
	IdempotencyKey string

	// RegisteredBy is the accountable Principal. While the Application authority is manual,
	// accountability rests here.
	RegisteredBy id.UUID

	ClientKey      string   `json:"client_key"`
	Profile        string   `json:"profile"`
	AudienceClass  string   `json:"audience_class"`
	ApplicationRef string   `json:"application_ref"`
	LifetimeClass  string   `json:"lifetime_class"`
	Audience       []string `json:"audience"`
	RedirectURIs   []string `json:"redirect_uris"`
}

// Registration is desired state as the API reports it. It carries no secret: the two profiles
// built hold none.
type Registration struct {
	ID                   id.UUID   `json:"registration_id"`
	Realm                string    `json:"realm"`
	ClientKey            string    `json:"client_key"`
	Profile              string    `json:"profile"`
	AudienceClass        string    `json:"audience_class"`
	ApplicationAuthority string    `json:"application_authority"`
	ApplicationRef       string    `json:"application_ref"`
	RegisteredBy         id.UUID   `json:"registered_by"`
	SigningAlgorithm     string    `json:"signing_algorithm"`
	LifetimeClass        string    `json:"lifetime_class,omitempty"`
	Audience             []string  `json:"audience"`
	RedirectURIs         []string  `json:"redirect_uris"`
	AccessTokenLifespan  int       `json:"access_token_lifespan,omitempty"`
	State                string    `json:"state"`
	Version              int64     `json:"version"`
	CreatedAt            time.Time `json:"created_at"`
}

// Config bounds the service.
type Config struct {
	Realm keycloak.Realm

	// CallTimeout bounds one Admin API call.
	CallTimeout time.Duration

	// PendingRecoveryAfter is the age at which a pending registration enters recovery. It must
	// exceed CallTimeout, or recovery searches for a client the original request is still creating.
	PendingRecoveryAfter time.Duration
}

// Service registers clients.
type Service struct {
	tx     Transactor
	kernel keycloak.ClientRegistry
	cfg    Config
	logger *slog.Logger
	newID  func() (id.UUID, error)
}

// New constructs the service.
func New(tx Transactor, kernel keycloak.ClientRegistry, cfg Config, logger *slog.Logger) (*Service, error) {
	switch {
	case tx == nil:
		return nil, errors.New("registration: a transaction source is required")
	case kernel == nil:
		return nil, errors.New("registration: a client registry is required")
	case logger == nil:
		return nil, errors.New("registration: a logger is required")
	case cfg.Realm == "":
		return nil, errors.New("registration: a realm is required")
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 10 * time.Second
	}
	if cfg.PendingRecoveryAfter <= 0 {
		cfg.PendingRecoveryAfter = 60 * time.Second
	}
	if cfg.PendingRecoveryAfter <= cfg.CallTimeout {
		return nil, fmt.Errorf("registration: PendingRecoveryAfter (%s) must exceed CallTimeout (%s)",
			cfg.PendingRecoveryAfter, cfg.CallTimeout)
	}
	return &Service{tx: tx, kernel: kernel, cfg: cfg, logger: logger, newID: id.NewV7}, nil
}

// LifespanSQL is the derived access token lifespan, in seconds, of a client in realm with the given
// audience, as a SQL expression over the two expressions given: the access token lifetime of the
// shortest lifetime class among the audience's active resource registrations, from STD-IAM-002
// §3.3. An entry no active resource registration names takes L0, as does an empty audience: the
// shortest class is the safe reading of what nobody declared. The reconciler compares against the
// same expression, so the table lives in one place.
func LifespanSQL(realm, audience string) string {
	return `coalesce((
    SELECT min(coalesce(CASE resource.lifetime_class
                            WHEN 'L0' THEN 240
                            WHEN 'L1' THEN 540
                            WHEN 'L2' THEN 900
                            WHEN 'L3' THEN 540
                        END, 240))
    FROM unnest(coalesce(` + audience + `, '{}'::text[])) AS aud(client_key)
    LEFT JOIN identity.client_registration resource
           ON resource.realm = ` + realm + ` AND resource.client_key = aud.client_key
          AND resource.profile = 'resource' AND resource.state <> 'retired'
), 240)`
}

var clientKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// validate applies the rules that need nothing but the request (TDD-identity-control-003
// §Validation).
func validate(req Request) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	switch {
	case req.RegisteredBy.IsNil():
		return invalid("the registering Principal is required")
	case !clientKeyPattern.MatchString(req.ClientKey):
		return invalid("client_key must be 1 to 128 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
	case strings.TrimSpace(req.ApplicationRef) == "":
		return invalid("an Application reference is required: every client traces to an Application (PAD-PLT-001 §7.3)")
	}
	switch req.Profile {
	case ProfilePublic, ProfileResource:
	case ProfileConfidential, ProfileWorkload:
		return ErrProfileNotBuilt
	default:
		return invalid("profile must be public or resource")
	}
	if _, ok := managedScopes[req.AudienceClass]; !ok {
		return invalid("audience_class must be internal, privileged, workload or external")
	}

	if req.Profile == ProfileResource {
		switch {
		case !slices.Contains([]string{"L0", "L1", "L2", "L3"}, req.LifetimeClass):
			return invalid("a resource carries exactly one lifetime class, L0 to L3 (STD-IAM-002 §3.3)")
		case len(req.RedirectURIs) > 0, len(req.Audience) > 0:
			return invalid("a resource has no redirect URIs and no audience")
		}
		return nil
	}

	switch {
	case req.LifetimeClass != "":
		return invalid("a client's lifetime is derived from its audience, not declared")
	case len(req.RedirectURIs) == 0:
		return invalid("a public client needs at least one redirect URI")
	}
	for _, uri := range req.RedirectURIs {
		if err := validateRedirect(uri); err != nil {
			return invalid("%v", err)
		}
	}
	for _, resource := range req.Audience {
		if !clientKeyPattern.MatchString(resource) {
			return invalid("an audience entry is not a client_key")
		}
	}
	return nil
}

// validateRedirect is exact-match hygiene (STD-IAM-001 §3.2). A wildcard is an open redirect with
// extra steps: it delegates to whoever controls any matching host.
func validateRedirect(raw string) error {
	if strings.Contains(raw, "*") {
		return errors.New("a redirect URI must not contain a wildcard")
	}
	uri, err := url.Parse(raw)
	if err != nil || uri.Host == "" || uri.Opaque != "" {
		return errors.New("a redirect URI must be absolute, with a host")
	}
	switch {
	case uri.User != nil:
		return errors.New("a redirect URI must not carry credentials")
	case uri.Fragment != "" || strings.Contains(raw, "#"):
		return errors.New("a redirect URI must not carry a fragment")
	}
	for _, segment := range strings.Split(uri.EscapedPath(), "/") {
		if segment == ".." || segment == "." || strings.EqualFold(segment, "%2e%2e") {
			return errors.New("a redirect URI must not traverse its path")
		}
	}
	local := slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, uri.Hostname())
	switch {
	case uri.Scheme == "https":
	case uri.Scheme == "http" && local:
	default:
		return errors.New("a redirect URI must be https, or http on a loopback host for local development")
	}
	return nil
}

func digest(req Request) string {
	body, _ := json.Marshal(struct {
		Request
		RegisteredBy string
	}{req, req.RegisteredBy.String()})
	return idempotency.Digest(body)
}

func call[T any](ctx context.Context, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(callCtx)
}

// Register validates the request, records it pending, creates the client, attaches its managed
// scope, and activates the registration.
func (s *Service) Register(ctx context.Context, req Request) (Registration, error) {
	if strings.TrimSpace(req.CallerScope) == "" || strings.TrimSpace(req.IdempotencyKey) == "" {
		return Registration{}, fmt.Errorf("%w: a caller and an Idempotency-Key are required", ErrInvalid)
	}
	if err := validate(req); err != nil {
		return Registration{}, err
	}

	// Kernel reads before anything is written: a class whose scope the realm lacks, and a
	// client_key a Keycloak client already holds, are refused with nothing recorded.
	scopeID, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (string, error) {
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, managedScopes[req.AudienceClass])
	})
	if errors.Is(err, keycloak.ErrNotFound) {
		return Registration{}, fmt.Errorf("%w: %s", ErrScopeUndeclared, managedScopes[req.AudienceClass])
	}
	if err != nil {
		return Registration{}, err
	}

	requestDigest := digest(req)
	var (
		registration Registration
		replay       bool
	)
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		claim, err := idempotency.Claim(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest)
		if err != nil {
			return err
		}
		if claim.State == idempotency.StateReplay {
			replay = true
			if claim.Status != 201 {
				return ErrKeyTaken
			}
			return json.Unmarshal(claim.Body, &registration)
		}
		registration, err = s.insertPending(ctx, tx, req)
		return err
	})
	if err != nil || replay {
		return registration, err
	}

	existing, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) ([]keycloak.Client, error) {
		return s.kernel.FindClients(ctx, s.cfg.Realm, req.ClientKey)
	})
	if err == nil && len(existing) > 0 {
		err = keycloak.ErrConflict
	}
	var client keycloak.ClientUUID
	if err == nil {
		client, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.ClientUUID, error) {
			return s.kernel.CreateClient(ctx, s.cfg.Realm, spec(registration))
		})
	}
	if errors.Is(err, keycloak.ErrConflict) {
		// A client no registration describes holds the key. The pending row is retired, which
		// releases the key and keeps the record; the key's response is stored, so a retry is told
		// the same thing instead of waiting on a request that will never finish.
		if retireErr := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			if _, err := tx.Exec(ctx, retirePendingStatement, registration.ID.String()); err != nil {
				return err
			}
			return idempotency.Complete(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest, 409,
				json.RawMessage(`{"error":"client_key in use by an unregistered Keycloak client"}`))
		}); retireErr != nil {
			return Registration{}, fmt.Errorf("registration: retire the refused registration: %w", retireErr)
		}
		return Registration{}, ErrKeyTaken
	}
	if err != nil {
		// Left pending on purpose, as Principal creation leaves its mapping: on ErrAmbiguous the
		// client may exist, and recovery adopts it by client_key rather than creating a second.
		s.logger.WarnContext(ctx, "client creation did not confirm; registration left pending for recovery",
			slog.String("client_key", req.ClientKey), slog.String("error", err.Error()))
		return Registration{}, fmt.Errorf("registration: create client: %w", err)
	}

	if err := s.finish(ctx, registration, client, scopeID, func(ctx context.Context, tx db.Tx, active Registration) error {
		body, err := json.Marshal(active)
		if err != nil {
			return err
		}
		registration = active
		return idempotency.Complete(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest, 201, body)
	}); err != nil {
		return Registration{}, err
	}
	return registration, nil
}

// finish attaches the managed scope and activates the registration, running then in the
// activating transaction.
func (s *Service) finish(ctx context.Context, registration Registration, client keycloak.ClientUUID, scopeID string,
	then func(context.Context, db.Tx, Registration) error) error {
	if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.kernel.AddDefaultClientScope(ctx, s.cfg.Realm, client, scopeID)
	}); err != nil {
		return fmt.Errorf("registration: attach %s: %w", managedScopes[registration.AudienceClass], err)
	}
	return s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, activateStatement, registration.ID.String(), string(client))
		if err != nil {
			return fmt.Errorf("registration: activate: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("registration: %s is no longer pending", registration.ID)
		}
		active, err := s.read(ctx, tx, registration.ID)
		if err != nil {
			return err
		}
		if then != nil {
			return then(ctx, tx, active)
		}
		return nil
	})
}

// spec is the Keycloak client desired state describes.
func spec(r Registration) keycloak.ClientSpec {
	if r.Profile == ProfileResource {
		return keycloak.ClientSpec{ClientID: r.ClientKey, Resource: true}
	}
	return keycloak.ClientSpec{ClientID: r.ClientKey, Public: true, RedirectURIs: r.RedirectURIs,
		AccessTokenLifespan: r.AccessTokenLifespan, Audience: r.Audience}
}

// RecoverPending resolves registrations whose creation was interrupted: a client that exists
// under the key is adopted, a missing one is created. It returns how many it resolved, and one
// failure does not stop the others.
func (s *Service) RecoverPending(ctx context.Context) (int, error) {
	var pending []Registration
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, pendingStatement, string(s.cfg.Realm), time.Now().Add(-s.cfg.PendingRecoveryAfter))
		if err != nil {
			return err
		}
		var ids []id.UUID
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			parsed, err := id.Parse(raw)
			if err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, parsed)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, registrationID := range ids {
			registration, err := s.read(ctx, tx, registrationID)
			if err != nil {
				return err
			}
			pending = append(pending, registration)
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("registration: read pending registrations: %w", err)
	}

	resolved := 0
	for _, registration := range pending {
		if err := s.recoverOne(ctx, registration); err != nil {
			s.logger.ErrorContext(ctx, "recovery of one registration failed; continuing",
				slog.String("client_key", registration.ClientKey), slog.String("error", err.Error()))
			continue
		}
		resolved++
	}
	return resolved, nil
}

func (s *Service) recoverOne(ctx context.Context, registration Registration) error {
	scopeID, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (string, error) {
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, managedScopes[registration.AudienceClass])
	})
	if err != nil {
		return err
	}
	found, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) ([]keycloak.Client, error) {
		return s.kernel.FindClients(ctx, s.cfg.Realm, registration.ClientKey)
	})
	if err != nil {
		return err
	}
	var client keycloak.ClientUUID
	switch len(found) {
	case 0:
		if client, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.ClientUUID, error) {
			return s.kernel.CreateClient(ctx, s.cfg.Realm, spec(registration))
		}); err != nil {
			return err
		}
	case 1:
		client = found[0].ID
	default:
		return fmt.Errorf("registration: %d clients carry client_key %s", len(found), registration.ClientKey)
	}
	return s.finish(ctx, registration, client, scopeID, nil)
}

// Recreate builds an active registration's client again from desired state, for a client deleted
// in the console. It records the new client's identifier and returns it.
func (s *Service) Recreate(ctx context.Context, registrationID id.UUID) (keycloak.ClientUUID, error) {
	var registration Registration
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		registration, err = s.read(ctx, tx, registrationID)
		return err
	}); err != nil {
		return "", err
	}
	if registration.State != "active" {
		return "", fmt.Errorf("registration: %s is %s, not active", registrationID, registration.State)
	}
	scopeID, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (string, error) {
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, managedScopes[registration.AudienceClass])
	})
	if err != nil {
		return "", err
	}
	client, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.ClientUUID, error) {
		return s.kernel.CreateClient(ctx, s.cfg.Realm, spec(registration))
	})
	if err != nil {
		return "", fmt.Errorf("registration: recreate %s: %w", registration.ClientKey, err)
	}
	if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.kernel.AddDefaultClientScope(ctx, s.cfg.Realm, client, scopeID)
	}); err != nil {
		return "", err
	}
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, relinkStatement, registrationID.String(), string(client))
		return err
	}); err != nil {
		return "", fmt.Errorf("registration: record the recreated client: %w", err)
	}
	return client, nil
}

// The page size a list returns when none is asked for, and the most it returns.
const (
	DefaultListLimit = 50
	MaxListLimit     = 100
)

// ListQuery selects one page of the realm's registrations.
type ListQuery struct {
	// After is the last registration_id of the previous page; the nil identifier starts at the
	// first registration.
	After id.UUID
	// Limit is the page size, 1 to MaxListLimit; zero takes DefaultListLimit.
	Limit int
	// State narrows the list to one lifecycle state; empty is every state, retired included.
	State string
}

// Page is one page of registrations, in creation order. Next is the After of the following page,
// and nil on the last.
type Page struct {
	Registrations []Registration `json:"registrations"`
	Next          *string        `json:"next"`
}

var listStates = map[string]bool{"": true, "pending": true, "active": true, "suspended": true, "retired": true}

// List reads one page of the configured realm's registrations (TDD-identity-control-003 §API /
// Interface). It never carries a secret: none is stored.
func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	switch {
	case query.Limit == 0:
		query.Limit = DefaultListLimit
	case query.Limit < 0 || query.Limit > MaxListLimit:
		return Page{}, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, MaxListLimit)
	}
	if !listStates[query.State] {
		return Page{}, fmt.Errorf("%w: state must be pending, active, suspended or retired", ErrInvalid)
	}
	var page Page
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		page, err = s.list(ctx, tx, query)
		return err
	})
	return page, err
}

// Get reads one registration.
func (s *Service) Get(ctx context.Context, registrationID id.UUID) (Registration, error) {
	var registration Registration
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		registration, err = s.read(ctx, tx, registrationID)
		return err
	})
	return registration, err
}
