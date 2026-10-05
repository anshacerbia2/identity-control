// Package registration holds desired state for protocol clients and protected resources, and is
// the only path that creates their Keycloak clients (TDD-identity-control-003).
//
// The path mirrors Principal creation. Desired state is written as a pending row before the kernel
// call, so a crash between the call and the commit leaves a row recovery can resolve, not a client
// nobody owns. The pending row is then activated with the kernel's identifier.
//
// Four profiles are built: public, a browser or native client holding no secret; confidential, a
// browser-facing backend; workload, a service acting as itself; and resource, a protected resource
// that is only an audience. Confidential and workload clients authenticate with a registered public
// key (private_key_jwt, ADR-IAM-001 §5.12): the client keeps its private key, and this service
// records and registers the public half only (keys.go).
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
// They are identity-kernel's names (realm/client-scopes.json). The privileged class's scope is its
// form's (privilegedScopes). A class whose scope the realm does not declare is refused at
// registration, never registered without its claim surface.
var managedScopes = map[string]string{
	"internal":   "scnehaux-internal",
	"privileged": "scnehaux-provider",
	"external":   "scnehaux-external",
	"workload":   "scnehaux-workload",
}

// The privileged forms a registration names (STD-IAM-002 §3.1.1, TDD-identity-control-003 1.29.0).
// provider-scope is also the claim surface of the resource-scoped form, which carries the same claims.
const (
	FormProviderScope = "provider-scope"
	FormTenantScoped  = "tenant-scoped"
)

// privilegedScopes maps a privileged form to its managed scope.
var privilegedScopes = map[string]string{
	FormProviderScope: "scnehaux-provider",
	FormTenantScoped:  "scnehaux-privileged",
}

// ManagedScope is the one managed client scope a registration of the class and form attaches.
func ManagedScope(audienceClass, privilegedForm string) string {
	if audienceClass == "privileged" {
		return privilegedScopes[privilegedForm]
	}
	return managedScopes[audienceClass]
}

// normalized gives a privileged request that names no form the provider-scope form, which every
// privileged registration was before forms were named.
func (r Request) normalized() Request {
	if r.AudienceClass == "privileged" && r.PrivilegedForm == "" {
		r.PrivilegedForm = FormProviderScope
	}
	return r
}

var (
	// ErrInvalid is a request a validation rule refuses. Its message names the rule.
	ErrInvalid = errors.New("registration: invalid request")

	// ErrScopeUndeclared is an audience class whose managed scope the realm does not declare.
	ErrScopeUndeclared = errors.New("registration: the realm declares no managed scope for this audience class")

	// ErrKeyTaken is a client_key already registered and active in this realm, or held by a
	// Keycloak client no registration describes. Adopting such a client is not built: it would
	// take over a client someone else configured.
	ErrKeyTaken = errors.New("registration: the client_key is already in use")

	ErrNotFound = errors.New("registration: no such registration")

	// ErrWorkloadRecreate is an operator's recreate of a workload's client. The workload's identity
	// lives on its client's service-account user, so the client is rebuilt through the workload.
	ErrWorkloadRecreate = errors.New("registration: a workload's client is rebuilt through its workload, not recreated alone")
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

	// Developer is a caller registering on application developer standing rather than provider
	// authority (TDD-identity-control-003 §Application Developers): what it may register is bounded,
	// and it becomes the registration's first owner.
	Developer bool

	// reserved runs in the transaction that reserves the registration, after it is recorded
	// pending: an approved request grants its owners and records its approval there, so the two
	// commit together (TDD-identity-control-003 §Registration Requests).
	reserved func(ctx context.Context, tx db.Tx, registration Registration) error

	ClientKey     string `json:"client_key"`
	Profile       string `json:"profile"`
	AudienceClass string `json:"audience_class"`
	// PrivilegedForm is a privileged registration's form, provider-scope or tenant-scoped, and empty
	// for every other class. A privileged request naming none is provider-scope.
	PrivilegedForm string   `json:"privileged_form,omitempty"`
	ApplicationRef string   `json:"application_ref"`
	LifetimeClass  string   `json:"lifetime_class"`
	Audience       []string `json:"audience"`
	RedirectURIs   []string `json:"redirect_uris"`

	// PublicKey is a confidential or workload client's first public key, as a JWK. The client
	// generated the pair and keeps the private half.
	PublicKey json.RawMessage `json:"public_key,omitempty"`
}

// Registration is desired state as the API reports it. It carries no secret, because none exists:
// a confidential or workload client's keys are listed on their own route, and they are public.
type Registration struct {
	ID                   id.UUID   `json:"registration_id"`
	Realm                string    `json:"realm"`
	ClientKey            string    `json:"client_key"`
	Profile              string    `json:"profile"`
	AudienceClass        string    `json:"audience_class"`
	PrivilegedForm       string    `json:"privileged_form,omitempty"`
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

	// Production is IDENTITY_ENVIRONMENT=production: a registration keeps at least
	// MinProductionOwners owners (ADR-IAM-003 §5.1).
	Production bool

	// KeyLifetime is how long a registered client key is valid before it is removed
	// (IDENTITY_CLIENT_KEY_LIFETIME).
	KeyLifetime time.Duration

	// RotationOverlap is how long the previous key keeps authenticating after the next is
	// registered (IDENTITY_CLIENT_KEY_ROTATION_OVERLAP). It is shorter than KeyLifetime.
	RotationOverlap time.Duration
}

// The defaults TDD-identity-control-003 §Configuration names.
const (
	DefaultKeyLifetime     = 90 * 24 * time.Hour
	DefaultRotationOverlap = 7 * 24 * time.Hour
)

// Service registers clients.
type Service struct {
	tx     Transactor
	kernel keycloak.ClientRegistry
	cfg    Config
	logger *slog.Logger
	newID  func() (id.UUID, error)
	now    func() time.Time
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
	if cfg.KeyLifetime <= 0 {
		cfg.KeyLifetime = DefaultKeyLifetime
	}
	if cfg.RotationOverlap <= 0 {
		cfg.RotationOverlap = DefaultRotationOverlap
	}
	if cfg.RotationOverlap >= cfg.KeyLifetime {
		return nil, fmt.Errorf("registration: RotationOverlap (%s) must be shorter than KeyLifetime (%s)",
			cfg.RotationOverlap, cfg.KeyLifetime)
	}
	return &Service{tx: tx, kernel: kernel, cfg: cfg, logger: logger, newID: id.NewV7,
		now: func() time.Time { return time.Now().UTC() }}, nil
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
	case ProfilePublic, ProfileResource, ProfileConfidential, ProfileWorkload:
	default:
		return invalid("profile must be public, confidential, workload or resource")
	}
	if _, ok := managedScopes[req.AudienceClass]; !ok {
		return invalid("audience_class must be internal, privileged, workload or external")
	}
	switch {
	case req.AudienceClass != "privileged" && req.PrivilegedForm != "":
		return invalid("privileged_form is named only for the privileged audience class")
	case req.AudienceClass == "privileged" && privilegedScopes[req.PrivilegedForm] == "":
		return invalid("privileged_form must be provider-scope or tenant-scoped")
	}
	switch {
	case req.Profile == ProfileWorkload && req.AudienceClass != "workload":
		return invalid("a workload registers the workload audience class")
	case !keyed(req.Profile) && submitted(req.PublicKey):
		return invalid("a public client or a resource holds no key")
	}
	for _, resource := range req.Audience {
		if !clientKeyPattern.MatchString(resource) {
			return invalid("an audience entry is not a client_key")
		}
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
	case req.Profile == ProfileWorkload && len(req.RedirectURIs) > 0:
		return invalid("a workload logs nobody in, so it has no redirect URIs")
	case req.Profile != ProfileWorkload && len(req.RedirectURIs) == 0:
		return invalid("a public or confidential client needs at least one redirect URI")
	}
	for _, uri := range req.RedirectURIs {
		if err := validateRedirect(uri); err != nil {
			return invalid("%v", err)
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
	if req.Developer {
		if err := s.developerScope(req); err != nil {
			return Registration{}, err
		}
	}
	req = req.normalized()
	prepared, err := s.Prepare(ctx, req)
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
		registration, err = s.Reserve(ctx, tx, prepared)
		if err != nil {
			return err
		}
		if req.reserved != nil {
			if err := req.reserved(ctx, tx, registration); err != nil {
				return err
			}
		}
		if !req.Developer {
			return nil
		}
		return s.claimAsDeveloper(ctx, tx, req, registration.ID)
	})
	if err != nil || replay {
		return registration, err
	}

	// The key's response is stored whichever way the realization ends, so a retry is told the same
	// thing instead of waiting on a request that will never finish.
	active, _, err := s.Realize(ctx, prepared, registration, Outcome{
		Refused: func(ctx context.Context, tx db.Tx) error {
			return idempotency.Complete(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest, 409,
				json.RawMessage(`{"error":"client_key in use by an unregistered Keycloak client"}`))
		},
		Active: func(ctx context.Context, tx db.Tx, active Registration) error {
			body, err := json.Marshal(active)
			if err != nil {
				return err
			}
			return idempotency.Complete(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest, 201, body)
		},
	})
	return active, err
}

// Prepared is a registration request that passed every rule needing nothing but the request and a
// kernel read. Reserve records it, and Realize creates its client.
type Prepared struct {
	req     Request
	key     *PublicKey
	scopeID string
}

// Prepare validates a registration, parses its public key, and resolves its managed scope. Kernel
// reads happen here, before anything is written: a class whose scope the realm lacks is refused with
// nothing recorded.
func (s *Service) Prepare(ctx context.Context, req Request) (Prepared, error) {
	req = req.normalized()
	if err := validate(req); err != nil {
		return Prepared{}, err
	}
	prepared := Prepared{req: req}
	if keyed(req.Profile) {
		parsed, err := parsePublicKey(req.PublicKey)
		if err != nil {
			return Prepared{}, err
		}
		prepared.key = &parsed
	}
	scopeID, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (string, error) {
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, ManagedScope(req.AudienceClass, req.PrivilegedForm))
	})
	if errors.Is(err, keycloak.ErrNotFound) {
		return Prepared{}, fmt.Errorf("%w: %s", ErrScopeUndeclared, ManagedScope(req.AudienceClass, req.PrivilegedForm))
	}
	if err != nil {
		return Prepared{}, err
	}
	prepared.scopeID = scopeID
	return prepared, nil
}

// Reserve records a prepared registration pending, with its first key, inside the caller's
// transaction. A workload reserves its registration in the same transaction as its own intent, so
// recovery never finds one without the other (TDD-identity-control-004 §Creation).
func (s *Service) Reserve(ctx context.Context, tx db.Tx, prepared Prepared) (Registration, error) {
	return s.insertPending(ctx, tx, prepared.req, prepared.key)
}

// Outcome is what the caller of Realize records in the transaction that closes a realization:
// Refused in the one that retires a registration an unregistered client's key refused, and Active
// in the one that activates it. Either may be nil.
type Outcome struct {
	Refused func(ctx context.Context, tx db.Tx) error
	Active  func(ctx context.Context, tx db.Tx, active Registration) error
}

// Realize creates a reserved registration's client, scopes it, and activates the registration,
// returning it with its client.
//
// A client_key an unregistered Keycloak client holds is refused, never adopted: the pending row is
// retired, which keeps the record and releases the key, its keys are revoked, and ErrKeyTaken is
// returned. Any other failure leaves the registration pending on purpose, as Principal creation
// leaves its mapping: on ErrAmbiguous the client may exist, and recovery adopts it by client_key
// rather than creating a second.
func (s *Service) Realize(ctx context.Context, prepared Prepared, registration Registration, outcome Outcome) (Registration, keycloak.ClientUUID, error) {
	existing, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) ([]keycloak.Client, error) {
		return s.kernel.FindClients(ctx, s.cfg.Realm, registration.ClientKey)
	})
	if err == nil && len(existing) > 0 {
		err = keycloak.ErrConflict
	}
	var client keycloak.ClientUUID
	if err == nil {
		var keys []keycloak.JWK
		if prepared.key != nil {
			keys = []keycloak.JWK{prepared.key.JWK}
		}
		client, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.ClientUUID, error) {
			return s.kernel.CreateClient(ctx, s.cfg.Realm, spec(registration, keys))
		})
	}
	if errors.Is(err, keycloak.ErrConflict) {
		if retireErr := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			if _, err := tx.Exec(ctx, retirePendingStatement, registration.ID.String()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, revokeRefusedKeysStatement, registration.ID.String(), s.now()); err != nil {
				return err
			}
			if outcome.Refused != nil {
				return outcome.Refused(ctx, tx)
			}
			return nil
		}); retireErr != nil {
			return Registration{}, "", fmt.Errorf("registration: retire the refused registration: %w", retireErr)
		}
		return Registration{}, "", ErrKeyTaken
	}
	if err != nil {
		s.logger.WarnContext(ctx, "client creation did not confirm; registration left pending for recovery",
			slog.String("client_key", registration.ClientKey), slog.String("error", err.Error()))
		return Registration{}, "", fmt.Errorf("registration: create client: %w", err)
	}

	var active Registration
	if err := s.finish(ctx, registration, client, prepared.scopeID, func(ctx context.Context, tx db.Tx, activated Registration) error {
		active = activated
		if outcome.Active != nil {
			return outcome.Active(ctx, tx, activated)
		}
		return nil
	}); err != nil {
		return Registration{}, "", err
	}
	// An approved request was decided by a second provider; anything else in production a provider
	// registered alone, which is reported each time (ADR-IAM-003 §5.3).
	if prepared.req.reserved == nil && !prepared.req.Developer {
		path := "registration"
		if active.Profile == ProfileWorkload {
			path = "workload"
		}
		s.reportDirect(ctx, path, active)
	}
	return active, client, nil
}

// reportDirect reports a production registration a provider created alone (ADR-IAM-003 §5.3,
// §5.7): a log line a review or an alert reads, until provider authority itself takes a second
// person's approval to activate.
func (s *Service) reportDirect(ctx context.Context, path string, registration Registration) {
	if !s.cfg.Production {
		return
	}
	s.logger.WarnContext(ctx, "a provider registered a production client directly, without a second person's approval",
		slog.String("path", path), slog.String("client_key", registration.ClientKey),
		slog.String("registration_id", registration.ID.String()),
		slog.String("registered_by", registration.RegisteredBy.String()))
}

// scope gives the client its scope sets (tokenprofile.go): exactly its default and optional scopes,
// the managed audience scope among them. A resource is issued no token, so it only holds its managed
// scope. Idempotent, so recovery and recreation run it again safely.
func (s *Service) scope(ctx context.Context, registration Registration, client keycloak.ClientUUID, scopeID string) error {
	desired, governed := DesiredScopes(registration.Profile, registration.AudienceClass, registration.PrivilegedForm)
	if !governed {
		if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
			return struct{}{}, s.kernel.AddDefaultClientScope(ctx, s.cfg.Realm, client, scopeID)
		}); err != nil {
			return fmt.Errorf("registration: attach %s: %w",
				ManagedScope(registration.AudienceClass, registration.PrivilegedForm), err)
		}
		return nil
	}
	return ConvergeScopes(ctx, s.kernel, s.cfg.Realm, client, desired, s.cfg.CallTimeout)
}

// finish scopes the client and activates the registration, running then in the activating
// transaction.
func (s *Service) finish(ctx context.Context, registration Registration, client keycloak.ClientUUID, scopeID string,
	then func(context.Context, db.Tx, Registration) error) error {
	if err := s.scope(ctx, registration, client, scopeID); err != nil {
		return err
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

// spec is the Keycloak client desired state describes, holding the given keys when its profile
// authenticates with one.
func spec(r Registration, keys []keycloak.JWK) keycloak.ClientSpec {
	if r.Profile == ProfileResource {
		return keycloak.ClientSpec{ClientID: r.ClientKey, Resource: true}
	}
	out := keycloak.ClientSpec{ClientID: r.ClientKey, RedirectURIs: r.RedirectURIs,
		AccessTokenLifespan: r.AccessTokenLifespan, Audience: r.Audience}
	switch r.Profile {
	case ProfilePublic:
		out.Public = true
	case ProfileConfidential:
		out.Confidential, out.Keys = true, keys
	case ProfileWorkload:
		out.Workload, out.Keys = true, keys
	}
	return out
}

// desired reads a registration and the keys its client holds, for building that client again.
func (s *Service) desired(ctx context.Context, registrationID id.UUID) (Registration, []keycloak.JWK, error) {
	var (
		registration Registration
		keys         []keycloak.JWK
	)
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		if registration, err = s.read(ctx, tx, registrationID); err != nil {
			return err
		}
		if keyed(registration.Profile) {
			keys, err = liveKeys(ctx, tx, registrationID)
		}
		return err
	})
	return registration, keys, err
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
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, ManagedScope(registration.AudienceClass, registration.PrivilegedForm))
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
		_, keys, err := s.desired(ctx, registration.ID)
		if err != nil {
			return err
		}
		if client, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.ClientUUID, error) {
			return s.kernel.CreateClient(ctx, s.cfg.Realm, spec(registration, keys))
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
//
// A confidential or workload client is recreated holding its active and retiring keys, so the key
// pairs that authenticated it before the deletion authenticate it again, and no other.
func (s *Service) Recreate(ctx context.Context, registrationID id.UUID) (keycloak.ClientUUID, error) {
	registration, keys, err := s.desired(ctx, registrationID)
	if err != nil {
		return "", err
	}
	if registration.State != "active" {
		return "", fmt.Errorf("registration: %s is %s, not active", registrationID, registration.State)
	}
	// A workload's client carries its Principal on its service-account user, which a new client
	// does not have: a recreated client would authenticate as a workload whose token names no
	// principal_id. Its client is rebuilt through the workload, which is not built yet.
	if registration.Profile == ProfileWorkload {
		return "", ErrWorkloadRecreate
	}
	scopeID, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (string, error) {
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, ManagedScope(registration.AudienceClass, registration.PrivilegedForm))
	})
	if err != nil {
		return "", err
	}
	client, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.ClientUUID, error) {
		return s.kernel.CreateClient(ctx, s.cfg.Realm, spec(registration, keys))
	})
	if err != nil {
		return "", fmt.Errorf("registration: recreate %s: %w", registration.ClientKey, err)
	}
	if err := s.scope(ctx, registration, client, scopeID); err != nil {
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
