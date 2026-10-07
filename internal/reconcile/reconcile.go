// Package reconcile compares registered desired state against the live Keycloak clients, and
// repairs or blocks what drifted (TDD-identity-control-003 §Drift Reconciliation).
//
// An absent client is held for an operator, not recreated. Three field classes are compared: a
// client's access token lifespan, which is repaired, and its redirect URIs and, for a confidential
// or workload client, its keys and authenticator, which are blocked. Each divergence is
// attributed through Keycloak's admin events before anything is done about it. A change an
// unexpired drift exception covers is left in place, and a change nobody can be named for is
// never repaired automatically. An unreachable Keycloak produces an 'unresolved' run that
// changes nothing. A client no registration describes is recorded 'unmanaged', and disabled when
// the setting says to; the kernel's built-in clients and this service's own Admin API clients are
// exempt.
//
// What this package does not do yet, and why:
//
//   - Signing algorithm and profile are not compared yet.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	registrations "github.com/anshacerbia2/identity-control/internal/registration"
)

// FieldClass names what diverged. Each has one policy.
type FieldClass string

const (
	TokenLifespan FieldClass = "token_lifespan"
	RedirectURIs  FieldClass = "redirect_uris"

	// ClientKeys is a confidential or workload client's credential: its authenticator, its held
	// JWKS, and the keys in it.
	ClientKeys FieldClass = "client_keys"

	// Suspension is a suspended registration's client: disabled, with the not-before that ends the
	// refresh tokens it was issued (ADR-IAM-001 §5.13).
	Suspension FieldClass = "suspension"

	// AudienceScope is a client's default and optional client scopes, as the closed sets of its
	// profile (TDD-identity-control-003 §Profiles).
	AudienceScope FieldClass = "audience_scope"

	// TokenFormat is a client's at+jwt header attribute and its client_id mapper (STD-IAM-002 §3.2).
	TokenFormat FieldClass = "token_format"

	// Audience is a client's audience mappers: one per resource its registration declares, and no
	// other (TDD-identity-control-003 1.33.0).
	Audience FieldClass = "audience"
)

// FindingClass is what the sweep did about a divergence.
type FindingClass string

const (
	Repaired     FindingClass = "repaired"
	Blocked      FindingClass = "blocked"
	Sanctioned   FindingClass = "sanctioned"
	Unattributed FindingClass = "unattributed"
	Missing      FindingClass = "missing"
	Recreated    FindingClass = "recreated"
	Unmanaged    FindingClass = "unmanaged"
)

// BuiltInClients are the clients Keycloak creates in every realm. They are never unmanaged:
// disabling realm-management or admin-cli would lock administration out of the realm, a worse
// incident than any drift (TDD-identity-control-003 §Drift Reconciliation).
var BuiltInClients = []string{"account", "account-console", "admin-cli", "broker", "realm-management",
	"security-admin-console"}

// Outcome is how a run ended.
type Outcome string

const (
	Converged  Outcome = "converged"
	Drift      Outcome = "drift"
	Unresolved Outcome = "unresolved"
)

var (
	// ErrSweepInProgress means another replica's sweep is running. It is not a failure: one sweep
	// at a time is the point.
	ErrSweepInProgress = errors.New("reconcile: a registration sweep is already running")

	// ErrNotResolvable means a named finding is not an open blocked, unattributed or missing one,
	// the only kinds an operator's reconcile applies desired state to.
	ErrNotResolvable = errors.New("reconcile: the finding is not an open blocked, unattributed or missing finding")

	// ErrInvalid is a request this package refuses before touching anything.
	ErrInvalid = errors.New("reconcile: invalid request")
)

// eventRetention is how long identity-kernel keeps admin events (adminEventsExpiration in its
// realm definition). Nothing older can be read.
const eventRetention = 7 * 24 * time.Hour

// Transactor is the transaction source this package needs.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Config bounds the reconciler.
type Config struct {
	Realm keycloak.Realm

	// Interval is the sweep cadence. A run unfinished after two intervals belonged to a replica
	// that stopped, and no longer blocks the next one.
	Interval time.Duration

	// CallTimeout bounds one Admin API call.
	CallTimeout time.Duration

	// ExemptClients are the clientIds never recorded unmanaged: the kernel's built-in clients and
	// this service's own Admin API clients (ADR-IAM-001 §5.12).
	ExemptClients []string

	// DisableUnmanaged disables a client no registration describes, as well as recording it
	// (IDENTITY_UNMANAGED_CLIENTS=disable). Off, the finding is recorded and the client left alone.
	DisableUnmanaged bool

	// Recreate builds a registration's client again from desired state and returns the new
	// client's identifier. The registration service supplies it. Only an operator's reconcile
	// naming a 'missing' finding calls it: a sweep never recreates a client on its own.
	Recreate func(ctx context.Context, registration id.UUID) (keycloak.ClientUUID, error)
}

// Reconciler runs registration sweeps.
type Reconciler struct {
	tx     Transactor
	kernel keycloak.ClientRegistry
	cfg    Config
	logger *slog.Logger

	now   func() time.Time
	newID func() (id.UUID, error)
}

// New constructs a Reconciler.
func New(tx Transactor, kernel keycloak.ClientRegistry, cfg Config, logger *slog.Logger) (*Reconciler, error) {
	switch {
	case tx == nil:
		return nil, errors.New("reconcile: a transaction source is required")
	case kernel == nil:
		return nil, errors.New("reconcile: a client registry is required")
	case logger == nil:
		return nil, errors.New("reconcile: a logger is required")
	case cfg.Realm == "":
		return nil, errors.New("reconcile: a realm is required")
	case cfg.Interval <= 0:
		return nil, errors.New("reconcile: a positive interval is required")
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 10 * time.Second
	}
	return &Reconciler{tx: tx, kernel: kernel, cfg: cfg, logger: logger,
		now: func() time.Time { return time.Now().UTC() }, newID: id.NewV7}, nil
}

// Run is one sweep's record.
type Run struct {
	ID          id.UUID    `json:"run_id"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	Outcome     Outcome    `json:"outcome,omitempty"`
	Attribution *bool      `json:"attribution"`
	Findings    int        `json:"findings"`
}

type registration struct {
	id           id.UUID
	clientKey    string
	client       keycloak.ClientUUID
	profile      string
	redirectURIs []string
	lifespan     int

	// keys are the active and retiring keys a confidential or workload client should hold.
	keys []keycloak.JWK

	// state is active or suspended, and suspendedAt the latest suspension.
	state       string
	suspendedAt *time.Time

	// audienceClass and privilegedForm select the managed scope among the client's scope sets.
	audienceClass, privilegedForm string

	// audience is the resources the client's tokens name, as registered.
	audience []string
}

// comparesTokenProfile reports whether the profile is issued tokens, and so holds a token format
// and scope sets. A resource is only an audience.
func (r registration) comparesTokenProfile() bool { return r.profile != "resource" }

// desiredScopes are the scope sets the registration's client holds.
func (r registration) desiredScopes() registrations.ScopeSets {
	desired, _ := registrations.DesiredScopes(r.profile, r.audienceClass, r.privilegedForm)
	return desired
}

// suspended reports whether the registration is suspended, and so compared for its suspension only.
func (r registration) suspended() bool { return r.state == "suspended" && r.suspendedAt != nil }

// notBefore is the not-before a suspended registration's client holds.
func (r registration) notBefore() int64 {
	return registrations.SuspensionNotBefore(*r.suspendedAt)
}

// comparesKeys reports whether the profile authenticates with a registered key.
func (r registration) comparesKeys() bool {
	return r.profile == "confidential" || r.profile == "workload"
}

// comparesRedirects reports whether the profile has redirect URIs at all.
func (r registration) comparesRedirects() bool {
	return r.profile == "confidential" || r.profile == "public"
}

// comparesLifespan reports whether the profile is issued tokens. A resource is only an audience.
func (r registration) comparesLifespan() bool { return r.profile != "resource" }

// Sweep runs one registration sweep.
//
// Every client is read before anything is written, so a kernel that becomes unreachable halfway
// leaves an 'unresolved' run and no partial repair.
func (r *Reconciler) Sweep(ctx context.Context) (Run, error) {
	run, since, err := r.claim(ctx)
	if err != nil {
		return Run{}, err
	}

	finish := func(outcome Outcome, attribution bool, findings int) (Run, error) {
		finishedAt := r.now()
		if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, finishRunStatement, run.ID.String(), finishedAt, string(outcome), attribution, findings)
			return err
		}); err != nil {
			return Run{}, fmt.Errorf("reconcile: finish run: %w", err)
		}
		run.FinishedAt, run.Outcome, run.Attribution, run.Findings = &finishedAt, outcome, &attribution, findings
		return run, nil
	}

	self, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (string, error) { return r.kernel.ServiceAccountUserID(ctx) })
	if err != nil {
		r.logger.WarnContext(ctx, "registration sweep unresolved: the kernel is unreachable", slog.String("error", err.Error()))
		return finish(Unresolved, false, 0)
	}

	// Attribution is what every automatic repair depends on. Unreadable events leave the sweep
	// able to block and to report, never to repair.
	events, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) ([]keycloak.AdminEvent, error) {
		return r.kernel.ClientAdminEvents(ctx, r.cfg.Realm, since)
	})
	attribution := err == nil
	switch {
	case errors.Is(err, keycloak.ErrUnavailable), errors.Is(err, keycloak.ErrAmbiguous):
		r.logger.WarnContext(ctx, "registration sweep unresolved: the kernel is unreachable", slog.String("error", err.Error()))
		return finish(Unresolved, false, 0)
	case err != nil:
		r.logger.ErrorContext(ctx, "admin events cannot be read; no divergence will be repaired automatically",
			slog.String("error", err.Error()))
	}
	latest := latestByClient(events, self)

	var (
		desired    []registration
		managed    map[string]bool
		open       map[findingKey]openFinding
		exceptions map[exceptionKey]bool
	)
	now := r.now()
	if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var readErr error
		if desired, readErr = readDesired(ctx, tx, r.cfg.Realm); readErr != nil {
			return readErr
		}
		if managed, readErr = readManagedKeys(ctx, tx, r.cfg.Realm); readErr != nil {
			return readErr
		}
		if open, readErr = readOpenFindings(ctx, tx); readErr != nil {
			return readErr
		}
		exceptions, readErr = readExceptions(ctx, tx, now)
		return readErr
	}); err != nil {
		return Run{}, err
	}

	live := make(map[keycloak.ClientUUID]keycloak.Client, len(desired))
	scopes := make(map[keycloak.ClientUUID]registrations.ScopeSets, len(desired))
	var absent []registration
	for _, reg := range desired {
		client, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (keycloak.Client, error) {
			return r.kernel.GetClient(ctx, r.cfg.Realm, reg.client)
		})
		switch {
		case errors.Is(err, keycloak.ErrNotFound):
			absent = append(absent, reg)
		case err != nil:
			// Unreachable, or the client read refused: nothing is known about the live state.
			r.logger.WarnContext(ctx, "registration sweep unresolved: a client could not be read",
				slog.String("client_key", reg.clientKey), slog.String("error", err.Error()))
			return finish(Unresolved, attribution, 0)
		default:
			live[reg.client] = client
		}
		if err != nil || !reg.comparesTokenProfile() || reg.suspended() {
			continue
		}
		sets, err := registrations.LiveScopes(ctx, r.kernel, r.cfg.Realm, reg.client, r.cfg.CallTimeout)
		if err != nil {
			r.logger.WarnContext(ctx, "registration sweep unresolved: a client's scopes could not be read",
				slog.String("client_key", reg.clientKey), slog.String("error", err.Error()))
			return finish(Unresolved, attribution, 0)
		}
		scopes[reg.client] = sets
	}

	// Every client in the realm, for the ones no registration describes. Read with the others, before
	// anything is written.
	all, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) ([]keycloak.Client, error) {
		return r.kernel.ListClients(ctx, r.cfg.Realm)
	})
	if err != nil {
		r.logger.WarnContext(ctx, "registration sweep unresolved: the realm's clients could not be listed",
			slog.String("error", err.Error()))
		return finish(Unresolved, attribution, 0)
	}
	var unmanaged []keycloak.Client
	for _, client := range all {
		if !managed[client.ClientID] && !slices.Contains(r.cfg.ExemptClients, client.ClientID) {
			unmanaged = append(unmanaged, client)
		}
	}

	written, diverged := 0, len(absent) > 0 || len(unmanaged) > 0
	for _, reg := range absent {
		wrote, err := r.holdMissing(ctx, run.ID, reg, open, latest)
		if err != nil {
			return Run{}, err
		}
		if wrote {
			written++
		}
	}
	for _, reg := range desired {
		client, ok := live[reg.client]
		if !ok {
			continue
		}
		if reg.suspended() {
			wrote, differs, err := r.reconcileSuspension(ctx, run.ID, reg, client, open, latest)
			if err != nil {
				return Run{}, err
			}
			if wrote {
				written++
			}
			diverged = diverged || differs
			continue
		}
		for _, field := range []FieldClass{TokenLifespan, RedirectURIs, ClientKeys, AudienceScope, TokenFormat, Audience} {
			wrote, differs, err := r.reconcileField(ctx, run.ID, reg, client, scopes[reg.client], field, open, exceptions,
				latest, attribution)
			if err != nil {
				return Run{}, err
			}
			if wrote {
				written++
			}
			diverged = diverged || differs
		}
	}

	for _, client := range unmanaged {
		if err := r.holdUnmanaged(ctx, run.ID, client, open, latest); err != nil {
			return Run{}, err
		}
		written++
	}
	// An unmanaged finding converges once its client is registered, by adoption or otherwise, or gone.
	still := map[keycloak.ClientUUID]bool{}
	for _, client := range unmanaged {
		still[client.ID] = true
	}
	for key, finding := range open {
		if finding.class != Unmanaged || still[key.client] {
			continue
		}
		if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return convergeFinding(ctx, tx, finding.id, r.now(), run.ID)
		}); err != nil {
			return Run{}, err
		}
	}

	if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, convergeRetiredStatement, string(r.cfg.Realm), r.now(), run.ID.String())
		return err
	}); err != nil {
		return Run{}, fmt.Errorf("reconcile: converge the findings of retired registrations: %w", err)
	}

	outcome := Converged
	if diverged {
		outcome = Drift
	}
	return finish(outcome, attribution, written)
}

// reconcileField decides and records one field class of one client. It reports whether it wrote a
// finding and whether the field diverged.
func (r *Reconciler) reconcileField(
	ctx context.Context,
	run id.UUID,
	reg registration,
	client keycloak.Client,
	scopes registrations.ScopeSets,
	field FieldClass,
	open map[findingKey]openFinding,
	exceptions map[exceptionKey]bool,
	latest map[keycloak.ClientUUID]keycloak.AdminEvent,
	attribution bool,
) (bool, bool, error) {
	var (
		applies           bool
		differs           bool
		desired, observed any
		repair            keycloak.ClientPatch
	)
	switch field {
	case TokenLifespan:
		applies = reg.comparesLifespan()
		differs = client.AccessTokenLifespan != reg.lifespan
		desired, observed = reg.lifespan, lifespanValue(client.AccessTokenLifespan)
		lifespan := reg.lifespan
		repair.AccessTokenLifespan = &lifespan
	case RedirectURIs:
		applies = reg.comparesRedirects()
		differs = !sameSet(client.RedirectURIs, reg.redirectURIs)
		desired, observed = sortedCopy(reg.redirectURIs), sortedCopy(client.RedirectURIs)
	case ClientKeys:
		applies = reg.comparesKeys()
		differs = !client.Credential.ByKeys(reg.keys)
		if applies && differs {
			// Confirmed before anything is done about it: this service's own rotation writes the
			// kernel before it commits the rows this sweep read, and blocking that would disable a
			// client for a change nobody made.
			var err error
			if reg, client, differs, err = r.confirmKeyDrift(ctx, reg); err != nil {
				return false, false, err
			}
		}
		desired, observed = keysValue(reg.keys, keycloak.ClientCredential{Authenticator: "client-jwt", HeldJWKS: true}),
			keysValue(client.Credential.Keys, client.Credential)
	case AudienceScope:
		applies = reg.comparesTokenProfile()
		differs = !registrations.SameScopes(scopes, reg.desiredScopes())
		desired, observed = sortedScopes(reg.desiredScopes()), sortedScopes(scopes)
	case TokenFormat:
		applies = reg.comparesTokenProfile()
		differs = !client.RFC9068 || client.ClientIDClaim != reg.clientKey
		desired = map[string]any{"at_jwt": true, "client_id": reg.clientKey}
		observed = map[string]any{"at_jwt": client.RFC9068, "client_id": client.ClientIDClaim}
		clientKey := reg.clientKey
		repair.TokenFormat = &clientKey
	case Audience:
		applies = reg.comparesTokenProfile()
		differs = !sameList(client.Audience, reg.audience)
		if applies && differs {
			// Confirmed first: an audience change writes the kernel before it commits the audience this
			// sweep read, and acting on that would record a change nobody made.
			var err error
			if reg, client, differs, err = r.confirmAudienceDrift(ctx, reg); err != nil {
				return false, false, err
			}
		}
		desired, observed = sortedList(reg.audience), sortedList(client.Audience)
		audience := sortedList(reg.audience)
		repair.Audience = &audience
	}
	if !applies {
		return false, false, nil
	}

	key := findingKey{reg.client, field}
	existing, isOpen := open[key]
	var existingPtr *openFinding
	if isOpen {
		existingPtr = &existing
	}

	now := r.now()
	if !differs {
		// A blocked finding converges only through an operator's reconcile, which re-enables the
		// client. A console fix of the URIs would otherwise close the finding and leave the client
		// disabled with nobody told why.
		if isOpen && existing.class != Blocked {
			return false, false, r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
				return convergeFinding(ctx, tx, existing.id, now, run)
			})
		}
		return false, isOpen, nil
	}

	actor, changedAt := "", (*time.Time)(nil)
	if event, ok := latest[reg.client]; ok {
		at := event.Time
		actor, changedAt = event.UserID, &at
	} else if isOpen && existing.actor != "" {
		// The attribution stays on the finding: a change left in place under an exception is still
		// attributed when the exception expires, long after its event left the sweep's window.
		actor, changedAt = existing.actor, existing.changedAt
	}

	write := findingWrite{existing: existingPtr, run: run, registration: reg.id, client: reg.client, field: field,
		desired: desired, observed: observed, actor: actor, changedAt: changedAt, detectedAt: now, newID: r.newID}

	switch {
	case actor != "" && exceptions[exceptionKey{reg.id, field, actor}]:
		write.class = Sanctioned

	case field == RedirectURIs || field == ClientKeys:
		// A changed redirect URI sends tokens to a host the registration never named, and a key or
		// authenticator changed in the console lets whoever holds the matching secret authenticate
		// as the client. Both are the shape of a takeover: the client is disabled, the changed value
		// is kept for whoever investigates, and only an operator's reconcile lifts it.
		write.class = Blocked
		if client.Enabled {
			disabled := false
			if _, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, r.kernel.PatchClient(ctx, r.cfg.Realm, reg.client, keycloak.ClientPatch{Enabled: &disabled})
			}); err != nil {
				return false, true, fmt.Errorf("reconcile: block %s: %w", reg.clientKey, err)
			}
			r.logger.ErrorContext(ctx, "a registered client's "+string(field)+" changed outside this service; the client is disabled",
				slog.String("client_key", reg.clientKey), slog.String("actor", actor))
		}

	case !attribution || actor == "":
		write.class = Unattributed
		r.logger.ErrorContext(ctx, "a divergence nobody can be named for; it is left for an operator",
			slog.String("client_key", reg.clientKey), slog.String("field_class", string(field)))

	default:
		write.class = Repaired
		converged, err := r.apply(ctx, reg, field, repair)
		if err != nil {
			return false, true, err
		}
		if converged {
			at := r.now()
			write.convergedAt = &at
		}
	}

	return true, true, r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return writeFinding(ctx, tx, write)
	})
}

// reconcileSuspension holds a suspended registration's client disabled with its not-before. The
// repair needs no attribution and no exception covers it: it removes access and never grants it,
// and the supported way to enable the client is a restore.
func (r *Reconciler) reconcileSuspension(ctx context.Context, run id.UUID, reg registration, client keycloak.Client,
	open map[findingKey]openFinding, latest map[keycloak.ClientUUID]keycloak.AdminEvent) (bool, bool, error) {
	key := findingKey{reg.client, Suspension}
	existing, isOpen := open[key]
	now := r.now()
	if !client.Enabled && client.NotBefore >= reg.notBefore() {
		if isOpen {
			return false, false, r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
				return convergeFinding(ctx, tx, existing.id, now, run)
			})
		}
		return false, false, nil
	}

	write := findingWrite{run: run, registration: reg.id, client: reg.client, field: Suspension, class: Repaired,
		desired:    map[string]any{"enabled": false, "not_before": reg.notBefore()},
		observed:   map[string]any{"enabled": client.Enabled, "not_before": client.NotBefore},
		detectedAt: now, newID: r.newID}
	if isOpen {
		write.existing = &existing
		write.actor, write.changedAt = existing.actor, existing.changedAt
	}
	if event, ok := latest[reg.client]; ok {
		at := event.Time
		write.actor, write.changedAt = event.UserID, &at
	}
	disabled, notBefore := false, reg.notBefore()
	converged, err := r.apply(ctx, reg, Suspension, keycloak.ClientPatch{Enabled: &disabled, NotBefore: &notBefore})
	if err != nil {
		return false, true, err
	}
	if converged {
		at := r.now()
		write.convergedAt = &at
	}
	r.logger.ErrorContext(ctx, "a suspended client was enabled or lost its not-before; it is disabled again",
		slog.String("client_key", reg.clientKey), slog.String("actor", write.actor))
	return true, true, r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error { return writeFinding(ctx, tx, write) })
}

// apply writes desired state for one field and reads the client back, reporting whether it now
// matches. A repair is recorded converged only when the kernel says so.
func (r *Reconciler) apply(ctx context.Context, reg registration, field FieldClass, patch keycloak.ClientPatch) (bool, error) {
	if field == AudienceScope {
		// The scope sets are their own resources, not fields of the client's representation.
		if err := registrations.ConvergeScopes(ctx, r.kernel, r.cfg.Realm, reg.client, reg.desiredScopes(),
			r.cfg.CallTimeout); err != nil {
			return false, fmt.Errorf("reconcile: repair %s %s: %w", reg.clientKey, field, err)
		}
		after, err := registrations.LiveScopes(ctx, r.kernel, r.cfg.Realm, reg.client, r.cfg.CallTimeout)
		if err != nil {
			return false, fmt.Errorf("reconcile: read back %s: %w", reg.clientKey, err)
		}
		return registrations.SameScopes(after, reg.desiredScopes()), nil
	}
	if _, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, r.kernel.PatchClient(ctx, r.cfg.Realm, reg.client, patch)
	}); err != nil {
		return false, fmt.Errorf("reconcile: repair %s %s: %w", reg.clientKey, field, err)
	}
	after, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (keycloak.Client, error) {
		return r.kernel.GetClient(ctx, r.cfg.Realm, reg.client)
	})
	if err != nil {
		return false, fmt.Errorf("reconcile: read back %s: %w", reg.clientKey, err)
	}
	switch field {
	case TokenLifespan:
		return after.AccessTokenLifespan == reg.lifespan, nil
	case RedirectURIs:
		return sameSet(after.RedirectURIs, reg.redirectURIs) && after.Enabled, nil
	case ClientKeys:
		return after.Credential.ByKeys(reg.keys) && after.Enabled, nil
	case Suspension:
		return !after.Enabled && after.NotBefore >= reg.notBefore(), nil
	case TokenFormat:
		return after.RFC9068 && after.ClientIDClaim == reg.clientKey, nil
	case Audience:
		return sameList(after.Audience, reg.audience), nil
	}
	return false, nil
}

// confirmAudienceDrift reads the registration's audience again under the share lock an audience
// change's update lock excludes, then the client again, and reports whether they still differ.
func (r *Reconciler) confirmAudienceDrift(ctx context.Context, reg registration) (registration, keycloak.Client, bool, error) {
	if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, lockedAudienceStatement, reg.id.String()).Scan(&reg.audience)
	}); err != nil {
		return reg, keycloak.Client{}, true, fmt.Errorf("reconcile: read %s's audience again: %w", reg.clientKey, err)
	}
	client, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (keycloak.Client, error) {
		return r.kernel.GetClient(ctx, r.cfg.Realm, reg.client)
	})
	if err != nil {
		return reg, keycloak.Client{}, true, fmt.Errorf("reconcile: read %s again: %w", reg.clientKey, err)
	}
	return reg, client, !sameList(client.Audience, reg.audience), nil
}

// sameList reports whether two lists hold the same values the same number of times. A second mapper
// for one resource is a difference a set comparison would miss.
func sameList(a, b []string) bool {
	return slices.Equal(sortedList(a), sortedList(b))
}

// sortedList is a sorted copy that keeps repeats, as a list of mappers is recorded.
func sortedList(values []string) []string {
	out := slices.Clone(values)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return out
}

// sortedScopes is a scope sets value as a finding records it.
func sortedScopes(sets registrations.ScopeSets) registrations.ScopeSets {
	return registrations.ScopeSets{Default: sortedCopy(sets.Default), Optional: sortedCopy(sets.Optional)}
}

// confirmKeyDrift reads the registration's keys again under the share lock a key change's update
// lock excludes, then the client again, and reports whether they still differ. It returns what it
// read, so the finding records the confirmed values.
func (r *Reconciler) confirmKeyDrift(ctx context.Context, reg registration) (registration, keycloak.Client, bool, error) {
	if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, lockRegistrationStatement, reg.id.String()); err != nil {
			return fmt.Errorf("reconcile: lock the registration: %w", err)
		}
		keys, err := readDesiredKeys(ctx, tx, lockedKeysStatement, reg.id.String())
		if err != nil {
			return err
		}
		reg.keys = keys[reg.id]
		return nil
	}); err != nil {
		return reg, keycloak.Client{}, true, err
	}
	client, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (keycloak.Client, error) {
		return r.kernel.GetClient(ctx, r.cfg.Realm, reg.client)
	})
	if err != nil {
		return reg, keycloak.Client{}, true, fmt.Errorf("reconcile: read %s again: %w", reg.clientKey, err)
	}
	return reg, client, !client.Credential.ByKeys(reg.keys), nil
}

// keysValue is a credential as a finding records it: the authenticator, whether the JWKS is held,
// and the kids, sorted. The key material is compared, and left out of the record: it is public, and
// the kid names it.
func keysValue(keys []keycloak.JWK, credential keycloak.ClientCredential) any {
	kids := make([]string, 0, len(keys))
	for _, key := range keys {
		kids = append(kids, key.KID)
	}
	return map[string]any{"authenticator": credential.Authenticator, "held_jwks": credential.HeldJWKS,
		"unreadable": credential.Unreadable, "kids": sortedCopy(kids)}
}

// claim records a new run unless another replica's is running, and returns the instant admin
// events are read from: the previous run's start, or two intervals back for the first run.
func (r *Reconciler) claim(ctx context.Context) (Run, time.Time, error) {
	runID, err := r.newID()
	if err != nil {
		return Run{}, time.Time{}, fmt.Errorf("reconcile: mint run_id: %w", err)
	}
	now := r.now()
	var previous *time.Time
	err = r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, claimLock); err != nil {
			return fmt.Errorf("reconcile: take the claim lock: %w", err)
		}
		var running bool
		if err := tx.QueryRow(ctx, runningStatement, now.Add(-2*r.cfg.Interval)).Scan(&running); err != nil {
			return fmt.Errorf("reconcile: look for a running sweep: %w", err)
		}
		if running {
			return ErrSweepInProgress
		}
		if err := tx.QueryRow(ctx, previousStartStatement).Scan(&previous); err != nil {
			return fmt.Errorf("reconcile: read the previous run: %w", err)
		}
		if _, err := tx.Exec(ctx, insertRunStatement, runID.String(), now); err != nil {
			return fmt.Errorf("reconcile: record the run: %w", err)
		}
		return nil
	})
	if err != nil {
		return Run{}, time.Time{}, err
	}
	// From the previous run's start, so a change made while no replica was sweeping is still
	// attributed; but never past the kernel's admin-event retention, where nothing is left to read.
	since := now.Add(-2 * r.cfg.Interval)
	if previous != nil {
		since = *previous
		if floor := now.Add(-eventRetention); since.Before(floor) {
			since = floor
		}
	}
	return Run{ID: runID, StartedAt: now}, since, nil
}

// call bounds one kernel call.
func call[T any](ctx context.Context, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(callCtx)
}

// holdUnmanaged records a client no registration describes as an open 'unmanaged' finding, naming
// whoever its latest admin event names, and disables it when the setting says to. Disabled rather
// than deleted: a false positive from a defect here is recoverable, and a deleted client some
// running system depends on is not.
func (r *Reconciler) holdUnmanaged(ctx context.Context, run id.UUID, client keycloak.Client,
	open map[findingKey]openFinding, latest map[keycloak.ClientUUID]keycloak.AdminEvent) error {
	existing, isOpen := open[findingKey{client.ID, ""}]
	write := findingWrite{run: run, client: client.ID, class: Unmanaged, desired: nil,
		observed: map[string]any{"client_id": client.ClientID, "enabled": client.Enabled}, detectedAt: r.now(), newID: r.newID}
	if isOpen {
		write.existing = &existing
		write.actor, write.changedAt = existing.actor, existing.changedAt
	}
	if event, ok := latest[client.ID]; ok {
		at := event.Time
		write.actor, write.changedAt = event.UserID, &at
	}
	if !isOpen {
		r.logger.ErrorContext(ctx, "a Keycloak client no registration describes",
			slog.String("client_id", client.ClientID), slog.String("actor", write.actor),
			slog.Bool("disabled", r.cfg.DisableUnmanaged))
	}
	if r.cfg.DisableUnmanaged && client.Enabled {
		disabled := false
		if _, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
			return struct{}{}, r.kernel.PatchClient(ctx, r.cfg.Realm, client.ID, keycloak.ClientPatch{Enabled: &disabled})
		}); err != nil {
			return fmt.Errorf("reconcile: disable unmanaged %s: %w", client.ClientID, err)
		}
	}
	return r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error { return writeFinding(ctx, tx, write) })
}

// holdMissing records a registered client absent from the kernel as an open 'missing' finding, and
// does not recreate it. Deleting a client in the console is how an operator contains a compromised
// one while the registration lifecycle (:suspend, :retire) is not built, and recreating it
// automatically would undo that containment within one interval. An operator's reconcile naming
// the finding recreates it. Whoever the deletion's admin event names is recorded.
func (r *Reconciler) holdMissing(ctx context.Context, run id.UUID, reg registration,
	open map[findingKey]openFinding, latest map[keycloak.ClientUUID]keycloak.AdminEvent) (bool, error) {
	existing, isOpen := open[findingKey{reg.client, ""}]
	now := r.now()
	write := findingWrite{run: run, registration: reg.id, client: reg.client, class: Missing,
		desired: map[string]string{"client_key": reg.clientKey}, observed: nil, detectedAt: now, newID: r.newID}
	if isOpen {
		write.existing = &existing
		write.actor, write.changedAt = existing.actor, existing.changedAt
	}
	if event, ok := latest[reg.client]; ok {
		at := event.Time
		write.actor, write.changedAt = event.UserID, &at
	}
	if !isOpen {
		r.logger.ErrorContext(ctx, "a registered client is absent from the kernel; it is held for an operator, not recreated",
			slog.String("client_key", reg.clientKey), slog.String("actor", write.actor))
	}
	return true, r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error { return writeFinding(ctx, tx, write) })
}
