// Package reconcile compares registered desired state against the live Keycloak clients, and
// repairs or blocks what drifted (TDD-identity-control-003 §Drift Reconciliation).
//
// An absent client is held for an operator, not recreated. Two field classes are compared, the two
// the drift proof exercises: a client's access token
// lifespan, which is repaired, and its redirect URIs, which are blocked. Each divergence is
// attributed through Keycloak's admin events before anything is done about it. A change an
// unexpired drift exception covers is left in place, and a change nobody can be named for is
// never repaired automatically. An unreachable Keycloak produces an 'unresolved' run that
// changes nothing.
//
// What this package does not do yet, and why:
//
//   - A client no registration describes is not disabled. The service's own clients are
//     confidential clients, which cannot be registered until client key registration is built,
//     so disabling unregistered clients would disable this service.
//   - Audience scope, signing algorithm and profile are not compared yet.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// FieldClass names what diverged. Each has one policy.
type FieldClass string

const (
	TokenLifespan FieldClass = "token_lifespan"
	RedirectURIs  FieldClass = "redirect_uris"
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
)

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
		open       map[findingKey]openFinding
		exceptions map[exceptionKey]bool
	)
	now := r.now()
	if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var readErr error
		if desired, readErr = readDesired(ctx, tx, r.cfg.Realm); readErr != nil {
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
	}

	written, diverged := 0, len(absent) > 0
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
		for _, field := range []FieldClass{TokenLifespan, RedirectURIs} {
			wrote, differs, err := r.reconcileField(ctx, run.ID, reg, client, field, open, exceptions, latest, attribution)
			if err != nil {
				return Run{}, err
			}
			if wrote {
				written++
			}
			diverged = diverged || differs
		}
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

	case field == RedirectURIs:
		write.class = Blocked
		if client.Enabled {
			disabled := false
			if _, err := call(ctx, r.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, r.kernel.PatchClient(ctx, r.cfg.Realm, reg.client, keycloak.ClientPatch{Enabled: &disabled})
			}); err != nil {
				return false, true, fmt.Errorf("reconcile: block %s: %w", reg.clientKey, err)
			}
			r.logger.ErrorContext(ctx, "a registered client's redirect URIs changed outside this service; the client is disabled",
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

// apply writes desired state for one field and reads the client back, reporting whether it now
// matches. A repair is recorded converged only when the kernel says so.
func (r *Reconciler) apply(ctx context.Context, reg registration, field FieldClass, patch keycloak.ClientPatch) (bool, error) {
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
	}
	return false, nil
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
