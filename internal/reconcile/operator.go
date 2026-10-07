package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	registrations "github.com/anshacerbia2/identity-control/internal/registration"
)

// What an operator does with the reconciler: read its last run and open findings, lift a block or
// apply desired state to an unattributed divergence, and grant a drift exception.

// Finding is one divergence, as the drift route reports it.
type Finding struct {
	ID id.UUID `json:"finding_id"`

	// Registration is null for an unmanaged client, which no registration describes.
	Registration *id.UUID        `json:"registration_id"`
	ClientKey    string          `json:"client_key"`
	FieldClass   FieldClass      `json:"field_class,omitempty"`
	Class        FindingClass    `json:"finding_class"`
	Desired      json.RawMessage `json:"desired"`
	Observed     json.RawMessage `json:"observed"`
	Actor        string          `json:"actor,omitempty"`
	ChangedAt    *time.Time      `json:"changed_at"`
	DetectedAt   time.Time       `json:"detected_at"`

	// ConvergedAt is when the client matched desired state again. ConvergedAt minus ChangedAt is
	// the convergence time the drift proof records.
	ConvergedAt *time.Time `json:"converged_at"`
}

// Status is the last run, what that run recorded, and every finding that has not converged.
type Status struct {
	LastRun *Run `json:"last_run"`

	// LastRunFindings are the findings the last run wrote or converged, converged ones included,
	// so a repair and its convergence time can be read after the fact.
	LastRunFindings []Finding `json:"last_run_findings"`

	Findings []Finding `json:"findings"`
}

const lastRunStatement = `SELECT run_id::text, started_at, finished_at, coalesce(outcome, ''), attribution, findings
FROM identity.reconcile_run WHERE sweep = 'registration'
ORDER BY started_at DESC LIMIT 1`

// An unmanaged client's finding has no registration, so its client_key is the clientId it recorded.
const findingColumns = `SELECT f.finding_id::text, coalesce(f.registration_id::text, ''),
       coalesce(r.client_key, f.observed->>'client_id', ''), coalesce(f.field_class, ''),
       f.finding_class, coalesce(f.desired, 'null'::jsonb)::text, coalesce(f.observed, 'null'::jsonb)::text,
       coalesce(f.actor, ''), f.changed_at, f.detected_at, f.converged_at
FROM identity.registration_finding f
LEFT JOIN identity.client_registration r ON r.registration_id = f.registration_id`

const openFindingDetailStatement = findingColumns + `
WHERE f.converged_at IS NULL
ORDER BY f.detected_at`

const runFindingDetailStatement = findingColumns + `
WHERE f.run_id = $1
ORDER BY f.detected_at`

// Status reads the last run, its findings, and the open findings.
func (r *Reconciler) Status(ctx context.Context) (Status, error) {
	status := Status{LastRunFindings: []Finding{}, Findings: []Finding{}}
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, lastRunStatement)
		if err != nil {
			return fmt.Errorf("reconcile: read the last run: %w", err)
		}
		for rows.Next() {
			var (
				raw     string
				run     Run
				outcome string
			)
			if err := rows.Scan(&raw, &run.StartedAt, &run.FinishedAt, &outcome, &run.Attribution, &run.Findings); err != nil {
				rows.Close()
				return fmt.Errorf("reconcile: scan the last run: %w", err)
			}
			if run.ID, err = id.Parse(raw); err != nil {
				rows.Close()
				return err
			}
			run.Outcome = Outcome(outcome)
			status.LastRun = &run
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		if status.LastRun != nil {
			if status.LastRunFindings, err = readFindings(ctx, tx, runFindingDetailStatement, status.LastRun.ID.String()); err != nil {
				return err
			}
		}
		status.Findings, err = readFindings(ctx, tx, openFindingDetailStatement)
		return err
	})
	return status, err
}

const registrationFindingsStatement = findingColumns + `
WHERE f.registration_id = $1
ORDER BY f.detected_at DESC
LIMIT 100`

// FindingsFor is one registration's findings, newest first, converged ones included: what happened
// to that client, and how long each divergence took to converge.
func (r *Reconciler) FindingsFor(ctx context.Context, registration id.UUID) ([]Finding, error) {
	var out []Finding
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		out, err = readFindings(ctx, tx, registrationFindingsStatement, registration.String())
		return err
	})
	return out, err
}

func readFindings(ctx context.Context, tx db.Tx, statement string, args ...any) ([]Finding, error) {
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("reconcile: read findings: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var (
			rawFinding, rawRegistration, field, class, desired, observed string
			finding                                                      Finding
		)
		if err := rows.Scan(&rawFinding, &rawRegistration, &finding.ClientKey, &field, &class, &desired, &observed,
			&finding.Actor, &finding.ChangedAt, &finding.DetectedAt, &finding.ConvergedAt); err != nil {
			return nil, fmt.Errorf("reconcile: scan finding: %w", err)
		}
		if finding.ID, err = id.Parse(rawFinding); err != nil {
			return nil, err
		}
		if rawRegistration != "" {
			registration, err := id.Parse(rawRegistration)
			if err != nil {
				return nil, err
			}
			finding.Registration = &registration
		}
		finding.FieldClass, finding.Class = FieldClass(field), FindingClass(class)
		finding.Desired, finding.Observed = json.RawMessage(desired), json.RawMessage(observed)
		out = append(out, finding)
	}
	return out, rows.Err()
}

// Resolution is an operator applying desired state to findings the sweep left alone.
type Resolution struct {
	Findings   []id.UUID
	ResolvedBy id.UUID
	Reason     string
}

const resolvableStatement = `SELECT count(*) FROM identity.registration_finding
WHERE finding_id = $1 AND converged_at IS NULL AND finding_class IN ('blocked', 'unattributed', 'missing')`

const resolveStatement = `UPDATE identity.registration_finding
SET converged_at = $2, resolved_by = $3, resolution_reason = $4
WHERE finding_id = $1 AND converged_at IS NULL`

// Resolve applies desired state to each named blocked or unattributed finding and records who did
// it and why. A blocked client is re-enabled with its desired redirect URIs. Every finding is
// checked before any is applied, so a request naming one that is not resolvable changes nothing.
func (r *Reconciler) Resolve(ctx context.Context, resolution Resolution) error {
	if len(resolution.Findings) == 0 || resolution.ResolvedBy.IsNil() || strings.TrimSpace(resolution.Reason) == "" {
		return fmt.Errorf("%w: a resolution names findings, the Principal resolving them, and a reason", ErrInvalid)
	}

	var desired []registration
	type target struct {
		finding id.UUID
		reg     registration
		field   FieldClass
	}
	var targets []target
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		if desired, err = readDesired(ctx, tx, r.cfg.Realm); err != nil {
			return err
		}
		open, err := readOpenFindings(ctx, tx)
		if err != nil {
			return err
		}
		for _, findingID := range resolution.Findings {
			var count int
			if err := tx.QueryRow(ctx, resolvableStatement, findingID.String()).Scan(&count); err != nil {
				return fmt.Errorf("reconcile: check finding: %w", err)
			}
			if count != 1 {
				return fmt.Errorf("%w: %s", ErrNotResolvable, findingID)
			}
			found := false
			for key, finding := range open {
				if finding.id != findingID {
					continue
				}
				for _, reg := range desired {
					if reg.client != key.client {
						continue
					}
					if reg.state != "active" {
						// Both a resolution and a recreation would enable the client of a suspended
						// registration. A restore is the path that does (ADR-IAM-001 §5.13).
						return fmt.Errorf("%w: %s is suspended; restoring it applies its desired state", ErrNotResolvable,
							findingID)
					}
					targets = append(targets, target{findingID, reg, key.field})
					found = true
				}
			}
			if !found {
				return fmt.Errorf("%w: %s has no active registration to apply", ErrNotResolvable, findingID)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, t := range targets {
		if t.field == "" {
			if err := r.recreateMissing(ctx, t.finding, t.reg, resolution); err != nil {
				return err
			}
			continue
		}
		var patch keycloak.ClientPatch
		switch t.field {
		case TokenLifespan:
			lifespan := t.reg.lifespan
			patch.AccessTokenLifespan = &lifespan
		case RedirectURIs:
			uris, enabled := append([]string{}, t.reg.redirectURIs...), true
			patch.RedirectURIs, patch.Enabled = &uris, &enabled
		case ClientKeys:
			// The JWKS is rebuilt from the active and retiring rows, and client-jwt restored, so a
			// key or a secret the console added stops authenticating before the client is re-enabled.
			keys, enabled := append([]keycloak.JWK{}, t.reg.keys...), true
			patch.Keys, patch.Enabled = &keys, &enabled
		case TokenFormat:
			clientKey := t.reg.clientKey
			patch.TokenFormat = &clientKey
		case Audience:
			audience := sortedList(t.reg.audience)
			patch.Audience = &audience
		}
		converged, err := r.apply(ctx, t.reg, t.field, patch)
		if err != nil {
			return err
		}
		if !converged {
			return fmt.Errorf("reconcile: %s did not match desired state after it was applied", t.reg.clientKey)
		}
		at := r.now()
		if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, resolveStatement, t.finding.String(), at, resolution.ResolvedBy.String(), resolution.Reason)
			return err
		}); err != nil {
			return fmt.Errorf("reconcile: record the resolution: %w", err)
		}
	}
	return nil
}

const recreatedStatement = `UPDATE identity.registration_finding
SET finding_class = 'recreated', desired = $5::jsonb, converged_at = $2, resolved_by = $3, resolution_reason = $4
WHERE finding_id = $1 AND converged_at IS NULL AND finding_class = 'missing'`

// recreateMissing is the one path that builds a missing client again: an operator's reconcile,
// with a reason, naming the finding.
func (r *Reconciler) recreateMissing(ctx context.Context, finding id.UUID, reg registration, resolution Resolution) error {
	if r.cfg.Recreate == nil {
		return fmt.Errorf("%w: nothing is configured to recreate %s", ErrNotResolvable, reg.clientKey)
	}
	client, err := r.cfg.Recreate(ctx, reg.id)
	if errors.Is(err, registrations.ErrWorkloadRecreate) {
		return fmt.Errorf("%w: %s is a workload's client, rebuilt through its workload", ErrNotResolvable, reg.clientKey)
	}
	if err != nil {
		return fmt.Errorf("reconcile: recreate %s: %w", reg.clientKey, err)
	}
	desired, err := json.Marshal(map[string]string{"client_key": reg.clientKey, "client": string(client)})
	if err != nil {
		return err
	}
	at := r.now()
	if err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, recreatedStatement, finding.String(), at, resolution.ResolvedBy.String(),
			resolution.Reason, string(desired))
		return err
	}); err != nil {
		return fmt.Errorf("reconcile: record the recreation: %w", err)
	}
	r.logger.WarnContext(ctx, "a missing client was recreated by an operator's reconcile",
		slog.String("client_key", reg.clientKey))
	return nil
}

// Exception is a drift exception: one Keycloak user may change one field class of one client in
// the console for a bounded time.
type Exception struct {
	ID           id.UUID    `json:"exception_id"`
	Registration id.UUID    `json:"registration_id"`
	FieldClass   FieldClass `json:"field_class"`
	Actor        string     `json:"actor"`
	Reason       string     `json:"reason"`
	GrantedBy    id.UUID    `json:"granted_by"`
	GrantedAt    time.Time  `json:"granted_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
}

// MaxException is the longest a drift exception may last, as the database also enforces.
const MaxException = 24 * time.Hour

const activeRegistrationStatement = `SELECT count(*) FROM identity.client_registration
WHERE registration_id = $1 AND state = 'active'`

const insertExceptionStatement = `INSERT INTO identity.drift_exception
    (exception_id, registration_id, field_class, actor, reason, granted_by, granted_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// ErrNoSuchRegistration means the exception names no active registration.
var ErrNoSuchRegistration = errors.New("reconcile: no active registration by that identifier")

// GrantException records a drift exception lasting the given duration.
func (r *Reconciler) GrantException(ctx context.Context, exception Exception, lasting time.Duration) (Exception, error) {
	switch {
	case exception.Registration.IsNil(), exception.GrantedBy.IsNil():
		return Exception{}, fmt.Errorf("%w: an exception names a registration and the Principal granting it", ErrInvalid)
	case !slices.Contains([]FieldClass{TokenLifespan, RedirectURIs}, exception.FieldClass):
		return Exception{}, fmt.Errorf("%w: field_class must be token_lifespan or redirect_uris", ErrInvalid)
	case strings.TrimSpace(exception.Actor) == "", strings.TrimSpace(exception.Reason) == "":
		return Exception{}, fmt.Errorf("%w: an exception names the Keycloak user and a reason", ErrInvalid)
	case lasting <= 0 || lasting > MaxException:
		return Exception{}, fmt.Errorf("%w: an exception lasts more than nothing and at most %s", ErrInvalid, MaxException)
	}
	exceptionID, err := r.newID()
	if err != nil {
		return Exception{}, fmt.Errorf("reconcile: mint exception_id: %w", err)
	}
	exception.ID = exceptionID
	exception.GrantedAt = r.now()
	exception.ExpiresAt = exception.GrantedAt.Add(lasting)
	err = r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, activeRegistrationStatement, exception.Registration.String()).Scan(&count); err != nil {
			return fmt.Errorf("reconcile: find registration: %w", err)
		}
		if count != 1 {
			return ErrNoSuchRegistration
		}
		_, err := tx.Exec(ctx, insertExceptionStatement, exception.ID.String(), exception.Registration.String(),
			string(exception.FieldClass), exception.Actor, exception.Reason, exception.GrantedBy.String(),
			exception.GrantedAt, exception.ExpiresAt)
		return err
	})
	if err != nil {
		return Exception{}, err
	}
	return exception, nil
}

const registrationExceptionsStatement = `SELECT exception_id::text, registration_id::text, field_class, actor, reason,
       granted_by::text, granted_at, expires_at
FROM identity.drift_exception
WHERE registration_id = $1
ORDER BY granted_at DESC
LIMIT 100`

// ExceptionsFor is one registration's drift exceptions, newest first, expired ones included: who
// was allowed to change what in the console, why, and until when. An expired exception stays the
// record of why a sanctioned finding was left in place.
func (r *Reconciler) ExceptionsFor(ctx context.Context, registration id.UUID) ([]Exception, error) {
	var out []Exception
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// Reset on every attempt, in case the transaction is retried.
		out = []Exception{}
		rows, err := tx.Query(ctx, registrationExceptionsStatement, registration.String())
		if err != nil {
			return fmt.Errorf("reconcile: read drift exceptions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				rawException, rawRegistration, field, rawGrantedBy string
				exception                                          Exception
			)
			if err := rows.Scan(&rawException, &rawRegistration, &field, &exception.Actor, &exception.Reason,
				&rawGrantedBy, &exception.GrantedAt, &exception.ExpiresAt); err != nil {
				return fmt.Errorf("reconcile: scan drift exception: %w", err)
			}
			if exception.ID, err = id.Parse(rawException); err != nil {
				return err
			}
			if exception.Registration, err = id.Parse(rawRegistration); err != nil {
				return err
			}
			if exception.GrantedBy, err = id.Parse(rawGrantedBy); err != nil {
				return err
			}
			exception.FieldClass = FieldClass(field)
			out = append(out, exception)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// latestByClient is the newest admin event on each client that this service did not cause. The
// reconciler's own repairs are admin events too, and attributing a divergence to them would name
// the reconciler as the one who made the change it is repairing.
func latestByClient(events []keycloak.AdminEvent, self string) map[keycloak.ClientUUID]keycloak.AdminEvent {
	out := map[keycloak.ClientUUID]keycloak.AdminEvent{}
	for _, event := range events {
		client := event.ClientID()
		if client == "" || event.UserID == "" || event.UserID == self {
			continue
		}
		if current, ok := out[client]; !ok || event.Time.After(current.Time) {
			out[client] = event
		}
	}
	return out
}

func sameSet(a, b []string) bool {
	return slices.Equal(sortedCopy(a), sortedCopy(b))
}

func sortedCopy(values []string) []string {
	out := slices.Clone(values)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// lifespanValue reports an absent override as null rather than 0, which is not a lifespan.
func lifespanValue(seconds int) any {
	if seconds == 0 {
		return nil
	}
	return seconds
}
