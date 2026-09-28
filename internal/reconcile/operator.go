package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// What an operator does with the reconciler: read its last run and open findings, lift a block or
// apply desired state to an unattributed divergence, and grant a drift exception.

// Finding is one open divergence, as the drift route reports it.
type Finding struct {
	ID           id.UUID         `json:"finding_id"`
	Registration id.UUID         `json:"registration_id"`
	ClientKey    string          `json:"client_key"`
	FieldClass   FieldClass      `json:"field_class"`
	Class        FindingClass    `json:"finding_class"`
	Desired      json.RawMessage `json:"desired"`
	Observed     json.RawMessage `json:"observed"`
	Actor        string          `json:"actor,omitempty"`
	ChangedAt    *time.Time      `json:"changed_at"`
	DetectedAt   time.Time       `json:"detected_at"`
}

// Status is the last run and every finding that has not converged.
type Status struct {
	LastRun  *Run      `json:"last_run"`
	Findings []Finding `json:"findings"`
}

const lastRunStatement = `SELECT run_id::text, started_at, finished_at, coalesce(outcome, ''), attribution, findings
FROM identity.reconcile_run WHERE sweep = 'registration'
ORDER BY started_at DESC LIMIT 1`

const openFindingDetailStatement = `SELECT f.finding_id::text, f.registration_id::text, r.client_key, coalesce(f.field_class, ''),
       f.finding_class, coalesce(f.desired, 'null'::jsonb)::text, coalesce(f.observed, 'null'::jsonb)::text,
       coalesce(f.actor, ''), f.changed_at, f.detected_at
FROM identity.registration_finding f
JOIN identity.client_registration r ON r.registration_id = f.registration_id
WHERE f.converged_at IS NULL
ORDER BY f.detected_at`

// Status reads the last run and the open findings.
func (r *Reconciler) Status(ctx context.Context) (Status, error) {
	status := Status{Findings: []Finding{}}
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

		rows, err = tx.Query(ctx, openFindingDetailStatement)
		if err != nil {
			return fmt.Errorf("reconcile: read open findings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				rawFinding, rawRegistration, field, class, desired, observed string
				finding                                                      Finding
			)
			if err := rows.Scan(&rawFinding, &rawRegistration, &finding.ClientKey, &field, &class, &desired, &observed,
				&finding.Actor, &finding.ChangedAt, &finding.DetectedAt); err != nil {
				return fmt.Errorf("reconcile: scan open finding: %w", err)
			}
			if finding.ID, err = id.Parse(rawFinding); err != nil {
				return err
			}
			if finding.Registration, err = id.Parse(rawRegistration); err != nil {
				return err
			}
			finding.FieldClass, finding.Class = FieldClass(field), FindingClass(class)
			finding.Desired, finding.Observed = json.RawMessage(desired), json.RawMessage(observed)
			status.Findings = append(status.Findings, finding)
		}
		return rows.Err()
	})
	return status, err
}

// Resolution is an operator applying desired state to findings the sweep left alone.
type Resolution struct {
	Findings   []id.UUID
	ResolvedBy id.UUID
	Reason     string
}

const resolvableStatement = `SELECT count(*) FROM identity.registration_finding
WHERE finding_id = $1 AND converged_at IS NULL AND finding_class IN ('blocked', 'unattributed')`

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
					if reg.client == key.client {
						targets = append(targets, target{findingID, reg, key.field})
						found = true
					}
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
		var patch keycloak.ClientPatch
		switch t.field {
		case TokenLifespan:
			lifespan := t.reg.lifespan
			patch.AccessTokenLifespan = &lifespan
		case RedirectURIs:
			uris, enabled := append([]string{}, t.reg.redirectURIs...), true
			patch.RedirectURIs, patch.Enabled = &uris, &enabled
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
