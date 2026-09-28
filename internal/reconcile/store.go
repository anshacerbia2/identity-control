package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	clientregistration "github.com/anshacerbia2/identity-control/internal/registration"
)

// The reads and writes of identity.reconcile_run, registration_finding and drift_exception, plus
// the desired state the sweep compares against. Every function takes the caller's transaction,
// per STD-GLB-BE-001 Rule 6.

// claimLock serialises run claims across replicas. Transaction-scoped: it is held only while one
// replica checks for a running sweep and records its own, so two replicas cannot both see none.
const claimLock = `SELECT pg_advisory_xact_lock(hashtext('identity.reconcile_run.registration'))`

// A run older than staleAfter that never finished belonged to a replica that stopped. It no longer
// blocks a new one, and it stays visible as the unfinished run it was.
const runningStatement = `SELECT EXISTS (
    SELECT 1 FROM identity.reconcile_run
    WHERE sweep = 'registration' AND finished_at IS NULL AND started_at > $1)`

const previousStartStatement = `SELECT max(started_at)
FROM identity.reconcile_run WHERE sweep = 'registration'`

const insertRunStatement = `INSERT INTO identity.reconcile_run (run_id, sweep, started_at)
VALUES ($1, 'registration', $2)`

const finishRunStatement = `UPDATE identity.reconcile_run
SET finished_at = $2, outcome = $3, attribution = $4, findings = $5
WHERE run_id = $1 AND finished_at IS NULL`

// desiredStatement is every active registration the sweep compares, with its derived access token
// lifespan (registration.LifespanSQL, TDD-identity-control-003 §Data Model).
var desiredStatement = `SELECT r.registration_id::text,
       r.client_key,
       r.kc_client_id,
       r.profile,
       coalesce(r.redirect_uris, '{}'::text[]),
       ` + clientregistration.LifespanSQL("r.realm", "r.audience") + `
FROM identity.client_registration r
WHERE r.realm = $1 AND r.state = 'active' AND r.kc_client_id IS NOT NULL
ORDER BY r.client_key`

func readDesired(ctx context.Context, tx db.Tx, realm keycloak.Realm) ([]registration, error) {
	rows, err := tx.Query(ctx, desiredStatement, string(realm))
	if err != nil {
		return nil, fmt.Errorf("reconcile: read desired state: %w", err)
	}
	defer rows.Close()
	var out []registration
	for rows.Next() {
		var (
			raw      string
			reg      registration
			clientID string
		)
		if err := rows.Scan(&raw, &reg.clientKey, &clientID, &reg.profile, &reg.redirectURIs, &reg.lifespan); err != nil {
			return nil, fmt.Errorf("reconcile: scan desired state: %w", err)
		}
		parsed, err := id.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("reconcile: registration_id: %w", err)
		}
		reg.id = parsed
		reg.client = keycloak.ClientUUID(clientID)
		out = append(out, reg)
	}
	return out, rows.Err()
}

const openFindingsStatement = `SELECT finding_id::text, kc_client_id, field_class, finding_class,
       coalesce(actor, ''), changed_at
FROM identity.registration_finding
WHERE converged_at IS NULL AND field_class IS NOT NULL`

type findingKey struct {
	client keycloak.ClientUUID
	field  FieldClass
}

type openFinding struct {
	id        id.UUID
	class     FindingClass
	actor     string
	changedAt *time.Time
}

func readOpenFindings(ctx context.Context, tx db.Tx) (map[findingKey]openFinding, error) {
	rows, err := tx.Query(ctx, openFindingsStatement)
	if err != nil {
		return nil, fmt.Errorf("reconcile: read open findings: %w", err)
	}
	defer rows.Close()
	out := map[findingKey]openFinding{}
	for rows.Next() {
		var (
			raw, client, field, class string
			finding                   openFinding
		)
		if err := rows.Scan(&raw, &client, &field, &class, &finding.actor, &finding.changedAt); err != nil {
			return nil, fmt.Errorf("reconcile: scan open finding: %w", err)
		}
		if finding.id, err = id.Parse(raw); err != nil {
			return nil, fmt.Errorf("reconcile: finding_id: %w", err)
		}
		finding.class = FindingClass(class)
		out[findingKey{keycloak.ClientUUID(client), FieldClass(field)}] = finding
	}
	return out, rows.Err()
}

const exceptionsStatement = `SELECT registration_id::text, field_class, actor
FROM identity.drift_exception WHERE expires_at > $1`

type exceptionKey struct {
	registration id.UUID
	field        FieldClass
	actor        string
}

func readExceptions(ctx context.Context, tx db.Tx, now time.Time) (map[exceptionKey]bool, error) {
	rows, err := tx.Query(ctx, exceptionsStatement, now)
	if err != nil {
		return nil, fmt.Errorf("reconcile: read drift exceptions: %w", err)
	}
	defer rows.Close()
	out := map[exceptionKey]bool{}
	for rows.Next() {
		var raw, field, actor string
		if err := rows.Scan(&raw, &field, &actor); err != nil {
			return nil, fmt.Errorf("reconcile: scan drift exception: %w", err)
		}
		registration, err := id.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("reconcile: exception registration_id: %w", err)
		}
		out[exceptionKey{registration, FieldClass(field), actor}] = true
	}
	return out, rows.Err()
}

const insertFindingStatement = `INSERT INTO identity.registration_finding
    (finding_id, run_id, registration_id, kc_client_id, field_class, finding_class,
     desired, observed, actor, changed_at, detected_at, converged_at)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11, $12)`

// updateFindingStatement moves an open finding to what this run saw. One divergence has one
// finding, so a sweep that still sees it updates the row rather than opening another; detected_at
// is the first sighting and is kept.
const updateFindingStatement = `UPDATE identity.registration_finding
SET run_id = $2, finding_class = $3, desired = $4::jsonb, observed = $5::jsonb,
    actor = $6, changed_at = $7, converged_at = $8
WHERE finding_id = $1 AND converged_at IS NULL`

type findingWrite struct {
	existing     *openFinding
	run          id.UUID
	registration id.UUID
	client       keycloak.ClientUUID
	field        FieldClass
	class        FindingClass
	desired      any
	observed     any
	actor        string
	changedAt    *time.Time
	convergedAt  *time.Time
	detectedAt   time.Time
	newID        func() (id.UUID, error)
}

func writeFinding(ctx context.Context, tx db.Tx, w findingWrite) error {
	desired, err := json.Marshal(w.desired)
	if err != nil {
		return fmt.Errorf("reconcile: encode desired value: %w", err)
	}
	observed, err := json.Marshal(w.observed)
	if err != nil {
		return fmt.Errorf("reconcile: encode observed value: %w", err)
	}
	actor, field := any(nil), any(nil)
	if w.actor != "" {
		actor = w.actor
	}
	if w.field != "" {
		field = string(w.field)
	}
	if w.existing != nil {
		if _, err := tx.Exec(ctx, updateFindingStatement, w.existing.id.String(), w.run.String(), string(w.class),
			string(desired), string(observed), actor, w.changedAt, w.convergedAt); err != nil {
			return fmt.Errorf("reconcile: update finding: %w", err)
		}
		return nil
	}
	findingID, err := w.newID()
	if err != nil {
		return fmt.Errorf("reconcile: mint finding_id: %w", err)
	}
	if _, err := tx.Exec(ctx, insertFindingStatement, findingID.String(), w.run.String(), w.registration.String(),
		string(w.client), field, string(w.class), string(desired), string(observed), actor,
		w.changedAt, w.detectedAt, w.convergedAt); err != nil {
		return fmt.Errorf("reconcile: insert finding: %w", err)
	}
	return nil
}

const convergeStatement = `UPDATE identity.registration_finding
SET converged_at = $2, run_id = $3
WHERE finding_id = $1 AND converged_at IS NULL`

func convergeFinding(ctx context.Context, tx db.Tx, finding id.UUID, at time.Time, run id.UUID) error {
	if _, err := tx.Exec(ctx, convergeStatement, finding.String(), at, run.String()); err != nil {
		return fmt.Errorf("reconcile: converge finding: %w", err)
	}
	return nil
}
