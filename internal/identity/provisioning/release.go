package provisioning

// Leaving quarantine, and the operator's listings (TDD-identity-control-001 1.18.0 §Leaving
// Quarantine, §API / Interface, §Operational Notes).
//
// A quarantined mapping is the reconciler's hold on a Principal whose invariant broke: two kernel
// users carried its identifier. Once the duplicate runbook has decided which user is the person and
// deleted the other, :release binds the mapping to the one user left and moves it to suspended, the
// containment state TDD-identity-control-005 owns. It never lands in active: access comes back only
// through :restore, which refuses while any finding about the Principal is open. That is why this
// package's state machine still holds quarantined terminal: release is not a transition the
// provisioning path makes, it hands the mapping to containment.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

var (
	// ErrReleaseRefused is a release the kernel's state does not justify: no user, or more than one,
	// carries the identifier, or the one user left is not the one the triage named. The message
	// names the count or the mismatch, never a kernel identifier.
	ErrReleaseRefused = errors.New("provisioning: the kernel does not show the duplicate resolved")

	// ErrWorkloadRelease refuses a workload: its user is its client's service account, rebuilt with
	// the client, and its quarantine is not this route's.
	ErrWorkloadRelease = errors.New("provisioning: a workload's mapping is not released here")
)

// ReleaseRequest is an operator releasing a quarantined mapping to the one kernel user left.
type ReleaseRequest struct {
	PrincipalID id.UUID
	ReleasedBy  id.UUID
	Reason      string

	// Username is the kernel user the triage decided is the person. Release refuses when the one
	// user carrying the identifier is not this one.
	Username string
}

// ReleaseResult is where the mapping ended: suspended, contained, until a :restore.
type ReleaseResult struct {
	PrincipalID id.UUID `json:"principal_id"`
	State       string  `json:"state"`
}

const stateReleased = "suspended"

const lockQuarantinedStatement = `SELECT subject_type, state, realm, coalesce(keycloak_user_id, ''),
       coalesce(quarantine_reason, '')
FROM identity.principal_mapping WHERE principal_id = $1 FOR UPDATE`

const releaseStatement = `UPDATE identity.principal_mapping
SET keycloak_user_id = $2, state = 'suspended', version = version + 1
WHERE principal_id = $1 AND state = 'quarantined'`

const releaseRecordStatement = `INSERT INTO identity.principal_release
    (release_id, principal_id, previous_keycloak_user_id, keycloak_user_id, quarantine_reason, released_by, reason)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

type quarantinedRow struct {
	subjectType, state, realm, user, reason string
}

func lockQuarantined(ctx context.Context, tx db.Tx, principalID id.UUID) (quarantinedRow, error) {
	rows, err := tx.Query(ctx, lockQuarantinedStatement, principalID.String())
	if err != nil {
		return quarantinedRow{}, fmt.Errorf("provisioning: lock the mapping: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return quarantinedRow{}, err
		}
		return quarantinedRow{}, ErrNotFound
	}
	var row quarantinedRow
	if err := rows.Scan(&row.subjectType, &row.state, &row.realm, &row.user, &row.reason); err != nil {
		return quarantinedRow{}, fmt.Errorf("provisioning: read the mapping: %w", err)
	}
	return row, nil
}

func (row quarantinedRow) admit() error {
	switch {
	case row.subjectType == string(keycloak.SubjectWorkload):
		return ErrWorkloadRelease
	case row.state != string(StateQuarantined):
		return fmt.Errorf("%w: a %s mapping is not released; only a quarantined one is", ErrInvalidTransition, row.state)
	}
	return nil
}

// Release binds a quarantined mapping to the one kernel user carrying its identifier and moves it
// to suspended, with that user disabled and its sessions ended, in one transaction that a kernel
// failure rolls back. It records the release insert-only, naming who released it and why.
func (p *Provisioner) Release(ctx context.Context, req ReleaseRequest) (ReleaseResult, error) {
	switch {
	case strings.TrimSpace(req.Reason) == "":
		return ReleaseResult{}, ErrReasonRequired
	case req.ReleasedBy.IsNil():
		return ReleaseResult{}, errors.New("provisioning: the releasing Principal is required")
	case strings.TrimSpace(req.Username) == "":
		return ReleaseResult{}, fmt.Errorf("%w: a release names the username the triage kept", ErrReleaseRefused)
	}

	// Read first, outside the kernel call, so a mapping that is not quarantined costs no search.
	var held quarantinedRow
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		held, err = lockQuarantined(ctx, tx, req.PrincipalID)
		return err
	}); err != nil {
		return ReleaseResult{}, err
	}
	if err := held.admit(); err != nil {
		return ReleaseResult{}, err
	}

	callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
	found, err := p.kernel.FindByPrincipalID(callCtx, keycloak.Realm(held.realm), req.PrincipalID)
	cancel()
	if err != nil {
		return ReleaseResult{}, fmt.Errorf("provisioning: search the kernel for the identifier: %w", err)
	}
	switch {
	case len(found) != 1:
		return ReleaseResult{}, fmt.Errorf("%w: %d kernel users carry this principal_id; exactly one must", ErrReleaseRefused, len(found))
	case !strings.EqualFold(found[0].Username, strings.TrimSpace(req.Username)):
		return ReleaseResult{}, fmt.Errorf("%w: the one kernel user carrying it is not the username named", ErrReleaseRefused)
	}
	user := found[0].ID

	releaseID, err := p.newID()
	if err != nil {
		return ReleaseResult{}, fmt.Errorf("provisioning: mint release_id: %w", err)
	}
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		row, err := lockQuarantined(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		if err := row.admit(); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, releaseStatement, req.PrincipalID.String(), string(user))
		if err != nil {
			return fmt.Errorf("provisioning: release the mapping: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: the mapping changed while it was being released", ErrInvalidTransition)
		}
		var previous any
		if row.user != "" {
			previous = row.user
		}
		var heldFor any
		if row.reason != "" {
			heldFor = row.reason
		}
		if _, err := tx.Exec(ctx, releaseRecordStatement, releaseID.String(), req.PrincipalID.String(), previous,
			string(user), heldFor, req.ReleasedBy.String(), strings.TrimSpace(req.Reason)); err != nil {
			return fmt.Errorf("provisioning: record the release: %w", err)
		}
		// Containment before the commit: a suspended Principal's user is disabled and holds no
		// session (TDD-identity-control-005 §Containment Is Reversible). Both calls are idempotent.
		kernelCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
		defer cancel()
		if err := p.kernel.DisableUser(kernelCtx, keycloak.Realm(row.realm), user); err != nil {
			return fmt.Errorf("provisioning: keep the released user disabled: %w", err)
		}
		if err := p.kernel.LogoutUser(kernelCtx, keycloak.Realm(row.realm), user); err != nil {
			return fmt.Errorf("provisioning: end the released user's sessions: %w", err)
		}
		return nil
	}); err != nil {
		return ReleaseResult{}, err
	}
	p.logger.WarnContext(ctx, "a quarantined mapping was released to suspended; :restore returns it to service",
		slog.String("principal_id", req.PrincipalID.String()),
		slog.String("released_by", req.ReleasedBy.String()))
	return ReleaseResult{PrincipalID: req.PrincipalID, State: stateReleased}, nil
}

// PendingMapping is a mapping in pending, as GET /v1/principals:pending lists it.
type PendingMapping struct {
	PrincipalID id.UUID              `json:"principal_id"`
	SubjectType keycloak.SubjectType `json:"subject_type"`
	Username    string               `json:"username"`
	CreatedAt   time.Time            `json:"created_at"`
	// Overdue is past IDENTITY_PENDING_RECOVERY_AFTER: recovery has had a chance to resolve it.
	Overdue bool `json:"overdue"`
}

// QuarantinedMapping is a mapping in quarantined, as GET /v1/principals:quarantined lists it.
type QuarantinedMapping struct {
	PrincipalID      id.UUID              `json:"principal_id"`
	SubjectType      keycloak.SubjectType `json:"subject_type"`
	Username         string               `json:"username"`
	QuarantinedAt    *time.Time           `json:"quarantined_at"`
	QuarantineReason string               `json:"quarantine_reason"`
	// Linked says whether the mapping holds a kernel user; one recovery quarantined holds none.
	Linked bool `json:"linked"`
}

// listLimit bounds each listing.
const listLimit = 500

const pendingListStatement = `SELECT principal_id::text, subject_type, username, created_at,
       created_at < now() - $2::interval
FROM identity.principal_mapping
WHERE realm = $1 AND state = 'pending'
ORDER BY created_at, principal_id
LIMIT $3`

const quarantinedListStatement = `SELECT principal_id::text, subject_type, username, quarantined_at,
       coalesce(quarantine_reason, ''), keycloak_user_id IS NOT NULL
FROM identity.principal_mapping
WHERE realm = $1 AND state = 'quarantined'
ORDER BY quarantined_at NULLS FIRST, principal_id
LIMIT $2`

// Pending lists the mappings in pending, oldest first.
func (p *Provisioner) Pending(ctx context.Context) ([]PendingMapping, error) {
	out := []PendingMapping{}
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, pendingListStatement, string(p.cfg.Realm), p.cfg.PendingRecoveryAfter.String(), listLimit)
		if err != nil {
			return fmt.Errorf("provisioning: read pending mappings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw, subject string
				m            PendingMapping
			)
			if err := rows.Scan(&raw, &subject, &m.Username, &m.CreatedAt, &m.Overdue); err != nil {
				return err
			}
			if m.PrincipalID, err = id.Parse(raw); err != nil {
				return err
			}
			m.SubjectType, m.CreatedAt = keycloak.SubjectType(subject), m.CreatedAt.UTC()
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// Quarantined lists the mappings in quarantined, oldest first.
func (p *Provisioner) Quarantined(ctx context.Context) ([]QuarantinedMapping, error) {
	out := []QuarantinedMapping{}
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, quarantinedListStatement, string(p.cfg.Realm), listLimit)
		if err != nil {
			return fmt.Errorf("provisioning: read quarantined mappings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw, subject string
				m            QuarantinedMapping
			)
			if err := rows.Scan(&raw, &subject, &m.Username, &m.QuarantinedAt, &m.QuarantineReason, &m.Linked); err != nil {
				return err
			}
			if m.PrincipalID, err = id.Parse(raw); err != nil {
				return err
			}
			m.SubjectType = keycloak.SubjectType(subject)
			if m.QuarantinedAt != nil {
				at := m.QuarantinedAt.UTC()
				m.QuarantinedAt = &at
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// gaugeReadTimeout bounds a gauge callback's read of the database.
const gaugeReadTimeout = 5 * time.Second

const mappingGaugeStatement = `SELECT
    count(*) FILTER (WHERE state = 'pending' AND created_at < now() - $2::interval),
    count(*) FILTER (WHERE state = 'pending' AND created_at >= now() - $2::interval),
    count(*) FILTER (WHERE state = 'quarantined')
FROM identity.principal_mapping WHERE realm = $1`

// Instrument registers the pending and quarantined gauges (TDD-identity-control-001 1.18.0
// §Operational Notes), state metrics read when the reader collects (STD-GLB-003 1.1.0 §State
// Metrics). A failed read observes nothing, so an alert on either fires on its absence too. A nil
// meter registers nothing.
func (p *Provisioner) Instrument(meter metric.Meter) error {
	if meter == nil {
		return nil
	}
	pending, err := meter.Int64ObservableGauge("identity.principal.pending",
		metric.WithDescription("Mappings in pending, by overdue: past IDENTITY_PENDING_RECOVERY_AFTER, a warning"))
	if err != nil {
		return err
	}
	quarantined, err := meter.Int64ObservableGauge("identity.principal.quarantined",
		metric.WithDescription("Mappings held in quarantined by the reconciler"))
	if err != nil {
		return err
	}
	_, err = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		ctx, cancel := context.WithTimeout(ctx, gaugeReadTimeout)
		defer cancel()
		var overdue, recent, held int64
		if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx, mappingGaugeStatement, string(p.cfg.Realm), p.cfg.PendingRecoveryAfter.String()).
				Scan(&overdue, &recent, &held)
		}); err != nil {
			p.logger.ErrorContext(ctx, "the mapping gauges could not read the mappings", slog.String("error", err.Error()))
			return err
		}
		o.ObserveInt64(pending, overdue, metric.WithAttributes(attribute.Bool("overdue", true)))
		o.ObserveInt64(pending, recent, metric.WithAttributes(attribute.Bool("overdue", false)))
		o.ObserveInt64(quarantined, held)
		return nil
	}, pending, quarantined)
	return err
}
