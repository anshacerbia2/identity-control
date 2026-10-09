package tenantcontext

// The operator's routes over the projection (TDD-identity-control-002 2.5.0 §Operator Routes): the
// Tenants not converged, the findings, one Tenant converged again on request, and the sweep on
// request, which is Sweep itself. None of them changes the desired state: only an event or a repair
// does, each with its inbox guard and version rule.

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
)

// ErrUnknownTenant is a re-drive of a Tenant the desired state does not hold.
var ErrUnknownTenant = errors.New("tenantcontext: the desired state holds no such Tenant")

// FindingClasses are the classes a projection finding carries (§Findings).
var FindingClasses = []string{"missing_member", "extra_member", "organization_state", "unknown_organization"}

// The listings' bounds.
const (
	unconvergedLimit     = 500
	findingsDefaultLimit = 100
	findingsMaxLimit     = 500
)

// knownTenantStatement reports whether the desired state holds the Tenant.
const knownTenantStatement = `SELECT EXISTS (SELECT 1 FROM identity.tenant_desired WHERE tenant_id = $1)`

// Redrive marks one Tenant as a sweep marks it: due now, its attempts reset when it was unresolved,
// and sweep set, so whatever its convergence has to change is recorded as a finding. It sets neither
// priority nor delivered_at: it is not a delivery. by and reason are logged, not stored.
func (r *Reconciler) Redrive(ctx context.Context, tenant, by id.UUID, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("tenantcontext: a re-drive requires a reason")
	}
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var known bool
		if err := tx.QueryRow(ctx, knownTenantStatement, tenant.String()).Scan(&known); err != nil {
			return fmt.Errorf("tenantcontext: reading tenant %s: %w", tenant, err)
		}
		if !known {
			return ErrUnknownTenant
		}
		if _, err := tx.Exec(ctx, markSweepStatement, tenant.String()); err != nil {
			return fmt.Errorf("tenantcontext: marking tenant %s: %w", tenant, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	r.metric.mark(ctx, markRedrive, false, 1)
	r.logger.WarnContext(ctx, "a Tenant was re-driven by an operator",
		slog.String("tenant_id", tenant.String()), slog.String("redriven_by", by.String()),
		slog.String("reason", strings.TrimSpace(reason)))
	return nil
}

// Unconverged is one Tenant waiting to converge or parked as unresolved.
type Unconverged struct {
	TenantID       id.UUID    `json:"tenant_id"`
	State          string     `json:"state"`
	Priority       bool       `json:"priority"`
	Sweep          bool       `json:"sweep"`
	Attempts       int        `json:"attempts"`
	LastErrorClass string     `json:"last_error_class,omitempty"`
	MarkedAt       time.Time  `json:"marked_at"`
	DeliveredAt    *time.Time `json:"delivered_at"`
	NextAttemptAt  time.Time  `json:"next_attempt_at"`
}

const unconvergedStatement = `SELECT tenant_id::text, state, priority, sweep, attempts, coalesce(last_error_class, ''),
       marked_at, delivered_at, next_attempt_at
FROM identity.tenant_convergence
WHERE state IN ('pending', 'unresolved')
ORDER BY marked_at, tenant_id
LIMIT $1`

// Unconverged lists the pending and unresolved Tenants, oldest mark first.
func (r *Reconciler) Unconverged(ctx context.Context) ([]Unconverged, error) {
	out := []Unconverged{}
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, unconvergedStatement, unconvergedLimit)
		if err != nil {
			return fmt.Errorf("tenantcontext: reading the unconverged Tenants: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw string
				u   Unconverged
			)
			if err := rows.Scan(&raw, &u.State, &u.Priority, &u.Sweep, &u.Attempts, &u.LastErrorClass, &u.MarkedAt,
				&u.DeliveredAt, &u.NextAttemptAt); err != nil {
				return err
			}
			if u.TenantID, err = id.Parse(raw); err != nil {
				return err
			}
			u.MarkedAt, u.NextAttemptAt = u.MarkedAt.UTC(), u.NextAttemptAt.UTC()
			if u.DeliveredAt != nil {
				at := u.DeliveredAt.UTC()
				u.DeliveredAt = &at
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

// Finding is one projection finding as the listing serves it.
type Finding struct {
	FindingID    id.UUID         `json:"finding_id"`
	FindingClass string          `json:"finding_class"`
	TenantID     *id.UUID        `json:"tenant_id"`
	PrincipalID  *id.UUID        `json:"principal_id"`
	Detail       json.RawMessage `json:"detail"`
	DetectedAt   time.Time       `json:"detected_at"`
}

// kernelOnlyDetail names the detail keys that carry a kernel identifier for a person. The record keeps
// them as evidence; a response never carries one (TDD-identity-control-001 §Operational Notes), and
// principal_id names the person instead.
var kernelOnlyDetail = []string{"kernel_user_id"}

const findingsStatement = `SELECT finding_id::text, finding_class, coalesce(tenant_id::text, ''),
       coalesce(principal_id::text, ''), detail::text, detected_at
FROM identity.projection_finding
WHERE ($1 = '' OR finding_class = $1)
ORDER BY detected_at DESC, finding_id DESC
LIMIT $2`

// ErrUnknownClass is a findings listing filtered by a class no finding carries.
var ErrUnknownClass = errors.New("tenantcontext: no such finding class")

// Findings lists the projection findings, newest first, of one class or all, at most limit (1 to 500,
// 100 when zero).
func (r *Reconciler) Findings(ctx context.Context, class string, limit int) ([]Finding, error) {
	switch {
	case class != "" && !slices.Contains(FindingClasses, class):
		return nil, ErrUnknownClass
	case limit == 0:
		limit = findingsDefaultLimit
	case limit < 0 || limit > findingsMaxLimit:
		return nil, fmt.Errorf("tenantcontext: a limit is 1 to %d", findingsMaxLimit)
	}
	out := []Finding{}
	err := r.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, findingsStatement, class, limit)
		if err != nil {
			return fmt.Errorf("tenantcontext: reading the findings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				rawID, tenant, principal, detail string
				f                                Finding
			)
			if err := rows.Scan(&rawID, &f.FindingClass, &tenant, &principal, &detail, &f.DetectedAt); err != nil {
				return err
			}
			if f.FindingID, err = id.Parse(rawID); err != nil {
				return err
			}
			if f.TenantID, err = optionalID(tenant); err != nil {
				return err
			}
			if f.PrincipalID, err = optionalID(principal); err != nil {
				return err
			}
			if f.Detail, err = withoutKernelUsers(detail); err != nil {
				return err
			}
			f.DetectedAt = f.DetectedAt.UTC()
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

func optionalID(raw string) (*id.UUID, error) {
	if raw == "" {
		return nil, nil
	}
	parsed, err := id.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// withoutKernelUsers is a finding's detail with every kernel user identifier removed.
func withoutKernelUsers(detail string) (json.RawMessage, error) {
	var fields map[string]any
	if err := json.Unmarshal([]byte(detail), &fields); err != nil {
		return nil, fmt.Errorf("tenantcontext: a finding's detail is not an object: %w", err)
	}
	for _, key := range kernelOnlyDetail {
		delete(fields, key)
	}
	return json.Marshal(fields)
}
