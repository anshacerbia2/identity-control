package providerauthority

// Emergency grant validation (ADR-ORG-002 §5.2, TDD-identity-control-006 §Emergency Grant
// Validation). A projected emergency grant is validated by using it: every request it authorizes
// records its last use here, and one unused for longer than ValidationPeriod is overdue. The
// Organization Control API records and reports its own scope; this service sees only its own.

import (
	"context"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// ValidationPeriod is Microsoft's interval for an emergency access drill, "At least every 90 days".
const ValidationPeriod = 90 * 24 * time.Hour

// EmergencyValidation is one active projected emergency grant and its last use.
type EmergencyValidation struct {
	GrantID     id.UUID    `json:"grant_id"`
	PrincipalID id.UUID    `json:"principal_id"`
	HeldSince   time.Time  `json:"held_since"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	Uses        int64      `json:"uses"`
	// DueAt is ValidationPeriod after the last use, or after HeldSince when it was never used.
	DueAt   time.Time `json:"due_at"`
	Overdue bool      `json:"overdue"`
}

// recordUseStatement records a request the Principal's projected emergency grant authorized. The
// grant is found again here, so one revoked between the decision and the write records nothing.
const recordUseStatement = `INSERT INTO identity.provider_emergency_use AS u (grant_id)
SELECT grant_id FROM identity.provider_grant
WHERE principal_id = $1 AND grant_status = 'active' AND kind = 'emergency'
ON CONFLICT (grant_id) DO UPDATE SET last_used_at = now(), uses = u.uses + 1`

// RecordEmergencyUse records that a request was authorized by the Principal's projected emergency
// grant. The ceremony's grant is not recorded: it is retired by the first emergency grant projected.
func (d *Decider) RecordEmergencyUse(ctx context.Context, principal id.UUID) error {
	if err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, recordUseStatement, principal.String())
		return err
	}); err != nil {
		return fmt.Errorf("providerauthority: recording an emergency grant's use: %w", err)
	}
	return nil
}

// validationStatement lists every active projected emergency grant with its last use, the oldest
// due first. A grant is held from when this service first applied it.
const validationStatement = `SELECT g.grant_id::text, g.principal_id::text, g.first_applied_at, u.last_used_at,
       coalesce(u.uses, 0)
FROM identity.provider_grant g
LEFT JOIN identity.provider_emergency_use u ON u.grant_id = g.grant_id
WHERE g.kind = 'emergency' AND g.grant_status = 'active'
ORDER BY coalesce(u.last_used_at, g.first_applied_at), g.grant_id`

// EmergencyValidation reads the report at now.
func (d *Decider) EmergencyValidation(ctx context.Context, now time.Time) ([]EmergencyValidation, error) {
	out := []EmergencyValidation{}
	err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, validationStatement)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				v                  EmergencyValidation
				grantID, principal string
			)
			if err := rows.Scan(&grantID, &principal, &v.HeldSince, &v.LastUsedAt, &v.Uses); err != nil {
				return err
			}
			if v.GrantID, err = id.Parse(grantID); err != nil {
				return err
			}
			if v.PrincipalID, err = id.Parse(principal); err != nil {
				return err
			}
			from := v.HeldSince
			if v.LastUsedAt != nil {
				from = *v.LastUsedAt
			}
			v.DueAt = from.Add(ValidationPeriod)
			v.Overdue = now.After(v.DueAt)
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("providerauthority: reading emergency grant validation: %w", err)
	}
	return out, nil
}
