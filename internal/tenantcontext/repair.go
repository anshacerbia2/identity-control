package tenantcontext

// Organization's reconciliation (TDD-identity-control-002 2.2.0 §Applying a Repair, §The Report an
// Operator Posts). An operator posts this consumer's report to organization-control's reconcile
// route; organization-control publishes projection.repair.reconciled with the authoritative state
// of each Membership it found apart, which is applied here by version, as foundation-reference
// applies it.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/inbox"

	"github.com/anshacerbia2/identity-control/internal/delivery"
	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

// RepairReconciled is organization-control's reconciliation sweep, one event per sweep that found
// something.
const RepairReconciled event.Type = "com.scnehaux.organization.projection.repair.reconciled"

type repairPayload struct {
	ConsumerID string          `json:"consumer_id"`
	Mark       int64           `json:"mark"`
	Findings   []repairFinding `json:"findings"`
}

type repairFinding struct {
	Classification string      `json:"classification"`
	MembershipID   id.UUID     `json:"membership_id"`
	State          *Membership `json:"state"`
}

// absentStatement withdraws a Membership the authority never granted. No version guard: a
// Membership that does not exist in the authority has no later event that could be overtaken.
const absentStatement = `UPDATE identity.membership_desired SET membership_status = 'absent', accepted_at = now()
WHERE membership_id = $1
RETURNING tenant_id::text`

// applyRepair applies one sweep, in one transaction with its inbox guard.
func (d *Desired) applyRepair(ctx context.Context, envelope event.Envelope) (delivery.Outcome, error) {
	var payload repairPayload
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		return delivery.Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if payload.ConsumerID != providerauthority.Consumer {
		// Another consumer's sweep: its findings describe that consumer's report, not this one's.
		return delivery.Outcome{}, d.advance(ctx, envelope.StreamPosition)
	}
	for _, f := range payload.Findings {
		if f.MembershipID.IsNil() {
			return delivery.Outcome{}, fmt.Errorf("%w: a finding names no membership", ErrMalformed)
		}
		if f.State == nil {
			// Null means "authority never granted this", which only an extra can say. A missing or
			// mismatch finding without a state is a producer that sent versions alone: reading its null
			// as a removal would withdraw a Membership the authority holds.
			if f.Classification != "extra" {
				return delivery.Outcome{}, fmt.Errorf("%w: a %s finding for %s carries no state", ErrMalformed,
					f.Classification, f.MembershipID)
			}
			continue
		}
		if f.State.MembershipID != f.MembershipID {
			return delivery.Outcome{}, fmt.Errorf("%w: the state for %s names another membership", ErrMalformed,
				f.MembershipID)
		}
		if err := f.State.validate(); err != nil {
			return delivery.Outcome{}, err
		}
	}

	var (
		outcome delivery.Outcome
		marked  int64
	)
	err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		first, err := inbox.Guard(ctx, tx, providerauthority.Consumer, envelope.ID, envelope.Type)
		if err != nil {
			return fmt.Errorf("tenantcontext: inbox guard: %w", err)
		}
		if !first {
			outcome.Duplicate = true
			return nil
		}
		tenants := map[string]bool{}
		for _, f := range payload.Findings {
			if f.State == nil {
				rows, err := tx.Query(ctx, absentStatement, f.MembershipID.String())
				if err != nil {
					return fmt.Errorf("tenantcontext: withdrawing %s: %w", f.MembershipID, err)
				}
				for rows.Next() {
					var tenant string
					if err := rows.Scan(&tenant); err != nil {
						rows.Close()
						return err
					}
					tenants[tenant] = true
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					return err
				}
				continue
			}
			tenantID, statement, args := desiredWrite(f.State, nil, envelope.ID)
			if _, err := tx.Exec(ctx, statement, args...); err != nil {
				return fmt.Errorf("tenantcontext: repairing %s: %w", f.MembershipID, err)
			}
			tenants[tenantID.String()] = true
		}
		for tenant := range tenants {
			if _, err := tx.Exec(ctx, markStatement, tenant, false); err != nil {
				return fmt.Errorf("tenantcontext: marking tenant %s: %w", tenant, err)
			}
		}
		marked = int64(len(tenants))
		if _, err := tx.Exec(ctx, providerauthority.AdvanceAppliedStatement, envelope.StreamPosition); err != nil {
			return fmt.Errorf("tenantcontext: recording the applied position: %w", err)
		}
		return nil
	})
	if err != nil {
		return delivery.Outcome{}, err
	}
	// A repair is a delivery: the marks it makes are measured from it (TDD-identity-control-002 2.5.0).
	d.metric.mark(ctx, markDelivery, false, marked)
	return outcome, nil
}

// advance records an applied position for an event that changes nothing here.
func (d *Desired) advance(ctx context.Context, position int64) error {
	return d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, providerauthority.AdvanceAppliedStatement, position); err != nil {
			return fmt.Errorf("tenantcontext: recording the applied position: %w", err)
		}
		return nil
	})
}

// Report is this consumer's account of its active Memberships at the position it has applied, in
// the shape organization-control's reconcile route takes.
type Report struct {
	ConsumerID string        `json:"consumer_id"`
	Mark       int64         `json:"mark"`
	Rows       []ReportedRow `json:"rows"`
}

// ReportedRow is one active Membership and its version.
type ReportedRow struct {
	MembershipID      id.UUID `json:"membership_id"`
	MembershipVersion int64   `json:"membership_version"`
}

const appliedMarkStatement = `SELECT coalesce(max(applied_mark), 0) FROM identity.provider_projection`

const activeStatement = `SELECT membership_id::text, membership_version FROM identity.membership_desired
WHERE membership_status = 'active' ORDER BY membership_id`

// Report reads the report in one transaction, so the rows and the position describe one instant.
func (d *Desired) Report(ctx context.Context) (Report, error) {
	report := Report{ConsumerID: providerauthority.Consumer, Rows: []ReportedRow{}}
	err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, appliedMarkStatement).Scan(&report.Mark); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, activeStatement)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw string
				row ReportedRow
			)
			if err := rows.Scan(&raw, &row.MembershipVersion); err != nil {
				return err
			}
			if row.MembershipID, err = id.Parse(raw); err != nil {
				return err
			}
			report.Rows = append(report.Rows, row)
		}
		return rows.Err()
	})
	if err != nil {
		return Report{}, fmt.Errorf("tenantcontext: reading the report: %w", err)
	}
	return report, nil
}
