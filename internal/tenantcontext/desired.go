// Package tenantcontext projects Organization's Tenants and Memberships into the identity kernel
// (TDD-identity-control-002 2.0.0, ADR-IAM-006). Each Tenant is a Keycloak Organization whose alias
// is the tenant_id, and its members are the Principals holding an active Membership.
//
// Delivery updates a desired state and marks its Tenant; a converger makes the kernel match it. The
// kernel is changed from the desired state, never by replaying an event, so a missed, duplicated or
// reordered event changes nothing a later convergence does not correct: "Level driven, not edge
// driven" (Kubernetes, Writing Controllers).
package tenantcontext

import (
	"go.opentelemetry.io/otel/metric"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/inbox"

	"github.com/anshacerbia2/identity-control/internal/delivery"
	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

// The Membership and Tenant event types Organization Control offers a consumer
// (TDD-organization-control-002).
const (
	MembershipGranted   event.Type = "com.scnehaux.organization.membership.lifecycle.granted"
	MembershipRestored  event.Type = "com.scnehaux.organization.membership.lifecycle.restored"
	MembershipSuspended event.Type = "com.scnehaux.organization.membership.security.suspended"
	MembershipRevoked   event.Type = "com.scnehaux.organization.membership.security.revoked"
	TenantActivated     event.Type = "com.scnehaux.organization.tenant.lifecycle.activated"
	TenantRetired       event.Type = "com.scnehaux.organization.tenant.lifecycle.retired"
	TenantSuspended     event.Type = "com.scnehaux.organization.tenant.security.suspended"
	TenantRestored      event.Type = "com.scnehaux.organization.tenant.security.restored"
)

// EventTypes are what this projection applies, and what this service adds to its registration.
var EventTypes = []event.Type{MembershipGranted, MembershipRestored, MembershipSuspended, MembershipRevoked,
	TenantActivated, TenantRetired, TenantSuspended, TenantRestored, RepairReconciled}

var membershipTypes = map[event.Type]bool{MembershipGranted: true, MembershipRestored: true,
	MembershipSuspended: true, MembershipRevoked: true}

var tenantTypes = map[event.Type]bool{TenantActivated: true, TenantRetired: true, TenantSuspended: true,
	TenantRestored: true}

var (
	// ErrUnknownType refuses an event this projection does not apply.
	ErrUnknownType = fmt.Errorf("tenantcontext: the event type is not one this projection applies: %w",
		delivery.ErrPoison)

	// ErrMalformed refuses a payload this projection cannot read.
	ErrMalformed = fmt.Errorf("tenantcontext: the payload is not a Membership or Tenant state: %w",
		delivery.ErrPoison)
)

// Priority reports whether a type travels the priority lane: exactly when its class, the fifth
// segment, is security. Organization Control routes its lanes by the same rule.
func Priority(t event.Type) bool {
	segments := strings.Split(string(t), ".")
	return len(segments) >= 5 && segments[4] == "security"
}

// Membership is one Membership's state, as an event carries it.
type Membership struct {
	MembershipID      id.UUID `json:"membership_id"`
	PrincipalID       id.UUID `json:"principal_id"`
	TenantID          id.UUID `json:"tenant_id"`
	MembershipStatus  string  `json:"membership_status"`
	MembershipVersion int64   `json:"membership_version"`
}

// Tenant is one Tenant's state, as an event carries it.
type Tenant struct {
	TenantID              id.UUID `json:"tenant_id"`
	TenantStatus          string  `json:"tenant_status"`
	TenantVersion         int64   `json:"tenant_version"`
	TenantSecurityVersion int64   `json:"tenant_security_version"`
}

var membershipStatuses = map[string]bool{"active": true, "suspended": true, "revoked": true}

var tenantStatuses = map[string]bool{"active": true, "suspended": true, "offboarding": true, "retired": true}

func (m Membership) validate() error {
	switch {
	case m.MembershipID.IsNil() || m.PrincipalID.IsNil() || m.TenantID.IsNil():
		return fmt.Errorf("%w: membership_id, principal_id and tenant_id are required", ErrMalformed)
	case !membershipStatuses[m.MembershipStatus]:
		return fmt.Errorf("%w: membership_status %q", ErrMalformed, m.MembershipStatus)
	case m.MembershipVersion < 1:
		return fmt.Errorf("%w: membership_version must be positive", ErrMalformed)
	}
	return nil
}

func (t Tenant) validate() error {
	switch {
	case t.TenantID.IsNil():
		return fmt.Errorf("%w: tenant_id is required", ErrMalformed)
	case !tenantStatuses[t.TenantStatus]:
		return fmt.Errorf("%w: tenant_status %q", ErrMalformed, t.TenantStatus)
	case t.TenantVersion < 1:
		return fmt.Errorf("%w: tenant_version must be positive", ErrMalformed)
	}
	return nil
}

// Transactor is the transaction source: foundation-platform's *db.Pool.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Desired applies delivered events to the desired state.
type Desired struct {
	tx     Transactor
	metric shared
}

// NewDesired builds the intake on the control database. It records no metric until Instrument.
func NewDesired(tx Transactor) (*Desired, error) {
	if tx == nil {
		return nil, errors.New("tenantcontext: a transactor is required")
	}
	metrics, err := newShared(nil)
	if err != nil {
		return nil, err
	}
	return &Desired{tx: tx, metric: metrics}, nil
}

// Instrument counts the intake's marks on the meter (TDD-identity-control-002 2.5.0). A nil meter
// counts nothing.
func (d *Desired) Instrument(meter metric.Meter) error {
	metrics, err := newShared(meter)
	if err != nil {
		return err
	}
	d.metric = metrics
	return nil
}

// upsertMembershipStatement writes a Membership's state when its version is above the one held.
// The conditional update makes the comparison and the write one statement: a lower version updates
// no row, which is how it is told superseded.
const upsertMembershipStatement = `INSERT INTO identity.membership_desired
    (membership_id, principal_id, tenant_id, membership_status, membership_version, source_event_id, accepted_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (membership_id) DO UPDATE
SET principal_id       = excluded.principal_id,
    tenant_id          = excluded.tenant_id,
    membership_status  = excluded.membership_status,
    membership_version = excluded.membership_version,
    source_event_id    = excluded.source_event_id,
    accepted_at        = excluded.accepted_at
WHERE identity.membership_desired.membership_version < excluded.membership_version`

const upsertTenantStatement = `INSERT INTO identity.tenant_desired
    (tenant_id, tenant_status, tenant_version, tenant_security_version, source_event_id, accepted_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (tenant_id) DO UPDATE
SET tenant_status           = excluded.tenant_status,
    tenant_version          = excluded.tenant_version,
    tenant_security_version = excluded.tenant_security_version,
    source_event_id         = excluded.source_event_id,
    accepted_at             = excluded.accepted_at
WHERE identity.tenant_desired.tenant_version < excluded.tenant_version`

// markStatement marks a Tenant to converge. A priority mark is due now and stays priority until the
// Tenant converges. A standard mark is due now unless the Tenant is already pending and backing off,
// whose schedule it keeps. Either clears an unresolved Tenant's attempts: new desired state is a
// new reason to try. It sets delivered_at when none is held, so the delay is measured from the first
// delivery the Tenant has not converged (TDD-identity-control-002 2.5.0).
const markStatement = `INSERT INTO identity.tenant_convergence (tenant_id, priority, marked_at, next_attempt_at, state, delivered_at)
VALUES ($1, $2, now(), now(), 'pending', now())
ON CONFLICT (tenant_id) DO UPDATE
SET priority        = identity.tenant_convergence.priority OR excluded.priority,
    marked_at       = now(),
    delivered_at    = coalesce(identity.tenant_convergence.delivered_at, now()),
    next_attempt_at = CASE
        WHEN excluded.priority OR identity.tenant_convergence.state <> 'pending' THEN now()
        ELSE identity.tenant_convergence.next_attempt_at END,
    attempts        = CASE WHEN identity.tenant_convergence.state = 'unresolved' THEN 0
        ELSE identity.tenant_convergence.attempts END,
    state           = 'pending'`

// Apply applies one delivered event, in one transaction with its inbox guard.
func (d *Desired) Apply(ctx context.Context, envelope event.Envelope) (delivery.Outcome, error) {
	if envelope.Type == RepairReconciled {
		return d.applyRepair(ctx, envelope)
	}
	var (
		membership *Membership
		tenant     *Tenant
	)
	switch {
	case membershipTypes[envelope.Type]:
		membership = &Membership{}
		if err := json.Unmarshal(envelope.Data, membership); err != nil {
			return delivery.Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if err := membership.validate(); err != nil {
			return delivery.Outcome{}, err
		}
	case tenantTypes[envelope.Type]:
		tenant = &Tenant{}
		if err := json.Unmarshal(envelope.Data, tenant); err != nil {
			return delivery.Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		if err := tenant.validate(); err != nil {
			return delivery.Outcome{}, err
		}
	default:
		return delivery.Outcome{}, fmt.Errorf("%w: %s", ErrUnknownType, envelope.Type)
	}

	var outcome delivery.Outcome
	err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		first, err := inbox.Guard(ctx, tx, providerauthority.Consumer, envelope.ID, envelope.Type)
		if err != nil {
			return fmt.Errorf("tenantcontext: inbox guard: %w", err)
		}
		if !first {
			outcome.Duplicate = true
			return nil
		}
		tenantID, statement, args := desiredWrite(membership, tenant, envelope.ID)
		tag, err := tx.Exec(ctx, statement, args...)
		if err != nil {
			return fmt.Errorf("tenantcontext: writing the desired state for tenant %s: %w", tenantID, err)
		}
		if tag.RowsAffected() == 0 {
			outcome.Superseded = true
			return nil
		}
		if _, err := tx.Exec(ctx, markStatement, tenantID.String(), Priority(envelope.Type)); err != nil {
			return fmt.Errorf("tenantcontext: marking tenant %s: %w", tenantID, err)
		}
		if _, err := tx.Exec(ctx, providerauthority.AdvanceAppliedStatement, envelope.StreamPosition); err != nil {
			return fmt.Errorf("tenantcontext: recording the applied position: %w", err)
		}
		return nil
	})
	if err != nil {
		return delivery.Outcome{}, err
	}
	if !outcome.Duplicate && !outcome.Superseded {
		d.metric.mark(ctx, markDelivery, Priority(envelope.Type), 1)
	}
	return outcome, nil
}

// desiredWrite is the statement and arguments that write one event's desired state, and the Tenant
// it belongs to.
func desiredWrite(membership *Membership, tenant *Tenant, eventID id.UUID) (id.UUID, string, []any) {
	if membership != nil {
		return membership.TenantID, upsertMembershipStatement, []any{membership.MembershipID.String(),
			membership.PrincipalID.String(), membership.TenantID.String(), membership.MembershipStatus,
			membership.MembershipVersion, eventID.String()}
	}
	return tenant.TenantID, upsertTenantStatement, []any{tenant.TenantID.String(), tenant.TenantStatus,
		tenant.TenantVersion, tenant.TenantSecurityVersion, eventID.String()}
}
