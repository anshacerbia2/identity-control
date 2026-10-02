package providerauthority

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// The bases a provider decision rests on.
const (
	// BasisCeremony is the ceremony's local emergency grant, honored until the first emergency
	// grant is projected (TDD-identity-control-006 §The Ceremony's Grant).
	BasisCeremony = "ceremony"
	// BasisEmergency is an active emergency grant: standing, honored while stale.
	BasisEmergency = "emergency"
	// BasisActivation is an activation in force of an eligible grant, honored only while fresh.
	BasisActivation = "activation"
)

// Decision is whether a Principal is a provider for one request, and on what basis.
type Decision struct {
	Provider bool
	Basis    string

	// Emergency is break-glass authority, the ceremony's or an emergency grant's. Each use is
	// reported (ADR-ORG-002 §5.2).
	Emergency bool

	// Stale is an activation in force that was not honored, because the projection is not fresh,
	// and StaleReason why.
	Stale       bool
	StaleReason string
}

// FreshnessReader is the held freshness observation: *Freshness in production.
type FreshnessReader interface {
	Fresh() (bool, string)
}

// unconfigured is the freshness of a process that reads no frontier: never fresh.
type unconfigured struct{}

func (unconfigured) Fresh() (bool, string) { return false, StaleUnobserved }

// Decider makes the per-request provider decision from the local projection and the held
// freshness, with no network call (TDD-identity-control-006 §The Provider Decision).
type Decider struct {
	tx        Transactor
	freshness FreshnessReader
	now       func() time.Time
}

// NewDecider builds the decision. A nil freshness is a process that reads no frontier: activations
// are never honored, and emergency authority is.
func NewDecider(tx Transactor, freshness FreshnessReader) (*Decider, error) {
	if tx == nil {
		return nil, errors.New("providerauthority: a transactor is required")
	}
	if freshness == nil {
		freshness = unconfigured{}
	}
	return &Decider{tx: tx, freshness: freshness, now: time.Now}, nil
}

// decideStatement reads, in one row, what the projection holds for the Principal: the unretired
// ceremony grant, an active emergency grant, and an activation in force at $2 on this process's
// clock. Each is an indexed read.
const decideStatement = `SELECT
    EXISTS (SELECT 1 FROM identity.bootstrap_ceremony
             WHERE principal_id = $1
               AND NOT EXISTS (SELECT 1 FROM identity.ceremony_grant_retirement)),
    EXISTS (SELECT 1 FROM identity.provider_grant
             WHERE principal_id = $1 AND grant_status = 'active' AND kind = 'emergency'),
    EXISTS (SELECT 1 FROM identity.provider_grant
             WHERE principal_id = $1 AND grant_status = 'active' AND activation_ends_at > $2)`

// Decide answers whether principal is a provider at this instant. An activation's natural end
// takes effect at once, from its recorded end; an early end or a revocation takes effect when its
// event is applied, or the projection reads stale and activations stop.
func (d *Decider) Decide(ctx context.Context, principal id.UUID) (Decision, error) {
	if principal.IsNil() {
		return Decision{}, nil
	}
	var ceremony, emergency, activation bool
	err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, decideStatement, principal.String(), d.now().UTC()).
			Scan(&ceremony, &emergency, &activation)
	})
	if err != nil {
		return Decision{}, fmt.Errorf("providerauthority: reading the provider decision: %w", err)
	}
	switch {
	case ceremony:
		return Decision{Provider: true, Basis: BasisCeremony, Emergency: true}, nil
	case emergency:
		return Decision{Provider: true, Basis: BasisEmergency, Emergency: true}, nil
	case activation:
		if fresh, reason := d.freshness.Fresh(); !fresh {
			return Decision{Stale: true, StaleReason: reason}, nil
		}
		return Decision{Provider: true, Basis: BasisActivation}, nil
	}
	return Decision{}, nil
}
