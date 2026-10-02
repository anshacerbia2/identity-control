// Package providerauthority holds this service's projection of Organization's
// provider:identity-control grants and activations (ADR-ORG-002 §5.3, TDD-identity-control-006).
//
// Organization Control publishes each transition of such a grant as one event carrying the grant's
// whole state and a grant_version. This package applies them: once per event, by version, in the
// transaction that registers the event with the inbox guard.
package providerauthority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/inbox"
)

// Consumer is this service's name as an Organization projection consumer: the inbox key, and the
// consumer_id Organization Control registers and delivers to.
const Consumer = "identity-control"

// Scope is the provider scope this projection holds. Organization publishes no other.
const Scope = "provider:identity-control"

// The provider grant event types (TDD-organization-control-001 §Provider Authority Projection).
const (
	EventGranted   event.Type = "com.scnehaux.organization.provider.lifecycle.granted"
	EventActivated event.Type = "com.scnehaux.organization.provider.lifecycle.activated"
	EventEnded     event.Type = "com.scnehaux.organization.provider.security.ended"
	EventRevoked   event.Type = "com.scnehaux.organization.provider.security.revoked"
)

// EventTypes are what this service subscribes to when it registers with Organization Control.
var EventTypes = []event.Type{EventGranted, EventActivated, EventEnded, EventRevoked}

var (
	// ErrUnknownType refuses an event this projection does not apply. Organization delivers only
	// the subscribed types, so one arriving here is a producer defect, and poison.
	ErrUnknownType = errors.New("providerauthority: the event type is not one this projection applies")

	// ErrMalformed refuses a payload this projection cannot read, or one naming another scope.
	ErrMalformed = errors.New("providerauthority: the payload is not a provider:identity-control grant")
)

// Transactor is the transaction source: foundation-platform's *db.Pool.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Grant is one grant's whole state, as an event or a snapshot row carries it.
type Grant struct {
	GrantID      id.UUID     `json:"grant_id"`
	PrincipalID  id.UUID     `json:"principal_id"`
	Scope        string      `json:"scope"`
	Kind         string      `json:"kind"`
	GrantStatus  string      `json:"grant_status"`
	GrantVersion int64       `json:"grant_version"`
	Activation   *Activation `json:"activation"`
}

// Activation is the activation in force when the state was published.
type Activation struct {
	ActivationID id.UUID   `json:"activation_id"`
	EndsAt       time.Time `json:"ends_at"`
}

func (g Grant) validate() error {
	switch {
	case g.GrantID.IsNil() || g.PrincipalID.IsNil():
		return fmt.Errorf("%w: grant_id and principal_id are required", ErrMalformed)
	case g.Scope != Scope:
		return fmt.Errorf("%w: the scope is not %s", ErrMalformed, Scope)
	case g.Kind != "eligible" && g.Kind != "emergency":
		return fmt.Errorf("%w: kind is eligible or emergency", ErrMalformed)
	case g.GrantStatus != "active" && g.GrantStatus != "revoked":
		return fmt.Errorf("%w: grant_status is active or revoked", ErrMalformed)
	case g.GrantVersion < 1:
		return fmt.Errorf("%w: grant_version must be positive", ErrMalformed)
	case g.Activation != nil && (g.Activation.ActivationID.IsNil() || g.Activation.EndsAt.IsZero()):
		return fmt.Errorf("%w: an activation names its id and its end", ErrMalformed)
	case g.Activation != nil && g.GrantStatus == "revoked":
		return fmt.Errorf("%w: a revoked grant carries no activation", ErrMalformed)
	}
	return nil
}

// Outcome is what applying one delivery did.
type Outcome struct {
	// Duplicate is a delivery the inbox guard had already registered: applied before.
	Duplicate bool
	// Superseded is an event whose version is not above the one held: discarded.
	Superseded bool
}

// Applied reports whether this consumer holds the event's effect, which is when the delivery may
// carry the application receipt marker (ADR-GLB-016 §5.4). A duplicate does: the guard found it
// applied. A superseded event does not: it was discarded.
func (o Outcome) Applied() bool { return !o.Superseded }

// Projection applies provider grant events and snapshots.
type Projection struct {
	tx Transactor
}

// New builds the projection on the control database.
func New(tx Transactor) (*Projection, error) {
	if tx == nil {
		return nil, errors.New("providerauthority: a transactor is required")
	}
	return &Projection{tx: tx}, nil
}

// heldVersionStatement reads the version held for the grant, locking its row. One row always: an
// unheld grant reads as version 0, which every event is above.
const heldVersionStatement = `SELECT coalesce((
    SELECT grant_version FROM identity.provider_grant WHERE grant_id = $1 FOR UPDATE), 0)`

const upsertStatement = `INSERT INTO identity.provider_grant
    (grant_id, principal_id, kind, grant_status, grant_version, activation_id, activation_ends_at, applied_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (grant_id) DO UPDATE
SET principal_id       = excluded.principal_id,
    kind               = excluded.kind,
    grant_status       = excluded.grant_status,
    grant_version      = excluded.grant_version,
    activation_id      = excluded.activation_id,
    activation_ends_at = excluded.activation_ends_at,
    applied_at         = excluded.applied_at
WHERE identity.provider_grant.grant_version < excluded.grant_version`

// advanceAppliedStatement records the highest stream position applied, for progress reports. No
// row is no bootstrap yet, and nothing is recorded until there is one.
const advanceAppliedStatement = `UPDATE identity.provider_projection
SET applied_mark = greatest(applied_mark, $1)
WHERE id = 1`

// Apply applies one delivered event, in one transaction with its inbox guard.
func (p *Projection) Apply(ctx context.Context, envelope event.Envelope) (Outcome, error) {
	switch envelope.Type {
	case EventGranted, EventActivated, EventEnded, EventRevoked:
	default:
		return Outcome{}, fmt.Errorf("%w: %s", ErrUnknownType, envelope.Type)
	}
	var grant Grant
	if err := json.Unmarshal(envelope.Data, &grant); err != nil {
		return Outcome{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := grant.validate(); err != nil {
		return Outcome{}, err
	}

	var outcome Outcome
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		first, err := inbox.Guard(ctx, tx, Consumer, envelope.ID, envelope.Type)
		if err != nil {
			return fmt.Errorf("providerauthority: inbox guard: %w", err)
		}
		if !first {
			outcome.Duplicate = true
			return nil
		}
		applied, err := upsert(ctx, tx, grant)
		if err != nil {
			return err
		}
		if !applied {
			outcome.Superseded = true
			return nil
		}
		if _, err := tx.Exec(ctx, advanceAppliedStatement, envelope.StreamPosition); err != nil {
			return fmt.Errorf("providerauthority: recording the applied position: %w", err)
		}
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

// upsert writes the grant's state when its version is above the one held, and reports whether it did.
func upsert(ctx context.Context, tx db.Tx, grant Grant) (bool, error) {
	var held int64
	if err := tx.QueryRow(ctx, heldVersionStatement, grant.GrantID.String()).Scan(&held); err != nil {
		return false, fmt.Errorf("providerauthority: reading the held version of %s: %w", grant.GrantID, err)
	}
	if held >= grant.GrantVersion {
		return false, nil
	}
	var activationID, endsAt any
	if grant.Activation != nil {
		activationID, endsAt = grant.Activation.ActivationID.String(), grant.Activation.EndsAt.UTC()
	}
	if _, err := tx.Exec(ctx, upsertStatement, grant.GrantID.String(), grant.PrincipalID.String(), grant.Kind,
		grant.GrantStatus, grant.GrantVersion, activationID, endsAt); err != nil {
		return false, fmt.Errorf("providerauthority: writing grant %s: %w", grant.GrantID, err)
	}
	return true, nil
}
