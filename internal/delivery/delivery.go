// Package delivery routes the events Organization Control's dispatcher posts to POST /v1/deliveries
// to the projection that applies each type: provider authority (TDD-identity-control-006) and the
// Tenant context (TDD-identity-control-002).
package delivery

import (
	"context"
	"errors"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/event"
)

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

// ErrPoison is an event no projection here can apply, as it is: an unknown type or an unreadable
// payload. Redelivering it fails identically forever, so the intake refuses it rather than asking
// for a retry. Each projection's own refusals wrap it.
var ErrPoison = errors.New("delivery: the event cannot be applied")

// Applier applies one delivered event.
type Applier interface {
	Apply(ctx context.Context, envelope event.Envelope) (Outcome, error)
}

// Route names the types one projection applies.
type Route struct {
	Types   []event.Type
	Applier Applier
}

// Router sends each event to the projection that applies its type.
type Router struct {
	byType map[event.Type]Applier
}

// NewRouter builds a router. A type named by two routes is refused: it would have two owners.
func NewRouter(routes ...Route) (*Router, error) {
	r := &Router{byType: map[event.Type]Applier{}}
	for _, route := range routes {
		if route.Applier == nil {
			continue
		}
		for _, t := range route.Types {
			if _, taken := r.byType[t]; taken {
				return nil, fmt.Errorf("delivery: %s is routed twice", t)
			}
			r.byType[t] = route.Applier
		}
	}
	return r, nil
}

// Apply routes one event. A type no route names is poison.
func (r *Router) Apply(ctx context.Context, envelope event.Envelope) (Outcome, error) {
	applier, ok := r.byType[envelope.Type]
	if !ok {
		return Outcome{}, fmt.Errorf("%w: no projection here applies %s", ErrPoison, envelope.Type)
	}
	return applier.Apply(ctx, envelope)
}
