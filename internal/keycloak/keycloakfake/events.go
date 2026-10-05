package keycloakfake

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// Events is an in-memory kernel event store.
type Events struct {
	mu     sync.Mutex
	events map[string][]keycloak.KernelEvent

	// Bound truncates a read after this many events of one kind, newest first, when positive.
	Bound int

	// Fail is returned by every read when set.
	Fail error

	// Reads counts the reads, per kind, and Since records the instant each asked from.
	Reads map[string]int
	Since map[string][]time.Time
}

// NewEvents builds an empty store.
func NewEvents() *Events {
	return &Events{events: map[string][]keycloak.KernelEvent{}, Reads: map[string]int{}, Since: map[string][]time.Time{}}
}

// Record adds events as the kernel records them.
func (e *Events) Record(events ...keycloak.KernelEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, event := range events {
		e.events[event.Kind] = append(e.events[event.Kind], event)
	}
}

// KernelEvents reads newest first, from since, bounded as the real read is.
func (e *Events) KernelEvents(_ context.Context, _ keycloak.Realm, kind string, since time.Time) ([]keycloak.KernelEvent, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Reads[kind]++
	e.Since[kind] = append(e.Since[kind], since)
	if e.Fail != nil {
		return nil, false, e.Fail
	}
	held := append([]keycloak.KernelEvent{}, e.events[kind]...)
	sort.SliceStable(held, func(i, j int) bool { return held[i].Time.After(held[j].Time) })
	var out []keycloak.KernelEvent
	for _, event := range held {
		if event.Time.Before(since) {
			continue
		}
		if e.Bound > 0 && len(out) == e.Bound {
			return out, true, nil
		}
		out = append(out, event)
	}
	return out, false, nil
}

var _ keycloak.EventStore = (*Events)(nil)
