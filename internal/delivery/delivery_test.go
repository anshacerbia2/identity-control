package delivery

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/event"
)

type recorder struct{ got []event.Type }

func (r *recorder) Apply(_ context.Context, envelope event.Envelope) (Outcome, error) {
	r.got = append(r.got, envelope.Type)
	return Outcome{}, nil
}

func TestTheRouterSendsEachTypeToItsProjection(t *testing.T) {
	provider, tenant := &recorder{}, &recorder{}
	router, err := NewRouter(Route{Types: []event.Type{"a.provider"}, Applier: provider},
		Route{Types: []event.Type{"a.tenant"}, Applier: tenant})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, eventType := range []event.Type{"a.provider", "a.tenant"} {
		if _, err := router.Apply(ctx, event.Envelope{Type: eventType}); err != nil {
			t.Fatal(err)
		}
	}
	if len(provider.got) != 1 || len(tenant.got) != 1 {
		t.Errorf("provider %v, tenant %v", provider.got, tenant.got)
	}
	if _, err := router.Apply(ctx, event.Envelope{Type: "a.workspace"}); !errors.Is(err, ErrPoison) {
		t.Errorf("an unrouted type: %v, want poison", err)
	}
	if _, err := NewRouter(Route{Types: []event.Type{"a"}, Applier: provider},
		Route{Types: []event.Type{"a"}, Applier: tenant}); err == nil {
		t.Error("a type routed twice was accepted")
	}
}
