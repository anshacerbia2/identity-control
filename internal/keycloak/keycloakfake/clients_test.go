package keycloakfake_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

// The registry records an admin event for every console change and every patch, as the kernel
// does, because attribution is what the reconciler's tests are about.
func TestTheRegistryRecordsWhoChangedWhat(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	registry := keycloakfake.NewRegistry("sa")
	registry.Now = func() time.Time { return at }
	registry.Put(keycloak.Client{ID: "c1", ClientID: "app", Enabled: true, RedirectURIs: []string{"https://a"}})

	registry.ConsoleChange("admin", "c1", func(c *keycloak.Client) { c.AccessTokenLifespan = 900 })
	at = at.Add(time.Minute)
	lifespan := 240
	if err := registry.PatchClient(ctx, "r", "c1", keycloak.ClientPatch{AccessTokenLifespan: &lifespan}); err != nil {
		t.Fatal(err)
	}
	registry.ConsoleChange("", "c1", func(c *keycloak.Client) { c.Enabled = false })

	events, err := registry.ClientAdminEvents(ctx, "r", at.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].UserID != "sa" || events[1].UserID != "admin" {
		t.Errorf("events = %+v, want the patch then the console change, newest first", events)
	}
	if later, _ := registry.ClientAdminEvents(ctx, "r", at.Add(time.Second)); len(later) != 0 {
		t.Errorf("events after the last one = %+v", later)
	}
	client, err := registry.GetClient(ctx, "r", "c1")
	if err != nil || client.AccessTokenLifespan != 240 || client.Enabled || registry.Patches != 1 {
		t.Errorf("client = %+v (%v), patches %d", client, err, registry.Patches)
	}
	if self, _ := registry.ServiceAccountUserID(ctx); self != "sa" {
		t.Errorf("service account = %q", self)
	}

	registry.Remove("admin", "c1")
	if _, err := registry.GetClient(ctx, "r", "c1"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("a removed client answered %v", err)
	}
	if err := registry.PatchClient(ctx, "r", "c1", keycloak.ClientPatch{}); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("patching a removed client answered %v", err)
	}
}

func TestTheRegistryFailsAsTold(t *testing.T) {
	ctx := context.Background()
	registry := keycloakfake.NewRegistry("sa")
	registry.Put(keycloak.Client{ID: "c1"})
	registry.FailGet, registry.FailPatch, registry.FailEvents = keycloak.ErrUnavailable, keycloak.ErrForbidden, keycloak.ErrForbidden
	if _, err := registry.GetClient(ctx, "r", "c1"); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Errorf("get answered %v", err)
	}
	if err := registry.PatchClient(ctx, "r", "c1", keycloak.ClientPatch{}); !errors.Is(err, keycloak.ErrForbidden) {
		t.Errorf("patch answered %v", err)
	}
	if _, err := registry.ClientAdminEvents(ctx, "r", time.Now()); !errors.Is(err, keycloak.ErrForbidden) {
		t.Errorf("events answered %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := registry.GetClient(cancelled, "r", "c1"); err == nil {
		t.Error("a cancelled get succeeded")
	}
	if err := registry.PatchClient(cancelled, "r", "c1", keycloak.ClientPatch{}); err == nil {
		t.Error("a cancelled patch succeeded")
	}
	if _, err := registry.ClientAdminEvents(cancelled, "r", time.Now()); err == nil {
		t.Error("a cancelled event read succeeded")
	}
}
