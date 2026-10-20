package keycloakfake_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

// The fake models a first credential as the kernel does (identity-kernel compat
// first_credential_test.go): a temporary password replaces the password and keeps UPDATE_PASSWORD, and
// the person's change drops it.
func TestTheFakeModelsAFirstCredential(t *testing.T) {
	ctx := context.Background()
	c := keycloakfake.New()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return at }
	principal, _ := id.NewV7()
	c.SeedPerson("r", "u1", "new.person", principal)
	if actions, err := c.UserRequiredActions(ctx, "r", "u1"); err != nil || !keycloak.OwesPassword(actions) {
		t.Fatalf("a seeded person owes %v, %v", actions, err)
	}
	if err := c.SetTemporaryPassword(ctx, "r", "u1", "FIRST"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTemporaryPassword(ctx, "r", "u1", "SECOND"); err != nil {
		t.Fatal(err)
	}
	credentials, _ := c.UserCredentials(ctx, "r", "u1")
	if value, _ := c.TemporaryPassword("u1"); value != "SECOND" || len(credentials) != 1 || !credentials[0].Created.Equal(at) {
		t.Fatalf("after two sets: %q, %+v", value, credentials)
	}
	c.ChoosePassword("u1", at.Add(time.Hour))
	actions, _ := c.UserRequiredActions(ctx, "r", "u1")
	if keycloak.OwesPassword(actions) {
		t.Fatal("the person's change left UPDATE_PASSWORD outstanding")
	}
	if _, ok := c.TemporaryPassword("u1"); ok {
		t.Fatal("the temporary value outlived the change")
	}
	if err := c.SetTemporaryPassword(ctx, "r", "gone", "X"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("an absent user: %v", err)
	}
	if _, err := c.UserRequiredActions(ctx, "other", "u1"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("another realm: %v", err)
	}
	c.FailSecurity, c.FailContainment = keycloak.ErrUnavailable, keycloak.ErrUnavailable
	if _, err := c.UserRequiredActions(ctx, "r", "u1"); err == nil {
		t.Fatal("FailSecurity was not returned")
	}
	if err := c.SetTemporaryPassword(ctx, "r", "u1", "X"); err == nil {
		t.Fatal("FailContainment was not returned")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.UserRequiredActions(cancelled, "r", "u1"); err == nil {
		t.Fatal("a cancelled read answered")
	}
	if err := c.SetTemporaryPassword(cancelled, "r", "u1", "X"); err == nil {
		t.Fatal("a cancelled set answered")
	}
}
