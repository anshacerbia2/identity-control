package keycloakfake

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The fake behaves as the adapter's contract says: a name is unique, a lost create still lands,
// adding an existing member and removing an absent one are done, and a set failure is returned.
func TestTheFakeOrganizationsKeepTheContract(t *testing.T) {
	ctx := context.Background()
	c := &Client{}
	created, err := c.CreateOrganization(ctx, "r", "t1", true)
	if err != nil || created == "" {
		t.Fatalf("create: %q, %v", created, err)
	}
	if _, err := c.CreateOrganization(ctx, "r", "t1", true); !errors.Is(err, keycloak.ErrConflict) {
		t.Errorf("a second of the same name: %v, want a conflict", err)
	}
	c.AmbiguousOrganizationCreate = true
	if _, err := c.CreateOrganization(ctx, "r", "t2", false); !errors.Is(err, keycloak.ErrAmbiguous) {
		t.Errorf("a lost create: %v", err)
	}
	if org, found, err := c.FindOrganization(ctx, "r", "t2"); err != nil || !found || org.Enabled {
		t.Errorf("the lost create landed: %+v, %v, %v", org, found, err)
	}
	if err := c.AddOrganizationMember(ctx, "r", created, "u1"); err != nil {
		t.Fatal(err)
	}
	if err := c.AddOrganizationMember(ctx, "r", created, "u1"); err != nil {
		t.Errorf("adding an existing member: %v", err)
	}
	c.SetOrganizationMember(created, "u2")
	if err := c.RemoveOrganizationMember(ctx, "r", created, "u3"); err != nil {
		t.Errorf("removing an absent member: %v", err)
	}
	if members, err := c.OrganizationMembers(ctx, "r", created); err != nil || len(members) != 2 || members[0] != "u1" {
		t.Errorf("members: %v, %v", members, err)
	}
	if err := c.RemoveOrganizationMember(ctx, "r", created, "u2"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetOrganizationEnabled(ctx, "r", created, false); err != nil {
		t.Fatal(err)
	}
	if org, err := c.GetOrganization(ctx, "r", created); err != nil || org.Enabled {
		t.Errorf("get after disabling: %+v, %v", org, err)
	}
	if listed, err := c.ListOrganizations(ctx, "r"); err != nil || len(listed) != 2 || listed[0].Name != "t1" {
		t.Errorf("list: %v, %v", listed, err)
	}
	for name, err := range map[string]error{
		"get":     func() error { _, err := c.GetOrganization(ctx, "r", "none"); return err }(),
		"enable":  c.SetOrganizationEnabled(ctx, "r", "none", true),
		"members": func() error { _, err := c.OrganizationMembers(ctx, "r", "none"); return err }(),
		"add":     c.AddOrganizationMember(ctx, "r", "none", "u1"),
		"remove":  c.RemoveOrganizationMember(ctx, "r", "none", "u1"),
	} {
		if !errors.Is(err, keycloak.ErrNotFound) {
			t.Errorf("%s on an absent Organization: %v, want not found", name, err)
		}
	}
	c.FailOrganizations = keycloak.ErrUnavailable
	if _, _, err := c.FindOrganization(ctx, "r", "t1"); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Errorf("a set failure: %v", err)
	}
	if _, err := c.ListOrganizations(ctx, "r"); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Errorf("a set failure on list: %v", err)
	}
}
