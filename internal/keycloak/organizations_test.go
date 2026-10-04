package keycloak_test

// The Organizations Admin API the Tenant context projection calls (TDD-identity-control-002 2.0.0
// §Keycloak Admin API).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

const tenant = "019235f2-4d11-7a03-b8c7-1e9f7a2c4b60"

func TestTheOrganizationsAPIIsCalledAsDocumented(t *testing.T) {
	k := &kernel{}
	k.route = func(method, path string) (int, string) {
		base := "/admin/realms/" + string(testRealm) + "/organizations"
		switch {
		case method == http.MethodGet && path == base:
			// An exact search may also match a domain; the adapter keeps only the equal name.
			return http.StatusOK, `[{"id":"o9","name":"near-` + tenant + `","alias":"x","enabled":true},
			  {"id":"o1","name":"` + tenant + `","alias":"` + tenant + `","enabled":true}]`
		case method == http.MethodGet && path == base+"/o1":
			return http.StatusOK, `{"id":"o1","name":"` + tenant + `","alias":"` + tenant + `","enabled":true,"description":"kept"}`
		case method == http.MethodPut && path == base+"/o1":
			return http.StatusNoContent, ""
		case method == http.MethodGet && path == base+"/o1/members":
			return http.StatusOK, `[{"id":"u1"},{"id":"u2"}]`
		case method == http.MethodPost && path == base+"/o1/members":
			return http.StatusConflict, `{"errorMessage":"User is already a member of the organization."}`
		case method == http.MethodDelete && path == base+"/o1/members/u3":
			return http.StatusNotFound, ""
		case method == http.MethodGet && path == base+"/gone":
			return http.StatusNotFound, ""
		}
		return http.StatusInternalServerError, ""
	}
	admin, _ := newAdmin(t, k)
	ctx := context.Background()

	org, found, err := admin.FindOrganization(ctx, testRealm, tenant)
	if err != nil || !found || org.ID != "o1" || org.Alias != tenant {
		t.Fatalf("find: %+v, %v, %v", org, found, err)
	}
	if _, found, err := admin.FindOrganization(ctx, testRealm, "another"); err != nil || found {
		t.Errorf("a name no Organization has: found %v, %v", found, err)
	}
	if !strings.Contains(k.lastQuery, "exact=true") {
		t.Errorf("the search is not exact: %s", k.lastQuery)
	}
	if got, err := admin.GetOrganization(ctx, testRealm, "o1"); err != nil || !got.Enabled {
		t.Errorf("get: %+v, %v", got, err)
	}
	if _, err := admin.GetOrganization(ctx, testRealm, "gone"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("a gone Organization: %v, want ErrNotFound", err)
	}

	if err := admin.SetOrganizationEnabled(ctx, testRealm, "o1", false); err != nil {
		t.Fatal(err)
	}
	var written map[string]any
	if err := json.Unmarshal(k.lastPutBody, &written); err != nil {
		t.Fatal(err)
	}
	if written["enabled"] != false || written["description"] != "kept" {
		t.Errorf("the update is not the live representation with enabled false: %v", written)
	}

	if members, err := admin.OrganizationMembers(ctx, testRealm, "o1"); err != nil || len(members) != 2 {
		t.Errorf("members: %v, %v", members, err)
	}
	if err := admin.AddOrganizationMember(ctx, testRealm, "o1", "u1"); err != nil {
		t.Errorf("adding a member who already belongs: %v, want done", err)
	}
	if err := admin.RemoveOrganizationMember(ctx, testRealm, "o1", "u3"); err != nil {
		t.Errorf("removing one who does not belong: %v, want done", err)
	}
	if listed, err := admin.ListOrganizations(ctx, testRealm); err != nil || len(listed) != 2 {
		t.Errorf("list: %v, %v", listed, err)
	}

	for name, call := range map[string]func() error{
		"get":     func() error { _, err := admin.GetOrganization(ctx, testRealm, ""); return err },
		"find":    func() error { _, _, err := admin.FindOrganization(ctx, testRealm, ""); return err },
		"enable":  func() error { return admin.SetOrganizationEnabled(ctx, testRealm, "", true) },
		"members": func() error { _, err := admin.OrganizationMembers(ctx, testRealm, ""); return err },
		"add":     func() error { return admin.AddOrganizationMember(ctx, testRealm, "o1", "") },
		"remove":  func() error { return admin.RemoveOrganizationMember(ctx, testRealm, "", "u1") },
	} {
		if call() == nil {
			t.Errorf("%s with a missing identifier was sent", name)
		}
	}
}

func TestAnOrganizationIsCreatedWithNoDomain(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated,
		adminLocation: "http://kernel/admin/realms/" + string(testRealm) + "/organizations/o7"}
	admin, _ := newAdmin(t, k)
	created, err := admin.CreateOrganization(context.Background(), testRealm, tenant, true)
	if err != nil || created != "o7" {
		t.Fatalf("create: %q, %v", created, err)
	}
	var body map[string]any
	if err := json.Unmarshal(k.lastBody, &body); err != nil {
		t.Fatal(err)
	}
	if body["name"] != tenant || body["alias"] != tenant || body["enabled"] != true || body["domains"] != nil {
		t.Errorf("the create body: %v", body)
	}
	if _, err := admin.CreateOrganization(context.Background(), testRealm, "", true); err == nil {
		t.Error("a create with no name was sent")
	}
}
