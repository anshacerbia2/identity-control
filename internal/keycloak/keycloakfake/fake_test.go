package keycloakfake_test

// A fake whose own behaviour is unverified makes every test that uses it unverified too.
// These tests assert the scenarios the creation and recovery suite depends on are actually
// reachable — in particular the lost-response case, which is the whole reason the pending
// state exists.

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

const realm = keycloak.Realm("scnehaux")

func mustUUID(t *testing.T) id.UUID {
	t.Helper()
	value, err := id.NewV7()
	if err != nil {
		t.Fatalf("NewV7: %v", err)
	}
	return value
}

func humanRequest(t *testing.T, username string) keycloak.CreateUserRequest {
	t.Helper()
	return keycloak.CreateUserRequest{
		Realm:       realm,
		Username:    username,
		Email:       username + "@example.com",
		PrincipalID: mustUUID(t),
		SubjectType: keycloak.SubjectHuman,
	}
}

func TestCreateThenFindReturnsExactlyOne(t *testing.T) {
	client := keycloakfake.New()
	ctx := context.Background()

	req := humanRequest(t, "operator")
	userID, err := client.CreateUser(ctx, req)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	found, err := client.FindByPrincipalID(ctx, realm, req.PrincipalID)
	if err != nil {
		t.Fatalf("FindByPrincipalID: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d users, want exactly 1", len(found))
	}
	if found[0].ID != userID {
		t.Errorf("found %q, want %q", found[0].ID, userID)
	}
	if !found[0].Mapped() {
		t.Error("created user reports itself unmapped")
	}
}

// TestAmbiguousCreateRecordsTheUser is the scenario the pending state exists for: the kernel
// committed and the caller was told the call failed. If the fake could not produce it, the
// recovery path would be untested and its first real exercise would be an incident.
func TestAmbiguousCreateRecordsTheUser(t *testing.T) {
	client := keycloakfake.New()
	client.FailCreate = keycloak.ErrAmbiguous
	client.AmbiguousCreateSucceeds = true
	ctx := context.Background()

	req := humanRequest(t, "operator")
	if _, err := client.CreateUser(ctx, req); !errors.Is(err, keycloak.ErrAmbiguous) {
		t.Fatalf("CreateUser error = %v, want ErrAmbiguous", err)
	}

	found, err := client.FindByPrincipalID(ctx, realm, req.PrincipalID)
	if err != nil {
		t.Fatalf("FindByPrincipalID: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d users, want 1: a lost response must leave the user behind", len(found))
	}
}

func TestFailedCreateWithoutCommitRecordsNothing(t *testing.T) {
	client := keycloakfake.New()
	client.FailCreate = keycloak.ErrUnavailable
	ctx := context.Background()

	req := humanRequest(t, "operator")
	if _, err := client.CreateUser(ctx, req); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("CreateUser error = %v, want ErrUnavailable", err)
	}
	if client.Count() != 0 {
		t.Errorf("fake holds %d users, want 0", client.Count())
	}
}

func TestDuplicateUsernameConflicts(t *testing.T) {
	client := keycloakfake.New()
	ctx := context.Background()

	if _, err := client.CreateUser(ctx, humanRequest(t, "operator")); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}
	_, err := client.CreateUser(ctx, humanRequest(t, "OPERATOR"))
	if !errors.Is(err, keycloak.ErrConflict) {
		t.Fatalf("second CreateUser error = %v, want ErrConflict", err)
	}
}

// TestSubstringSearchDoesNotWidenResults is the seam for the open proof-of-concept question.
// Under the pessimistic reading of Keycloak's attribute query, the port still returns exact
// matches only, so a caller written against the port is correct before the answer arrives.
func TestSubstringSearchDoesNotWidenResults(t *testing.T) {
	ctx := context.Background()

	for _, mode := range []struct {
		name string
		mode keycloakfake.SearchSemantics
	}{
		{"exact", keycloakfake.SearchExact},
		{"substring", keycloakfake.SearchSubstring},
	} {
		t.Run(mode.name, func(t *testing.T) {
			client := keycloakfake.New()
			client.SearchMode = mode.mode

			wanted := humanRequest(t, "wanted")
			if _, err := client.CreateUser(ctx, wanted); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			other := humanRequest(t, "other")
			if _, err := client.CreateUser(ctx, other); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}

			found, err := client.FindByPrincipalID(ctx, realm, wanted.PrincipalID)
			if err != nil {
				t.Fatalf("FindByPrincipalID: %v", err)
			}
			if len(found) != 1 {
				t.Fatalf("found %d users, want 1", len(found))
			}
			if found[0].PrincipalID != wanted.PrincipalID {
				t.Errorf("found principal %s, want %s", found[0].PrincipalID, wanted.PrincipalID)
			}
		})
	}
}

// TestDuplicateAttributeIsReachable models the invariant Keycloak cannot enforce. The
// reconciler quarantines both users rather than choosing one, and it can only be tested if
// the state is constructible.
func TestDuplicateAttributeIsReachable(t *testing.T) {
	client := keycloakfake.New()
	ctx := context.Background()

	shared := mustUUID(t)
	client.Seed(realm, "first", shared, keycloak.SubjectHuman)
	client.Seed(realm, "second", shared, keycloak.SubjectHuman)

	found, err := client.FindByPrincipalID(ctx, realm, shared)
	if err != nil {
		t.Fatalf("FindByPrincipalID: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d users, want 2: Keycloak enforces no attribute uniqueness", len(found))
	}
}

// TestUnmappedUserIsReachable models a Principal that arrived through a creation path that
// should be closed. It reports itself unmapped rather than erroring, because the reconciler
// treats it as a finding.
func TestUnmappedUserIsReachable(t *testing.T) {
	client := keycloakfake.New()
	ctx := context.Background()

	client.Seed(realm, "console-created", id.UUID{}, keycloak.SubjectHuman)

	users, err := client.ListUsers(ctx, realm, keycloak.Page{First: 0, Max: 10})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("listed %d users, want 1", len(users))
	}
	if users[0].Mapped() {
		t.Error("seeded user without an attribute reports itself mapped")
	}
}

func TestListUsersPagesWithoutOverlapOrGap(t *testing.T) {
	client := keycloakfake.New()
	ctx := context.Background()

	const total = 7
	for i := range total {
		if _, err := client.CreateUser(ctx, humanRequest(t, string(rune('a'+i)))); err != nil {
			t.Fatalf("CreateUser %d: %v", i, err)
		}
	}

	seen := map[keycloak.UserID]bool{}
	for first := 0; ; first += 3 {
		page, err := client.ListUsers(ctx, realm, keycloak.Page{First: first, Max: 3})
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, user := range page {
			if seen[user.ID] {
				t.Fatalf("user %q returned by two pages", user.ID)
			}
			seen[user.ID] = true
		}
	}
	if len(seen) != total {
		t.Errorf("paged enumeration saw %d users, want %d", len(seen), total)
	}
}

// TestDisableIsIdempotentAndNeverDeletes asserts the containment property directly.
// TDD-identity-control-001 chooses disable over delete because a reconciler defect must be
// recoverable, and a deleted Principal is not.
func TestDisableIsIdempotentAndNeverDeletes(t *testing.T) {
	client := keycloakfake.New()
	ctx := context.Background()

	userID := client.Seed(realm, "suspect", mustUUID(t), keycloak.SubjectHuman)

	for attempt := range 2 {
		if err := client.DisableUser(ctx, realm, userID); err != nil {
			t.Fatalf("DisableUser attempt %d: %v", attempt, err)
		}
	}

	user, ok := client.User(userID)
	if !ok {
		t.Fatal("user was removed; disable must never delete")
	}
	if user.Enabled {
		t.Error("user is still enabled after DisableUser")
	}
	if client.Count() != 1 {
		t.Errorf("fake holds %d users, want 1", client.Count())
	}
}

func TestValidationRejectsInconsistentSubjects(t *testing.T) {
	client := keycloakfake.New()
	ctx := context.Background()

	cases := map[string]keycloak.CreateUserRequest{
		"workload without an owner": {
			Realm: realm, Username: "job", PrincipalID: mustUUID(t),
			SubjectType: keycloak.SubjectWorkload,
		},
		"human carrying an owner": {
			Realm: realm, Username: "person", PrincipalID: mustUUID(t),
			SubjectType: keycloak.SubjectHuman, WorkloadOwner: mustUUID(t),
		},
		"nil principal_id": {
			Realm: realm, Username: "person", SubjectType: keycloak.SubjectHuman,
		},
		"unknown subject type": {
			Realm: realm, Username: "person", PrincipalID: mustUUID(t),
			SubjectType: keycloak.SubjectType("service"),
		},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := client.CreateUser(ctx, req); err == nil {
				t.Fatal("CreateUser accepted an invalid request")
			}
			if client.Count() != 0 {
				t.Errorf("fake recorded %d users for a rejected request", client.Count())
			}
		})
	}
}
