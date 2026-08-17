package keycloak_test

// Validate is the last guard before the remote call, and it runs there rather than only at
// the API edge because a repair script or a recovery path reaches the port directly. These
// tests exercise it on its own so that a change to it fails here rather than in whichever
// caller happened to cover it.

import (
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func mustUUID(t *testing.T) id.UUID {
	t.Helper()
	value, err := id.NewV7()
	if err != nil {
		t.Fatalf("NewV7: %v", err)
	}
	return value
}

func TestValidateAcceptsAHumanAndAWorkload(t *testing.T) {
	human := keycloak.CreateUserRequest{
		Realm: "scnehaux", Username: "operator",
		PrincipalID: mustUUID(t), SubjectType: keycloak.SubjectHuman,
	}
	if err := human.Validate(); err != nil {
		t.Errorf("human request rejected: %v", err)
	}

	workload := keycloak.CreateUserRequest{
		Realm: "scnehaux", Username: "nightly-job",
		PrincipalID: mustUUID(t), SubjectType: keycloak.SubjectWorkload,
		WorkloadOwner: mustUUID(t),
	}
	if err := workload.Validate(); err != nil {
		t.Errorf("workload request rejected: %v", err)
	}
}

// TestValidateEnforcesTheAccountabilityInvariant is the pair of cases that matter. A workload
// without an owner is a credential nobody will ever decide to revoke, and a human carrying one
// makes the claim meaningless for the products that read it to distinguish the two.
func TestValidateEnforcesTheAccountabilityInvariant(t *testing.T) {
	cases := map[string]keycloak.CreateUserRequest{
		"workload without an owner": {
			Realm: "scnehaux", Username: "job",
			PrincipalID: mustUUID(t), SubjectType: keycloak.SubjectWorkload,
		},
		"human carrying an owner": {
			Realm: "scnehaux", Username: "person",
			PrincipalID: mustUUID(t), SubjectType: keycloak.SubjectHuman,
			WorkloadOwner: mustUUID(t),
		},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if err := req.Validate(); err == nil {
				t.Fatal("Validate accepted a request violating the accountability invariant")
			}
		})
	}
}

func TestValidateRejectsMissingFields(t *testing.T) {
	cases := map[string]keycloak.CreateUserRequest{
		"no realm": {
			Username: "operator", PrincipalID: mustUUID(t), SubjectType: keycloak.SubjectHuman,
		},
		"no username": {
			Realm: "scnehaux", PrincipalID: mustUUID(t), SubjectType: keycloak.SubjectHuman,
		},
		"nil principal_id": {
			Realm: "scnehaux", Username: "operator", SubjectType: keycloak.SubjectHuman,
		},
		"unknown subject type": {
			Realm: "scnehaux", Username: "operator",
			PrincipalID: mustUUID(t), SubjectType: keycloak.SubjectType("service"),
		},
		"empty subject type": {
			Realm: "scnehaux", Username: "operator", PrincipalID: mustUUID(t),
		},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if err := req.Validate(); err == nil {
				t.Fatal("Validate accepted an incomplete request")
			}
		})
	}
}

func TestSubjectTypeValidity(t *testing.T) {
	for _, valid := range []keycloak.SubjectType{keycloak.SubjectHuman, keycloak.SubjectWorkload} {
		if !valid.Valid() {
			t.Errorf("%q reports itself invalid", valid)
		}
	}
	for _, invalid := range []keycloak.SubjectType{"", "service", "agent", "Human"} {
		if invalid.Valid() {
			t.Errorf("%q reports itself valid", invalid)
		}
	}
}

// TestMappedDistinguishesAnUnmappedUser states the property the reconciler depends on: a user
// carrying no canonical identifier is a finding, and it must be detectable rather than read as
// a user whose identifier happens to be the zero value.
func TestMappedDistinguishesAnUnmappedUser(t *testing.T) {
	mapped := keycloak.User{ID: "kc-user-0001", PrincipalID: mustUUID(t)}
	if !mapped.Mapped() {
		t.Error("a user carrying an identifier reports itself unmapped")
	}

	unmapped := keycloak.User{ID: "kc-user-0002"}
	if unmapped.Mapped() {
		t.Error("a user carrying no identifier reports itself mapped")
	}
}
