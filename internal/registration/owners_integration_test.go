package registration

// Registration ownership against the real database (ADR-IAM-003, TDD-identity-control-003
// §Registration Ownership).

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// person records an active human Principal's mapping, as the Principal path leaves one.
func (h *harness) person(subjectType string) id.UUID {
	h.t.Helper()
	principalID, _ := id.NewV7()
	var owner any
	if subjectType == "workload" {
		owner = h.caller.String()
	}
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
		    (principal_id, realm, username, subject_type, workload_owner, keycloak_user_id, state)
		    VALUES ($1, $2, $3, $4, $5, $6, 'active')`,
			principalID.String(), string(testRealm), "owner-"+principalID.String(), subjectType, owner,
			"kc-"+principalID.String())
		return err
	}); err != nil {
		h.t.Fatalf("record a Principal: %v", err)
	}
	h.t.Cleanup(func() {
		_ = h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM identity.principal_mapping WHERE principal_id = $1`, principalID.String())
			return err
		})
	})
	return principalID
}

func (h *harness) setMapping(principalID id.UUID, state string) {
	h.t.Helper()
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.principal_mapping SET state = $2 WHERE principal_id = $1`,
			principalID.String(), state)
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
}

func TestAnOwnerIsAnActivePersonAndOwnsWhatItWasGranted(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	registration := h.resource("owned-api", "L1")
	other := h.resource("other-api", "L1")
	alice, workload := h.person("human"), h.person("workload")
	change := func(principal id.UUID) OwnershipChange {
		return OwnershipChange{RegistrationID: registration.ID, Principal: principal, ChangedBy: h.caller, Reason: "the orders team"}
	}

	if _, err := h.service.GrantOwner(ctx, change(workload)); !errors.Is(err, ErrOwnerNotEligible) {
		t.Errorf("granting a workload answered %v, want ErrOwnerNotEligible", err)
	}
	if _, err := h.service.GrantOwner(ctx, OwnershipChange{RegistrationID: registration.ID, Principal: alice, ChangedBy: h.caller}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a grant without a reason answered %v, want ErrInvalid", err)
	}
	owners, err := h.service.GrantOwner(ctx, change(alice))
	if err != nil || len(owners) != 1 || !owners[0].Active || owners[0].GrantedBy != h.caller {
		t.Fatalf("grant: %+v, %v", owners, err)
	}
	if _, err := h.service.GrantOwner(ctx, change(alice)); !errors.Is(err, ErrAlreadyOwner) {
		t.Errorf("a second grant answered %v, want ErrAlreadyOwner", err)
	}

	if owns, _ := h.service.Owns(ctx, alice, registration.ID); !owns {
		t.Error("the owner does not own its registration")
	}
	if owns, _ := h.service.Owns(ctx, alice, other.ID); owns {
		t.Error("the owner owns a registration it was never granted")
	}
	if mine, _ := h.service.Mine(ctx, alice); len(mine) != 1 || mine[0].ID != registration.ID {
		t.Errorf("mine = %+v", mine)
	}

	// A Principal no longer active confers nothing, without anything being revoked.
	h.setMapping(alice, "quarantined")
	if owns, _ := h.service.Owns(ctx, alice, registration.ID); owns {
		t.Error("a quarantined Principal still owns its registration")
	}
	if mine, _ := h.service.Mine(ctx, alice); len(mine) != 0 {
		t.Errorf("a quarantined Principal still lists %d registrations", len(mine))
	}
}

func TestAProductionRegistrationKeepsTwoOwners(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.service.cfg.Production = true
	registration := h.resource("production-api", "L1")
	alice, bob, carol := h.person("human"), h.person("human"), h.person("human")
	for _, principal := range []id.UUID{alice, bob} {
		if _, err := h.service.GrantOwner(ctx, OwnershipChange{RegistrationID: registration.ID, Principal: principal,
			ChangedBy: h.caller, Reason: "the orders team"}); err != nil {
			t.Fatal(err)
		}
	}
	revoke := func(principal id.UUID) error {
		_, err := h.service.RevokeOwner(ctx, OwnershipChange{RegistrationID: registration.ID, Principal: principal,
			ChangedBy: h.caller, Reason: "moved team"})
		return err
	}
	if err := revoke(alice); !errors.Is(err, ErrTooFewOwners) {
		t.Errorf("revoking one of two owners answered %v, want ErrTooFewOwners", err)
	}
	if err := revoke(carol); !errors.Is(err, ErrOwnerNotFound) {
		t.Errorf("revoking a non-owner answered %v, want ErrOwnerNotFound", err)
	}

	// A third owner makes room; an owner that confers nothing can always be revoked.
	if _, err := h.service.GrantOwner(ctx, OwnershipChange{RegistrationID: registration.ID, Principal: carol,
		ChangedBy: h.caller, Reason: "joined"}); err != nil {
		t.Fatal(err)
	}
	if err := revoke(alice); err != nil {
		t.Errorf("revoking one of three owners answered %v", err)
	}
	h.setMapping(bob, "retired")
	if err := revoke(bob); err != nil {
		t.Errorf("revoking an owner that confers nothing answered %v", err)
	}
	owners, _ := h.service.Owners(ctx, registration.ID)
	revoked := 0
	for _, owner := range owners {
		if owner.RevokedAt != nil {
			revoked++
			if owner.RevokedBy == nil || *owner.RevokedBy != h.caller || owner.RevokeReason != "moved team" {
				t.Errorf("a revoked ownership = %+v", owner)
			}
		}
	}
	if len(owners) != 3 || revoked != 2 {
		t.Errorf("%d ownerships, %d revoked; want three kept and two revoked", len(owners), revoked)
	}
}
