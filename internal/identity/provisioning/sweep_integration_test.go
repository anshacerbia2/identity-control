package provisioning_test

// The Principal sweep's unmapped, orphan and duplicate branches (TDD-identity-control-001 1.13.0),
// against a real PostgreSQL and the fake kernel. Each test owns its realm's rows.

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// disabling returns the same fixture with a provisioner that disables unmapped and orphan users.
func (p *portability) disabling() *provisioning.Provisioner {
	p.t.Helper()
	provisioner, err := provisioning.New(p.pool, p.kernel, provisioning.Config{
		ProvisionTimeout: time.Second, PendingRecoveryAfter: time.Minute, RecoveryBatch: 2, Realm: portabilityRealm,
		DisableUnmapped: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		p.t.Fatal(err)
	}
	return provisioner
}

func (p *portability) sweep(provisioner *provisioning.Provisioner) provisioning.SweepResult {
	p.t.Helper()
	result, err := provisioner.Sweep(context.Background())
	if err != nil {
		p.t.Fatalf("sweep: %v", err)
	}
	return result
}

func (p *portability) unmapped() []provisioning.UserFinding {
	p.t.Helper()
	found, err := p.provisioner.Unmapped(context.Background())
	if err != nil {
		p.t.Fatalf("unmapped: %v", err)
	}
	return found
}

func (p *portability) mappingState(principal id.UUID) string {
	p.t.Helper()
	var state string
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM identity.principal_mapping WHERE principal_id = $1`,
			principal.String()).Scan(&state)
	}); err != nil {
		p.t.Fatal(err)
	}
	return state
}

func (p *portability) enabled(user keycloak.UserID) bool {
	p.t.Helper()
	found, ok := p.kernel.User(user)
	if !ok {
		p.t.Fatalf("user %s is gone", user)
	}
	return found.Enabled
}

// A user made in the console, carrying no identifier, is recorded unmapped and, under disable,
// disabled; under report it is recorded and left alone. Deleting it resolves the finding.
func TestAnUnmappedUserIsRecordedAndDisabledOnlyWhenAsked(t *testing.T) {
	p := newPortability(t)
	p.create("mapped.user")
	stray := p.kernel.Seed(portabilityRealm, "console.made", id.Nil, keycloak.SubjectHuman)

	if result := p.sweep(p.provisioner); result.Unmapped != 1 || result.Orphan != 0 || result.Duplicate != 0 {
		t.Fatalf("report sweep = %+v", result)
	}
	if !p.enabled(stray) {
		t.Error("report mode disabled the user")
	}
	found := p.unmapped()
	if len(found) != 1 || found[0].Class != provisioning.FindingUnmapped || found[0].Username != "console.made" ||
		found[0].UserDisabled || found[0].PrincipalID != nil {
		t.Fatalf("findings = %+v", found)
	}

	// A second sweep keeps the one finding; disabling records it on the same finding.
	if result := p.sweep(p.disabling()); result.Unmapped != 1 {
		t.Fatalf("disable sweep = %+v", result)
	}
	if p.enabled(stray) {
		t.Error("disable mode left the user enabled")
	}
	found = p.unmapped()
	if len(found) != 1 || !found[0].UserDisabled {
		t.Fatalf("after disabling, findings = %+v", found)
	}

	p.kernel.DeleteUser(stray)
	p.sweep(p.provisioner)
	if found := p.unmapped(); len(found) != 0 {
		t.Errorf("a deleted user's finding stayed open: %+v", found)
	}
	var resolution string
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT resolution FROM identity.principal_finding WHERE realm = $1 AND finding_class = 'unmapped'`,
			string(portabilityRealm)).Scan(&resolution)
	}); err != nil || resolution != "user_absent" {
		t.Errorf("resolution %q (%v), want user_absent", resolution, err)
	}
}

// A user carrying an identifier no mapping holds is an orphan, and so is one carrying a value that
// does not parse: something wrote it.
func TestAUserCarryingAnUnknownIdentifierIsAnOrphan(t *testing.T) {
	p := newPortability(t)
	stranger, _ := id.NewV7()
	forged := p.kernel.Seed(portabilityRealm, "forged.user", stranger, keycloak.SubjectHuman)
	garbled := p.kernel.SeedClaim(portabilityRealm, "garbled.user", "not-a-uuid")

	if result := p.sweep(p.disabling()); result.Orphan != 2 || result.Unmapped != 0 {
		t.Fatalf("sweep = %+v", result)
	}
	if p.enabled(forged) || p.enabled(garbled) {
		t.Error("an orphan was left enabled under disable")
	}
	claims := map[string]bool{}
	for _, finding := range p.unmapped() {
		if finding.Class != provisioning.FindingOrphan {
			t.Errorf("finding %+v", finding)
		}
		claims[finding.ClaimedPrincipalID] = true
	}
	if !claims[stranger.String()] || !claims["not-a-uuid"] {
		t.Errorf("claimed identifiers = %v", claims)
	}
}

// Two users carrying one Principal's identifier: both disabled, whatever the setting, and the
// mapping quarantined. A second sweep changes nothing more.
func TestADuplicateIsContainedAndTheMappingQuarantined(t *testing.T) {
	p := newPortability(t)
	created := p.create("original.user")
	original := p.user(created.PrincipalID)
	copied := p.kernel.Seed(portabilityRealm, "copied.user", created.PrincipalID, keycloak.SubjectHuman)

	if result := p.sweep(p.provisioner); result.Duplicate != 1 {
		t.Fatalf("sweep = %+v", result)
	}
	if p.enabled(original.ID) || p.enabled(copied) {
		t.Error("a duplicate's users were left enabled")
	}
	if state := p.mappingState(created.PrincipalID); state != "quarantined" {
		t.Errorf("mapping %s, want quarantined", state)
	}
	found := p.unmapped()
	if len(found) != 1 || found[0].Class != provisioning.FindingDuplicate || found[0].PrincipalID == nil ||
		*found[0].PrincipalID != created.PrincipalID || found[0].Username != "copied.user" {
		t.Fatalf("findings = %+v", found)
	}
	if result := p.sweep(p.provisioner); result.Duplicate != 1 || len(p.unmapped()) != 1 {
		t.Errorf("a second sweep = %+v, findings %+v", result, p.unmapped())
	}
}

// A mapping whose own user is gone, while another user carries its identifier, is a dangling mapping
// or a rebind in flight, not a duplicate: nothing is quarantined and the other user is left alone.
func TestAMappingWhoseUserIsGoneIsNotADuplicate(t *testing.T) {
	p := newPortability(t)
	created := p.create("rebound.user")
	original := p.user(created.PrincipalID)
	p.kernel.DeleteUser(original.ID)
	successor := p.kernel.Seed(portabilityRealm, "successor.user", created.PrincipalID, keycloak.SubjectHuman)

	result := p.sweep(p.disabling())
	if result.Duplicate != 0 || result.Dangling != 1 {
		t.Fatalf("sweep = %+v", result)
	}
	if !p.enabled(successor) || p.mappingState(created.PrincipalID) != "active" {
		t.Error("a rebind in flight was contained as a duplicate")
	}
}

// A client's service-account user is its client's, so it is never unmapped, and a workload's user,
// which the listing may not return, is read directly before it is reported dangling.
func TestServiceAccountsAreNeitherUnmappedNorDangling(t *testing.T) {
	for _, listed := range []bool{false, true} {
		p := newPortability(t)
		p.kernel.ListServiceAccounts = listed
		owner := p.create("workload.owner")
		p.kernel.AddServiceAccount(portabilityRealm, keycloak.User{ID: "sa-admin-client", Username: "service-account-identity-control"})
		principalID, _ := id.NewV7()
		p.kernel.AddServiceAccount(portabilityRealm, keycloak.User{ID: "sa-nightly", Username: "service-account-nightly"})
		if err := p.kernel.WriteWorkloadIdentity(context.Background(), portabilityRealm, "sa-nightly", principalID, owner.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
			    (principal_id, realm, username, subject_type, workload_owner, keycloak_user_id, state, activated_at)
			    VALUES ($1, $2, 'service-account-nightly', 'workload', $3, 'sa-nightly', 'active', now() - interval '1 minute')`,
				principalID.String(), string(portabilityRealm), owner.PrincipalID.String())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if result := p.sweep(p.disabling()); result != (provisioning.SweepResult{}) {
			t.Errorf("listed=%v: sweep = %+v, want nothing", listed, result)
		}
		if !p.enabled("sa-admin-client") || !p.enabled("sa-nightly") {
			t.Errorf("listed=%v: a service-account user was disabled", listed)
		}
	}
}

// A pending workload's identity is on its service-account user before its mapping exists, and that
// is not an orphan.
func TestAPendingWorkloadsIdentifierIsNotAnOrphan(t *testing.T) {
	p := newPortability(t)
	p.kernel.ListServiceAccounts = true
	owner := p.create("pending.owner")
	principalID, _ := id.NewV7()
	registrationID, _ := id.NewV7()
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM identity.workload w USING identity.client_registration r
		    WHERE r.registration_id = w.registration_id AND r.realm = $1`, string(portabilityRealm)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity.client_registration WHERE realm = $1`, string(portabilityRealm)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity.client_registration
		    (registration_id, realm, client_key, profile, application_authority, application_ref, registered_by,
		     audience_class, state)
		    VALUES ($1, $2, 'pending-nightly', 'workload', 'manual', 'sweep-test', $3, 'workload', 'pending')`,
			registrationID.String(), string(portabilityRealm), owner.PrincipalID.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO identity.workload
		    (principal_id, registration_id, display_name, purpose, workload_type, owner_principal_id, state,
		     created_by, idempotency_scope, idempotency_key, request_digest)
		    VALUES ($1, $2, 'nightly', 'a test', 'job', $3, 'pending', $3, 'scope', 'key', 'digest')`,
			principalID.String(), registrationID.String(), owner.PrincipalID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p.kernel.AddServiceAccount(portabilityRealm, keycloak.User{ID: "sa-pending", Username: "service-account-pending-nightly"})
	if err := p.kernel.WriteWorkloadIdentity(context.Background(), portabilityRealm, "sa-pending", principalID, owner.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if result := p.sweep(p.disabling()); result.Orphan != 0 {
		t.Errorf("sweep = %+v; a pending workload's identifier was taken for an orphan", result)
	}
	if !p.enabled("sa-pending") {
		t.Error("a pending workload's user was disabled")
	}
}

// An enumeration that fails part way records nothing, so an unread page is not a missing user.
func TestASweepFailingPartWayRecordsNothing(t *testing.T) {
	p := newPortability(t)
	for _, name := range []string{"a.user", "b.user", "c.user"} {
		p.create(name)
	}
	p.kernel.Seed(portabilityRealm, "stray.user", id.Nil, keycloak.SubjectHuman)
	p.kernel.FailListAfter = 1
	if _, err := p.disabling().Sweep(context.Background()); err == nil {
		t.Fatal("a sweep whose second page failed succeeded")
	}
	if found := p.unmapped(); len(found) != 0 {
		t.Errorf("a failed sweep recorded %+v", found)
	}
}
