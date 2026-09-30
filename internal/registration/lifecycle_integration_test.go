package registration

// The lifecycle against a real PostgreSQL and a fake kernel (TDD-identity-control-003 §Suspension,
// Restoration, and Retirement): a suspension disables the client and ends its sessions, a restore
// writes desired state back before it enables, and a retirement follows a suspension and deletes the
// client.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func (h *harness) change(registrationID id.UUID, reason string) StateChange {
	return StateChange{RegistrationID: registrationID, ChangedBy: h.caller, Reason: reason}
}

type stateChange struct{ from, to, reason string }

// stateChanges are the registration's lifecycle records, oldest first, each by the harness's caller.
func (h *harness) stateChanges(registrationID id.UUID) []stateChange {
	h.t.Helper()
	var out []stateChange
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT from_state, to_state, reason FROM identity.registration_state_change
		    WHERE registration_id = $1 AND changed_by = $2 ORDER BY changed_at, change_id`,
			registrationID.String(), h.caller.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c stateChange
			if err := rows.Scan(&c.from, &c.to, &c.reason); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	}); err != nil {
		h.t.Fatalf("read the lifecycle records: %v", err)
	}
	return out
}

func (h *harness) suspendedAt(registrationID id.UUID) time.Time {
	h.t.Helper()
	var at time.Time
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT suspended_at FROM identity.client_registration WHERE registration_id = $1`,
			registrationID.String()).Scan(&at)
	}); err != nil {
		h.t.Fatalf("read suspended_at: %v", err)
	}
	return at
}

// A suspension disables the client and sets the not-before that ends its refresh tokens, and records
// who asked and why. A repeat records nothing more and applies it again.
func TestASuspensionDisablesTheClientAndEndsItsSessions(t *testing.T) {
	h := newHarness(t)
	registration, client := h.registerConfidential("suspended-bff", testKey(t))

	suspended, err := h.service.Suspend(context.Background(), h.change(registration.ID, "the BFF's key may have leaked"))
	if err != nil {
		t.Fatal(err)
	}
	if suspended.State != StateSuspended {
		t.Fatalf("state = %s, want suspended", suspended.State)
	}
	live := h.live(client)
	if live.Enabled || live.NotBefore != SuspensionNotBefore(h.suspendedAt(registration.ID)) {
		t.Errorf("client = enabled %v, not-before %d; want disabled with the suspension's not-before", live.Enabled,
			live.NotBefore)
	}
	if got := h.stateChanges(registration.ID); !slices.Equal(got,
		[]stateChange{{StateActive, StateSuspended, "the BFF's key may have leaked"}}) {
		t.Errorf("lifecycle records = %+v", got)
	}

	// Re-enabled in the console, the client is disabled again by a repeated suspension, which records
	// nothing new.
	h.kernel.ConsoleChange("console-admin", client, func(c *keycloak.Client) { c.Enabled = true })
	if _, err := h.service.Suspend(context.Background(), h.change(registration.ID, "again")); err != nil {
		t.Fatal(err)
	}
	if h.live(client).Enabled || len(h.stateChanges(registration.ID)) != 1 {
		t.Errorf("a repeated suspension left the client enabled or recorded a second change")
	}
}

// A kernel that cannot be reached leaves the suspension recorded: the record is desired state, and
// the sweep or a retry finishes it.
func TestASuspensionTheKernelMissedIsStillRecorded(t *testing.T) {
	h := newHarness(t)
	registration, client := h.registerConfidential("unreachable-bff", testKey(t))
	h.kernel.FailPatch = keycloak.ErrUnavailable
	if _, err := h.service.Suspend(context.Background(), h.change(registration.ID, "contain it")); !errors.Is(err,
		keycloak.ErrUnavailable) {
		t.Fatalf("Suspend answered %v, want the kernel's failure", err)
	}
	if state, _ := h.state(registration.ID); state != StateSuspended {
		t.Errorf("state = %s, want suspended", state)
	}
	h.kernel.FailPatch = nil
	if _, err := h.service.Suspend(context.Background(), h.change(registration.ID, "contain it")); err != nil {
		t.Fatal(err)
	}
	if h.live(client).Enabled {
		t.Error("the retried suspension left the client enabled")
	}
}

// A restore writes the registered redirect URIs and keys back before it enables the client, so a
// console change made while it was suspended does not come back to life.
func TestARestoreWritesDesiredStateBeforeItEnables(t *testing.T) {
	h := newHarness(t)
	key := testKey(t)
	registration, client := h.registerConfidential("restored-bff", key)
	if _, err := h.service.Suspend(context.Background(), h.change(registration.ID, "investigate")); err != nil {
		t.Fatal(err)
	}
	h.kernel.ConsoleChange("console-admin", client, func(c *keycloak.Client) {
		c.RedirectURIs = []string{"https://evil.example.net/cb"}
		c.Credential.Keys = []keycloak.JWK{{KID: "planted", N: "bg", E: "AQAB"}}
	})

	restored, err := h.service.Restore(context.Background(), h.change(registration.ID, "cleared"))
	if err != nil {
		t.Fatal(err)
	}
	live := h.live(client)
	if restored.State != StateActive || !live.Enabled || !slices.Equal(live.RedirectURIs, []string{"https://bff.example.com/callback"}) ||
		!slices.Equal(h.kernelKIDs(client), []string{key.kid}) {
		t.Errorf("restored %s: client = %+v, kids %v", restored.State, live, h.kernelKIDs(client))
	}
	if got := h.stateChanges(registration.ID); len(got) != 2 || got[1] != (stateChange{StateSuspended, StateActive, "cleared"}) {
		t.Errorf("lifecycle records = %+v", got)
	}

	// A restore of an active registration changes nothing: it never lifts a block.
	h.kernel.ConsoleChange("", client, func(c *keycloak.Client) { c.Enabled = false })
	patches := h.kernel.Patches
	if _, err := h.service.Restore(context.Background(), h.change(registration.ID, "again")); err != nil {
		t.Fatal(err)
	}
	if h.kernel.Patches != patches || h.live(client).Enabled || len(h.stateChanges(registration.ID)) != 2 {
		t.Error("a restore of an active registration changed the client or recorded a change")
	}
}

// A restore the kernel refuses leaves the registration suspended and records nothing.
func TestARestoreTheKernelRefusesLeavesItSuspended(t *testing.T) {
	h := newHarness(t)
	registration, client := h.registerConfidential("refused-restore", testKey(t))
	if _, err := h.service.Suspend(context.Background(), h.change(registration.ID, "investigate")); err != nil {
		t.Fatal(err)
	}
	h.kernel.FailPatch = keycloak.ErrUnavailable
	if _, err := h.service.Restore(context.Background(), h.change(registration.ID, "cleared")); err == nil {
		t.Fatal("a restore the kernel refused succeeded")
	}
	if state, _ := h.state(registration.ID); state != StateSuspended || h.live(client).Enabled ||
		len(h.stateChanges(registration.ID)) != 1 {
		t.Errorf("state = %s after a refused restore, want suspended with the client disabled", state)
	}
}

// A retirement follows a suspension. It deletes the client, revokes the keys, keeps the record, and
// frees the client_key for a new registration.
func TestARetirementFollowsASuspension(t *testing.T) {
	h := newHarness(t)
	registration, client := h.registerConfidential("retired-bff", testKey(t))
	if _, err := h.service.Retire(context.Background(), h.change(registration.ID, "decommissioned")); !errors.Is(err,
		ErrInvalidTransition) {
		t.Fatalf("retiring an active client answered %v, want ErrInvalidTransition", err)
	}
	if _, err := h.service.Suspend(context.Background(), h.change(registration.ID, "decommissioning")); err != nil {
		t.Fatal(err)
	}
	retired, err := h.service.Retire(context.Background(), h.change(registration.ID, "decommissioned"))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := h.kernel.Client(client); retired.State != StateRetired || present {
		t.Errorf("retired %s, the client still present: %v", retired.State, present)
	}
	for _, key := range h.keys(registration.ID) {
		if key.State != KeyRevoked || key.RevocationReason != "the registration was retired" {
			t.Errorf("key %s is %s (%s) after the retirement", key.KID, key.State, key.RevocationReason)
		}
	}
	if got := h.stateChanges(registration.ID); len(got) != 2 || got[1] != (stateChange{StateSuspended, StateRetired, "decommissioned"}) {
		t.Errorf("lifecycle records = %+v", got)
	}

	// A repeat returns the retired registration and records nothing; the name is free again.
	if again, err := h.service.Retire(context.Background(), h.change(registration.ID, "again")); err != nil ||
		again.State != StateRetired || len(h.stateChanges(registration.ID)) != 2 {
		t.Errorf("a repeated retirement answered %+v, %v", again, err)
	}
	next, _ := h.registerConfidential("retired-bff", testKey(t))
	if next.ID == registration.ID || next.State != StateActive {
		t.Errorf("the freed client_key registered as %+v", next)
	}
}

// A retirement retried after the client is already gone records the retirement.
func TestARetirementFindsTheClientAlreadyGone(t *testing.T) {
	h := newHarness(t)
	registration, client := h.registerConfidential("gone-bff", testKey(t))
	if _, err := h.service.Suspend(context.Background(), h.change(registration.ID, "contain")); err != nil {
		t.Fatal(err)
	}
	h.kernel.Remove("console-admin", client)
	if retired, err := h.service.Retire(context.Background(), h.change(registration.ID, "its client was deleted")); err != nil ||
		retired.State != StateRetired {
		t.Fatalf("retiring a registration whose client is gone answered %+v, %v", retired, err)
	}

	// A deletion the kernel refuses rolls the retirement back.
	other, otherClient := h.registerConfidential("undeletable-bff", testKey(t))
	if _, err := h.service.Suspend(context.Background(), h.change(other.ID, "contain")); err != nil {
		t.Fatal(err)
	}
	h.kernel.FailDelete = keycloak.ErrUnavailable
	if _, err := h.service.Retire(context.Background(), h.change(other.ID, "decommissioned")); err == nil {
		t.Fatal("a retirement whose deletion failed succeeded")
	}
	if state, _ := h.state(other.ID); state != StateSuspended {
		t.Errorf("state = %s after a failed deletion, want suspended", state)
	}
	if len(h.kernelKIDs(otherClient)) != 0 {
		t.Errorf("the undeleted client still holds keys %v", h.kernelKIDs(otherClient))
	}
}

// A resource is retired without a suspension, and only when no active or suspended registration
// names it in its audience.
func TestAResourceIsRetiredOnceNothingNamesIt(t *testing.T) {
	h := newHarness(t)
	resource := h.resource("orders-api", "L1")
	if _, err := h.service.Suspend(context.Background(), h.change(resource.ID, "pause")); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("suspending a resource answered %v, want ErrInvalidTransition", err)
	}
	req := h.confidential("orders-bff", testKey(t))
	req.Audience = []string{"orders-api"}
	dependent, err := h.service.Register(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Suspend(context.Background(), h.change(dependent.ID, "decommissioning")); err != nil {
		t.Fatal(err)
	}
	var inUse *ResourceInUseError
	if _, err := h.service.Retire(context.Background(), h.change(resource.ID, "decommissioned")); !errors.As(err, &inUse) ||
		!slices.Equal(inUse.Dependents, []string{"orders-bff"}) {
		t.Fatalf("retiring a resource a suspended client names answered %v", err)
	}
	if _, err := h.service.Retire(context.Background(), h.change(dependent.ID, "decommissioned")); err != nil {
		t.Fatal(err)
	}
	if retired, err := h.service.Retire(context.Background(), h.change(resource.ID, "decommissioned")); err != nil ||
		retired.State != StateRetired {
		t.Errorf("retiring the resource answered %+v, %v", retired, err)
	}
}

// Every lifecycle action refuses a workload's client, an unknown registration, and a request that
// names no caller or reason.
func TestTheLifecycleRefusesWhatItDoesNotStop(t *testing.T) {
	h := newHarness(t)
	h.kernel.Scopes["scnehaux-workload"] = "scope-workload"
	req := h.request("lifecycle-job", ProfileWorkload)
	req.AudienceClass, req.PublicKey = "workload", testKey(t).public
	workload, err := h.service.Register(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	unknown, _ := id.NewV7()
	actions := map[string]func(context.Context, StateChange) (Registration, error){
		"suspend": h.service.Suspend, "restore": h.service.Restore, "retire": h.service.Retire}
	for name, action := range actions {
		if _, err := action(context.Background(), h.change(workload.ID, "stop")); !errors.Is(err, ErrWorkloadLifecycle) {
			t.Errorf("%s of a workload's client answered %v, want ErrWorkloadLifecycle", name, err)
		}
		if _, err := action(context.Background(), h.change(unknown, "stop")); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s of an unknown registration answered %v, want ErrNotFound", name, err)
		}
		if _, err := action(context.Background(), StateChange{RegistrationID: workload.ID, ChangedBy: h.caller, Reason: " "}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s without a reason answered %v, want ErrInvalid", name, err)
		}
	}
	if len(h.stateChanges(workload.ID)) != 0 {
		t.Error("a refused action recorded a change")
	}
}
