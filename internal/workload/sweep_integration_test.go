package workload

// The workload sweep, the owner's review and the client rebuild (TDD-identity-control-004 1.5.0),
// against a real PostgreSQL and the fake kernel ports.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// at moves the service's clock to now plus the offset, as a later sweep would find it.
func (h *harness) at(offset time.Duration) {
	at := time.Now().UTC().Add(offset)
	h.service.now = func() time.Time { return at }
}

func (h *harness) execSQL(statement string, args ...any) {
	h.t.Helper()
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, statement, args...)
		return err
	}); err != nil {
		h.t.Fatalf("%s: %v", statement, err)
	}
}

func (h *harness) sweep() SweepResult {
	h.t.Helper()
	result, err := h.service.Sweep(context.Background())
	if err != nil {
		h.t.Fatalf("sweep: %v", err)
	}
	return result
}

func (h *harness) create(clientKey string) Workload {
	h.t.Helper()
	created, err := h.service.Create(context.Background(), h.request(clientKey))
	if err != nil {
		h.t.Fatalf("create %s: %v", clientKey, err)
	}
	return created
}

func (h *harness) ownerState(state string) {
	h.execSQL(`UPDATE identity.principal_mapping SET state = $2 WHERE principal_id = $1`, h.owner.String(), state)
}

// An owner suspended orphans the workload, which keeps working; restored, the owner reclaims it.
// Retired, the orphan is reminded, escalated, and at thirty days suspended, automatically and on the
// record.
func TestAnOrphanIsRemindedEscalatedAndSuspended(t *testing.T) {
	h := newHarness(t)
	created := h.create("orphan-job")
	h.at(0)
	if result := h.sweep(); result.Orphaned != 0 {
		t.Fatalf("a workload with an active owner was orphaned: %+v", result)
	}

	h.ownerState("suspended")
	if result := h.sweep(); result.Orphaned != 1 {
		t.Fatalf("sweep = %+v, want one orphan", result)
	}
	if got, _ := h.service.Get(context.Background(), created.PrincipalID); got.State != StateOrphaned || got.OrphanedAt == nil {
		t.Fatalf("workload = %+v, want orphaned", got)
	}
	client := h.clientsNamed("orphan-job")[0]
	if !client.Enabled {
		t.Error("an orphan stopped working")
	}
	orphans, _ := h.service.Orphaned(context.Background())
	if len(orphans) != 1 || orphans[0].Stage != StageReminder {
		t.Fatalf("orphans = %+v, want one at the reminder stage", orphans)
	}
	h.at(8 * 24 * time.Hour)
	if orphans, _ := h.service.Orphaned(context.Background()); orphans[0].Stage != StageEscalated {
		t.Errorf("after eight days the stage is %s, want escalated", orphans[0].Stage)
	}

	h.ownerState("active")
	if result := h.sweep(); result.Reclaimed != 1 {
		t.Fatalf("sweep = %+v, want the restored owner to reclaim it", result)
	}
	if got, _ := h.service.Get(context.Background(), created.PrincipalID); got.State != StateActive || got.OrphanedAt != nil {
		t.Errorf("workload = %+v, want active again", got)
	}

	h.ownerState("retired")
	h.at(0)
	h.sweep()
	h.at(31 * 24 * time.Hour)
	if result := h.sweep(); result.Suspended != 1 {
		t.Fatalf("sweep = %+v, want the thirty-day orphan suspended", result)
	}
	if got, _ := h.service.Get(context.Background(), created.PrincipalID); got.State != StateSuspended {
		t.Errorf("workload = %s, want suspended", got.State)
	}
	if h.clientsNamed("orphan-job")[0].Enabled {
		t.Error("a suspended orphan's client is still enabled")
	}
	var automatic bool
	var changedBy *string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT automatic, changed_by::text FROM identity.registration_state_change
		    WHERE registration_id = $1 AND to_state = 'suspended'`, created.RegistrationID.String()).Scan(&automatic, &changedBy)
	}); err != nil || !automatic || changedBy != nil {
		t.Errorf("the suspension was recorded automatic=%v by %v (%v); want automatic and no Principal", automatic, changedBy, err)
	}
	// A restore needs an owner: reassign first.
	if _, err := h.service.Restore(context.Background(), LifecycleRequest{PrincipalID: created.PrincipalID,
		ChangedBy: h.caller, Reason: "back"}); !errors.Is(err, ErrOwnerNotEligible) {
		t.Errorf("restoring an orphan with no owner answered %v", err)
	}
}

// A workload not seen within the threshold is found once, and resolved when it authenticates again.
func TestAnUnusedWorkloadIsFoundAndResolvedWhenSeen(t *testing.T) {
	h := newHarness(t)
	created := h.create("idle-job")
	h.at(0)
	if result := h.sweep(); result.Unused != 0 {
		t.Fatalf("a new workload was unused: %+v", result)
	}
	h.at(91 * 24 * time.Hour)
	if result := h.sweep(); result.Unused != 1 {
		t.Fatalf("sweep = %+v, want one unused", result)
	}
	if result := h.sweep(); result.Unused != 1 {
		t.Errorf("a second sweep = %+v, want the one finding kept", result)
	}
	unused, _ := h.service.Unused(context.Background())
	if len(unused) != 1 || unused[0].PrincipalID != created.PrincipalID || unused[0].LastSeenAt != nil {
		t.Fatalf("unused = %+v", unused)
	}
	h.execSQL(`UPDATE identity.workload SET last_seen_at = $2 WHERE principal_id = $1`, created.PrincipalID.String(),
		h.service.now())
	if result := h.sweep(); result.Unused != 0 {
		t.Errorf("sweep = %+v; a workload seen again is still unused", result)
	}
	var resolution string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT resolution FROM identity.workload_finding WHERE principal_id = $1 AND finding_class = 'unused'`,
			created.PrincipalID.String()).Scan(&resolution)
	}); err != nil || resolution != "seen" {
		t.Errorf("resolution %q (%v), want seen", resolution, err)
	}
}

// A review is due ninety days after activation; past it, the sweep finds it overdue and suspends
// nothing; only the owner reviews, which resolves it and moves the due date.
func TestTheOwnerReviewsAnOverdueWorkload(t *testing.T) {
	h := newHarness(t)
	created := h.create("reviewed-job")
	if created.ReviewDueAt == nil || created.LastReviewedAt != nil {
		t.Fatalf("a new workload's review is due %v, last %v", created.ReviewDueAt, created.LastReviewedAt)
	}
	h.at(91 * 24 * time.Hour)
	if result := h.sweep(); result.ReviewsOverdue != 1 || result.Suspended != 0 {
		t.Fatalf("sweep = %+v, want one overdue review and nothing suspended", result)
	}
	if _, err := h.service.Review(context.Background(), ReviewRequest{PrincipalID: created.PrincipalID,
		ReviewedBy: h.caller, Statement: "still needed"}); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a review by someone else answered %v, want ErrNotOwner", err)
	}
	if _, err := h.service.Review(context.Background(), ReviewRequest{PrincipalID: created.PrincipalID,
		ReviewedBy: h.owner, Statement: " "}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a review with no statement answered %v", err)
	}
	reviewed, err := h.service.Review(context.Background(), ReviewRequest{PrincipalID: created.PrincipalID,
		ReviewedBy: h.owner, Statement: "still exports payroll; purpose, owner and team hold"})
	if err != nil || reviewed.LastReviewedAt == nil || reviewed.ReviewDueAt == nil ||
		!reviewed.ReviewDueAt.After(*created.ReviewDueAt) {
		t.Fatalf("review = %+v, %v", reviewed, err)
	}
	if overdue, _ := h.service.ReviewsOverdue(context.Background()); len(overdue) != 0 {
		t.Errorf("after the review, overdue = %+v", overdue)
	}
}

// A workload's client deleted in the console is rebuilt under the same principal_id and keys, its
// mapping bound to the new service-account user; nothing is rebuilt while the client exists, and a
// rebuild that fails leaves no client behind.
func TestADeletedWorkloadClientIsRebuilt(t *testing.T) {
	h := newHarness(t)
	created := h.create("rebuilt-job")
	request := LifecycleRequest{PrincipalID: created.PrincipalID, ChangedBy: h.caller, Reason: "deleted in the console"}
	if _, err := h.service.Rebuild(context.Background(), request); !errors.Is(err, ErrClientPresent) {
		t.Fatalf("a rebuild while the client exists answered %v", err)
	}
	original := h.clientsNamed("rebuilt-job")[0]
	keys := h.clients.Keys(original.ID)
	previous, _, _ := h.mapping(created.PrincipalID)
	h.clients.Remove("admin", original.ID)
	h.users.DeleteUser(keycloak.UserID(previous))

	h.users.FailWrite = errors.New("kernel refused the write")
	if _, err := h.service.Rebuild(context.Background(), request); err == nil {
		t.Fatal("a rebuild whose identity write failed succeeded")
	}
	if left := h.clientsNamed("rebuilt-job"); len(left) != 0 {
		t.Errorf("a failed rebuild left %d client(s)", len(left))
	}
	h.users.FailWrite = nil

	rebuilt, err := h.service.Rebuild(context.Background(), request)
	if err != nil || rebuilt.State != StateActive {
		t.Fatalf("rebuild = %+v, %v", rebuilt, err)
	}
	now := h.clientsNamed("rebuilt-job")
	if len(now) != 1 || now[0].ID == original.ID {
		t.Fatalf("clients after the rebuild = %+v", now)
	}
	if got := h.clients.Keys(now[0].ID); len(got) != len(keys) || got[0] != keys[0] {
		t.Errorf("the rebuilt client holds %+v, want %+v", got, keys)
	}
	user, state, _ := h.mapping(created.PrincipalID)
	if user == previous || state != "active" {
		t.Errorf("mapping = %s %s, want active under the new service-account user", user, state)
	}
	carried, ok := h.users.User(keycloak.UserID(user))
	if !ok || carried.PrincipalID != created.PrincipalID || carried.WorkloadOwner != h.owner {
		t.Errorf("the new service-account user holds %+v", carried)
	}
	var relinks int
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.principal_relink WHERE principal_id = $1
		    AND previous_keycloak_user_id = $2 AND relinked_by = $3`, created.PrincipalID.String(), previous,
			h.caller.String()).Scan(&relinks)
	}); err != nil || relinks != 1 {
		t.Errorf("%d relink records (%v), want the rebuild's", relinks, err)
	}
	if _, err := h.service.Rebuild(context.Background(), request); !errors.Is(err, ErrClientPresent) {
		t.Errorf("a second rebuild answered %v", err)
	}
	other, _ := id.NewV7()
	if _, err := h.service.Rebuild(context.Background(), LifecycleRequest{PrincipalID: other, ChangedBy: h.caller,
		Reason: "r"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a rebuild of no workload answered %v", err)
	}
}
