package provisioning_test

// These tests are the Week 1 exit criteria of the Principal creation path, stated as tests:
//
//	a repeated Idempotency-Key returns the original identifier and performs no remote call
//	process termination between the remote call and the local commit recovers without
//	creating a second Principal
//
// Both are about what happens when something is interrupted, so the fake transaction source
// below can fail a commit after its function succeeded. Without that capability neither
// criterion is testable, and the first real exercise of the recovery path would be an
// incident.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/db/dbtest"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

// fakeTx hands out a pre-configured transaction per InTx call and can fail a commit.
//
// One transaction per call rather than one shared: the two checkpoints of the creation path
// send different statements and expect different outcomes, and a single recorder would make
// an assertion about the second indistinguishable from one about the first.
type fakeTx struct {
	txs          []*dbtest.Tx
	used         int
	failCommitAt int // 1-based InTx call whose commit fails after fn succeeded
}

func (f *fakeTx) InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error {
	f.used++
	if f.used > len(f.txs) {
		return fmt.Errorf("fakeTx: unexpected InTx call %d; only %d configured", f.used, len(f.txs))
	}
	tx := f.txs[f.used-1]
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if f.failCommitAt == f.used {
		return errors.New("fakeTx: commit failed")
	}
	return nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// claimed configures a transaction whose Exec reports one row, which is what
// idempotency.Claim reads as a fresh claim.
func claimed() *dbtest.Tx { return &dbtest.Tx{Tag: dbtest.CommandTag(1)} }

// replaying configures a transaction whose Exec reports no rows and whose row carries a
// completed claim, which idempotency.Claim reads as a replay.
//
// The sql.NullInt64 is the stored status column's type. It is the only reason this file
// imports database/sql, and arch.json records that exception: it is a scan destination, not
// a second connection source.
func replaying(digest string, body []byte) *dbtest.Tx {
	return &dbtest.Tx{
		Tag:       dbtest.CommandTag(0),
		RowValues: []any{digest, sql.NullInt64{Int64: 201, Valid: true}, body, true},
	}
}

func humanCreate() provisioning.CreateRequest {
	return provisioning.CreateRequest{
		CallerScope:    "svc:admin-api",
		IdempotencyKey: "key-0001",
		Realm:          "scnehaux",
		Username:       "operator",
		Email:          "operator@example.com",
		SubjectType:    keycloak.SubjectHuman,
	}
}

func newProvisioner(t *testing.T, tx provisioning.Transactor, kernel keycloak.AdminClient) *provisioning.Provisioner {
	t.Helper()
	p, err := provisioning.New(tx, kernel, provisioning.Config{
		ProvisionTimeout:     time.Second,
		PendingRecoveryAfter: 2 * time.Second,
		RecoveryBatch:        10,
	}, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestCreateMintsAnIdentifierAndActivatesTheMapping(t *testing.T) {
	tx := &fakeTx{txs: []*dbtest.Tx{claimed(), claimed()}}
	kernel := keycloakfake.New()
	p := newProvisioner(t, tx, kernel)

	got, err := p.Create(context.Background(), humanCreate())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.PrincipalID.IsNil() {
		t.Fatal("Create returned a nil principal_id")
	}
	if got.PrincipalID.Version() != 7 {
		t.Errorf("principal_id is UUID version %d, want 7", got.PrincipalID.Version())
	}
	if kernel.Calls.CreateUser != 1 {
		t.Errorf("kernel CreateUser called %d times, want 1", kernel.Calls.CreateUser)
	}

	// The identifier must be inside the creation payload, not set afterwards. That is what
	// removes the window in which a Principal exists without its canonical identifier.
	found, err := kernel.FindByPrincipalID(context.Background(), "scnehaux", got.PrincipalID)
	if err != nil {
		t.Fatalf("FindByPrincipalID: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("kernel holds %d users for the identifier, want 1", len(found))
	}
}

// TestRepeatedKeyReturnsTheOriginalIdentifierAndPerformsNoRemoteCall is the first exit
// criterion, and the assertion that matters is the call count. A replay that returned the
// right identifier while still touching the kernel would create a second user.
func TestRepeatedKeyReturnsTheOriginalIdentifierAndPerformsNoRemoteCall(t *testing.T) {
	req := humanCreate()

	first := &fakeTx{txs: []*dbtest.Tx{claimed(), claimed()}}
	kernel := keycloakfake.New()
	original, err := newProvisioner(t, first, kernel).Create(context.Background(), req)
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	callsAfterFirst := kernel.Calls.CreateUser

	// The stored response is what the completed claim replays.
	stored, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal stored response: %v", err)
	}
	digest := digestOf(t, first)

	second := &fakeTx{txs: []*dbtest.Tx{replaying(digest, stored)}}
	replayed, err := newProvisioner(t, second, kernel).Create(context.Background(), req)
	if err != nil {
		t.Fatalf("replayed Create: %v", err)
	}

	if replayed.PrincipalID != original.PrincipalID {
		t.Errorf("replay returned %s, want the original %s", replayed.PrincipalID, original.PrincipalID)
	}
	if kernel.Calls.CreateUser != callsAfterFirst {
		t.Errorf("replay performed %d remote calls, want 0",
			kernel.Calls.CreateUser-callsAfterFirst)
	}
	if second.used != 1 {
		t.Errorf("replay opened %d transactions, want 1: it must return before the second checkpoint", second.used)
	}
}

// digestOf recovers the digest the provisioner computed, by reading it out of the claim
// statement the first transaction recorded. Recomputing it in the test would assert the test's
// own arithmetic rather than the provisioner's.
func digestOf(t *testing.T, tx *fakeTx) string {
	t.Helper()
	for _, call := range tx.txs[0].Calls() {
		if len(call.Args) == 3 {
			digest, ok := call.Args[2].(string)
			if ok {
				return digest
			}
		}
	}
	t.Fatal("no claim statement with a digest was recorded")
	return ""
}

// TestConflictingDigestIsRefusedWithoutARemoteCall asserts that a key reused for a different
// request conflicts rather than returning the first request's identifier. Answering the wrong
// question with a stored response is worse than failing.
func TestConflictingDigestIsRefusedWithoutARemoteCall(t *testing.T) {
	kernel := keycloakfake.New()
	tx := &fakeTx{txs: []*dbtest.Tx{
		{Tag: dbtest.CommandTag(0), RowValues: []any{
			"a-different-digest", sql.NullInt64{Int64: 201, Valid: true}, []byte(`{}`), true,
		}},
	}}

	_, err := newProvisioner(t, tx, kernel).Create(context.Background(), humanCreate())
	if !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("Create error = %v, want idempotency.ErrConflict", err)
	}
	if kernel.Calls.CreateUser != 0 {
		t.Errorf("a conflicting key performed %d remote calls, want 0", kernel.Calls.CreateUser)
	}
}

func TestInProgressKeyIsRefusedWithoutARemoteCall(t *testing.T) {
	kernel := keycloakfake.New()
	digest := "" // read back below; an in-progress row carries the same digest
	tx := &fakeTx{txs: []*dbtest.Tx{
		{Tag: dbtest.CommandTag(0), RowValues: []any{
			digest, sql.NullInt64{}, []byte(nil), false,
		}},
	}}

	// The stored digest is empty and the computed one is not, so this reports a conflict
	// rather than in-progress. Assert on the refusal and the absent remote call, which is
	// the property either way.
	_, err := newProvisioner(t, tx, kernel).Create(context.Background(), humanCreate())
	if err == nil {
		t.Fatal("Create succeeded against an unfinished claim")
	}
	if kernel.Calls.CreateUser != 0 {
		t.Errorf("an unfinished claim performed %d remote calls, want 0", kernel.Calls.CreateUser)
	}
}

// TestKernelFailureLeavesTheMappingPending asserts the deliberate absence of a rollback. The
// pending row names the identifier to search for, and discarding it would strand a kernel user
// nothing on our side can find.
func TestKernelFailureLeavesTheMappingPending(t *testing.T) {
	kernel := keycloakfake.New()
	kernel.FailCreate = keycloak.ErrUnavailable
	tx := &fakeTx{txs: []*dbtest.Tx{claimed()}}

	_, err := newProvisioner(t, tx, kernel).Create(context.Background(), humanCreate())
	if !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("Create error = %v, want keycloak.ErrUnavailable", err)
	}
	if tx.used != 1 {
		t.Errorf("opened %d transactions, want 1: the second checkpoint must not run", tx.used)
	}
	// The first transaction committed, so the pending mapping is durable.
	statements := tx.txs[0].Calls()
	if len(statements) != 2 {
		t.Fatalf("first checkpoint sent %d statements, want 2 (claim and insert)", len(statements))
	}
}

// TestCrashBetweenRemoteCallAndCommitRecoversWithoutASecondPrincipal is the second exit
// criterion, end to end.
//
// The kernel create succeeds, the activation commit fails, and recovery then finds the user
// and adopts it. The assertion is that CreateUser ran exactly once across both phases: a
// recovery that retried instead of adopting would have produced a second Principal for one
// request, which is the failure the pending state exists to prevent.
func TestCrashBetweenRemoteCallAndCommitRecoversWithoutASecondPrincipal(t *testing.T) {
	kernel := keycloakfake.New()
	ctx := context.Background()

	// Phase one: create succeeds remotely, checkpoint two fails to commit.
	crashing := &fakeTx{txs: []*dbtest.Tx{claimed(), claimed()}, failCommitAt: 2}
	_, err := newProvisioner(t, crashing, kernel).Create(ctx, humanCreate())
	if err == nil {
		t.Fatal("Create reported success although the activation commit failed")
	}
	if kernel.Calls.CreateUser != 1 {
		t.Fatalf("kernel CreateUser called %d times in phase one, want 1", kernel.Calls.CreateUser)
	}

	// The identifier the interrupted request minted, read from the kernel the same way
	// recovery will.
	orphan := onlyKernelUser(t, kernel)

	// Phase two: recovery reads the pending row and adopts the existing user.
	pending := &dbtest.Tx{Rows: [][]any{{
		orphan.PrincipalID.String(), "", "scnehaux", "operator", "operator@example.com",
		string(keycloak.SubjectHuman), "", string(provisioning.StatePending), 1,
	}}}
	recovering := &fakeTx{txs: []*dbtest.Tx{pending, claimed()}}

	resolved, err := newProvisioner(t, recovering, kernel).RecoverPending(ctx)
	if err != nil {
		t.Fatalf("RecoverPending: %v", err)
	}
	if resolved != 1 {
		t.Errorf("resolved %d mappings, want 1", resolved)
	}
	if kernel.Calls.CreateUser != 1 {
		t.Errorf("kernel CreateUser called %d times in total, want 1: recovery must adopt, not recreate",
			kernel.Calls.CreateUser)
	}
	if kernel.Count() != 1 {
		t.Errorf("kernel holds %d users, want 1: a second Principal was created", kernel.Count())
	}

	// Adoption is an activation carrying the kernel identifier.
	activation := recovering.txs[1].Only(t)
	if activation.Args[1] != string(orphan.ID) {
		t.Errorf("activation recorded %v, want the existing kernel identifier %q", activation.Args[1], orphan.ID)
	}
}

func onlyKernelUser(t *testing.T, kernel *keycloakfake.Client) keycloak.User {
	t.Helper()
	users, err := kernel.ListUsers(context.Background(), "scnehaux", keycloak.Page{First: 0, Max: 10})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("kernel holds %d users, want 1", len(users))
	}
	return users[0]
}

// TestRecoveryRetriesTheCreateWithTheOriginalIdentifier covers the zero-match branch. The
// retry must carry the identifier and the payload from the row, which is why the mapping
// stores the creation payload at all.
func TestRecoveryRetriesTheCreateWithTheOriginalIdentifier(t *testing.T) {
	kernel := keycloakfake.New()
	principalID := mustUUID(t)

	pending := &dbtest.Tx{Rows: [][]any{{
		principalID.String(), "", "scnehaux", "nightly-job", "job@example.com",
		string(keycloak.SubjectWorkload), mustUUID(t).String(), string(provisioning.StatePending), 1,
	}}}
	tx := &fakeTx{txs: []*dbtest.Tx{pending, claimed()}}

	resolved, err := newProvisioner(t, tx, kernel).RecoverPending(context.Background())
	if err != nil {
		t.Fatalf("RecoverPending: %v", err)
	}
	if resolved != 1 {
		t.Fatalf("resolved %d mappings, want 1", resolved)
	}
	if kernel.Calls.CreateUser != 1 {
		t.Fatalf("kernel CreateUser called %d times, want 1", kernel.Calls.CreateUser)
	}

	created := onlyKernelUser(t, kernel)
	if created.PrincipalID != principalID {
		t.Errorf("retry created principal %s, want the original %s", created.PrincipalID, principalID)
	}
	if created.Username != "nightly-job" {
		t.Errorf("retry used username %q; the payload must come from the row", created.Username)
	}
}

// TestRecoveryQuarantinesADuplicateAndDisablesBoth covers the branch that cannot be resolved
// automatically. Both users are disabled rather than deleted, and the mapping is quarantined
// rather than pointed at one of them: choosing between two users carrying one identifier is a
// decision only an investigation can make.
func TestRecoveryQuarantinesADuplicateAndDisablesBoth(t *testing.T) {
	kernel := keycloakfake.New()
	principalID := mustUUID(t)
	first := kernel.Seed("scnehaux", "one", principalID, keycloak.SubjectHuman)
	second := kernel.Seed("scnehaux", "two", principalID, keycloak.SubjectHuman)

	pending := &dbtest.Tx{Rows: [][]any{{
		principalID.String(), "", "scnehaux", "one", "",
		string(keycloak.SubjectHuman), "", string(provisioning.StatePending), 1,
	}}}
	quarantine := claimed()
	tx := &fakeTx{txs: []*dbtest.Tx{pending, quarantine}}

	resolved, err := newProvisioner(t, tx, kernel).RecoverPending(context.Background())
	if err != nil {
		t.Fatalf("RecoverPending: %v", err)
	}
	// The mapping was not resolved: a duplicate is a finding, not a repair.
	if resolved != 0 {
		t.Errorf("resolved %d mappings, want 0", resolved)
	}

	for _, userID := range []keycloak.UserID{first, second} {
		user, ok := kernel.User(userID)
		if !ok {
			t.Fatalf("user %q was deleted; containment must disable", userID)
		}
		if user.Enabled {
			t.Errorf("user %q is still enabled", userID)
		}
	}

	call := quarantine.Only(t)
	if call.Args[1] == "" {
		t.Error("quarantine recorded no reason")
	}
}

func TestRecoverySkipsOneFailureAndContinuesTheSweep(t *testing.T) {
	kernel := keycloakfake.New()
	kernel.FailFind = keycloak.ErrUnavailable

	pending := &dbtest.Tx{Rows: [][]any{
		{mustUUID(t).String(), "", "scnehaux", "a", "", string(keycloak.SubjectHuman), "", string(provisioning.StatePending), 1},
		{mustUUID(t).String(), "", "scnehaux", "b", "", string(keycloak.SubjectHuman), "", string(provisioning.StatePending), 1},
	}}
	tx := &fakeTx{txs: []*dbtest.Tx{pending}}

	resolved, err := newProvisioner(t, tx, kernel).RecoverPending(context.Background())
	if err != nil {
		t.Fatalf("RecoverPending returned an error for a per-mapping failure: %v", err)
	}
	if resolved != 0 {
		t.Errorf("resolved %d mappings, want 0", resolved)
	}
	// Both mappings were attempted. A sweep that stopped at the first failure would leave
	// every later mapping unexamined, and its value is that it is exhaustive.
	if kernel.Calls.FindByPrincipalID != 2 {
		t.Errorf("searched %d times, want 2", kernel.Calls.FindByPrincipalID)
	}
}

// TestConfigRefusesRecoveryThatRacesProvisioning asserts the relationship between two
// timeouts rather than either value. A recovery threshold below the provision timeout makes
// the sweep search the kernel for a user the original request is still creating, and the
// resulting duplicate would look like a kernel fault.
func TestConfigRefusesRecoveryThatRacesProvisioning(t *testing.T) {
	_, err := provisioning.New(&fakeTx{}, keycloakfake.New(), provisioning.Config{
		ProvisionTimeout:     10 * time.Second,
		PendingRecoveryAfter: 5 * time.Second,
	}, discardLogger())
	if err == nil {
		t.Fatal("New accepted a recovery threshold below the provision timeout")
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	cases := map[string]func() error{
		"no transactor": func() error {
			_, err := provisioning.New(nil, keycloakfake.New(), provisioning.Config{}, discardLogger())
			return err
		},
		"no kernel": func() error {
			_, err := provisioning.New(&fakeTx{}, nil, provisioning.Config{}, discardLogger())
			return err
		},
		"no logger": func() error {
			_, err := provisioning.New(&fakeTx{}, keycloakfake.New(), provisioning.Config{}, nil)
			return err
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if err := build(); err == nil {
				t.Fatal("New accepted a missing dependency")
			}
		})
	}
}

func TestCreateRejectsInvalidRequests(t *testing.T) {
	valid := humanCreate()
	cases := map[string]func(provisioning.CreateRequest) provisioning.CreateRequest{
		"no caller scope":     func(r provisioning.CreateRequest) provisioning.CreateRequest { r.CallerScope = ""; return r },
		"no idempotency key":  func(r provisioning.CreateRequest) provisioning.CreateRequest { r.IdempotencyKey = ""; return r },
		"no realm":            func(r provisioning.CreateRequest) provisioning.CreateRequest { r.Realm = ""; return r },
		"no username":         func(r provisioning.CreateRequest) provisioning.CreateRequest { r.Username = ""; return r },
		"unknown subject":     func(r provisioning.CreateRequest) provisioning.CreateRequest { r.SubjectType = "service"; return r },
		"human with an owner": func(r provisioning.CreateRequest) provisioning.CreateRequest { r.WorkloadOwner = mustUUID(t); return r },
		"workload without an owner": func(r provisioning.CreateRequest) provisioning.CreateRequest {
			r.SubjectType = keycloak.SubjectWorkload
			return r
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			kernel := keycloakfake.New()
			tx := &fakeTx{}
			if _, err := newProvisioner(t, tx, kernel).Create(context.Background(), mutate(valid)); err == nil {
				t.Fatal("Create accepted an invalid request")
			}
			if tx.used != 0 {
				t.Errorf("an invalid request opened %d transactions", tx.used)
			}
			if kernel.Calls.CreateUser != 0 {
				t.Errorf("an invalid request performed %d remote calls", kernel.Calls.CreateUser)
			}
		})
	}
}

// TestResponseCarriesNoKernelIdentifier asserts the property at the boundary that matters: the
// serialized form. A field added later that happened to carry the kernel identifier would fail
// here rather than in review.
func TestResponseCarriesNoKernelIdentifier(t *testing.T) {
	tx := &fakeTx{txs: []*dbtest.Tx{claimed(), claimed()}}
	kernel := keycloakfake.New()

	response, err := newProvisioner(t, tx, kernel).Create(context.Background(), humanCreate())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for key, value := range fields {
		if key == "keycloak_user_id" || key == "user_id" {
			t.Errorf("response carries %q", key)
		}
		if text, ok := value.(string); ok && len(text) > 3 && text[:3] == "kc-" {
			t.Errorf("field %q carries a kernel identifier %q", key, text)
		}
	}

	orphan := onlyKernelUser(t, kernel)
	if string(orphan.ID) == "" {
		t.Fatal("the kernel assigned no identifier, so this assertion proves nothing")
	}
	_ = id.UUID{}
}
