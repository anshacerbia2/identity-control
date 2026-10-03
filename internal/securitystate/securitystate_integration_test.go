package securitystate

// Security commands against a real PostgreSQL and the fake kernel. Each test owns the rows of its
// own realm; the evidence is insert-only and is read by the test's own subjects.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
	"github.com/anshacerbia2/identity-control/internal/securityref"
)

const testRealm = keycloak.Realm("securitystate-test")

type harness struct {
	t       *testing.T
	pool    *db.Pool
	kernel  *keycloakfake.Client
	refs    *securityref.Codec
	service *Service
	actor   id.UUID
	keys    int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{Name: "securitystate-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, statement := range []string{
			`DELETE FROM identity.security_operation_attempt WHERE operation_id IN
			   (SELECT o.operation_id FROM identity.security_operation o
			    JOIN identity.principal_mapping m ON m.principal_id = o.principal_id WHERE m.realm = $1)`,
			`DELETE FROM identity.security_operation WHERE principal_id IN
			   (SELECT principal_id FROM identity.principal_mapping WHERE realm = $1)`,
			`DELETE FROM identity.security_subject_state WHERE principal_id IN
			   (SELECT principal_id FROM identity.principal_mapping WHERE realm = $1)`,
			`DELETE FROM identity.principal_finding WHERE principal_id IN
			   (SELECT principal_id FROM identity.principal_mapping WHERE realm = $1)`,
			`DELETE FROM identity.principal_mapping WHERE realm = $1`,
		} {
			if _, err := tx.Exec(ctx, statement, string(testRealm)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("empty this realm's Principals: %v", err)
	}
	refs, err := securityref.New([]securityref.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	kernel := keycloakfake.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := New(pool, kernel, refs, Config{Realm: testRealm, Budget: 5 * time.Second, AttemptTimeout: time.Second},
		logger)
	if err != nil {
		t.Fatal(err)
	}
	// Retries are due at once, so a test drives each attempt with RunOnce rather than by waiting.
	service.jitter = func(time.Duration) time.Duration { return 0 }
	actor, _ := id.NewV7()
	return &harness{t: t, pool: pool, kernel: kernel, refs: refs, service: service, actor: actor}
}

// principal records a mapping and, unless it is pending, its kernel user.
func (h *harness) principal(subjectType, state string) (id.UUID, keycloak.UserID) {
	h.t.Helper()
	principalID, _ := id.NewV7()
	var (
		user  keycloak.UserID
		kcArg any
		owner any
	)
	if state != "pending" {
		user = keycloak.UserID("kc-securitystate-" + principalID.String())
		h.kernel.AddServiceAccount(testRealm, keycloak.User{ID: user, Username: "user-" + principalID.String()})
		kcArg = string(user)
	}
	if subjectType == "workload" {
		owner = h.actor.String()
	}
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
		    (principal_id, realm, username, subject_type, workload_owner, keycloak_user_id, state)
		    VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			principalID.String(), string(testRealm), "user-"+principalID.String(), subjectType, owner, kcArg, state)
		return err
	}); err != nil {
		h.t.Fatalf("record a %s %s Principal: %v", state, subjectType, err)
	}
	return principalID, user
}

func (h *harness) command(opType string, subject id.UUID, version int64) Command {
	h.keys++
	return Command{Type: opType, Subject: subject, ExpectedVersion: version, Reason: "incident 42",
		IdempotencyKey: "key-" + subject.String() + "-" + string(rune('a'+h.keys)),
		Actor: Actor{Principal: h.actor, Emergency: true, Correlation: "corr-1",
			Assurance: "acr=1;auth_time=2026-10-03T12:00:00Z"}}
}

func (h *harness) mappingState(principalID id.UUID) string {
	h.t.Helper()
	var state string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM identity.principal_mapping WHERE principal_id = $1`,
			principalID.String()).Scan(&state)
	}); err != nil {
		h.t.Fatal(err)
	}
	return state
}

type record struct{ action, outcome, reason, correlation string }

func (h *harness) evidence(subject id.UUID) []record {
	h.t.Helper()
	var out []record
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT action, outcome, coalesce(reason, ''), correlation_id
		  FROM identity.privileged_access WHERE subject_principal_id = $1 AND emergency
		  ORDER BY recorded_at, access_id`, subject.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r record
			if err := rows.Scan(&r.action, &r.outcome, &r.reason, &r.correlation); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	}); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *harness) count(query string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(&n)
	}); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestASuspensionDisablesEndsTheSessionsAndIsEvidenced(t *testing.T) {
	h := newHarness(t)
	alice, user := h.principal("human", "active")
	h.kernel.SetSecurity(user, keycloakfake.Security{Sessions: []keycloak.Session{{ID: "s1"}, {ID: "s2"}}})
	ctx := context.Background()

	op, err := h.service.Submit(ctx, h.command(TypeSuspend, alice, 1))
	if err != nil || op.State != StateApplied || op.Attempts != 1 || op.AppliedAt == nil {
		t.Fatalf("Submit: %+v, %v", op, err)
	}
	if got, _ := h.kernel.User(user); got.Enabled {
		t.Error("the kernel user is still enabled")
	}
	if sessions, _ := h.kernel.UserSessions(ctx, testRealm, user); len(sessions) != 0 {
		t.Errorf("%d sessions remain", len(sessions))
	}
	if state := h.mappingState(alice); state != "suspended" {
		t.Errorf("the mapping is %s", state)
	}
	if version, _ := h.service.SecurityVersion(ctx, alice); version != 2 {
		t.Errorf("security_version %d, want 2", version)
	}
	if records := h.evidence(alice); len(records) != 1 || records[0] != (record{TypeSuspend, "applied", "incident 42", "corr-1"}) {
		t.Errorf("evidence %+v", records)
	}
	if n := h.count(`SELECT count(*) FROM identity.security_operation_attempt WHERE operation_id = $1 AND outcome = 'applied'`,
		op.OperationID.String()); n != 1 {
		t.Errorf("%d applied attempts recorded", n)
	}

	restored, err := h.service.Submit(ctx, h.command(TypeRestore, alice, 2))
	if err != nil || restored.State != StateApplied {
		t.Fatalf("restore: %+v, %v", restored, err)
	}
	if got, _ := h.kernel.User(user); !got.Enabled || h.mappingState(alice) != "active" {
		t.Errorf("restored: enabled %t, mapping %s", got.Enabled, h.mappingState(alice))
	}
}

// A repeated key returns its operation and repeats no effect, though that operation moved the
// version and the state it was checked against. The same key for another request is refused.
func TestARepeatedKeyReturnsItsOperation(t *testing.T) {
	h := newHarness(t)
	alice, _ := h.principal("human", "active")
	ctx := context.Background()
	cmd := h.command(TypeSuspend, alice, 1)

	first, err := h.service.Submit(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	again, err := h.service.Submit(ctx, cmd)
	if err != nil || again.OperationID != first.OperationID || again.State != StateApplied {
		t.Fatalf("the repeat: %+v, %v", again, err)
	}
	if h.kernel.Calls.DisableUser != 1 {
		t.Errorf("%d disables for one operation", h.kernel.Calls.DisableUser)
	}
	other := cmd
	other.Reason = "another incident"
	if _, err := h.service.Submit(ctx, other); !errors.Is(err, ErrKeyReuse) {
		t.Errorf("the key for another request: %v, want ErrKeyReuse", err)
	}
}

func TestACommandIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	h := newHarness(t)
	active, _ := h.principal("human", "active")
	pending, _ := h.principal("human", "pending")
	workload, _ := h.principal("workload", "active")
	absent, _ := id.NewV7()
	ctx := context.Background()

	self := h.command(TypeSuspend, h.actor, 1)
	noReason := h.command(TypeSuspend, active, 1)
	noReason.Reason = " "
	for name, c := range map[string]struct {
		cmd  Command
		want error
	}{
		"itself":              {self, ErrSelfAction},
		"no reason":           {noReason, ErrInvalid},
		"an outdated version": {h.command(TypeSuspend, active, 2), ErrVersion},
		"an absent Principal": {h.command(TypeSuspend, absent, 1), ErrNotFound},
		"a workload":          {h.command(TypeSuspend, workload, 1), ErrWorkload},
		"no kernel user":      {h.command(TypeTerminateAll, pending, 1), ErrState},
		"restoring an active": {h.command(TypeRestore, active, 1), ErrState},
		"a foreign reference": {func() Command {
			c := h.command(TypeRevoke, active, 1)
			c.Ref, _ = h.refs.Seal(securityref.KindCredential, workload, securityref.PurposeAdminRevoke, string(testRealm), "x")
			return c
		}(), ErrNotFound},
	} {
		if _, err := h.service.Submit(ctx, c.cmd); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if n := h.count(`SELECT count(*) FROM identity.security_operation WHERE actor_principal_id = $1`, h.actor.String()); n != 0 {
		t.Errorf("%d operations written by refused commands", n)
	}
	if h.mappingState(active) != "active" {
		t.Error("a refused command moved the mapping")
	}
}

func TestARestoreWaitsForAnOpenFinding(t *testing.T) {
	h := newHarness(t)
	alice, user := h.principal("human", "active")
	ctx := context.Background()
	if _, err := h.service.Submit(ctx, h.command(TypeSuspend, alice, 1)); err != nil {
		t.Fatal(err)
	}
	findingID, _ := id.NewV7()
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_finding (finding_id, principal_id, finding_class, keycloak_user_id)
		    VALUES ($1, $2, 'dangling', $3)`, findingID.String(), alice.String(), string(user))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Submit(ctx, h.command(TypeRestore, alice, 2)); !errors.Is(err, ErrState) {
		t.Errorf("a restore with an open finding: %v, want ErrState", err)
	}
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.principal_finding SET resolved_at = now(), resolution = 'user_present'
		    WHERE finding_id = $1`, findingID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if op, err := h.service.Submit(ctx, h.command(TypeRestore, alice, 2)); err != nil || op.State != StateApplied {
		t.Errorf("a restore once the finding is resolved: %+v, %v", op, err)
	}
}

// A second factor is revoked; the last first factor is refused, and the refusal is evidenced.
func TestARevocationKeepsTheLastFirstFactor(t *testing.T) {
	h := newHarness(t)
	alice, user := h.principal("human", "active")
	h.kernel.SetSecurity(user, keycloakfake.Security{Credentials: []keycloak.Credential{
		{ID: "kc-password", Type: "password"}, {ID: "kc-otp", Type: "otp"}}})
	ctx := context.Background()
	seal := func(kernelID string) string {
		handle, err := h.refs.Seal(securityref.KindCredential, alice, securityref.PurposeAdminRevoke, string(testRealm), kernelID)
		if err != nil {
			t.Fatal(err)
		}
		return handle
	}

	otp := h.command(TypeRevoke, alice, 1)
	otp.Ref = seal("kc-otp")
	if op, err := h.service.Submit(ctx, otp); err != nil || op.State != StateApplied {
		t.Fatalf("revoking the OTP: %+v, %v", op, err)
	}
	credentials, _ := h.kernel.UserCredentials(ctx, testRealm, user)
	if len(credentials) != 1 || credentials[0].ID != "kc-password" {
		t.Errorf("credentials after the OTP's revocation: %+v", credentials)
	}

	password := h.command(TypeRevoke, alice, 2)
	password.Ref = seal("kc-password")
	op, err := h.service.Submit(ctx, password)
	if err != nil || op.State != StateRefused || op.ResultCode != ResultLastAuthenticator {
		t.Fatalf("revoking the last password: %+v, %v", op, err)
	}
	if credentials, _ := h.kernel.UserCredentials(ctx, testRealm, user); len(credentials) != 1 {
		t.Error("the last first factor was deleted")
	}
	records := h.evidence(alice)
	if len(records) != 2 || records[0].outcome != "applied" || records[1].outcome != "refused" ||
		records[1].action != TypeRevoke {
		t.Errorf("evidence %+v", records)
	}
}

// A transient failure is retried after a backoff; after the last attempt the operation is parked as
// unresolved, nothing is evidenced, and the Principal's later commands wait behind it.
func TestATransientFailureIsRetriedThenParked(t *testing.T) {
	h := newHarness(t)
	alice, _ := h.principal("human", "active")
	h.kernel.FailDisable = keycloak.ErrUnavailable
	ctx := context.Background()

	op, err := h.service.Submit(ctx, h.command(TypeSuspend, alice, 1))
	if err != nil || op.State != StateRetrying || op.Attempts != 1 {
		t.Fatalf("first attempt: %+v, %v", op, err)
	}
	for attempt := 2; attempt <= 3; attempt++ {
		if _, err := h.service.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	op, _ = h.service.Get(ctx, op.OperationID)
	if op.State != StateUnresolved || op.Attempts != 3 {
		t.Fatalf("after three attempts: %+v", op)
	}
	if records := h.evidence(alice); len(records) != 0 {
		t.Errorf("an unresolved operation was evidenced: %+v", records)
	}

	h.kernel.FailDisable = nil
	later, err := h.service.Submit(ctx, h.command(TypeTerminateAll, alice, 2))
	if err != nil {
		t.Fatal(err)
	}
	if later.State != StatePending || later.Attempts != 0 {
		t.Errorf("a command behind an unresolved one ran: %+v", later)
	}
	if _, err := h.service.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if later, _ = h.service.Get(ctx, later.OperationID); later.State != StatePending {
		t.Errorf("the executor ran a command behind an unresolved one: %+v", later)
	}
}

// A worker whose lease another took over finishes nothing: no state, no evidence.
func TestAnAttemptWhoseLeaseWasTakenFinishesNothing(t *testing.T) {
	h := newHarness(t)
	alice, _ := h.principal("human", "active")
	ctx := context.Background()
	op, err := h.service.Accept(ctx, h.command(TypeTerminateAll, alice, 1))
	if err != nil {
		t.Fatal(err)
	}
	work, err := h.service.claim(ctx, &op.OperationID)
	if err != nil || len(work) != 1 {
		t.Fatalf("claim: %d, %v", len(work), err)
	}
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.security_operation SET attempts = attempts + 1 WHERE operation_id = $1`,
			op.OperationID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.service.finish(ctx, work[0], outcome{state: StateApplied, resultCode: StateApplied}); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.service.Get(ctx, op.OperationID); got.State != StatePending {
		t.Errorf("the overtaken attempt finished the operation: %+v", got)
	}
	if records := h.evidence(alice); len(records) != 0 {
		t.Errorf("the overtaken attempt was evidenced: %+v", records)
	}
}
