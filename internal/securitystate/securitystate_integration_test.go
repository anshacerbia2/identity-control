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

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

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

// selfCommand is a person's command on their own Principal: no reason, no version.
func (h *harness) selfCommand(opType string, person id.UUID, ref string) Command {
	h.keys++
	return Command{Self: true, Type: opType, Subject: person, Ref: ref,
		IdempotencyKey: "self-" + person.String() + "-" + string(rune('a'+h.keys)),
		Actor: Actor{Principal: person, Correlation: "corr-self",
			Assurance: "acr=1;auth_time=2026-10-03T12:00:00Z"}}
}

func (h *harness) selfEvidence(subject id.UUID) []record {
	h.t.Helper()
	var out []record
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT action, outcome, coalesce(reason, '<null>'), route
		  FROM identity.privileged_access WHERE subject_principal_id = $1 AND actor_principal_id = $1 AND NOT emergency
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

// A person lists their sessions, the current one marked by sid, and ends one of them; the other is
// kept, and the command is evidenced with the person as actor and subject and no reason.
func TestAPersonEndsOneOfTheirSessions(t *testing.T) {
	h := newHarness(t)
	person, user := h.principal("human", "active")
	h.kernel.SetSecurity(user, keycloakfake.Security{Sessions: []keycloak.Session{{ID: "s-here"}, {ID: "s-there"}}})
	ctx := context.Background()

	sessions, err := h.service.MySessions(ctx, person, "s-here")
	if err != nil || len(sessions) != 2 {
		t.Fatalf("MySessions: %+v, %v", sessions, err)
	}
	there := sessions[1].SecurityRef
	if !sessions[0].Current || sessions[1].Current {
		t.Errorf("current marks %t %t; want the sid's session alone", sessions[0].Current, sessions[1].Current)
	}

	op, err := h.service.Submit(ctx, h.selfCommand(TypeSessionTerminate, person, there))
	if err != nil || op.State != StateApplied {
		t.Fatalf("ending one session: %+v, %v", op, err)
	}
	left, _ := h.kernel.UserSessions(ctx, testRealm, user)
	if len(left) != 1 || left[0].ID != "s-here" {
		t.Errorf("sessions left %+v; want the current one", left)
	}
	if records := h.selfEvidence(person); len(records) != 1 ||
		records[0] != (record{TypeSessionTerminate, "applied", "<null>", "POST /v1/me/sessions/{security_ref}:terminate"}) {
		t.Errorf("evidence %+v", records)
	}
	if version, _ := h.service.SecurityVersion(ctx, person); version != 2 {
		t.Errorf("security_version %d; a self command advances it too", version)
	}
	if _, err := h.service.Submit(ctx, h.command(TypeSuspend, person, 1)); !errors.Is(err, ErrVersion) {
		t.Errorf("an administrator's command on the version before: %v, want ErrVersion", err)
	}
}

// A person's handle opens on the self routes only, and an administrator's on the administrative
// ones only.
func TestSelfAndAdministrativeReferencesDoNotCross(t *testing.T) {
	h := newHarness(t)
	person, user := h.principal("human", "active")
	h.kernel.SetSecurity(user, keycloakfake.Security{Credentials: []keycloak.Credential{
		{ID: "kc-password", Type: "password"}, {ID: "kc-otp", Type: "otp"}}})
	ctx := context.Background()
	mine, err := h.service.MyAuthenticators(ctx, person)
	if err != nil || len(mine) != 2 {
		t.Fatalf("MyAuthenticators: %+v, %v", mine, err)
	}
	admin, _ := h.refs.Seal(securityref.KindCredential, person, securityref.PurposeAdminRevoke, string(testRealm), "kc-otp")

	if _, err := h.service.Submit(ctx, h.selfCommand(TypeAuthenticatorRemove, person, admin)); !errors.Is(err, ErrNotFound) {
		t.Errorf("an administrator's handle on the self route: %v, want ErrNotFound", err)
	}
	revoke := h.command(TypeRevoke, person, 1)
	revoke.Ref = mine[1].SecurityRef
	if _, err := h.service.Submit(ctx, revoke); !errors.Is(err, ErrNotFound) {
		t.Errorf("a person's handle on the administrative route: %v, want ErrNotFound", err)
	}

	var otp, password string
	for _, a := range mine {
		if a.Type == "otp" {
			otp = a.SecurityRef
		} else {
			password = a.SecurityRef
		}
	}
	if op, err := h.service.Submit(ctx, h.selfCommand(TypeAuthenticatorRemove, person, otp)); err != nil || op.State != StateApplied {
		t.Errorf("removing one's OTP: %+v, %v", op, err)
	}
	if op, err := h.service.Submit(ctx, h.selfCommand(TypeAuthenticatorRemove, person, password)); err != nil ||
		op.State != StateRefused || op.ResultCode != ResultLastAuthenticator {
		t.Errorf("removing one's last password: %+v, %v", op, err)
	}
}

func TestASuspendedPersonCommandsNothingAndReadsOnlyTheirOwnOperations(t *testing.T) {
	h := newHarness(t)
	person, _ := h.principal("human", "suspended")
	other, _ := h.principal("human", "active")
	ctx := context.Background()
	if _, err := h.service.Submit(ctx, h.selfCommand(TypeTerminateAll, person, "")); !errors.Is(err, ErrState) {
		t.Errorf("a suspended person's command: %v, want ErrState", err)
	}
	op, err := h.service.Submit(ctx, h.selfCommand(TypeTerminateAll, other, ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.MyOperation(ctx, other, op.OperationID); err != nil {
		t.Errorf("one's own operation: %v", err)
	}
	if _, err := h.service.MyOperation(ctx, person, op.OperationID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another person's operation: %v, want ErrNotFound", err)
	}
}

// A parked operation is listed, re-driven with a reason and a new attempt budget, evidenced, and
// then completes once its cause is gone; a second re-drive finds nothing parked.
func TestAParkedOperationIsRedriven(t *testing.T) {
	h := newHarness(t)
	alice, user := h.principal("human", "active")
	h.kernel.FailDisable = keycloak.ErrUnavailable
	ctx := context.Background()
	op, err := h.service.Submit(ctx, h.command(TypeSuspend, alice, 1))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := h.service.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	parked, err := h.service.Unresolved(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range parked {
		if p.OperationID == op.OperationID && p.Attempts == 3 && p.LastErrorClass == "unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the parked operation is not listed: %+v", parked)
	}

	h.kernel.FailDisable = nil
	operator := Actor{Principal: h.actor, Correlation: "corr-redrive", Assurance: "acr=aal2;auth_time=2026-10-03T12:00:00Z"}
	redriven, err := h.service.Redrive(ctx, operator, op.OperationID, "kernel back after the outage")
	if err != nil || redriven.State != StateApplied || redriven.Attempts != 4 {
		t.Fatalf("re-drive: %+v, %v", redriven, err)
	}
	if got, _ := h.kernel.User(user); got.Enabled {
		t.Error("the re-driven suspension did not disable the user")
	}
	if n := h.count(`SELECT count(*) FROM identity.privileged_access WHERE subject_principal_id = $1
	    AND action = 'operation.redrive' AND reason = 'kernel back after the outage' AND correlation_id = 'corr-redrive'`,
		alice.String()); n != 1 {
		t.Errorf("%d re-drive evidence rows", n)
	}
	if _, err := h.service.Redrive(ctx, operator, op.OperationID, "again"); !errors.Is(err, ErrState) {
		t.Errorf("re-driving an applied operation: %v, want ErrState", err)
	}
	missing, _ := id.NewV7()
	if _, err := h.service.Redrive(ctx, operator, missing, "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("re-driving an absent operation: %v, want ErrNotFound", err)
	}
}

// The executor's metrics reach a meter: accepted commands and attempts by outcome.
func TestTheExecutorIsMeasured(t *testing.T) {
	h := newHarness(t)
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	service, err := New(h.pool, h.kernel, h.refs, Config{Realm: testRealm, Budget: 5 * time.Second,
		AttemptTimeout: time.Second, Meter: provider.Meter("test")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := h.principal("human", "active")
	if _, err := service.Submit(context.Background(), h.command(TypeTerminateAll, alice, 1)); err != nil {
		t.Fatal(err)
	}
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			seen[m.Name] = true
		}
	}
	for _, name := range []string{"identity.security_operation.accepted", "identity.security_operation.attempts",
		"identity.security_operation.wait", "identity.security_operation.duration", "identity.security_operation.unresolved"} {
		if !seen[name] {
			t.Errorf("%s was not recorded; recorded %v", name, seen)
		}
	}
}

type providers map[id.UUID]bool

func (p providers) Holds(_ context.Context, principal id.UUID) (bool, bool, error) {
	return p[principal], false, nil
}

// A provider keeps a second factor: their last one is not removed, by themselves or by another
// provider; a person who is no provider may remove theirs.
func TestAProviderKeepsTheirLastSecondFactor(t *testing.T) {
	h := newHarness(t)
	provider, providerUser := h.principal("human", "active")
	person, personUser := h.principal("human", "active")
	h.service.UseProviders(providers{provider: true})
	for _, user := range []keycloak.UserID{providerUser, personUser} {
		h.kernel.SetSecurity(user, keycloakfake.Security{Credentials: []keycloak.Credential{
			{ID: "kc-password-" + string(user), Type: "password"}, {ID: "kc-otp-" + string(user), Type: "otp"}}})
	}
	ctx := context.Background()
	seal := func(subject id.UUID, purpose, kernelID string) string {
		handle, err := h.refs.Seal(securityref.KindCredential, subject, purpose, string(testRealm), kernelID)
		if err != nil {
			t.Fatal(err)
		}
		return handle
	}

	own := h.selfCommand(TypeAuthenticatorRemove, provider, seal(provider, securityref.PurposeSelfAuthenticatorRemove,
		"kc-otp-"+string(providerUser)))
	if op, err := h.service.Submit(ctx, own); err != nil || op.State != StateRefused || op.ResultCode != ResultAssuranceFloor {
		t.Errorf("a provider removing their last second factor: %+v, %v", op, err)
	}
	revoke := h.command(TypeRevoke, provider, 2)
	revoke.Ref = seal(provider, securityref.PurposeAdminRevoke, "kc-otp-"+string(providerUser))
	if op, err := h.service.Submit(ctx, revoke); err != nil || op.State != StateRefused || op.ResultCode != ResultAssuranceFloor {
		t.Errorf("another provider revoking it: %+v, %v", op, err)
	}

	// Assisted recovery (ADR-IAM-005 §5.5): once the provider is suspended, they cannot sign in, and
	// their lost factor is revoked.
	if op, err := h.service.Submit(ctx, h.command(TypeSuspend, provider, 3)); err != nil || op.State != StateApplied {
		t.Fatalf("suspending the provider: %+v, %v", op, err)
	}
	revoke = h.command(TypeRevoke, provider, 4)
	revoke.Ref = seal(provider, securityref.PurposeAdminRevoke, "kc-otp-"+string(providerUser))
	if op, err := h.service.Submit(ctx, revoke); err != nil || op.State != StateApplied {
		t.Errorf("revoking a suspended provider's last second factor: %+v, %v", op, err)
	}

	theirs := h.selfCommand(TypeAuthenticatorRemove, person, seal(person, securityref.PurposeSelfAuthenticatorRemove,
		"kc-otp-"+string(personUser)))
	if op, err := h.service.Submit(ctx, theirs); err != nil || op.State != StateApplied {
		t.Errorf("a person who is no provider removing theirs: %+v, %v", op, err)
	}
}

// Binding takes the account's highest level (NIST SP 800-63B-4 4.1.2.1), and the authorization is
// recorded; only the types the API enrolls are authorized.
func TestEnrollingTakesTheAccountsLevel(t *testing.T) {
	h := newHarness(t)
	fresh, freshUser := h.principal("human", "active")
	enrolled, enrolledUser := h.principal("human", "active")
	h.kernel.SetSecurity(freshUser, keycloakfake.Security{Credentials: []keycloak.Credential{{ID: "p1", Type: "password"}}})
	h.kernel.SetSecurity(enrolledUser, keycloakfake.Security{Credentials: []keycloak.Credential{
		{ID: "p2", Type: "password"}, {ID: "o2", Type: "otp"}}})
	ctx := context.Background()
	actor := func(p id.UUID) Actor { return Actor{Principal: p, Correlation: "corr-enroll", Assurance: "acr=aal1"} }

	if level, err := h.service.EnrollmentLevel(ctx, fresh); err != nil || level != "aal1" {
		t.Errorf("a person with no second factor: %q, %v", level, err)
	}
	if level, err := h.service.EnrollmentLevel(ctx, enrolled); err != nil || level != "aal2" {
		t.Errorf("a person with one: %q, %v", level, err)
	}
	onlyAAL1 := func(level string) bool { return level == "aal1" }
	if action, err := h.service.Enroll(ctx, actor(fresh), "totp", onlyAAL1); err != nil || action != "CONFIGURE_TOTP" {
		t.Errorf("enrolling a first: %q, %v", action, err)
	}
	if _, err := h.service.Enroll(ctx, actor(enrolled), "totp", onlyAAL1); func() bool {
		level, ok := IsStepUp(err)
		return !ok || level != "aal2"
	}() {
		t.Errorf("enrolling a second at aal1: %v, want a step-up to aal2", err)
	}
	if action, err := h.service.Enroll(ctx, actor(fresh), "webauthn", onlyAAL1); err != nil || action != "webauthn-register" {
		t.Errorf("enrolling a first security key: %q, %v", action, err)
	}
	if _, err := h.service.Enroll(ctx, actor(enrolled), "webauthn", onlyAAL1); func() bool {
		level, ok := IsStepUp(err)
		return !ok || level != "aal2"
	}() {
		t.Errorf("enrolling a security key at aal1 beside a TOTP: %v, want a step-up to aal2", err)
	}
	if action, err := h.service.Enroll(ctx, actor(enrolled), "recovery-codes", func(string) bool { return true }); err != nil ||
		action != "CONFIGURE_RECOVERY_AUTHN_CODES" {
		t.Errorf("a new set of recovery codes: %q, %v", action, err)
	}
	for _, refused := range []string{"sms", "webauthn-passwordless", "WEBAUTHN"} {
		if _, err := h.service.Enroll(ctx, actor(fresh), refused, onlyAAL1); !errors.Is(err, ErrInvalid) {
			t.Errorf("type %q: %v, want ErrInvalid", refused, err)
		}
	}
	if _, err := h.service.Enroll(ctx, actor(fresh), "sms", onlyAAL1); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unknown type: %v, want ErrInvalid", err)
	}
	if n := h.count(`SELECT count(*) FROM identity.privileged_access WHERE actor_principal_id = $1
	    AND action = 'authenticator.enroll' AND outcome = 'served'`, fresh.String()); n != 2 {
		t.Errorf("%d enrollment records", n)
	}
}

// The applied hook sees each applied command once, in the transaction that records it: a hook that
// fails leaves the command unfinished rather than applied without what the hook writes
// (TDD-identity-control-008 1.3.0).
func TestTheAppliedHookSeesEachAppliedCommandOnce(t *testing.T) {
	h := newHarness(t)
	alice, _ := h.principal("human", "active")
	ctx := context.Background()
	var seen []Applied
	h.service.OnApplied(func(_ context.Context, _ db.Tx, op Applied) error {
		seen = append(seen, op)
		return nil
	})
	suspended, err := h.service.Submit(ctx, h.command(TypeSuspend, alice, 1))
	if err != nil || suspended.State != StateApplied {
		t.Fatalf("suspend: %+v, %v", suspended, err)
	}
	restored, err := h.service.Submit(ctx, h.command(TypeRestore, alice, 2))
	if err != nil || restored.State != StateApplied {
		t.Fatalf("restore: %+v, %v", restored, err)
	}
	want := []Applied{
		{OperationID: suspended.OperationID, Type: TypeSuspend, Subject: alice, Actor: h.actor},
		{OperationID: restored.OperationID, Type: TypeRestore, Subject: alice, Actor: h.actor},
	}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Errorf("the hook saw %+v; want %+v", seen, want)
	}

	bob, _ := h.principal("human", "active")
	if _, err := h.service.Submit(ctx, h.command(TypeSuspend, bob, 1)); err != nil {
		t.Fatal(err)
	}
	h.service.OnApplied(func(context.Context, db.Tx, Applied) error { return errors.New("no request recorded") })
	op, _ := h.service.Submit(ctx, h.command(TypeRestore, bob, 2))
	if op.State == StateApplied || op.AppliedAt != nil {
		t.Errorf("a restore whose hook failed reads %s; it must not be applied without what the hook writes", op.State)
	}
	if n := h.count(`SELECT count(*) FROM identity.privileged_access WHERE subject_principal_id = $1 AND action = $2`,
		bob.String(), TypeRestore); n != 0 {
		t.Errorf("%d restore evidence records committed beside a failed hook", n)
	}
}
