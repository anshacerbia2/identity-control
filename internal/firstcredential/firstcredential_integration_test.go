package firstcredential

// The first-credential path against the real engine and the kernel fake (TDD-identity-control-005
// 2.12.0 §A First Credential): issued once, never stored, replayed without its value, replaced,
// lapsed, and used.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

func openPool(t *testing.T) *db.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	p, err := db.Open(context.Background(), db.Config{Name: "firstcredential-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func newID(t *testing.T) id.UUID {
	t.Helper()
	v, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func exec(t *testing.T, p *db.Pool, statement string, args ...any) {
	t.Helper()
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, statement, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

func scalar[T any](t *testing.T, p *db.Pool, statement string, args ...any) T {
	t.Helper()
	var v T
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, statement, args...).Scan(&v)
	}); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
	return v
}

type fixture struct {
	pool     *db.Pool
	kernel   *keycloakfake.Client
	service  *Service
	realm    keycloak.Realm
	provider id.UUID
}

func setup(t *testing.T) fixture {
	t.Helper()
	p := openPool(t)
	realm := keycloak.Realm("first-credential-" + newID(t).String())
	kernel := keycloakfake.New()
	s, err := New(p, kernel, Config{Realm: realm, TTL: DefaultTTL, CallTimeout: 5 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{pool: p, kernel: kernel, service: s, realm: realm, provider: newID(t)}
}

// person creates a human Principal the way the creation path does: its kernel user owes
// UPDATE_PASSWORD and holds no credential.
func (f fixture) person(t *testing.T) (id.UUID, keycloak.UserID) {
	t.Helper()
	principal := newID(t)
	user := keycloak.UserID("kc-first-" + principal.String())
	f.kernel.SeedPerson(f.realm, user, "first-"+principal.String(), principal)
	exec(t, f.pool, `INSERT INTO identity.principal_mapping (principal_id, realm, username, subject_type, keycloak_user_id, state)
	    VALUES ($1, $2, $3, 'human', $4, 'active')`, principal.String(), string(f.realm), "first-"+principal.String(), string(user))
	return principal, user
}

func (f fixture) issue(t *testing.T, subject id.UUID, key string) (Issuance, bool, error) {
	t.Helper()
	return f.service.Issue(context.Background(), Request{Actor: Actor{Principal: f.provider, Correlation: "c-" + key,
		Assurance: "acr=aal2", Route: "POST /v1/principals/{principal_id}:issue-temporary-password"},
		Subject: subject, Reason: "first sign-in for a new colleague", IdempotencyKey: key})
}

// holds reports whether any text the service wrote, its records, its evidence and its key's answer,
// holds the value.
func (f fixture) holds(t *testing.T, value string) bool {
	t.Helper()
	return scalar[bool](t, f.pool, `SELECT
	    EXISTS (SELECT 1 FROM identity.temporary_password_issuance i WHERE i::text LIKE '%' || $1 || '%')
	 OR EXISTS (SELECT 1 FROM identity.temporary_password_outcome o WHERE o::text LIKE '%' || $1 || '%')
	 OR EXISTS (SELECT 1 FROM identity.privileged_access a WHERE a::text LIKE '%' || $1 || '%')
	 OR EXISTS (SELECT 1 FROM identity.security_notification n WHERE n::text LIKE '%' || $1 || '%')
	 OR EXISTS (SELECT 1 FROM platform.idempotency_key k WHERE k::text LIKE '%' || $1 || '%')`, value)
}

func outcome(t *testing.T, f fixture, issuance id.UUID) string {
	t.Helper()
	return scalar[string](t, f.pool, `SELECT coalesce((SELECT outcome FROM identity.temporary_password_outcome
	    WHERE issuance_id = $1), '')`, issuance.String())
}

func TestATemporaryPasswordIsIssuedOnceAndNeverStored(t *testing.T) {
	f := setup(t)
	subject, user := f.person(t)
	issued, replay, err := f.issue(t, subject, "issue-"+subject.String())
	if err != nil || replay {
		t.Fatalf("issue: %v (replay %t)", err, replay)
	}
	if len(issued.Value) != valueLength || issued.PrincipalID != subject || issued.IssuedBy != f.provider ||
		issued.LapsesAt.Sub(issued.IssuedAt) != DefaultTTL {
		t.Fatalf("the issuance is %+v", issued)
	}
	// The kernel holds it as temporary: UPDATE_PASSWORD stays outstanding.
	if set, _ := f.kernel.TemporaryPassword(user); set != issued.Value {
		t.Fatal("the kernel does not hold the value the provider was shown")
	}
	actions, _ := f.kernel.UserRequiredActions(context.Background(), f.realm, user)
	if !keycloak.OwesPassword(actions) {
		t.Fatalf("the kernel's required actions are %v; UPDATE_PASSWORD must stay outstanding", actions)
	}
	// Recorded, with its evidence, and the value nowhere in the database.
	if got := scalar[int](t, f.pool, `SELECT count(*) FROM identity.temporary_password_issuance WHERE principal_id = $1`,
		subject.String()); got != 1 {
		t.Fatalf("%d issuances recorded", got)
	}
	if got := scalar[int](t, f.pool, `SELECT count(*) FROM identity.privileged_access
	    WHERE subject_principal_id = $1 AND action = 'temporary_password.issue' AND outcome = 'applied'`,
		subject.String()); got != 1 {
		t.Fatalf("%d evidence rows", got)
	}
	if f.holds(t, issued.Value) {
		t.Fatal("the value was written to the database")
	}

	// A retry with the same key answers the issuance without the value, and sets nothing.
	calls := f.kernel.Calls.SetTemporaryPassword
	again, replay, err := f.issue(t, subject, "issue-"+subject.String())
	if err != nil || !replay || again.Value != "" || again.IssuanceID != issued.IssuanceID {
		t.Fatalf("the retry answered %+v, replay %t, %v", again, replay, err)
	}
	if f.kernel.Calls.SetTemporaryPassword != calls {
		t.Fatal("the retry set another password")
	}
	// The same key for another Principal is another request.
	other, _ := f.person(t)
	if _, _, err := f.issue(t, other, "issue-"+subject.String()); !errors.Is(err, ErrKeyReuse) {
		t.Fatalf("a reused key answered %v; want ErrKeyReuse", err)
	}

	// Issuing again replaces the first: the kernel holds one password.
	second, _, err := f.issue(t, subject, "issue-again-"+subject.String())
	if err != nil || second.Value == issued.Value {
		t.Fatalf("a second issuance: %v", err)
	}
	if got := outcome(t, f, issued.IssuanceID); got != OutcomeReplaced {
		t.Fatalf("the first issuance is %q; want replaced", got)
	}
	if got := outcome(t, f, second.IssuanceID); got != "" {
		t.Fatalf("the second issuance is %q; want open", got)
	}
}

func TestAPersonWhoSetTheirOwnPasswordIsRefused(t *testing.T) {
	f := setup(t)
	subject, user := f.person(t)
	f.kernel.ChoosePassword(user, time.Now())
	if _, _, err := f.issue(t, subject, "own-"+subject.String()); !errors.Is(err, ErrCredentialEstablished) {
		t.Fatalf("answered %v; want ErrCredentialEstablished", err)
	}
	if got := scalar[int](t, f.pool, `SELECT count(*) FROM identity.temporary_password_issuance WHERE principal_id = $1`,
		subject.String()); got != 0 {
		t.Fatalf("a refused issuance recorded %d rows", got)
	}
	// The refusal released the key: a corrected retry with it runs.
	if got := scalar[int](t, f.pool, `SELECT count(*) FROM platform.idempotency_key WHERE key = $1`, "own-"+subject.String()); got != 0 {
		t.Fatalf("the refused key is still held (%d)", got)
	}
}

func TestOnlyAnActiveLinkedHumanIsIssuedFor(t *testing.T) {
	f := setup(t)
	if _, _, err := f.issue(t, newID(t), "unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown Principal answered %v", err)
	}
	suspended, _ := f.person(t)
	exec(t, f.pool, `UPDATE identity.principal_mapping SET state = 'suspended' WHERE principal_id = $1`, suspended.String())
	if _, _, err := f.issue(t, suspended, "suspended-"+suspended.String()); !errors.Is(err, ErrState) {
		t.Fatalf("a suspended Principal answered %v", err)
	}
	// The refusal rolled its claim back.
	if got := scalar[int](t, f.pool, `SELECT count(*) FROM platform.idempotency_key WHERE key = $1`,
		"suspended-"+suspended.String()); got != 0 {
		t.Fatalf("a refused claim was kept (%d)", got)
	}
}

func TestAKernelFailureLeavesNothingTheSweepCannotRemove(t *testing.T) {
	f := setup(t)
	subject, _ := f.person(t)
	f.kernel.FailContainment = keycloak.ErrUnavailable
	if _, _, err := f.issue(t, subject, "down-"+subject.String()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("answered %v; want ErrUnavailable", err)
	}
	// The kernel may or may not hold a value, so the issuance stays open for the sweep.
	open := scalar[int](t, f.pool, `SELECT count(*) FROM identity.temporary_password_issuance i
	    WHERE i.principal_id = $1 AND NOT EXISTS (SELECT 1 FROM identity.temporary_password_outcome o
	    WHERE o.issuance_id = i.issuance_id)`, subject.String())
	if open != 1 {
		t.Fatalf("%d open issuances; want 1", open)
	}
	f.kernel.FailContainment = nil
	// A retry with the same key issues: the failed attempt released it.
	if _, replay, err := f.issue(t, subject, "down-"+subject.String()); err != nil || replay {
		t.Fatalf("the retry: %v (replay %t)", err, replay)
	}
}

func TestAnUnusedTemporaryPasswordLapsesAndAUsedOneIsKept(t *testing.T) {
	f := setup(t)
	unused, unusedUser := f.person(t)
	used, usedUser := f.person(t)
	lapsing, _, err := f.issue(t, unused, "lapse-"+unused.String())
	if err != nil {
		t.Fatal(err)
	}
	kept, _, err := f.issue(t, used, "use-"+used.String())
	if err != nil {
		t.Fatal(err)
	}
	// The person signs in and chooses a password; the kernel drops UPDATE_PASSWORD.
	f.kernel.ChoosePassword(usedUser, time.Now().Add(time.Hour))

	// Before the lapse nothing is due.
	if result, err := f.service.Sweep(context.Background()); err != nil || result != (SweepResult{}) {
		t.Fatalf("a sweep before the lapse: %+v, %v", result, err)
	}
	// After it, the unused value is deleted and the used one is recorded used and kept.
	f.service.now = func() time.Time { return time.Now().Add(DefaultTTL + time.Minute) }
	result, err := f.service.Sweep(context.Background())
	if err != nil || result.Lapsed < 1 || result.Used < 1 {
		t.Fatalf("the sweep: %+v, %v", result, err)
	}
	if got := outcome(t, f, lapsing.IssuanceID); got != OutcomeLapsed {
		t.Fatalf("the unused issuance is %q; want lapsed", got)
	}
	if got := outcome(t, f, kept.IssuanceID); got != OutcomeUsed {
		t.Fatalf("the used issuance is %q; want used", got)
	}
	unusedCredentials, _ := f.kernel.UserCredentials(context.Background(), f.realm, unusedUser)
	for _, c := range unusedCredentials {
		if c.Type == keycloak.PasswordCredential {
			t.Fatal("the lapsed temporary password is still in the kernel")
		}
	}
	usedCredentials, _ := f.kernel.UserCredentials(context.Background(), f.realm, usedUser)
	if len(usedCredentials) != 1 {
		t.Fatalf("the person's own password was touched: %+v", usedCredentials)
	}
	// A second sweep finds nothing left.
	if result, err := f.service.Sweep(context.Background()); err != nil || result != (SweepResult{}) {
		t.Fatalf("a repeated sweep: %+v, %v", result, err)
	}
}

// A password the person chose after the issuance is never deleted, even while UPDATE_PASSWORD reads
// outstanding: only a credential created within the set window is the issuance's.
func TestTheSweepDeletesOnlyThePasswordTheIssuanceSet(t *testing.T) {
	f := setup(t)
	subject, user := f.person(t)
	issued, _, err := f.issue(t, subject, "window-"+subject.String())
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(3 * time.Hour)
	f.kernel.SetSecurity(user, keycloakfake.Security{Credentials: []keycloak.Credential{
		{ID: "chosen", Type: keycloak.PasswordCredential, Created: later}}})
	f.service.now = func() time.Time { return time.Now().Add(DefaultTTL + time.Minute) }
	if _, err := f.service.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	credentials, _ := f.kernel.UserCredentials(context.Background(), f.realm, user)
	if len(credentials) != 1 || credentials[0].ID != "chosen" {
		t.Fatalf("the sweep removed a password created after the issuance: %+v", credentials)
	}
	if got := outcome(t, f, issued.IssuanceID); got != OutcomeLapsed {
		t.Fatalf("the issuance is %q; want lapsed", got)
	}
}

func TestThePersonsPasswordChangeInTheKernelEventRecordIsAUse(t *testing.T) {
	f := setup(t)
	subject, user := f.person(t)
	issued, _, err := f.issue(t, subject, "event-"+subject.String())
	if err != nil {
		t.Fatal(err)
	}
	event := keycloak.KernelEvent{Kind: keycloak.KindUserEvent, ID: "e1", Time: time.Now().Add(time.Minute),
		Type: "UPDATE_CREDENTIAL", UserID: string(user), Details: map[string]string{"credential_type": "password"}}
	// An event older than the issuance is not its use.
	old := event
	old.Time = issued.IssuedAt.Add(-time.Hour)
	for _, e := range []keycloak.KernelEvent{old, event, event} {
		if err := f.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			return f.service.FromKernelEvent(ctx, tx, f.realm, e)
		}); err != nil {
			t.Fatal(err)
		}
		if e.Time.Equal(old.Time) {
			if got := outcome(t, f, issued.IssuanceID); got != "" {
				t.Fatalf("an older change recorded %q", got)
			}
		}
	}
	if got := outcome(t, f, issued.IssuanceID); got != OutcomeUsed {
		t.Fatalf("the issuance is %q; want used", got)
	}
}

func TestTheRecordRefusesALapseBeyondADay(t *testing.T) {
	f := setup(t)
	subject, _ := f.person(t)
	err := f.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, insertIssuanceStatement, newID(t).String(), subject.String(), f.provider.String(),
			"r", "c", false, "acr=aal2", time.Now(), time.Now().Add(25*time.Hour))
		return err
	})
	if err == nil {
		t.Fatal("an issuance lapsing after 25 hours was recorded")
	}
}

// A lapse the kernel cannot complete is left open and retried by the next sweep.
func TestALapseTheKernelRefusesIsRetried(t *testing.T) {
	f := setup(t)
	subject, _ := f.person(t)
	issued, _, err := f.issue(t, subject, "retry-"+subject.String())
	if err != nil {
		t.Fatal(err)
	}
	f.service.now = func() time.Time { return time.Now().Add(DefaultTTL + time.Minute) }
	f.kernel.FailSecurity = keycloak.ErrUnavailable
	if _, err := f.service.Sweep(context.Background()); err == nil {
		t.Fatal("a sweep the kernel refused reported no failure")
	}
	if got := outcome(t, f, issued.IssuanceID); got != "" {
		t.Fatalf("a refused lapse recorded %q", got)
	}
	f.kernel.FailSecurity = nil
	if result, err := f.service.Sweep(context.Background()); err != nil || result.Lapsed != 1 {
		t.Fatalf("the retry: %+v, %v", result, err)
	}
	// A key still in progress refuses its retry rather than issuing twice.
	exec(t, f.pool, `INSERT INTO platform.idempotency_key (scope, key, request_digest) VALUES ($1, $2, 'other')`,
		"temporary-password:principal:"+f.provider.String(), "held-"+subject.String())
	if _, _, err := f.issue(t, subject, "held-"+subject.String()); !errors.Is(err, ErrKeyReuse) && !errors.Is(err, ErrInProgress) {
		t.Fatalf("a held key answered %v", err)
	}
}
