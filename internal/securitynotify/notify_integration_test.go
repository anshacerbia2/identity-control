package securitynotify

// Requests and their dispatch against the real engine (TDD-identity-control-008 §Testing Strategy).

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
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
	p, err := db.Open(context.Background(), db.Config{Name: "securitynotify-test", DSN: dsn, MaxConns: 4})
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

// person records an active human Principal mapped to a fresh kernel user, with the given addresses.
func person(t *testing.T, p *db.Pool, realm keycloak.Realm, addresses ...string) (id.UUID, string) {
	t.Helper()
	principal, kcUser := newID(t), newID(t).String()
	exec(t, p, `INSERT INTO identity.principal_mapping (principal_id, realm, username, subject_type, keycloak_user_id, state)
	    VALUES ($1, $2, $3, 'human', $4, 'active')`, principal.String(), string(realm), "notify-"+principal.String(), kcUser)
	for _, a := range addresses {
		exec(t, p, `INSERT INTO identity.notification_address (address_id, principal_id, channel, address, origin, state)
		    VALUES ($1, $2, 'email', $3, 'creation', 'active')`, newID(t).String(), principal.String(), a)
	}
	return principal, kcUser
}

func request(t *testing.T, p *db.Pool, realm keycloak.Realm, e keycloak.KernelEvent) {
	t.Helper()
	r := NewRequester(nil)
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return r.FromKernelEvent(ctx, tx, realm, e)
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
}

func bound(kcUser, eventID string) keycloak.KernelEvent {
	return keycloak.KernelEvent{Kind: keycloak.KindUserEvent, ID: eventID, Time: time.Now().UTC(), Type: "UPDATE_CREDENTIAL",
		UserID: kcUser, Details: map[string]string{"credential_type": "otp"}}
}

func TestARequestIsRecordedOncePerEventToTheAddressesHeldThen(t *testing.T) {
	p := openPool(t)
	realm := keycloak.Realm("notify-" + newID(t).String())
	principal, kcUser := person(t, p, realm, "first@example.test", "second@example.test")
	eventID := newID(t).String()

	request(t, p, realm, bound(kcUser, eventID))
	request(t, p, realm, bound(kcUser, eventID)) // the sweep read it twice
	if n := scalar[int](t, p, `SELECT count(*) FROM identity.security_notification WHERE principal_id = $1`, principal.String()); n != 1 {
		t.Fatalf("%d requests for one event; want 1", n)
	}
	if n := scalar[int](t, p, `SELECT cardinality(recipients) FROM identity.security_notification WHERE principal_id = $1`,
		principal.String()); n != 2 {
		t.Errorf("the request lists %d recipients; want both addresses", n)
	}
	// Removing an address afterwards does not withdraw what was owed.
	exec(t, p, `UPDATE identity.notification_address SET state = 'removed', removed_at = now() WHERE principal_id = $1
	    AND address = 'second@example.test'`, principal.String())
	if n := scalar[int](t, p, `SELECT cardinality(recipients) FROM identity.security_notification WHERE principal_id = $1`,
		principal.String()); n != 2 {
		t.Errorf("after the removal the request lists %d recipients; want still 2", n)
	}

	// A kernel user no mapping holds records nothing.
	request(t, p, realm, bound(newID(t).String(), newID(t).String()))
	// A Principal with no address is recorded as no_address.
	lonely, lonelyUser := person(t, p, realm)
	request(t, p, realm, bound(lonelyUser, newID(t).String()))
	if s := scalar[string](t, p, `SELECT state FROM identity.security_notification WHERE principal_id = $1`, lonely.String()); s != StateNoAddress {
		t.Errorf("a Principal with no address: state %q, want no_address", s)
	}
}

type deliverer struct {
	err      error
	received []Request
}

func (d *deliverer) Deliver(_ context.Context, r Request) (string, error) {
	d.received = append(d.received, r)
	return "ref-" + r.NotificationID.String(), d.err
}

func TestTheDispatcherHandsOverOnceAndBacksOffOnRefusal(t *testing.T) {
	p := openPool(t)
	realm := keycloak.Realm("notify-" + newID(t).String())
	principal, kcUser := person(t, p, realm, "person@example.test")
	request(t, p, realm, bound(kcUser, newID(t).String()))
	// Other tests' requests may be due too; only this Principal's are read back.
	refused := &deliverer{err: errors.New("the platform is unreachable")}
	d, err := NewDispatcher(p, refused, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := scalar[string](t, p, `SELECT state FROM identity.security_notification WHERE principal_id = $1`, principal.String()); s != StateRequested {
		t.Errorf("after a refusal the state is %q; want requested, for a retry", s)
	}
	if later := scalar[bool](t, p, `SELECT next_attempt_at > now() FROM identity.security_notification WHERE principal_id = $1`,
		principal.String()); !later {
		t.Error("a refused request is due again at once; want a backoff")
	}

	// Due again, and accepted.
	exec(t, p, `UPDATE identity.security_notification SET next_attempt_at = now() WHERE principal_id = $1`, principal.String())
	accepted := &deliverer{}
	d, _ = NewDispatcher(p, accepted, nil)
	if _, err := d.Dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	var mine *Request
	for i := range accepted.received {
		if accepted.received[i].PrincipalID == principal {
			mine = &accepted.received[i]
		}
	}
	if mine == nil || len(mine.Addresses) != 1 || mine.Addresses[0] != "person@example.test" || mine.Event != EventAuthenticatorBound {
		t.Fatalf("the deliverer received %+v for the Principal", mine)
	}
	if s := scalar[string](t, p, `SELECT state FROM identity.security_notification WHERE principal_id = $1`, principal.String()); s != StateSubmitted {
		t.Errorf("after acceptance the state is %q; want submitted", s)
	}
	// A submitted request is not handed over again.
	again := &deliverer{}
	d, _ = NewDispatcher(p, again, nil)
	_, _ = d.Dispatch(context.Background())
	for _, r := range again.received {
		if r.PrincipalID == principal {
			t.Error("a submitted request was handed over again")
		}
	}

	// Ten refusals fail it.
	request(t, p, realm, bound(kcUser, newID(t).String()))
	exec(t, p, `UPDATE identity.security_notification SET attempts = 9 WHERE principal_id = $1 AND state = 'requested'`, principal.String())
	d, _ = NewDispatcher(p, refused, nil)
	_, _ = d.Dispatch(context.Background())
	if n := scalar[int](t, p, `SELECT count(*) FROM identity.security_notification WHERE principal_id = $1 AND state = 'failed'`,
		principal.String()); n != 1 {
		t.Errorf("%d failed after the tenth refusal; want 1", n)
	}
}

// An assisted recovery's restore requests account_recovered once, to the active addresses alone
// (TDD-identity-control-008 1.3.0).
func TestARestoreRequestsAnAssistedRecoveryOnce(t *testing.T) {
	p := openPool(t)
	realm := keycloak.Realm("notify-" + newID(t).String())
	principal, _ := person(t, p, realm, "first@example.test", "second@example.test")
	exec(t, p, `INSERT INTO identity.notification_address
	    (address_id, principal_id, channel, address, origin, state, proof_hash, proof_expires_at)
	    VALUES ($1, $2, 'email', 'unproven@example.test', 'added', 'pending', 'not-a-real-hash', now() + interval '10 minutes')`,
		newID(t).String(), principal.String())
	operation := newID(t)
	r := NewRequester(nil)
	for range 2 { // an attempt finished twice requests once
		if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			return r.FromRestore(ctx, tx, operation, principal)
		}); err != nil {
			t.Fatalf("FromRestore: %v", err)
		}
	}
	if n := scalar[int](t, p, `SELECT count(*) FROM identity.security_notification WHERE principal_id = $1`, principal.String()); n != 1 {
		t.Fatalf("%d requests for one restore; want 1", n)
	}
	type row struct {
		event, method, actor, source, state string
		recipients                          int
	}
	var got row
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT event, details->>'method', details->>'actor', source_key, state, cardinality(recipients)
		    FROM identity.security_notification WHERE principal_id = $1`, principal.String()).Scan(&got.event, &got.method,
			&got.actor, &got.source, &got.state, &got.recipients)
	}); err != nil {
		t.Fatal(err)
	}
	want := row{EventAccountRecovered, "assisted", ActorAdministrator, "command:operation:" + operation.String(), StateRequested, 2}
	if got != want {
		t.Errorf("the request reads %+v; want %+v, the pending address left out", got, want)
	}

	lonely, _ := person(t, p, realm)
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return r.FromRestore(ctx, tx, newID(t), lonely)
	}); err != nil {
		t.Fatal(err)
	}
	if s := scalar[string](t, p, `SELECT state FROM identity.security_notification WHERE principal_id = $1`, lonely.String()); s != StateNoAddress {
		t.Errorf("a restored Principal with no address: state %q, want no_address", s)
	}
}

// A removal this service's command made is told once, as the command tells it, whether the command
// or the sweep records it first; once handed over it is not rewritten (TDD-identity-control-008 1.4.0).
func TestARemovalIsToldOnceAsTheCommandTellsIt(t *testing.T) {
	p := openPool(t)
	realm := keycloak.Realm("notify-" + newID(t).String())
	r := NewRequester(nil)
	removal := func(principal id.UUID, credential string, self bool) {
		t.Helper()
		if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			return r.FromRemoval(ctx, tx, realm, principal, credential, "otp", self)
		}); err != nil {
			t.Fatalf("FromRemoval: %v", err)
		}
	}
	adminAction := func(kcUser, credential string) keycloak.KernelEvent {
		return keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, ID: newID(t).String(), Time: time.Now().UTC(),
			Type: "ACTION", UserID: "kc-identity-control", ResourceType: "USER",
			ResourcePath: "users/" + kcUser + "/credentials/" + credential}
	}
	told := func(principal id.UUID) (int, string, string) {
		t.Helper()
		var actor, authenticator string
		n := scalar[int](t, p, `SELECT count(*) FROM identity.security_notification WHERE principal_id = $1`, principal.String())
		if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			return tx.QueryRow(ctx, `SELECT details->>'actor', coalesce(details->>'authenticator', '')
			    FROM identity.security_notification WHERE principal_id = $1 LIMIT 1`, principal.String()).Scan(&actor, &authenticator)
		}); err != nil {
			t.Fatal(err)
		}
		return n, actor, authenticator
	}

	// The command first: the sweep's later read of the same removal records nothing.
	first, firstUser := person(t, p, realm, "first@example.test")
	removal(first, "cred-1", true)
	request(t, p, realm, adminAction(firstUser, "cred-1"))
	if n, actor, authenticator := told(first); n != 1 || actor != ActorSelf || authenticator != "otp" {
		t.Errorf("command first: %d requests, actor %q, authenticator %q; want 1, self, otp", n, actor, authenticator)
	}

	// The sweep first, before the command finished: the command's telling replaces it.
	second, secondUser := person(t, p, realm, "second@example.test")
	request(t, p, realm, adminAction(secondUser, "cred-2"))
	removal(second, "cred-2", true)
	if n, actor, authenticator := told(second); n != 1 || actor != ActorSelf || authenticator != "otp" {
		t.Errorf("sweep first: %d requests, actor %q, authenticator %q; want 1, self, otp", n, actor, authenticator)
	}

	// Handed over already: what the person was told stays.
	third, thirdUser := person(t, p, realm, "third@example.test")
	request(t, p, realm, adminAction(thirdUser, "cred-3"))
	exec(t, p, `UPDATE identity.security_notification SET state = 'submitted', submitted_at = now(), platform_ref = 'p'
	    WHERE principal_id = $1`, third.String())
	removal(third, "cred-3", true)
	if n, actor, _ := told(third); n != 1 || actor != ActorAdministrator {
		t.Errorf("handed over: %d requests, actor %q; want 1, unchanged administrator", n, actor)
	}

	// A removal no command made, such as one in the Admin Console, is an administrator's.
	fourth, fourthUser := person(t, p, realm, "fourth@example.test")
	request(t, p, realm, adminAction(fourthUser, "cred-4"))
	if n, actor, _ := told(fourth); n != 1 || actor != ActorAdministrator {
		t.Errorf("the console: %d requests, actor %q; want 1, administrator", n, actor)
	}
}
