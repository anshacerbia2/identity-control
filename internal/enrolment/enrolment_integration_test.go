package enrolment

// Enrolment from an invitation against the real engine, the kernel fake and the real creation and
// first-credential paths (ADR-IAM-011 §5.1 to §5.9, TDD-identity-control-001 1.27.0). Every test names
// its own addresses, so the shared database's Principals never collide across tests.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/firstcredential"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
	"github.com/anshacerbia2/identity-control/internal/securitynotify"
	"github.com/anshacerbia2/identity-control/internal/securityref"
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
	p, err := db.Open(context.Background(), db.Config{Name: "enrolment-test", DSN: dsn, MaxConns: 6})
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

// resolver stands in for Organization Control's resolve: a token names an invitation or nothing.
type resolver struct {
	mu          sync.Mutex
	invitations map[string]Invitation
	err         error
	calls       int
}

func (r *resolver) Resolve(_ context.Context, token string) (Invitation, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return Invitation{}, false, r.err
	}
	invitation, ok := r.invitations[token]
	return invitation, ok, nil
}

// lookup is a kernel whose search finds nothing, so the create's own refusal is reached.
type blindKernel struct{}

func (blindKernel) FindByUsernameOrEmail(context.Context, keycloak.Realm, string) ([]keycloak.User, error) {
	return nil, nil
}

// logs collects every line any test's service writes, so the last test can read them all.
var (
	logsMu sync.Mutex
	logs   bytes.Buffer
)

type lockedWriter struct{}

func (lockedWriter) Write(p []byte) (int, error) {
	logsMu.Lock()
	defer logsMu.Unlock()
	return logs.Write(p)
}

var logger = slog.New(slog.NewJSONHandler(lockedWriter{}, &slog.HandlerOptions{Level: slog.LevelDebug}))

// secrets are every token, address, code and password the tests used, checked against the logs.
var (
	secretsMu sync.Mutex
	secrets   []string
)

func remember(values ...string) {
	secretsMu.Lock()
	defer secretsMu.Unlock()
	secrets = append(secrets, values...)
}

type fixture struct {
	pool        *db.Pool
	kernel      *keycloakfake.Client
	resolver    *resolver
	codec       *securityref.Codec
	provisioner *provisioning.Provisioner
	service     *Service
	realm       keycloak.Realm
	caller      id.UUID
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := openPool(t)
	f := &fixture{pool: p, kernel: keycloakfake.New(), resolver: &resolver{invitations: map[string]Invitation{}},
		realm: keycloak.Realm("enrolment-" + newID(t).String())}
	f.kernel.IDPrefix = "kc-enrolment-" + newID(t).String()
	secret := make([]byte, 32)
	copy(secret, newID(t).String())
	codec, err := securityref.New([]securityref.Key{{ID: "k1", Secret: secret}}, CodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	f.codec = codec
	f.provisioner, err = provisioning.New(p, f.kernel, provisioning.Config{ProvisionTimeout: 5 * time.Second,
		PendingRecoveryAfter: 6 * time.Second, RecoveryBatch: 10, Realm: f.realm}, logger)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := firstcredential.New(p, f.kernel, firstcredential.Config{Realm: f.realm,
		TTL: firstcredential.DefaultTTL, CallTimeout: 5 * time.Second}, logger)
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = New(p, f.resolver, f.kernel, f.provisioner, issuer, codec, codec,
		Config{Realm: f.realm, CallTimeout: 5 * time.Second}, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.caller = f.workload(t)
	return f
}

// workload records an active workload Principal, as the BFF's would be.
func (f *fixture) workload(t *testing.T) id.UUID {
	t.Helper()
	principal := newID(t)
	exec(t, f.pool, `INSERT INTO identity.principal_mapping
	    (principal_id, realm, username, subject_type, workload_owner, keycloak_user_id, state)
	    VALUES ($1, $2, $3, 'workload', $4, $5, 'active')`, principal.String(), string(f.realm),
		"bff-"+principal.String(), newID(t).String(), "kc-bff-"+principal.String())
	return principal
}

// invite makes a token that names a fresh invitation to a fresh address, and answers both.
func (f *fixture) invite(t *testing.T, address string) (string, Invitation) {
	t.Helper()
	token := "token-" + newID(t).String()
	invitation := Invitation{ID: newID(t), Address: address}
	f.resolver.mu.Lock()
	f.resolver.invitations[token] = invitation
	f.resolver.mu.Unlock()
	remember(token, address, strings.ToLower(address))
	return token, invitation
}

func address(t *testing.T, label string) string {
	return label + "." + strings.ReplaceAll(newID(t).String(), "-", "") + "@Example.test"
}

// clientAddress is a fresh documentation address per call, so the per-address limits of one test do
// not reach another's.
func clientAddress(t *testing.T) string {
	n := clients.Add(1)
	return fmt.Sprintf("10.%d.%d.%d", rand.IntN(250), n/250%250, n%250)
}

var clients atomic.Int64

func (f *fixture) request(t *testing.T, client, token string) id.UUID {
	t.Helper()
	enrolmentID, err := f.service.Request(context.Background(), RequestInput{Caller: f.caller, ClientAddress: client, Token: token})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	return enrolmentID
}

// code opens the code the newest message for the enrolment carries, as the dispatcher would.
func (f *fixture) code(t *testing.T, enrolmentID id.UUID) string {
	t.Helper()
	sealed := scalar[string](t, f.pool, `SELECT sealed_secret FROM identity.enrolment_message
	    WHERE enrolment_id = $1 AND kind = 'code' ORDER BY requested_at DESC LIMIT 1`, enrolmentID.String())
	ref, err := f.codec.Open(sealed, securityref.KindEnrolmentCode, enrolmentID, securitynotify.EnrolmentPurpose)
	if err != nil {
		t.Fatalf("open the code: %v", err)
	}
	remember(ref.KernelID)
	return ref.KernelID
}

func (f *fixture) verify(t *testing.T, client string, enrolmentID id.UUID, code string) (Completed, error) {
	t.Helper()
	completed, err := f.service.Verify(context.Background(), VerifyInput{Caller: f.caller, ClientAddress: client,
		EnrolmentID: enrolmentID, Code: code, Correlation: "c-" + enrolmentID.String()})
	if completed.TemporaryPassword != "" {
		remember(completed.TemporaryPassword)
	}
	return completed, err
}

func (f *fixture) enrolments(t *testing.T, invitation id.UUID) int {
	return scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment WHERE invitation_id = $1`, invitation.String())
}

func (f *fixture) accountMessages(t *testing.T, address string) int {
	return scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment_message
	    WHERE kind = 'account_exists' AND address = $1`, address)
}

func wrongCode(code string) string {
	if code == "00000000" {
		return "00000001"
	}
	return "00000000"
}

func TestAnInviteeWithNoAccountEnrolsAndIsShownItsPasswordOnce(t *testing.T) {
	f := setup(t)
	invited := address(t, "newcomer")
	token, invitation := f.invite(t, invited)
	client := clientAddress(t)

	enrolmentID := f.request(t, client, token)
	if got := scalar[string](t, f.pool, `SELECT state FROM identity.enrolment WHERE enrolment_id = $1`, enrolmentID.String()); got != "open" {
		t.Fatalf("the enrolment is %q, want open", got)
	}
	if got := scalar[string](t, f.pool, `SELECT invitation_id::text FROM identity.enrolment WHERE enrolment_id = $1`,
		enrolmentID.String()); got != invitation.ID.String() {
		t.Errorf("the enrolment names invitation %s", got)
	}
	code := f.code(t, enrolmentID)
	if len(code) != 8 {
		t.Fatalf("the code is %d characters, want 8", len(code))
	}
	if scalar[bool](t, f.pool, `SELECT code_hash = $2 OR address_hash = $3 FROM identity.enrolment WHERE enrolment_id = $1`,
		enrolmentID.String(), code, invited) {
		t.Error("the record holds the code or the address in the clear where a hash belongs")
	}

	if _, err := f.verify(t, client, enrolmentID, wrongCode(code)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a wrong code returned %v, want ErrRefused", err)
	}
	completed, err := f.verify(t, client, enrolmentID, code)
	if err != nil {
		t.Fatalf("the right code: %v", err)
	}
	if completed.Username != strings.ToLower(invited) || len(completed.TemporaryPassword) != 24 || completed.PrincipalID.IsNil() {
		t.Fatalf("completed %+v", completed)
	}
	if !completed.LapsesAt.After(time.Now()) || completed.LapsesAt.After(time.Now().Add(24*time.Hour+time.Minute)) {
		t.Errorf("the password lapses at %s", completed.LapsesAt)
	}

	// The Principal, through the ordinary path: active, human, its creation address proven.
	if got := scalar[string](t, f.pool, `SELECT state || ' ' || subject_type || ' ' || username FROM identity.principal_mapping
	    WHERE principal_id = $1`, completed.PrincipalID.String()); got != "active human "+strings.ToLower(invited) {
		t.Errorf("the mapping is %q", got)
	}
	if !scalar[bool](t, f.pool, `SELECT verified_at IS NOT NULL FROM identity.notification_address
	    WHERE principal_id = $1 AND origin = 'creation'`, completed.PrincipalID.String()) {
		t.Error("the creation address is not proven")
	}
	// The password is temporary in the kernel, and the issuance names the BFF workload and the enrolment.
	users, _ := f.kernel.FindByPrincipalID(context.Background(), f.realm, completed.PrincipalID)
	if len(users) != 1 {
		t.Fatalf("the kernel holds %d users for the Principal", len(users))
	}
	if value, ok := f.kernel.TemporaryPassword(users[0].ID); !ok || value != completed.TemporaryPassword {
		t.Error("the kernel does not hold the password shown")
	}
	if got := scalar[string](t, f.pool, `SELECT issued_by::text || ' ' || reason || ' ' || assurance
	    FROM identity.temporary_password_issuance WHERE principal_id = $1`, completed.PrincipalID.String()); got !=
		f.caller.String()+" enrolment "+enrolmentID.String()+" enrolment-code" {
		t.Errorf("the issuance reads %q", got)
	}
	// The record: completed, the Principal and the issuance named, the address and the code's hash gone.
	if got := scalar[string](t, f.pool, `SELECT state || ' ' || (principal_id = $2)::text || ' ' ||
	    (address IS NULL AND code_hash IS NULL AND closed_at IS NOT NULL AND issuance_id IS NOT NULL)::text
	    FROM identity.enrolment WHERE enrolment_id = $1`, enrolmentID.String(), completed.PrincipalID.String()); got != "completed true true" {
		t.Errorf("the enrolment reads %q", got)
	}
	// No Membership is granted here, and the value is held by no row.
	if scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment e, identity.enrolment_message m,
	    identity.temporary_password_issuance i, platform.idempotency_key k
	    WHERE e::text LIKE '%' || $1 || '%' OR m::text LIKE '%' || $1 || '%' OR i::text LIKE '%' || $1 || '%'
	       OR k::text LIKE '%' || $1 || '%'`, completed.TemporaryPassword) != 0 {
		t.Error("a row holds the temporary password")
	}

	// Used once: the same code again creates nothing and shows nothing.
	again, err := f.verify(t, client, enrolmentID, code)
	if !errors.Is(err, ErrRefused) || again.TemporaryPassword != "" {
		t.Errorf("a second verify returned %+v, %v", again, err)
	}
	// And a new request for the invitation is the "an account exists" message now.
	before := f.accountMessages(t, invited)
	f.request(t, client, token)
	if f.accountMessages(t, invited) != before+1 {
		t.Error("a request for an address now held queued no account message")
	}
}

// TestEveryOutcomeAnswersAlike: an unknown token, an address held proven, held but not proven, a kernel
// username and a kernel email equal to the address, and an open enrolment's repeat all answer a fresh
// identifier no enrolment holds; the held cases queue the account message, the others nothing
// (ADR-IAM-011 §5.1, §5.9).
func TestEveryOutcomeAnswersAlike(t *testing.T) {
	f := setup(t)
	client := clientAddress(t)
	held := func(proven bool) string {
		a := address(t, "held")
		principal := newID(t)
		exec(t, f.pool, `INSERT INTO identity.principal_mapping (principal_id, realm, username, email, subject_type, keycloak_user_id, state)
		    VALUES ($1, $2, $3, $4, 'human', $5, 'active')`, principal.String(), string(f.realm),
			"someone-"+principal.String(), a, "kc-held-"+principal.String())
		exec(t, f.pool, `INSERT INTO identity.notification_address (address_id, principal_id, channel, address, origin, state, verified_at)
		    VALUES ($1, $2, 'email', $3, 'creation', 'active', CASE WHEN $4::boolean THEN now() END)`,
			newID(t).String(), principal.String(), a, proven)
		return a
	}
	kernelUsername := address(t, "kerneluser")
	f.kernel.SeedEmail(f.realm, strings.ToLower(kernelUsername), "")
	kernelEmail := address(t, "kernelmail")
	f.kernel.SeedEmail(f.realm, "orphan-"+newID(t).String(), kernelEmail)

	cases := []struct {
		name    string
		address string
		message bool
	}{
		{"held and proven", held(true), true},
		{"held and not proven", held(false), true},
		{"a kernel username", kernelUsername, true},
		{"a kernel email", kernelEmail, true},
	}
	seen := map[id.UUID]bool{}
	for _, tc := range cases {
		token, invitation := f.invite(t, tc.address)
		answer := f.request(t, clientAddress(t), token)
		if seen[answer] || answer.IsNil() {
			t.Errorf("%s: answered %s twice or nil", tc.name, answer)
		}
		seen[answer] = true
		if f.enrolments(t, invitation.ID) != 0 {
			t.Errorf("%s: an enrolment was made", tc.name)
		}
		if got := scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment WHERE enrolment_id = $1`, answer.String()); got != 0 {
			t.Errorf("%s: the answer names a stored enrolment", tc.name)
		}
		if got := f.accountMessages(t, tc.address); got != 1 {
			t.Errorf("%s: %d account messages, want 1", tc.name, got)
		}
	}

	unknown := f.request(t, client, "token-"+newID(t).String())
	if seen[unknown] || scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment WHERE enrolment_id = $1`, unknown.String()) != 0 {
		t.Error("an unknown token's answer is not fresh, or names an enrolment")
	}

	// One open enrolment per invitation: the repeat sends nothing and answers a fresh identifier.
	token, invitation := f.invite(t, address(t, "repeat"))
	first := f.request(t, client, token)
	second := f.request(t, client, token)
	if first == second || f.enrolments(t, invitation.ID) != 1 {
		t.Errorf("a repeat answered %s after %s and left %d enrolments", second, first, f.enrolments(t, invitation.ID))
	}
	if got := scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment_message WHERE enrolment_id = $1`, first.String()); got != 1 {
		t.Errorf("the open enrolment has %d messages, want 1", got)
	}
}

// TestTheMessageLimitPerInvitationIsSilent: 3 messages an hour for one invitation; the fourth request
// answers as always and sends nothing (ADR-IAM-011 §5.8).
func TestTheMessageLimitPerInvitationIsSilent(t *testing.T) {
	f := setup(t)
	token, invitation := f.invite(t, address(t, "limited"))
	for i := range 3 {
		enrolmentID := f.request(t, clientAddress(t), token)
		if f.enrolments(t, invitation.ID) != i+1 {
			t.Fatalf("request %d made no enrolment", i+1)
		}
		// Its code lapses, so the next request is not held by an open enrolment.
		exec(t, f.pool, `UPDATE identity.enrolment SET code_expires_at = now() - interval '1 second' WHERE enrolment_id = $1`,
			enrolmentID.String())
	}
	answer := f.request(t, clientAddress(t), token)
	if f.enrolments(t, invitation.ID) != 3 || answer.IsNil() {
		t.Errorf("the fourth request made an enrolment (%d) or answered nil", f.enrolments(t, invitation.ID))
	}
	if scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment_count WHERE key_hash = $1 AND rule = 'message:hour'`,
		invitationKey(f.codec, invitation.ID)) != 1 {
		t.Error("the invitation's count is not kept under its keyed hash")
	}
	if scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment_count WHERE key_hash = $1 OR key_hash = $2`,
		invitation.ID.String(), strings.ToLower(invitation.Address)) != 0 {
		t.Error("a count names the invitation or the address in the clear")
	}
}

// TestTheAddressLimitsAnswer429: 5 requests a minute from one address, the sixth refused with how long
// to wait, whatever its token; :verify the same (ADR-IAM-011 §5.8).
func TestTheAddressLimitsAnswer429(t *testing.T) {
	f := setup(t)
	client := "2001:db8:" + strings.ReplaceAll(newID(t).String()[:4], "-", "") + ":1::/64"
	for i := range 5 {
		f.request(t, client, "token-"+newID(t).String())
		_ = i
	}
	_, err := f.service.Request(context.Background(), RequestInput{Caller: f.caller, ClientAddress: client, Token: "token-x"})
	var limited *Limited
	if !errors.As(err, &limited) || limited.RetryAfter < 1 || limited.RetryAfter > 60 {
		t.Fatalf("the sixth request returned %v; want ErrLimited within a minute", err)
	}
	if f.resolver.calls != 5 {
		t.Errorf("Organization Control was asked %d times; the limit is read before it", f.resolver.calls)
	}
	for i := range 5 {
		if _, err := f.verify(t, client, newID(t), "12345678"); !errors.Is(err, ErrRefused) {
			t.Fatalf("verify %d returned %v", i+1, err)
		}
	}
	if _, err := f.verify(t, client, newID(t), "12345678"); !errors.As(err, &limited) {
		t.Fatalf("the sixth verify returned %v; want ErrLimited", err)
	}
}

// TestCodesAreBoundedPerEnrolmentAndPerInvitation: five attempts per code, then even the right one is
// refused; 15 failed codes a day per invitation, then every code is (ADR-IAM-011 §5.2, §5.8).
func TestCodesAreBoundedPerEnrolmentAndPerInvitation(t *testing.T) {
	f := setup(t)
	token, invitation := f.invite(t, address(t, "guessed"))
	enrolmentID := f.request(t, clientAddress(t), token)
	code := f.code(t, enrolmentID)
	for range 5 {
		if _, err := f.verify(t, clientAddress(t), enrolmentID, wrongCode(code)); !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
	}
	if _, err := f.verify(t, clientAddress(t), enrolmentID, code); !errors.Is(err, ErrRefused) {
		t.Fatalf("the right code after five wrong ones returned %v", err)
	}
	if got := scalar[string](t, f.pool, `SELECT state FROM identity.enrolment WHERE enrolment_id = $1`, enrolmentID.String()); got != "refused" {
		t.Errorf("the exhausted enrolment is %q", got)
	}

	// Ten more failures on two more enrolments reach 15 for the invitation.
	for range 2 {
		next := f.request(t, clientAddress(t), token)
		c := f.code(t, next)
		for range 5 {
			_, _ = f.verify(t, clientAddress(t), next, wrongCode(c))
		}
	}
	exec(t, f.pool, `DELETE FROM identity.enrolment_count WHERE key_hash = $1 AND rule LIKE 'message:%'`, invitationKey(f.codec, invitation.ID))
	last := f.request(t, clientAddress(t), token)
	c := f.code(t, last)
	if _, err := f.verify(t, clientAddress(t), last, c); !errors.Is(err, ErrRefused) {
		t.Fatalf("the right code after 15 failures for the invitation returned %v", err)
	}
	if got := scalar[int](t, f.pool, `SELECT attempts FROM identity.enrolment WHERE enrolment_id = $1`, last.String()); got != 0 {
		t.Errorf("the code was compared (%d attempts) past the invitation's limit", got)
	}
}

// TestAHolderAppearingBeforeTheCreateCreatesNothing: a provider gives the address to a Principal
// between the request and :verify; the right code creates nothing and consumes the enrolment
// (ADR-IAM-011 §5.9, the double check).
func TestAHolderAppearingBeforeTheCreateCreatesNothing(t *testing.T) {
	f := setup(t)
	invited := address(t, "raced")
	token, _ := f.invite(t, invited)
	enrolmentID := f.request(t, clientAddress(t), token)
	code := f.code(t, enrolmentID)
	principal := newID(t)
	// Active, never pending: another suite's recovery reads every realm's pending mappings.
	exec(t, f.pool, `INSERT INTO identity.principal_mapping (principal_id, realm, username, email, subject_type, keycloak_user_id, state)
	    VALUES ($1, $2, $3, $4, 'human', $5, 'active')`, principal.String(), string(f.realm), "provider-made-"+principal.String(), invited,
		"kc-provider-made-"+principal.String())
	if _, err := f.verify(t, clientAddress(t), enrolmentID, code); !errors.Is(err, ErrRefused) {
		t.Fatalf("the right code returned %v, want the refusal", err)
	}
	if got := scalar[int](t, f.pool, `SELECT count(*) FROM identity.principal_mapping WHERE idempotency_scope = 'enrolment'
	    AND idempotency_key = $1`, enrolmentID.String()); got != 0 {
		t.Error("a mapping was made")
	}
	if f.kernel.Calls.CreateUser != 0 {
		t.Error("the kernel was asked to create a user")
	}
	if got := scalar[string](t, f.pool, `SELECT state FROM identity.enrolment WHERE enrolment_id = $1`, enrolmentID.String()); got != "refused" {
		t.Errorf("the enrolment is %q, want refused", got)
	}
}

// TestAKernelDuplicateAtTheCreateLeavesNothingForRecovery: the kernel refuses the user as a duplicate
// email its search did not show; the mapping is quarantined, so recovery has nothing to finish, and
// the answer is the refusal (ADR-IAM-011 §5.9).
func TestAKernelDuplicateAtTheCreateLeavesNothingForRecovery(t *testing.T) {
	f := setup(t)
	issuer, _ := firstcredential.New(f.pool, f.kernel, firstcredential.Config{Realm: f.realm, TTL: firstcredential.DefaultTTL,
		CallTimeout: 5 * time.Second}, logger)
	blind, err := New(f.pool, f.resolver, blindKernel{}, f.provisioner, issuer, f.codec, f.codec,
		Config{Realm: f.realm, CallTimeout: 5 * time.Second}, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	invited := address(t, "duplicate")
	f.kernel.RefuseDuplicateEmail = true
	f.kernel.SeedEmail(f.realm, "stray-"+newID(t).String(), invited)
	token, _ := f.invite(t, invited)
	client := clientAddress(t)
	enrolmentID, err := blind.Request(context.Background(), RequestInput{Caller: f.caller, ClientAddress: client, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	code := f.code(t, enrolmentID)
	_, err = blind.Verify(context.Background(), VerifyInput{Caller: f.caller, ClientAddress: client, EnrolmentID: enrolmentID, Code: code})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("a kernel duplicate returned %v, want the refusal", err)
	}
	if got := scalar[string](t, f.pool, `SELECT state FROM identity.principal_mapping WHERE idempotency_scope = 'enrolment'
	    AND idempotency_key = $1`, enrolmentID.String()); got != "quarantined" {
		t.Errorf("the mapping is %q, want quarantined", got)
	}
	if got := scalar[string](t, f.pool, `SELECT state FROM identity.enrolment WHERE enrolment_id = $1`, enrolmentID.String()); got != "refused" {
		t.Errorf("the enrolment is %q, want refused", got)
	}
}

// TestAnUnconfirmedCreateResumesWithTheSameCode: the kernel's answer to the create is lost; the
// mapping waits for recovery, the code stays good, and once recovery has adopted the user the same
// code completes through the create's own key (TDD-identity-control-001 §Idempotency and Crash Recovery).
func TestAnUnconfirmedCreateResumesWithTheSameCode(t *testing.T) {
	f := setup(t)
	token, _ := f.invite(t, address(t, "resumed"))
	client := clientAddress(t)
	enrolmentID := f.request(t, client, token)
	code := f.code(t, enrolmentID)
	f.kernel.FailCreate, f.kernel.AmbiguousCreateSucceeds = keycloak.ErrAmbiguous, true
	if _, err := f.verify(t, client, enrolmentID, code); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a lost create returned %v, want ErrUnavailable", err)
	}
	f.kernel.FailCreate, f.kernel.AmbiguousCreateSucceeds = nil, false
	if got := scalar[string](t, f.pool, `SELECT state FROM identity.enrolment WHERE enrolment_id = $1`, enrolmentID.String()); got != "open" {
		t.Fatalf("the enrolment is %q, want open", got)
	}
	// Recovery's adoption, as recoverOne does it for this mapping alone: the user the kernel made is
	// recorded, and the create's key completed with its answer. RecoverPending reads every realm's
	// pending mappings, and this suite shares its database with others.
	principalRaw := scalar[string](t, f.pool, `SELECT principal_id::text FROM identity.principal_mapping
	    WHERE idempotency_scope = 'enrolment' AND idempotency_key = $1 AND state = 'pending'`, enrolmentID.String())
	principal, _ := id.Parse(principalRaw)
	users, _ := f.kernel.FindByPrincipalID(context.Background(), f.realm, principal)
	if len(users) != 1 {
		t.Fatalf("the kernel holds %d users for the pending Principal", len(users))
	}
	digest := scalar[string](t, f.pool, `SELECT request_digest FROM identity.principal_mapping WHERE principal_id = $1`, principalRaw)
	if err := f.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		if err := (provisioning.Repository{}).Activate(ctx, tx, principal, users[0].ID); err != nil {
			return err
		}
		body := []byte(`{"principal_id":"` + principalRaw + `","subject_type":"human","realm":"` + string(f.realm) + `"}`)
		return idempotency.Complete(ctx, tx, CallerScope, enrolmentID.String(), digest, 201, body)
	}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	completed, err := f.verify(t, client, enrolmentID, code)
	if err != nil || completed.TemporaryPassword == "" {
		t.Fatalf("the resumed verify returned %+v, %v", completed, err)
	}
	if f.kernel.Calls.CreateUser != 1 {
		t.Errorf("the kernel was asked to create %d users, want 1", f.kernel.Calls.CreateUser)
	}
}

func TestAnUnreachableOrganizationControlIsUnavailable(t *testing.T) {
	f := setup(t)
	f.resolver.err = errors.New("organization: transport failure")
	_, err := f.service.Request(context.Background(), RequestInput{Caller: f.caller, ClientAddress: clientAddress(t), Token: "t"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("returned %v, want ErrUnavailable", err)
	}
}

func TestTheSweepEndsWhatHasRunItsCourse(t *testing.T) {
	f := setup(t)
	token, _ := f.invite(t, address(t, "swept"))
	enrolmentID := f.request(t, clientAddress(t), token)
	exec(t, f.pool, `UPDATE identity.enrolment SET code_expires_at = now() - interval '1 second' WHERE enrolment_id = $1`, enrolmentID.String())
	exec(t, f.pool, `INSERT INTO identity.enrolment_count (key_hash, rule, window_ends_at, count)
	    VALUES ($1, 'request:minute', now() - interval '1 second', 3)`, "sweep-"+newID(t).String())
	if _, err := f.service.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := scalar[string](t, f.pool, `SELECT state || ' ' || (address IS NULL)::text FROM identity.enrolment WHERE enrolment_id = $1`,
		enrolmentID.String()); got != "refused true" {
		t.Errorf("the lapsed enrolment reads %q", got)
	}
	if scalar[int](t, f.pool, `SELECT count(*) FROM identity.enrolment_count WHERE window_ends_at <= now()`) != 0 {
		t.Error("a count past its window is kept")
	}
}

func TestTheCallerRecordAdmitsAnActiveWorkloadAlone(t *testing.T) {
	f := setup(t)
	callers, err := NewCallers(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	provider := newID(t)
	human := newID(t)
	exec(t, f.pool, `INSERT INTO identity.principal_mapping (principal_id, realm, username, subject_type, keycloak_user_id, state)
	    VALUES ($1, $2, $3, 'human', $4, 'active')`, human.String(), string(f.realm), "h-"+human.String(), "kc-h-"+human.String())
	if _, err := callers.Register(ctx, Change{Principal: human, Purpose: "p", By: provider, Reason: "r"}); !errors.Is(err, ErrNotWorkload) {
		t.Errorf("a human was registered: %v", err)
	}
	if admitted, _ := callers.Admitted(ctx, f.caller); admitted {
		t.Error("an unregistered workload is admitted")
	}
	caller, err := callers.Register(ctx, Change{Principal: f.caller, Purpose: "Identity Experience's BFF", By: provider, Reason: "the enrolment page"})
	if err != nil || caller.PrincipalID != f.caller || caller.RetiredAt != nil {
		t.Fatalf("Register: %+v, %v", caller, err)
	}
	if _, err := callers.Register(ctx, Change{Principal: f.caller, Purpose: "again", By: provider, Reason: "r"}); !errors.Is(err, ErrRegistered) {
		t.Errorf("a second registration returned %v", err)
	}
	if admitted, err := callers.Admitted(ctx, f.caller); err != nil || !admitted {
		t.Errorf("the registered workload is not admitted: %v", err)
	}
	list, err := callers.List(ctx)
	if err != nil || len(list) == 0 {
		t.Fatalf("List: %d, %v", len(list), err)
	}
	if _, err := callers.Retire(ctx, Change{Principal: f.caller, By: provider, Reason: "replaced"}); err != nil {
		t.Fatal(err)
	}
	if admitted, _ := callers.Admitted(ctx, f.caller); admitted {
		t.Error("a retired caller is admitted")
	}
	if _, err := callers.Retire(ctx, Change{Principal: f.caller, By: provider, Reason: "again"}); !errors.Is(err, ErrNoCaller) {
		t.Errorf("a second retirement returned %v", err)
	}
	if _, err := callers.Register(ctx, Change{Principal: f.caller, By: provider}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a registration with no purpose or reason returned %v", err)
	}
}

// TestZNoTokenAddressCodeOrPasswordIsLogged reads every line the services above wrote. Named to run
// last in the file.
func TestZNoTokenAddressCodeOrPasswordIsLogged(t *testing.T) {
	openPool(t)
	logsMu.Lock()
	text := logs.String()
	logsMu.Unlock()
	if !strings.Contains(text, "an enrolment created a Principal") {
		t.Fatalf("the logs hold no completed enrolment; the suite did not run first:\n%s", text)
	}
	secretsMu.Lock()
	defer secretsMu.Unlock()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			t.Errorf("the logs hold a token, address, code or password")
		}
	}
}
