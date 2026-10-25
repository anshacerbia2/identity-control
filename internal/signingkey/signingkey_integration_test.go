package signingkey_test

// The signing key registry against PostgreSQL (ADR-IAM-002 §5.5 Q5 to Q9, TDD-identity-control-001
// 1.29.0 §The Signing Key Registry). Each test names its own realm, so tests sharing the database
// never see each other's keys.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/signingkey"
)

func openRegistry(t *testing.T) (*signingkey.Registry, *db.Pool, string) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	pool, err := db.Open(context.Background(), db.Config{Name: "signingkey-test", DSN: dsn, MaxConns: 6})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	realmID, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	realm := "signing-key-test-" + realmID.String()
	t.Cleanup(func() {
		_ = pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			for _, statement := range []string{
				`SET LOCAL session_replication_role = replica`,
				`DELETE FROM identity.signing_key_transition WHERE kid IN (SELECT kid FROM identity.signing_key WHERE realm = $1)`,
				`DELETE FROM identity.signing_key_approval WHERE kid IN (SELECT kid FROM identity.signing_key WHERE realm = $1)`,
				`DELETE FROM identity.signing_key WHERE realm = $1`,
			} {
				var args []any
				if strings.Contains(statement, "$1") {
					args = []any{realm}
				}
				if _, err := tx.Exec(ctx, statement, args...); err != nil {
					return err
				}
			}
			return nil
		})
	})
	return signingkey.New(pool), pool, realm
}

type testKey struct {
	kid string
	jwk []byte
}

var (
	keysOnce sync.Once
	keys     []testKey
)

// newKeys makes RSA-3072 public JWKs once for the package: generating one takes a while.
func newKey(t *testing.T, n int) testKey {
	t.Helper()
	keysOnce.Do(func() {
		for range 12 {
			private, err := rsa.GenerateKey(rand.Reader, 3072)
			if err != nil {
				panic(err)
			}
			keys = append(keys, jwkOf(&private.PublicKey))
		}
	})
	return keys[n]
}

func jwkOf(public *rsa.PublicKey) testKey {
	jwk, _ := json.Marshal(map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	})
	kid, err := signingkey.Thumbprint(jwk)
	if err != nil {
		panic(err)
	}
	return testKey{kid: kid, jwk: jwk}
}

func stage(t *testing.T, r *signingkey.Registry, realm string, key testKey, operator string) {
	t.Helper()
	if err := r.Stage(context.Background(), signingkey.StageRequest{Realm: realm, Kid: key.kid, PublicJWK: key.jwk,
		CustodyRef: "deploy/dev/keys", Operator: operator, Witness: "Witness", Reason: "test",
		CorrelationID: "CHG-1"}); err != nil {
		t.Fatalf("staging %s: %v", key.kid, err)
	}
}

func approve(t *testing.T, r *signingkey.Registry, realm, kid, transition, operator, approver string, emergency bool) id.UUID {
	t.Helper()
	approvalID, err := r.Approve(context.Background(), signingkey.ApproveRequest{Realm: realm, Kid: kid,
		Transition: transition, Operator: operator, Approver: approver, Emergency: emergency, Reason: "test",
		CorrelationID: "CHG-2"})
	if err != nil {
		t.Fatalf("approving %s of %s: %v", transition, kid, err)
	}
	return approvalID
}

func record(t *testing.T, r *signingkey.Registry, realm string, approvalID id.UUID, evidence string) []signingkey.Recorded {
	t.Helper()
	written, err := r.Record(context.Background(), signingkey.RecordRequest{Realm: realm, ApprovalID: approvalID,
		Outcome: signingkey.Completed, Evidence: evidence})
	if err != nil {
		t.Fatalf("recording %s: %v", approvalID, err)
	}
	return written
}

func states(t *testing.T, r *signingkey.Registry, realm string) map[string]string {
	t.Helper()
	listed, err := r.State(context.Background(), realm, "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, s := range listed {
		out[s.Kid] = s.State
	}
	return out
}

func refused(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, signingkey.ErrRefused) {
		t.Errorf("%s: got %v, want a refusal", what, err)
	}
}

func TestAKeyPassesThroughEveryState(t *testing.T) {
	r, _, realm := openRegistry(t)
	ctx := context.Background()
	first, second, abandoned, suspect := newKey(t, 0), newKey(t, 1), newKey(t, 2), newKey(t, 3)

	stage(t, r, realm, first, "Alice")
	approval := approve(t, r, realm, first.kid, signingkey.Activate, "Dave", "Carol", false)
	if found, err := r.Check(ctx, signingkey.CheckRequest{Realm: realm, Kid: first.kid,
		Transition: signingkey.Activate, Operator: "dave "}); err != nil || found.ID != approval {
		t.Fatalf("check found %v, %v; want %s", found.ID, err, approval)
	}
	record(t, r, realm, approval, "")

	stage(t, r, realm, second, "Alice")
	approval = approve(t, r, realm, second.kid, signingkey.Activate, "Dave", "Carol", false)
	_, err := r.Check(ctx, signingkey.CheckRequest{Realm: realm, Kid: second.kid, Transition: signingkey.Activate,
		Operator: "Dave", MinAge: time.Hour})
	refused(t, "an activation before the cache window", err)
	written := record(t, r, realm, approval, "")
	if len(written) != 2 || written[1].Kid != first.kid || written[1].Step != "demote" {
		t.Errorf("the activation wrote %+v; want it and the first key's demotion", written)
	}
	if got := states(t, r, realm); got[first.kid] != signingkey.Retiring || got[second.kid] != signingkey.Active {
		t.Fatalf("states %v after the second activation", got)
	}

	retire := approve(t, r, realm, first.kid, signingkey.Retire, "Erin", "Carol", false)
	_, err = r.Record(ctx, signingkey.RecordRequest{Realm: realm, ApprovalID: retire, Outcome: signingkey.Completed})
	refused(t, "a retirement without the destruction's evidence", err)
	record(t, r, realm, retire, "removed realm-signing-"+first.kid+".p12 and its password")

	stage(t, r, realm, abandoned, "Alice")
	record(t, r, realm, approve(t, r, realm, abandoned.kid, signingkey.Abandon, "Erin", "Carol", false), "removed")
	stage(t, r, realm, suspect, "Alice")
	record(t, r, realm, approve(t, r, realm, suspect.kid, signingkey.Revoke, "Erin", "Carol", false), "removed")

	want := map[string]string{first.kid: signingkey.Retired, second.kid: signingkey.Active,
		abandoned.kid: signingkey.Retired, suspect.kid: signingkey.Revoked}
	got := states(t, r, realm)
	for kid, state := range want {
		if got[kid] != state {
			t.Errorf("%s is %s, want %s", kid, got[kid], state)
		}
	}
}

func TestTheRegistryRefusesWhatQ9Forbids(t *testing.T) {
	r, pool, realm := openRegistry(t)
	ctx := context.Background()
	key, other := newKey(t, 4), newKey(t, 5)

	err := r.Stage(ctx, signingkey.StageRequest{Realm: realm, Kid: key.kid, PublicJWK: key.jwk, CustodyRef: "x",
		Operator: "Alice", Witness: " alice ", Reason: "test", CorrelationID: "c"})
	refused(t, "a witness who is the operator", err)
	err = r.Stage(ctx, signingkey.StageRequest{Realm: realm, Kid: other.kid, PublicJWK: key.jwk, CustodyRef: "x",
		Operator: "Alice", Witness: "Bob", Reason: "test", CorrelationID: "c"})
	refused(t, "a kid that is not the JWK's thumbprint", err)
	small, _ := rsa.GenerateKey(rand.Reader, 2048)
	weak := jwkOfUnchecked(&small.PublicKey)
	_, err = signingkey.Thumbprint(weak)
	refused(t, "a 2048-bit key", err)

	stage(t, r, realm, key, "Alice")
	refused(t, "a kid staged twice", r.Stage(ctx, signingkey.StageRequest{Realm: realm, Kid: key.kid,
		PublicJWK: key.jwk, CustodyRef: "x", Operator: "Alice", Witness: "Bob", Reason: "test", CorrelationID: "c"}))

	for _, c := range []struct {
		what                           string
		transition, operator, approver string
		emergency                      bool
	}{
		{"an approver who is the step's operator", signingkey.Activate, "Dave", "DAVE", false},
		{"an activation approved by the key's generating operator", signingkey.Activate, "Dave", "alice", false},
		{"an emergency retirement", signingkey.Retire, "Dave", "Carol", true},
		{"a retirement of a staged key", signingkey.Retire, "Dave", "Carol", false},
		{"a transition that does not exist", "reactivate", "Dave", "Carol", false},
	} {
		_, err := r.Approve(ctx, signingkey.ApproveRequest{Realm: realm, Kid: key.kid, Transition: c.transition,
			Operator: c.operator, Approver: c.approver, Emergency: c.emergency, Reason: "test", CorrelationID: "c"})
		refused(t, c.what, err)
	}
	_, err = r.Approve(ctx, signingkey.ApproveRequest{Realm: "another-realm", Kid: key.kid, Transition: signingkey.Activate,
		Operator: "Dave", Approver: "Carol", Reason: "test", CorrelationID: "c"})
	refused(t, "a key named under another realm", err)

	_, err = r.Check(ctx, signingkey.CheckRequest{Realm: realm, Kid: key.kid, Transition: signingkey.Activate, Operator: "Dave"})
	refused(t, "a step with no approval", err)
	approval := approve(t, r, realm, key.kid, signingkey.Activate, "Dave", "Carol", false)
	_, err = r.Check(ctx, signingkey.CheckRequest{Realm: realm, Kid: key.kid, Transition: signingkey.Activate, Operator: "Erin"})
	refused(t, "a step run by another operator than the approval names", err)

	// A failure records the error, changes no state and leaves the approval unused.
	if _, err := r.Record(ctx, signingkey.RecordRequest{Realm: realm, ApprovalID: approval, Outcome: signingkey.Failed,
		Evidence: "the kernel refused the provider"}); err != nil {
		t.Fatalf("recording a failure: %v", err)
	}
	if got := states(t, r, realm)[key.kid]; got != signingkey.Staged {
		t.Fatalf("after a failure the key is %s, want staged", got)
	}
	record(t, r, realm, approval, "")
	_, err = r.Record(ctx, signingkey.RecordRequest{Realm: realm, ApprovalID: approval, Outcome: signingkey.Completed})
	refused(t, "an approval used twice", err)

	// The active key is revoked only after a replacement's activation demotes it (Q7).
	_, err = r.Approve(ctx, signingkey.ApproveRequest{Realm: realm, Kid: key.kid, Transition: signingkey.Revoke,
		Operator: "Dave", Approver: "Carol", Reason: "test", CorrelationID: "c"})
	refused(t, "a revocation of the active key", err)

	// An emergency activation does not wait the cache window, and demotes the compromised key.
	stage(t, r, realm, other, "Alice")
	emergency := approve(t, r, realm, other.kid, signingkey.Activate, "Dave", "Carol", true)
	if _, err := r.Check(ctx, signingkey.CheckRequest{Realm: realm, Kid: other.kid, Transition: signingkey.Activate,
		Operator: "Dave", MinAge: time.Hour}); err != nil {
		t.Errorf("an emergency activation waited the cache window: %v", err)
	}
	record(t, r, realm, emergency, "")
	record(t, r, realm, approve(t, r, realm, key.kid, signingkey.Revoke, "Dave", "Carol", false), "deleted")

	// A retired or revoked key is never active again (Q6).
	_, err = r.Approve(ctx, signingkey.ApproveRequest{Realm: realm, Kid: key.kid, Transition: signingkey.Activate,
		Operator: "Dave", Approver: "Carol", Reason: "test", CorrelationID: "c"})
	refused(t, "a reactivation", err)

	// The runtime's tables refuse a second row entering the same state, whatever the code does.
	err = pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		transitionID, _ := id.NewV7()
		_, err := tx.Exec(ctx, `INSERT INTO identity.signing_key_transition (transition_id, kid, step, from_state,
			to_state, actor, approval_id, reason, correlation_id, outcome)
			VALUES ($1, $2, 'activate', 'retiring', 'active', 'Dave', $3, 'test', 'c', 'completed')`,
			transitionID.String(), key.kid, emergency.String())
		return err
	})
	if err == nil {
		t.Error("the table took a second activation of one key")
	}
}

func TestTwoActivationsLeaveOneActiveKey(t *testing.T) {
	r, _, realm := openRegistry(t)
	current, left, right := newKey(t, 6), newKey(t, 7), newKey(t, 8)
	stage(t, r, realm, current, "Alice")
	record(t, r, realm, approve(t, r, realm, current.kid, signingkey.Activate, "Dave", "Carol", false), "")
	stage(t, r, realm, left, "Alice")
	stage(t, r, realm, right, "Alice")
	approvals := []id.UUID{
		approve(t, r, realm, left.kid, signingkey.Activate, "Dave", "Carol", false),
		approve(t, r, realm, right.kid, signingkey.Activate, "Dave", "Carol", false),
	}
	var wg sync.WaitGroup
	errs := make([]error, len(approvals))
	for i, approval := range approvals {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = r.Record(context.Background(), signingkey.RecordRequest{Realm: realm, ApprovalID: approval,
				Outcome: signingkey.Completed})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("an activation failed: %v", err)
		}
	}
	active := 0
	for kid, state := range states(t, r, realm) {
		if state == signingkey.Active {
			active++
		} else if state != signingkey.Retiring {
			t.Errorf("%s is %s", kid, state)
		}
	}
	if active != 1 {
		t.Errorf("%d keys are active, want 1", active)
	}
}

func jwkOfUnchecked(public *rsa.PublicKey) []byte {
	jwk, _ := json.Marshal(map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	})
	return jwk
}
