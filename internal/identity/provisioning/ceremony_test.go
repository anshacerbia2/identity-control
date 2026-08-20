package provisioning_test

// The bootstrap ceremony, stated as tests.
//
// The properties under test are the ones ADR-IAM-001 §5.8 commits to, and each is about a refusal
// rather than a success: the ceremony must be unrepeatable, must refuse a populated registry, must
// not let a retry rewrite who is on record, and must not hold a credential. A test that only
// proved the happy path would leave every one of those unchecked.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db/dbtest"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

// ceremonyClaimed configures the claiming transaction: the insert affected one row, and the
// read-back reports the operator, reason, key, and an empty registry.
func ceremonyClaimed(operator, reason, key string, existingMappings int) *dbtest.Tx {
	return &dbtest.Tx{
		Tag:       dbtest.CommandTag(1),
		RowValues: []any{operator, reason, key, existingMappings},
	}
}

// ceremonyAlreadyClaimed configures a resumed ceremony: the insert affected no row because one
// already existed, and the read-back returns what the first attempt recorded.
func ceremonyAlreadyClaimed(operator, reason, key string, existingMappings int) *dbtest.Tx {
	return &dbtest.Tx{
		Tag:       dbtest.CommandTag(0),
		RowValues: []any{operator, reason, key, existingMappings},
	}
}

func ceremonyRequest() provisioning.CeremonyRequest {
	return provisioning.CeremonyRequest{
		Realm:    "scnehaux",
		Username: "first.operator",
		Email:    "first.operator@example.com",
		Operator: "ansha@example.com",
		Reason:   "initial estate stand-up",
	}
}

func TestBootstrapCreatesTheFirstPrincipalThroughTheOrdinaryPath(t *testing.T) {
	tx := &fakeTx{txs: []*dbtest.Tx{
		ceremonyClaimed("ansha@example.com", "initial estate stand-up", "bootstrap:scnehaux", 0),
		claimed(), // Create checkpoint one
		claimed(), // Create checkpoint two
	}}
	kernel := keycloakfake.New()
	p := newProvisioner(t, tx, kernel)

	response, record, err := p.Bootstrap(context.Background(), ceremonyRequest())
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if response.PrincipalID.IsNil() {
		t.Fatal("Bootstrap returned a nil principal_id")
	}
	// UUIDv7 through the ordinary path, not a reserved or well-known identifier. A fixed
	// identifier for the first Principal would be a value an attacker knows in every estate.
	if response.PrincipalID.Version() != 7 {
		t.Errorf("principal_id is UUID version %d, want 7", response.PrincipalID.Version())
	}
	if response.SubjectType != keycloak.SubjectHuman {
		t.Errorf("subject_type = %q, want human", response.SubjectType)
	}
	if record.Operator != "ansha@example.com" {
		t.Errorf("recorded operator = %q", record.Operator)
	}
	if kernel.Calls.CreateUser != 1 {
		t.Errorf("kernel CreateUser called %d times, want 1", kernel.Calls.CreateUser)
	}
}

// TestBootstrapHoldsNoCredential is the property that keeps the ceremony from becoming the one
// process in the estate that both authorizes an identity and holds its credential.
//
// The kernel is told to demand a credential instead. Asserted through the fake's record of the
// create call, because the port has no credential field to inspect — which is itself the point.
func TestBootstrapHoldsNoCredential(t *testing.T) {
	tx := &fakeTx{txs: []*dbtest.Tx{
		ceremonyClaimed("ansha@example.com", "initial estate stand-up", "bootstrap:scnehaux", 0),
		claimed(),
		claimed(),
	}}
	kernel := keycloakfake.New()
	p := newProvisioner(t, tx, kernel)

	response, _, err := p.Bootstrap(context.Background(), ceremonyRequest())
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	found, err := kernel.FindByPrincipalID(context.Background(), "scnehaux", response.PrincipalID)
	if err != nil {
		t.Fatalf("FindByPrincipalID: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d users, want 1", len(found))
	}

	actions := kernel.RequiredActions(found[0].ID)
	if len(actions) != 1 || actions[0] != keycloak.ActionUpdatePassword {
		t.Errorf("required actions = %v, want [%s]; the Principal must owe a credential this process never held",
			actions, keycloak.ActionUpdatePassword)
	}
}

// TestBootstrapRefusesAPopulatedRegistry closes the path by which the ceremony could be used to
// inject a Principal into a running estate rather than to start one.
func TestBootstrapRefusesAPopulatedRegistry(t *testing.T) {
	tx := &fakeTx{txs: []*dbtest.Tx{
		ceremonyClaimed("ansha@example.com", "initial estate stand-up", "bootstrap:scnehaux", 3),
	}}
	kernel := keycloakfake.New()
	p := newProvisioner(t, tx, kernel)

	_, _, err := p.Bootstrap(context.Background(), ceremonyRequest())
	if !errors.Is(err, provisioning.ErrRegistryNotEmpty) {
		t.Fatalf("error = %v, want ErrRegistryNotEmpty", err)
	}
	// Nothing reached the kernel. The refusal happens in the claiming transaction, so a
	// ceremony that should not have run leaves no user behind either.
	if kernel.Calls.CreateUser != 0 {
		t.Errorf("kernel CreateUser called %d times, want 0", kernel.Calls.CreateUser)
	}
}

// TestResumedCeremonyUsesTheRecordedOperator is the immutability property expressed in behaviour
// rather than in privilege. grants.sql withholds UPDATE, so the record cannot be rewritten in the
// database; this asserts the code does not try, and reports the original operator instead.
func TestResumedCeremonyUsesTheRecordedOperator(t *testing.T) {
	tx := &fakeTx{txs: []*dbtest.Tx{
		// The registry holds the pending mapping the interrupted attempt wrote. A resumed
		// ceremony must tolerate that rather than refuse it.
		ceremonyAlreadyClaimed("first.operator@example.com", "the original reason", "bootstrap:scnehaux", 1),
		claimed(),
		claimed(),
	}}
	kernel := keycloakfake.New()
	p := newProvisioner(t, tx, kernel)

	request := ceremonyRequest()
	request.Operator = "someone.else@example.com"
	request.Reason = "a different reason"

	_, record, err := p.Bootstrap(context.Background(), request)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if record.Operator != "first.operator@example.com" {
		t.Errorf("operator = %q; a resumed ceremony must report who ran the first attempt", record.Operator)
	}
	if record.Reason != "the original reason" {
		t.Errorf("reason = %q; a resumed ceremony must not rewrite the recorded reason", record.Reason)
	}
}

// TestResumedCeremonyReusesTheStoredKey is what makes the ceremony survive a crash without a
// second Principal. The key lives in the row, so step two replays the original claim rather than
// minting a fresh identifier.
func TestResumedCeremonyReusesTheStoredKey(t *testing.T) {
	first := &fakeTx{txs: []*dbtest.Tx{
		ceremonyClaimed("ansha@example.com", "initial estate stand-up", "bootstrap:scnehaux", 0),
		claimed(),
		claimed(),
	}}
	original, _, err := newProvisioner(t, first, keycloakfake.New()).
		Bootstrap(context.Background(), ceremonyRequest())
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	stored, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal stored response: %v", err)
	}

	// The second run finds the claim completed. Create replays the stored response and performs
	// no remote call, which is the property the exit criterion names.
	second := &fakeTx{txs: []*dbtest.Tx{
		ceremonyAlreadyClaimed("ansha@example.com", "initial estate stand-up", "bootstrap:scnehaux", 1),
		replaying(claimArg(t, first.txs[1], 2), stored),
	}}
	kernel := keycloakfake.New()

	response, _, err := newProvisioner(t, second, kernel).
		Bootstrap(context.Background(), ceremonyRequest())
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if response.PrincipalID != original.PrincipalID {
		t.Errorf("principal_id = %s, want %s; a resumed ceremony minted a second identifier",
			response.PrincipalID, original.PrincipalID)
	}
	if kernel.Calls.CreateUser != 0 {
		t.Errorf("kernel CreateUser called %d times, want 0", kernel.Calls.CreateUser)
	}
}

// claimArg recovers one argument of the idempotency claim statement the provisioner sent.
//
// Reading it back rather than recomputing it is the same choice digestOf makes: recomputing would
// assert the test's own arithmetic instead of the provisioner's. The claim carries exactly three
// arguments — scope, key, digest — which is what identifies it among the recorded statements.
func claimArg(t *testing.T, tx *dbtest.Tx, index int) string {
	t.Helper()
	for _, call := range tx.Calls() {
		if len(call.Args) != 3 {
			continue
		}
		if value, ok := call.Args[index].(string); ok {
			return value
		}
	}
	t.Fatal("no claim statement was recorded")
	return ""
}

// TestBootstrapRequiresANamedHumanAndAReason keeps the record meaningful. An empty operator would
// produce evidence naming nobody, which is indistinguishable from no evidence.
func TestBootstrapRequiresANamedHumanAndAReason(t *testing.T) {
	cases := map[string]func(*provisioning.CeremonyRequest){
		"no operator":    func(r *provisioning.CeremonyRequest) { r.Operator = "" },
		"blank operator": func(r *provisioning.CeremonyRequest) { r.Operator = "   " },
		"no reason":      func(r *provisioning.CeremonyRequest) { r.Reason = "" },
		"blank reason":   func(r *provisioning.CeremonyRequest) { r.Reason = "\t" },
		"no username":    func(r *provisioning.CeremonyRequest) { r.Username = "" },
		"no realm":       func(r *provisioning.CeremonyRequest) { r.Realm = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := ceremonyRequest()
			mutate(&request)

			// No transaction is configured. A request that reached the database would fail the
			// fake with "unexpected InTx call", so this also asserts the refusal happens before
			// anything durable.
			p := newProvisioner(t, &fakeTx{}, keycloakfake.New())
			if _, _, err := p.Bootstrap(context.Background(), request); err == nil {
				t.Fatal("Bootstrap accepted the request")
			}
		})
	}
}

// TestCeremonyScopeCannotCollideWithACaller keeps the ceremony's idempotency key out of every
// authenticated caller's namespace. A shared scope would let an API caller replay or consume the
// ceremony's claim.
func TestCeremonyScopeCannotCollideWithACaller(t *testing.T) {
	tx := &fakeTx{txs: []*dbtest.Tx{
		ceremonyClaimed("ansha@example.com", "reason", "bootstrap:scnehaux", 0),
		claimed(),
		claimed(),
	}}
	p := newProvisioner(t, tx, keycloakfake.New())
	if _, _, err := p.Bootstrap(context.Background(), ceremonyRequest()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// The scope reached idempotency.Claim as the first argument of the claim statement. Every
	// API caller's scope is "principal:<uuid>", so asserting the prefix differs is asserting the
	// namespaces are disjoint.
	scope := claimArg(t, tx.txs[1], 0)
	if strings.HasPrefix(scope, "principal:") {
		t.Errorf("ceremony claimed under %q, which is inside the caller namespace", scope)
	}
	if scope == "" {
		t.Error("the ceremony claimed under an empty scope")
	}
}
