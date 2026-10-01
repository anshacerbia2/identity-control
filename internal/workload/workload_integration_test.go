package workload

// Workload creation against a real PostgreSQL and the two fake kernel ports, joined the way the real
// kernel joins them: a workload client comes with a service-account user, and the Principal
// credential writes the workload's identity on it. Each test owns the rows of its own realm.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

const testRealm = keycloak.Realm("workload-test")

type harness struct {
	t          *testing.T
	pool       *db.Pool
	clients    *keycloakfake.Registry
	users      *keycloakfake.Client
	registrar  *registration.Service
	service    *Service
	caller     id.UUID
	owner      id.UUID
	ownerScope string
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
	pool, err := db.Open(ctx, db.Config{Name: "workload-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, statement := range []string{
			`DELETE FROM identity.workload_owner_change WHERE principal_id IN
			   (SELECT w.principal_id FROM identity.workload w
			    JOIN identity.client_registration r ON r.registration_id = w.registration_id WHERE r.realm = $1)`,
			`DELETE FROM identity.workload WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.client_key WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.registration_adoption WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.registration_state_change WHERE registration_id IN
			   (SELECT registration_id FROM identity.client_registration WHERE realm = $1)`,
			`DELETE FROM identity.client_registration WHERE realm = $1`,
			`DELETE FROM identity.principal_mapping WHERE realm = $1`,
		} {
			if _, err := tx.Exec(ctx, statement, string(testRealm)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("empty this realm's workloads: %v", err)
	}

	users := keycloakfake.New()
	clients := keycloakfake.NewRegistry("registration-service-account")
	clients.Scopes["scnehaux-workload"] = "scope-workload"
	clients.OnServiceAccount = func(user keycloak.User) { users.AddServiceAccount(testRealm, user) }
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	registrar, err := registration.New(pool, clients, registration.Config{Realm: testRealm, CallTimeout: time.Second,
		PendingRecoveryAfter: time.Minute}, logger)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(pool, registrar, clients, users, Config{Realm: testRealm, CallTimeout: time.Second,
		PendingRecoveryAfter: time.Minute}, logger)
	if err != nil {
		t.Fatal(err)
	}
	caller, _ := id.NewV7()
	h := &harness{t: t, pool: pool, clients: clients, users: users, registrar: registrar, service: service, caller: caller}
	h.owner = h.principal("human", "active")
	return h
}

// principal records a mapping of the given subject type and state, as the Principal path leaves one.
func (h *harness) principal(subjectType, state string) id.UUID {
	h.t.Helper()
	principalID, _ := id.NewV7()
	var owner any
	if subjectType == "workload" {
		owner = h.owner.String()
	}
	var user any = "kc-" + principalID.String()
	if state == "pending" {
		user = nil
	}
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
		    (principal_id, realm, username, subject_type, workload_owner, keycloak_user_id, state)
		    VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			principalID.String(), string(testRealm), "user-"+principalID.String(), subjectType, owner, user, state)
		return err
	}); err != nil {
		h.t.Fatalf("record a %s %s Principal: %v", state, subjectType, err)
	}
	return principalID
}

func publicKey(t *testing.T) json.RawMessage {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, keycloak.MinClientKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"kty": "RSA",
		"n": base64.RawURLEncoding.EncodeToString(private.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(private.E)).Bytes())})
	return raw
}

func (h *harness) request(clientKey string) CreateRequest {
	key, _ := id.NewV7()
	return CreateRequest{CallerScope: "principal:" + h.caller.String(), IdempotencyKey: key.String(), CreatedBy: h.caller,
		DisplayName: "Nightly payroll export", Purpose: "Exports approved payroll to the bank each night",
		WorkloadType: TypeJob, Owner: h.owner, TeamReference: "payroll-platform", ClientKey: clientKey,
		Application: "payroll", PublicKey: publicKey(h.t)}
}

func (h *harness) clientsNamed(clientKey string) []keycloak.Client {
	found, _ := h.clients.FindClients(context.Background(), testRealm, clientKey)
	return found
}

func (h *harness) mapping(principalID id.UUID) (string, string, string) {
	h.t.Helper()
	var user, state, owner string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT coalesce(keycloak_user_id, ''), state, coalesce(workload_owner::text, '')
		    FROM identity.principal_mapping WHERE principal_id = $1`, principalID.String()).Scan(&user, &state, &owner)
	}); err != nil {
		h.t.Fatalf("read the mapping: %v", err)
	}
	return user, state, owner
}

func (h *harness) age(principalID id.UUID) {
	h.t.Helper()
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE identity.workload SET created_at = now() - interval '1 hour'
		    WHERE principal_id = $1`, principalID.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE identity.client_registration SET created_at = now() - interval '1 hour'
		    WHERE registration_id = (SELECT registration_id FROM identity.workload WHERE principal_id = $1)`,
			principalID.String())
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) pendingWorkload(clientKey string) id.UUID {
	h.t.Helper()
	var raw string
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT w.principal_id::text FROM identity.workload w
		    JOIN identity.client_registration r ON r.registration_id = w.registration_id
		    WHERE r.realm = $1 AND r.client_key = $2`, string(testRealm), clientKey).Scan(&raw)
	}); err != nil {
		h.t.Fatalf("find the workload: %v", err)
	}
	parsed, _ := id.Parse(raw)
	return parsed
}

// A workload is a Principal whose Keycloak user is its client's service-account user: the identity
// is written there, the mapping points there, and nothing else carries it.
func TestAWorkloadIsBoundToItsClientsServiceAccount(t *testing.T) {
	h := newHarness(t)
	req := h.request("nightly-job")
	created, err := h.service.Create(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if created.State != StateActive || created.Owner != h.owner || created.ClientKey != "nightly-job" ||
		created.CreatedBy != h.caller || created.TeamReference != "payroll-platform" || created.ActivatedAt == nil {
		t.Errorf("workload = %+v", created)
	}

	found := h.clientsNamed("nightly-job")
	if len(found) != 1 {
		t.Fatalf("%d clients named nightly-job", len(found))
	}
	spec, scopes, _ := h.clients.Spec(found[0].ID)
	if !spec.Workload || len(spec.Keys) != 1 || !slices.Equal(scopes, []string{"scope-basic", "scope-workload"}) {
		t.Errorf("client spec = %+v, scopes %v", spec, scopes)
	}
	serviceAccount := keycloak.UserID("sa-" + string(found[0].ID))
	user, ok := h.users.User(serviceAccount)
	if !ok || user.PrincipalID != created.PrincipalID || user.SubjectType != keycloak.SubjectWorkload ||
		user.WorkloadOwner != h.owner {
		t.Errorf("the service-account user holds %+v, want the workload's identity", user)
	}
	if kcUser, state, owner := h.mapping(created.PrincipalID); kcUser != string(serviceAccount) || state != "active" ||
		owner != h.owner.String() {
		t.Errorf("mapping = %s %s %s", kcUser, state, owner)
	}
	if h.users.Calls.CreateUser != 0 {
		t.Error("a user was created through POST /users; a workload's user is its client's service account")
	}

	// A replay returns the same workload and creates nothing more.
	again, err := h.service.Create(context.Background(), req)
	if err != nil || again.PrincipalID != created.PrincipalID {
		t.Errorf("a replay answered %+v, %v", again, err)
	}
	if len(h.clientsNamed("nightly-job")) != 1 {
		t.Error("a replay created a second client")
	}
	read, err := h.service.Get(context.Background(), created.PrincipalID)
	if err != nil || read.PrincipalID != created.PrincipalID || read.Purpose != req.Purpose {
		t.Errorf("Get = %+v, %v", read, err)
	}
}

// The owner is an active human Principal. A workload cannot answer for a workload, and a pending or
// quarantined human answers for nothing yet. A refused owner records nothing.
func TestTheOwnerMustBeAnActiveHuman(t *testing.T) {
	h := newHarness(t)
	unknown, _ := id.NewV7()
	for name, owner := range map[string]id.UUID{
		"an unknown Principal": unknown,
		"a workload":           h.principal("workload", "active"),
		"a pending human":      h.principal("human", "pending"),
		"a quarantined human":  h.principal("human", "quarantined"),
	} {
		req := h.request("owned-by-nobody")
		req.Owner = owner
		if _, err := h.service.Create(context.Background(), req); !errors.Is(err, ErrOwnerNotEligible) {
			t.Errorf("%s as owner answered %v, want ErrOwnerNotEligible", name, err)
		}
	}
	if n := len(h.clientsNamed("owned-by-nobody")); n != 0 {
		t.Errorf("a refused owner created %d client(s)", n)
	}
	var rows int
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.client_registration WHERE realm = $1 AND client_key = 'owned-by-nobody'`,
			string(testRealm)).Scan(&rows)
	}); err != nil || rows != 0 {
		t.Errorf("%d registration(s) recorded for a refused owner, %v", rows, err)
	}
}

func TestTheValidationRulesRefuse(t *testing.T) {
	h := newHarness(t)
	for name, c := range map[string]struct {
		change func(*CreateRequest)
		want   error
	}{
		"no purpose":         {func(r *CreateRequest) { r.Purpose = " " }, ErrInvalid},
		"no display name":    {func(r *CreateRequest) { r.DisplayName = "" }, ErrInvalid},
		"no owner":           {func(r *CreateRequest) { r.Owner = id.UUID{} }, ErrInvalid},
		"an agent":           {func(r *CreateRequest) { r.WorkloadType = TypeAgent }, ErrAgentNotBuilt},
		"an unknown type":    {func(r *CreateRequest) { r.WorkloadType = "robot" }, ErrInvalid},
		"no key":             {func(r *CreateRequest) { r.PublicKey = nil }, registration.ErrInvalid},
		"no Idempotency-Key": {func(r *CreateRequest) { r.IdempotencyKey = "" }, ErrInvalid},
	} {
		req := h.request("checked-job")
		c.change(&req)
		if _, err := h.service.Create(context.Background(), req); !errors.Is(err, c.want) {
			t.Errorf("%s answered %v, want %v", name, err, c.want)
		}
	}
	delete(h.clients.Scopes, "scnehaux-workload")
	if _, err := h.service.Create(context.Background(), h.request("checked-job")); !errors.Is(err, registration.ErrScopeUndeclared) {
		t.Errorf("a realm without the workload scope answered %v", err)
	}
	if n := len(h.clientsNamed("checked-job")); n != 0 {
		t.Errorf("a refused workload created %d client(s)", n)
	}
}

// A client_key an unregistered client holds is refused, never adopted, and the refusal is what a
// retry of the same request is told.
func TestAWorkloadOverAnUnregisteredClientIsRefused(t *testing.T) {
	h := newHarness(t)
	h.clients.Put(keycloak.Client{ID: "hand-made", ClientID: "hand-made-job", Enabled: true})
	req := h.request("hand-made-job")
	if _, err := h.service.Create(context.Background(), req); !errors.Is(err, ErrRefused) {
		t.Fatalf("a workload over an unregistered client answered %v, want ErrRefused", err)
	}
	if _, err := h.service.Create(context.Background(), req); !errors.Is(err, ErrRefused) {
		t.Errorf("a retry answered %v, want the same refusal", err)
	}
	refused, err := h.service.Get(context.Background(), h.pendingWorkload("hand-made-job"))
	if err != nil || refused.State != StateRetired {
		t.Errorf("the refused workload = %+v, %v", refused, err)
	}
}

// A crash after the client exists and before the identity is bound leaves the workload pending with
// its registration active. The same request is told it is in progress, recovery binds it, and then
// the same request replays the workload.
func TestRecoveryBindsAWorkloadWhoseIdentityWasNotWritten(t *testing.T) {
	h := newHarness(t)
	req := h.request("half-bound-job")
	h.users.FailWrite = keycloak.ErrUnavailable
	if _, err := h.service.Create(context.Background(), req); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("a failed identity write answered %v", err)
	}
	h.users.FailWrite = nil
	pending := h.pendingWorkload("half-bound-job")
	if _, err := h.service.Create(context.Background(), req); !errors.Is(err, idempotency.ErrInProgress) {
		t.Errorf("a retry while pending answered %v, want ErrInProgress", err)
	}

	if n, _ := h.service.RecoverPending(context.Background()); n != 0 {
		t.Errorf("recovery finished %d workload(s) younger than the threshold", n)
	}
	h.age(pending)
	if n, err := h.service.RecoverPending(context.Background()); n != 1 || err != nil {
		t.Fatalf("recovery finished %d, %v", n, err)
	}
	if _, state, _ := h.mapping(pending); state != "active" {
		t.Errorf("the recovered mapping is %s", state)
	}
	replayed, err := h.service.Create(context.Background(), req)
	if err != nil || replayed.PrincipalID != pending || replayed.State != StateActive {
		t.Errorf("the request after recovery answered %+v, %v", replayed, err)
	}
}

// A client creation that never landed is created by registration recovery, and the workload is then
// bound by its own.
func TestRecoveryFinishesAWorkloadWhoseClientNeverLanded(t *testing.T) {
	h := newHarness(t)
	h.clients.FailCreate = keycloak.ErrUnavailable
	if _, err := h.service.Create(context.Background(), h.request("never-landed-job")); err == nil {
		t.Fatal("a failed client creation succeeded")
	}
	h.clients.FailCreate = nil
	pending := h.pendingWorkload("never-landed-job")
	h.age(pending)
	if n, err := h.registrar.RecoverPending(context.Background()); n != 1 || err != nil {
		t.Fatalf("registration recovery resolved %d, %v", n, err)
	}
	if n, err := h.service.RecoverPending(context.Background()); n != 1 || err != nil {
		t.Fatalf("workload recovery finished %d, %v", n, err)
	}
	if recovered, _ := h.service.Get(context.Background(), pending); recovered.State != StateActive {
		t.Errorf("the recovered workload is %s", recovered.State)
	}
}

// Reassignment moves the owner on the record, the mapping and the service-account user together, and
// records who moved it and why.
func TestAWorkloadIsReassigned(t *testing.T) {
	h := newHarness(t)
	created, err := h.service.Create(context.Background(), h.request("reassigned-job"))
	if err != nil {
		t.Fatal(err)
	}
	successor := h.principal("human", "active")
	for name, c := range map[string]struct {
		req  ReassignRequest
		want error
	}{
		"no reason":           {ReassignRequest{PrincipalID: created.PrincipalID, NewOwner: successor, ChangedBy: h.caller}, ErrInvalid},
		"the same owner":      {ReassignRequest{PrincipalID: created.PrincipalID, NewOwner: h.owner, ChangedBy: h.caller, Reason: "r"}, ErrInvalid},
		"a workload owner":    {ReassignRequest{PrincipalID: created.PrincipalID, NewOwner: h.principal("workload", "active"), ChangedBy: h.caller, Reason: "r"}, ErrOwnerNotEligible},
		"itself":              {ReassignRequest{PrincipalID: created.PrincipalID, NewOwner: created.PrincipalID, ChangedBy: h.caller, Reason: "r"}, ErrOwnerNotEligible},
		"an unknown workload": {ReassignRequest{PrincipalID: successor, NewOwner: h.owner, ChangedBy: h.caller, Reason: "r"}, ErrNotFound},
	} {
		if _, err := h.service.Reassign(context.Background(), c.req); !errors.Is(err, c.want) {
			t.Errorf("%s answered %v, want %v", name, err, c.want)
		}
	}

	// A kernel that refuses the write changes nothing here.
	h.users.FailWrite = keycloak.ErrUnavailable
	if _, err := h.service.Reassign(context.Background(), ReassignRequest{PrincipalID: created.PrincipalID,
		NewOwner: successor, ChangedBy: h.caller, Reason: "the owner moved team"}); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("a refused write answered %v", err)
	}
	if unchanged, _ := h.service.Get(context.Background(), created.PrincipalID); unchanged.Owner != h.owner {
		t.Error("a reassignment the kernel refused changed the owner of record")
	}
	h.users.FailWrite = nil

	moved, err := h.service.Reassign(context.Background(), ReassignRequest{PrincipalID: created.PrincipalID,
		NewOwner: successor, ChangedBy: h.caller, Reason: "the owner moved team"})
	if err != nil {
		t.Fatal(err)
	}
	if moved.Owner != successor || moved.State != StateActive || !moved.OwnerRecordedAt.After(created.OwnerRecordedAt) {
		t.Errorf("after the reassignment: %+v", moved)
	}
	kcUser, _, owner := h.mapping(created.PrincipalID)
	if owner != successor.String() {
		t.Errorf("the mapping names owner %s", owner)
	}
	if user, _ := h.users.User(keycloak.UserID(kcUser)); user.WorkloadOwner != successor {
		t.Errorf("the service-account user names owner %s", user.WorkloadOwner)
	}
	var changes int
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.workload_owner_change
		    WHERE principal_id = $1 AND previous_owner = $2 AND new_owner = $3 AND changed_by = $4
		      AND reason = 'the owner moved team'`,
			created.PrincipalID.String(), h.owner.String(), successor.String(), h.caller.String()).Scan(&changes)
	}); err != nil || changes != 1 {
		t.Errorf("%d change record(s), %v", changes, err)
	}
}
