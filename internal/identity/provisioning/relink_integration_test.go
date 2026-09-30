package provisioning_test

// Portability against a real PostgreSQL and a fake kernel. The rules that matter live in the
// database: an active mapping cannot lose its user, one open finding per Principal, and a relink
// record nobody can rewrite. Each test owns the rows of its own realm.

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

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

const portabilityRealm = keycloak.Realm("portability-test")

type portability struct {
	t           *testing.T
	pool        *db.Pool
	kernel      *keycloakfake.Client
	provisioner *provisioning.Provisioner
	operator    id.UUID
}

func newPortability(t *testing.T) *portability {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{Name: "portability-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, statement := range []string{
			`DELETE FROM identity.principal_finding WHERE principal_id IN
			   (SELECT principal_id FROM identity.principal_mapping WHERE realm = $1)`,
			`DELETE FROM identity.principal_relink WHERE principal_id IN
			   (SELECT principal_id FROM identity.principal_mapping WHERE realm = $1)`,
			`DELETE FROM identity.principal_mapping WHERE realm = $1`,
		} {
			if _, err := tx.Exec(ctx, statement, string(portabilityRealm)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("empty this realm's mappings: %v", err)
	}
	kernel := keycloakfake.New()
	provisioner, err := provisioning.New(pool, kernel, provisioning.Config{
		ProvisionTimeout: time.Second, PendingRecoveryAfter: time.Minute, RecoveryBatch: 2, Realm: portabilityRealm,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	operator, _ := id.NewV7()
	return &portability{t: t, pool: pool, kernel: kernel, provisioner: provisioner, operator: operator}
}

func (p *portability) create(username string) provisioning.Response {
	p.t.Helper()
	key, _ := id.NewV7()
	created, err := p.provisioner.Create(context.Background(), provisioning.CreateRequest{
		CallerScope: "principal:" + p.operator.String(), IdempotencyKey: key.String(), Realm: portabilityRealm,
		Username: username, SubjectType: keycloak.SubjectHuman,
	})
	if err != nil {
		p.t.Fatalf("create %s: %v", username, err)
	}
	return created
}

func (p *portability) user(principalID id.UUID) keycloak.User {
	p.t.Helper()
	found, err := p.kernel.FindByPrincipalID(context.Background(), portabilityRealm, principalID)
	if err != nil || len(found) != 1 {
		p.t.Fatalf("%d kernel user(s) carry %s (%v), want exactly one", len(found), principalID, err)
	}
	return found[0]
}

func (p *portability) relink(principalID id.UUID, reason string) (provisioning.RelinkResult, error) {
	return p.provisioner.Relink(context.Background(), provisioning.RelinkRequest{
		PrincipalID: principalID, RelinkedBy: p.operator, Reason: reason})
}

// The portability test: a Principal's Keycloak user is deleted, the sweep reports it and changes
// nothing, and a relink with a reason provisions a new user carrying the same principal_id.
func TestADeletedUserIsRelinkedUnderTheSamePrincipal(t *testing.T) {
	p := newPortability(t)
	created := p.create("portable.user")
	bystander := p.create("bystander.user")
	original := p.user(created.PrincipalID)
	p.kernel.DeleteUser(original.ID)

	if n, err := p.provisioner.FindDangling(context.Background()); err != nil || n != 1 {
		t.Fatalf("the sweep found %d dangling mapping(s) (%v), want 1", n, err)
	}
	if n, err := p.provisioner.FindDangling(context.Background()); err != nil || n != 1 {
		t.Fatalf("a second sweep found %d (%v)", n, err)
	}
	open, err := p.provisioner.Dangling(context.Background())
	if err != nil || len(open) != 1 || open[0].PrincipalID != created.PrincipalID {
		t.Fatalf("open findings = %+v (%v), want the one Principal once", open, err)
	}
	if n := p.kernel.Count(); n != 1 {
		t.Errorf("the sweep changed the kernel: %d user(s), want only the bystander", n)
	}

	if _, err := p.relink(created.PrincipalID, " "); !errors.Is(err, provisioning.ErrReasonRequired) {
		t.Errorf("a relink without a reason answered %v", err)
	}
	result, err := p.relink(created.PrincipalID, "the user was deleted by mistake")
	if err != nil {
		t.Fatal(err)
	}
	if result.PrincipalID != created.PrincipalID || result.State != provisioning.StateActive {
		t.Errorf("relink = %+v, want the same Principal active again", result)
	}
	replacement := p.user(created.PrincipalID)
	if replacement.ID == original.ID || replacement.Username != "portable.user" {
		t.Errorf("the new user is %+v, want a different user carrying the same identifier and username", replacement)
	}
	if open, _ := p.provisioner.Dangling(context.Background()); len(open) != 0 {
		t.Errorf("the finding is still open after the relink: %+v", open)
	}
	if p.user(bystander.PrincipalID).ID == "" {
		t.Error("the bystander lost its user")
	}

	var previous, reason string
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT previous_keycloak_user_id, reason FROM identity.principal_relink
		    WHERE principal_id = $1`, created.PrincipalID.String()).Scan(&previous, &reason)
	}); err != nil || previous != string(original.ID) || reason != "the user was deleted by mistake" {
		t.Errorf("the relink record is %q, %q (%v)", previous, reason, err)
	}

	if _, err := p.relink(created.PrincipalID, "again"); !errors.Is(err, provisioning.ErrUserStillExists) {
		t.Errorf("a relink while the user exists answered %v", err)
	}
}

func TestARelinkNeedsAnAbsentUserAndAnActiveMapping(t *testing.T) {
	p := newPortability(t)
	created := p.create("still.here")
	if _, err := p.relink(created.PrincipalID, "why"); !errors.Is(err, provisioning.ErrUserStillExists) {
		t.Errorf("relinking a Principal whose user exists answered %v", err)
	}
	nobody, _ := id.NewV7()
	if _, err := p.relink(nobody, "why"); !errors.Is(err, provisioning.ErrNotFound) {
		t.Errorf("relinking an unknown Principal answered %v", err)
	}

	// An unknown answer is not an absent user: the mapping stays active.
	p.kernel.DeleteUser(p.user(created.PrincipalID).ID)
	p.kernel.FailFind = keycloak.ErrUnavailable
	if _, err := p.relink(created.PrincipalID, "why"); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Errorf("a relink against an unreachable kernel answered %v", err)
	}
	var state string
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM identity.principal_mapping WHERE principal_id = $1`,
			created.PrincipalID.String()).Scan(&state)
	}); err != nil || state != "active" {
		t.Errorf("after a refused relink the mapping is %q (%v)", state, err)
	}
}

// An unread page is not a missing user.
func TestAFailedEnumerationRecordsNothing(t *testing.T) {
	p := newPortability(t)
	for _, name := range []string{"a.user", "b.user", "c.user"} {
		p.create(name)
	}
	p.kernel.FailList = keycloak.ErrUnavailable
	if _, err := p.provisioner.FindDangling(context.Background()); err == nil {
		t.Fatal("a failed enumeration succeeded")
	}
	if open, _ := p.provisioner.Dangling(context.Background()); len(open) != 0 {
		t.Errorf("a failed enumeration recorded %d finding(s)", len(open))
	}
	p.kernel.FailList = nil
	// Three users over pages of two: every page is read.
	if n, err := p.provisioner.FindDangling(context.Background()); err != nil || n != 0 {
		t.Errorf("a full enumeration found %d dangling (%v), want none", n, err)
	}
}

func TestReconcileRecoversPendingAndSweeps(t *testing.T) {
	p := newPortability(t)
	created := p.create("swept.user")
	p.kernel.DeleteUser(p.user(created.PrincipalID).ID)
	recovered, dangling, err := p.provisioner.Reconcile(context.Background())
	if err != nil || recovered != 0 || dangling != 1 {
		t.Errorf("Reconcile = %d recovered, %d dangling, %v", recovered, dangling, err)
	}
}

// A workload is never relinked here. Its user is its client's service account, and a user this path
// created would carry the workload's identity into no token; the workload path rebuilds it.
func TestAWorkloadIsNotRelinkedAsAUser(t *testing.T) {
	p := newPortability(t)
	owner := p.create("workload.owner")
	principalID, _ := id.NewV7()
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
		    (principal_id, realm, username, subject_type, workload_owner, keycloak_user_id, state)
		    VALUES ($1, $2, 'service-account-nightly-job', 'workload', $3, $4, 'active')`,
			principalID.String(), string(portabilityRealm), owner.PrincipalID.String(), "sa-"+principalID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.relink(principalID, "its client was deleted"); !errors.Is(err, provisioning.ErrWorkloadPath) {
		t.Errorf("relinking a workload answered %v, want ErrWorkloadPath", err)
	}
	if p.kernel.Calls.CreateUser != 1 {
		t.Errorf("%d users were created; only the owner should have been", p.kernel.Calls.CreateUser)
	}
}
