package tenantcontext

// Applying Membership and Tenant events to the desired state against the real engine
// (TDD-identity-control-002 2.0.0 §Applying an Event).

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/event"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/delivery"
)

func pool(t *testing.T) *db.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	p, err := db.Open(context.Background(), db.Config{Name: "tenantcontext-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func newID(t *testing.T) id.UUID {
	t.Helper()
	value, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func envelope(t *testing.T, eventType event.Type, data any, position int64) event.Envelope {
	t.Helper()
	built, err := event.New("/systems/organization-control", eventType, time.Now().UTC(), data)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	built.StreamPosition = position
	return built
}

type convergence struct {
	state    string
	priority bool
	marked   time.Time
}

func readMembership(t *testing.T, p *db.Pool, membershipID id.UUID) (string, int64) {
	t.Helper()
	var status string
	var version int64
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT membership_status, membership_version FROM identity.membership_desired
			WHERE membership_id = $1`, membershipID.String()).Scan(&status, &version)
	}); err != nil {
		t.Fatal(err)
	}
	return status, version
}

func readConvergence(t *testing.T, p *db.Pool, tenantID id.UUID) (convergence, bool) {
	t.Helper()
	var c convergence
	found := false
	if err := p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT state, priority, marked_at FROM identity.tenant_convergence
			WHERE tenant_id = $1`, tenantID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			found = true
			return rows.Scan(&c.state, &c.priority, &c.marked)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return c, found
}

// A revoke delivered before the older grant leaves the Membership revoked; the grant is superseded,
// carries no receipt, and a duplicate writes nothing twice.
func TestTheNewestMembershipStateWins(t *testing.T) {
	p := pool(t)
	desired, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	membership := Membership{MembershipID: newID(t), PrincipalID: newID(t), TenantID: newID(t)}

	revoked := membership
	revoked.MembershipStatus, revoked.MembershipVersion = "revoked", 14
	first := envelope(t, MembershipRevoked, revoked, 140)
	if outcome, err := desired.Apply(ctx, first); err != nil || !outcome.Applied() || outcome.Duplicate {
		t.Fatalf("the revoke: %+v, %v", outcome, err)
	}
	c, found := readConvergence(t, p, membership.TenantID)
	if !found || c.state != "pending" || !c.priority {
		t.Errorf("a revoke marks its Tenant priority: %+v, found %v", c, found)
	}

	granted := membership
	granted.MembershipStatus, granted.MembershipVersion = "active", 13
	if outcome, err := desired.Apply(ctx, envelope(t, MembershipGranted, granted, 130)); err != nil ||
		!outcome.Superseded || outcome.Applied() {
		t.Errorf("an older grant after it: %+v, %v; want superseded", outcome, err)
	}
	if status, version := readMembership(t, p, membership.MembershipID); status != "revoked" || version != 14 {
		t.Errorf("the desired state is %s at %d; want revoked at 14", status, version)
	}

	if outcome, err := desired.Apply(ctx, first); err != nil || !outcome.Duplicate || !outcome.Applied() {
		t.Errorf("the revoke again: %+v, %v; want a duplicate, still applied", outcome, err)
	}
}

// A Tenant event orders by tenant_version, and a standard event marks without priority.
func TestATenantEventOrdersByItsVersion(t *testing.T) {
	p := pool(t)
	desired, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tenantID := newID(t)
	activated := Tenant{TenantID: tenantID, TenantStatus: "active", TenantVersion: 1, TenantSecurityVersion: 1}
	if _, err := desired.Apply(ctx, envelope(t, TenantActivated, activated, 10)); err != nil {
		t.Fatal(err)
	}
	if c, _ := readConvergence(t, p, tenantID); c.priority {
		t.Error("an activation is standard, not priority")
	}
	suspended := Tenant{TenantID: tenantID, TenantStatus: "suspended", TenantVersion: 3, TenantSecurityVersion: 2}
	if _, err := desired.Apply(ctx, envelope(t, TenantSuspended, suspended, 30)); err != nil {
		t.Fatal(err)
	}
	restored := Tenant{TenantID: tenantID, TenantStatus: "active", TenantVersion: 2, TenantSecurityVersion: 2}
	if outcome, err := desired.Apply(ctx, envelope(t, TenantRestored, restored, 20)); err != nil || !outcome.Superseded {
		t.Errorf("an older restore: %+v, %v; want superseded", outcome, err)
	}
	var status string
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_status FROM identity.tenant_desired WHERE tenant_id = $1`,
			tenantID.String()).Scan(&status)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Errorf("the Tenant is %s; want suspended", status)
	}
	if c, _ := readConvergence(t, p, tenantID); !c.priority || c.state != "pending" {
		t.Errorf("the suspension marks it priority: %+v", c)
	}
}

// A payload this projection cannot read, and a type it does not apply, are poison.
func TestPoisonIsRefused(t *testing.T) {
	p := pool(t)
	desired, err := NewDesired(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bad := Membership{MembershipID: newID(t), PrincipalID: newID(t), TenantID: newID(t), MembershipStatus: "pending",
		MembershipVersion: 1}
	if _, err := desired.Apply(ctx, envelope(t, MembershipGranted, bad, 1)); !errors.Is(err, delivery.ErrPoison) {
		t.Errorf("an unknown status: %v, want poison", err)
	}
	if _, err := desired.Apply(ctx, envelope(t, "com.scnehaux.organization.workspace.lifecycle.archived", bad, 1)); !errors.Is(err, delivery.ErrPoison) {
		t.Errorf("an unknown type: %v, want poison", err)
	}
}
