package provisioning_test

// Leaving quarantine against a real PostgreSQL and a fake kernel (TDD-identity-control-001 1.18.0
// §Leaving Quarantine): the release lands in suspended, keeps the user contained, and is recorded
// insert-only.

import (
	"context"
	"errors"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

func (p *portability) release(principalID id.UUID, username string) (provisioning.ReleaseResult, error) {
	return p.provisioner.Release(context.Background(), provisioning.ReleaseRequest{
		PrincipalID: principalID, ReleasedBy: p.operator, Reason: "the console copy was deleted; ticket 41",
		Username: username})
}

func (p *portability) state(principalID id.UUID) (string, string) {
	p.t.Helper()
	var state, user string
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, coalesce(keycloak_user_id, '') FROM identity.principal_mapping
		    WHERE principal_id = $1`, principalID.String()).Scan(&state, &user)
	}); err != nil {
		p.t.Fatal(err)
	}
	return state, user
}

// quarantinedDuplicate creates a Principal, puts a second kernel user carrying its identifier beside
// it, and lets the sweep quarantine the mapping and disable both users.
func (p *portability) quarantinedDuplicate(username string) (provisioning.Response, keycloak.UserID, keycloak.UserID) {
	p.t.Helper()
	created := p.create(username)
	person := p.user(created.PrincipalID).ID
	copied := p.kernel.Seed(portabilityRealm, username+".copy", created.PrincipalID, keycloak.SubjectHuman)
	if _, err := p.provisioner.Sweep(context.Background()); err != nil {
		p.t.Fatalf("sweep: %v", err)
	}
	if state, _ := p.state(created.PrincipalID); state != "quarantined" {
		p.t.Fatalf("the duplicate left the mapping %s", state)
	}
	return created, person, copied
}

// The duplicate resolved in the kernel, a release binds the mapping to the user left, suspended, with
// that user disabled and its sessions ended, and records who, why and onto which user.
func TestAReleaseLandsInSuspendedOnceOneUserIsLeft(t *testing.T) {
	p := newPortability(t)
	created, person, copied := p.quarantinedDuplicate("released.person")
	p.kernel.SetSecurity(person, keycloakfake.Security{Sessions: []keycloak.Session{{ID: "s-1"}}})

	if _, err := p.release(created.PrincipalID, "released.person"); !errors.Is(err, provisioning.ErrReleaseRefused) {
		t.Errorf("a release with two users left answered %v, want ErrReleaseRefused", err)
	}
	p.kernel.DeleteUser(copied)
	if _, err := p.release(created.PrincipalID, "released.person.copy"); !errors.Is(err, provisioning.ErrReleaseRefused) {
		t.Errorf("a release naming the deleted user answered %v, want ErrReleaseRefused", err)
	}
	if state, _ := p.state(created.PrincipalID); state != "quarantined" {
		t.Fatalf("a refused release left the mapping %s", state)
	}

	result, err := p.release(created.PrincipalID, "Released.Person")
	if err != nil || result.State != "suspended" || result.PrincipalID != created.PrincipalID {
		t.Fatalf("release: %+v, %v", result, err)
	}
	state, user := p.state(created.PrincipalID)
	if state != "suspended" || user != string(person) {
		t.Errorf("the mapping is %s, bound to %q; want suspended, bound to the person", state, user)
	}
	if u, ok := p.kernel.User(person); !ok || u.Enabled {
		t.Errorf("the released user is enabled or gone: %+v", u)
	}
	if sessions, _ := p.kernel.UserSessions(context.Background(), portabilityRealm, person); len(sessions) != 0 {
		t.Errorf("the released user keeps %d session(s)", len(sessions))
	}
	var recorded int
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.principal_release
		    WHERE principal_id = $1 AND keycloak_user_id = $2 AND released_by = $3
		      AND quarantine_reason IS NOT NULL AND reason = 'the console copy was deleted; ticket 41'`,
			created.PrincipalID.String(), string(person), p.operator.String()).Scan(&recorded)
	}); err != nil || recorded != 1 {
		t.Errorf("%d release record(s) (%v), want one", recorded, err)
	}

	// Released once, it is suspended, and a second release is refused.
	if _, err := p.release(created.PrincipalID, "released.person"); !errors.Is(err, provisioning.ErrInvalidTransition) {
		t.Errorf("a second release answered %v, want ErrInvalidTransition", err)
	}
	if listed, err := p.provisioner.Quarantined(context.Background()); err != nil || len(listed) != 0 {
		t.Errorf("the quarantined listing holds %+v (%v)", listed, err)
	}
}

// A kernel that does not confirm the containment rolls the release back.
func TestAReleaseTheKernelDoesNotConfirmChangesNothing(t *testing.T) {
	p := newPortability(t)
	created, _, copied := p.quarantinedDuplicate("unconfirmed.person")
	p.kernel.DeleteUser(copied)
	p.kernel.FailContainment = keycloak.ErrUnavailable
	if _, err := p.release(created.PrincipalID, "unconfirmed.person"); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Fatalf("release answered %v, want the kernel's failure", err)
	}
	if state, user := p.state(created.PrincipalID); state != "quarantined" || user == "" {
		t.Errorf("a failed release left the mapping %s, bound to %q", state, user)
	}
	listed, err := p.provisioner.Quarantined(context.Background())
	if err != nil || len(listed) != 1 || listed[0].PrincipalID != created.PrincipalID || !listed[0].Linked ||
		listed[0].QuarantineReason == "" {
		t.Errorf("the quarantined listing holds %+v (%v)", listed, err)
	}
	p.kernel.FailContainment = nil
	if result, err := p.release(created.PrincipalID, "unconfirmed.person"); err != nil || result.State != "suspended" {
		t.Errorf("the retried release answered %+v, %v", result, err)
	}
}

// Only a quarantined human mapping is released.
func TestOnlyAQuarantinedPersonIsReleased(t *testing.T) {
	p := newPortability(t)
	active := p.create("active.person")
	if _, err := p.release(active.PrincipalID, "active.person"); !errors.Is(err, provisioning.ErrInvalidTransition) {
		t.Errorf("releasing an active mapping answered %v, want ErrInvalidTransition", err)
	}
	unknown, _ := id.NewV7()
	if _, err := p.release(unknown, "nobody"); !errors.Is(err, provisioning.ErrNotFound) {
		t.Errorf("releasing no mapping answered %v, want ErrNotFound", err)
	}
	if _, err := p.provisioner.Release(context.Background(), provisioning.ReleaseRequest{
		PrincipalID: active.PrincipalID, ReleasedBy: p.operator, Reason: " ", Username: "x"}); !errors.Is(err, provisioning.ErrReasonRequired) {
		t.Errorf("a release without a reason answered %v", err)
	}
}

// The pending listing marks a mapping overdue past the recovery threshold.
func TestThePendingListingMarksTheOverdue(t *testing.T) {
	p := newPortability(t)
	fresh, _ := id.NewV7()
	stale, _ := id.NewV7()
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		for _, row := range []struct {
			principal id.UUID
			age       string
		}{{fresh, "1 second"}, {stale, "2 hours"}} {
			if _, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
			    (principal_id, realm, username, subject_type, state, created_at)
			    VALUES ($1, $2, $3, 'human', 'pending', now() - $4::interval)`,
				row.principal.String(), string(portabilityRealm), "pending."+row.age, row.age); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	listed, err := p.provisioner.Pending(context.Background())
	if err != nil || len(listed) != 2 {
		t.Fatalf("pending = %+v (%v)", listed, err)
	}
	if listed[0].PrincipalID != stale || !listed[0].Overdue || listed[1].PrincipalID != fresh || listed[1].Overdue {
		t.Errorf("pending = %+v, want the stale one first and overdue, the fresh one not", listed)
	}
}

// The pending and quarantined gauges are observed when the reader collects, every overdue value
// included (TDD-identity-control-001 1.18.0 §Operational Notes).
func TestTheMappingGaugesAreObserved(t *testing.T) {
	p := newPortability(t)
	p.quarantinedDuplicate("gauged.person")
	reader := sdkmetric.NewManualReader()
	if err := p.provisioner.Instrument(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")); err != nil {
		t.Fatal(err)
	}
	if err := p.provisioner.Instrument(nil); err != nil {
		t.Errorf("a nil meter answered %v", err)
	}
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatal(err)
	}
	got := map[string]metricdata.Gauge[int64]{}
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			if gauge, ok := m.Data.(metricdata.Gauge[int64]); ok {
				got[m.Name] = gauge
			}
		}
	}
	if pending := got["identity.principal.pending"]; len(pending.DataPoints) != 2 {
		t.Errorf("identity.principal.pending observed %d series, want overdue true and false", len(pending.DataPoints))
	}
	held := got["identity.principal.quarantined"]
	if len(held.DataPoints) != 1 || held.DataPoints[0].Value < 1 {
		t.Errorf("identity.principal.quarantined observed %+v, want the quarantined mapping counted", held.DataPoints)
	}
}
