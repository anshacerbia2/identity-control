package provisioning_test

// Re-adopting an orphan's identifier against a real PostgreSQL and a fake kernel (ADR-IAM-001 §5.11
// as amended 2026-10-20, TDD-identity-control-001 1.23.0): the plan's four checks, each refusal, and
// an adoption that lands suspended, contained and recorded insert-only.

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

// creatorAccount is the kernel user this service's Principal credential acts as, in these tests.
const creatorAccount = "service-account-identity-control"

// uuidV7At is a version 7 UUID carrying the given instant (RFC 9562 §5.7), so a test states whether an
// identifier could have been in the backup without racing the clock of other packages' mappings.
func uuidV7At(t *testing.T, at time.Time) id.UUID {
	t.Helper()
	var u id.UUID
	if _, err := rand.Read(u[:]); err != nil {
		t.Fatal(err)
	}
	ms := at.UnixMilli()
	for i := 0; i < 6; i++ {
		u[i] = byte(ms >> (40 - 8*i))
	}
	u[6] = 0x70 | (u[6] & 0x0f)
	u[8] = 0x80 | (u[8] & 0x3f)
	return u
}

// orphan puts a kernel user carrying identifier beside the registry, as a restore to an older point
// leaves a Principal created after the backup, and lets the sweep record it.
func (p *portability) orphan(username string, identifier id.UUID, events *keycloakfake.Events, recorded bool) keycloak.UserID {
	p.t.Helper()
	user := p.kernel.Seed(portabilityRealm, username, identifier, keycloak.SubjectHuman)
	if recorded {
		events.Record(keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, ID: "admin-event-" + username,
			Time: time.Now().UTC(), Type: "CREATE", ResourceType: "USER", ResourcePath: "users/" + string(user),
			UserID: creatorAccount, Representation: `{"username":"` + username +
				`","attributes":{"scnehaux_principal_id":["` + identifier.String() + `"]}}`})
	}
	if _, err := p.provisioner.Sweep(context.Background()); err != nil {
		p.t.Fatalf("sweep: %v", err)
	}
	return user
}

func (p *portability) adopter(events *keycloakfake.Events) {
	p.provisioner.UseCreationJournal(events, func(context.Context) (string, error) { return creatorAccount, nil })
}

func (p *portability) adopt(identifier id.UUID, dryRun bool) (provisioning.AdoptPlan, error) {
	return p.provisioner.Adopt(context.Background(), provisioning.AdoptRequest{PrincipalID: identifier,
		AdoptedBy: p.operator, Reason: "restored to the 02:15 backup; ticket 52", DryRun: dryRun})
}

func check(plan provisioning.AdoptPlan, name string) provisioning.AdoptCheck {
	for _, c := range plan.Checks {
		if c.Check == name {
			return c
		}
	}
	return provisioning.AdoptCheck{}
}

// An orphan created after the backup, by this service, is planned adoptable, then adopted: its
// mapping lands suspended on the one user, the user is disabled and holds no session, the finding is
// resolved adopted, and the adoption is recorded with the evidence of each check.
func TestAnOrphanCreatedAfterTheBackupIsAdoptedToSuspended(t *testing.T) {
	p := newPortability(t)
	events := keycloakfake.NewEvents()
	p.adopter(events)
	p.create("kept.from.backup")
	identifier := uuidV7At(t, time.Now().Add(time.Hour))
	user := p.orphan("created.after.backup", identifier, events, true)
	p.kernel.SetSecurity(user, keycloakfake.Security{Sessions: []keycloak.Session{{ID: "s-1"}}})

	plan, err := p.adopt(identifier, true)
	if err != nil || !plan.Adoptable || len(plan.Checks) != 4 {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	if state, _ := p.state2(identifier); state != "" {
		t.Fatalf("a plan wrote a mapping in %s", state)
	}

	adopted, err := p.adopt(identifier, false)
	if err != nil || !adopted.Adopted || adopted.State != "suspended" {
		t.Fatalf("adopt: %+v, %v", adopted, err)
	}
	state, bound := p.state2(identifier)
	if state != "suspended" || bound != string(user) {
		t.Errorf("the mapping is %s on %s, want suspended on %s", state, bound, user)
	}
	held, err := p.kernel.GetUser(context.Background(), portabilityRealm, user)
	if err != nil || held.Enabled {
		t.Errorf("the adopted user is enabled (%v): an adoption contains it until :restore", err)
	}
	if sessions, _ := p.kernel.UserSessions(context.Background(), portabilityRealm, user); len(sessions) != 0 {
		t.Errorf("the adopted user holds %d sessions", len(sessions))
	}
	var (
		resolution, eventID, by string
		identifierTime          time.Time
	)
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(resolution, '') FROM identity.principal_finding
		    WHERE realm = $1 AND claimed_principal_id = $2`, string(portabilityRealm), identifier.String()).Scan(&resolution); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT creation_event_id, adopted_by::text, identifier_time FROM identity.principal_adoption
		    WHERE principal_id = $1`, identifier.String()).Scan(&eventID, &by, &identifierTime)
	}); err != nil {
		t.Fatal(err)
	}
	if resolution != "adopted" || eventID != "admin-event-created.after.backup" || by != p.operator.String() ||
		!identifierTime.After(time.Now()) {
		t.Errorf("finding %q, adoption event %q by %s at %s", resolution, eventID, by, identifierTime)
	}
	// A second adoption finds a mapping: nothing to adopt.
	if _, err := p.adopt(identifier, false); !errors.Is(err, provisioning.ErrMapped) {
		t.Errorf("a second adoption answered %v, want ErrMapped", err)
	}
}

// Each check refuses on its own: no finding, two users, an identifier older than the newest mapping,
// and a creation the kernel's journal does not show this service making.
func TestAnAdoptionRefusesUnlessEveryCheckHolds(t *testing.T) {
	p := newPortability(t)
	events := keycloakfake.NewEvents()
	p.adopter(events)
	p.create("the.newest.mapping")

	refused := func(identifier id.UUID, failing string) {
		t.Helper()
		plan, err := p.adopt(identifier, false)
		if !errors.Is(err, provisioning.ErrNotAdoptable) || plan.Adoptable || check(plan, failing).Holds {
			t.Errorf("%s: %+v, %v; want refused on %s", failing, plan, err, failing)
		}
		if state, _ := p.state2(identifier); state != "" {
			t.Errorf("%s: a refused adoption wrote a mapping in %s", failing, state)
		}
	}

	// No sweep has recorded it, so no finding names it.
	unswept := uuidV7At(t, time.Now().Add(time.Hour))
	p.kernel.Seed(portabilityRealm, "never.swept", unswept, keycloak.SubjectHuman)
	refused(unswept, provisioning.CheckOrphanFinding)

	// An identifier older than the newest mapping could have been in the backup.
	older := uuidV7At(t, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	p.orphan("older.than.backup", older, events, true)
	refused(older, provisioning.CheckNewerThanBackup)

	// Created by someone else: the console's administrator, not this service.
	console := uuidV7At(t, time.Now().Add(time.Hour))
	consoleUser := p.orphan("made.in.console", console, events, false)
	events.Record(keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, ID: "console-create", Time: time.Now().UTC(),
		Type: "CREATE", ResourceType: "USER", ResourcePath: "users/" + string(consoleUser), UserID: "kc-admin",
		Representation: `{"attributes":{"scnehaux_principal_id":["` + console.String() + `"]}}`})
	refused(console, provisioning.CheckCreationOnRecord)

	// Two users carry it.
	twice := uuidV7At(t, time.Now().Add(time.Hour))
	p.orphan("carried.once", twice, events, true)
	p.kernel.Seed(portabilityRealm, "carried.twice", twice, keycloak.SubjectHuman)
	refused(twice, provisioning.CheckOneKernelUser)

	// A provider never adopts the Principal in its own token, and every adoption names a reason.
	if _, err := p.provisioner.Adopt(context.Background(), provisioning.AdoptRequest{PrincipalID: p.operator,
		AdoptedBy: p.operator, Reason: "mine"}); !errors.Is(err, provisioning.ErrSelfAdopt) {
		t.Errorf("a self adoption answered %v", err)
	}
	if _, err := p.provisioner.Adopt(context.Background(), provisioning.AdoptRequest{PrincipalID: twice,
		AdoptedBy: p.operator}); !errors.Is(err, provisioning.ErrReasonRequired) {
		t.Errorf("an adoption without a reason answered %v", err)
	}
}

// An adoption without the kernel's journal cannot read check 4, and a journal that does not answer is
// an unknown, not a refusal.
func TestAnAdoptionNeedsTheJournal(t *testing.T) {
	p := newPortability(t)
	identifier := uuidV7At(t, time.Now().Add(time.Hour))
	if _, err := p.adopt(identifier, true); !errors.Is(err, provisioning.ErrAdoptionUnavailable) {
		t.Errorf("an adoption with no journal answered %v", err)
	}
	events := keycloakfake.NewEvents()
	p.adopter(events)
	p.orphan("journal.down", identifier, events, true)
	events.Fail = keycloak.ErrUnavailable
	if _, err := p.adopt(identifier, true); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Errorf("a journal that did not answer gave %v, want ErrUnavailable", err)
	}
}

// state2 is a mapping's state and user, or "" when no mapping holds the identifier.
func (p *portability) state2(principalID id.UUID) (string, string) {
	p.t.Helper()
	var state, user string
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT state, coalesce(keycloak_user_id, '') FROM identity.principal_mapping
		    WHERE principal_id = $1`, principalID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			return rows.Scan(&state, &user)
		}
		return rows.Err()
	}); err != nil {
		p.t.Fatal(err)
	}
	return state, user
}
