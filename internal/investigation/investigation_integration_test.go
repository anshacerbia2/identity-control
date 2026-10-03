package investigation

// The investigation reads against a real PostgreSQL and the fake kernel. Each test owns the rows of
// its own realm and asserts the evidence of its own actor, whose identifier is fresh per test: the
// evidence is insert-only and is never cleaned up.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
	"github.com/anshacerbia2/identity-control/internal/securityref"
)

const testRealm = keycloak.Realm("investigation-test")

type harness struct {
	t       *testing.T
	pool    *db.Pool
	kernel  *keycloakfake.Client
	refs    *securityref.Codec
	service *Service
	actor   Actor
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
	pool, err := db.Open(ctx, db.Config{Name: "investigation-test", DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, statement := range []string{
			`DELETE FROM identity.principal_finding WHERE principal_id IN
			   (SELECT principal_id FROM identity.principal_mapping WHERE realm = $1)`,
			`DELETE FROM identity.principal_mapping WHERE realm = $1`,
		} {
			if _, err := tx.Exec(ctx, statement, string(testRealm)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("empty this realm's Principals: %v", err)
	}
	refs, err := securityref.New([]securityref.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	kernel := keycloakfake.New()
	service, err := New(pool, kernel, refs, Config{Realm: testRealm, CallTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	actor, _ := id.NewV7()
	return &harness{t: t, pool: pool, kernel: kernel, refs: refs, service: service,
		actor: Actor{Principal: actor, Route: "GET /v1/principals/{principal_id}", Correlation: "corr-1"}}
}

// principal records an active human Principal and its kernel user, or a pending one with none.
func (h *harness) principal(username, email string, linked bool) (id.UUID, keycloak.UserID) {
	h.t.Helper()
	principalID, _ := id.NewV7()
	var (
		user  keycloak.UserID
		state = "pending"
		kcArg any
	)
	if linked {
		user = h.kernel.Seed(testRealm, username, principalID, keycloak.SubjectHuman)
		state, kcArg = "active", string(user)
	}
	var emailArg any
	if email != "" {
		emailArg = email
	}
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.principal_mapping
		    (principal_id, realm, username, email, subject_type, keycloak_user_id, state)
		    VALUES ($1, $2, $3, $4, 'human', $5, $6)`,
			principalID.String(), string(testRealm), username, emailArg, kcArg, state)
		return err
	}); err != nil {
		h.t.Fatalf("record %s: %v", username, err)
	}
	return principalID, user
}

type evidence struct {
	subject, action, route, correlation string
	query                               *string
	count                               *int
	emergency                           bool
}

// evidence reads what this test's actor left, oldest first.
func (h *harness) evidence() []evidence {
	h.t.Helper()
	var out []evidence
	if err := h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT coalesce(subject_principal_id::text, ''), action, route, correlation_id,
		    query, result_count, emergency, outcome
		  FROM identity.privileged_access WHERE actor_principal_id = $1 ORDER BY recorded_at, access_id`,
			h.actor.Principal.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				e       evidence
				outcome string
			)
			if err := rows.Scan(&e.subject, &e.action, &e.route, &e.correlation, &e.query, &e.count, &e.emergency, &outcome); err != nil {
				return err
			}
			if outcome != "served" {
				h.t.Errorf("a read was recorded %q, not served", outcome)
			}
			out = append(out, e)
		}
		return rows.Err()
	}); err != nil {
		h.t.Fatalf("read the evidence: %v", err)
	}
	return out
}

func TestASearchFindsByPrefixAndIsRecordedWithItsQuery(t *testing.T) {
	h := newHarness(t)
	alice, _ := h.principal("alice.tan", "alice@example.com", true)
	h.principal("bob", "alicia@example.com", true)
	h.principal("carol", "", false)

	results, err := h.service.Search(context.Background(), h.actor, "  ALICE ")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].PrincipalID != alice {
		t.Fatalf("results %+v; want alice alone", results)
	}
	byEmail, err := h.service.Search(context.Background(), h.actor, "alici")
	if err != nil || len(byEmail) != 1 || byEmail[0].Username != "bob" {
		t.Fatalf("by email: %+v, %v", byEmail, err)
	}

	records := h.evidence()
	if len(records) != 2 || records[0].action != "search" || records[0].subject != "" ||
		records[0].query == nil || *records[0].query != "ALICE" || *records[0].count != 1 {
		t.Fatalf("evidence %+v", records)
	}
}

// A search is a lookup, never a listing: a wildcard is literal, and one too short is refused before
// anything is read or recorded.
func TestASearchIsNeverAListing(t *testing.T) {
	h := newHarness(t)
	h.principal("alice", "", true)
	h.principal("a_b_c", "", true)

	for _, query := range []string{"", "al", "%%%", "***", "_ _"} {
		if _, err := h.service.Search(context.Background(), h.actor, query); !errors.Is(err, ErrQuery) {
			t.Errorf("%q: %v, want ErrQuery", query, err)
		}
	}
	results, err := h.service.Search(context.Background(), h.actor, "a_b")
	if err != nil || len(results) != 1 || results[0].Username != "a_b_c" {
		t.Errorf("an underscore matched as a wildcard: %+v, %v", results, err)
	}
	if records := h.evidence(); len(records) != 1 {
		t.Errorf("%d records; a refused search records nothing", len(records))
	}
}

func TestAPrincipalAndItsKernelStateAreReadAndEachReadIsRecorded(t *testing.T) {
	h := newHarness(t)
	alice, user := h.principal("alice", "alice@example.com", true)
	started := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	h.kernel.SetSecurity(user, keycloakfake.Security{
		Sessions:    []keycloak.Session{{ID: "kc-session-1", Started: started, LastAccess: started.Add(time.Hour), Clients: []string{"identity-experience"}}},
		Credentials: []keycloak.Credential{{ID: "kc-credential-1", Type: "password", Created: started}},
		Links:       []keycloak.FederatedIdentity{{Provider: "google", UserName: "alice@example.com"}},
	})
	h.actor.Emergency = true
	ctx := context.Background()

	principal, err := h.service.Principal(ctx, h.actor, alice)
	if err != nil || principal.Username != "alice" || principal.State != "active" || principal.Realm != string(testRealm) {
		t.Fatalf("Principal: %+v, %v", principal, err)
	}
	sessions, err := h.service.Sessions(ctx, h.actor, alice)
	if err != nil || len(sessions) != 1 || !sessions[0].Started.Equal(started) {
		t.Fatalf("Sessions: %+v, %v", sessions, err)
	}
	authenticators, err := h.service.Authenticators(ctx, h.actor, alice)
	if err != nil || len(authenticators) != 1 || authenticators[0].Type != "password" {
		t.Fatalf("Authenticators: %+v, %v", authenticators, err)
	}
	if strings.Contains(authenticators[0].SecurityRef, "kc-credential-1") {
		t.Error("the kernel identifier is visible in the reference")
	}
	ref, err := h.refs.Open(authenticators[0].SecurityRef, securityref.KindCredential, alice, PurposeRevoke)
	if err != nil || ref.KernelID != "kc-credential-1" {
		t.Errorf("the reference does not open for its revocation: %+v, %v", ref, err)
	}
	links, err := h.service.FederationLinks(ctx, h.actor, alice)
	if err != nil || len(links) != 1 || links[0].Provider != "google" {
		t.Fatalf("FederationLinks: %+v, %v", links, err)
	}
	findings, err := h.service.Findings(ctx, h.actor, alice)
	if err != nil || len(findings) != 0 {
		t.Fatalf("Findings: %+v, %v", findings, err)
	}

	records := h.evidence()
	want := []string{"read.principal", "read.sessions", "read.authenticators", "read.federation-links", "read.findings"}
	if len(records) != len(want) {
		t.Fatalf("%d records; want %d", len(records), len(want))
	}
	for i, r := range records {
		if r.action != want[i] || r.subject != alice.String() || !r.emergency || r.correlation != "corr-1" ||
			r.route != h.actor.Route || r.query != nil {
			t.Errorf("record %d: %+v; want %s about %s, emergency", i, r, want[i], alice)
		}
	}
}

func TestAReadThatFailsIsNotRecorded(t *testing.T) {
	h := newHarness(t)
	pending, _ := h.principal("pending", "", false)
	linked, _ := h.principal("linked", "", true)
	missing, _ := id.NewV7()
	ctx := context.Background()

	if _, err := h.service.Principal(ctx, h.actor, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("an absent Principal: %v", err)
	}
	if _, err := h.service.Sessions(ctx, h.actor, pending); !errors.Is(err, ErrUnlinked) {
		t.Errorf("a pending Principal: %v", err)
	}
	h.kernel.FailSecurity = keycloak.ErrUnavailable
	if _, err := h.service.Authenticators(ctx, h.actor, linked); !errors.Is(err, keycloak.ErrUnavailable) {
		t.Errorf("the kernel failing: %v", err)
	}
	if records := h.evidence(); len(records) != 0 {
		t.Errorf("%d records of reads that were not served", len(records))
	}
}
