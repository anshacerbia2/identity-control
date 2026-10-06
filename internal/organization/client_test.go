package organization_test

// The client of Organization Control's consumer routes, against a stand-in that holds their
// contract (TDD-organization-control-002 §Bootstrap Contract, TDD-identity-control-006).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/organization"
	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

type tokens struct {
	mu          sync.Mutex
	invalidated int
}

func (t *tokens) Token(context.Context) (string, error) { return "workload-token", nil }

func (t *tokens) Invalidate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.invalidated++
}

// request is what the stand-in received.
type request struct {
	method, path, authorization string
	body                        map[string]any
}

type standIn struct {
	mu       sync.Mutex
	received []request
	answer   func(w http.ResponseWriter, r request)
}

func (s *standIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	got := request{method: r.Method, path: r.URL.Path, authorization: r.Header.Get("Authorization")}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &got.body)
	}
	s.mu.Lock()
	s.received = append(s.received, got)
	s.mu.Unlock()
	s.answer(w, got)
}

func client(t *testing.T, answer func(w http.ResponseWriter, r request)) (*organization.Client, *standIn, *tokens) {
	t.Helper()
	s := &standIn{answer: answer}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	tk := &tokens{}
	c, err := organization.New(organization.Config{BaseURL: server.URL + "/", Consumer: providerauthority.Consumer, Tokens: tk})
	if err != nil {
		t.Fatal(err)
	}
	return c, s, tk
}

func grant(t *testing.T) providerauthority.Grant {
	t.Helper()
	g, p := mustID(t), mustID(t)
	return providerauthority.Grant{GrantID: g, PrincipalID: p, Scope: providerauthority.Scope, Kind: "eligible",
		GrantStatus: "active", GrantVersion: 1}
}

func mustID(t *testing.T) id.UUID {
	t.Helper()
	v, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func respond(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	for _, cfg := range []organization.Config{
		{BaseURL: "organization.example", Consumer: "c", Tokens: &tokens{}},
		{BaseURL: "https://organization.example", Tokens: &tokens{}},
		{BaseURL: "https://organization.example", Consumer: "c"},
	} {
		if _, err := organization.New(cfg); err == nil {
			t.Errorf("%+v was accepted", cfg)
		}
	}
}

func TestNewWorkloadRefusesAMissingKey(t *testing.T) {
	_, err := organization.NewWorkload(organization.Workload{
		BaseURL: "https://organization.example", ClientID: "identity-control-workload",
		KeyFile: t.TempDir() + "/absent.pem", TokenURL: "https://kernel.example/token", Audience: "https://kernel.example",
	})
	if err == nil {
		t.Fatal("a workload with no key file was built")
	}
}

// Every page after the first is read under the first page's mark, and the grants are joined.
func TestTheSnapshotIsReadPageByPageUnderOneMark(t *testing.T) {
	first, second := grant(t), grant(t)
	c, s, _ := client(t, func(w http.ResponseWriter, r request) {
		if r.body["cursor"] == nil {
			respond(w, map[string]any{"high_water_mark": 0, "grants": []providerauthority.Grant{first}, "cursor": "next"})
			return
		}
		respond(w, map[string]any{"high_water_mark": 99, "grants": []providerauthority.Grant{second}})
	})

	snapshot, err := c.ProviderSnapshot(context.Background())
	if err != nil {
		t.Fatalf("ProviderSnapshot: %v", err)
	}
	if snapshot.Mark != 0 {
		t.Errorf("the mark is %d; want the first page's, 0", snapshot.Mark)
	}
	if len(snapshot.Grants) != 2 || snapshot.Grants[0].GrantID != first.GrantID || snapshot.Grants[1].GrantID != second.GrantID {
		t.Errorf("the grants are %+v", snapshot.Grants)
	}

	if len(s.received) != 2 {
		t.Fatalf("%d requests; want 2", len(s.received))
	}
	for i, r := range s.received {
		if r.method != http.MethodPost || r.path != "/v1/projections/provider-authority/snapshot" {
			t.Errorf("request %d is %s %s", i, r.method, r.path)
		}
		if r.authorization != "Bearer workload-token" {
			t.Errorf("request %d carries %q", i, r.authorization)
		}
		if r.body["consumer_id"] != providerauthority.Consumer {
			t.Errorf("request %d names consumer %v", i, r.body["consumer_id"])
		}
	}
	if _, ok := s.received[0].body["mark"]; ok {
		t.Error("the first page named a mark")
	}
	// A mark of zero is sent, not omitted: an omitted one asks for a fresh snapshot.
	if mark, ok := s.received[1].body["mark"]; !ok || mark != float64(0) || s.received[1].body["cursor"] != "next" {
		t.Errorf("the second page asked with %v", s.received[1].body)
	}
}

func TestTheMarkAndProgressAreReportedAsThisConsumer(t *testing.T) {
	c, s, _ := client(t, func(w http.ResponseWriter, r request) { respond(w, map[string]any{}) })
	ctx := context.Background()
	if err := c.RecordBootstrap(ctx, 12); err != nil {
		t.Fatalf("RecordBootstrap: %v", err)
	}
	if err := c.ReportProgress(ctx, 30); err != nil {
		t.Fatalf("ReportProgress: %v", err)
	}
	want := []struct {
		path, field string
		value       float64
	}{
		{"/v1/projections/consumers/identity-control/bootstrap", "mark", 12},
		{"/v1/projections/consumers/identity-control/progress", "applied_mark", 30},
	}
	for i, w := range want {
		r := s.received[i]
		if r.method != http.MethodPost || r.path != w.path || r.body[w.field] != w.value {
			t.Errorf("request %d is %s %s %v; want POST %s {%s: %v}", i, r.method, r.path, r.body, w.path, w.field, w.value)
		}
	}
}

func TestTheFrontierIsReadAsAnObservation(t *testing.T) {
	c, s, _ := client(t, func(w http.ResponseWriter, r request) {
		respond(w, map[string]any{
			"highest_committed_mark": 40, "oldest_unpublished_mark": 38,
			"oldest_unpublished_age_seconds": 2.5, "unpublished": true,
			"security_dead_lettered": 1, "security_debt": true,
			"observed_at": time.Now().UTC().Format(time.RFC3339Nano),
		})
	})
	got, err := c.Frontier(context.Background())
	if err != nil {
		t.Fatalf("Frontier: %v", err)
	}
	want := providerauthority.Observation{Owed: true, OldestOwedAge: 2500 * time.Millisecond, SecurityDebt: true}
	if got != want {
		t.Errorf("Frontier() = %+v; want %+v", got, want)
	}
	if r := s.received[0]; r.method != http.MethodGet || r.path != "/v1/projections/frontier" {
		t.Errorf("the frontier was read with %s %s", r.method, r.path)
	}
}

// A 401 drops the cached token so the next call presents a fresh one; any non-2xx is an error.
func TestARefusalIsAnErrorAndA401DropsTheToken(t *testing.T) {
	status := http.StatusUnauthorized
	c, _, tk := client(t, func(w http.ResponseWriter, r request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"title":"refused"}`))
	})
	ctx := context.Background()
	if _, err := c.Frontier(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a 401 read as %v", err)
	}
	if tk.invalidated != 1 {
		t.Errorf("a 401 invalidated the token %d times; want 1", tk.invalidated)
	}

	status = http.StatusForbidden
	if _, err := c.ProviderSnapshot(ctx); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a 403 read as %v", err)
	}
	if tk.invalidated != 1 {
		t.Error("a 403 invalidated the token; only a 401 says the token is the problem")
	}
}

// A cursor that never ends is the producer's defect, and the read stops.
func TestASnapshotThatNeverEndsIsRefused(t *testing.T) {
	c, _, _ := client(t, func(w http.ResponseWriter, r request) {
		respond(w, map[string]any{"high_water_mark": 1, "grants": []providerauthority.Grant{}, "cursor": "again"})
	})
	if _, err := c.ProviderSnapshot(context.Background()); err == nil {
		t.Fatal("an endless snapshot was accepted")
	}
}

// The Organization snapshot is read the same way: every page under the first page's mark, the rows
// joined, each carrying its Tenant's version.
func TestTheOrganizationSnapshotIsReadUnderOneMark(t *testing.T) {
	c, s, _ := client(t, func(w http.ResponseWriter, r request) {
		row := map[string]any{"membership_id": "019235f4-0000-7000-8000-000000000001",
			"principal_id": "019235f1-0000-7000-8000-000000000001", "tenant_id": "019235f2-0000-7000-8000-000000000001",
			"membership_status": "active", "membership_version": 3, "tenant_status": "suspended", "tenant_version": 7,
			"tenant_security_version": 2}
		if r.body["cursor"] == nil {
			respond(w, map[string]any{"high_water_mark": 41, "rows": []any{row}, "cursor": "next"})
			return
		}
		respond(w, map[string]any{"high_water_mark": 99, "rows": []any{row}})
	})
	mark, rows, err := c.OrganizationSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mark != 41 || len(rows) != 2 || rows[0].TenantVersion != 7 || rows[0].TenantStatus != "suspended" {
		t.Errorf("mark %d, rows %+v", mark, rows)
	}
	if len(s.received) != 2 || s.received[1].body["mark"] != float64(41) {
		t.Errorf("the second page was not read under the first page's mark: %+v", s.received)
	}
	// Organization Control's route, POST /v1/projections/snapshot. The design documents once named
	// /v1/projections/organization/snapshot, which it never served.
	for i, r := range s.received {
		if r.method != http.MethodPost || r.path != "/v1/projections/snapshot" {
			t.Errorf("request %d is %s %s, want POST /v1/projections/snapshot", i, r.method, r.path)
		}
	}
}

// A 403 is ErrRefused, which the bootstrap reads as a registration that does not subscribe yet.
func TestARefusalIsTold(t *testing.T) {
	c, _, _ := client(t, func(w http.ResponseWriter, r request) {
		w.WriteHeader(http.StatusForbidden)
	})
	if _, _, err := c.OrganizationSnapshot(context.Background()); !errors.Is(err, organization.ErrRefused) {
		t.Errorf("a 403: %v, want ErrRefused", err)
	}
}
