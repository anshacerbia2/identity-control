package keycloak_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

const clientRepresentation = `{
  "id": "0b1c2d3e",
  "clientId": "identity-control-caller",
  "enabled": true,
  "publicClient": false,
  "redirectUris": ["http://127.0.0.1:8099/callback"],
  "attributes": {"access.token.lifespan": "240", "pkce.code.challenge.method": "S256"}
}`

func TestGetClientReadsWhatTheReconcilerCompares(t *testing.T) {
	k := &kernel{adminBody: clientRepresentation}
	admin, _ := newAdmin(t, k)

	client, err := admin.GetClient(context.Background(), testRealm, "0b1c2d3e")
	if err != nil {
		t.Fatal(err)
	}
	if client.ID != "0b1c2d3e" || client.ClientID != "identity-control-caller" || !client.Enabled ||
		client.AccessTokenLifespan != 240 || len(client.RedirectURIs) != 1 {
		t.Errorf("client = %+v", client)
	}
	if k.lastPath != "/admin/realms/scnehaux/clients/0b1c2d3e" {
		t.Errorf("read %s", k.lastPath)
	}
}

func TestAClientWithoutALifespanOverrideReadsAsZero(t *testing.T) {
	admin, _ := newAdmin(t, &kernel{adminBody: `{"id":"x","clientId":"c","enabled":true,"attributes":{}}`})
	client, err := admin.GetClient(context.Background(), testRealm, "x")
	if err != nil || client.AccessTokenLifespan != 0 {
		t.Errorf("client = %+v, err = %v; want no override", client, err)
	}
}

func TestAnUnreadableLifespanIsAnError(t *testing.T) {
	admin, _ := newAdmin(t, &kernel{adminBody: `{"id":"x","clientId":"c","attributes":{"access.token.lifespan":"soon"}}`})
	if _, err := admin.GetClient(context.Background(), testRealm, "x"); err == nil {
		t.Error("an unreadable lifespan was read as a number")
	}
}

func TestAnAbsentClientIsNotFound(t *testing.T) {
	admin, _ := newAdmin(t, &kernel{adminStatus: http.StatusNotFound})
	if _, err := admin.GetClient(context.Background(), testRealm, "gone"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("an absent client answered %v, want ErrNotFound", err)
	}
	if _, err := admin.GetClient(context.Background(), testRealm, ""); err == nil {
		t.Error("an empty client identifier was sent")
	}
}

// A repair writes the whole representation back. The fields it does not patch, the PKCE method
// among them, must survive it.
func TestPatchClientKeepsWhatItDoesNotPatch(t *testing.T) {
	k := &kernel{adminBody: clientRepresentation}
	admin, _ := newAdmin(t, k)

	lifespan, enabled := 600, false
	uris := []string{"https://app.example.com/callback"}
	if err := admin.PatchClient(context.Background(), testRealm, "0b1c2d3e", keycloak.ClientPatch{
		AccessTokenLifespan: &lifespan, Enabled: &enabled, RedirectURIs: &uris}); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodPut {
		t.Fatalf("the last call was %s, want the PUT", k.lastMethod)
	}
	var written map[string]any
	if err := json.Unmarshal(k.lastBody, &written); err != nil {
		t.Fatal(err)
	}
	attributes := written["attributes"].(map[string]any)
	if attributes["access.token.lifespan"] != "600" || attributes["pkce.code.challenge.method"] != "S256" {
		t.Errorf("attributes written = %v, want the lifespan changed and PKCE kept", attributes)
	}
	if written["enabled"] != false || written["publicClient"] != false || written["clientId"] != "identity-control-caller" {
		t.Errorf("representation written = %v", written)
	}
	if got := written["redirectUris"].([]any); len(got) != 1 || got[0] != uris[0] {
		t.Errorf("redirect URIs written = %v", got)
	}
}

func TestPatchClientSendsNothingForAnEmptyIdentifier(t *testing.T) {
	k := &kernel{}
	admin, _ := newAdmin(t, k)
	if err := admin.PatchClient(context.Background(), testRealm, "", keycloak.ClientPatch{}); err == nil {
		t.Error("a patch without a client identifier was accepted")
	}
	if k.adminCalls.Load() != 0 {
		t.Error("a patch without a client identifier reached the kernel")
	}
}

func adminEventsJSON(times ...time.Time) string {
	var events []string
	for i, at := range times {
		events = append(events, fmt.Sprintf(`{"time":%d,"operationType":"UPDATE","resourceType":"CLIENT",`+
			`"resourcePath":"clients/c%d","authDetails":{"userId":"u%d"}}`, at.UnixMilli(), i, i))
	}
	return "[" + strings.Join(events, ",") + "]"
}

// Keycloak filters by date, so the read asks from the day before and keeps only what falls at or
// after the instant.
func TestClientAdminEventsStopAtTheInstantAsked(t *testing.T) {
	since := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	k := &kernel{adminBody: adminEventsJSON(since.Add(2*time.Minute), since.Add(time.Minute), since.Add(-time.Minute))}
	admin, _ := newAdmin(t, k)

	events, err := admin.ClientAdminEvents(context.Background(), testRealm, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ClientID() != "c0" || events[0].UserID != "u0" || !events[0].Time.After(events[1].Time) {
		t.Errorf("events = %+v, want the two at or after the instant, newest first", events)
	}
	query, _ := url.ParseQuery(k.lastQuery)
	if query.Get("resourceTypes") != "CLIENT" || query.Get("dateFrom") != "2026-09-27" {
		t.Errorf("query = %v, want client events from the day before", query)
	}
}

func TestClientAdminEventsReadEveryPage(t *testing.T) {
	now := time.Now().UTC()
	k := &kernel{adminBodyFor: func(query url.Values) string {
		first, _ := strconv.Atoi(query.Get("first"))
		if first >= 200 {
			return adminEventsJSON(now)
		}
		times := make([]time.Time, 100)
		for i := range times {
			times[i] = now
		}
		return adminEventsJSON(times...)
	}}
	admin, _ := newAdmin(t, k)
	events, err := admin.ClientAdminEvents(context.Background(), testRealm, now.Add(-time.Hour))
	if err != nil || len(events) != 201 {
		t.Errorf("read %d events (%v), want all three pages", len(events), err)
	}
}

// More events than one sweep reads is not attribution from part of the record.
func TestTooManyAdminEventsIsAnError(t *testing.T) {
	now := time.Now().UTC()
	k := &kernel{adminBodyFor: func(url.Values) string {
		times := make([]time.Time, 100)
		for i := range times {
			times[i] = now
		}
		return adminEventsJSON(times...)
	}}
	admin, _ := newAdmin(t, k)
	if _, err := admin.ClientAdminEvents(context.Background(), testRealm, now.Add(-time.Hour)); !errors.Is(err, keycloak.ErrTooManyEvents) {
		t.Errorf("an unbounded event read answered %v, want ErrTooManyEvents", err)
	}
}

func TestAdminEventsTheCredentialCannotReadAreForbidden(t *testing.T) {
	admin, _ := newAdmin(t, &kernel{adminStatus: http.StatusForbidden})
	if _, err := admin.ClientAdminEvents(context.Background(), testRealm, time.Now()); !errors.Is(err, keycloak.ErrForbidden) {
		t.Errorf("a refused event read answered %v, want ErrForbidden", err)
	}
}

func TestAnEventOnSomethingElseNamesNoClient(t *testing.T) {
	for path, want := range map[string]keycloak.ClientUUID{
		"clients/abc":                  "abc",
		"clients/abc/protocol-mappers": "abc",
		"users/abc":                    "",
	} {
		if got := (keycloak.AdminEvent{ResourcePath: path}).ClientID(); got != want {
			t.Errorf("%s names client %q, want %q", path, got, want)
		}
	}
}

func jwtWith(claims string) string {
	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return encode(`{"alg":"none"}`) + "." + encode(claims) + ".signature"
}

func TestServiceAccountUserIDIsTheTokensSubject(t *testing.T) {
	k := &kernel{tokenBody: fmt.Sprintf(`{"access_token":%q,"expires_in":300}`, jwtWith(`{"sub":"sa-user-1"}`))}
	admin, _ := newAdmin(t, k)
	subject, err := admin.ServiceAccountUserID(context.Background())
	if err != nil || subject != "sa-user-1" {
		t.Errorf("subject = %q, %v", subject, err)
	}
}

func TestATokenThatIsNotAJWTNamesNoServiceAccount(t *testing.T) {
	for _, token := range []string{"opaque", jwtWith(`{}`), "a.!!!.c"} {
		k := &kernel{tokenBody: fmt.Sprintf(`{"access_token":%q,"expires_in":300}`, token)}
		admin, _ := newAdmin(t, k)
		if _, err := admin.ServiceAccountUserID(context.Background()); err == nil {
			t.Errorf("token %q named a service account", token)
		}
	}
}

func TestCreateClientSendsAPublicClientAsTheProfileRequires(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated, adminLocation: "http://kc/admin/realms/scnehaux/clients/new-uuid"}
	admin, _ := newAdmin(t, k)
	client, err := admin.CreateClient(context.Background(), testRealm, keycloak.ClientSpec{ClientID: "web", Public: true,
		RedirectURIs: []string{"https://app.example.com/cb"}, AccessTokenLifespan: 540, Audience: []string{"orders"}})
	if err != nil || client != "new-uuid" {
		t.Fatalf("CreateClient = %q, %v", client, err)
	}
	var sent map[string]any
	if err := json.Unmarshal(k.lastBody, &sent); err != nil {
		t.Fatal(err)
	}
	attributes := sent["attributes"].(map[string]any)
	if sent["publicClient"] != true || sent["directAccessGrantsEnabled"] != false || sent["implicitFlowEnabled"] != false ||
		attributes["pkce.code.challenge.method"] != "S256" || attributes["use.refresh.tokens"] != "false" ||
		attributes["access.token.lifespan"] != "540" || attributes["access.token.signed.response.alg"] != "PS256" {
		t.Errorf("sent %v", sent)
	}
	mappers := sent["protocolMappers"].([]any)
	config := mappers[0].(map[string]any)["config"].(map[string]any)
	if len(mappers) != 1 || config["included.client.audience"] != "orders" {
		t.Errorf("audience mappers = %v", mappers)
	}
}

func TestCreateClientSendsAResourceThatNobodyLogsInThrough(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated, adminLocation: "http://kc/admin/realms/scnehaux/clients/res"}
	admin, _ := newAdmin(t, k)
	if _, err := admin.CreateClient(context.Background(), testRealm, keycloak.ClientSpec{ClientID: "orders", Resource: true}); err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	_ = json.Unmarshal(k.lastBody, &sent)
	if sent["bearerOnly"] != true || sent["standardFlowEnabled"] != false || sent["redirectUris"] != nil {
		t.Errorf("sent %v", sent)
	}
}

func TestCreateClientRefusesAnIncoherentSpec(t *testing.T) {
	k := &kernel{}
	admin, _ := newAdmin(t, k)
	for name, spec := range map[string]keycloak.ClientSpec{
		"no clientId":                 {Public: true, RedirectURIs: []string{"https://a"}, AccessTokenLifespan: 1},
		"neither public nor resource": {ClientID: "x"},
		"both":                        {ClientID: "x", Public: true, Resource: true},
		"public without redirects":    {ClientID: "x", Public: true, AccessTokenLifespan: 1},
		"a resource with an audience": {ClientID: "x", Resource: true, Audience: []string{"y"}},
	} {
		if _, err := admin.CreateClient(context.Background(), testRealm, spec); err == nil {
			t.Errorf("%s was sent", name)
		}
	}
	if k.adminCalls.Load() != 0 {
		t.Error("an incoherent spec reached the kernel")
	}
}

func TestACreateWithoutALocationIsAmbiguous(t *testing.T) {
	admin, _ := newAdmin(t, &kernel{adminStatus: http.StatusCreated})
	_, err := admin.CreateClient(context.Background(), testRealm, keycloak.ClientSpec{ClientID: "orders", Resource: true})
	if !errors.Is(err, keycloak.ErrAmbiguous) {
		t.Errorf("a 201 without a Location answered %v, want ErrAmbiguous", err)
	}
	conflict, _ := newAdmin(t, &kernel{adminStatus: http.StatusConflict})
	if _, err := conflict.CreateClient(context.Background(), testRealm, keycloak.ClientSpec{ClientID: "orders", Resource: true}); !errors.Is(err, keycloak.ErrConflict) {
		t.Errorf("a 409 answered %v", err)
	}
}

func TestFindClientsIsExact(t *testing.T) {
	k := &kernel{adminBody: `[{"id":"a","clientId":"web"},{"id":"b","clientId":"web-2"}]`}
	admin, _ := newAdmin(t, k)
	found, err := admin.FindClients(context.Background(), testRealm, "web")
	if err != nil || len(found) != 1 || found[0].ID != "a" {
		t.Errorf("found %+v, %v", found, err)
	}
	query, _ := url.ParseQuery(k.lastQuery)
	if query.Get("clientId") != "web" || query.Get("search") != "false" {
		t.Errorf("query = %v", query)
	}
	if _, err := admin.FindClients(context.Background(), testRealm, " "); err == nil {
		t.Error("an empty clientId was searched")
	}
}

func TestClientScopeIDFindsTheNamedScope(t *testing.T) {
	admin, _ := newAdmin(t, &kernel{adminBody: `[{"id":"s1","name":"scnehaux-internal"},{"id":"s2","name":"profile"}]`})
	if scope, err := admin.ClientScopeID(context.Background(), testRealm, "scnehaux-internal"); err != nil || scope != "s1" {
		t.Errorf("scope = %q, %v", scope, err)
	}
	if _, err := admin.ClientScopeID(context.Background(), testRealm, "scnehaux-workload"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("an undeclared scope answered %v", err)
	}
}

func TestAddDefaultClientScopeAttachesByIdentifier(t *testing.T) {
	k := &kernel{adminStatus: http.StatusNoContent}
	admin, _ := newAdmin(t, k)
	if err := admin.AddDefaultClientScope(context.Background(), testRealm, "c1", "s1"); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodPut || k.lastPath != "/admin/realms/scnehaux/clients/c1/default-client-scopes/s1" {
		t.Errorf("%s %s", k.lastMethod, k.lastPath)
	}
	if err := admin.AddDefaultClientScope(context.Background(), testRealm, "", "s1"); err == nil {
		t.Error("an attachment without a client was sent")
	}
}
