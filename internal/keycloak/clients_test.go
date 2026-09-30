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

// A suspension writes the client's not-before, the Unix second before which the kernel refuses its
// refresh tokens, and reads it back as the reconciler compares it.
func TestPatchClientWritesTheNotBefore(t *testing.T) {
	k := &kernel{adminBody: clientRepresentation}
	admin, _ := newAdmin(t, k)
	notBefore, enabled := int64(1790800001), false
	if err := admin.PatchClient(context.Background(), testRealm, "0b1c2d3e", keycloak.ClientPatch{
		NotBefore: &notBefore, Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	var written map[string]any
	if err := json.Unmarshal(k.lastBody, &written); err != nil {
		t.Fatal(err)
	}
	if written["notBefore"] != float64(1790800001) || written["enabled"] != false || written["clientId"] != "identity-control-caller" {
		t.Errorf("representation written = %v", written)
	}

	read, _ := newAdmin(t, &kernel{adminBody: `{"id":"0b1c2d3e","clientId":"c","enabled":false,"notBefore":1790800001}`})
	client, err := read.GetClient(context.Background(), testRealm, "0b1c2d3e")
	if err != nil || client.NotBefore != 1790800001 {
		t.Errorf("read the not-before as %d, %v", client.NotBefore, err)
	}
}

// A retirement deletes the client by its identifier; a client already gone is not found.
func TestDeleteClientDeletesByIdentifier(t *testing.T) {
	k := &kernel{adminStatus: http.StatusNoContent}
	admin, _ := newAdmin(t, k)
	if err := admin.DeleteClient(context.Background(), testRealm, "0b1c2d3e"); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodDelete || !strings.HasSuffix(k.lastPath, "/clients/0b1c2d3e") {
		t.Errorf("sent %s %s", k.lastMethod, k.lastPath)
	}
	gone, _ := newAdmin(t, &kernel{adminStatus: http.StatusNotFound})
	if err := gone.DeleteClient(context.Background(), testRealm, "0b1c2d3e"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("deleting an absent client answered %v, want ErrNotFound", err)
	}
	if err := admin.DeleteClient(context.Background(), testRealm, ""); err == nil {
		t.Error("an empty client identifier was sent")
	}
}

// Replacing a client's keys writes its JWKS and the attributes that make the keys its only
// credential, and keeps everything else the representation carried.
func TestPatchClientReplacesTheKeysAndNothingElse(t *testing.T) {
	k := &kernel{adminBody: clientRepresentation}
	admin, _ := newAdmin(t, k)

	keys := []keycloak.JWK{{KID: "new", N: "bmV3", E: "AQAB"}, {KID: "old", N: "b2xk", E: "AQAB"}}
	if err := admin.PatchClient(context.Background(), testRealm, "0b1c2d3e", keycloak.ClientPatch{Keys: &keys}); err != nil {
		t.Fatal(err)
	}
	var written map[string]any
	if err := json.Unmarshal(k.lastBody, &written); err != nil {
		t.Fatal(err)
	}
	attributes := written["attributes"].(map[string]any)
	if written["clientAuthenticatorType"] != "client-jwt" || attributes["use.jwks.string"] != "true" ||
		attributes["use.jwks.url"] != "false" || attributes["token.endpoint.auth.signing.alg"] != "PS256" ||
		attributes["pkce.code.challenge.method"] != "S256" || attributes["access.token.lifespan"] != "240" {
		t.Errorf("representation written = %v", written)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(attributes["jwks.string"].(string)), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 || jwks.Keys[0]["kid"] != "new" || jwks.Keys[0]["alg"] != "PS256" ||
		jwks.Keys[0]["kty"] != "RSA" || jwks.Keys[0]["use"] != "sig" || jwks.Keys[1]["kid"] != "old" {
		t.Errorf("jwks written = %v", jwks.Keys)
	}
	for _, key := range jwks.Keys {
		if _, private := key["d"]; private || len(key) != 6 {
			t.Errorf("a written key carries more than its public members: %v", key)
		}
	}

	// No keys at all is a client that authenticates as nothing: revoking the last key.
	none := []keycloak.JWK{}
	if err := admin.PatchClient(context.Background(), testRealm, "0b1c2d3e", keycloak.ClientPatch{Keys: &none}); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(k.lastBody, &written)
	if got := written["attributes"].(map[string]any)["jwks.string"]; got != `{"keys":[]}` {
		t.Errorf("an emptied JWKS was written as %v", got)
	}
}

func TestPatchClientRefusesKeysForAPublicClientOrTooMany(t *testing.T) {
	public, _ := newAdmin(t, &kernel{adminBody: `{"id":"p","clientId":"web","publicClient":true,"attributes":{}}`})
	one := []keycloak.JWK{{KID: "a", N: "YQ", E: "AQAB"}}
	if err := public.PatchClient(context.Background(), testRealm, "p", keycloak.ClientPatch{Keys: &one}); err == nil {
		t.Error("a public client was given a key")
	}
	k := &kernel{adminBody: clientRepresentation}
	admin, _ := newAdmin(t, k)
	three := append(one, one[0], one[0])
	if err := admin.PatchClient(context.Background(), testRealm, "0b1c2d3e", keycloak.ClientPatch{Keys: &three}); err == nil {
		t.Error("three keys were written to one client")
	}
	if k.lastMethod == http.MethodPut {
		t.Error("a refused key change reached the kernel")
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

// A confidential client logs users in with the code flow and PKCE, and proves itself by its key: a
// JWKS held on the client, and no secret it could be asked for.
func TestCreateClientSendsAConfidentialClientThatAuthenticatesByKey(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated, adminLocation: "http://kc/admin/realms/scnehaux/clients/bff"}
	admin, _ := newAdmin(t, k)
	if _, err := admin.CreateClient(context.Background(), testRealm, keycloak.ClientSpec{ClientID: "bff", Confidential: true,
		RedirectURIs: []string{"https://app.example.com/cb"}, AccessTokenLifespan: 540,
		Keys: []keycloak.JWK{{KID: "k1", N: "bg", E: "AQAB"}}}); err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	if err := json.Unmarshal(k.lastBody, &sent); err != nil {
		t.Fatal(err)
	}
	attributes := sent["attributes"].(map[string]any)
	if sent["publicClient"] != false || sent["clientAuthenticatorType"] != "client-jwt" || sent["standardFlowEnabled"] != true ||
		sent["serviceAccountsEnabled"] != false || sent["directAccessGrantsEnabled"] != false ||
		attributes["pkce.code.challenge.method"] != "S256" || attributes["use.jwks.string"] != "true" ||
		attributes["use.jwks.url"] != "false" || attributes["token.endpoint.auth.signing.alg"] != "PS256" ||
		attributes["access.token.signed.response.alg"] != "PS256" || attributes["access.token.lifespan"] != "540" {
		t.Errorf("sent %v", sent)
	}
	if _, refusesRefresh := attributes["use.refresh.tokens"]; refusesRefresh {
		t.Error("a confidential client was refused refresh tokens, which its profile permits")
	}
	if !strings.Contains(attributes["jwks.string"].(string), `"kid":"k1"`) {
		t.Errorf("jwks = %v", attributes["jwks.string"])
	}
	if _, secret := sent["secret"]; secret {
		t.Error("a secret was sent")
	}
}

// A workload authenticates as itself with its key on every token request, and is issued no refresh
// token and no login.
func TestCreateClientSendsAWorkloadThatAuthenticatesByKey(t *testing.T) {
	k := &kernel{adminStatus: http.StatusCreated, adminLocation: "http://kc/admin/realms/scnehaux/clients/job"}
	admin, _ := newAdmin(t, k)
	if _, err := admin.CreateClient(context.Background(), testRealm, keycloak.ClientSpec{ClientID: "job", Workload: true,
		AccessTokenLifespan: 540, Keys: []keycloak.JWK{{KID: "k1", N: "bg", E: "AQAB"}}}); err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	_ = json.Unmarshal(k.lastBody, &sent)
	attributes := sent["attributes"].(map[string]any)
	if sent["serviceAccountsEnabled"] != true || sent["standardFlowEnabled"] != false || sent["publicClient"] != false ||
		sent["clientAuthenticatorType"] != "client-jwt" || sent["redirectUris"] != nil ||
		attributes["use.refresh.tokens"] != "false" || attributes["use.jwks.string"] != "true" {
		t.Errorf("sent %v", sent)
	}
}

func TestCreateClientRefusesAnIncoherentSpec(t *testing.T) {
	k := &kernel{}
	admin, _ := newAdmin(t, k)
	key := []keycloak.JWK{{KID: "k", N: "bg", E: "AQAB"}}
	for name, spec := range map[string]keycloak.ClientSpec{
		"no clientId":                   {Public: true, RedirectURIs: []string{"https://a"}, AccessTokenLifespan: 1},
		"neither public nor resource":   {ClientID: "x"},
		"both":                          {ClientID: "x", Public: true, Resource: true},
		"public and confidential":       {ClientID: "x", Public: true, Confidential: true},
		"public without redirects":      {ClientID: "x", Public: true, AccessTokenLifespan: 1},
		"a resource with an audience":   {ClientID: "x", Resource: true, Audience: []string{"y"}},
		"a public client with a key":    {ClientID: "x", Public: true, RedirectURIs: []string{"https://a"}, AccessTokenLifespan: 1, Keys: key},
		"a resource with a key":         {ClientID: "x", Resource: true, Keys: key},
		"a confidential client, no key": {ClientID: "x", Confidential: true, RedirectURIs: []string{"https://a"}, AccessTokenLifespan: 1},
		"a confidential, no redirects":  {ClientID: "x", Confidential: true, AccessTokenLifespan: 1, Keys: key},
		"a workload with redirects":     {ClientID: "x", Workload: true, RedirectURIs: []string{"https://a"}, AccessTokenLifespan: 1, Keys: key},
		"a workload without a lifespan": {ClientID: "x", Workload: true, Keys: key},
		"a workload holding three keys": {ClientID: "x", Workload: true, AccessTokenLifespan: 1, Keys: append(key, key[0], key[0])},
		"a workload holding no key":     {ClientID: "x", Workload: true, AccessTokenLifespan: 1},
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

func TestRemoveDefaultClientScopeDetachesByIdentifier(t *testing.T) {
	k := &kernel{adminStatus: http.StatusNoContent}
	admin, _ := newAdmin(t, k)
	if err := admin.RemoveDefaultClientScope(context.Background(), testRealm, "c1", "acr-id"); err != nil {
		t.Fatal(err)
	}
	if k.lastMethod != http.MethodDelete || k.lastPath != "/admin/realms/scnehaux/clients/c1/default-client-scopes/acr-id" {
		t.Errorf("%s %s", k.lastMethod, k.lastPath)
	}
	// A scope the client does not hold is already detached.
	absent, _ := newAdmin(t, &kernel{adminStatus: http.StatusNotFound})
	if err := absent.RemoveDefaultClientScope(context.Background(), testRealm, "c1", "acr-id"); err != nil {
		t.Errorf("detaching a scope the client does not hold answered %v", err)
	}
	if err := admin.RemoveDefaultClientScope(context.Background(), testRealm, "c1", ""); err == nil {
		t.Error("a detachment without a scope was sent")
	}
}

func TestServiceAccountUserIsTheClientsOwnUser(t *testing.T) {
	k := &kernel{adminBody: `{"id":"sa-1","username":"service-account-nightly-job","enabled":true}`}
	admin, _ := newAdmin(t, k)
	user, err := admin.ServiceAccountUser(context.Background(), testRealm, "c1")
	if err != nil || user.ID != "sa-1" || user.Username != "service-account-nightly-job" {
		t.Fatalf("ServiceAccountUser = %+v, %v", user, err)
	}
	if k.lastPath != "/admin/realms/scnehaux/clients/c1/service-account-user" {
		t.Errorf("read %s", k.lastPath)
	}
	none, _ := newAdmin(t, &kernel{adminStatus: http.StatusNotFound})
	if _, err := none.ServiceAccountUser(context.Background(), testRealm, "c1"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Errorf("a client without a service account answered %v", err)
	}
}

// A client's credential is read as the kernel holds it, and compared by kid and key material
// together: a kid kept over a swapped modulus is a different key.
func TestAClientsCredentialIsReadAndCompared(t *testing.T) {
	admin, _ := newAdmin(t, &kernel{adminBody: `{"id":"c","clientId":"bff","clientAuthenticatorType":"client-jwt",
	  "attributes":{"use.jwks.string":"true","use.jwks.url":"false",
	  "jwks.string":"{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"bg\",\"e\":\"AQAB\"}]}"}}`})
	client, err := admin.GetClient(context.Background(), testRealm, "c")
	if err != nil {
		t.Fatal(err)
	}
	key := keycloak.JWK{KID: "k1", N: "bg", E: "AQAB"}
	if !client.Credential.ByKeys([]keycloak.JWK{key}) {
		t.Errorf("credential %+v does not hold its own key", client.Credential)
	}
	for name, keys := range map[string][]keycloak.JWK{
		"a swapped modulus": {{KID: "k1", N: "other", E: "AQAB"}},
		"a second key":      {key, {KID: "k2", N: "bh", E: "AQAB"}},
		"no key":            nil,
	} {
		if client.Credential.ByKeys(keys) {
			t.Errorf("%s compared equal", name)
		}
	}
	for name, body := range map[string]string{
		"a secret":          `{"id":"c","clientAuthenticatorType":"client-secret","attributes":{"use.jwks.string":"true","jwks.string":"{\"keys\":[{\"kid\":\"k1\",\"n\":\"bg\",\"e\":\"AQAB\"}]}"}}`,
		"a key URL":         `{"id":"c","clientAuthenticatorType":"client-jwt","attributes":{"use.jwks.string":"true","use.jwks.url":"true","jwks.string":"{\"keys\":[{\"kid\":\"k1\",\"n\":\"bg\",\"e\":\"AQAB\"}]}"}}`,
		"an unreadable set": `{"id":"c","clientAuthenticatorType":"client-jwt","attributes":{"use.jwks.string":"true","jwks.string":"not json"}}`,
	} {
		other, _ := newAdmin(t, &kernel{adminBody: body})
		read, err := other.GetClient(context.Background(), testRealm, "c")
		if err != nil {
			t.Fatal(err)
		}
		if read.Credential.ByKeys([]keycloak.JWK{key}) {
			t.Errorf("%s compared as the registered key", name)
		}
	}
}

func TestListClientsReadsEveryPage(t *testing.T) {
	k := &kernel{adminBodyFor: func(query url.Values) string {
		first, _ := strconv.Atoi(query.Get("first"))
		if first >= 100 {
			return `[{"id":"last","clientId":"z"}]`
		}
		var page []string
		for i := range 100 {
			page = append(page, fmt.Sprintf(`{"id":"c%d","clientId":"client-%d"}`, first+i, first+i))
		}
		return "[" + strings.Join(page, ",") + "]"
	}}
	admin, _ := newAdmin(t, k)
	clients, err := admin.ListClients(context.Background(), testRealm)
	if err != nil || len(clients) != 101 || clients[100].ID != "last" {
		t.Errorf("ListClients read %d clients, %v", len(clients), err)
	}
}

func TestDefaultClientScopesAreNamed(t *testing.T) {
	k := &kernel{adminBody: `[{"id":"s1","name":"scnehaux-internal"},{"id":"s2","name":"acr"}]`}
	admin, _ := newAdmin(t, k)
	names, err := admin.DefaultClientScopes(context.Background(), testRealm, "c1")
	if err != nil || len(names) != 2 || names[0] != "scnehaux-internal" {
		t.Errorf("DefaultClientScopes = %v, %v", names, err)
	}
	if k.lastPath != "/admin/realms/scnehaux/clients/c1/default-client-scopes" {
		t.Errorf("read %s", k.lastPath)
	}
}
