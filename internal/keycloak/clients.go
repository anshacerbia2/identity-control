package keycloak

// The registration path's port: clients and the admin events that attribute a change to one.
//
// It is a second interface rather than more methods on AdminClient because it is held by a second
// credential. TDD-identity-control-003 gives the registration path its own Keycloak client,
// identity-control-registration, holding manage-clients, view-clients and view-events, and the
// Principal path keeps users only. The composition root builds one Admin per credential and hands
// each path the interface its credential can serve, so the Principal path has no client method to
// call even by mistake.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ClientUUID is Keycloak's internal identifier for a client, the one its Admin API paths carry. It
// is not the clientId a caller names, which is why it is a type of its own.
type ClientUUID string

// AttrAccessTokenLifespan is the client attribute that overrides the realm's access token lifespan,
// in seconds.
const AttrAccessTokenLifespan = "access.token.lifespan"

// Client is the subset of a client's representation the reconciler compares.
type Client struct {
	ID           ClientUUID
	ClientID     string
	Enabled      bool
	RedirectURIs []string

	// AccessTokenLifespan is the client's override in seconds, and 0 when it has none, in which
	// case the realm's lifespan applies. The reconciler treats an absent override as a divergence:
	// STD-IAM-002 §3.3 derives every client's lifetime from its audience, and the realm default is
	// not that derivation.
	AccessTokenLifespan int

	// Credential is how the client proves itself: its authenticator, whether it takes its keys from
	// the JWKS held on it, and those keys. The reconciler compares it for a confidential or
	// workload client (the client_keys field class).
	Credential ClientCredential
}

// ClientCredential is a client's authentication configuration as the kernel holds it.
type ClientCredential struct {
	// Authenticator is clientAuthenticatorType: client-jwt for a client that proves itself by a
	// signed assertion, client-secret for one that presents a secret.
	Authenticator string

	// HeldJWKS is whether the kernel verifies assertions against the JWKS held on the client
	// (use.jwks.string) rather than one fetched from a URL.
	HeldJWKS bool

	// Keys are the keys of that JWKS. Unreadable is set when the JWKS does not parse: a JWKS
	// nobody can read is not the registered one.
	Keys       []JWK
	Unreadable bool
}

// ByKeys reports whether the credential authenticates by exactly the given keys and nothing else:
// client-jwt, the held JWKS and not a URL, and the same set of keys, compared by kid and key
// material together so a kid kept over a swapped modulus is still a difference.
func (c ClientCredential) ByKeys(keys []JWK) bool {
	if c.Authenticator != clientJWTAuthorizer || !c.HeldJWKS || c.Unreadable || len(c.Keys) != len(keys) {
		return false
	}
	want := map[JWK]bool{}
	for _, key := range keys {
		want[key] = true
	}
	for _, key := range c.Keys {
		if !want[key] {
			return false
		}
	}
	return true
}

// ClientPatch is a change to a client. A nil field is left as it is.
type ClientPatch struct {
	Enabled             *bool
	RedirectURIs        *[]string
	AccessTokenLifespan *int

	// Keys replaces the client's JWKS, and sets the attributes that make the kernel authenticate the
	// client by those keys alone (TDD-identity-control-003 §Client Key Rotation). An empty list is a
	// client with no key, which authenticates as nothing: what revoking its last key means.
	Keys *[]JWK
}

// JWK is one public key a confidential or workload client authenticates with: RSA, for signatures,
// PS256 (STD-IAM-001 §3.2). It has no field for private material, so none can be sent.
type JWK struct {
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k JWK) representation() map[string]string {
	return map[string]string{"kty": "RSA", "kid": k.KID, "use": "sig", "alg": "PS256", "n": k.N, "e": k.E}
}

// The client attributes that hold a client's keys, in the shape identity-kernel's
// compat/client_keys_test.go proved against the pinned kernel: a JWKS held on the client rather
// than fetched from a URL, so no application has to serve a key endpoint to be a client.
const (
	AttrJWKS            = "jwks.string"
	attrUseJWKSString   = "use.jwks.string"
	attrUseJWKSURL      = "use.jwks.url"
	attrAssertionAlg    = "token.endpoint.auth.signing.alg"
	clientJWTAuthorizer = "client-jwt"
)

// jwksString is the JWKS the kernel holds for a client.
func jwksString(keys []JWK) string {
	set := struct {
		Keys []map[string]string `json:"keys"`
	}{Keys: []map[string]string{}}
	for _, key := range keys {
		set.Keys = append(set.Keys, key.representation())
	}
	raw, _ := json.Marshal(set)
	return string(raw)
}

// keyAttributes writes a client's keys and the attributes that make them its only credential.
func keyAttributes(attributes map[string]any, keys []JWK) {
	attributes[attrAssertionAlg] = "PS256"
	attributes[attrUseJWKSURL] = "false"
	attributes[attrUseJWKSString] = "true"
	attributes[AttrJWKS] = jwksString(keys)
}

// AdminEvent is one admin event on a client: who changed it, and when.
type AdminEvent struct {
	Time          time.Time
	OperationType string
	ResourcePath  string

	// UserID is the Keycloak user whose credential made the change: an administrator in the
	// console, or a service account. It is the actor a drift exception names.
	UserID string
}

// ClientID is the client the event's resource path names, or "" for an event on something else.
func (e AdminEvent) ClientID() ClientUUID {
	rest, ok := strings.CutPrefix(e.ResourcePath, "clients/")
	if !ok {
		return ""
	}
	client, _, _ := strings.Cut(rest, "/")
	return ClientUUID(client)
}

// ClientRegistry is the registration path's surface: read and change a client, and read the admin
// events that attribute a change to one.
type ClientRegistry interface {
	// GetClient returns the client, or ErrNotFound when the realm has none by that identifier.
	GetClient(ctx context.Context, realm Realm, client ClientUUID) (Client, error)

	// PatchClient applies the patch and leaves every other field as it is.
	PatchClient(ctx context.Context, realm Realm, client ClientUUID, patch ClientPatch) error

	// ClientAdminEvents returns every admin event on a client since the given time, newest first.
	// It fails with ErrForbidden when the credential cannot read admin events, which the reconciler
	// reads as attribution being unavailable.
	ClientAdminEvents(ctx context.Context, realm Realm, since time.Time) ([]AdminEvent, error)

	// ServiceAccountUserID is the Keycloak user this credential acts as. An admin event it caused
	// is the reconciler's own repair, never a change to attribute to someone.
	ServiceAccountUserID(ctx context.Context) (string, error)

	// CreateClient creates a client from its specification and returns its identifier. On
	// ErrAmbiguous the client may exist: the caller reads it back by clientId before acting, as
	// Principal creation does, because a blind retry is refused by the kernel as a conflict.
	CreateClient(ctx context.Context, realm Realm, spec ClientSpec) (ClientUUID, error)

	// FindClients returns every client whose clientId equals the one given, exactly.
	FindClients(ctx context.Context, realm Realm, clientID string) ([]Client, error)

	// ClientScopeID returns the identifier of the named client scope, or ErrNotFound when the
	// realm declares none by that name.
	ClientScopeID(ctx context.Context, realm Realm, name string) (string, error)

	// AddDefaultClientScope attaches a client scope to a client as a default scope.
	AddDefaultClientScope(ctx context.Context, realm Realm, client ClientUUID, scopeID string) error

	// RemoveDefaultClientScope detaches a default client scope from a client. Detaching one the
	// client does not hold succeeds.
	RemoveDefaultClientScope(ctx context.Context, realm Realm, client ClientUUID, scopeID string) error

	// ServiceAccountUser returns the user a client credentials token of this client is issued for,
	// the one Keycloak creates with a client whose service accounts are enabled. It answers
	// ErrNotFound for a client without one. A workload's claim-source attributes live on this user
	// (TDD-identity-kernel-001 §Claim Projection).
	ServiceAccountUser(ctx context.Context, realm Realm, client ClientUUID) (User, error)

	// ListClients returns every client in the realm, reading every page.
	ListClients(ctx context.Context, realm Realm) ([]Client, error)

	// DefaultClientScopes returns the names of the client's default client scopes.
	DefaultClientScopes(ctx context.Context, realm Realm, client ClientUUID) ([]string, error)
}

// ClientSpec is a client built from desired state (TDD-identity-control-003 §Profiles). Exactly one
// of Public, Confidential, Workload and Resource is set.
type ClientSpec struct {
	ClientID string

	// Public is a client that holds no secret and no key. It authenticates with PKCE S256 and is
	// issued no refresh token.
	Public bool

	// Confidential is a browser-facing backend. It logs users in with the authorization code flow
	// and PKCE, and authenticates itself with a signed assertion by one of Keys.
	Confidential bool

	// Workload is a service acting as itself. It authenticates with a signed assertion by one of
	// Keys on every token request, through the client credentials grant, and is issued no refresh
	// token.
	Workload bool

	// Resource is a protected resource: an audience only, through which no one logs in.
	Resource bool

	RedirectURIs        []string
	AccessTokenLifespan int

	// Audience names the resources a token issued to this client is for, each through an audience
	// mapper. Which API a token is for belongs to the client relationship, not to the claim profile.
	Audience []string

	// Keys are a confidential or workload client's public keys: one, or two during a rotation.
	Keys []JWK
}

// MaxClientKeys is how many keys a client holds at once: the active one, and during a rotation the
// one retiring. It is the overlap the pinned kernel was proven to accept.
const MaxClientKeys = 2

// Validate refuses a specification the kernel would accept and the profiles would not.
func (s ClientSpec) Validate() error {
	kinds := 0
	for _, set := range []bool{s.Public, s.Confidential, s.Workload, s.Resource} {
		if set {
			kinds++
		}
	}
	keyed := s.Confidential || s.Workload
	switch {
	case strings.TrimSpace(s.ClientID) == "":
		return errors.New("keycloak: a clientId is required")
	case kinds != 1:
		return errors.New("keycloak: a client is exactly one of public, confidential, workload or resource")
	case (s.Public || s.Confidential) && (len(s.RedirectURIs) == 0 || s.AccessTokenLifespan <= 0):
		return errors.New("keycloak: a public or confidential client needs redirect URIs and an access token lifespan")
	case s.Workload && (len(s.RedirectURIs) > 0 || s.AccessTokenLifespan <= 0):
		return errors.New("keycloak: a workload has no redirect URIs and needs an access token lifespan")
	case s.Resource && (len(s.RedirectURIs) > 0 || len(s.Audience) > 0):
		return errors.New("keycloak: a resource has no redirect URIs and no audience")
	case keyed && (len(s.Keys) == 0 || len(s.Keys) > MaxClientKeys):
		return fmt.Errorf("keycloak: a confidential or workload client holds 1 to %d keys", MaxClientKeys)
	case !keyed && len(s.Keys) > 0:
		return errors.New("keycloak: only a confidential or workload client holds keys")
	}
	return nil
}

func (s ClientSpec) representation() map[string]any {
	representation := map[string]any{
		"clientId":                  s.ClientID,
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"implicitFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"serviceAccountsEnabled":    false,
	}
	if s.Resource {
		representation["publicClient"] = false
		representation["bearerOnly"] = true
		representation["standardFlowEnabled"] = false
		return representation
	}
	attributes := map[string]any{
		"access.token.signed.response.alg": "PS256",
		AttrAccessTokenLifespan:            strconv.Itoa(s.AccessTokenLifespan),
	}
	switch {
	case s.Public:
		representation["publicClient"] = true
		representation["standardFlowEnabled"] = true
		representation["redirectUris"] = append([]string{}, s.RedirectURIs...)
		attributes["pkce.code.challenge.method"] = "S256"
		// STD-IAM-001 §3.2: a public client holds no refresh token.
		attributes["use.refresh.tokens"] = "false"
	case s.Confidential:
		// The kernel still generates a secret for a confidential client, and the client-jwt
		// authenticator never accepts it: the client proves itself by its key or not at all.
		representation["publicClient"] = false
		representation["clientAuthenticatorType"] = clientJWTAuthorizer
		representation["standardFlowEnabled"] = true
		representation["redirectUris"] = append([]string{}, s.RedirectURIs...)
		attributes["pkce.code.challenge.method"] = "S256"
		keyAttributes(attributes, s.Keys)
	case s.Workload:
		representation["publicClient"] = false
		representation["clientAuthenticatorType"] = clientJWTAuthorizer
		representation["standardFlowEnabled"] = false
		representation["serviceAccountsEnabled"] = true
		// A workload re-authenticates with its own key rather than continuing a session.
		attributes["use.refresh.tokens"] = "false"
		keyAttributes(attributes, s.Keys)
	}
	representation["attributes"] = attributes
	var mappers []map[string]any
	for _, resource := range s.Audience {
		mappers = append(mappers, map[string]any{
			"name":           "audience-" + resource,
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-audience-mapper",
			"config": map[string]any{
				"included.client.audience":  resource,
				"access.token.claim":        "true",
				"id.token.claim":            "false",
				"introspection.token.claim": "true",
			},
		})
	}
	if len(mappers) > 0 {
		representation["protocolMappers"] = mappers
	}
	return representation
}

var _ ClientRegistry = (*Admin)(nil)

func (a *Admin) clientPath(realm Realm, client ClientUUID) string {
	return fmt.Sprintf("/admin/realms/%s/clients/%s", url.PathEscape(string(realm)), url.PathEscape(string(client)))
}

// GetClient reads one client.
func (a *Admin) GetClient(ctx context.Context, realm Realm, client ClientUUID) (Client, error) {
	if client == "" {
		return Client{}, errors.New("keycloak: a client identifier is required")
	}
	representation, err := a.clientRepresentation(ctx, realm, client)
	if err != nil {
		return Client{}, err
	}
	return clientFrom(representation)
}

// PatchClient reads the whole representation, changes the patched fields, and writes it back.
//
// The whole representation rather than the patched fields alone, because an update that omits
// attributes is not a documented no-op for them, and a lifespan repair that cleared the client's
// PKCE method would be a worse drift than the one it repaired.
func (a *Admin) PatchClient(ctx context.Context, realm Realm, client ClientUUID, patch ClientPatch) error {
	if client == "" {
		return errors.New("keycloak: a client identifier is required")
	}
	representation, err := a.clientRepresentation(ctx, realm, client)
	if err != nil {
		return err
	}
	if patch.Enabled != nil {
		representation["enabled"] = *patch.Enabled
	}
	if patch.RedirectURIs != nil {
		representation["redirectUris"] = append([]string{}, *patch.RedirectURIs...)
	}
	if patch.AccessTokenLifespan != nil {
		attributes, _ := representation["attributes"].(map[string]any)
		if attributes == nil {
			attributes = map[string]any{}
		}
		attributes[AttrAccessTokenLifespan] = strconv.Itoa(*patch.AccessTokenLifespan)
		representation["attributes"] = attributes
	}
	if patch.Keys != nil {
		if len(*patch.Keys) > MaxClientKeys {
			return fmt.Errorf("keycloak: a client holds at most %d keys", MaxClientKeys)
		}
		if public, _ := representation["publicClient"].(bool); public {
			return errors.New("keycloak: a public client holds no key")
		}
		attributes, _ := representation["attributes"].(map[string]any)
		if attributes == nil {
			attributes = map[string]any{}
		}
		keyAttributes(attributes, *patch.Keys)
		representation["attributes"] = attributes
		representation["clientAuthenticatorType"] = clientJWTAuthorizer
	}
	// Not marked mutating: a PUT of a whole representation is idempotent, so a lost response costs
	// a repeated call rather than a duplicated effect.
	response, err := a.do(ctx, http.MethodPut, a.clientPath(realm, client), nil, representation, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

func (a *Admin) clientRepresentation(ctx context.Context, realm Realm, client ClientUUID) (map[string]any, error) {
	response, err := a.do(ctx, http.MethodGet, a.clientPath(realm, client), nil, nil, false)
	if err != nil {
		return nil, err
	}
	defer response.Close()
	var representation map[string]any
	if err := json.Unmarshal(response.body, &representation); err != nil {
		return nil, fmt.Errorf("keycloak: decode client: %w", err)
	}
	return representation, nil
}

func clientFrom(representation map[string]any) (Client, error) {
	client := Client{}
	client.ID = ClientUUID(stringField(representation, "id"))
	client.ClientID = stringField(representation, "clientId")
	client.Enabled, _ = representation["enabled"].(bool)
	if uris, ok := representation["redirectUris"].([]any); ok {
		for _, uri := range uris {
			if value, ok := uri.(string); ok {
				client.RedirectURIs = append(client.RedirectURIs, value)
			}
		}
	}
	attributes, _ := representation["attributes"].(map[string]any)
	client.Credential = credentialFrom(representation, attributes)
	if raw, ok := attributes[AttrAccessTokenLifespan].(string); ok && strings.TrimSpace(raw) != "" {
		lifespan, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return Client{}, fmt.Errorf("keycloak: client %s carries an unreadable %s", client.ClientID, AttrAccessTokenLifespan)
		}
		client.AccessTokenLifespan = lifespan
	}
	return client, nil
}

// credentialFrom reads a client's authentication configuration. A JWKS URL in use is a held JWKS
// not in use, whatever the string attribute says.
func credentialFrom(representation, attributes map[string]any) ClientCredential {
	credential := ClientCredential{Authenticator: stringField(representation, "clientAuthenticatorType")}
	held, _ := attributes[attrUseJWKSString].(string)
	byURL, _ := attributes[attrUseJWKSURL].(string)
	credential.HeldJWKS = held == "true" && byURL != "true"
	raw, _ := attributes[AttrJWKS].(string)
	if strings.TrimSpace(raw) == "" {
		return credential
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		credential.Unreadable = true
		return credential
	}
	for _, key := range set.Keys {
		kid, _ := key["kid"].(string)
		n, _ := key["n"].(string)
		e, _ := key["e"].(string)
		credential.Keys = append(credential.Keys, JWK{KID: kid, N: n, E: e})
	}
	return credential
}

func stringField(representation map[string]any, name string) string {
	value, _ := representation[name].(string)
	return value
}

// adminEventPage is one page of the admin-event read, and adminEventPages bounds the read. Ten
// thousand client events inside one sweep interval is an incident on its own, and reading on
// would make the sweep's cost a function of that incident.
const (
	adminEventPage  = 100
	adminEventPages = 100
)

// ErrTooManyEvents means more client admin events fell inside the window than one read takes.
// The reconciler treats it as attribution being unavailable, not as the events it did read:
// attributing from part of the record could name the wrong actor.
var ErrTooManyEvents = errors.New("keycloak: more client admin events than one sweep reads")

// ClientAdminEvents reads the realm's client admin events since the given time.
//
// Keycloak filters admin events by date, not by instant, and the date is read in the server's
// time zone. The query therefore asks from the day before and filters to the instant here.
func (a *Admin) ClientAdminEvents(ctx context.Context, realm Realm, since time.Time) ([]AdminEvent, error) {
	var events []AdminEvent
	path := fmt.Sprintf("/admin/realms/%s/admin-events", url.PathEscape(string(realm)))
	for page := 0; page < adminEventPages; page++ {
		query := url.Values{}
		query.Set("resourceTypes", "CLIENT")
		query.Set("dateFrom", since.UTC().AddDate(0, 0, -1).Format("2006-01-02"))
		query.Set("first", strconv.Itoa(page*adminEventPage))
		query.Set("max", strconv.Itoa(adminEventPage))

		response, err := a.do(ctx, http.MethodGet, path, query, nil, false)
		if err != nil {
			return nil, err
		}
		var representations []adminEventRepresentation
		decodeErr := json.Unmarshal(response.body, &representations)
		response.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("keycloak: decode admin events: %w", decodeErr)
		}

		reachedSince := false
		for _, representation := range representations {
			event := representation.toEvent()
			if event.Time.Before(since) {
				reachedSince = true
				continue
			}
			events = append(events, event)
		}
		if len(representations) < adminEventPage || reachedSince {
			sort.SliceStable(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
			return events, nil
		}
	}
	return nil, ErrTooManyEvents
}

type adminEventRepresentation struct {
	Time          int64  `json:"time"`
	OperationType string `json:"operationType"`
	ResourcePath  string `json:"resourcePath"`
	AuthDetails   struct {
		UserID string `json:"userId"`
	} `json:"authDetails"`
}

func (r adminEventRepresentation) toEvent() AdminEvent {
	return AdminEvent{
		Time:          time.UnixMilli(r.Time).UTC(),
		OperationType: r.OperationType,
		ResourcePath:  r.ResourcePath,
		UserID:        r.AuthDetails.UserID,
	}
}

// ServiceAccountUserID reads the sub claim of this credential's own access token: for a service
// account, the Keycloak user it acts as. The token came from the token endpoint over this
// client's own connection, so it is read without verifying a signature; it is never accepted
// from anywhere else.
func (a *Admin) ServiceAccountUserID(ctx context.Context) (string, error) {
	token, err := a.accessToken(ctx)
	if err != nil {
		return "", err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("keycloak: the access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("keycloak: the access token payload is not base64url")
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Subject == "" {
		return "", errors.New("keycloak: the access token names no subject")
	}
	return claims.Subject, nil
}

// CreateClient creates the client. Marked mutating: a create whose response is lost may have
// happened, and the caller must read it back rather than retry.
func (a *Admin) CreateClient(ctx context.Context, realm Realm, spec ClientSpec) (ClientUUID, error) {
	if err := spec.Validate(); err != nil {
		return "", err
	}
	response, err := a.do(ctx, http.MethodPost,
		fmt.Sprintf("/admin/realms/%s/clients", url.PathEscape(string(realm))), nil, spec.representation(), true)
	if err != nil {
		return "", err
	}
	defer response.Close()
	if client := ClientUUID(userIDFromLocation(response.location)); client != "" {
		return client, nil
	}
	return "", fmt.Errorf("keycloak: created a client but the Location header carried no identifier: %w", ErrAmbiguous)
}

// FindClients reads clients by clientId. The kernel's clientId query is exact unless search is
// asked for, and the result is filtered to equality here as well, as user search is.
func (a *Admin) FindClients(ctx context.Context, realm Realm, clientID string) ([]Client, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, errors.New("keycloak: a clientId is required")
	}
	query := url.Values{}
	query.Set("clientId", clientID)
	query.Set("search", "false")
	response, err := a.do(ctx, http.MethodGet,
		fmt.Sprintf("/admin/realms/%s/clients", url.PathEscape(string(realm))), query, nil, false)
	if err != nil {
		return nil, err
	}
	defer response.Close()
	var representations []map[string]any
	if err := json.Unmarshal(response.body, &representations); err != nil {
		return nil, fmt.Errorf("keycloak: decode clients: %w", err)
	}
	var out []Client
	for _, representation := range representations {
		client, err := clientFrom(representation)
		if err != nil {
			return nil, err
		}
		if client.ClientID == clientID {
			out = append(out, client)
		}
	}
	return out, nil
}

// ClientScopeID finds a client scope by name.
func (a *Admin) ClientScopeID(ctx context.Context, realm Realm, name string) (string, error) {
	response, err := a.do(ctx, http.MethodGet,
		fmt.Sprintf("/admin/realms/%s/client-scopes", url.PathEscape(string(realm))), nil, nil, false)
	if err != nil {
		return "", err
	}
	defer response.Close()
	var scopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(response.body, &scopes); err != nil {
		return "", fmt.Errorf("keycloak: decode client scopes: %w", err)
	}
	for _, scope := range scopes {
		if scope.Name == name {
			return scope.ID, nil
		}
	}
	return "", fmt.Errorf("keycloak: the realm declares no client scope %q: %w", name, ErrNotFound)
}

// clientPage is the client enumeration's page, and clientPages bounds it: ten thousand clients in one
// realm is an estate this service was not sized for, and reading on would make a sweep's cost a
// function of it.
const (
	clientPage  = 100
	clientPages = 100
)

// ErrTooManyClients means the realm holds more clients than one enumeration reads.
var ErrTooManyClients = errors.New("keycloak: more clients than one enumeration reads")

// ListClients reads every client in the realm, page by page.
func (a *Admin) ListClients(ctx context.Context, realm Realm) ([]Client, error) {
	var out []Client
	path := fmt.Sprintf("/admin/realms/%s/clients", url.PathEscape(string(realm)))
	for page := 0; page < clientPages; page++ {
		query := url.Values{}
		query.Set("first", strconv.Itoa(page*clientPage))
		query.Set("max", strconv.Itoa(clientPage))
		response, err := a.do(ctx, http.MethodGet, path, query, nil, false)
		if err != nil {
			return nil, err
		}
		var representations []map[string]any
		decodeErr := json.Unmarshal(response.body, &representations)
		response.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("keycloak: decode clients: %w", decodeErr)
		}
		for _, representation := range representations {
			client, err := clientFrom(representation)
			if err != nil {
				return nil, err
			}
			out = append(out, client)
		}
		if len(representations) < clientPage {
			return out, nil
		}
	}
	return nil, ErrTooManyClients
}

// DefaultClientScopes reads the names of a client's default client scopes.
func (a *Admin) DefaultClientScopes(ctx context.Context, realm Realm, client ClientUUID) ([]string, error) {
	if client == "" {
		return nil, errors.New("keycloak: a client identifier is required")
	}
	response, err := a.do(ctx, http.MethodGet, a.clientPath(realm, client)+"/default-client-scopes", nil, nil, false)
	if err != nil {
		return nil, err
	}
	defer response.Close()
	var scopes []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(response.body, &scopes); err != nil {
		return nil, fmt.Errorf("keycloak: decode default client scopes: %w", err)
	}
	names := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		names = append(names, scope.Name)
	}
	return names, nil
}

// ServiceAccountUser reads the client's service-account user.
func (a *Admin) ServiceAccountUser(ctx context.Context, realm Realm, client ClientUUID) (User, error) {
	if client == "" {
		return User{}, errors.New("keycloak: a client identifier is required")
	}
	response, err := a.do(ctx, http.MethodGet, a.clientPath(realm, client)+"/service-account-user", nil, nil, false)
	if err != nil {
		return User{}, err
	}
	defer response.Close()
	var representation userRepresentation
	if err := json.Unmarshal(response.body, &representation); err != nil {
		return User{}, fmt.Errorf("keycloak: decode service-account user: %w", err)
	}
	if representation.ID == "" {
		return User{}, fmt.Errorf("keycloak: the client has no service-account user: %w", ErrNotFound)
	}
	return representation.toUser(), nil
}

// RemoveDefaultClientScope detaches the scope. Idempotent: a scope the client does not hold is
// already detached, so the kernel's not-found answer is success.
func (a *Admin) RemoveDefaultClientScope(ctx context.Context, realm Realm, client ClientUUID, scopeID string) error {
	if client == "" || scopeID == "" {
		return errors.New("keycloak: a client and a scope are required")
	}
	response, err := a.do(ctx, http.MethodDelete,
		a.clientPath(realm, client)+"/default-client-scopes/"+url.PathEscape(scopeID), nil, nil, false)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

// AddDefaultClientScope attaches the scope. Idempotent: attaching one already attached succeeds.
func (a *Admin) AddDefaultClientScope(ctx context.Context, realm Realm, client ClientUUID, scopeID string) error {
	if client == "" || scopeID == "" {
		return errors.New("keycloak: a client and a scope are required")
	}
	response, err := a.do(ctx, http.MethodPut,
		a.clientPath(realm, client)+"/default-client-scopes/"+url.PathEscape(scopeID), nil, nil, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}
