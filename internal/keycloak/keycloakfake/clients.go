package keycloakfake

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// Registry is an in-memory ClientRegistry.
//
// A test changes a client "in the console" with ConsoleChange, which records the admin event a
// real console change would, and it makes attribution or the kernel itself unavailable by setting
// the failure fields. Those are the cases the reconciler exists for, and none of them happens on
// a healthy server.
type Registry struct {
	mu sync.Mutex

	// ServiceAccount is the user this registry's credential acts as. Every PatchClient records an
	// admin event naming it, as the real kernel does.
	ServiceAccount string

	// FailGet and FailPatch are returned by their operations when set. keycloak.ErrUnavailable in
	// FailGet is an unreachable kernel.
	FailGet    error
	FailPatch  error
	FailDelete error

	// FailEvents is returned by ClientAdminEvents when set. keycloak.ErrForbidden is a credential
	// without view-events.
	FailEvents error

	// Now is the clock admin events are stamped with. Nil uses time.Now.
	Now func() time.Time

	Patches int

	// FailPatchOf, when it names a client, is returned by PatchClient for that client alone: a kernel
	// that accepts one client's change and refuses another's.
	FailPatchOf map[keycloak.ClientUUID]error

	// FailCreate is returned by CreateClient when set. With AmbiguousCreateSucceeds, the client is
	// created anyway: a response lost after the kernel committed.
	FailCreate              error
	AmbiguousCreateSucceeds bool

	// Scopes are the realm's client scopes, by name, with their identifiers.
	Scopes map[string]string

	// OnServiceAccount is called, outside the lock, when a created client gets a service-account
	// user, as a workload client does in the real kernel. A test joins it to the user fake with
	// Client.AddServiceAccount, so the two fakes see one user, as the two credentials do.
	OnServiceAccount func(user keycloak.User)

	// RealmDefaults are the scope identifiers every created client holds as default scopes, as the
	// real kernel attaches its realm default client scopes, acr among them. Empty unless a test sets
	// it.
	RealmDefaults []string

	// RealmOptional are the scope identifiers every created client holds as optional scopes.
	RealmOptional []string

	clients         map[keycloak.ClientUUID]keycloak.Client
	specs           map[keycloak.ClientUUID]keycloak.ClientSpec
	serviceAccounts map[keycloak.ClientUUID]keycloak.User
	defaultScopes   map[keycloak.ClientUUID][]string
	optionalScopes  map[keycloak.ClientUUID][]string
	events          []keycloak.AdminEvent
	deletes         int
}

// NewRegistry returns an empty registry acting as the given service account.
func NewRegistry(serviceAccount string) *Registry {
	return &Registry{ServiceAccount: serviceAccount, clients: map[keycloak.ClientUUID]keycloak.Client{},
		serviceAccounts: map[keycloak.ClientUUID]keycloak.User{},
		specs:           map[keycloak.ClientUUID]keycloak.ClientSpec{}, defaultScopes: map[keycloak.ClientUUID][]string{},
		optionalScopes: map[keycloak.ClientUUID][]string{},
		Scopes: map[string]string{"scnehaux-internal": "scope-internal", "scnehaux-provider": "scope-provider",
			"scnehaux-privileged": "scope-privileged",
			"scnehaux-external":   "scope-external", "basic": "scope-basic", "acr": "scope-acr",
			"scnehaux-profile": "scope-sign-in", "profile": "scope-profile", "email": "scope-email",
			"service_account": "scope-service-account", "organization": "scope-organization"}}
}

var _ keycloak.ClientRegistry = (*Registry)(nil)

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

// Put stores a client as it stands, recording no admin event: the state before the test begins. A
// client given no logout configuration holds what the Admin API gives a client created without one:
// front channel off and "session required" on (Keycloak 26.7.5 OIDCLoginProtocolFactory, ADR-IAM-009
// [R4]).
func (r *Registry) Put(client keycloak.Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client.Logout == (keycloak.Logout{}) {
		client.Logout = keycloak.DesiredLogout("")
	}
	r.clients[client.ID] = copyClient(client)
}

// HoldScopes sets a client's default and optional scopes by name, as they stand before the test
// begins, recording no admin event. A name Scopes does not declare is held as it is.
func (r *Registry) HoldScopes(client keycloak.ClientUUID, defaults, optional []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := func(names []string) []string {
		out := make([]string, 0, len(names))
		for _, name := range names {
			if id, ok := r.Scopes[name]; ok {
				out = append(out, id)
			} else {
				out = append(out, name)
			}
		}
		return out
	}
	r.defaultScopes[client], r.optionalScopes[client] = ids(defaults), ids(optional)
}

// Remove deletes a client, as a console deletion would, recording its admin event.
func (r *Registry) Remove(actor string, client keycloak.ClientUUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, client)
	r.events = append(r.events, keycloak.AdminEvent{Time: r.now(), OperationType: "DELETE",
		ResourcePath: "clients/" + string(client), UserID: actor})
}

// Deletes counts the clients deleted through DeleteClient, for a test's assertions.
func (r *Registry) Deletes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deletes
}

// DeleteClient deletes a client and its service-account user, as the kernel does, recording the admin
// event under this registry's own service account.
func (r *Registry) DeleteClient(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailDelete != nil {
		return r.FailDelete
	}
	if _, ok := r.clients[client]; !ok {
		return keycloak.ErrNotFound
	}
	delete(r.clients, client)
	delete(r.specs, client)
	delete(r.serviceAccounts, client)
	delete(r.defaultScopes, client)
	delete(r.optionalScopes, client)
	r.deletes++
	r.events = append(r.events, keycloak.AdminEvent{Time: r.now(), OperationType: "DELETE",
		ResourcePath: "clients/" + string(client), UserID: r.ServiceAccount})
	return nil
}

// ConsoleChange changes a client as the named user would in the console, recording the admin
// event. An empty actor records no event: a change made by a path that leaves none.
func (r *Registry) ConsoleChange(actor string, client keycloak.ClientUUID, change func(*keycloak.Client)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := r.clients[client]
	change(&stored)
	r.clients[client] = copyClient(stored)
	if actor != "" {
		r.events = append(r.events, keycloak.AdminEvent{Time: r.now(), OperationType: "UPDATE",
			ResourcePath: "clients/" + string(client), UserID: actor})
	}
}

// Client returns the stored client, for a test's assertions.
func (r *Registry) Client(client keycloak.ClientUUID) (keycloak.Client, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.clients[client]
	return copyClient(stored), ok
}

func (r *Registry) GetClient(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID) (keycloak.Client, error) {
	if err := ctx.Err(); err != nil {
		return keycloak.Client{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailGet != nil {
		return keycloak.Client{}, r.FailGet
	}
	stored, ok := r.clients[client]
	if !ok {
		return keycloak.Client{}, keycloak.ErrNotFound
	}
	return copyClient(stored), nil
}

func (r *Registry) PatchClient(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID, patch keycloak.ClientPatch) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailPatch != nil {
		return r.FailPatch
	}
	if err := r.FailPatchOf[client]; err != nil {
		return err
	}
	stored, ok := r.clients[client]
	if !ok {
		return keycloak.ErrNotFound
	}
	if patch.Enabled != nil {
		stored.Enabled = *patch.Enabled
	}
	if patch.RedirectURIs != nil {
		stored.RedirectURIs = append([]string{}, *patch.RedirectURIs...)
	}
	if patch.AccessTokenLifespan != nil {
		stored.AccessTokenLifespan = *patch.AccessTokenLifespan
	}
	if patch.NotBefore != nil {
		stored.NotBefore = *patch.NotBefore
	}
	if patch.BackChannelLogoutURL != nil {
		spec := r.specs[client]
		if spec.Public && *patch.BackChannelLogoutURL != "" {
			return errors.New("keycloakfake: a public client has no back-channel logout URL")
		}
		stored.Logout = keycloak.DesiredLogout(*patch.BackChannelLogoutURL)
	}
	if patch.TokenFormat != nil {
		stored.RFC9068, stored.ClientIDClaim = true, *patch.TokenFormat
	}
	if patch.Audience != nil {
		spec := r.specs[client]
		spec.Audience = append([]string{}, *patch.Audience...)
		r.specs[client] = spec
		stored.Audience = sortedAudience(*patch.Audience)
	}
	if patch.Keys != nil {
		spec := r.specs[client]
		if spec.Public {
			return errors.New("keycloakfake: a public client holds no key")
		}
		if len(*patch.Keys) > keycloak.MaxClientKeys {
			return errors.New("keycloakfake: too many keys")
		}
		spec.Keys = append([]keycloak.JWK{}, *patch.Keys...)
		r.specs[client] = spec
		stored.Credential = keycloak.ClientCredential{Authenticator: "client-jwt", HeldJWKS: true,
			Keys: append([]keycloak.JWK{}, *patch.Keys...)}
	}
	r.clients[client] = stored
	r.Patches++
	r.events = append(r.events, keycloak.AdminEvent{Time: r.now(), OperationType: "UPDATE",
		ResourcePath: "clients/" + string(client), UserID: r.ServiceAccount})
	return nil
}

func (r *Registry) ClientAdminEvents(ctx context.Context, _ keycloak.Realm, since time.Time) ([]keycloak.AdminEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailEvents != nil {
		return nil, r.FailEvents
	}
	var out []keycloak.AdminEvent
	for _, event := range r.events {
		if !event.Time.Before(since) {
			out = append(out, event)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out, nil
}

func (r *Registry) ServiceAccountUserID(context.Context) (string, error) {
	return r.ServiceAccount, nil
}

// sortedAudience is a client's audience mappers as the kernel's representation lists them, sorted.
func sortedAudience(resources []string) []string {
	if len(resources) == 0 {
		return nil
	}
	out := append([]string(nil), resources...)
	sort.Strings(out)
	return out
}

func copyClient(client keycloak.Client) keycloak.Client {
	client.Audience = sortedAudience(client.Audience)
	client.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	client.Credential.Keys = append([]keycloak.JWK(nil), client.Credential.Keys...)
	return client
}

// Keys returns the public keys the client holds now: what CreateClient was given, as later patches
// and console changes left it.
func (r *Registry) Keys(client keycloak.ClientUUID) []keycloak.JWK {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]keycloak.JWK(nil), r.clients[client].Credential.Keys...)
}

// Spec returns what CreateClient was given for a client, and its default scopes.
func (r *Registry) Spec(client keycloak.ClientUUID) (keycloak.ClientSpec, []string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	spec, ok := r.specs[client]
	return spec, append([]string(nil), r.defaultScopes[client]...), ok
}

func (r *Registry) CreateClient(ctx context.Context, realm keycloak.Realm, spec keycloak.ClientSpec) (keycloak.ClientUUID, error) {
	client, serviceAccount, err := r.createClient(ctx, realm, spec)
	if serviceAccount != nil && r.OnServiceAccount != nil {
		r.OnServiceAccount(*serviceAccount)
	}
	return client, err
}

func (r *Registry) createClient(ctx context.Context, _ keycloak.Realm, spec keycloak.ClientSpec) (keycloak.ClientUUID, *keycloak.User, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if err := spec.Validate(); err != nil {
		return "", nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailCreate != nil && !r.AmbiguousCreateSucceeds {
		return "", nil, r.FailCreate
	}
	for _, existing := range r.clients {
		if existing.ClientID == spec.ClientID {
			return "", nil, keycloak.ErrConflict
		}
	}
	// A UUID, as the kernel's identifiers are: they are unique across every test sharing a database.
	minted, err := id.NewV7()
	if err != nil {
		return "", nil, err
	}
	client := keycloak.ClientUUID(minted.String())
	created := keycloak.Client{ID: client, ClientID: spec.ClientID, Enabled: true,
		RedirectURIs: append([]string(nil), spec.RedirectURIs...), AccessTokenLifespan: spec.AccessTokenLifespan}
	if spec.Confidential || spec.Workload {
		created.Credential = keycloak.ClientCredential{Authenticator: "client-jwt", HeldJWKS: true,
			Keys: append([]keycloak.JWK(nil), spec.Keys...)}
	}
	if !spec.Resource {
		created.RFC9068, created.ClientIDClaim = true, spec.ClientID
		created.Audience = sortedAudience(spec.Audience)
		created.Logout = keycloak.DesiredLogout(spec.BackChannelLogoutURL)
	}
	r.clients[client] = created
	r.specs[client] = spec
	r.defaultScopes[client] = append([]string(nil), r.RealmDefaults...)
	r.optionalScopes[client] = append([]string(nil), r.RealmOptional...)
	r.events = append(r.events, keycloak.AdminEvent{Time: r.now(), OperationType: "CREATE",
		ResourcePath: "clients/" + string(client), UserID: r.ServiceAccount})
	var serviceAccount *keycloak.User
	if spec.Workload {
		user := keycloak.User{ID: keycloak.UserID("sa-" + string(client)), Username: "service-account-" + spec.ClientID,
			Enabled: true}
		r.serviceAccounts[client] = user
		serviceAccount = &user
	}
	if r.FailCreate != nil {
		return "", serviceAccount, r.FailCreate
	}
	return client, serviceAccount, nil
}

func (r *Registry) ListClients(ctx context.Context, _ keycloak.Realm) ([]keycloak.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailGet != nil {
		return nil, r.FailGet
	}
	out := make([]keycloak.Client, 0, len(r.clients))
	for _, client := range r.clients {
		out = append(out, copyClient(client))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

// DefaultClientScopes returns the names of the client's default scopes: the name each attached
// scope identifier has in Scopes, or the identifier itself for one Scopes does not name.
func (r *Registry) DefaultClientScopes(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailGet != nil {
		return nil, r.FailGet
	}
	if _, ok := r.clients[client]; !ok {
		return nil, keycloak.ErrNotFound
	}
	names := []string{}
	for _, scopeID := range r.defaultScopes[client] {
		name := scopeID
		for scopeName, id := range r.Scopes {
			if id == scopeID {
				name = scopeName
			}
		}
		names = append(names, name)
	}
	return names, nil
}

// AttachScope attaches a default scope to a client with no admin event: the state before a test.
// OptionalScopes are the identifiers of the client's optional scopes, for a test's assertions.
func (r *Registry) OptionalScopes(client keycloak.ClientUUID) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.optionalScopes[client]...)
}

// AttachOptionalScope attaches an optional scope as the console would, recording no event.
func (r *Registry) AttachOptionalScope(client keycloak.ClientUUID, scopeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.optionalScopes[client] = append(r.optionalScopes[client], scopeID)
}

func (r *Registry) OptionalClientScopes(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailGet != nil {
		return nil, r.FailGet
	}
	return r.scopeNames(r.optionalScopes[client]), nil
}

func (r *Registry) AddOptionalClientScope(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID, scopeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailPatch != nil {
		return r.FailPatch
	}
	for _, held := range r.optionalScopes[client] {
		if held == scopeID {
			return nil
		}
	}
	r.optionalScopes[client] = append(r.optionalScopes[client], scopeID)
	return nil
}

func (r *Registry) RemoveOptionalClientScope(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID, scopeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailPatch != nil {
		return r.FailPatch
	}
	kept := r.optionalScopes[client][:0]
	for _, held := range r.optionalScopes[client] {
		if held != scopeID {
			kept = append(kept, held)
		}
	}
	r.optionalScopes[client] = kept
	return nil
}

// scopeNames maps scope identifiers to their names in Scopes, keeping an identifier Scopes does not
// name. The caller holds the lock.
func (r *Registry) scopeNames(ids []string) []string {
	names := make([]string, 0, len(ids))
	for _, scopeID := range ids {
		name := scopeID
		for scopeName, id := range r.Scopes {
			if id == scopeID {
				name = scopeName
			}
		}
		names = append(names, name)
	}
	return names
}

func (r *Registry) AttachScope(client keycloak.ClientUUID, scopeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultScopes[client] = append(r.defaultScopes[client], scopeID)
}

func (r *Registry) ServiceAccountUser(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID) (keycloak.User, error) {
	if err := ctx.Err(); err != nil {
		return keycloak.User{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailGet != nil {
		return keycloak.User{}, r.FailGet
	}
	if _, ok := r.clients[client]; !ok {
		return keycloak.User{}, keycloak.ErrNotFound
	}
	user, ok := r.serviceAccounts[client]
	if !ok {
		return keycloak.User{}, keycloak.ErrNotFound
	}
	return user, nil
}

func (r *Registry) FindClients(ctx context.Context, _ keycloak.Realm, clientID string) ([]keycloak.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailGet != nil {
		return nil, r.FailGet
	}
	var out []keycloak.Client
	for _, client := range r.clients {
		if client.ClientID == clientID {
			out = append(out, copyClient(client))
		}
	}
	return out, nil
}

func (r *Registry) ClientScopeID(ctx context.Context, _ keycloak.Realm, name string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailGet != nil {
		return "", r.FailGet
	}
	scope, ok := r.Scopes[name]
	if !ok {
		return "", keycloak.ErrNotFound
	}
	return scope, nil
}

func (r *Registry) RemoveDefaultClientScope(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID, scopeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailPatch != nil {
		return r.FailPatch
	}
	if _, ok := r.clients[client]; !ok {
		return keycloak.ErrNotFound
	}
	kept := r.defaultScopes[client][:0]
	for _, held := range r.defaultScopes[client] {
		if held != scopeID {
			kept = append(kept, held)
		}
	}
	r.defaultScopes[client] = kept
	return nil
}

func (r *Registry) AddDefaultClientScope(ctx context.Context, _ keycloak.Realm, client keycloak.ClientUUID, scopeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailPatch != nil {
		return r.FailPatch
	}
	if _, ok := r.clients[client]; !ok {
		return keycloak.ErrNotFound
	}
	for _, name := range r.defaultScopes[client] {
		if name == scopeID {
			return nil
		}
	}
	r.defaultScopes[client] = append(r.defaultScopes[client], scopeID)
	return nil
}
