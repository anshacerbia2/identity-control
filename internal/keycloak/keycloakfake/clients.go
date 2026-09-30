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
	FailGet   error
	FailPatch error

	// FailEvents is returned by ClientAdminEvents when set. keycloak.ErrForbidden is a credential
	// without view-events.
	FailEvents error

	// Now is the clock admin events are stamped with. Nil uses time.Now.
	Now func() time.Time

	Patches int

	// FailCreate is returned by CreateClient when set. With AmbiguousCreateSucceeds, the client is
	// created anyway: a response lost after the kernel committed.
	FailCreate              error
	AmbiguousCreateSucceeds bool

	// Scopes are the realm's client scopes, by name, with their identifiers.
	Scopes map[string]string

	clients       map[keycloak.ClientUUID]keycloak.Client
	specs         map[keycloak.ClientUUID]keycloak.ClientSpec
	defaultScopes map[keycloak.ClientUUID][]string
	events        []keycloak.AdminEvent
}

// NewRegistry returns an empty registry acting as the given service account.
func NewRegistry(serviceAccount string) *Registry {
	return &Registry{ServiceAccount: serviceAccount, clients: map[keycloak.ClientUUID]keycloak.Client{},
		specs: map[keycloak.ClientUUID]keycloak.ClientSpec{}, defaultScopes: map[keycloak.ClientUUID][]string{},
		Scopes: map[string]string{"scnehaux-internal": "scope-internal", "scnehaux-provider": "scope-provider",
			"scnehaux-external": "scope-external"}}
}

var _ keycloak.ClientRegistry = (*Registry)(nil)

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}

// Put stores a client as it stands, recording no admin event: the state before the test begins.
func (r *Registry) Put(client keycloak.Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[client.ID] = copyClient(client)
}

// Remove deletes a client, as a console deletion would, recording its admin event.
func (r *Registry) Remove(actor string, client keycloak.ClientUUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, client)
	r.events = append(r.events, keycloak.AdminEvent{Time: r.now(), OperationType: "DELETE",
		ResourcePath: "clients/" + string(client), UserID: actor})
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

func copyClient(client keycloak.Client) keycloak.Client {
	client.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	return client
}

// Keys returns the public keys the client holds now: what CreateClient was given, as later patches
// left it.
func (r *Registry) Keys(client keycloak.ClientUUID) []keycloak.JWK {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]keycloak.JWK(nil), r.specs[client].Keys...)
}

// Spec returns what CreateClient was given for a client, and its default scopes.
func (r *Registry) Spec(client keycloak.ClientUUID) (keycloak.ClientSpec, []string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	spec, ok := r.specs[client]
	return spec, append([]string(nil), r.defaultScopes[client]...), ok
}

func (r *Registry) CreateClient(ctx context.Context, _ keycloak.Realm, spec keycloak.ClientSpec) (keycloak.ClientUUID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := spec.Validate(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.FailCreate != nil && !r.AmbiguousCreateSucceeds {
		return "", r.FailCreate
	}
	for _, existing := range r.clients {
		if existing.ClientID == spec.ClientID {
			return "", keycloak.ErrConflict
		}
	}
	// A UUID, as the kernel's identifiers are: they are unique across every test sharing a database.
	minted, err := id.NewV7()
	if err != nil {
		return "", err
	}
	client := keycloak.ClientUUID(minted.String())
	r.clients[client] = keycloak.Client{ID: client, ClientID: spec.ClientID, Enabled: true,
		RedirectURIs: append([]string(nil), spec.RedirectURIs...), AccessTokenLifespan: spec.AccessTokenLifespan}
	r.specs[client] = spec
	r.events = append(r.events, keycloak.AdminEvent{Time: r.now(), OperationType: "CREATE",
		ResourcePath: "clients/" + string(client), UserID: r.ServiceAccount})
	if r.FailCreate != nil {
		return "", r.FailCreate
	}
	return client, nil
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
