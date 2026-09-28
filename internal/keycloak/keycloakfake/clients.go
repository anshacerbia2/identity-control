package keycloakfake

import (
	"context"
	"sort"
	"sync"
	"time"

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

	clients map[keycloak.ClientUUID]keycloak.Client
	events  []keycloak.AdminEvent
}

// NewRegistry returns an empty registry acting as the given service account.
func NewRegistry(serviceAccount string) *Registry {
	return &Registry{ServiceAccount: serviceAccount, clients: map[keycloak.ClientUUID]keycloak.Client{}}
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
