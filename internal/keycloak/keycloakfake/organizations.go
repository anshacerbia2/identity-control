package keycloakfake

import (
	"context"
	"fmt"
	"sort"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

type organization struct {
	keycloak.Organization
	members map[keycloak.UserID]bool
}

func (c *Client) organizationsLocked() map[string]*organization {
	if c.organizations == nil {
		c.organizations = map[string]*organization{}
	}
	return c.organizations
}

// FindOrganization finds an Organization by exact name.
func (c *Client) FindOrganization(_ context.Context, _ keycloak.Realm, name string) (keycloak.Organization, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return keycloak.Organization{}, false, c.FailOrganizations
	}
	for _, o := range c.organizationsLocked() {
		if o.Name == name {
			return o.Organization, true, nil
		}
	}
	return keycloak.Organization{}, false, nil
}

// GetOrganization reads one Organization.
func (c *Client) GetOrganization(_ context.Context, _ keycloak.Realm, id string) (keycloak.Organization, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return keycloak.Organization{}, c.FailOrganizations
	}
	o, ok := c.organizationsLocked()[id]
	if !ok {
		return keycloak.Organization{}, fmt.Errorf("organization %s: %w", id, keycloak.ErrNotFound)
	}
	return o.Organization, nil
}

// CreateOrganization creates one, refusing a second of the same name, as the kernel does.
func (c *Client) CreateOrganization(_ context.Context, _ keycloak.Realm, name string, enabled bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return "", c.FailOrganizations
	}
	for _, o := range c.organizationsLocked() {
		if o.Name == name {
			return "", fmt.Errorf("organization %s exists: %w", name, keycloak.ErrConflict)
		}
	}
	c.Calls.CreateOrganization++
	orgID := fmt.Sprintf("org-%d", len(c.organizations)+1)
	c.organizations[orgID] = &organization{
		Organization: keycloak.Organization{ID: orgID, Name: name, Alias: name, Enabled: enabled},
		members:      map[keycloak.UserID]bool{},
	}
	if c.AmbiguousOrganizationCreate {
		c.AmbiguousOrganizationCreate = false
		return "", keycloak.ErrAmbiguous
	}
	return orgID, nil
}

// SetOrganizationEnabled enables or disables one.
func (c *Client) SetOrganizationEnabled(_ context.Context, _ keycloak.Realm, id string, enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return c.FailOrganizations
	}
	o, ok := c.organizationsLocked()[id]
	if !ok {
		return fmt.Errorf("organization %s: %w", id, keycloak.ErrNotFound)
	}
	o.Enabled = enabled
	return nil
}

// OrganizationMembers lists the members, sorted.
func (c *Client) OrganizationMembers(_ context.Context, _ keycloak.Realm, id string) ([]keycloak.UserID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return nil, c.FailOrganizations
	}
	o, ok := c.organizationsLocked()[id]
	if !ok {
		return nil, fmt.Errorf("organization %s: %w", id, keycloak.ErrNotFound)
	}
	members := make([]keycloak.UserID, 0, len(o.members))
	for m := range o.members {
		members = append(members, m)
	}
	sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
	return members, nil
}

// AddOrganizationMember adds a member; an existing one is done.
func (c *Client) AddOrganizationMember(_ context.Context, _ keycloak.Realm, id string, user keycloak.UserID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return c.FailOrganizations
	}
	o, ok := c.organizationsLocked()[id]
	if !ok {
		return fmt.Errorf("organization %s: %w", id, keycloak.ErrNotFound)
	}
	o.members[user] = true
	return nil
}

// RemoveOrganizationMember removes a member; an absent one is done.
func (c *Client) RemoveOrganizationMember(_ context.Context, _ keycloak.Realm, id string, user keycloak.UserID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return c.FailOrganizations
	}
	o, ok := c.organizationsLocked()[id]
	if !ok {
		return fmt.Errorf("organization %s: %w", id, keycloak.ErrNotFound)
	}
	delete(o.members, user)
	return nil
}

// ListOrganizations lists every Organization, sorted by name.
func (c *Client) ListOrganizations(_ context.Context, _ keycloak.Realm) ([]keycloak.Organization, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailOrganizations != nil {
		return nil, c.FailOrganizations
	}
	all := make([]keycloak.Organization, 0, len(c.organizations))
	for _, o := range c.organizationsLocked() {
		all = append(all, o.Organization)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	return all, nil
}

// SetOrganizationMember puts a member in place without the converger, as a hand edit would.
func (c *Client) SetOrganizationMember(id string, user keycloak.UserID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if o, ok := c.organizationsLocked()[id]; ok {
		o.members[user] = true
	}
}

var _ keycloak.TenantOrganizations = (*Client)(nil)
