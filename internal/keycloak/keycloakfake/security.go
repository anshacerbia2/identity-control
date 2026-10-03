package keycloakfake

import (
	"context"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// Security is what the fake holds for one user's security state. A test sets it with SetSecurity.
type Security struct {
	Sessions    []keycloak.Session
	Credentials []keycloak.Credential
	Links       []keycloak.FederatedIdentity
}

// SetSecurity records a user's sessions, credentials and federation links.
func (c *Client) SetSecurity(userID keycloak.UserID, security Security) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.security == nil {
		c.security = map[keycloak.UserID]Security{}
	}
	c.security[userID] = security
}

func (c *Client) readSecurity(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) (Security, error) {
	if err := ctx.Err(); err != nil {
		return Security{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailSecurity != nil {
		return Security{}, c.FailSecurity
	}
	stored, ok := c.users[userID]
	if !ok || stored.realm != realm {
		return Security{}, keycloak.ErrNotFound
	}
	c.Calls.SecurityReads++
	return c.security[userID], nil
}

func (c *Client) UserSessions(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) ([]keycloak.Session, error) {
	s, err := c.readSecurity(ctx, realm, userID)
	return append([]keycloak.Session{}, s.Sessions...), err
}

func (c *Client) UserCredentials(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) ([]keycloak.Credential, error) {
	s, err := c.readSecurity(ctx, realm, userID)
	return append([]keycloak.Credential{}, s.Credentials...), err
}

func (c *Client) UserFederatedIdentities(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) ([]keycloak.FederatedIdentity, error) {
	s, err := c.readSecurity(ctx, realm, userID)
	return append([]keycloak.FederatedIdentity{}, s.Links...), err
}

var _ keycloak.SecurityReader = (*Client)(nil)
