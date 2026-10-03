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

// EnableUser sets a user enabled.
func (c *Client) EnableUser(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailContainment != nil {
		return c.FailContainment
	}
	entry, ok := c.users[userID]
	if !ok || entry.realm != realm {
		return keycloak.ErrNotFound
	}
	entry.user.Enabled = true
	c.users[userID] = entry
	c.Calls.EnableUser++
	return nil
}

// LogoutUser ends every session of a user.
func (c *Client) LogoutUser(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailContainment != nil {
		return c.FailContainment
	}
	entry, ok := c.users[userID]
	if !ok || entry.realm != realm {
		return keycloak.ErrNotFound
	}
	s := c.security[userID]
	s.Sessions = nil
	c.setSecurityLocked(userID, s)
	c.Calls.Logout++
	return nil
}

// DeleteCredential removes one credential of a user.
func (c *Client) DeleteCredential(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID, credentialID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailContainment != nil {
		return c.FailContainment
	}
	entry, ok := c.users[userID]
	if !ok || entry.realm != realm {
		return keycloak.ErrNotFound
	}
	s := c.security[userID]
	kept := s.Credentials[:0:0]
	found := false
	for _, credential := range s.Credentials {
		if credential.ID == credentialID {
			found = true
			continue
		}
		kept = append(kept, credential)
	}
	if !found {
		return keycloak.ErrNotFound
	}
	s.Credentials = kept
	c.setSecurityLocked(userID, s)
	c.Calls.DeleteCredential++
	return nil
}

// DeleteSession ends one session, whichever user of the realm holds it.
func (c *Client) DeleteSession(ctx context.Context, realm keycloak.Realm, sessionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailContainment != nil {
		return c.FailContainment
	}
	for userID, s := range c.security {
		if entry, ok := c.users[userID]; !ok || entry.realm != realm {
			continue
		}
		for i, session := range s.Sessions {
			if session.ID == sessionID {
				s.Sessions = append(append([]keycloak.Session{}, s.Sessions[:i]...), s.Sessions[i+1:]...)
				c.security[userID] = s
				c.Calls.DeleteSession++
				return nil
			}
		}
	}
	return keycloak.ErrNotFound
}

func (c *Client) setSecurityLocked(userID keycloak.UserID, s Security) {
	if c.security == nil {
		c.security = map[keycloak.UserID]Security{}
	}
	c.security[userID] = s
}

var _ keycloak.Containment = (*Client)(nil)
