package keycloakfake

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

var _ keycloak.FirstCredential = (*Client)(nil)

// UserRequiredActions answers the actions the kernel demands of a user: what its creation asked for,
// less what a sign-in or SetRequiredActions changed.
func (c *Client) UserRequiredActions(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.FailSecurity != nil {
		return nil, c.FailSecurity
	}
	entry, ok := c.users[userID]
	if !ok || entry.realm != realm {
		return nil, keycloak.ErrNotFound
	}
	return slices.Clone(entry.requiredActions), nil
}

// SetTemporaryPassword replaces the user's password credential with a new one and keeps
// UPDATE_PASSWORD outstanding, as the kernel's reset-password with temporary on does. The fake keeps
// the value only so a test can assert what was set; nothing outside a test reads it.
func (c *Client) SetTemporaryPassword(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID, value string) error {
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
	c.Calls.SetTemporaryPassword++
	c.nextID++
	s := c.security[userID]
	kept := s.Credentials[:0:0]
	for _, credential := range s.Credentials {
		if credential.Type != keycloak.PasswordCredential {
			kept = append(kept, credential)
		}
	}
	created := time.Now().UTC()
	if c.Now != nil {
		created = c.Now().UTC()
	}
	s.Credentials = append(kept, keycloak.Credential{ID: fmt.Sprintf("kc-cred-%04d", c.nextID),
		Type: keycloak.PasswordCredential, Created: created})
	c.setSecurityLocked(userID, s)
	if !slices.Contains(entry.requiredActions, keycloak.ActionUpdatePassword) {
		entry.requiredActions = append(entry.requiredActions, keycloak.ActionUpdatePassword)
	}
	c.users[userID] = entry
	if c.temporary == nil {
		c.temporary = map[keycloak.UserID]string{}
	}
	c.temporary[userID] = value
	return nil
}

// ChoosePassword models the person's first sign-in: the kernel requires a new password, replaces the
// credential, and drops UPDATE_PASSWORD.
func (c *Client) ChoosePassword(userID keycloak.UserID, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.users[userID]
	entry.requiredActions = slices.DeleteFunc(slices.Clone(entry.requiredActions),
		func(a string) bool { return a == keycloak.ActionUpdatePassword })
	c.users[userID] = entry
	c.nextID++
	s := c.security[userID]
	kept := s.Credentials[:0:0]
	for _, credential := range s.Credentials {
		if credential.Type != keycloak.PasswordCredential {
			kept = append(kept, credential)
		}
	}
	s.Credentials = append(kept, keycloak.Credential{ID: fmt.Sprintf("kc-cred-%04d", c.nextID),
		Type: keycloak.PasswordCredential, Created: at.UTC()})
	c.setSecurityLocked(userID, s)
	delete(c.temporary, userID)
}

// TemporaryPassword returns the value last set with SetTemporaryPassword, for a test's assertion.
func (c *Client) TemporaryPassword(userID keycloak.UserID) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.temporary[userID]
	return value, ok
}

// SeedPerson records a human user under the given kernel identifier, owing UPDATE_PASSWORD and holding
// no credential, as the creation path leaves one. A test that writes the identifier to a shared
// database names it, so it never meets another test's.
func (c *Client) SeedPerson(realm keycloak.Realm, userID keycloak.UserID, username string, principalID id.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users[userID] = stored{realm: realm,
		user: keycloak.User{ID: userID, Username: username, Enabled: true, PrincipalID: principalID,
			SubjectType: keycloak.SubjectHuman},
		requiredActions: []string{keycloak.ActionUpdatePassword}}
}
