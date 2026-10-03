package keycloak

// The Admin API calls that contain a user (TDD-identity-control-005 §Containment as Built): enable
// or disable it, end its sessions, delete one credential. Each is idempotent, so none is marked
// mutating: a lost response costs a repeated call and a read-back, never a duplicated effect.
// identity-kernel's compat/user_containment_test.go proves each against the pinned kernel.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// Containment is what the security operation executor calls. *Admin implements it with the
// Principal credential, which holds manage-users and view-users.
type Containment interface {
	SecurityReader
	GetUser(ctx context.Context, realm Realm, userID UserID) (User, error)
	DisableUser(ctx context.Context, realm Realm, userID UserID) error
	EnableUser(ctx context.Context, realm Realm, userID UserID) error
	LogoutUser(ctx context.Context, realm Realm, userID UserID) error
	DeleteCredential(ctx context.Context, realm Realm, userID UserID, credentialID string) error
}

// EnableUser sets the user enabled, with a partial update that keeps its attributes (compat suite).
func (a *Admin) EnableUser(ctx context.Context, realm Realm, userID UserID) error {
	if userID == "" {
		return errors.New("keycloak: a user identifier is required")
	}
	response, err := a.do(ctx, http.MethodPut, a.userPath(realm, userID), nil, map[string]any{"enabled": true}, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

// LogoutUser ends every session the user holds: "Remove all user sessions associated with the user".
func (a *Admin) LogoutUser(ctx context.Context, realm Realm, userID UserID) error {
	if userID == "" {
		return errors.New("keycloak: a user identifier is required")
	}
	response, err := a.do(ctx, http.MethodPost, a.userPath(realm, userID)+"/logout", nil, nil, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

// DeleteCredential removes one of the user's credentials. A credential already gone is ErrNotFound,
// which the executor reads as applied once the read-back agrees.
func (a *Admin) DeleteCredential(ctx context.Context, realm Realm, userID UserID, credentialID string) error {
	if userID == "" || credentialID == "" {
		return errors.New("keycloak: a user and a credential identifier are required")
	}
	response, err := a.do(ctx, http.MethodDelete,
		a.userPath(realm, userID)+"/credentials/"+url.PathEscape(credentialID), nil, nil, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

var _ Containment = (*Admin)(nil)
