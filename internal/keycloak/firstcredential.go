package keycloak

// The Admin API calls of a first credential (ADR-IAM-010, TDD-identity-control-005 2.12.0 §A First
// Credential): read whether the user still owes UPDATE_PASSWORD, set a temporary password, and, at
// its lapse, delete it through DeleteCredential. identity-kernel's compat suite proves each against
// the pinned kernel.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
)

// PasswordCredential is the kernel's credential type of a password.
const PasswordCredential = "password"

// FirstCredential is what the first-credential path calls. *Admin implements it with the Principal
// credential, which holds manage-users and view-users.
type FirstCredential interface {
	UserRequiredActions(ctx context.Context, realm Realm, userID UserID) ([]string, error)
	SetTemporaryPassword(ctx context.Context, realm Realm, userID UserID, value string) error
	UserCredentials(ctx context.Context, realm Realm, userID UserID) ([]Credential, error)
	DeleteCredential(ctx context.Context, realm Realm, userID UserID, credentialID string) error
}

// requiredActionsRepresentation is the one field of the user representation this call reads. The
// User type does not carry it, so no other path starts depending on it unseen.
type requiredActionsRepresentation struct {
	RequiredActions []string `json:"requiredActions"`
}

// UserRequiredActions reads the actions the kernel demands of the user at its next sign-in.
func (a *Admin) UserRequiredActions(ctx context.Context, realm Realm, userID UserID) ([]string, error) {
	if userID == "" {
		return nil, errors.New("keycloak: a user identifier is required")
	}
	response, err := a.do(ctx, http.MethodGet, a.userPath(realm, userID), nil, nil, false)
	if err != nil {
		return nil, err
	}
	defer response.Close()
	var representation requiredActionsRepresentation
	if err := json.Unmarshal(response.body, &representation); err != nil {
		return nil, fmt.Errorf("keycloak: decode the user's required actions: %w", err)
	}
	return representation.RequiredActions, nil
}

// OwesPassword reports whether a user's required actions still include ActionUpdatePassword: it has never
// set a password of its own.
func OwesPassword(actions []string) bool { return slices.Contains(actions, ActionUpdatePassword) }

// SetTemporaryPassword sets the user's password with temporary on: "Set up a new password for the
// user", after which "the user must change the password at the first login" (Keycloak Admin REST API
// and Server Administration Guide, ADR-IAM-010 [R9][R10]).
//
// The value is in the request body and nowhere else: no error, log or return value of this client
// carries a request body, and the kernel's admin event records the path without the representation
// (identity-kernel compat). Not marked mutating: the same value set twice is the same state, so a
// lost response is retried rather than read back.
func (a *Admin) SetTemporaryPassword(ctx context.Context, realm Realm, userID UserID, value string) error {
	if userID == "" || value == "" {
		return errors.New("keycloak: a user identifier and a value are required")
	}
	response, err := a.do(ctx, http.MethodPut, a.userPath(realm, userID)+"/reset-password", nil,
		map[string]any{"type": PasswordCredential, "value": value, "temporary": true}, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}
