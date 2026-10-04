package keycloak

// A user's security state as the kernel holds it: sessions, credentials and federation links
// (TDD-identity-control-005 §Component Design). Read through the supported Admin REST API only;
// no account-console endpoint, no database read, and nothing of a credential but its metadata.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// SecurityReader reads a user's security state. *Admin implements it with the service's own Admin
// API client, which holds view-users.
type SecurityReader interface {
	UserSessions(ctx context.Context, realm Realm, userID UserID) ([]Session, error)
	UserCredentials(ctx context.Context, realm Realm, userID UserID) ([]Credential, error)
	UserFederatedIdentities(ctx context.Context, realm Realm, userID UserID) ([]FederatedIdentity, error)
}

// Session is one of a user's sessions. Its kernel identifier never leaves this service; the IP
// address the kernel records is not carried at all.
type Session struct {
	ID         string
	Started    time.Time
	LastAccess time.Time
	// Clients are the client_ids the session has signed in to, sorted.
	Clients []string
}

// Credential is one authenticator's metadata. The kernel's secret and credential data are never
// decoded: the type, label and creation time are all this service reads.
type Credential struct {
	ID      string
	Type    string
	Label   string
	Created time.Time
	// Remaining is how many recovery codes of a set are unused; nil for every other type.
	Remaining *int
}

// FederatedIdentity is a link from the user to an identity provider's account.
type FederatedIdentity struct {
	Provider string
	UserName string
}

func (a *Admin) userPath(realm Realm, userID UserID) string {
	return fmt.Sprintf("/admin/realms/%s/users/%s", url.PathEscape(string(realm)), url.PathEscape(string(userID)))
}

// getList reads one user sub-resource into out.
func (a *Admin) getList(ctx context.Context, realm Realm, userID UserID, resource string, out any) error {
	if userID == "" {
		return errors.New("keycloak: a user identifier is required")
	}
	response, err := a.do(ctx, http.MethodGet, a.userPath(realm, userID)+"/"+resource, nil, nil, false)
	if err != nil {
		return err
	}
	defer response.Close()
	if err := json.Unmarshal(response.body, out); err != nil {
		return fmt.Errorf("keycloak: decode %s: %w", resource, err)
	}
	return nil
}

type sessionRepresentation struct {
	ID         string            `json:"id"`
	Start      int64             `json:"start"`
	LastAccess int64             `json:"lastAccess"`
	Clients    map[string]string `json:"clients"`
}

// UserSessions lists the user's sessions, newest activity first.
func (a *Admin) UserSessions(ctx context.Context, realm Realm, userID UserID) ([]Session, error) {
	var raw []sessionRepresentation
	if err := a.getList(ctx, realm, userID, "sessions", &raw); err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(raw))
	for _, r := range raw {
		clients := make([]string, 0, len(r.Clients))
		for _, clientID := range r.Clients {
			clients = append(clients, clientID)
		}
		sort.Strings(clients)
		sessions = append(sessions, Session{ID: r.ID, Started: time.UnixMilli(r.Start).UTC(),
			LastAccess: time.UnixMilli(r.LastAccess).UTC(), Clients: clients})
	}
	sort.SliceStable(sessions, func(i, j int) bool { return sessions[i].LastAccess.After(sessions[j].LastAccess) })
	return sessions, nil
}

// credentialRepresentation names the fields read, and only those: secretData and credentialData
// are absent from the struct, so they are never decoded into this process's memory as values.
type credentialRepresentation struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	UserLabel   string `json:"userLabel"`
	CreatedDate int64  `json:"createdDate"`
	// CredentialData is the credential's metadata as a JSON string. The secret is never listed.
	CredentialData string `json:"credentialData"`
}

// RecoveryCodes is the kernel's credential type for a set of recovery codes (ADR-IAM-005 §5.1).
const RecoveryCodes = "recovery-authn-codes"

// remainingCodes reads how many codes of a set are unused, from the metadata the kernel keeps beside
// the hashes ({"remaining":11,"total":12}). Nil when the metadata does not say.
func remainingCodes(credentialData string) *int {
	var data struct {
		Remaining *int `json:"remaining"`
	}
	if json.Unmarshal([]byte(credentialData), &data) != nil {
		return nil
	}
	return data.Remaining
}

// UserCredentials lists the user's authenticators' metadata, oldest first.
func (a *Admin) UserCredentials(ctx context.Context, realm Realm, userID UserID) ([]Credential, error) {
	var raw []credentialRepresentation
	if err := a.getList(ctx, realm, userID, "credentials", &raw); err != nil {
		return nil, err
	}
	credentials := make([]Credential, 0, len(raw))
	for _, r := range raw {
		credential := Credential{ID: r.ID, Type: r.Type, Label: r.UserLabel, Created: time.UnixMilli(r.CreatedDate).UTC()}
		if r.Type == RecoveryCodes {
			credential.Remaining = remainingCodes(r.CredentialData)
		}
		credentials = append(credentials, credential)
	}
	sort.SliceStable(credentials, func(i, j int) bool { return credentials[i].Created.Before(credentials[j].Created) })
	return credentials, nil
}

type federatedIdentityRepresentation struct {
	IdentityProvider string `json:"identityProvider"`
	UserName         string `json:"userName"`
}

// UserFederatedIdentities lists the user's links to identity providers.
func (a *Admin) UserFederatedIdentities(ctx context.Context, realm Realm, userID UserID) ([]FederatedIdentity, error) {
	var raw []federatedIdentityRepresentation
	if err := a.getList(ctx, realm, userID, "federated-identity", &raw); err != nil {
		return nil, err
	}
	links := make([]FederatedIdentity, 0, len(raw))
	for _, r := range raw {
		links = append(links, FederatedIdentity{Provider: r.IdentityProvider, UserName: r.UserName})
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].Provider < links[j].Provider })
	return links, nil
}

var _ SecurityReader = (*Admin)(nil)
