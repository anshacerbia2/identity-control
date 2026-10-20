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

// Consents lists and withdraws a person's consents (TDD-identity-control-005 2.13.0, slice 3b):
// "Get consents granted by the user" and "Revoke consent and offline tokens for particular client
// from user" (Keycloak Admin REST API). identity-kernel's compat/consent_test.go proves both on the
// pinned kernel: the listing names the client and its granted scopes, and a withdrawal ends the
// refresh tokens issued on it. The withdrawal needs manage-users, which the Principal credential holds.
type Consents interface {
	UserConsents(ctx context.Context, realm Realm, userID UserID) ([]Consent, error)
	// RevokeConsent withdraws the consent to one client, named by its clientId. A consent already
	// gone is ErrNotFound, which the executor reads as withdrawn once the listing agrees.
	RevokeConsent(ctx context.Context, realm Realm, userID UserID, clientID string) error
}

// Consent is one client a person consented to: its clientId, the client scopes granted, and when.
type Consent struct {
	ClientID string
	Scopes   []string
	Granted  time.Time
	Updated  time.Time
}

type consentRepresentation struct {
	ClientID            string   `json:"clientId"`
	GrantedClientScopes []string `json:"grantedClientScopes"`
	CreatedDate         int64    `json:"createdDate"`
	LastUpdatedDate     int64    `json:"lastUpdatedDate"`
}

// UserConsents lists the person's consents, by clientId.
func (a *Admin) UserConsents(ctx context.Context, realm Realm, userID UserID) ([]Consent, error) {
	var raw []consentRepresentation
	if err := a.getList(ctx, realm, userID, "consents", &raw); err != nil {
		return nil, err
	}
	consents := make([]Consent, 0, len(raw))
	for _, r := range raw {
		scopes := append([]string{}, r.GrantedClientScopes...)
		sort.Strings(scopes)
		consent := Consent{ClientID: r.ClientID, Scopes: scopes, Granted: time.UnixMilli(r.CreatedDate).UTC()}
		if r.LastUpdatedDate > 0 {
			consent.Updated = time.UnixMilli(r.LastUpdatedDate).UTC()
		}
		consents = append(consents, consent)
	}
	sort.SliceStable(consents, func(i, j int) bool { return consents[i].ClientID < consents[j].ClientID })
	return consents, nil
}

// RevokeConsent withdraws one consent. Not marked mutating: a repeat answers 404, the state wanted.
func (a *Admin) RevokeConsent(ctx context.Context, realm Realm, userID UserID, clientID string) error {
	if userID == "" || clientID == "" {
		return errors.New("keycloak: a user and a client identifier are required")
	}
	response, err := a.do(ctx, http.MethodDelete, a.userPath(realm, userID)+"/consents/"+url.PathEscape(clientID),
		nil, nil, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

var _ Consents = (*Admin)(nil)

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
	// Remaining and Total are how many recovery codes of a set are unused, and how many it began
	// with; nil for every other type.
	Remaining *int
	Total     *int
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

// codeCounts reads how many codes of a set are unused, and how many it began with, from the
// metadata the kernel keeps beside the hashes ({"remaining":11,"total":12}). Nil where it does not say.
func codeCounts(credentialData string) (remaining, total *int) {
	var data struct {
		Remaining *int `json:"remaining"`
		Total     *int `json:"total"`
	}
	if json.Unmarshal([]byte(credentialData), &data) != nil {
		return nil, nil
	}
	return data.Remaining, data.Total
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
			credential.Remaining, credential.Total = codeCounts(r.CredentialData)
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
