package keycloak

// The registration path's port: clients and the admin events that attribute a change to one.
//
// It is a second interface rather than more methods on AdminClient because it is held by a second
// credential. TDD-identity-control-003 gives the registration path its own Keycloak client,
// identity-control-registration, holding manage-clients, view-clients and view-events, and the
// Principal path keeps users only. The composition root builds one Admin per credential and hands
// each path the interface its credential can serve, so the Principal path has no client method to
// call even by mistake.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ClientUUID is Keycloak's internal identifier for a client, the one its Admin API paths carry. It
// is not the clientId a caller names, which is why it is a type of its own.
type ClientUUID string

// AttrAccessTokenLifespan is the client attribute that overrides the realm's access token lifespan,
// in seconds.
const AttrAccessTokenLifespan = "access.token.lifespan"

// Client is the subset of a client's representation the reconciler compares.
type Client struct {
	ID           ClientUUID
	ClientID     string
	Enabled      bool
	RedirectURIs []string

	// AccessTokenLifespan is the client's override in seconds, and 0 when it has none, in which
	// case the realm's lifespan applies. The reconciler treats an absent override as a divergence:
	// STD-IAM-002 §3.3 derives every client's lifetime from its audience, and the realm default is
	// not that derivation.
	AccessTokenLifespan int
}

// ClientPatch is a change to a client. A nil field is left as it is.
type ClientPatch struct {
	Enabled             *bool
	RedirectURIs        *[]string
	AccessTokenLifespan *int
}

// AdminEvent is one admin event on a client: who changed it, and when.
type AdminEvent struct {
	Time          time.Time
	OperationType string
	ResourcePath  string

	// UserID is the Keycloak user whose credential made the change: an administrator in the
	// console, or a service account. It is the actor a drift exception names.
	UserID string
}

// ClientID is the client the event's resource path names, or "" for an event on something else.
func (e AdminEvent) ClientID() ClientUUID {
	rest, ok := strings.CutPrefix(e.ResourcePath, "clients/")
	if !ok {
		return ""
	}
	client, _, _ := strings.Cut(rest, "/")
	return ClientUUID(client)
}

// ClientRegistry is the registration path's surface: read and change a client, and read the admin
// events that attribute a change to one.
type ClientRegistry interface {
	// GetClient returns the client, or ErrNotFound when the realm has none by that identifier.
	GetClient(ctx context.Context, realm Realm, client ClientUUID) (Client, error)

	// PatchClient applies the patch and leaves every other field as it is.
	PatchClient(ctx context.Context, realm Realm, client ClientUUID, patch ClientPatch) error

	// ClientAdminEvents returns every admin event on a client since the given time, newest first.
	// It fails with ErrForbidden when the credential cannot read admin events, which the reconciler
	// reads as attribution being unavailable.
	ClientAdminEvents(ctx context.Context, realm Realm, since time.Time) ([]AdminEvent, error)

	// ServiceAccountUserID is the Keycloak user this credential acts as. An admin event it caused
	// is the reconciler's own repair, never a change to attribute to someone.
	ServiceAccountUserID(ctx context.Context) (string, error)
}

var _ ClientRegistry = (*Admin)(nil)

func (a *Admin) clientPath(realm Realm, client ClientUUID) string {
	return fmt.Sprintf("/admin/realms/%s/clients/%s", url.PathEscape(string(realm)), url.PathEscape(string(client)))
}

// GetClient reads one client.
func (a *Admin) GetClient(ctx context.Context, realm Realm, client ClientUUID) (Client, error) {
	if client == "" {
		return Client{}, errors.New("keycloak: a client identifier is required")
	}
	representation, err := a.clientRepresentation(ctx, realm, client)
	if err != nil {
		return Client{}, err
	}
	return clientFrom(representation)
}

// PatchClient reads the whole representation, changes the patched fields, and writes it back.
//
// The whole representation rather than the patched fields alone, because an update that omits
// attributes is not a documented no-op for them, and a lifespan repair that cleared the client's
// PKCE method would be a worse drift than the one it repaired.
func (a *Admin) PatchClient(ctx context.Context, realm Realm, client ClientUUID, patch ClientPatch) error {
	if client == "" {
		return errors.New("keycloak: a client identifier is required")
	}
	representation, err := a.clientRepresentation(ctx, realm, client)
	if err != nil {
		return err
	}
	if patch.Enabled != nil {
		representation["enabled"] = *patch.Enabled
	}
	if patch.RedirectURIs != nil {
		representation["redirectUris"] = append([]string{}, *patch.RedirectURIs...)
	}
	if patch.AccessTokenLifespan != nil {
		attributes, _ := representation["attributes"].(map[string]any)
		if attributes == nil {
			attributes = map[string]any{}
		}
		attributes[AttrAccessTokenLifespan] = strconv.Itoa(*patch.AccessTokenLifespan)
		representation["attributes"] = attributes
	}
	// Not marked mutating: a PUT of a whole representation is idempotent, so a lost response costs
	// a repeated call rather than a duplicated effect.
	response, err := a.do(ctx, http.MethodPut, a.clientPath(realm, client), nil, representation, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

func (a *Admin) clientRepresentation(ctx context.Context, realm Realm, client ClientUUID) (map[string]any, error) {
	response, err := a.do(ctx, http.MethodGet, a.clientPath(realm, client), nil, nil, false)
	if err != nil {
		return nil, err
	}
	defer response.Close()
	var representation map[string]any
	if err := json.Unmarshal(response.body, &representation); err != nil {
		return nil, fmt.Errorf("keycloak: decode client: %w", err)
	}
	return representation, nil
}

func clientFrom(representation map[string]any) (Client, error) {
	client := Client{}
	client.ID = ClientUUID(stringField(representation, "id"))
	client.ClientID = stringField(representation, "clientId")
	client.Enabled, _ = representation["enabled"].(bool)
	if uris, ok := representation["redirectUris"].([]any); ok {
		for _, uri := range uris {
			if value, ok := uri.(string); ok {
				client.RedirectURIs = append(client.RedirectURIs, value)
			}
		}
	}
	attributes, _ := representation["attributes"].(map[string]any)
	if raw, ok := attributes[AttrAccessTokenLifespan].(string); ok && strings.TrimSpace(raw) != "" {
		lifespan, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return Client{}, fmt.Errorf("keycloak: client %s carries an unreadable %s", client.ClientID, AttrAccessTokenLifespan)
		}
		client.AccessTokenLifespan = lifespan
	}
	return client, nil
}

func stringField(representation map[string]any, name string) string {
	value, _ := representation[name].(string)
	return value
}

// adminEventPage is one page of the admin-event read, and adminEventPages bounds the read. Ten
// thousand client events inside one sweep interval is an incident on its own, and reading on
// would make the sweep's cost a function of that incident.
const (
	adminEventPage  = 100
	adminEventPages = 100
)

// ErrTooManyEvents means more client admin events fell inside the window than one read takes.
// The reconciler treats it as attribution being unavailable, not as the events it did read:
// attributing from part of the record could name the wrong actor.
var ErrTooManyEvents = errors.New("keycloak: more client admin events than one sweep reads")

// ClientAdminEvents reads the realm's client admin events since the given time.
//
// Keycloak filters admin events by date, not by instant, and the date is read in the server's
// time zone. The query therefore asks from the day before and filters to the instant here.
func (a *Admin) ClientAdminEvents(ctx context.Context, realm Realm, since time.Time) ([]AdminEvent, error) {
	var events []AdminEvent
	path := fmt.Sprintf("/admin/realms/%s/admin-events", url.PathEscape(string(realm)))
	for page := 0; page < adminEventPages; page++ {
		query := url.Values{}
		query.Set("resourceTypes", "CLIENT")
		query.Set("dateFrom", since.UTC().AddDate(0, 0, -1).Format("2006-01-02"))
		query.Set("first", strconv.Itoa(page*adminEventPage))
		query.Set("max", strconv.Itoa(adminEventPage))

		response, err := a.do(ctx, http.MethodGet, path, query, nil, false)
		if err != nil {
			return nil, err
		}
		var representations []adminEventRepresentation
		decodeErr := json.Unmarshal(response.body, &representations)
		response.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("keycloak: decode admin events: %w", decodeErr)
		}

		reachedSince := false
		for _, representation := range representations {
			event := representation.toEvent()
			if event.Time.Before(since) {
				reachedSince = true
				continue
			}
			events = append(events, event)
		}
		if len(representations) < adminEventPage || reachedSince {
			sort.SliceStable(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
			return events, nil
		}
	}
	return nil, ErrTooManyEvents
}

type adminEventRepresentation struct {
	Time          int64  `json:"time"`
	OperationType string `json:"operationType"`
	ResourcePath  string `json:"resourcePath"`
	AuthDetails   struct {
		UserID string `json:"userId"`
	} `json:"authDetails"`
}

func (r adminEventRepresentation) toEvent() AdminEvent {
	return AdminEvent{
		Time:          time.UnixMilli(r.Time).UTC(),
		OperationType: r.OperationType,
		ResourcePath:  r.ResourcePath,
		UserID:        r.AuthDetails.UserID,
	}
}

// ServiceAccountUserID reads the sub claim of this credential's own access token: for a service
// account, the Keycloak user it acts as. The token came from the token endpoint over this
// client's own connection, so it is read without verifying a signature; it is never accepted
// from anywhere else.
func (a *Admin) ServiceAccountUserID(ctx context.Context) (string, error) {
	token, err := a.accessToken(ctx)
	if err != nil {
		return "", err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("keycloak: the access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("keycloak: the access token payload is not base64url")
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Subject == "" {
		return "", errors.New("keycloak: the access token names no subject")
	}
	return claims.Subject, nil
}
