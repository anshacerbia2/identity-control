package keycloak

// The kernel's native event store, read through the supported Admin API (TDD-identity-control-007,
// TDD-identity-kernel-003 §Reconciliation Source). User events and admin events are read the same
// way: newest first, filtered by date, every page, bounded.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// The kinds of kernel event.
const (
	KindUserEvent  = "user"
	KindAdminEvent = "admin"
)

// KernelEvent is one event as the kernel recorded it. Representation is an admin event's resource
// as written, unparsed; the record redacts it before keeping it.
type KernelEvent struct {
	Kind           string
	ID             string
	Time           time.Time
	Type           string
	UserID         string
	ClientID       string
	SessionID      string
	IPAddress      string
	Error          string
	ResourceType   string
	ResourcePath   string
	Details        map[string]string
	Representation string
}

// EventStore reads the kernel's native event store. *Admin implements it.
type EventStore interface {
	// KernelEvents reads every event of the kind recorded at or after since, newest first. Truncated
	// is a read that stopped at its bound before reaching since: what it returns is the newest events,
	// not necessarily all of them.
	KernelEvents(ctx context.Context, realm Realm, kind string, since time.Time) (events []KernelEvent, truncated bool, err error)
}

// kernelEventPage is one page of the read, and kernelEventPages bounds it: 50 000 events of one kind
// inside one sweep window is an operational signal, and reading on would make the sweep's cost a
// function of whatever produced them.
const (
	kernelEventPage  = 500
	kernelEventPages = 100
)

type userEventRepresentation struct {
	ID        string            `json:"id"`
	Time      int64             `json:"time"`
	Type      string            `json:"type"`
	ClientID  string            `json:"clientId"`
	UserID    string            `json:"userId"`
	SessionID string            `json:"sessionId"`
	IPAddress string            `json:"ipAddress"`
	Error     string            `json:"error"`
	Details   map[string]string `json:"details"`
}

type kernelAdminEventRepresentation struct {
	ID            string `json:"id"`
	Time          int64  `json:"time"`
	OperationType string `json:"operationType"`
	ResourceType  string `json:"resourceType"`
	ResourcePath  string `json:"resourcePath"`
	Error         string `json:"error"`
	AuthDetails   struct {
		ClientID  string `json:"clientId"`
		UserID    string `json:"userId"`
		IPAddress string `json:"ipAddress"`
	} `json:"authDetails"`
	Representation string `json:"representation"`
}

// KernelEvents reads the realm's events of one kind since the given time. Keycloak filters by date in
// the server's time zone, so the query asks from the day before and filters to the instant here, as
// ClientAdminEvents does.
func (a *Admin) KernelEvents(ctx context.Context, realm Realm, kind string, since time.Time) ([]KernelEvent, bool, error) {
	var resource string
	switch kind {
	case KindUserEvent:
		resource = "events"
	case KindAdminEvent:
		resource = "admin-events"
	default:
		return nil, false, fmt.Errorf("keycloak: unknown event kind %q", kind)
	}
	path := fmt.Sprintf("/admin/realms/%s/%s", url.PathEscape(string(realm)), resource)
	var events []KernelEvent
	for page := 0; page < kernelEventPages; page++ {
		query := url.Values{}
		query.Set("dateFrom", since.UTC().AddDate(0, 0, -1).Format("2006-01-02"))
		query.Set("first", strconv.Itoa(page*kernelEventPage))
		query.Set("max", strconv.Itoa(kernelEventPage))
		response, err := a.do(ctx, http.MethodGet, path, query, nil, false)
		if err != nil {
			return nil, false, err
		}
		pageEvents, err := decodeKernelEvents(kind, response.body)
		response.Close()
		if err != nil {
			return nil, false, err
		}
		reachedSince := false
		for _, event := range pageEvents {
			if event.Time.Before(since) {
				reachedSince = true
				continue
			}
			events = append(events, event)
		}
		if len(pageEvents) < kernelEventPage || reachedSince {
			return events, false, nil
		}
	}
	return events, true, nil
}

func decodeKernelEvents(kind string, body []byte) ([]KernelEvent, error) {
	var events []KernelEvent
	if kind == KindUserEvent {
		var listed []userEventRepresentation
		if err := json.Unmarshal(body, &listed); err != nil {
			return nil, fmt.Errorf("keycloak: decode user events: %w", err)
		}
		for _, r := range listed {
			events = append(events, KernelEvent{Kind: kind, ID: r.ID, Time: time.UnixMilli(r.Time).UTC(), Type: r.Type,
				UserID: r.UserID, ClientID: r.ClientID, SessionID: r.SessionID, IPAddress: r.IPAddress, Error: r.Error,
				Details: r.Details})
		}
		return events, nil
	}
	var listed []kernelAdminEventRepresentation
	if err := json.Unmarshal(body, &listed); err != nil {
		return nil, fmt.Errorf("keycloak: decode admin events: %w", err)
	}
	for _, r := range listed {
		events = append(events, KernelEvent{Kind: kind, ID: r.ID, Time: time.UnixMilli(r.Time).UTC(), Type: r.OperationType,
			UserID: r.AuthDetails.UserID, ClientID: r.AuthDetails.ClientID, IPAddress: r.AuthDetails.IPAddress, Error: r.Error,
			ResourceType: r.ResourceType, ResourcePath: r.ResourcePath, Representation: r.Representation})
	}
	return events, nil
}

// ErrNoEventID is an event the kernel returned without an identifier, which the record cannot key.
var ErrNoEventID = errors.New("keycloak: a kernel event carries no id")

var _ EventStore = (*Admin)(nil)

// UserCreation is one admin event that created a user: when, by which kernel user (the
// service account of the client whose credential made the call), and the principal_id the
// representation sent carried (ADR-IAM-001 §5.11 check 4, amended 2026-10-20).
type UserCreation struct {
	EventID            string
	Time               time.Time
	ActorUserID        string
	ClaimedPrincipalID string
}

// CreationJournal reads the kernel's record of a user's creation. *Admin implements it with a
// credential that holds view-events, the registration credential's (TDD-identity-control-007).
type CreationJournal interface {
	// UserCreations returns every admin event CREATE on the user, newest first. A user whose
	// creation left the kernel's event retention returns none.
	UserCreations(ctx context.Context, realm Realm, user UserID) ([]UserCreation, error)
}

// UserCreations reads the admin events that created the user. The kernel's admin event query takes
// operationTypes, resourceTypes and resourcePath filters (Admin REST API, "Get admin events"), and
// "The Include Representation switch includes JSON documents sent through the admin REST API", which
// is where the principal_id the creation carried is read.
func (a *Admin) UserCreations(ctx context.Context, realm Realm, user UserID) ([]UserCreation, error) {
	if user == "" {
		return nil, errors.New("keycloak: a user identifier is required")
	}
	query := url.Values{}
	query.Set("operationTypes", "CREATE")
	query.Set("resourceTypes", "USER")
	query.Set("resourcePath", "users/"+string(user))
	query.Set("max", strconv.Itoa(kernelEventPage))
	path := fmt.Sprintf("/admin/realms/%s/admin-events", url.PathEscape(string(realm)))
	response, err := a.do(ctx, http.MethodGet, path, query, nil, false)
	if err != nil {
		return nil, err
	}
	events, err := decodeKernelEvents(KindAdminEvent, response.body)
	response.Close()
	if err != nil {
		return nil, err
	}
	return UserCreationsOf(events, user), nil
}

// UserCreationsOf keeps the admin events that created the user, and reads the principal_id each
// one's representation carried. The kernel's filters are applied again here, so a kernel that
// ignored one is not trusted with the answer.
func UserCreationsOf(events []KernelEvent, user UserID) []UserCreation {
	out := []UserCreation{}
	for _, event := range events {
		if event.Kind != KindAdminEvent || event.Type != "CREATE" || event.ResourceType != "USER" ||
			event.ResourcePath != "users/"+string(user) || event.Error != "" {
			continue
		}
		var representation struct {
			Attributes map[string][]string `json:"attributes"`
		}
		claimed := ""
		if json.Unmarshal([]byte(event.Representation), &representation) == nil {
			claimed = firstAttribute(representation.Attributes, AttrPrincipalID)
		}
		out = append(out, UserCreation{EventID: event.ID, Time: event.Time, ActorUserID: event.UserID,
			ClaimedPrincipalID: claimed})
	}
	return out
}

var _ CreationJournal = (*Admin)(nil)
