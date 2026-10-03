package httpapi

// A provider's reads of another Principal (TDD-identity-control-005 §Read Authorization and
// Disclosure). Every route here is providerOnly, and every read is recorded by the service before
// it is answered.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/identity-control/internal/investigation"
)

// Investigator is the read path the handler serves.
type Investigator interface {
	Search(ctx context.Context, actor investigation.Actor, query string) ([]investigation.Summary, error)
	Principal(ctx context.Context, actor investigation.Actor, principalID id.UUID) (investigation.Principal, error)
	Sessions(ctx context.Context, actor investigation.Actor, principalID id.UUID) ([]investigation.Session, error)
	Authenticators(ctx context.Context, actor investigation.Actor, principalID id.UUID) ([]investigation.Authenticator, error)
	FederationLinks(ctx context.Context, actor investigation.Actor, principalID id.UUID) ([]investigation.FederationLink, error)
	Findings(ctx context.Context, actor investigation.Actor, principalID id.UUID) ([]investigation.Finding, error)
}

// Investigation is the handler.
type Investigation struct {
	reader Investigator
}

// NewInvestigation constructs the handler.
func NewInvestigation(reader Investigator) (*Investigation, error) {
	if reader == nil {
		return nil, errors.New("httpapi: an investigator is required")
	}
	return &Investigation{reader: reader}, nil
}

// actor is who reads, as the request established it: the token's Principal, whether its provider
// authority is emergency, the route pattern, and the correlation identifier.
func actor(r *http.Request) investigation.Actor {
	principal, _ := callerPrincipal(r)
	correlation := ""
	if value, ok := observability.CorrelationID(r.Context()); ok {
		correlation = value.String()
	}
	return investigation.Actor{Principal: principal, Emergency: ProviderEmergency(r.Context()),
		Route: r.Pattern, Correlation: correlation}
}

func subjectOf(w http.ResponseWriter, r *http.Request) (id.UUID, bool) {
	subject, err := id.Parse(r.PathValue("principal_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return id.UUID{}, false
	}
	return subject, true
}

func writeInvestigationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, investigation.ErrQuery):
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, investigation.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such Principal")
	case errors.Is(err, investigation.ErrUnlinked):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "The Principal has no kernel user to read")
	case kernelFailure(err):
		httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The identity kernel did not answer; retry")
	default:
		httpapi.Problem(w, r, httpapi.Internal, "The read could not be served")
	}
}

// Search handles GET /v1/principals:search?q=.
func (h *Investigation) Search(w http.ResponseWriter, r *http.Request) {
	results, err := h.reader.Search(r.Context(), actor(r), strings.TrimSpace(r.URL.Query().Get("q")))
	if err != nil {
		writeInvestigationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"principals": results})
}

// Principal handles GET /v1/principals/{principal_id}.
func (h *Investigation) Principal(w http.ResponseWriter, r *http.Request) {
	subject, ok := subjectOf(w, r)
	if !ok {
		return
	}
	principal, err := h.reader.Principal(r.Context(), actor(r), subject)
	if err != nil {
		writeInvestigationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, principal)
}

// list serves one of the Principal's security-state lists under a key.
func list[T any](read func(context.Context, investigation.Actor, id.UUID) ([]T, error), key string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject, ok := subjectOf(w, r)
		if !ok {
			return
		}
		items, err := read(r.Context(), actor(r), subject)
		if err != nil {
			writeInvestigationError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{key: items})
	}
}

// Sessions handles GET /v1/principals/{principal_id}/sessions.
func (h *Investigation) Sessions(w http.ResponseWriter, r *http.Request) {
	list(h.reader.Sessions, "sessions")(w, r)
}

// Authenticators handles GET /v1/principals/{principal_id}/authenticators.
func (h *Investigation) Authenticators(w http.ResponseWriter, r *http.Request) {
	list(h.reader.Authenticators, "authenticators")(w, r)
}

// FederationLinks handles GET /v1/principals/{principal_id}/federation-links.
func (h *Investigation) FederationLinks(w http.ResponseWriter, r *http.Request) {
	list(h.reader.FederationLinks, "federation_links")(w, r)
}

// Findings handles GET /v1/principals/{principal_id}/findings.
func (h *Investigation) Findings(w http.ResponseWriter, r *http.Request) {
	list(h.reader.Findings, "findings")(w, r)
}
