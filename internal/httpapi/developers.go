package httpapi

// Application developer standing at the transport (ADR-IAM-003 §5.3, TDD-identity-control-003
// §Application Developers). Granting and revoking it are a provider's. A caller holding it may
// create a registration, within the bounds the service holds, and nothing else it did not already
// own.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/registration"
)

// creator serves the registration route to a provider, and to a caller holding application
// developer standing, read before the body is.
func (h *Registrations) creator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := callerPrincipal(r)
		if !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		if IsProvider(r.Context()) {
			next(w, r)
			return
		}
		developer, err := h.registrar.IsApplicationDeveloper(r.Context(), principal)
		if err != nil {
			httpapi.Problem(w, r, httpapi.Internal, "The application developer standing could not be read")
			return
		}
		if !developer {
			httpapi.Problem(w, r, httpapi.Forbidden,
				"Creating a registration requires provider authority or application developer standing")
			return
		}
		next(w, r)
	}
}

// ApplicationDevelopers handles GET /v1/application-developers, a provider's.
func (h *Registrations) ApplicationDevelopers(w http.ResponseWriter, r *http.Request) {
	developers, err := h.registrar.ApplicationDevelopers(r.Context())
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The application developers could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"developers": developers})
}

type grantDeveloperRequest struct {
	Principal string `json:"principal_id"`
}

// GrantApplicationDeveloper handles POST /v1/application-developers, a provider's, with a reason.
func (h *Registrations) GrantApplicationDeveloper(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Granting the standing requires an X-Administrative-Reason header")
		return
	}
	var body grantDeveloperRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid standing document")
		return
	}
	developer, err := id.Parse(strings.TrimSpace(body.Principal))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	if err := h.registrar.GrantApplicationDeveloper(r.Context(), registration.DeveloperChange{
		Principal: developer, ChangedBy: principal, Reason: reason}); err != nil {
		writeDeveloperError(w, r, err)
		return
	}
	h.developersAfter(w, r, http.StatusCreated)
}

// DeveloperAction handles POST /v1/application-developers/{principal_id}:revoke, a provider's, with
// a reason.
func (h *Registrations) DeveloperAction(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	raw, action, _ := strings.Cut(r.PathValue("developer_action"), ":")
	if action != "revoke" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such standing action")
		return
	}
	developer, err := id.Parse(raw)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Revoking the standing requires an X-Administrative-Reason header")
		return
	}
	if err := h.registrar.RevokeApplicationDeveloper(r.Context(), registration.DeveloperChange{
		Principal: developer, ChangedBy: principal, Reason: reason}); err != nil {
		writeDeveloperError(w, r, err)
		return
	}
	h.developersAfter(w, r, http.StatusOK)
}

// developersAfter answers a standing change with the grants as they now stand.
func (h *Registrations) developersAfter(w http.ResponseWriter, r *http.Request, status int) {
	developers, err := h.registrar.ApplicationDevelopers(r.Context())
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The standing changed, and the application developers could not be read")
		return
	}
	writeJSON(w, status, map[string]any{"developers": developers})
}

func writeDeveloperError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, registration.ErrOwnerNotEligible), errors.Is(err, registration.ErrInvalid):
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, registration.ErrAlreadyDeveloper):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, registration.ErrDeveloperNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, err.Error())
	default:
		httpapi.Problem(w, r, httpapi.Internal, "The standing change could not be made")
	}
}
