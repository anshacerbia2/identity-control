package httpapi

// Registration ownership at the transport (ADR-IAM-003, TDD-identity-control-003 §Registration
// Ownership). A caller is a provider or a registration owner, and the two are kept apart by route:
// providerOnly refuses an owner before any record is read, and owned admits an owner only to a
// registration it owns, answering 404 for any other so an owner cannot learn which exist.

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

// providerOnly serves a route only to a provider. Every route is wrapped in it unless it is one of
// the owner routes, so a route added later is a provider's by default.
func providerOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := CallerScope(r.Context()); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		if !IsProvider(r.Context()) {
			httpapi.Problem(w, r, httpapi.Forbidden, "This route requires provider authority")
			return
		}
		next(w, r)
	}
}

// registrationOf reads the registration a path names. The lifecycle route carries its action in the
// same segment (`{registration_id}:suspend`), so the identifier is the part before the colon.
func registrationOf(r *http.Request) (id.UUID, string, error) {
	raw, action, _ := strings.Cut(r.PathValue("registration_id"), ":")
	registrationID, err := id.Parse(raw)
	return registrationID, action, err
}

// owned serves a route to a provider, and to an owner of the registration the path names when the
// action, if any, is one an owner may take. ownerActions lists those actions; nil means the route
// has none.
func (h *Registrations) owned(next http.HandlerFunc, ownerActions ...string) http.HandlerFunc {
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
		registrationID, action, err := registrationOf(r)
		if err != nil {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
			return
		}
		if action != "" && !contains(ownerActions, action) {
			httpapi.Problem(w, r, httpapi.Forbidden, "This action requires provider authority")
			return
		}
		owns, err := h.registrar.Owns(r.Context(), principal, registrationID)
		if err != nil {
			httpapi.Problem(w, r, httpapi.Internal, "The ownership could not be read")
			return
		}
		if !owns {
			// Not 403: an owner must not learn that a registration it does not own exists.
			httpapi.Problem(w, r, httpapi.NotFound, "No such registration")
			return
		}
		next(w, r)
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// Mine handles GET /v1/registrations:mine: the registrations the caller owns.
func (h *Registrations) Mine(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	mine, err := h.registrar.Mine(r.Context(), principal)
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The owned registrations could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registrations": mine})
}

// Owners handles GET /v1/registrations/{registration_id}/owners.
func (h *Registrations) Owners(w http.ResponseWriter, r *http.Request) {
	registrationID, _, err := registrationOf(r)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	owners, err := h.registrar.Owners(r.Context(), registrationID)
	if err != nil {
		writeOwnershipError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"owners": owners})
}

type grantOwnerRequest struct {
	Principal string `json:"principal_id"`
}

// GrantOwner handles POST /v1/registrations/{registration_id}/owners, a provider's, with a reason.
func (h *Registrations) GrantOwner(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	registrationID, _, err := registrationOf(r)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Granting ownership requires an X-Administrative-Reason header")
		return
	}
	var body grantOwnerRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid ownership document")
		return
	}
	owner, err := id.Parse(strings.TrimSpace(body.Principal))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	owners, err := h.registrar.GrantOwner(r.Context(), registration.OwnershipChange{
		RegistrationID: registrationID, Principal: owner, ChangedBy: principal, Reason: reason})
	if err != nil {
		writeOwnershipError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"owners": owners})
}

// OwnerAction handles POST /v1/registrations/{registration_id}/owners/{principal_id}:revoke, a
// provider's, with a reason.
func (h *Registrations) OwnerAction(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	registrationID, _, err := registrationOf(r)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	raw, action, _ := strings.Cut(r.PathValue("owner_action"), ":")
	if action != "revoke" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such ownership action")
		return
	}
	owner, err := id.Parse(raw)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Revoking ownership requires an X-Administrative-Reason header")
		return
	}
	owners, err := h.registrar.RevokeOwner(r.Context(), registration.OwnershipChange{
		RegistrationID: registrationID, Principal: owner, ChangedBy: principal, Reason: reason})
	if err != nil {
		writeOwnershipError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"owners": owners})
}

func writeOwnershipError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, registration.ErrOwnerNotEligible), errors.Is(err, registration.ErrInvalid):
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, registration.ErrAlreadyOwner), errors.Is(err, registration.ErrTooFewOwners),
		errors.Is(err, registration.ErrInvalidTransition):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, registration.ErrOwnerNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, err.Error())
	case errors.Is(err, registration.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such registration")
	default:
		httpapi.Problem(w, r, httpapi.Internal, "The ownership change could not be made")
	}
}
