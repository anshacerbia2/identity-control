package httpapi

// Registration changes at the transport (ADR-IAM-003 §5.2, TDD-identity-control-003 §Registration
// Changes). An owner proposes and withdraws a change to the redirect URIs or the audience of a
// registration it owns, or to the lifetime class of a resource it owns (ADR-IAM-003 §5.9); approving and rejecting are a provider's, refused to an owner here before
// anything is read, and refused to the proposer by the service and the database.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

// proposeChangeRequest carries one of redirect_uris, audience and lifetime_class. An audience of []
// is a change to no resource, which is why it is a pointer: absent and empty are different requests.
type proposeChangeRequest struct {
	RedirectURIs    []string  `json:"redirect_uris"`
	Audience        *[]string `json:"audience"`
	LifetimeClass   *string   `json:"lifetime_class"`
	ExpectedVersion int64     `json:"expected_version"`
}

// ProposeChange handles POST /v1/registrations/{registration_id}/changes, with a reason. It answers
// 201 with a change recorded now, applied or waiting, and 200 with the same open change retried.
func (h *Registrations) ProposeChange(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	registrationID, _, err := registrationOf(r)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A change requires an X-Administrative-Reason header")
		return
	}
	var body proposeChangeRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid change document")
		return
	}
	change, created, err := h.registrar.ProposeChange(r.Context(), registration.Proposal{
		RegistrationID: registrationID, RedirectURIs: body.RedirectURIs, Audience: body.Audience,
		LifetimeClass:   body.LifetimeClass,
		ExpectedVersion: body.ExpectedVersion, ProposedBy: principal, Reason: reason, Provider: IsProvider(r.Context())})
	if err != nil {
		writeChangeError(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, change)
}

// Changes handles GET /v1/registrations/{registration_id}/changes.
func (h *Registrations) Changes(w http.ResponseWriter, r *http.Request) {
	registrationID, _, err := registrationOf(r)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	changes, err := h.registrar.Changes(r.Context(), registrationID)
	if err != nil {
		writeChangeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": changes})
}

// OpenChanges handles GET /v1/registrations:changes, the approval queue: a provider's.
func (h *Registrations) OpenChanges(w http.ResponseWriter, r *http.Request) {
	changes, err := h.registrar.OpenChanges(r.Context())
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The open changes could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": changes})
}

// ChangeAction handles POST /v1/registrations/{registration_id}/changes/{change_id}:approve,
// :reject and :withdraw, each with a reason.
func (h *Registrations) ChangeAction(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	registrationID, _, err := registrationOf(r)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	raw, action, _ := strings.Cut(r.PathValue("change_action"), ":")
	switch action {
	case registration.DecisionApprove, registration.DecisionReject:
		if !IsProvider(r.Context()) {
			httpapi.Problem(w, r, httpapi.Forbidden, "Approving or rejecting a change requires provider authority")
			return
		}
	case registration.DecisionWithdraw:
	default:
		httpapi.Problem(w, r, httpapi.NotFound, "No such change action")
		return
	}
	changeID, err := id.Parse(raw)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "change_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A decision requires an X-Administrative-Reason header")
		return
	}
	change, err := h.registrar.DecideChange(r.Context(), registration.Decision{
		RegistrationID: registrationID, ChangeID: changeID, Decision: action, DecidedBy: principal, Reason: reason},
		IsProvider(r.Context()))
	if err != nil {
		writeChangeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, change)
}

func writeChangeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, registration.ErrInvalid):
		// The message names the rule, never a submitted URI.
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, registration.ErrVersionConflict):
		httpapi.Problem(w, r, httpapi.VersionConflict, err.Error())
	case errors.Is(err, registration.ErrChangeOpen), errors.Is(err, registration.ErrChangeDecided),
		errors.Is(err, registration.ErrSuperseded), errors.Is(err, registration.ErrInvalidTransition):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, registration.ErrSelfApproval), errors.Is(err, registration.ErrNotProvider),
		errors.Is(err, registration.ErrNotProposer), errors.Is(err, registration.ErrNotResourceOwner):
		httpapi.Problem(w, r, httpapi.Forbidden, err.Error())
	case errors.Is(err, registration.ErrChangeNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such change")
	case errors.Is(err, registration.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such registration")
	case kernelFailure(err):
		httpapi.Problem(w, r, httpapi.DependencyUnavailable,
			"The change was not applied: the identity kernel did not confirm it; retry the same request")
	default:
		// Not the kernel: the database refused it, or a defect. The service logged the cause.
		httpapi.Problem(w, r, httpapi.Internal, "The change was not applied; it was not recorded")
	}
}

// kernelFailure reports whether an error came from the identity kernel, which a retry may get past.
func kernelFailure(err error) bool {
	for _, kernel := range []error{keycloak.ErrUnavailable, keycloak.ErrForbidden, keycloak.ErrConflict,
		keycloak.ErrNotFound, keycloak.ErrAmbiguous} {
		if errors.Is(err, kernel) {
			return true
		}
	}
	return false
}
