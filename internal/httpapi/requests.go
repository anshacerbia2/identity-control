package httpapi

// Registration requests at the transport (ADR-IAM-003 §5.3, TDD-identity-control-003
// §Registration Requests). An application developer proposes a production registration and
// withdraws its own; approving, rejecting and the queue are a provider's, and the proposer's
// approval is refused by the service and the database.

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

type proposeRegistrationRequest struct {
	registerRequest
	Owners []string `json:"owners"`
}

// ProposeRegistration handles POST /v1/registration-requests, with a reason. It answers 201 with a
// request recorded now and 200 with the same open request retried.
func (h *Registrations) ProposeRegistration(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A registration request requires an X-Administrative-Reason header")
		return
	}
	var body proposeRegistrationRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid registration request")
		return
	}
	owners := make([]id.UUID, 0, len(body.Owners))
	for _, raw := range body.Owners {
		owner, err := id.Parse(strings.TrimSpace(raw))
		if err != nil {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "An owner is not a valid principal_id")
			return
		}
		owners = append(owners, owner)
	}
	request, created, err := h.registrar.ProposeRegistration(r.Context(), registration.RegistrationProposal{
		Request: registration.Request{
			RegisteredBy: principal, Developer: !IsProvider(r.Context()),
			ClientKey: body.ClientKey, Profile: body.Profile, AudienceClass: body.AudienceClass,
			PrivilegedForm: body.PrivilegedForm,
			ApplicationRef: body.ApplicationRef, LifetimeClass: body.LifetimeClass,
			Audience: body.Audience, RedirectURIs: body.RedirectURIs, PublicKey: body.PublicKey,
		},
		Owners: owners, Reason: reason,
	})
	if err != nil {
		writeRequestError(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, request)
}

// RequestQueue handles GET /v1/registration-requests, the approval queue: a provider's.
func (h *Registrations) RequestQueue(w http.ResponseWriter, r *http.Request) {
	requests, err := h.registrar.RequestQueue(r.Context())
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The registration requests could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": requests})
}

// MyRequests handles GET /v1/registration-requests:mine, the caller's own requests.
func (h *Registrations) MyRequests(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	requests, err := h.registrar.MyRequests(r.Context(), principal)
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The registration requests could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": requests})
}

// RequestAction handles POST /v1/registration-requests/{request_id}:approve, :reject and
// :withdraw, each with a reason.
func (h *Registrations) RequestAction(w http.ResponseWriter, r *http.Request) {
	principal, _ := callerPrincipal(r)
	raw, action, _ := strings.Cut(r.PathValue("request_action"), ":")
	switch action {
	case registration.DecisionApprove, registration.DecisionReject:
		if !IsProvider(r.Context()) {
			httpapi.Problem(w, r, httpapi.Forbidden, "Approving or rejecting a registration request requires provider authority")
			return
		}
	case registration.DecisionWithdraw:
	default:
		httpapi.Problem(w, r, httpapi.NotFound, "No such request action")
		return
	}
	requestID, err := id.Parse(raw)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "request_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A decision requires an X-Administrative-Reason header")
		return
	}
	request, err := h.registrar.DecideRegistration(r.Context(), registration.RequestDecision{
		RequestID: requestID, Decision: action, DecidedBy: principal, Reason: reason}, IsProvider(r.Context()))
	if err != nil {
		writeRequestError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func writeRequestError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, registration.ErrRequestNotNeeded):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"Outside production a registration is created directly with POST /v1/registrations")
	case errors.Is(err, registration.ErrRequestOpen), errors.Is(err, registration.ErrChangeDecided):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, registration.ErrSelfApproval), errors.Is(err, registration.ErrNotProvider),
		errors.Is(err, registration.ErrNotProposer):
		httpapi.Problem(w, r, httpapi.Forbidden, err.Error())
	case errors.Is(err, registration.ErrRequestNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such registration request")
	case errors.Is(err, registration.ErrOwnerNotEligible):
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	default:
		writeRegistrationError(w, r, err)
	}
}
