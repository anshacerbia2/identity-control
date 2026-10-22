package httpapi

// The record of BFF workloads admitted to the enrolment routes (ADR-IAM-011 §5.8,
// TDD-identity-control-001 1.27.0). Registering and retiring one are a provider's, with a reason.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/enrolment"
)

// EnrolmentCallerRegistry is the record: *enrolment.Callers.
type EnrolmentCallerRegistry interface {
	List(ctx context.Context) ([]enrolment.Caller, error)
	Register(ctx context.Context, change enrolment.Change) (enrolment.Caller, error)
	Retire(ctx context.Context, change enrolment.Change) (enrolment.Caller, error)
}

// EnrolmentCallers serves the registry's three provider routes.
type EnrolmentCallers struct{ callers EnrolmentCallerRegistry }

// NewEnrolmentCallers builds the handler.
func NewEnrolmentCallers(callers EnrolmentCallerRegistry) (*EnrolmentCallers, error) {
	if callers == nil {
		return nil, errors.New("httpapi: the enrolment caller registry is required")
	}
	return &EnrolmentCallers{callers: callers}, nil
}

// List handles GET /v1/enrolment-callers.
func (h *EnrolmentCallers) List(w http.ResponseWriter, r *http.Request) {
	callers, err := h.callers.List(r.Context())
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The enrolment callers could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrolment_callers": callers})
}

type registerEnrolmentCallerRequest struct {
	Principal string `json:"principal_id"`
	Purpose   string `json:"purpose"`
}

// Register handles POST /v1/enrolment-callers.
func (h *EnrolmentCallers) Register(w http.ResponseWriter, r *http.Request) {
	actor, _ := callerPrincipal(r)
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Registering an enrolment caller requires an X-Administrative-Reason header")
		return
	}
	var body registerEnrolmentCallerRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The body is not {\"principal_id\": \"...\", \"purpose\": \"...\"}")
		return
	}
	principal, err := id.Parse(strings.TrimSpace(body.Principal))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	caller, err := h.callers.Register(r.Context(), enrolment.Change{Principal: principal, Purpose: body.Purpose,
		By: actor, Reason: reason})
	if err != nil {
		writeEnrolmentCallerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, caller)
}

// Action handles POST /v1/enrolment-callers/{principal_id}:retire.
func (h *EnrolmentCallers) Action(w http.ResponseWriter, r *http.Request) {
	actor, _ := callerPrincipal(r)
	raw, action, _ := strings.Cut(r.PathValue("caller_action"), ":")
	if action != "retire" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such enrolment caller action")
		return
	}
	principal, err := id.Parse(raw)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Retiring an enrolment caller requires an X-Administrative-Reason header")
		return
	}
	caller, err := h.callers.Retire(r.Context(), enrolment.Change{Principal: principal, By: actor, Reason: reason})
	if err != nil {
		writeEnrolmentCallerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, caller)
}

func writeEnrolmentCallerError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, enrolment.ErrInvalid):
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id, a purpose of at most 500 characters and a reason are required")
	case errors.Is(err, enrolment.ErrNotWorkload):
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not an active workload Principal")
	case errors.Is(err, enrolment.ErrRegistered):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "The workload is registered already, active or retired")
	case errors.Is(err, enrolment.ErrNoCaller):
		httpapi.Problem(w, r, httpapi.NotFound, "No active enrolment caller has this principal_id")
	default:
		httpapi.Problem(w, r, httpapi.Internal, "The enrolment caller could not be changed")
	}
}
