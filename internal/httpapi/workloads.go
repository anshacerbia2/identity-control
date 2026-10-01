package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/registration"
	"github.com/anshacerbia2/identity-control/internal/workload"
)

// WorkloadService is the workload surface (TDD-identity-control-004 §API / Interface).
type WorkloadService interface {
	Create(ctx context.Context, req workload.CreateRequest) (workload.Workload, error)
	Get(ctx context.Context, principalID id.UUID) (workload.Workload, error)
	Reassign(ctx context.Context, req workload.ReassignRequest) (workload.Workload, error)
	Suspend(ctx context.Context, req workload.LifecycleRequest) (workload.Workload, error)
	Restore(ctx context.Context, req workload.LifecycleRequest) (workload.Workload, error)
	Retire(ctx context.Context, req workload.LifecycleRequest) (workload.Workload, error)
}

// Workloads serves the workload routes.
type Workloads struct {
	service WorkloadService
}

// NewWorkloads constructs the handler.
func NewWorkloads(service WorkloadService) (*Workloads, error) {
	if service == nil {
		return nil, errors.New("httpapi: a workload service is required")
	}
	return &Workloads{service: service}, nil
}

// createWorkloadRequest is the wire shape. The creating Principal is absent on purpose: the
// authenticated caller is it.
type createWorkloadRequest struct {
	DisplayName   string          `json:"display_name"`
	Purpose       string          `json:"purpose"`
	WorkloadType  string          `json:"workload_type"`
	Owner         string          `json:"owner_principal_id"`
	TeamReference string          `json:"team_reference"`
	ClientKey     string          `json:"client_key"`
	Application   string          `json:"application_ref"`
	Audience      []string        `json:"audience"`
	PublicKey     json.RawMessage `json:"public_key"`
}

// CreateWorkload handles POST /v1/workloads.
func (h *Workloads) CreateWorkload(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	key, ok := idempotencyKey(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.ValidationFailed,
			"A non-empty Idempotency-Key header of at most 255 characters is required")
		return
	}
	var body createWorkloadRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid workload document")
		return
	}
	owner, err := id.Parse(body.Owner)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "owner_principal_id is not a valid identifier")
		return
	}
	scope, _ := CallerScope(r.Context())
	created, err := h.service.Create(r.Context(), workload.CreateRequest{
		CallerScope: scope, IdempotencyKey: key, CreatedBy: principal,
		DisplayName: body.DisplayName, Purpose: body.Purpose, WorkloadType: body.WorkloadType, Owner: owner,
		TeamReference: body.TeamReference, ClientKey: body.ClientKey, Application: body.Application,
		Audience: body.Audience, PublicKey: body.PublicKey,
	})
	if err != nil {
		writeWorkloadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// GetWorkload handles GET /v1/workloads/{principal_id}.
func (h *Workloads) GetWorkload(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	principalID, err := id.Parse(r.PathValue("target"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	found, err := h.service.Get(r.Context(), principalID)
	if err != nil {
		writeWorkloadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, found)
}

type reassignRequest struct {
	Owner string `json:"owner_principal_id"`
}

// WorkloadAction handles POST /v1/workloads/{principal_id}:{action}: :reassign, :suspend, :restore
// and :retire. The action is part of the last segment, because the mux matches whole segments. Each
// requires X-Administrative-Reason.
func (h *Workloads) WorkloadAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	raw, action, _ := strings.Cut(r.PathValue("target"), ":")
	lifecycle := map[string]func(context.Context, workload.LifecycleRequest) (workload.Workload, error){
		"suspend": h.service.Suspend, "restore": h.service.Restore, "retire": h.service.Retire,
	}
	if _, known := lifecycle[action]; !known && action != "reassign" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such workload action")
		return
	}
	target, err := id.Parse(raw)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A workload action requires an X-Administrative-Reason header")
		return
	}
	if act, ok := lifecycle[action]; ok {
		// The lifecycle actions take no body: the workload, the caller and the reason are the whole
		// request (TDD-identity-control-004 §Suspension, Restoration, and Retirement).
		changed, err := act(r.Context(), workload.LifecycleRequest{PrincipalID: target, ChangedBy: principal, Reason: reason})
		if err != nil {
			writeWorkloadError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, changed)
		return
	}
	var body reassignRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid reassignment document")
		return
	}
	owner, err := id.Parse(body.Owner)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "owner_principal_id is not a valid identifier")
		return
	}
	moved, err := h.service.Reassign(r.Context(), workload.ReassignRequest{
		PrincipalID: target, NewOwner: owner, ChangedBy: principal, Reason: reason})
	if err != nil {
		writeWorkloadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, moved)
}

func writeWorkloadError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, workload.ErrInvalid), errors.Is(err, workload.ErrAgentNotBuilt),
		errors.Is(err, workload.ErrOwnerNotEligible):
		// Each message names a rule, never a stored value.
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, workload.ErrRefused):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"The client_key is held by a Keycloak client no registration describes")
	case errors.Is(err, workload.ErrInvalidTransition):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, workload.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such workload")
	case errors.Is(err, registration.ErrInvalidTransition):
		// A lifecycle action its registration refused, such as a restore whose client is gone. The
		// message names the rule and the state.
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, registration.ErrInvalid), errors.Is(err, registration.ErrScopeUndeclared),
		errors.Is(err, registration.ErrPrivateKey), errors.Is(err, registration.ErrKeyTaken),
		errors.Is(err, registration.ErrKeyInUse), errors.Is(err, idempotency.ErrConflict),
		errors.Is(err, idempotency.ErrInProgress):
		// The workload's client goes through the registration path, and so do its refusals.
		writeRegistrationError(w, r, err)
	default:
		httpapi.Problem(w, r, httpapi.DependencyUnavailable,
			"The identity kernel did not confirm the workload; retry with the same Idempotency-Key")
	}
}
