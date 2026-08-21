package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// maxBodyBytes bounds a request body.
//
// A Principal creation carries a handful of short strings, so a megabyte is already generous.
// The bound exists because an unbounded decode lets one request consume memory proportional to
// what a client chooses to send.
const maxBodyBytes = 64 << 10

// Provisioner is the creation path this surface exposes.
//
// An interface rather than the concrete type so the transport can be tested without a
// database or a kernel, and so this package cannot reach past the two operations it needs.
type Provisioner interface {
	Create(ctx context.Context, req provisioning.CreateRequest) (provisioning.Response, error)
}

// Principals serves the Principal surface.
type Principals struct {
	provisioner Provisioner
	realm       keycloak.Realm
}

// NewPrincipals constructs the handler.
func NewPrincipals(provisioner Provisioner, realm keycloak.Realm) (*Principals, error) {
	if provisioner == nil {
		return nil, errors.New("httpapi: a provisioner is required")
	}
	if realm == "" {
		return nil, errors.New("httpapi: a realm is required")
	}
	return &Principals{provisioner: provisioner, realm: realm}, nil
}

// createPrincipalRequest is the wire shape.
//
// The realm is absent deliberately. ADR-IAM-001 §5.4 fixes a small static set of realms, so it
// is configuration rather than something a caller selects — and a caller-supplied realm would
// let one request create a Principal in a realm its authorization never covered.
type createPrincipalRequest struct {
	Username      string `json:"username"`
	Email         string `json:"email"`
	SubjectType   string `json:"subject_type"`
	WorkloadOwner string `json:"workload_owner"`
}

// CreatePrincipal handles POST /v1/principals.
func (h *Principals) CreatePrincipal(w http.ResponseWriter, r *http.Request) {
	scope, ok := CallerScope(r.Context())
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired,
			"The request carries no authenticated caller")
		return
	}

	key, ok := idempotencyKey(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.ValidationFailed,
			"A non-empty Idempotency-Key header of at most 255 characters is required")
		return
	}

	var body createPrincipalRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		// The decoder error is not echoed. It quotes the offending input, and a request body
		// must never be reflected into a response: TDD-foundation-platform-002 places
		// redaction at the serializer precisely because an error path is where a credential
		// escapes.
		httpapi.Problem(w, r, httpapi.ValidationFailed,
			"The request body is not a valid Principal creation document")
		return
	}

	req := provisioning.CreateRequest{
		CallerScope:    scope,
		IdempotencyKey: key,
		Realm:          h.realm,
		Username:       body.Username,
		Email:          body.Email,
		SubjectType:    keycloak.SubjectType(body.SubjectType),
	}
	if body.WorkloadOwner != "" {
		owner, err := id.Parse(body.WorkloadOwner)
		if err != nil {
			httpapi.Problem(w, r, httpapi.ValidationFailed,
				"workload_owner is not a valid identifier")
			return
		}
		req.WorkloadOwner = owner
	}

	response, err := h.provisioner.Create(r.Context(), req)
	if err != nil {
		writeProvisioningError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// writeProvisioningError maps a domain error onto the compiled problem registry.
//
// The mapping is explicit rather than a default-to-500, because the status code is the only
// part of a failure most clients act on: a 409 tells a caller to stop retrying and a 503 tells
// it to retry later, and collapsing both into 500 removes the distinction.
func writeProvisioningError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, idempotency.ErrConflict):
		httpapi.Problem(w, r, httpapi.IdempotencyKeyConflict,
			"The key was first used with a different request")

	case errors.Is(err, idempotency.ErrInProgress):
		// RequestInProgress rather than StateTransitionRefused. Both answer 409, and the
		// distinction is the advice they carry: a refused transition means no retry will help,
		// while this one means the retry is what will. The registry had no such type until
		// foundation-platform v0.2.2 added it, which is why an earlier revision here used the
		// refusal and recorded the gap rather than inventing a local type.
		httpapi.Problem(w, r, httpapi.RequestInProgress,
			"An identical request is already in progress; retry after it completes")

	case errors.Is(err, keycloak.ErrConflict):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"A Principal with that username already exists in this realm")

	case errors.Is(err, keycloak.ErrUnavailable), errors.Is(err, keycloak.ErrAmbiguous):
		// Ambiguous is reported as unavailable on purpose. The caller's correct action is
		// identical — retry with the same key — and telling it the outcome is unknown would
		// invite it to retry with a new key, which is how a second Principal appears.
		httpapi.Problem(w, r, httpapi.DependencyUnavailable,
			"The identity kernel did not confirm the operation; retry with the same Idempotency-Key")

	case errors.Is(err, provisioning.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such Principal")

	case errors.Is(err, provisioning.ErrIdentifierTaken),
		errors.Is(err, provisioning.ErrDuplicateInKernel),
		errors.Is(err, keycloak.ErrForbidden):
		// All three are our defects rather than the caller's: a reused identifier, a
		// uniqueness violation inside the kernel, and an administration credential missing a
		// role. A caller can do nothing with any of them, so none is described.
		httpapi.Problem(w, r, httpapi.Internal, "The request could not be completed")

	default:
		// A validation error from the provisioner reaches here. It is safe to describe
		// because it names a field rather than a value: validateCreate never includes input
		// in its message.
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	}
}
