package httpapi

// A person's own sessions and authenticators (TDD-identity-control-005 §Self-Service as Built).
// Route class self: the subject is the Principal in the token, and no path segment names it. A
// provider is served here as the person it is, never as a provider.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/identity-control/internal/securitystate"
)

// SelfService is what the self routes serve.
type SelfService interface {
	MySessions(ctx context.Context, principal id.UUID, sid string) ([]securitystate.MySession, error)
	MyAuthenticators(ctx context.Context, principal id.UUID) ([]securitystate.MyAuthenticator, error)
	MyOperation(ctx context.Context, principal, operationID id.UUID) (securitystate.Operation, error)
	Submit(ctx context.Context, cmd securitystate.Command) (securitystate.Operation, error)
}

// Me is the handler.
type Me struct {
	service      SelfService
	stepUpMaxAge time.Duration
	now          func() time.Time
	// assurance is the routes' policy, which Routes hands it.
	assurance AssurancePolicy
}

// NewMe constructs the handler. stepUpMaxAge is IDENTITY_STEP_UP_MAX_AGE.
func NewMe(service SelfService, stepUpMaxAge time.Duration) (*Me, error) {
	switch {
	case service == nil:
		return nil, errors.New("httpapi: a self service is required")
	case stepUpMaxAge <= 0:
		return nil, errors.New("httpapi: the step-up age must be positive")
	}
	return &Me{service: service, stepUpMaxAge: stepUpMaxAge, now: time.Now}, nil
}

func writeMeError(w http.ResponseWriter, r *http.Request, err error) {
	if kernelFailure(err) {
		httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The identity kernel did not answer; retry")
		return
	}
	writeSecurityError(w, r, err)
}

func (h *Me) caller(w http.ResponseWriter, r *http.Request) (id.UUID, bool) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
	}
	return principal, ok
}

// Sessions handles GET /v1/me/sessions.
func (h *Me) Sessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.caller(w, r)
	if !ok {
		return
	}
	sessions, err := h.service.MySessions(r.Context(), principal, SessionID(r.Context()))
	if err != nil {
		writeMeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

// Authenticators handles GET /v1/me/authenticators.
func (h *Me) Authenticators(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.caller(w, r)
	if !ok {
		return
	}
	authenticators, err := h.service.MyAuthenticators(r.Context(), principal)
	if err != nil {
		writeMeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticators": authenticators})
}

// Operation handles GET /v1/me/security-operations/{operation_id}: the caller's own commands only.
func (h *Me) Operation(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.caller(w, r)
	if !ok {
		return
	}
	operationID, err := id.Parse(r.PathValue("operation_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "operation_id is not a valid identifier")
		return
	}
	op, err := h.service.MyOperation(r.Context(), principal, operationID)
	if err != nil {
		writeMeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

// SessionAction handles POST /v1/me/sessions/{security_ref}:terminate.
func (h *Me) SessionAction(w http.ResponseWriter, r *http.Request) {
	ref, action, _ := strings.Cut(r.PathValue("session_action"), ":")
	if action != "terminate" || ref == "" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such session action")
		return
	}
	h.command(w, r, securitystate.TypeSessionTerminate, ref, false)
}

// TerminateAll handles POST /v1/me/sessions:terminate-all. It ends the session the request came
// from as well.
func (h *Me) TerminateAll(w http.ResponseWriter, r *http.Request) {
	h.command(w, r, securitystate.TypeTerminateAll, "", false)
}

// AuthenticatorAction handles POST /v1/me/authenticators/{security_ref}:remove, under step-up.
func (h *Me) AuthenticatorAction(w http.ResponseWriter, r *http.Request) {
	ref, action, _ := strings.Cut(r.PathValue("authenticator_action"), ":")
	if action != "remove" || ref == "" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such authenticator action")
		return
	}
	h.command(w, r, securitystate.TypeAuthenticatorRemove, ref, true)
}

func (h *Me) command(w http.ResponseWriter, r *http.Request, opType, ref string, stepUp bool) {
	principal, ok := h.caller(w, r)
	if !ok {
		return
	}
	key, ok := idempotencyKey(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A non-empty Idempotency-Key header of at most 255 characters is required")
		return
	}
	acr, authTime, ok := Assurance(r.Context())
	// Removing an authenticator changes how the account is protected: aal2, recently
	// (ADR-IAM-004 §5.2). Ending a session asks for neither.
	if !ok || (stepUp && (!h.assurance.meets(r, levelAAL2) || h.now().Sub(authTime) > h.stepUpMaxAge)) {
		stepUpChallenge(w, r, AcrAAL2, h.stepUpMaxAge)
		return
	}
	correlation := ""
	if value, ok := observability.CorrelationID(r.Context()); ok {
		correlation = value.String()
	} else if minted, err := id.NewV7(); err == nil {
		correlation = minted.String()
	}
	op, err := h.service.Submit(r.Context(), securitystate.Command{
		Self: true, Type: opType, Subject: principal, Ref: ref, IdempotencyKey: key,
		Actor: securitystate.Actor{Principal: principal, Correlation: correlation,
			Assurance: fmt.Sprintf("acr=%s;auth_time=%s", acr, authTime.UTC().Format(time.RFC3339))},
	})
	if err != nil {
		writeMeError(w, r, err)
		return
	}
	if !op.Final() {
		w.Header().Set("Location", "/v1/me/security-operations/"+op.OperationID.String())
		writeJSON(w, http.StatusAccepted, op)
		return
	}
	writeJSON(w, http.StatusOK, op)
}
