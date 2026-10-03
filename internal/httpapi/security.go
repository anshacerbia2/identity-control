package httpapi

// A provider's security commands on another Principal (TDD-identity-control-005 §Containment as
// Built): suspend, restore, end every session, revoke one authenticator, and read an operation.
// Every route is providerOnly. The refusals that need no record are made here, in the order the
// design states; the rest are the service's.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/identity-control/internal/securitystate"
)

// SecurityCommander is the command path the handler serves.
type SecurityCommander interface {
	Submit(ctx context.Context, cmd securitystate.Command) (securitystate.Operation, error)
	Get(ctx context.Context, operationID id.UUID) (securitystate.Operation, error)
}

// Security is the handler.
type Security struct {
	commands     SecurityCommander
	stepUpMaxAge time.Duration
	now          func() time.Time
}

// NewSecurity constructs the handler. stepUpMaxAge is IDENTITY_STEP_UP_MAX_AGE.
func NewSecurity(commands SecurityCommander, stepUpMaxAge time.Duration) (*Security, error) {
	switch {
	case commands == nil:
		return nil, errors.New("httpapi: a security commander is required")
	case stepUpMaxAge <= 0:
		return nil, errors.New("httpapi: the step-up age must be positive")
	}
	return &Security{commands: commands, stepUpMaxAge: stepUpMaxAge, now: time.Now}, nil
}

type securityCommandRequest struct {
	ExpectedVersion int64 `json:"expected_version"`
}

// Suspend handles the :suspend action of POST /v1/principals/{target}.
func (h *Security) Suspend(w http.ResponseWriter, r *http.Request, subject string) {
	h.command(w, r, securitystate.TypeSuspend, subject, "")
}

// Restore handles the :restore action of POST /v1/principals/{target}.
func (h *Security) Restore(w http.ResponseWriter, r *http.Request, subject string) {
	h.command(w, r, securitystate.TypeRestore, subject, "")
}

// TerminateAll handles POST /v1/principals/{principal_id}/sessions:terminate-all.
func (h *Security) TerminateAll(w http.ResponseWriter, r *http.Request) {
	h.command(w, r, securitystate.TypeTerminateAll, r.PathValue("principal_id"), "")
}

// Revoke handles POST /v1/principals/{principal_id}/authenticators/{security_ref}:revoke.
func (h *Security) Revoke(w http.ResponseWriter, r *http.Request) {
	ref, action, _ := strings.Cut(r.PathValue("authenticator_action"), ":")
	if action != "revoke" || ref == "" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such authenticator action")
		return
	}
	h.command(w, r, securitystate.TypeRevoke, r.PathValue("principal_id"), ref)
}

// Operation handles GET /v1/security-operations/{operation_id}.
func (h *Security) Operation(w http.ResponseWriter, r *http.Request) {
	operationID, err := id.Parse(r.PathValue("operation_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "operation_id is not a valid identifier")
		return
	}
	op, err := h.commands.Get(r.Context(), operationID)
	if err != nil {
		writeSecurityError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

func (h *Security) command(w http.ResponseWriter, r *http.Request, opType, rawSubject, ref string) {
	actor, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	subject, err := id.Parse(rawSubject)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "principal_id is not a valid identifier")
		return
	}
	if subject == actor {
		httpapi.Problem(w, r, httpapi.Forbidden, "A provider cannot suspend, restore or change the security of the Principal in its own token")
		return
	}
	key, ok := idempotencyKey(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A non-empty Idempotency-Key header of at most 255 characters is required")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A security command requires an X-Administrative-Reason header")
		return
	}
	var body securityCommandRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || body.ExpectedVersion < 1 {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The body must name expected_version, the Principal's security_version")
		return
	}
	acr, authTime, ok := Assurance(r.Context())
	if !ok || h.now().Sub(authTime) > h.stepUpMaxAge {
		h.stepUp(w, r)
		return
	}
	correlation := ""
	if value, ok := observability.CorrelationID(r.Context()); ok {
		correlation = value.String()
	} else if minted, err := id.NewV7(); err == nil {
		correlation = minted.String()
	}

	op, err := h.commands.Submit(r.Context(), securitystate.Command{
		Type: opType, Subject: subject, Ref: ref, ExpectedVersion: body.ExpectedVersion, Reason: reason,
		IdempotencyKey: key,
		Actor: securitystate.Actor{Principal: actor, Emergency: ProviderEmergency(r.Context()), Correlation: correlation,
			Assurance: fmt.Sprintf("acr=%s;auth_time=%s", acr, authTime.UTC().Format(time.RFC3339))},
	})
	if err != nil {
		writeSecurityError(w, r, err)
		return
	}
	if !op.Final() {
		// RFC 9110 §15.3.3: the representation describes the current status and points to the
		// status monitor.
		w.Header().Set("Location", "/v1/security-operations/"+op.OperationID.String())
		writeJSON(w, http.StatusAccepted, op)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

// stepUp answers as RFC 9470 §3 defines: 401 with insufficient_user_authentication and the
// allowable elapsed time since the last authentication. acr_values is not sent: the realm maps no
// level of authentication to ask for (TDD-identity-control-005 §Step-Up).
func (h *Security) stepUp(w http.ResponseWriter, r *http.Request) {
	stepUpChallenge(w, r, h.stepUpMaxAge)
}

func stepUpChallenge(w http.ResponseWriter, r *http.Request, maxAge time.Duration) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer error="insufficient_user_authentication", error_description="A more recent authentication is required", max_age=%d`,
		int(maxAge.Seconds())))
	httpapi.Problem(w, r, httpapi.AuthenticationRequired,
		fmt.Sprintf("This command requires an authentication within the last %s; sign in again", maxAge))
}

func writeSecurityError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, securitystate.ErrInvalid):
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, securitystate.ErrSelfAction):
		httpapi.Problem(w, r, httpapi.Forbidden, "A provider cannot act on the Principal in its own token")
	case errors.Is(err, securitystate.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such Principal, authenticator or operation")
	case errors.Is(err, securitystate.ErrWorkload):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"A workload is suspended and restored through /v1/workloads/{principal_id}:suspend and :restore")
	case errors.Is(err, securitystate.ErrState):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, securitystate.ErrVersion):
		httpapi.Problem(w, r, httpapi.VersionConflict, "The Principal's security_version changed; read it again")
	case errors.Is(err, securitystate.ErrKeyReuse):
		httpapi.Problem(w, r, httpapi.IdempotencyKeyConflict, "The Idempotency-Key was used for another request")
	case errors.Is(err, securitystate.ErrInProgress):
		httpapi.Problem(w, r, httpapi.RequestInProgress, "A request with this Idempotency-Key is being accepted; retry")
	default:
		httpapi.Problem(w, r, httpapi.Internal, "The command could not be accepted")
	}
}
