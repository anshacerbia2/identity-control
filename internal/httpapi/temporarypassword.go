package httpapi

// A provider issues a temporary password to a person who has never set one (ADR-IAM-010 §5.1,
// TDD-identity-control-005 2.12.0 §A First Credential): POST /v1/principals/{principal_id}:issue-temporary-password,
// dispatched from POST /v1/principals/{target}. The response carries the value once, with
// Cache-Control: no-store, and nothing here logs, stores or replays it (STD-IAM-001 2.8.0 §3.1).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/firstcredential"
)

// TemporaryPasswordIssuer is the first-credential path: *firstcredential.Service.
type TemporaryPasswordIssuer interface {
	Issue(ctx context.Context, req firstcredential.Request) (firstcredential.Issuance, bool, error)
}

// TemporaryPasswords is the handler.
type TemporaryPasswords struct {
	issuer       TemporaryPasswordIssuer
	stepUpMaxAge time.Duration
	now          func() time.Time
}

// NewTemporaryPasswords constructs the handler. stepUpMaxAge is IDENTITY_STEP_UP_MAX_AGE.
func NewTemporaryPasswords(issuer TemporaryPasswordIssuer, stepUpMaxAge time.Duration) (*TemporaryPasswords, error) {
	switch {
	case issuer == nil:
		return nil, errors.New("httpapi: a temporary password issuer is required")
	case stepUpMaxAge <= 0:
		return nil, errors.New("httpapi: the step-up age must be positive")
	}
	return &TemporaryPasswords{issuer: issuer, stepUpMaxAge: stepUpMaxAge, now: time.Now}, nil
}

// maxIssueBody bounds the body, which carries nothing: an empty body or {}.
const maxIssueBody = 64

// Issue handles the :issue-temporary-password action. The refusals that need no record are made here,
// in the order the other provider commands make them.
func (h *TemporaryPasswords) Issue(w http.ResponseWriter, r *http.Request, rawSubject string) {
	// Every answer, a refusal included, is never cached: the first answer carries a credential.
	w.Header().Set("Cache-Control", "no-store")
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
		httpapi.Problem(w, r, httpapi.Forbidden, "A provider cannot issue a temporary password for the Principal in its own token")
		return
	}
	key, ok := idempotencyKey(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A non-empty Idempotency-Key header of at most 255 characters is required")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Issuing a temporary password requires an X-Administrative-Reason header")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIssueBody+1))
	if trimmed := strings.TrimSpace(string(body)); err != nil || len(body) > maxIssueBody || (trimmed != "" && trimmed != "{}") {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The body is empty or {}: the value is generated, never chosen")
		return
	}
	acr, authTime, ok := Assurance(r.Context())
	if !ok || h.now().Sub(authTime) > h.stepUpMaxAge {
		stepUpChallenge(w, r, AcrAAL2, h.stepUpMaxAge)
		return
	}
	issued, replay, err := h.issuer.Issue(r.Context(), firstcredential.Request{
		Actor: firstcredential.Actor{Principal: actor, Emergency: ProviderEmergency(r.Context()),
			Correlation: correlationOf(r), Route: "POST /v1/principals/{principal_id}:issue-temporary-password",
			Assurance: fmt.Sprintf("acr=%s;auth_time=%s", acr, authTime.UTC().Format(time.RFC3339))},
		Subject: subject, Reason: reason, IdempotencyKey: key,
	})
	if err != nil {
		writeTemporaryPasswordError(w, r, err)
		return
	}
	status := http.StatusCreated
	if replay {
		// The issuance as recorded: its value was never kept, so it cannot be shown again.
		status, issued.Value = http.StatusOK, ""
	}
	writeJSON(w, status, map[string]any{"temporary_password": issued})
}

func writeTemporaryPasswordError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, firstcredential.ErrInvalid):
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request is invalid")
	case errors.Is(err, firstcredential.ErrSelf):
		httpapi.Problem(w, r, httpapi.Forbidden, "A provider cannot issue a temporary password for the Principal in its own token")
	case errors.Is(err, firstcredential.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such Principal")
	case errors.Is(err, firstcredential.ErrCredentialEstablished):
		// ADR-IAM-010 §5.1 names the refusal credential-established. The problem registry is closed, so
		// the name leads the detail of a refused transition.
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"credential-established: the person has set a password of their own, so no temporary password is issued")
	case errors.Is(err, firstcredential.ErrState):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"A temporary password is issued only to an active human Principal linked to its kernel user")
	case errors.Is(err, firstcredential.ErrKeyReuse):
		httpapi.Problem(w, r, httpapi.IdempotencyKeyConflict, "The Idempotency-Key was used for another request")
	case errors.Is(err, firstcredential.ErrInProgress):
		httpapi.Problem(w, r, httpapi.RequestInProgress,
			"A request with this Idempotency-Key is in progress, or ended without recording its answer; issue again with a new key")
	case errors.Is(err, firstcredential.ErrUnavailable):
		httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The identity kernel could not be reached; issue again")
	default:
		httpapi.Problem(w, r, httpapi.Internal, "The temporary password could not be issued")
	}
}
