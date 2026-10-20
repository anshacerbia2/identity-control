package httpapi

// Whether a Principal holds an address, proven (ADR-ORG-007 §5.3, TDD-identity-control-008 1.7.0):
// POST /v1/principals/{principal_id}/identifiers:match. Organization Control asks it when a person
// accepts an invitation. It admits Organization Control's workload alone, as the delivery intake
// does, and it is mounted apart from every caller route, behind its own verification.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/identity-control/internal/securitynotify"
)

// IdentifierMatcher answers the question: *securitynotify.Addresses.
type IdentifierMatcher interface {
	Match(ctx context.Context, principal id.UUID, address string) (bool, error)
}

// maxMatchBody bounds the request: one address of at most 254 characters, in JSON.
const maxMatchBody = 1 << 10

type matchRequest struct {
	Address string `json:"address"`
}

// identifierMatch verifies Organization Control's workload token, then answers {"match": true} or
// {"match": false}. The answer is the same shape for every Principal, known or not, and the log line
// names the Principal and the answer, never the address.
func identifierMatch(verifier TokenVerifier, matcher IdentifierMatcher, telemetry *observability.Telemetry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if verifier == nil || matcher == nil {
			fhttp.Problem(w, r, fhttp.DependencyUnavailable, "The identifier match is not configured")
			return
		}
		token, ok := bearerToken(r)
		if !ok {
			fhttp.Problem(w, r, fhttp.AuthenticationRequired, "A bearer token is required")
			return
		}
		if _, err := verifier.Verify(token); err != nil {
			fhttp.Problem(w, r, fhttp.AuthenticationRequired, "The bearer token is not valid for this resource")
			return
		}
		raw, action, _ := strings.Cut(r.PathValue("principal_id"), ":")
		principal, err := id.Parse(raw)
		if action != "" || err != nil {
			fhttp.Problem(w, r, fhttp.ValidationFailed, "principal_id is not a valid identifier")
			return
		}
		defer func() { _ = r.Body.Close() }()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMatchBody))
		decoder.DisallowUnknownFields()
		var body matchRequest
		if err := decoder.Decode(&body); err != nil {
			fhttp.Problem(w, r, fhttp.ValidationFailed, "The body is not {\"address\": \"...\"}")
			return
		}
		match, err := matcher.Match(r.Context(), principal, body.Address)
		switch {
		case errors.Is(err, securitynotify.ErrInvalidAddress):
			fhttp.Problem(w, r, fhttp.ValidationFailed, "The address is not one email address")
			return
		case err != nil:
			fhttp.Problem(w, r, fhttp.DependencyUnavailable, "The match could not be answered")
			return
		}
		if telemetry != nil {
			telemetry.Logger(r.Context()).InfoContext(r.Context(), "an identifier match was answered",
				slog.String("principal_id", principal.String()), slog.Bool("match", match))
		}
		writeJSON(w, http.StatusOK, map[string]bool{"match": match})
	})
}
