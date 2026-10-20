package httpapi

// The bootstrap ceremony's record and its independent review (STD-IAM-001 2.9.0 §3.10, ADR-IAM-001
// §5.11 requirement 3 as amended 2026-10-20; TDD-identity-control-001 1.23.0 §The Bootstrap Ceremony).
// Both are a provider's routes: the reviewer is a named member of Security or of the Architecture
// Authority who signs in as a provider, and the review is recorded under that Principal.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/httpapi"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
)

// CeremonyRecords reads the ceremony's record and records a review of it. *provisioning.Provisioner
// satisfies it.
type CeremonyRecords interface {
	Ceremony(ctx context.Context) (provisioning.CeremonyView, error)
	ReviewCeremony(ctx context.Context, req provisioning.CeremonyReviewRequest) (provisioning.CeremonyReview, error)
}

// ceremonyReviewRequest is the review's body. The statement is the X-Administrative-Reason header,
// visible US-ASCII as every reason is (STD-GLB-001 §Request Header Values).
type ceremonyReviewRequest struct {
	Reviewer string `json:"reviewer"`
	Outcome  string `json:"outcome"`
}

// ceremonyRecord handles GET /v1/bootstrap-ceremony.
func ceremonyRecord(records CeremonyRecords) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := callerPrincipal(r); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		view, err := records.Ceremony(r.Context())
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, view)
		case errors.Is(err, provisioning.ErrNoCeremony):
			httpapi.Problem(w, r, httpapi.NotFound, "No bootstrap ceremony is on record")
		default:
			httpapi.Problem(w, r, httpapi.Internal, "The ceremony record could not be read")
		}
	}
}

// ceremonyReview handles POST /v1/bootstrap-ceremony:review. It answers 201 with the review, 409 when
// the reviewer is the operator, the witness or the first Principal's holder, and 404 when no ceremony
// is on record.
func ceremonyReview(records CeremonyRecords) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := callerPrincipal(r)
		if !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		statement := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
		if statement == "" {
			httpapi.Problem(w, r, httpapi.ValidationFailed,
				"A review states its finding in the X-Administrative-Reason header")
			return
		}
		var body ceremonyReviewRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || strings.TrimSpace(body.Reviewer) == "" {
			httpapi.Problem(w, r, httpapi.ValidationFailed,
				`A review names its reviewer and outcome: {"reviewer": "...", "outcome": "satisfactory"|"findings"}`)
			return
		}
		review, err := records.ReviewCeremony(r.Context(), provisioning.CeremonyReviewRequest{
			Reviewer: body.Reviewer, RecordedBy: principal, Outcome: body.Outcome, Statement: statement,
			Correlation: correlationOf(r)})
		switch {
		case err == nil:
			writeJSON(w, http.StatusCreated, review)
		case errors.Is(err, provisioning.ErrReviewerNotIndependent):
			httpapi.Problem(w, r, httpapi.StateTransitionRefused,
				"The reviewer is the ceremony's operator, its witness or the first Principal; an independent person reviews the record")
		case errors.Is(err, provisioning.ErrReviewInvalid):
			httpapi.Problem(w, r, httpapi.ValidationFailed, `outcome is "satisfactory" or "findings"`)
		case errors.Is(err, provisioning.ErrNoCeremony), errors.Is(err, provisioning.ErrCeremonyUnnamed):
			httpapi.Problem(w, r, httpapi.NotFound, "No bootstrap ceremony with a Principal is on record")
		default:
			httpapi.Problem(w, r, httpapi.Internal, "The review could not be recorded")
		}
	}
}
