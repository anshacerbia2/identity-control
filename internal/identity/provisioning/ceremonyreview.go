package provisioning

// The bootstrap ceremony's record, read by a provider, and its independent review (STD-IAM-001 2.9.0
// §3.10, ADR-IAM-001 §5.11 requirement 3 as amended 2026-10-20; TDD-identity-control-001 1.23.0 §The
// Bootstrap Ceremony).
//
// A third person reviews the record: not the operator, not the witness, and not the holder of the
// first Principal. AC-5 asks "that security personnel who administer access control functions do not
// also administer audit functions". The review is recorded insert-only, and the database refuses a
// review naming the operator or the witness, or recorded by the first Principal: the review row
// carries the three, held to the ceremony's own by a foreign key, and a check compares them.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// The outcomes a review records.
const (
	ReviewSatisfactory = "satisfactory"
	ReviewFindings     = "findings"
)

var (
	// ErrNoCeremony is a Control Database whose ceremony has not run.
	ErrNoCeremony = errors.New("provisioning: no bootstrap ceremony is on record")

	// ErrReviewerNotIndependent is a review by the operator, the witness, or the first Principal's
	// holder (STD-IAM-001 §3.10).
	ErrReviewerNotIndependent = errors.New("provisioning: the reviewer is the operator, the witness or the first Principal; an independent person reviews the record")

	// ErrReviewInvalid is a review missing what every review records.
	ErrReviewInvalid = errors.New("provisioning: a review names its reviewer, an outcome and a statement")
)

// CeremonyReview is one recorded review.
type CeremonyReview struct {
	ReviewID            id.UUID   `json:"review_id"`
	Reviewer            string    `json:"reviewer"`
	ReviewerPrincipalID id.UUID   `json:"reviewer_principal_id"`
	Outcome             string    `json:"outcome"`
	Statement           string    `json:"statement"`
	ReviewedAt          time.Time `json:"reviewed_at"`
}

// CeremonyView is the ceremony's record as a provider reads it: who ran it, who witnessed it, why,
// which Principal it created, when, and every review of it, oldest first. The idempotency key is not
// served: it is the ceremony's own claim, and naming it outside the record serves no review.
type CeremonyView struct {
	Operator    string           `json:"operator"`
	Witness     string           `json:"witness"`
	Reason      string           `json:"reason"`
	PrincipalID *id.UUID         `json:"principal_id"`
	RequestedAt time.Time        `json:"requested_at"`
	Reviewed    bool             `json:"reviewed"`
	Reviews     []CeremonyReview `json:"reviews"`
}

// CeremonyReviewRequest is one review: the reviewer's name, the Principal recording it, the outcome,
// the statement (the request's X-Administrative-Reason) and its correlation.
type CeremonyReviewRequest struct {
	Reviewer    string
	RecordedBy  id.UUID
	Outcome     string
	Statement   string
	Correlation string
}

const ceremonyViewStatement = `SELECT operator, witness, reason, coalesce(principal_id::text, ''), requested_at
FROM identity.bootstrap_ceremony WHERE id = $1`

const ceremonyReviewsStatement = `SELECT review_id::text, reviewer, reviewer_principal_id::text, outcome, statement, reviewed_at
FROM identity.bootstrap_ceremony_review WHERE ceremony_id = $1
ORDER BY reviewed_at, review_id`

// insertReviewStatement copies the ceremony's operator, witness and Principal from its row, so the
// foreign key and the independence check hold the review to the ceremony it names.
const insertReviewStatement = `INSERT INTO identity.bootstrap_ceremony_review
    (review_id, ceremony_id, operator, witness, ceremony_principal_id, reviewer, reviewer_principal_id,
     outcome, statement, correlation_id)
SELECT $1, c.id, c.operator, c.witness, c.principal_id, $2, $3, $4, $5, $6
FROM identity.bootstrap_ceremony c WHERE c.id = $7 AND c.principal_id IS NOT NULL`

// Ceremony reads the ceremony's record and its reviews.
func (p *Provisioner) Ceremony(ctx context.Context) (CeremonyView, error) {
	var view CeremonyView
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		view, err = readCeremonyView(ctx, tx)
		return err
	})
	return view, err
}

func readCeremonyView(ctx context.Context, tx db.Tx) (CeremonyView, error) {
	rows, err := tx.Query(ctx, ceremonyViewStatement, ceremonyRowID)
	if err != nil {
		return CeremonyView{}, fmt.Errorf("provisioning: read the ceremony: %w", err)
	}
	if !rows.Next() {
		rows.Close()
		if err := rows.Err(); err != nil {
			return CeremonyView{}, err
		}
		return CeremonyView{}, ErrNoCeremony
	}
	var (
		view      CeremonyView
		principal string
	)
	err = rows.Scan(&view.Operator, &view.Witness, &view.Reason, &principal, &view.RequestedAt)
	rows.Close()
	if err != nil {
		return CeremonyView{}, fmt.Errorf("provisioning: read the ceremony: %w", err)
	}
	view.RequestedAt = view.RequestedAt.UTC()
	if principal != "" {
		parsed, err := id.Parse(principal)
		if err != nil {
			return CeremonyView{}, fmt.Errorf("provisioning: the ceremony names principal_id %q: %w", principal, err)
		}
		view.PrincipalID = &parsed
	}
	reviews, err := tx.Query(ctx, ceremonyReviewsStatement, ceremonyRowID)
	if err != nil {
		return CeremonyView{}, fmt.Errorf("provisioning: read the reviews: %w", err)
	}
	defer reviews.Close()
	view.Reviews = []CeremonyReview{}
	for reviews.Next() {
		var (
			review             CeremonyReview
			reviewID, reviewer string
		)
		if err := reviews.Scan(&reviewID, &review.Reviewer, &reviewer, &review.Outcome, &review.Statement,
			&review.ReviewedAt); err != nil {
			return CeremonyView{}, err
		}
		if review.ReviewID, err = id.Parse(reviewID); err != nil {
			return CeremonyView{}, err
		}
		if review.ReviewerPrincipalID, err = id.Parse(reviewer); err != nil {
			return CeremonyView{}, err
		}
		review.ReviewedAt = review.ReviewedAt.UTC()
		view.Reviews = append(view.Reviews, review)
	}
	view.Reviewed = len(view.Reviews) > 0
	return view, reviews.Err()
}

// ReviewCeremony records one independent review of the ceremony's record. It refuses the operator,
// the witness and the first Principal's holder before the insert, so the refusal is named, and the
// database refuses them again.
func (p *Provisioner) ReviewCeremony(ctx context.Context, req CeremonyReviewRequest) (CeremonyReview, error) {
	switch {
	case strings.TrimSpace(req.Reviewer) == "", strings.TrimSpace(req.Statement) == "",
		strings.TrimSpace(req.Correlation) == "", req.RecordedBy.IsNil():
		return CeremonyReview{}, ErrReviewInvalid
	case req.Outcome != ReviewSatisfactory && req.Outcome != ReviewFindings:
		return CeremonyReview{}, fmt.Errorf("%w: outcome is %q or %q", ErrReviewInvalid, ReviewSatisfactory, ReviewFindings)
	}
	reviewID, err := p.newID()
	if err != nil {
		return CeremonyReview{}, fmt.Errorf("provisioning: mint review_id: %w", err)
	}
	var review CeremonyReview
	err = p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		view, err := readCeremonyView(ctx, tx)
		if err != nil {
			return err
		}
		switch {
		case view.PrincipalID == nil:
			return ErrCeremonyUnnamed
		case samePerson(req.Reviewer, view.Operator), samePerson(req.Reviewer, view.Witness),
			req.RecordedBy == *view.PrincipalID:
			return ErrReviewerNotIndependent
		}
		tag, err := tx.Exec(ctx, insertReviewStatement, reviewID.String(), strings.TrimSpace(req.Reviewer),
			req.RecordedBy.String(), req.Outcome, strings.TrimSpace(req.Statement), req.Correlation, ceremonyRowID)
		if err != nil {
			return fmt.Errorf("provisioning: record the review: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNoCeremony
		}
		return tx.QueryRow(ctx, `SELECT reviewed_at FROM identity.bootstrap_ceremony_review WHERE review_id = $1`,
			reviewID.String()).Scan(&review.ReviewedAt)
	})
	if err != nil {
		return CeremonyReview{}, err
	}
	review.ReviewID, review.Reviewer, review.ReviewerPrincipalID = reviewID, strings.TrimSpace(req.Reviewer), req.RecordedBy
	review.Outcome, review.Statement, review.ReviewedAt = req.Outcome, strings.TrimSpace(req.Statement), review.ReviewedAt.UTC()
	p.logger.InfoContext(ctx, "the bootstrap ceremony's record was reviewed")
	return review, nil
}
