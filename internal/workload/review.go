package workload

// The owner's periodic review (TDD-identity-control-004 1.5.0 §Periodic Review, CIS 5.5, NIST SP
// 800-53 AC-2(j)): the workload's owner vouches that it is still needed, that its purpose holds and
// that its owner and team are right. The review is recorded insert-only with who gave it and what
// they said; anything that does not hold is changed by what changes it, :reassign, :suspend or
// :retire, not by the review.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// ErrNotOwner is a review by anyone but the workload's current owner. The transport answers it as
// not found, so a caller cannot learn which workloads exist.
var ErrNotOwner = errors.New("workload: only the workload's owner reviews it")

// ReviewRequest is one owner's review.
type ReviewRequest struct {
	PrincipalID id.UUID
	ReviewedBy  id.UUID
	Statement   string
}

const insertReviewStatement = `INSERT INTO identity.workload_review (review_id, principal_id, reviewed_by, statement, reviewed_at)
VALUES ($1, $2, $3, $4, $5)`

const resolveOverdueStatement = `UPDATE identity.workload_finding
SET resolved_at = $2, resolution = 'reviewed'
WHERE principal_id = $1 AND finding_class = 'review_overdue' AND resolved_at IS NULL`

// maxStatement bounds what an owner writes.
const maxStatement = 2000

// Review records the owner's review of an active workload and resolves an overdue one.
func (s *Service) Review(ctx context.Context, req ReviewRequest) (Workload, error) {
	statement := strings.TrimSpace(req.Statement)
	switch {
	case req.PrincipalID.IsNil() || req.ReviewedBy.IsNil():
		return Workload{}, fmt.Errorf("%w: a review names the workload and its owner", ErrInvalid)
	case statement == "" || len(statement) > maxStatement:
		return Workload{}, fmt.Errorf("%w: a review states, in at most %d characters, that the workload is still needed, "+
			"its purpose holds and its owner and team are right", ErrInvalid, maxStatement)
	}
	reviewID, err := s.newID()
	if err != nil {
		return Workload{}, fmt.Errorf("workload: mint review_id: %w", err)
	}
	var reviewed Workload
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lock(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		if locked.Owner != req.ReviewedBy {
			return ErrNotOwner
		}
		// The owner counts only while its mapping is an active human one, as its read does
		// (TDD-identity-control-004 1.7.0): a retired owner is anyone else, not a late reviewer.
		if err := s.ownerEligible(ctx, tx, locked.Owner); errors.Is(err, ErrOwnerNotEligible) {
			return ErrNotOwner
		} else if err != nil {
			return err
		}
		if locked.State != StateActive {
			return fmt.Errorf("%w: only an active workload is reviewed; this one is %s", ErrInvalidTransition, locked.State)
		}
		now := s.now()
		if _, err := tx.Exec(ctx, insertReviewStatement, reviewID.String(), req.PrincipalID.String(),
			req.ReviewedBy.String(), statement, now); err != nil {
			return fmt.Errorf("workload: record the review: %w", err)
		}
		if _, err := tx.Exec(ctx, resolveOverdueStatement, req.PrincipalID.String(), now); err != nil {
			return fmt.Errorf("workload: resolve the overdue review: %w", err)
		}
		reviewed, err = s.read(ctx, tx, req.PrincipalID)
		return err
	})
	if err != nil {
		return Workload{}, err
	}
	s.logger.InfoContext(ctx, "a workload's owner reviewed it",
		slog.String("principal_id", req.PrincipalID.String()), slog.String("owner_principal_id", req.ReviewedBy.String()))
	return reviewed, nil
}
