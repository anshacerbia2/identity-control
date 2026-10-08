package workload

// The owner's read (TDD-identity-control-004 1.7.0, ADR-IAM-003 §5.8), against a real PostgreSQL:
// the owner lists and reads its own workloads with their review dates, another's workload is the same
// ErrNotFound as none, and an owner whose mapping is no longer active reads and reviews nothing.

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"
)

func TestTheOwnerReadsAndListsOnlyItsOwnWorkloads(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	mine := h.create("owned-job")
	someone := h.principal("human", "active")
	request := h.request("someone-elses-job")
	request.Owner = someone
	theirs, err := h.service.Create(ctx, request)
	if err != nil {
		t.Fatalf("create another owner's workload: %v", err)
	}

	read, err := h.service.Owned(ctx, mine.PrincipalID, h.owner)
	if err != nil || read.PrincipalID != mine.PrincipalID || read.ClientKey != "owned-job" ||
		read.ReviewDueAt == nil || read.LastReviewedAt != nil {
		t.Fatalf("the owner's read = %+v, %v", read, err)
	}
	unknown, _ := id.NewV7()
	for name, target := range map[string]id.UUID{"another's": theirs.PrincipalID, "an unknown": unknown} {
		if _, err := h.service.Owned(ctx, target, h.owner); !errors.Is(err, ErrNotFound) {
			t.Errorf("the owner reading %s workload answered %v, want ErrNotFound", name, err)
		}
	}

	listed, err := h.service.Mine(ctx, h.owner)
	if err != nil || len(listed) != 1 || listed[0].PrincipalID != mine.PrincipalID || listed[0].ReviewDueAt == nil {
		t.Fatalf("mine = %+v, %v", listed, err)
	}
	if none, err := h.service.Mine(ctx, h.caller); err != nil || none == nil || len(none) != 0 {
		t.Errorf("a Principal owning nothing listed %+v, %v; want an empty list", none, err)
	}

	// A review is listed with its date, and moves the next one.
	reviewed, err := h.service.Review(ctx, ReviewRequest{PrincipalID: mine.PrincipalID, ReviewedBy: h.owner,
		Statement: "still exports payroll; purpose, owner and team hold"})
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if listed, _ := h.service.Mine(ctx, h.owner); len(listed) != 1 || listed[0].LastReviewedAt == nil ||
		!listed[0].ReviewDueAt.Equal(*reviewed.ReviewDueAt) {
		t.Errorf("after the review, mine = %+v", listed)
	}

	// Retired, the owner confers nothing from the next request: no read, no listing, no review.
	h.ownerState("retired")
	if _, err := h.service.Owned(ctx, mine.PrincipalID, h.owner); !errors.Is(err, ErrNotFound) {
		t.Errorf("a retired owner's read answered %v, want ErrNotFound", err)
	}
	if listed, err := h.service.Mine(ctx, h.owner); err != nil || len(listed) != 0 {
		t.Errorf("a retired owner listed %+v, %v", listed, err)
	}
	if _, err := h.service.Review(ctx, ReviewRequest{PrincipalID: mine.PrincipalID, ReviewedBy: h.owner,
		Statement: "still needed"}); !errors.Is(err, ErrNotOwner) {
		t.Errorf("a retired owner's review answered %v, want ErrNotOwner", err)
	}
}
