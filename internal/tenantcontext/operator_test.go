package tenantcontext

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A finding's detail keeps its evidence and loses the kernel user identifier before it is served.
func TestAListedDetailCarriesNoKernelUser(t *testing.T) {
	got, err := withoutKernelUsers(`{"organization_id":"o-1","kernel_user_id":"kc-7","members_removed":2}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "kernel_user_id") || !strings.Contains(string(got), `"organization_id":"o-1"`) {
		t.Errorf("the detail is %s", got)
	}
	if _, err := withoutKernelUsers(`[1]`); err == nil {
		t.Error("a detail that is not an object was accepted")
	}
}

func TestAnOptionalIdentifierParsesOrIsAbsent(t *testing.T) {
	if got, err := optionalID(""); got != nil || err != nil {
		t.Errorf("empty answered %v, %v", got, err)
	}
	if _, err := optionalID("not-a-uuid"); err == nil {
		t.Error("a malformed identifier was accepted")
	}
	if got, err := optionalID("019235f4-0000-7000-8000-000000000001"); err != nil || got == nil {
		t.Errorf("a valid identifier answered %v, %v", got, err)
	}
}

// The findings listing refuses an unknown class and a limit out of range before reading anything.
func TestTheFindingsListingBoundsItsQuery(t *testing.T) {
	r := &Reconciler{}
	if _, err := r.Findings(context.Background(), "nonsense", 0); !errors.Is(err, ErrUnknownClass) {
		t.Errorf("an unknown class answered %v", err)
	}
	for _, limit := range []int{-1, 501} {
		if _, err := r.Findings(context.Background(), "", limit); err == nil {
			t.Errorf("a limit of %d was accepted", limit)
		}
	}
	if err := r.Redrive(context.Background(), [16]byte{}, [16]byte{}, " "); err == nil {
		t.Error("a re-drive without a reason was accepted")
	}
}
