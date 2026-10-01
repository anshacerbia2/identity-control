package registration

// Application developer standing against the real database (ADR-IAM-003 §5.3,
// TDD-identity-control-003 §Application Developers).

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// developer records an active person and grants it the standing.
func (h *harness) developer() id.UUID {
	h.t.Helper()
	person := h.person("human")
	if err := h.service.GrantApplicationDeveloper(context.Background(),
		DeveloperChange{Principal: person, ChangedBy: h.caller, Reason: "builds the orders service"}); err != nil {
		h.t.Fatalf("grant the standing: %v", err)
	}
	h.t.Cleanup(func() {
		_ = h.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM identity.application_developer WHERE principal_id = $1`, person.String())
			return err
		})
	})
	return person
}

// asDeveloper is a registration request made on the developer's standing.
func (h *harness) asDeveloper(developer id.UUID, key, profile string) Request {
	req := h.request(key, profile)
	req.CallerScope, req.RegisteredBy, req.Developer = "principal:"+developer.String(), developer, true
	return req
}

func TestAProviderGrantsTheStandingToAnActivePerson(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	workload := h.person("workload")
	if err := h.service.GrantApplicationDeveloper(ctx, DeveloperChange{Principal: workload, ChangedBy: h.caller, Reason: "r"}); !errors.Is(err, ErrOwnerNotEligible) {
		t.Errorf("granting a workload answered %v, want ErrOwnerNotEligible", err)
	}
	if err := h.service.GrantApplicationDeveloper(ctx, DeveloperChange{Principal: workload, ChangedBy: h.caller}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a grant without a reason answered %v, want ErrInvalid", err)
	}

	developer := h.developer()
	if err := h.service.GrantApplicationDeveloper(ctx, DeveloperChange{Principal: developer, ChangedBy: h.caller, Reason: "again"}); !errors.Is(err, ErrAlreadyDeveloper) {
		t.Errorf("a second grant answered %v, want ErrAlreadyDeveloper", err)
	}
	if is, err := h.service.IsApplicationDeveloper(ctx, developer); err != nil || !is {
		t.Fatalf("the grantee holds no standing: %v, %v", is, err)
	}
	listed, err := h.service.ApplicationDevelopers(ctx)
	found := false
	for _, grant := range listed {
		found = found || (grant.Principal == developer && grant.Active && grant.GrantedBy == h.caller)
	}
	if err != nil || !found {
		t.Errorf("the grant is not listed active: %v", err)
	}

	// A Principal that is no longer active holds nothing, without a revocation.
	h.setMapping(developer, "quarantined")
	if is, _ := h.service.IsApplicationDeveloper(ctx, developer); is {
		t.Error("a quarantined Principal still holds the standing")
	}
	h.setMapping(developer, "active")

	if err := h.service.RevokeApplicationDeveloper(ctx, DeveloperChange{Principal: developer, ChangedBy: h.caller, Reason: "moved teams"}); err != nil {
		t.Fatal(err)
	}
	if is, _ := h.service.IsApplicationDeveloper(ctx, developer); is {
		t.Error("a revoked grant still confers the standing")
	}
	if err := h.service.RevokeApplicationDeveloper(ctx, DeveloperChange{Principal: developer, ChangedBy: h.caller, Reason: "again"}); !errors.Is(err, ErrDeveloperNotFound) {
		t.Errorf("a second revocation answered %v, want ErrDeveloperNotFound", err)
	}
}

func TestAnApplicationDeveloperRegistersAndOwnsTheRegistration(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	developer := h.developer()

	registered, err := h.service.Register(ctx, h.asDeveloper(developer, "dev-web", ProfilePublic))
	if err != nil || registered.State != StateActive {
		t.Fatalf("register: %+v, %v", registered, err)
	}
	if owns, _ := h.service.Owns(ctx, developer, registered.ID); !owns {
		t.Error("the developer does not own what it registered")
	}
	owners, _ := h.service.Owners(ctx, registered.ID)
	if len(owners) != 1 || owners[0].GrantedBy != developer || owners[0].GrantReason != firstOwnerReason {
		t.Errorf("the first owner is %+v", owners)
	}

	// Its own resource may be in its client's audience; another team's may not.
	resource := h.asDeveloper(developer, "dev-api", ProfileResource)
	resource.LifetimeClass, resource.RedirectURIs = "L1", nil
	if _, err := h.service.Register(ctx, resource); err != nil {
		t.Fatalf("register a resource: %v", err)
	}
	h.resource("their-api", "L1")
	ownAudience := h.asDeveloper(developer, "dev-client", ProfilePublic)
	ownAudience.Audience = []string{"dev-api"}
	if _, err := h.service.Register(ctx, ownAudience); err != nil {
		t.Errorf("a client for the developer's own resource answered %v", err)
	}
	theirs := h.asDeveloper(developer, "dev-theirs", ProfilePublic)
	theirs.Audience = []string{"dev-api", "their-api"}
	if _, err := h.service.Register(ctx, theirs); !errors.Is(err, ErrDeveloperScope) {
		t.Errorf("a client for another team's resource answered %v, want ErrDeveloperScope", err)
	}
	if n := h.registrationsNamed("dev-theirs"); n != 0 {
		t.Errorf("a refused registration left %d records", n)
	}
}

func TestAnApplicationDeveloperRegistersOnlyWithinItsBounds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	developer := h.developer()

	privileged := h.asDeveloper(developer, "dev-admin", ProfilePublic)
	privileged.AudienceClass = "privileged"
	workload := h.asDeveloper(developer, "dev-job", ProfileWorkload)
	workload.AudienceClass, workload.RedirectURIs = "workload", nil
	for name, req := range map[string]Request{"privileged class": privileged, "workload profile": workload} {
		if _, err := h.service.Register(ctx, req); !errors.Is(err, ErrDeveloperScope) {
			t.Errorf("a developer's %s answered %v, want ErrDeveloperScope", name, err)
		}
		if n := h.registrationsNamed(req.ClientKey); n != 0 {
			t.Errorf("a refused %s left %d records", name, n)
		}
	}

	h.service.cfg.Production = true
	if _, err := h.service.Register(ctx, h.asDeveloper(developer, "dev-prod", ProfilePublic)); !errors.Is(err, ErrDeveloperScope) {
		t.Errorf("a developer's production registration answered %v, want ErrDeveloperScope", err)
	}
	h.service.cfg.Production = false

	// Standing revoked after the transport read it creates nothing.
	stranger := h.person("human")
	if _, err := h.service.Register(ctx, h.asDeveloper(stranger, "dev-stranger", ProfilePublic)); !errors.Is(err, ErrNotDeveloper) {
		t.Errorf("a registration without the standing answered %v, want ErrNotDeveloper", err)
	}
	if n := h.registrationsNamed("dev-stranger"); n != 0 {
		t.Errorf("a refused registration left %d records", n)
	}
}
