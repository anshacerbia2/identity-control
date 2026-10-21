package provisioning_test

// Recovery completes the creating request's Idempotency-Key (TDD-identity-control-001 1.14.0),
// against a real PostgreSQL, foundation-platform's idempotency table and the fake kernel.

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// A request whose kernel call failed leaves its key in progress. Once recovery resolves the
// mapping, the caller's retry with the same key is answered the recorded response, the identifier
// the request minted, with no kernel call: not 409 request-in-progress.
func TestARetryAfterRecoveryGetsTheRecordedResponse(t *testing.T) {
	for name, ambiguous := range map[string]bool{
		"the create failed, and recovery creates the user":       false,
		"the create was ambiguous, and recovery adopts the user": true,
	} {
		t.Run(name, func(t *testing.T) {
			p := newPortability(t)
			ctx := context.Background()
			key, _ := id.NewV7()
			request := provisioning.CreateRequest{
				CallerScope: "principal:" + p.operator.String(), IdempotencyKey: key.String(),
				Realm: portabilityRealm, Username: "recovered.user", SubjectType: keycloak.SubjectHuman,
			}

			p.kernel.FailCreate = keycloak.ErrUnavailable
			if ambiguous {
				p.kernel.FailCreate = keycloak.ErrAmbiguous
				p.kernel.AmbiguousCreateSucceeds = true
			}
			if _, err := p.provisioner.Create(ctx, request); err == nil {
				t.Fatal("Create succeeded although the kernel call failed")
			}
			p.kernel.FailCreate = nil
			p.kernel.AmbiguousCreateSucceeds = false

			if _, err := p.provisioner.Create(ctx, request); !errors.Is(err, idempotency.ErrInProgress) {
				t.Fatalf("a retry before recovery = %v, want request-in-progress", err)
			}

			var principal string
			if err := p.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
				// Older than the recovery threshold, as an interrupted request's row would be.
				if err := tx.QueryRow(ctx, `UPDATE identity.principal_mapping
					SET created_at = now() - interval '2 minutes'
					WHERE realm = $1 AND username = 'recovered.user' AND state = 'pending'
					RETURNING principal_id::text`, string(portabilityRealm)).Scan(&principal); err != nil {
					return err
				}
				return nil
			}); err != nil {
				t.Fatalf("age the pending mapping: %v", err)
			}

			resolved, err := p.provisioner.RecoverPending(ctx)
			if err != nil || resolved != 1 {
				t.Fatalf("RecoverPending = %d, %v; want 1 resolved", resolved, err)
			}
			if got := p.mappingState(id.MustParse(principal)); got != "active" {
				t.Fatalf("the mapping is %s after recovery, want active", got)
			}

			calls := p.kernel.Calls.CreateUser
			replayed, err := p.provisioner.Create(ctx, request)
			if err != nil {
				t.Fatalf("a retry after recovery = %v, want the recorded response", err)
			}
			if replayed.PrincipalID.String() != principal {
				t.Errorf("the retry answered %s, want the identifier the request minted, %s", replayed.PrincipalID, principal)
			}
			if p.kernel.Calls.CreateUser != calls {
				t.Errorf("the retry called the kernel's create %d more time(s); a replay makes no remote call",
					p.kernel.Calls.CreateUser-calls)
			}
		})
	}
}

// An enrolment's create the kernel refuses as a duplicate quarantines its mapping, so recovery has
// nothing to finish, and writes its creation address proven when it succeeds (TDD-identity-control-001
// 1.27.0, ADR-IAM-011 §5.3, §5.9).
func TestAnEnrolmentsCreateIsQuarantinedOnADuplicateAndProvenOtherwise(t *testing.T) {
	h := newPortability(t)
	ctx := context.Background()
	h.kernel.RefuseDuplicateEmail = true
	taken := "taken." + mustUUIDString(t) + "@example.test"
	h.kernel.SeedEmail(portabilityRealm, "stray-"+mustUUIDString(t), taken)
	key := mustUUIDString(t)
	_, err := h.provisioner.Create(ctx, provisioning.CreateRequest{CallerScope: "enrolment", IdempotencyKey: key,
		Realm: portabilityRealm, Username: taken, Email: taken, SubjectType: keycloak.SubjectHuman,
		VerifiedEmail: true, QuarantineOnConflict: true})
	if !errors.Is(err, provisioning.ErrKernelDuplicate) {
		t.Fatalf("a duplicate returned %v, want ErrKernelDuplicate", err)
	}
	var state string
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM identity.principal_mapping WHERE idempotency_scope = 'enrolment' AND idempotency_key = $1`,
			key).Scan(&state)
	}); err != nil || state != "quarantined" {
		t.Fatalf("the mapping is %q (%v), want quarantined", state, err)
	}

	fresh := "fresh." + mustUUIDString(t) + "@example.test"
	created, err := h.provisioner.Create(ctx, provisioning.CreateRequest{CallerScope: "enrolment", IdempotencyKey: mustUUIDString(t),
		Realm: portabilityRealm, Username: fresh, Email: fresh, SubjectType: keycloak.SubjectHuman,
		VerifiedEmail: true, QuarantineOnConflict: true})
	if err != nil {
		t.Fatal(err)
	}
	var proven bool
	if err := h.pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT verified_at IS NOT NULL FROM identity.notification_address WHERE principal_id = $1`,
			created.PrincipalID.String()).Scan(&proven)
	}); err != nil || !proven {
		t.Errorf("the enrolled creation address is not proven (%v)", err)
	}
}

func mustUUIDString(t *testing.T) string {
	t.Helper()
	v, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return v.String()
}
