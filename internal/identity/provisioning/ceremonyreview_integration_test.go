package provisioning_test

// The bootstrap ceremony's witness and its independent review against a real PostgreSQL
// (STD-IAM-001 2.9.0 §3.10, ADR-IAM-001 §5.11 requirement 3): both people are on the insert-only
// record, and the review refuses the operator, the witness and the first Principal, in the code and
// in the database.

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
)

// ceremonyHeld empties the single-row ceremony table for the test and puts back what was there, as
// the provider authority suite does: the row is shared with whatever else ran against this database.
func ceremonyHeld(t *testing.T, p *portability) {
	t.Helper()
	ceremonyLock(t, p.pool)
	clear := func() error {
		return p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			for _, statement := range []string{
				// The audit tables refuse a young record's delete to every role (STD-GLB-007 1.2.1);
				// the test's rows go with the triggers off, for this transaction alone.
				`SET LOCAL session_replication_role = replica`,
				`DELETE FROM identity.ceremony_grant_retirement`,
				`DELETE FROM identity.bootstrap_ceremony_review`,
				`DELETE FROM identity.bootstrap_ceremony`,
			} {
				if _, err := tx.Exec(ctx, statement); err != nil {
					return err
				}
			}
			return nil
		})
	}
	var count int
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.bootstrap_ceremony`).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	if count > 0 {
		t.Skip("this database holds a ceremony another suite owns")
	}
	t.Cleanup(func() { _ = clear() })
}

func TestTheCeremonyRecordsTheWitnessAndAnIndependentReview(t *testing.T) {
	p := newPortability(t)
	ceremonyHeld(t, p)
	// The registry is shared with the other suites, so the ceremony's row is written as the ceremony
	// writes it rather than by Bootstrap, which refuses a populated registry.
	first, _ := id.NewV7()
	if err := p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.bootstrap_ceremony (id, operator, reason, idempotency_key, principal_id, witness)
		    VALUES (1, 'Operator Name', 'the suite''s ceremony', 'bootstrap:suite', $1, 'Witness Name')`, first.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	response := provisioning.Response{PrincipalID: first}
	record, performed, err := p.provisioner.CeremonyPerformed(context.Background())
	if err != nil || !performed || record.Witness != "Witness Name" {
		t.Errorf("CeremonyPerformed: %+v, %v, %v", record, performed, err)
	}
	view, err := p.provisioner.Ceremony(context.Background())
	if err != nil || view.Operator != "Operator Name" || view.Witness != "Witness Name" || view.Reviewed ||
		view.PrincipalID == nil || *view.PrincipalID != response.PrincipalID {
		t.Fatalf("Ceremony: %+v, %v", view, err)
	}

	reviewer, _ := id.NewV7()
	review := func(name string, by id.UUID) error {
		_, err := p.provisioner.ReviewCeremony(context.Background(), provisioning.CeremonyReviewRequest{
			Reviewer: name, RecordedBy: by, Outcome: provisioning.ReviewSatisfactory,
			Statement: "record matches the change ticket", Correlation: "corr-1"})
		return err
	}
	for name, c := range map[string]struct {
		name string
		by   id.UUID
	}{
		"the operator":        {" operator name ", reviewer},
		"the witness":         {"WITNESS NAME", reviewer},
		"the first Principal": {"Someone Else", response.PrincipalID},
	} {
		if err := review(c.name, c.by); !errors.Is(err, provisioning.ErrReviewerNotIndependent) {
			t.Errorf("a review by %s answered %v", name, err)
		}
	}
	if err := review("Security Reviewer", reviewer); err != nil {
		t.Fatalf("an independent review: %v", err)
	}
	view, err = p.provisioner.Ceremony(context.Background())
	if err != nil || !view.Reviewed || len(view.Reviews) != 1 || view.Reviews[0].Reviewer != "Security Reviewer" ||
		view.Reviews[0].ReviewerPrincipalID != reviewer || view.Reviews[0].Outcome != provisioning.ReviewSatisfactory {
		t.Fatalf("after the review: %+v, %v", view, err)
	}

	// The database refuses what the code refuses: a review naming the witness, written past the code.
	err = p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.bootstrap_ceremony_review
		    (review_id, ceremony_id, operator, witness, ceremony_principal_id, reviewer, reviewer_principal_id,
		     outcome, statement, correlation_id)
		    SELECT gen_random_uuid(), id, operator, witness, principal_id, 'witness name', $1, 'satisfactory', 's', 'c'
		    FROM identity.bootstrap_ceremony`, reviewer.String())
		return err
	})
	if err == nil {
		t.Error("the database accepted a review by the witness")
	}
	// And a review naming another ceremony's people than the one recorded.
	err = p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO identity.bootstrap_ceremony_review
		    (review_id, ceremony_id, operator, witness, ceremony_principal_id, reviewer, reviewer_principal_id,
		     outcome, statement, correlation_id)
		    SELECT gen_random_uuid(), id, 'Not The Operator', witness, principal_id, 'Operator Name', $1, 'satisfactory', 's', 'c'
		    FROM identity.bootstrap_ceremony`, reviewer.String())
		return err
	})
	if err == nil {
		t.Error("the database accepted a review whose operator is not the ceremony's")
	}
	// The witness is never the operator, in the database too.
	err = p.pool.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE identity.bootstrap_ceremony SET witness = operator`)
		return err
	})
	if err == nil {
		t.Error("the database accepted the operator as witness")
	}
}

// ceremonyLock serializes the suites that write the single-row ceremony table: this one and
// internal/identity/provisioning's ceremony review suite, which run as separate packages and in
// parallel against one database. A transaction-scoped advisory lock is held, on one of the pool's
// connections, until the test ends.
func ceremonyLock(t *testing.T, p *db.Pool) {
	t.Helper()
	locked, release, done := make(chan error, 1), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(4242001)`)
			locked <- err
			if err != nil {
				return err
			}
			<-release
			return nil
		})
	}()
	if err := <-locked; err != nil {
		t.Fatalf("take the ceremony lock: %v", err)
	}
	t.Cleanup(func() { close(release); <-done })
}
