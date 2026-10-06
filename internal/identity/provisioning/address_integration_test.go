package provisioning

// The creation address (ADR-IAM-007 §5.2, TDD-identity-control-008 §Data Model): the email a person is
// created with is their first notification address, written with the pending mapping. A workload, and
// a person created with no email, get none.

import (
	"context"
	"os"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func TestTheCreationEmailIsTheFirstNotificationAddress(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_INTEGRATION") != "" {
			t.Fatal("REQUIRE_INTEGRATION is set and TEST_DATABASE_URL is empty")
		}
		t.Skip("TEST_DATABASE_URL is unset")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, db.Config{Name: "address-test", DSN: dsn, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	insert := func(m Mapping) {
		t.Helper()
		if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return Repository{}.InsertPending(ctx, tx, m)
		}); err != nil {
			t.Fatalf("insert %s: %v", m.Username, err)
		}
	}
	addresses := func(principal id.UUID) []string {
		t.Helper()
		var out []string
		if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			rows, err := tx.Query(ctx, `SELECT address || ' ' || origin || ' ' || state FROM identity.notification_address
			    WHERE principal_id = $1`, principal.String())
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err != nil {
					return err
				}
				out = append(out, s)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}

	person, _ := id.NewV7()
	insert(Mapping{PrincipalID: person, Realm: "address-test", Username: "a-" + person.String(),
		Email: "person@example.test", SubjectType: keycloak.SubjectHuman})
	if got := addresses(person); len(got) != 1 || got[0] != "person@example.test creation active" {
		t.Errorf("a person's addresses are %v; want the creation email, active", got)
	}

	silent, _ := id.NewV7()
	insert(Mapping{PrincipalID: silent, Realm: "address-test", Username: "s-" + silent.String(), SubjectType: keycloak.SubjectHuman})
	if got := addresses(silent); len(got) != 0 {
		t.Errorf("a person created with no email has addresses %v", got)
	}

	owner, _ := id.NewV7()
	workload, _ := id.NewV7()
	insert(Mapping{PrincipalID: workload, Realm: "address-test", Username: "w-" + workload.String(),
		Email: "w@example.test", SubjectType: keycloak.SubjectWorkload, WorkloadOwner: owner})
	if got := addresses(workload); len(got) != 0 {
		t.Errorf("a workload has addresses %v; only a person is told", got)
	}
}
