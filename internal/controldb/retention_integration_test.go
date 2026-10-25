package controldb_test

// The audit records' retention, proven against PostgreSQL: STD-GLB-007 1.2.1 §5 item 4, "A service
// that holds audit records tests that its purge deletes only records older than 7 years", and "that a
// direct `DELETE` of a younger record and a `TRUNCATE` are refused, as the migration role and as a
// superuser" (TDD-identity-control-001 1.24.0 §Audit Retention). This service holds no Tenant's data,
// so it has no Tenant decommissioning purge to leave them.
//
// The suite's connection is the superuser that applies the migrations here (CI and deploy/dev), and
// so the tables' owner: one connection is the migration role and the superuser both. The rows it
// writes are dated by hand, years back, and removed afterwards in a transaction that sets
// session_replication_role, a superuser's setting, which the triggers are written to stop for anyone
// else.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/controldb"
)

func newUUID(t *testing.T) string {
	t.Helper()
	u, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return u.String()
}

// exec runs statements in one transaction and answers its error.
func exec(ctx context.Context, pool *db.Pool, statements ...string) error {
	return pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	})
}

// refusedByRetention says whether err is a retention trigger's refusal, not some other failure. Read
// from the message, because no package here names the driver (arch.json deniedImports).
func refusedByRetention(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "never deleted") || strings.Contains(message, "never emptied in bulk")
}

// TestTheRetentionTriggersReadEveryTimestamp holds the migration and controldb.AuditTables together:
// each audit table's row trigger is given every timestamptz column the table holds, the columns the
// purge reads its age from, and its statement trigger refuses the bulk statement.
func TestTheRetentionTriggersReadEveryTimestamp(t *testing.T) {
	pool, ctx := openPool(t)
	for _, table := range controldb.AuditTables {
		name := strings.TrimPrefix(table.Name, "identity.")
		columns := queryStrings(t, pool, ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'identity' AND table_name = $1 AND data_type = 'timestamp with time zone'
			ORDER BY ordinal_position`, name)
		if !slices.Equal(sorted(columns), sorted(table.Columns)) {
			t.Errorf("%s holds timestamps %v; controldb.AuditTables names %v", table.Name, columns, table.Columns)
		}
		// tgtype bits: 1 row, 2 before, 8 delete, 32 truncate (PostgreSQL's pg_trigger.h).
		args := queryStrings(t, pool, ctx, `SELECT unnest(string_to_array(rtrim(encode(tg.tgargs, 'escape'), '\000'), '\000'))
			FROM pg_trigger tg WHERE tg.tgrelid = $1::regclass AND tg.tgname = $2 AND tg.tgtype = 1 | 2 | 8
			  AND tg.tgfoid = 'identity.refuse_young_audit_delete'::regproc AND tg.tgenabled = 'O'`,
			table.Name, name+"_retention")
		if !slices.Equal(args, table.Columns) {
			t.Errorf("%s_retention reads %v, want %v", name, args, table.Columns)
		}
		if !queryBool(t, pool, ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger tg WHERE tg.tgrelid = $1::regclass
			AND tg.tgname = $2 AND tg.tgtype = 2 | 32 AND tg.tgenabled = 'O'
			AND tg.tgfoid = 'identity.refuse_young_audit_delete'::regproc)`, table.Name, name+"_no_truncate") {
			t.Errorf("%s has no enabled BEFORE TRUNCATE statement trigger", table.Name)
		}
	}
}

func sorted(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}

// TestAYoungAuditRecordIsNeverDeleted: a record younger than 7 years is refused to the superuser that
// owns the table and to the purge role, and every audit table refuses TRUNCATE.
func TestAYoungAuditRecordIsNeverDeleted(t *testing.T) {
	pool, ctx := openPool(t)
	young, old := newUUID(t), newUUID(t)
	insert := `INSERT INTO identity.privileged_access (access_id, actor_principal_id, action, route, outcome,
		correlation_id, emergency, recorded_at) VALUES ('%s', '%s', 'retention.test', '/test', 'served', 'retention-test', false, %s)`
	if err := exec(ctx, pool,
		fmt.Sprintf(insert, young, newUUID(t), "now() - interval '6 years 364 days'"),
		fmt.Sprintf(insert, old, newUUID(t), "now() - interval '7 years 1 day'")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec(context.Background(), pool, `SET LOCAL session_replication_role = replica`,
			fmt.Sprintf(`DELETE FROM identity.privileged_access WHERE access_id IN ('%s', '%s')`, young, old))
	})

	deleteYoung := fmt.Sprintf(`DELETE FROM identity.privileged_access WHERE access_id = '%s'`, young)
	if err := exec(ctx, pool, deleteYoung); !refusedByRetention(err) {
		t.Errorf("the superuser deleted a record younger than 7 years: %v", err)
	}
	// The purge role reads only recorded_at, so it names each row by its time. Each attempt is in a
	// transaction rolled back whatever happens.
	var youngAt, oldAt time.Time
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT recorded_at FROM identity.privileged_access WHERE access_id = $1`, young).Scan(&youngAt); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT recorded_at FROM identity.privileged_access WHERE access_id = $1`, old).Scan(&oldAt)
	}); err != nil {
		t.Fatal(err)
	}
	asPurgeRole := func(at time.Time) (int64, error) {
		var deleted int64
		err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+controldb.AuditPurgeRole); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `DELETE FROM identity.privileged_access WHERE recorded_at = $1`, at)
			if err != nil {
				return err
			}
			deleted = tag.RowsAffected()
			return errRollback
		})
		if errors.Is(err, errRollback) {
			err = nil
		}
		return deleted, err
	}
	if _, err := asPurgeRole(youngAt); !refusedByRetention(err) {
		t.Errorf("the purge role deleted a record younger than 7 years: %v", err)
	}
	if !queryBool(t, pool, ctx, `SELECT EXISTS (SELECT 1 FROM identity.privileged_access WHERE access_id = $1)`, young) {
		t.Error("the young record is gone")
	}
	// The boundary holds on the other side: one day past 7 years is deleted by the purge role.
	if deleted, err := asPurgeRole(oldAt); err != nil || deleted < 1 {
		t.Errorf("the purge role could not delete a record older than 7 years: %d, %v", deleted, err)
	}
	// And the purge role reads nothing else: not even the row's identifier.
	err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+controldb.AuditPurgeRole); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT access_id FROM identity.privileged_access LIMIT 1`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the purge role read an identifier: %v", err)
	}

	// Each in a transaction that is rolled back whatever happens, so a missing trigger fails the test
	// and empties nothing. CASCADE, so a table another audit table references reaches its trigger
	// rather than stopping on the reference.
	for _, table := range controldb.AuditTables {
		err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			if _, err := tx.Exec(ctx, `TRUNCATE `+table.Name+` CASCADE`); err != nil {
				return err
			}
			return errRollback
		})
		if !refusedByRetention(err) {
			t.Errorf("TRUNCATE %s was not refused by its retention trigger: %v", table.Name, err)
		}
	}
}

// TestTheAuditPurgeDeletesOnlyExpiredRecords runs the scheduled pass's purge and reads what it left:
// records past 7 years gone, younger ones kept, and a record still in force kept at any age.
func TestTheAuditPurgeDeletesOnlyExpiredRecords(t *testing.T) {
	pool, ctx := openPool(t)
	if _, err := controldb.PurgeExpiredAuditRecords(ctx, pool, controldb.AuditRetentionFloor-1); err == nil {
		t.Error("the purge accepted 6 years")
	}

	person, operator := newUUID(t), newUUID(t)
	access := map[string]string{"expired": newUUID(t), "young": newUUID(t)}
	operation := map[string]string{"final": newUUID(t), "unresolved": newUUID(t)}
	issuance := map[string]string{"closed": newUUID(t), "open": newUUID(t)}
	setup := []string{
		fmt.Sprintf(`INSERT INTO identity.principal_mapping (principal_id, realm, username, subject_type, state)
			VALUES ('%s', 'retention-test', 'retention-%s', 'human', 'suspended')`, person, person),
		fmt.Sprintf(`INSERT INTO identity.security_subject_state (principal_id) VALUES ('%s')`, person),
	}
	pa := `INSERT INTO identity.privileged_access (access_id, actor_principal_id, action, route, outcome,
		correlation_id, emergency, recorded_at) VALUES ('%s', '%s', 'retention.test', '/test', 'served', 'retention-test', false, %s)`
	setup = append(setup,
		fmt.Sprintf(pa, access["expired"], operator, "now() - interval '8 years'"),
		fmt.Sprintf(pa, access["young"], operator, "now() - interval '6 years'"))
	op := `INSERT INTO identity.security_operation (operation_id, principal_id, subject_sequence, actor_principal_id,
		idempotency_key, request_digest, operation_type, expected_version, correlation_id, assurance, emergency,
		state, next_attempt_at, created_at, applied_at)
		VALUES ('%s', '%s', %s, '%s', '%s', 'digest', 'suspend', 1, 'retention-test', 'aal2', false, '%s',
		        now() - interval '8 years', now() - interval '8 years', %s)`
	setup = append(setup,
		fmt.Sprintf(op, operation["final"], person, "1", operator, operation["final"], "applied", "now() - interval '8 years'"),
		fmt.Sprintf(op, operation["unresolved"], person, "2", operator, operation["unresolved"], "unresolved", "NULL"),
		fmt.Sprintf(`INSERT INTO identity.security_operation_attempt (operation_id, attempt, claimed_at, lease_until, finished_at, outcome)
			VALUES ('%s', 1, now() - interval '8 years', now() - interval '8 years', now() - interval '8 years', 'applied')`, operation["final"]),
		fmt.Sprintf(`INSERT INTO identity.security_operation_attempt (operation_id, attempt, claimed_at, lease_until, finished_at, outcome)
			VALUES ('%s', 1, now() - interval '8 years', now() - interval '8 years', now() - interval '8 years', 'unresolved')`, operation["unresolved"]))
	tp := `INSERT INTO identity.temporary_password_issuance (issuance_id, principal_id, issued_by, reason, correlation_id,
		emergency, assurance, issued_at, lapses_at)
		VALUES ('%s', '%s', '%s', 'retention test', 'retention-test', false, 'aal2', now() - interval '8 years', now() - interval '8 years' + interval '1 hour')`
	setup = append(setup,
		fmt.Sprintf(tp, issuance["closed"], person, operator),
		fmt.Sprintf(tp, issuance["open"], person, operator),
		fmt.Sprintf(`INSERT INTO identity.temporary_password_outcome (issuance_id, outcome, recorded_at)
			VALUES ('%s', 'used', now() - interval '8 years')`, issuance["closed"]))
	if err := exec(ctx, pool, setup...); err != nil {
		t.Fatalf("seed the records: %v", err)
	}
	t.Cleanup(func() {
		_ = exec(context.Background(), pool, `SET LOCAL session_replication_role = replica`,
			fmt.Sprintf(`DELETE FROM identity.privileged_access WHERE actor_principal_id = '%s'`, operator),
			fmt.Sprintf(`DELETE FROM identity.security_operation_attempt WHERE operation_id IN
				(SELECT operation_id FROM identity.security_operation WHERE principal_id = '%s')`, person),
			fmt.Sprintf(`DELETE FROM identity.security_operation WHERE principal_id = '%s'`, person),
			fmt.Sprintf(`DELETE FROM identity.temporary_password_outcome WHERE issuance_id IN
				(SELECT issuance_id FROM identity.temporary_password_issuance WHERE principal_id = '%s')`, person),
			fmt.Sprintf(`DELETE FROM identity.temporary_password_issuance WHERE principal_id = '%s'`, person),
			fmt.Sprintf(`DELETE FROM identity.security_subject_state WHERE principal_id = '%s'`, person),
			fmt.Sprintf(`DELETE FROM identity.principal_mapping WHERE principal_id = '%s'`, person))
	})

	purged, err := controldb.PurgeExpiredAuditRecords(ctx, pool, controldb.AuditRetentionFloor)
	if err != nil {
		t.Fatalf("the purge failed: %v", err)
	}
	if purged["identity.privileged_access"] < 1 || purged["identity.security_operation"] < 1 ||
		purged["identity.security_operation_attempt"] < 1 || purged["identity.temporary_password_outcome"] < 1 {
		t.Errorf("the purge counted %v", purged)
	}
	if purged.Total() < 4 {
		t.Errorf("the purge counted %d records in all, want at least 4", purged.Total())
	}

	exists := func(statement, key string) bool {
		return queryBool(t, pool, ctx, `SELECT EXISTS (`+statement+`)`, key)
	}
	for _, check := range []struct {
		what, statement, key string
		kept                 bool
	}{
		{"an access 8 years old", `SELECT 1 FROM identity.privileged_access WHERE access_id = $1`, access["expired"], false},
		{"an access 6 years old", `SELECT 1 FROM identity.privileged_access WHERE access_id = $1`, access["young"], true},
		{"an applied command 8 years old", `SELECT 1 FROM identity.security_operation WHERE operation_id = $1`, operation["final"], false},
		{"its attempt", `SELECT 1 FROM identity.security_operation_attempt WHERE operation_id = $1`, operation["final"], false},
		{"an unresolved command 8 years old, which can still be re-driven", `SELECT 1 FROM identity.security_operation WHERE operation_id = $1`, operation["unresolved"], true},
		{"its attempt", `SELECT 1 FROM identity.security_operation_attempt WHERE operation_id = $1`, operation["unresolved"], true},
		{"a used temporary password's issuance, 8 years old", `SELECT 1 FROM identity.temporary_password_issuance WHERE issuance_id = $1`, issuance["closed"], false},
		{"its outcome", `SELECT 1 FROM identity.temporary_password_outcome WHERE issuance_id = $1`, issuance["closed"], false},
		{"an issuance with no outcome, which the lapse sweep still owes", `SELECT 1 FROM identity.temporary_password_issuance WHERE issuance_id = $1`, issuance["open"], true},
	} {
		if got := exists(check.statement, check.key); got != check.kept {
			t.Errorf("%s: kept %v, want %v", check.what, got, check.kept)
		}
	}
}

// TestTheSigningKeyRegistryIsPurgedOnlyAfterItsKeyEnds holds the registry's retention
// (TDD-identity-control-001 1.29.0 §The Signing Key Registry): a key's rows go together once its
// retired or revoked row is 7 years old, and never while the key is in force, however old.
func TestTheSigningKeyRegistryIsPurgedOnlyAfterItsKeyEnds(t *testing.T) {
	pool, ctx := openPool(t)
	kid := func() string {
		sum := sha256.Sum256([]byte(newUUID(t)))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	ended, recent, inForce := kid(), kid(), kid()
	key := `INSERT INTO identity.signing_key (kid, realm, algorithm, public_jwk, custody_ref, operator, witness, reason,
		correlation_id, staged_at) VALUES ('%s', 'retention-test', 'PS256', '{}', 'test', 'operator', 'witness', 'test',
		'retention-test', now() - interval '%s')`
	approval := `INSERT INTO identity.signing_key_approval (approval_id, kid, transition, operator, approver, reason,
		correlation_id, approved_at) VALUES ('%s', '%s', '%s', 'operator', 'approver', 'test', 'retention-test',
		now() - interval '%s')`
	row := `INSERT INTO identity.signing_key_transition (transition_id, kid, step, from_state, to_state, actor,
		approval_id, reason, correlation_id, outcome, evidence, occurred_at)
		VALUES ('%s', '%s', '%s', %s, '%s', 'operator', %s, 'test', 'retention-test', 'completed', %s, now() - interval '%s')`
	var setup []string
	for _, k := range []struct{ kid, staged, ended, end string }{
		{ended, "9 years", "8 years", "retired"},
		{recent, "9 years", "6 years", "revoked"},
		{inForce, "9 years", "", ""},
	} {
		activation, end := newUUID(t), newUUID(t)
		setup = append(setup,
			fmt.Sprintf(key, k.kid, k.staged),
			fmt.Sprintf(row, newUUID(t), k.kid, "stage", "NULL", "staged", "NULL", "NULL", k.staged),
			fmt.Sprintf(approval, activation, k.kid, "activate", k.staged),
			fmt.Sprintf(row, newUUID(t), k.kid, "activate", "'staged'", "active", "'"+activation+"'", "NULL", k.staged))
		if k.end != "" {
			step := map[string]string{"retired": "retire", "revoked": "revoke"}[k.end]
			setup = append(setup,
				fmt.Sprintf(row, newUUID(t), k.kid, "demote", "'active'", "retiring", "'"+newUUID(t)+"'", "NULL", k.staged),
				fmt.Sprintf(approval, end, k.kid, step, k.ended),
				fmt.Sprintf(row, newUUID(t), k.kid, step, "'retiring'", k.end, "'"+end+"'", "'files removed'", k.ended))
		}
	}
	if err := exec(ctx, pool, setup...); err != nil {
		t.Fatalf("seed the registry: %v", err)
	}
	t.Cleanup(func() {
		in := fmt.Sprintf("('%s', '%s', '%s')", ended, recent, inForce)
		_ = exec(context.Background(), pool, `SET LOCAL session_replication_role = replica`,
			`DELETE FROM identity.signing_key_transition WHERE kid IN `+in,
			`DELETE FROM identity.signing_key_approval WHERE kid IN `+in,
			`DELETE FROM identity.signing_key WHERE kid IN `+in)
	})

	purged, err := controldb.PurgeExpiredAuditRecords(ctx, pool, controldb.AuditRetentionFloor)
	if err != nil {
		t.Fatalf("the purge failed: %v", err)
	}
	if purged["identity.signing_key"] < 1 || purged["identity.signing_key_transition"] < 4 ||
		purged["identity.signing_key_approval"] < 2 {
		t.Errorf("the purge counted %v", purged)
	}
	for _, check := range []struct {
		what, kid string
		kept      bool
	}{
		{"a key retired 8 years ago", ended, false},
		{"a key revoked 6 years ago", recent, true},
		{"an active key staged 9 years ago, still in force", inForce, true},
	} {
		for _, table := range []string{"signing_key", "signing_key_approval", "signing_key_transition"} {
			got := queryBool(t, pool, ctx, `SELECT EXISTS (SELECT 1 FROM identity.`+table+` WHERE kid = $1)`, check.kid)
			if got != check.kept {
				t.Errorf("%s: %s kept %v, want %v", check.what, table, got, check.kept)
			}
		}
	}
}
