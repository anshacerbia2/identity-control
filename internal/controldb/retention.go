package controldb

// The audit records' retention: kept 7 years, purged after that by this service's own scheduled pass
// (STD-GLB-007 1.2.1 §Data Retention and §5 item 4, TDD-identity-control-001 1.24.0 §Audit Retention).
//
// Three things hold it, and each holds without the others:
//
//   - The tables. Migration 20261020200000_audit_retention gives every audit table a BEFORE DELETE
//     trigger that raises on a row younger than 7 years, and a statement trigger that raises on every
//     bulk emptying, for every role, the owner and a superuser included.
//   - The role. The purge runs as identity_audit_purger, which holds DELETE on the tables purged here
//     and SELECT on the columns these statements read, and nothing else (roles.sql, grants.sql). The
//     runtime is a member WITH INHERIT FALSE, so it never holds the DELETE itself; it becomes the role
//     for the purge's own transaction with SET LOCAL ROLE.
//   - This code. It refuses fewer than AuditRetentionFloor years before it runs anything, and it
//     never purges a row that is still in force, which the trigger cannot know.
//
// # One clock
//
// Every boundary is now() - make_interval(years => n), on the database clock, as the triggers compute
// theirs. now() is the transaction's start, so the purge and the triggers agree on every row.

import (
	"context"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
)

// AuditRetentionFloor is the 7 years STD-GLB-007 keeps an audit record. The tables' retention
// triggers hold the same number, in the database, for every role.
const AuditRetentionFloor = 7

// AuditPurgeRole is the role the purge runs as. roles.sql creates it and grants.sql gives it its
// privileges.
const AuditPurgeRole = "identity_audit_purger"

// AuditTable is one audit table and the columns its age is read from: every timestamptz column it
// holds, the newest of which is when the row was last written. The retention trigger on the table is
// given the same columns, and TestTheRetentionTriggersReadEveryTimestamp holds the two together.
type AuditTable struct {
	Name    string
	Columns []string
}

// AuditTables are this service's audit records (TDD-identity-control-001 §Audit Retention). Every one
// carries the two retention triggers. Purged says whether the scheduled pass deletes from it.
var AuditTables = []struct {
	AuditTable
	Purged bool
}{
	{AuditTable{"identity.privileged_access", []string{"recorded_at"}}, true},
	{AuditTable{"identity.provider_emergency_use", []string{"first_used_at", "last_used_at"}}, true},
	{AuditTable{"identity.kernel_event", []string{"occurred_at", "recorded_at"}}, false},
	{AuditTable{"identity.bootstrap_ceremony", []string{"requested_at"}}, false},
	{AuditTable{"identity.bootstrap_ceremony_review", []string{"reviewed_at"}}, false},
	{AuditTable{"identity.ceremony_grant_retirement", []string{"retired_at"}}, false},
	{AuditTable{"identity.principal_relink", []string{"relinked_at"}}, true},
	{AuditTable{"identity.principal_release", []string{"released_at"}}, true},
	{AuditTable{"identity.principal_adoption", []string{"identifier_time", "newest_mapping_at", "creation_event_at", "adopted_at"}}, true},
	{AuditTable{"identity.registration_adoption", []string{"adopted_at"}}, true},
	{AuditTable{"identity.registration_state_change", []string{"changed_at"}}, true},
	{AuditTable{"identity.registration_change", []string{"proposed_at", "decided_at"}}, true},
	{AuditTable{"identity.registration_request", []string{"proposed_at", "decided_at"}}, true},
	{AuditTable{"identity.registration_owner", []string{"granted_at", "revoked_at"}}, true},
	{AuditTable{"identity.application_developer", []string{"granted_at", "revoked_at"}}, true},
	{AuditTable{"identity.drift_exception", []string{"granted_at", "expires_at"}}, true},
	{AuditTable{"identity.workload_owner_change", []string{"changed_at"}}, true},
	{AuditTable{"identity.workload_review", []string{"reviewed_at"}}, true},
	{AuditTable{"identity.security_operation", []string{"next_attempt_at", "created_at", "applied_at"}}, true},
	{AuditTable{"identity.security_operation_attempt", []string{"claimed_at", "lease_until", "finished_at"}}, true},
	{AuditTable{"identity.temporary_password_issuance", []string{"issued_at", "lapses_at"}}, true},
	{AuditTable{"identity.temporary_password_outcome", []string{"recorded_at"}}, true},
	{AuditTable{"identity.security_notification", []string{"occurred_at", "next_attempt_at", "requested_at", "submitted_at"}}, true},
}

// expired is the boundary every purge statement compares a row's newest timestamp with. $1 is the
// retention in years.
const expired = `< now() - make_interval(years => $1)`

// auditPurges are the statements, in the order they run: a child before the row it references, so a
// foreign key never stops the pass. Each names its table, for the count and for the error.
//
// A row still in force is never purged here, whatever its age, because deleting it would change what
// the service does rather than what it remembers: an ownership or a developer standing not revoked, a
// change or a request not decided, a security command not final (an `unresolved` one can still be
// re-driven), a notification not yet handed over, and a temporary password whose outcome is not
// recorded, which the lapse sweep still owes. TDD-identity-control-001 §Audit Retention lists them.
var auditPurges = []struct{ table, statement string }{
	{"identity.privileged_access",
		`DELETE FROM identity.privileged_access WHERE recorded_at ` + expired},
	{"identity.provider_emergency_use",
		`DELETE FROM identity.provider_emergency_use WHERE greatest(first_used_at, last_used_at) ` + expired},
	{"identity.principal_relink",
		`DELETE FROM identity.principal_relink WHERE relinked_at ` + expired},
	{"identity.principal_release",
		`DELETE FROM identity.principal_release WHERE released_at ` + expired},
	{"identity.principal_adoption",
		`DELETE FROM identity.principal_adoption
		  WHERE greatest(identifier_time, newest_mapping_at, creation_event_at, adopted_at) ` + expired},
	{"identity.registration_adoption",
		`DELETE FROM identity.registration_adoption WHERE adopted_at ` + expired},
	{"identity.registration_state_change",
		`DELETE FROM identity.registration_state_change WHERE changed_at ` + expired},
	{"identity.registration_change",
		`DELETE FROM identity.registration_change
		  WHERE state <> 'proposed' AND greatest(proposed_at, decided_at) ` + expired},
	{"identity.registration_request",
		`DELETE FROM identity.registration_request
		  WHERE state <> 'proposed' AND greatest(proposed_at, decided_at) ` + expired},
	{"identity.registration_owner",
		`DELETE FROM identity.registration_owner
		  WHERE revoked_at IS NOT NULL AND greatest(granted_at, revoked_at) ` + expired},
	{"identity.application_developer",
		`DELETE FROM identity.application_developer
		  WHERE revoked_at IS NOT NULL AND greatest(granted_at, revoked_at) ` + expired},
	{"identity.drift_exception",
		`DELETE FROM identity.drift_exception WHERE greatest(granted_at, expires_at) ` + expired},
	{"identity.workload_owner_change",
		`DELETE FROM identity.workload_owner_change WHERE changed_at ` + expired},
	{"identity.workload_review",
		`DELETE FROM identity.workload_review WHERE reviewed_at ` + expired},
	// An attempt goes with its command: only a finished attempt of a final, expired command.
	{"identity.security_operation_attempt",
		`DELETE FROM identity.security_operation_attempt a
		  WHERE a.finished_at IS NOT NULL
		    AND greatest(a.claimed_at, a.lease_until, a.finished_at) ` + expired + `
		    AND a.operation_id IN (SELECT o.operation_id FROM identity.security_operation o
		                            WHERE o.state IN ('applied', 'refused')
		                              AND greatest(o.next_attempt_at, o.created_at, o.applied_at) ` + expired + `)`},
	{"identity.security_operation",
		`DELETE FROM identity.security_operation o
		  WHERE o.state IN ('applied', 'refused')
		    AND greatest(o.next_attempt_at, o.created_at, o.applied_at) ` + expired + `
		    AND NOT EXISTS (SELECT 1 FROM identity.security_operation_attempt a WHERE a.operation_id = o.operation_id)`},
	// An outcome goes with its issuance, both expired, in one statement: an issuance left without its
	// outcome would read as open, and the lapse sweep would act on it again.
	{"identity.temporary_password_outcome",
		`WITH outcomes AS (
		    DELETE FROM identity.temporary_password_outcome o
		     USING identity.temporary_password_issuance i
		     WHERE i.issuance_id = o.issuance_id
		       AND o.recorded_at ` + expired + `
		       AND greatest(i.issued_at, i.lapses_at) ` + expired + `
		    RETURNING o.issuance_id)
		DELETE FROM identity.temporary_password_issuance i
		 WHERE i.issuance_id IN (SELECT issuance_id FROM outcomes)`},
	{"identity.security_notification",
		`DELETE FROM identity.security_notification
		  WHERE state <> 'requested'
		    AND greatest(occurred_at, next_attempt_at, requested_at, submitted_at) ` + expired},
}

// AuditPurge is how many audit records one pass deleted, by table. The temporary password's outcome
// and issuance are counted as one, under the outcome's table: they go together.
type AuditPurge map[string]int64

// Total is every record the pass deleted.
func (p AuditPurge) Total() int64 {
	var total int64
	for _, n := range p {
		total += n
	}
	return total
}

// Transactor opens a transaction. *db.Pool satisfies it.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// PurgeExpiredAuditRecords deletes the audit records older than years calendar years, in one
// transaction of its own, as AuditPurgeRole, and answers how many from each table.
//
// It refuses fewer than AuditRetentionFloor years before running anything. The database refuses them
// as well, whatever the caller asks: a delete this function did not issue, or a defect in it, can
// remove nothing younger. Any error rolls the whole pass back; the next pass runs it again.
func PurgeExpiredAuditRecords(ctx context.Context, store Transactor, years int) (AuditPurge, error) {
	if years < AuditRetentionFloor {
		return nil, fmt.Errorf("controldb: audit retention of %d years is shorter than the %d years STD-GLB-007 keeps an audit record",
			years, AuditRetentionFloor)
	}
	purged := AuditPurge{}
	err := store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// SET LOCAL ends with this transaction, committed or not, so nothing after it runs as the role.
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+AuditPurgeRole); err != nil {
			return fmt.Errorf("controldb: become %s: %w", AuditPurgeRole, err)
		}
		for _, purge := range auditPurges {
			tag, err := tx.Exec(ctx, purge.statement, years)
			if err != nil {
				return fmt.Errorf("controldb: purge %s: %w", purge.table, err)
			}
			purged[purge.table] = tag.RowsAffected()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return purged, nil
}
