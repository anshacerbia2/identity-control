SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- Audit retention in the database: STD-GLB-007 1.2.1 §Data Retention and §5 item 4,
-- TDD-identity-control-001 1.24.0 §Audit Retention.
--
-- An audit record younger than 7 years is never deleted, by any role. Each audit table gets two
-- triggers. A BEFORE DELETE row trigger raises on a row younger than 7 years, and a statement
-- trigger raises on every emptying of the table. The error rolls the statement back: "if either the
-- statement or the trigger causes an error, the effects of both will be rolled back" (PostgreSQL 17,
-- Overview of Trigger Behavior). A row-level security policy is not used: it binds neither a superuser
-- nor the table's owner, and whole-table operations are "not subject to row security" (PostgreSQL 17,
-- Row Security Policies). organization-control's audit.refuse_young_audit_delete is the precedent.
--
-- A row's age is its newest timestamp: the greatest of every timestamptz column it holds, passed to
-- the function by name. A row whose columns are all null is refused, never deleted. The boundary is
-- now() - 7 years on the database clock, as the purge computes it (internal/controldb/retention.go).
--
-- CREATE OR REPLACE because Atlas, scoped to the schema, clears its dev database between replays of
-- this directory by the objects it models, and Atlas Community models no function: a plain CREATE
-- met the copy the previous replay left (found running `atlas migrate validate` then `diff`).
--
-- The purge itself, and which tables it reaches, is the code's (TDD-identity-control-001 §Audit
-- Retention). The triggers hold the floor for every table, purged or not.
CREATE OR REPLACE FUNCTION identity.refuse_young_audit_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    column_name TEXT;
    stamp       TIMESTAMPTZ;
    recorded    TIMESTAMPTZ;
BEGIN
    IF TG_LEVEL = 'STATEMENT' THEN
        RAISE EXCEPTION 'audit records are never emptied in bulk: %.% keeps each record 7 years', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING HINT = 'STD-GLB-007 1.2.1; the scheduled pass purges records older than that';
    END IF;
    FOREACH column_name IN ARRAY TG_ARGV LOOP
        stamp := (to_jsonb(OLD) ->> column_name)::timestamptz;
        IF stamp IS NOT NULL AND (recorded IS NULL OR stamp > recorded) THEN
            recorded := stamp;
        END IF;
    END LOOP;
    IF recorded IS NULL OR recorded >= now() - make_interval(years => 7) THEN
        RAISE EXCEPTION 'an audit record younger than 7 years is never deleted: %.% was last written at %',
                        TG_TABLE_SCHEMA, TG_TABLE_NAME, recorded
            USING HINT = 'STD-GLB-007 1.2.1; the scheduled pass purges records older than that';
    END IF;
    RETURN OLD;
END;
$$;
COMMENT ON FUNCTION identity.refuse_young_audit_delete() IS
    'Refuses the delete of an audit record younger than 7 years, and every bulk emptying. STD-GLB-007 1.2.1.';
-- The statement triggers below name the statement they refuse. The text match of ADR-GLB-004 §5.1
-- item 2 reads the word, so each line carries its reviewed approval: it creates a trigger that
-- refuses the statement, and removes nothing.
CREATE TRIGGER "privileged_access_retention" BEFORE DELETE ON "privileged_access"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('recorded_at');
CREATE TRIGGER "privileged_access_no_truncate" BEFORE TRUNCATE ON "privileged_access" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "provider_emergency_use_retention" BEFORE DELETE ON "provider_emergency_use"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('first_used_at', 'last_used_at');
CREATE TRIGGER "provider_emergency_use_no_truncate" BEFORE TRUNCATE ON "provider_emergency_use" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "kernel_event_retention" BEFORE DELETE ON "kernel_event"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('occurred_at', 'recorded_at');
CREATE TRIGGER "kernel_event_no_truncate" BEFORE TRUNCATE ON "kernel_event" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "bootstrap_ceremony_retention" BEFORE DELETE ON "bootstrap_ceremony"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('requested_at');
CREATE TRIGGER "bootstrap_ceremony_no_truncate" BEFORE TRUNCATE ON "bootstrap_ceremony" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "bootstrap_ceremony_review_retention" BEFORE DELETE ON "bootstrap_ceremony_review"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('reviewed_at');
CREATE TRIGGER "bootstrap_ceremony_review_no_truncate" BEFORE TRUNCATE ON "bootstrap_ceremony_review" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "ceremony_grant_retirement_retention" BEFORE DELETE ON "ceremony_grant_retirement"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('retired_at');
CREATE TRIGGER "ceremony_grant_retirement_no_truncate" BEFORE TRUNCATE ON "ceremony_grant_retirement" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "principal_relink_retention" BEFORE DELETE ON "principal_relink"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('relinked_at');
CREATE TRIGGER "principal_relink_no_truncate" BEFORE TRUNCATE ON "principal_relink" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "principal_release_retention" BEFORE DELETE ON "principal_release"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('released_at');
CREATE TRIGGER "principal_release_no_truncate" BEFORE TRUNCATE ON "principal_release" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "principal_adoption_retention" BEFORE DELETE ON "principal_adoption"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('identifier_time', 'newest_mapping_at', 'creation_event_at', 'adopted_at');
CREATE TRIGGER "principal_adoption_no_truncate" BEFORE TRUNCATE ON "principal_adoption" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "registration_adoption_retention" BEFORE DELETE ON "registration_adoption"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('adopted_at');
CREATE TRIGGER "registration_adoption_no_truncate" BEFORE TRUNCATE ON "registration_adoption" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "registration_state_change_retention" BEFORE DELETE ON "registration_state_change"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('changed_at');
CREATE TRIGGER "registration_state_change_no_truncate" BEFORE TRUNCATE ON "registration_state_change" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "registration_change_retention" BEFORE DELETE ON "registration_change"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('proposed_at', 'decided_at');
CREATE TRIGGER "registration_change_no_truncate" BEFORE TRUNCATE ON "registration_change" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "registration_request_retention" BEFORE DELETE ON "registration_request"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('proposed_at', 'decided_at');
CREATE TRIGGER "registration_request_no_truncate" BEFORE TRUNCATE ON "registration_request" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "registration_owner_retention" BEFORE DELETE ON "registration_owner"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('granted_at', 'revoked_at');
CREATE TRIGGER "registration_owner_no_truncate" BEFORE TRUNCATE ON "registration_owner" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "application_developer_retention" BEFORE DELETE ON "application_developer"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('granted_at', 'revoked_at');
CREATE TRIGGER "application_developer_no_truncate" BEFORE TRUNCATE ON "application_developer" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "drift_exception_retention" BEFORE DELETE ON "drift_exception"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('granted_at', 'expires_at');
CREATE TRIGGER "drift_exception_no_truncate" BEFORE TRUNCATE ON "drift_exception" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "workload_owner_change_retention" BEFORE DELETE ON "workload_owner_change"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('changed_at');
CREATE TRIGGER "workload_owner_change_no_truncate" BEFORE TRUNCATE ON "workload_owner_change" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "workload_review_retention" BEFORE DELETE ON "workload_review"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('reviewed_at');
CREATE TRIGGER "workload_review_no_truncate" BEFORE TRUNCATE ON "workload_review" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "security_operation_retention" BEFORE DELETE ON "security_operation"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('next_attempt_at', 'created_at', 'applied_at');
CREATE TRIGGER "security_operation_no_truncate" BEFORE TRUNCATE ON "security_operation" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "security_operation_attempt_retention" BEFORE DELETE ON "security_operation_attempt"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('claimed_at', 'lease_until', 'finished_at');
CREATE TRIGGER "security_operation_attempt_no_truncate" BEFORE TRUNCATE ON "security_operation_attempt" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "temporary_password_issuance_retention" BEFORE DELETE ON "temporary_password_issuance"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('issued_at', 'lapses_at');
CREATE TRIGGER "temporary_password_issuance_no_truncate" BEFORE TRUNCATE ON "temporary_password_issuance" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "temporary_password_outcome_retention" BEFORE DELETE ON "temporary_password_outcome"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('recorded_at');
CREATE TRIGGER "temporary_password_outcome_no_truncate" BEFORE TRUNCATE ON "temporary_password_outcome" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "security_notification_retention" BEFORE DELETE ON "security_notification"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('occurred_at', 'next_attempt_at', 'requested_at', 'submitted_at');
CREATE TRIGGER "security_notification_no_truncate" BEFORE TRUNCATE ON "security_notification" -- atlas:destructive-approved 2026-10-20: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
