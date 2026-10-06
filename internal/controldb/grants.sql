-- Privileges for the runtime role on both schemas.
--
-- Applied by `identity-migrate -stage=post`, after the platform migrations and after
-- Atlas has applied the `identity` schema. It runs last because GRANT names objects, and
-- an object that does not exist yet cannot be granted on.
--
-- The Week 1 exit criterion is that the runtime role owns no table, holds no SUPERUSER,
-- no BYPASSRLS, and no DDL privilege. Everything below is written to make that true, and
-- ci.yml asserts it against the catalog rather than trusting this file to be complete.
--
-- foundation-platform ships the `platform` schema with no GRANT of its own, deliberately:
-- it does not know what the consuming system's roles are called. Granting on it is
-- therefore this repository's obligation, and forgetting it produces a runtime that
-- cannot reach its own outbox.

-- ORDERING GUARD.
--
-- `GRANT ... ON ALL TABLES IN SCHEMA x` over an empty schema is a no-op, not an error.
-- Run before Atlas has applied schema.hcl, this file therefore reports success and grants
-- nothing, and the failure surfaces later as a runtime that cannot read its own tables.
-- That is exactly what happened the first time this pipeline ran end to end, so the
-- ordering is asserted here rather than trusted to the caller.
DO $$
DECLARE
    missing TEXT;
BEGIN
    SELECT string_agg(expected.name, ', ' ORDER BY expected.name)
      INTO missing
      FROM (VALUES
              ('identity.principal_mapping'),
              ('identity.projection_cursor'),
              ('identity.bootstrap_ceremony'),
              ('identity.client_registration'),
              ('identity.reconcile_run'),
              ('identity.registration_finding'),
              ('identity.drift_exception'),
              ('identity.client_key'),
              ('identity.workload'),
              ('identity.workload_owner_change'),
              ('identity.registration_adoption'),
              ('identity.registration_state_change'),
              ('identity.registration_owner'),
              ('identity.registration_change'),
              ('identity.application_developer'),
              ('identity.registration_request'),
              ('identity.provider_grant'),
              ('identity.provider_emergency_use'),
              ('identity.provider_projection'),
              ('identity.ceremony_grant_retirement'),
              ('identity.privileged_access'),
              ('identity.security_subject_state'),
              ('identity.security_operation'),
              ('identity.security_operation_attempt'),
              ('identity.principal_relink'),
              ('identity.principal_finding'),
              ('identity.tenant_desired'),
              ('identity.membership_desired'),
              ('identity.tenant_convergence'),
              ('identity.projection_finding'),
              ('identity.kernel_event'),
              ('identity.kernel_event_mark'),
              ('identity.notification_address'),
              ('identity.security_notification'),
              ('platform.outbox'),
              ('platform.processed_event'),
              ('platform.dead_letter'),
              ('platform.idempotency_key')
           ) AS expected(name)
     WHERE to_regclass(expected.name) IS NULL;

    IF missing IS NOT NULL THEN
        RAISE EXCEPTION
            'grants stage ran before its objects existed; missing: %', missing
            USING HINT = 'run identity-migrate -stage=pre, then atlas migrate apply, then this stage';
    END IF;
END
$$;

-- Ownership. Every object belongs to the migration role, which is what leaves the
-- runtime role unable to alter or drop anything regardless of its DML grants.
ALTER SCHEMA identity OWNER TO identity_migrator;
ALTER SCHEMA platform OWNER TO identity_migrator;

-- CREATE on a schema is a DDL privilege. PostgreSQL grants it to the schema owner only,
-- but PUBLIC retains USAGE on schemas by default in some configurations, so both are
-- stated rather than assumed.
REVOKE ALL ON SCHEMA identity FROM PUBLIC;
REVOKE ALL ON SCHEMA platform FROM PUBLIC;

GRANT USAGE ON SCHEMA identity TO identity_runtime;
GRANT USAGE ON SCHEMA platform TO identity_runtime;

-- DML only. CREATE, TRUNCATE, and REFERENCES are withheld: TRUNCATE on platform.outbox
-- would let the runtime discard undelivered security events, which is the one operation
-- the partition retention job exists to perform under the migration role.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA identity TO identity_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA platform TO identity_runtime;

-- The bootstrap ceremony record is insert-only, and the narrowing is applied after the
-- schema-wide grant above rather than by excluding the table from it. Listing tables
-- individually there would mean a new table is unreachable until someone remembers to add it;
-- revoking here means a new table is readable and only this one is special.
--
-- ADR-IAM-001 §5.8 requires the operator and reason on record to be immutable. Without the
-- REVOKE, the runtime role inherits UPDATE and DELETE from the schema-wide grant, and whoever
-- runs the ceremony a second time could rewrite who ran it the first time — which is the entire
-- value of the record.
--
-- SELECT and INSERT remain: the ceremony claims the row, and a resumed ceremony reads it back.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.bootstrap_ceremony FROM identity_runtime;

-- The registration records are evidence, and TDD-identity-control-003 keeps each of them after it
-- stops mattering operationally: a retired registration stays auditable, a converged finding is
-- the record that a console change happened, and a finished run is how the reconciler is
-- observed. So none of them is deletable by the runtime. The findings and runs keep UPDATE,
-- because a sweep finishes its run and converges its findings.
--
-- A drift exception is insert-only as well. It permits one console change for a bounded time,
-- and one the runtime could edit could be extended by whoever wanted the change kept.
REVOKE DELETE, TRUNCATE ON identity.client_registration FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.reconcile_run FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.registration_finding FROM identity_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON identity.drift_exception FROM identity_runtime;

-- A client key is evidence too: a revoked key is the record of which key pair stopped
-- authenticating a client, and when. So nothing deletes one. A key is also never rewritten. The key
-- material, its kid, its owner and its dates are fixed at registration, and the runtime may change
-- only what a rotation, a revocation or an expiry changes. A runtime that could rewrite public_jwk
-- could swap a client's registered key for one whose private half it holds, and the next rebuild of
-- the kernel's JWKS would install it.
--
-- The table-level UPDATE is revoked before the column-level one is granted, because revoking a table
-- privilege also revokes it on every column.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.client_key FROM identity_runtime;
GRANT UPDATE (state, retiring_at, revoked_at, revoked_by, revocation_reason) ON identity.client_key TO identity_runtime;

-- A workload record outlives the workload: a retired workload stays the record of who answered for
-- a credential and why it existed. A change of owner is insert-only, so the record of who was
-- answerable at a given time cannot be rewritten by whoever holds the workload now.
REVOKE DELETE, TRUNCATE ON identity.workload FROM identity_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON identity.workload_owner_change FROM identity_runtime;

-- An adoption record says who brought a client created outside this service under registration,
-- why, and what the client held then. Insert-only (ADR-IAM-001 §5.12 rule 5).
REVOKE UPDATE, DELETE, TRUNCATE ON identity.registration_adoption FROM identity_runtime;

-- A lifecycle record says who suspended, restored or retired a client, when and why. Insert-only
-- (ADR-IAM-001 §5.13), so the record of a containment cannot be rewritten by whoever lifts it.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.registration_state_change FROM identity_runtime;

-- An ownership says who could act on a registration besides a provider, granted by whom and why
-- (ADR-IAM-003). Nothing deletes one, and only its revocation is ever written after the grant: the
-- table-level UPDATE is revoked before the column-level one is granted, as for client_key.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.registration_owner FROM identity_runtime;
GRANT UPDATE (revoked_at, revoked_by, revoke_reason) ON identity.registration_owner TO identity_runtime;

-- A change says who asked for which redirect URIs against which version, and why (ADR-IAM-003
-- §5.2). Its content and its proposer are never rewritten and nothing deletes one: only its
-- decision is written after the proposal.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.registration_change FROM identity_runtime;
GRANT UPDATE (state, decided_by, decision_reason, decided_at) ON identity.registration_change TO identity_runtime;

-- Application developer standing is held as an ownership is (ADR-IAM-003 §5.3): granted with a
-- reason, never deleted, and only its revocation written after the grant.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.application_developer FROM identity_runtime;
GRANT UPDATE (revoked_at, revoked_by, revoke_reason) ON identity.application_developer TO identity_runtime;

-- A registration request says who asked for which production client, naming which owners, and
-- why (ADR-IAM-003 §5.3). Its document and its proposer are never rewritten and nothing deletes
-- one: only its decision, and the registration an approval created, are written after it.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.registration_request FROM identity_runtime;
GRANT UPDATE (state, decided_by, decision_reason, decided_at, registration_id) ON identity.registration_request TO identity_runtime;

-- A relink record says who moved a Principal to a new Keycloak user and why, so it is insert-only.
-- A dangling-mapping finding is evidence that a user disappeared, kept after it is resolved.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.principal_relink FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.principal_finding FROM identity_runtime;
-- The provider authority projection (TDD-identity-control-006): written by the delivery intake and
-- the bootstrap, replaced by version, never deleted. A revoked grant stays as the record a late,
-- older event is discarded against.
REVOKE DELETE, TRUNCATE ON identity.provider_grant FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.provider_projection FROM identity_runtime;
-- The use of each projected emergency grant (ADR-ORG-002 §5.2): every request one authorizes
-- records it, and the validation report reads it. Only the last use and the count are rewritten,
-- and nothing deletes one: it is the evidence that the grant was validated.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.provider_emergency_use FROM identity_runtime;
GRANT UPDATE (last_used_at, uses) ON identity.provider_emergency_use TO identity_runtime;
-- The Tenant context projection keeps a row per Tenant and per Membership, superseded by version
-- and never removed (TDD-identity-control-002 2.0.0).
REVOKE DELETE, TRUNCATE ON identity.tenant_desired FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.membership_desired FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.tenant_convergence FROM identity_runtime;
-- A finding is evidence: written once, never changed or removed.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.projection_finding FROM identity_runtime;
-- The kernel event record (TDD-identity-control-007, STD-IAM-001 §3.8): written once by the sweep,
-- never edited, and kept until Audit & Evidence has it. The mark moves; nothing deletes it.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.kernel_event FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.kernel_event_mark FROM identity_runtime;
-- Account security notifications (ADR-IAM-007, TDD-identity-control-008). An address is removed by
-- its state, never deleted, so the record of where a person was told survives. A request is evidence
-- that the person was told, or that they could not be: its state moves forward and nothing deletes one.
REVOKE DELETE, TRUNCATE ON identity.notification_address FROM identity_runtime;
REVOKE DELETE, TRUNCATE ON identity.security_notification FROM identity_runtime;
-- The ceremony grant ends once, by an insert, and is never revived: insert-only like the ceremony
-- row it retires (TDD-identity-control-006 §The Ceremony's Grant).
REVOKE UPDATE, DELETE, TRUNCATE ON identity.ceremony_grant_retirement FROM identity_runtime;
-- Every administrative read and command (TDD-identity-control-005 §Evidence). Audit information is
-- protected from modification and deletion (NIST SP 800-53 AU-9), so the runtime inserts and reads
-- and does nothing else.
REVOKE UPDATE, DELETE, TRUNCATE ON identity.privileged_access FROM identity_runtime;
-- A security command is the record of who asked to contain whom, why and when (TDD-identity-control-005
-- §Containment as Built). Nothing deletes one, and its request is never rewritten: only its execution
-- state is written after acceptance. An attempt is insert-only but for its own finish. The subject
-- state is a counter, updated by every command and never deleted.
REVOKE DELETE, TRUNCATE ON identity.security_subject_state FROM identity_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON identity.security_operation FROM identity_runtime;
GRANT UPDATE (state, attempts, next_attempt_at, result_code, last_error_class, applied_at, redriven_at) ON identity.security_operation TO identity_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON identity.security_operation_attempt FROM identity_runtime;
GRANT UPDATE (finished_at, outcome, error_class) ON identity.security_operation_attempt TO identity_runtime;

-- platform.outbox_sequence is read by every append. Without USAGE the outbox write fails
-- inside the caller's domain transaction, so a membership mutation would roll back.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA identity TO identity_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA platform TO identity_runtime;

-- The partition maintenance helpers are invoked by the migration job, never by the
-- runtime. EXECUTE is granted to nobody else.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA platform FROM PUBLIC;

-- A table added by a future migration inherits these privileges. Without this, the next
-- schema change ships a table the runtime cannot read, and the failure appears at
-- request time rather than at deploy time.
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA identity
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO identity_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA platform
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO identity_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA identity
    GRANT USAGE, SELECT ON SEQUENCES TO identity_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE identity_migrator IN SCHEMA platform
    GRANT USAGE, SELECT ON SEQUENCES TO identity_runtime;
