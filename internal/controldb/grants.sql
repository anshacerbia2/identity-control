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
