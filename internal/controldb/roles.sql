-- Cluster roles and the `identity` schema container.
--
-- Applied by `identity-migrate -stage=pre`, before Atlas runs.
--
-- WHY THE ROLES ARE NOT IN schema.hcl: roles are cluster objects, not schema objects.
-- Atlas Community manages schemas, tables, indexes, and constraints declaratively; it does
-- not own the role graph. Declaring roles here as explicit SQL is the honest boundary
-- rather than a workaround, and CI asserts the resulting privileges directly against the
-- catalog so the separation costs no verification.
--
-- WHY THE SCHEMA IS NOT IN schema.hcl EITHER: Atlas is scoped to one schema, and a
-- schema-scoped plan may not modify the schema it is scoped to. The scope is what stops
-- Atlas from reading `platform` and `public` as undeclared drift and planning to drop
-- them, so the schema object is created here and Atlas owns only its contents.
--
-- Every statement is idempotent. PostgreSQL has no CREATE ROLE IF NOT EXISTS, so that
-- guard is explicit.

-- The migration role. Owns the schemas and every object in them, and is the only role
-- holding DDL. TDD-foundation-platform-001 requires schema application and partition
-- maintenance to run under a role distinct from the runtime role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity_migrator') THEN
        CREATE ROLE identity_migrator
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$$;

-- The application role. Holds DML and nothing else.
--
-- NOBYPASSRLS is not a default worth trusting silently: a role created with BYPASSRLS
-- would read every tenant's rows while every Row-Level Security policy in the estate
-- still reported as enabled. It is stated here and asserted in CI.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity_runtime') THEN
        CREATE ROLE identity_runtime
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$$;

-- Re-assert the attributes on an existing role. A role created by an earlier run, by
-- hand, or by a restored dump may carry privileges this file never granted, and the
-- Week 1 exit criterion is a property of the role rather than of the statement that
-- created it.
ALTER ROLE identity_migrator NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE identity_runtime  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- The schema container Atlas fills. Ownership is assigned in grants.sql, after every
-- object inside it exists, so a single place decides who owns what.
CREATE SCHEMA IF NOT EXISTS identity;

COMMENT ON SCHEMA identity IS
    'Identity Control Service authority. Owned by identity_migrator; identity_runtime holds DML only.';
