#!/bin/sh
# The Control Database pipeline, in a container: the same four sources, in the same order, as
# scripts/dev-database.ps1 and a deployment.
#
#   1. databases            identity_control and Atlas's scratch atlas_dev (development only)
#   2. identity-migrate -stage=pre      roles, then foundation-platform's platform schema
#   3. atlas migrate apply              the identity schema
#   4. identity-migrate -stage=post     privileges
#   5. the identity_app login role, and an assertion of the privilege shape
#
# The order is load-bearing: grants.sql refuses to run before the objects it grants on exist, because
# an earlier pipeline ran it first and it granted nothing, silently. Idempotent, so it runs on every
# `docker compose up`.
#
# POSTGRES_SUPER_URL is the server's superuser, without a database: roles.sql creates roles, which is a
# cluster-level act. A deployment runs this as a role with CREATEROLE instead; the SQL is identical.
set -eu

: "${POSTGRES_SUPER_URL:?POSTGRES_SUPER_URL is required}"
: "${IDENTITY_APP_PASSWORD:?IDENTITY_APP_PASSWORD is required}"
base="${POSTGRES_SUPER_URL%/}"
database=identity_control
dev=atlas_dev

sql() { psql -v ON_ERROR_STOP=1 -qtA "$@"; }

echo "[1/5] databases"
for name in "$database" "$dev"; do
	if [ "$(sql -d "$base/postgres" -c "SELECT 1 FROM pg_database WHERE datname = '$name'")" != "1" ]; then
		sql -d "$base/postgres" -c "CREATE DATABASE \"$name\""
		echo "      created $name"
	fi
done
# Atlas's scratch database is schema-scoped like the target; the schema must exist before it can be
# materialised there. CI found this as `schema "identity" was not found`.
sql -d "$base/$dev" -c 'CREATE SCHEMA IF NOT EXISTS identity'

scoped="sslmode=disable&search_path=identity"

echo "[2/5] identity-migrate -stage=pre"
IDENTITY_MIGRATION_DATABASE_URL="$base/$database?$scoped" identity-migrate -stage=pre

echo "[3/5] atlas migrate apply"
DATABASE_URL="$base/$database?$scoped" ATLAS_DEV_URL="$base/$dev?$scoped" atlas migrate apply --env local

echo "[4/5] identity-migrate -stage=post"
IDENTITY_MIGRATION_DATABASE_URL="$base/$database?$scoped" identity-migrate -stage=post

echo "[5/5] login role identity_app"
# The password travels as a psql variable, quoted by psql, never spliced into the SQL text.
psql -v ON_ERROR_STOP=1 -q -d "$base/$database" -v app_password="$IDENTITY_APP_PASSWORD" <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity_app') THEN
        CREATE ROLE identity_app LOGIN;
    END IF;
END
$$;
ALTER ROLE identity_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'app_password';
GRANT identity_runtime TO identity_app;
SQL

# The privilege shape, asked of the database rather than trusted. Each has been wrong once.
check() {
	got="$(sql -d "$base/$database" -c "$2")"
	if [ "$got" != "$3" ]; then
		echo "      FAIL $1 (got $got, want $3)" >&2
		exit 1
	fi
	echo "      ok   $1"
}
check "runtime can insert principal_mapping" "SELECT has_table_privilege('identity_app','identity.principal_mapping','INSERT')" t
check "runtime cannot create in identity" "SELECT has_schema_privilege('identity_app','identity','CREATE')" f
check "runtime cannot reach the atlas schema" "SELECT has_schema_privilege('identity_app','atlas','USAGE')" f
check "runtime owns no table" "SELECT count(*) = 0 FROM pg_tables WHERE tableowner IN ('identity_app','identity_runtime')" t

echo "control database ready"
