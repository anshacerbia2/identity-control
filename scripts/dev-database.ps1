# Builds a local Control Database for identity-control.
#
# Runs the same four-source pipeline the deployment runs, in the same order, so a local database
# has the same privilege shape as a deployed one:
#
#   1. CREATE DATABASE                      (local only; a deployment is handed a database)
#   2. identity-migrate -stage=pre          roles, then foundation-platform's platform schema
#   3. atlas migrate apply                  the identity schema
#   4. identity-migrate -stage=post         privileges
#
# The order is load-bearing. grants.sql opens with a guard that raises if the objects it grants
# on do not exist yet, because an earlier version of this pipeline ran it first and it granted
# nothing at all — silently, with no error and no privileges.
#
# SECRETS: read from the environment, never defaulted, never written to a file.
#
#   $env:PGPASSWORD          = '...'   # the superuser password, for step 1 only
#   $env:IDENTITY_APP_PASSWORD = '...' # the login role identity-control authenticates as
#
# Optional:
#   -SeedBootstrapPrincipal            with BOOTSTRAP_PRINCIPAL_ID and BOOTSTRAP_KEYCLOAK_ID set
#
# Usage: pwsh ./scripts/dev-database.ps1

param(
    [switch]$SeedBootstrapPrincipal
)

$ErrorActionPreference = "Stop"

$pgHost   = if ($env:PGHOST) { $env:PGHOST } else { "127.0.0.1" }
$pgPort   = if ($env:PGPORT) { $env:PGPORT } else { "5432" }
$pgSuper  = if ($env:PGUSER) { $env:PGUSER } else { "postgres" }
$database = if ($env:IDENTITY_DATABASE_NAME) { $env:IDENTITY_DATABASE_NAME } else { "identity_control_dev" }
$devDb    = if ($env:ATLAS_DEV_DATABASE_NAME) { $env:ATLAS_DEV_DATABASE_NAME } else { "atlas_dev" }

if ([string]::IsNullOrWhiteSpace($env:PGPASSWORD)) {
    throw "PGPASSWORD is required (the superuser password). This script defaults no credential."
}
if ([string]::IsNullOrWhiteSpace($env:IDENTITY_APP_PASSWORD)) {
    throw "IDENTITY_APP_PASSWORD is required. This script defaults no credential."
}

# Both tools are overridable because neither is reliably on PATH on Windows: psql lives under
# "C:\Program Files\PostgreSQL\<major>\bin" and the Atlas CLI is distributed as a bare exe.
$psql  = if ($env:PSQL) { $env:PSQL } else { "psql" }
$atlas = if ($env:ATLAS) { $env:ATLAS } else { "atlas" }
$superPassword = $env:PGPASSWORD

function Invoke-Psql($db, $sql) {
    $env:PGPASSWORD = $superPassword
    & $psql -U $pgSuper -h $pgHost -p $pgPort -d $db -v ON_ERROR_STOP=1 -q -c $sql
    if ($LASTEXITCODE -ne 0) { throw "psql failed on $db" }
}

# ---------------------------------------------------------------------------------------------
Write-Host "[1/5] databases"
# `atlas_dev` is Atlas's scratch database. It must be a real PostgreSQL of the same major
# version as the target, because Atlas materialises the desired state there to compute a diff:
# a version mismatch produces a plan that is correct for the wrong server.
foreach ($name in @($database, $devDb)) {
    $exists = & $psql -U $pgSuper -h $pgHost -p $pgPort -d postgres -tAc `
        "SELECT 1 FROM pg_database WHERE datname = '$name';"
    if ($exists -ne "1") {
        Invoke-Psql "postgres" "CREATE DATABASE `"$name`";"
        Write-Host "      created $name"
    } else {
        Write-Host "      $name exists"
    }
}

# ---------------------------------------------------------------------------------------------
Write-Host "[2/5] identity-migrate -stage=pre"
# The migration DSN authenticates as the superuser locally because roles.sql creates roles, which
# is a cluster-level act. A deployment runs this stage as a role with CREATEROLE rather than as a
# superuser; the SQL is identical.
$env:IDENTITY_MIGRATION_DATABASE_URL =
    "postgres://${pgSuper}:${superPassword}@${pgHost}:${pgPort}/${database}?sslmode=disable&search_path=identity"
go run ./cmd/identity-migrate -stage=pre
if ($LASTEXITCODE -ne 0) { throw "stage=pre failed" }

# ---------------------------------------------------------------------------------------------
Write-Host "[3/5] atlas migrate apply"
# Both urls are scoped to `search_path=identity`. That scope is load-bearing: the first plan this
# repository generated was produced in database scope and ended with DROP SCHEMA "public" CASCADE,
# because `public` is not declared in schema.hcl. Unscoped, the same reasoning drops `platform`.
$env:DATABASE_URL =
    "postgres://${pgSuper}:${superPassword}@${pgHost}:${pgPort}/${database}?sslmode=disable&search_path=identity"
$env:ATLAS_DEV_URL =
    "postgres://${pgSuper}:${superPassword}@${pgHost}:${pgPort}/${devDb}?sslmode=disable&search_path=identity"
& $atlas migrate apply --env local
if ($LASTEXITCODE -ne 0) { throw "atlas migrate apply failed" }

# ---------------------------------------------------------------------------------------------
Write-Host "[4/5] identity-migrate -stage=post"
go run ./cmd/identity-migrate -stage=post
if ($LASTEXITCODE -ne 0) { throw "stage=post failed" }

# ---------------------------------------------------------------------------------------------
Write-Host "[5/5] login role identity_app"
# identity_migrator and identity_runtime are NOLOGIN group roles: they carry privilege and cannot
# be authenticated as. A deployable authenticates as a login role that inherits one of them, so
# rotating a credential never touches a grant. identity_app inherits identity_runtime, which
# holds DML and no DDL — a migration attempted through the runtime pool fails at the database.
$appPassword = $env:IDENTITY_APP_PASSWORD
Invoke-Psql $database @"
DO `$`$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity_app') THEN
        CREATE ROLE identity_app LOGIN;
    END IF;
END
`$`$;
ALTER ROLE identity_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '$appPassword';
GRANT identity_runtime TO identity_app;
"@

# Assert the privilege shape rather than trusting the grants ran. Each of these has been wrong at
# some point in this repository's history, and each was found by asking the database.
$checks = @(
    @{ label = "runtime can insert principal_mapping"; sql = "SELECT has_table_privilege('identity_app','identity.principal_mapping','INSERT');"; want = "t" }
    @{ label = "runtime cannot create in identity";    sql = "SELECT has_schema_privilege('identity_app','identity','CREATE');";               want = "f" }
    @{ label = "runtime cannot reach atlas schema";    sql = "SELECT has_schema_privilege('identity_app','atlas','USAGE');";                   want = "f" }
    @{ label = "runtime owns no table";                sql = "SELECT count(*) = 0 FROM pg_tables WHERE tableowner IN ('identity_app','identity_runtime');"; want = "t" }
)
$failed = $false
foreach ($check in $checks) {
    $env:PGPASSWORD = $superPassword
    $got = (& $psql -U $pgSuper -h $pgHost -p $pgPort -d $database -tAc $check.sql).Trim()
    $verdict = if ($got -eq $check.want) { "ok" } else { "FAIL (got $got, want $($check.want))"; $failed = $true }
    Write-Host "      $($check.label): $verdict"
}
if ($failed) { throw "the privilege shape is wrong; do not run the service against this database" }

# ---------------------------------------------------------------------------------------------
if ($SeedBootstrapPrincipal) {
    Write-Host "[+] bootstrap principal"
    # Out-of-band Principal creation, which TDD-identity-control-001 prohibits. See the bootstrap
    # note in dev-keycloak.ps1: the first Principal in a realm cannot be created through the only
    # sanctioned path, because that path requires an authenticated Principal. Local only.
    if ([string]::IsNullOrWhiteSpace($env:BOOTSTRAP_PRINCIPAL_ID) -or
        [string]::IsNullOrWhiteSpace($env:BOOTSTRAP_KEYCLOAK_ID)) {
        throw "BOOTSTRAP_PRINCIPAL_ID and BOOTSTRAP_KEYCLOAK_ID are required with -SeedBootstrapPrincipal"
    }
    $realm = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
    Invoke-Psql $database @"
INSERT INTO identity.principal_mapping
    (principal_id, keycloak_user_id, realm, username, email, subject_type, state, activated_at)
VALUES
    ('$($env:BOOTSTRAP_PRINCIPAL_ID)', '$($env:BOOTSTRAP_KEYCLOAK_ID)', '$realm',
     'bootstrap-operator', 'bootstrap-operator@scnehaux.local', 'human', 'active', now())
ON CONFLICT (principal_id) DO NOTHING;
"@
    Write-Host "      recorded $($env:BOOTSTRAP_PRINCIPAL_ID)"
}

Write-Host ""
Write-Host "control database ready: $database"
