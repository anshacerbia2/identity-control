# Performs the bootstrap ceremony, then makes the resulting Principal usable locally.
#
# Two steps, and only the first is a production procedure:
#
#   1. `identity-bootstrap` — the ceremony. Creates the first Principal through the same path
#      POST /v1/principals uses, records who ran it and why, and can succeed at most once per
#      Control Database. ADR-IAM-001 §5.11.
#
#   2. Setting a password and clearing the required action. DEVELOPMENT ONLY. The ceremony
#      deliberately leaves the Principal owing a credential so that no process in the estate
#      holds one; a real operator completes that through the kernel's own credential flow. The
#      harness needs a password because direct access grant is the only way to get a token
#      without a browser, and Keycloak refuses one to an account with a pending required action.
#
# SECRETS: read from the environment, never defaulted.
#
#   $env:IDENTITY_APP_PASSWORD    = '...'   # the identity_app login role
#   $env:IDENTITY_CONTROL_SECRET  = '...'   # the service's Admin API client secret
#   $env:KC_ADMIN_PASSWORD        = '...'   # Keycloak bootstrap admin, for step 2 only
#   $env:IDENTITY_CALLER_PASSWORD = '...'   # the password step 2 sets
#
# Usage: pwsh ./scripts/dev-bootstrap.ps1 [-Operator you@example.com] [-Resume]

param(
    [string]$Operator = "",
    [string]$Reason   = "local development harness stand-up",
    [string]$Username = "bootstrap-operator",
    [switch]$Resume
)

$ErrorActionPreference = "Stop"

$kcBase   = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$realm    = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
$kcAdmin  = if ($env:KC_ADMIN_USER) { $env:KC_ADMIN_USER } else { "admin" }
$pgHost   = if ($env:PGHOST) { $env:PGHOST } else { "127.0.0.1" }
$pgPort   = if ($env:PGPORT) { $env:PGPORT } else { "5432" }
$database = if ($env:IDENTITY_DATABASE_NAME) { $env:IDENTITY_DATABASE_NAME } else { "identity_control_dev" }

function Require-Env($name) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$name is required. This script defaults no credential."
    }
    return $value
}

$appPassword    = Require-Env "IDENTITY_APP_PASSWORD"
$serviceSecret  = Require-Env "IDENTITY_CONTROL_SECRET"
$kcPassword     = Require-Env "KC_ADMIN_PASSWORD"
$callerPassword = Require-Env "IDENTITY_CALLER_PASSWORD"

# The operator is a person. Defaulting it to the OS user is a guess, but a wrong name on record is
# worse than a prompt, so the guess is stated rather than silent.
if ([string]::IsNullOrWhiteSpace($Operator)) {
    $Operator = "$env:USERNAME@$env:COMPUTERNAME"
    Write-Host "no -Operator given; recording '$Operator'"
}

# ---------------------------------------------------------------------------------------------
Write-Host ""
Write-Host "[1/2] bootstrap ceremony"
# The runtime credential, not the migration one. A ceremony that could alter the schema could
# remove the constraint that makes it single-use.
$env:IDENTITY_DATABASE_URL = "postgres://identity_app:$appPassword@${pgHost}:${pgPort}/${database}?sslmode=disable"
$env:IDENTITY_KEYCLOAK_REALM = $realm
$env:IDENTITY_KEYCLOAK_BASE_URL = $kcBase
$env:IDENTITY_KEYCLOAK_CLIENT_ID = "identity-control"
$env:IDENTITY_KEYCLOAK_CLIENT_SECRET = $serviceSecret

$arguments = @(
    "run", "./cmd/identity-bootstrap",
    "-operator", $Operator,
    "-reason", $Reason,
    "-username", $Username,
    "-email", "$Username@scnehaux.local"
)
if ($Resume) { $arguments += @("-resume", $Operator) }

& go @arguments
if ($LASTEXITCODE -ne 0) {
    throw "the ceremony failed or was refused; nothing below has run"
}

# ---------------------------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/2] set a local credential  <-- DEVELOPMENT ONLY"
# Everything from here down exists because this is a loopback harness. STD-IAM-001 §3.2 forbids
# direct access grant outside development, and the ceremony's whole point is that it does not hand
# any process a credential. This step is the human at the keyboard, standing in for the kernel's
# credential-setting flow.
$adminToken = (Invoke-RestMethod -Method Post -ContentType "application/x-www-form-urlencoded" `
    -Uri "$kcBase/realms/master/protocol/openid-connect/token" -Body @{
        grant_type = "password"
        client_id  = "admin-cli"
        username   = $kcAdmin
        password   = $kcPassword
    }).access_token
$H = @{ Authorization = "Bearer $adminToken" }

$found = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/users?username=$Username&exact=true"
if ($found.Count -eq 0) {
    throw "the ceremony reported success but $Username is not in the kernel"
}
$userId = $found[0].id

# Verify the ceremony actually landed the claim source. A discarded attribute is invisible at the
# write and surfaces three steps later as an unexplained 401.
$stored = Invoke-RestMethod -Uri "$kcBase/admin/realms/$realm/users/$userId" -Headers $H
if (-not $stored.attributes.scnehaux_principal_id) {
    throw "the kernel user carries no scnehaux_principal_id; the user profile declaration did not take effect"
}
Write-Host "      principal_id on the kernel user: $($stored.attributes.scnehaux_principal_id -join ',')"

# The ceremony left UPDATE_PASSWORD pending, which is why this is needed at all: Keycloak refuses
# a direct access grant to an account with an outstanding required action.
Write-Host "      required actions before: $(@($stored.requiredActions) -join ',')"

Invoke-RestMethod -Method Put -Headers $H -ContentType "application/json" `
    -Uri "$kcBase/admin/realms/$realm/users/$userId/reset-password" `
    -Body (@{ type = "password"; value = $callerPassword; temporary = $false } | ConvertTo-Json) | Out-Null

# firstName and lastName are required by the default user profile, and an account missing them is
# refused with "Account is not fully set up" rather than a validation error naming the field.
$stored | Add-Member -NotePropertyName firstName       -NotePropertyValue "Bootstrap" -Force
$stored | Add-Member -NotePropertyName lastName        -NotePropertyValue "Operator"  -Force
$stored | Add-Member -NotePropertyName requiredActions -NotePropertyValue @()         -Force

# The provider scope is NOT set here any more.
#
# ADR-IAM-001 5.6 places the authority for a provider grant in the Organization Platform,
# projected into the kernel through ADR-ORG-001 5.4, and makes the bootstrap ceremony the one
# exception. So the ceremony grants it, inside the same call that creates the Principal and
# under the same immutable record. An earlier version of this script wrote the attribute
# directly, which is indistinguishable from the prohibited path once it looks normal.
Invoke-RestMethod -Method Put -Headers $H -ContentType "application/json" `
    -Uri "$kcBase/admin/realms/$realm/users/$userId" `
    -Body ($stored | ConvertTo-Json -Depth 10) | Out-Null

Write-Host "      credential set and required action cleared (development only)"
Write-Host ""
Write-Host "ready. Start the service, then ./scripts/dev-smoke.ps1"
