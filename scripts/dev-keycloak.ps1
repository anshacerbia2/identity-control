# Registers identity-control's two clients in a local Keycloak whose realm identity-kernel has applied.
#
# The realm is not built here. Its scopes, attributes, and signing key are identity-kernel's
# realm definition, applied by its realm-apply, so a local realm and the development server's
# realm come from the same source:
#
#   cd ../identity-kernel
#   $env:KEYCLOAK_ADMIN_USER = 'admin'; $env:KEYCLOAK_ADMIN_PASSWORD = $env:KC_ADMIN_PASSWORD
#   go run ./cmd/realm-apply -environment local -url http://127.0.0.1:8081 -apply
#
# An earlier version of this script built the realm itself -- key, attributes, the provider scope
# and its mappers -- which put one realm under two repositories' configuration. It also granted the
# service account client management, which TDD-identity-control-001 and -002 exclude. Rerunning this
# version against a realm the old one configured removes those two roles.
#
# What remains is what this repository owns: its own clients, registered against that realm. It is
# the local counterpart of deploy/dev/create-kernel-clients.sh.
#
# Idempotent: every step checks before it writes.
#
# CREDENTIALS: the two clients hold no secret. Each authenticates with its own key by signed JWT
# (ADR-IAM-001 §5.12). The keys are made here, in deploy/dev/keys (git-ignored), by identity-kernel's
# client-key tool from the sibling checkout, and only their public halves are given to Keycloak. A
# key that already exists is kept, so a rerun does not cut off a running service.
#
#   $env:KC_ADMIN_PASSWORD            = '...'   # Keycloak bootstrap admin
#   $env:IDENTITY_KERNEL_DIR          = '...'   # optional; defaults to ../identity-kernel
#
# This script creates no user. The first Principal comes from the bootstrap ceremony
# (scripts/dev-bootstrap.ps1), because ADR-IAM-001 §5.11 gives that authority to the Identity
# Control Service and nothing else.
#
# Usage: pwsh ./scripts/dev-keycloak.ps1

$ErrorActionPreference = "Stop"

$kcBase   = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$realm    = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
$kcAdmin  = if ($env:KC_ADMIN_USER) { $env:KC_ADMIN_USER } else { "admin" }

function Require-Env($name) {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$name is required. This script defaults no credential."
    }
    return $value
}

$kcAdminPassword = Require-Env "KC_ADMIN_PASSWORD"
$kernelDir = if ($env:IDENTITY_KERNEL_DIR) { $env:IDENTITY_KERNEL_DIR } else { Join-Path $PSScriptRoot "..\..\identity-kernel" }
$keyDir = Join-Path $PSScriptRoot "..\deploy\dev\keys"
New-Item -ItemType Directory -Force $keyDir | Out-Null
$keyDir = (Resolve-Path $keyDir).Path

# Get-ClientJWKS makes the client's key pair if it has none, and returns the JWKS Keycloak is given:
# the public half only.
function Get-ClientJWKS($name) {
    $pem = Join-Path $keyDir "$name.pem"
    if (-not (Test-Path $pem)) {
        Push-Location $kernelDir
        try { go run ./cmd/client-key new -out $pem | Out-Host } finally { Pop-Location }
        if ($LASTEXITCODE -ne 0) { throw "client-key could not make the key for $name" }
    }
    $jwk = Get-Content -Raw (Join-Path $keyDir "$name.jwk.json") | ConvertFrom-Json
    return (@{ keys = @($jwk) } | ConvertTo-Json -Depth 5 -Compress)
}
$keyAttributes = @{
    "token.endpoint.auth.signing.alg" = "PS256"
    "use.jwks.url"                    = "false"
    "use.jwks.string"                 = "true"
}

$adminToken = (Invoke-RestMethod -Method Post -ContentType "application/x-www-form-urlencoded" `
    -Uri "$kcBase/realms/master/protocol/openid-connect/token" -Body @{
        grant_type = "password"
        client_id  = "admin-cli"
        username   = $kcAdmin
        password   = $kcAdminPassword
    }).access_token
$H = @{ Authorization = "Bearer $adminToken" }

# ---------------------------------------------------------------------------------------------
# 1. The realm identity-kernel applied
# ---------------------------------------------------------------------------------------------
Write-Host "[1/4] realm $realm, as identity-kernel applied it"
$realms = Invoke-RestMethod -Uri "$kcBase/admin/realms" -Headers $H
if (-not ($realms | Where-Object { $_.realm -eq $realm })) {
    throw "realm $realm does not exist. Apply identity-kernel's realm definition first (see the header of this script)."
}
$scopes = Invoke-RestMethod -Headers $H -Uri "$kcBase/admin/realms/$realm/client-scopes"
$providerScope = $scopes | Where-Object { $_.name -eq "scnehaux-provider" }
if (-not $providerScope) {
    throw "realm $realm has no scnehaux-provider scope, which STD-IAM-002 3.2.1 requires and identity-kernel declares. Apply its current realm definition."
}
Write-Host "      scnehaux-provider present"

# Messages go to the host, not the pipeline: a function's pipeline output is its return value, so a
# Write-Output here would be appended to the client id this function returns.
function Upsert-Client($payload) {
    $existing = Invoke-RestMethod -Headers $H `
        -Uri "$kcBase/admin/realms/$realm/clients?clientId=$($payload.clientId)"
    if ($existing.Count -gt 0) {
        # Update, not skip. A create-only helper means every configuration change after the first
        # run is silently not applied.
        $payload.id = $existing[0].id
        Invoke-RestMethod -Method Put -Uri "$kcBase/admin/realms/$realm/clients/$($existing[0].id)" `
            -Headers $H -Body ($payload | ConvertTo-Json -Depth 8) -ContentType "application/json" | Out-Null
        return $existing[0].id
    }
    Invoke-RestMethod -Method Post -Uri "$kcBase/admin/realms/$realm/clients" -Headers $H `
        -Body ($payload | ConvertTo-Json -Depth 8) -ContentType "application/json" | Out-Null
    return (Invoke-RestMethod -Headers $H `
        -Uri "$kcBase/admin/realms/$realm/clients?clientId=$($payload.clientId)")[0].id
}

# ---------------------------------------------------------------------------------------------
# 2. The service client
# ---------------------------------------------------------------------------------------------
Write-Host "[2/4] client identity-control"
$serviceClientId = Upsert-Client @{
    clientId                  = "identity-control"
    name                      = "Identity Control Service"
    enabled                   = $true
    protocol                  = "openid-connect"
    publicClient              = $false
    clientAuthenticatorType   = "client-jwt"
    serviceAccountsEnabled    = $true
    standardFlowEnabled       = $false
    directAccessGrantsEnabled = $false
    attributes                = $keyAttributes + @{ "jwks.string" = (Get-ClientJWKS "identity-control") }
}

# Exactly manage-users and view-users, which TDD-identity-control-001 gives this service for user
# creation, attribute write, user search, and user disable, and manage-organizations and
# view-organizations, which TDD-identity-control-002 2.0.0 gives it to project Tenants. It holds no
# client management, no realm administration, and no credential read. The set is converged, not appended to: a role
# granted by an earlier version of this script is removed.
$realmManagement = (Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients?clientId=realm-management")[0]
$serviceAccount = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$serviceClientId/service-account-user"
$mappingUri = "$kcBase/admin/realms/$realm/users/$($serviceAccount.id)/role-mappings/clients/$($realmManagement.id)"

$wanted = @("manage-users", "view-users", "manage-organizations", "view-organizations")
$held = @(Invoke-RestMethod -Headers $H -Uri $mappingUri)
$extra = @($held | Where-Object { $wanted -notcontains $_.name } | ForEach-Object { @{ id = $_.id; name = $_.name } })
if ($extra.Count -gt 0) {
    Invoke-RestMethod -Method Delete -Headers $H -ContentType "application/json" -Uri $mappingUri `
        -Body (ConvertTo-Json @($extra) -Depth 5) | Out-Null
    Write-Host "      removed: $(($extra | ForEach-Object { $_.name }) -join ', ')"
}
$available = Invoke-RestMethod -Headers $H -Uri "$kcBase/admin/realms/$realm/clients/$($realmManagement.id)/roles"
$grant = @($available | Where-Object { $wanted -contains $_.name } | ForEach-Object { @{ id = $_.id; name = $_.name } })
Invoke-RestMethod -Method Post -Headers $H -ContentType "application/json" -Uri $mappingUri `
    -Body (ConvertTo-Json @($grant) -Depth 5) | Out-Null
Write-Host "      roles: $($wanted -join ', ')"

# ---------------------------------------------------------------------------------------------
# 3. The registration path's client
# ---------------------------------------------------------------------------------------------
# Its own credential, clients and admin events and no users (TDD-identity-control-003 §Security
# Notes), so one leaked key cannot both mint a Principal and register a client that redirects its
# tokens. The local counterpart of deploy/dev/create-registration-client.sh.
Write-Host "[3/4] client identity-control-registration"
$registrationClientId = Upsert-Client @{
    clientId                  = "identity-control-registration"
    name                      = "Identity Control registration path"
    enabled                   = $true
    protocol                  = "openid-connect"
    publicClient              = $false
    clientAuthenticatorType   = "client-jwt"
    serviceAccountsEnabled    = $true
    standardFlowEnabled       = $false
    directAccessGrantsEnabled = $false
    attributes                = $keyAttributes + @{ "jwks.string" = (Get-ClientJWKS "identity-control-registration") }
}
$registrationAccount = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$registrationClientId/service-account-user"
$registrationRoles = @($available | Where-Object { @("manage-clients", "view-clients", "view-events") -contains $_.name } |
    ForEach-Object { @{ id = $_.id; name = $_.name } })
Invoke-RestMethod -Method Post -Headers $H -ContentType "application/json" `
    -Uri "$kcBase/admin/realms/$realm/users/$($registrationAccount.id)/role-mappings/clients/$($realmManagement.id)" `
    -Body (ConvertTo-Json @($registrationRoles) -Depth 5) | Out-Null
Write-Host "      roles: manage-clients, view-clients, view-events"

# ---------------------------------------------------------------------------------------------
# 4. The harness caller client
# ---------------------------------------------------------------------------------------------
Write-Host "[4/4] client identity-control-caller"
# Authorization Code with PKCE S256 and no password grant: STD-IAM-001 3.2 prohibits that grant, and
# a direct grant carries no auth_time, which a provider-scope token must (STD-IAM-002 3.2).
# scripts/dev-token.ps1 drives the real flow without a browser. The access token lifetime is 240
# seconds because provider-scope is lifetime class L0 (3.3), and it is set on the client because
# the lifetime is part of the registration, not of the realm.
$callerClientId = Upsert-Client @{
    clientId                  = "identity-control-caller"
    name                      = "Identity Control Caller (local harness only)"
    enabled                   = $true
    protocol                  = "openid-connect"
    publicClient              = $false
    serviceAccountsEnabled    = $false
    standardFlowEnabled       = $true
    directAccessGrantsEnabled = $false
    redirectUris              = @("http://127.0.0.1:8099/callback")
    clientAuthenticatorType   = "client-jwt"
    attributes                = $keyAttributes + @{
        "access.token.signed.response.alg" = "PS256"
        "pkce.code.challenge.method"       = "S256"
        "access.token.lifespan"            = "240"
        "jwks.string"                      = (Get-ClientJWKS "identity-control-caller")
    }
}

# Which API a token is for belongs to the client relationship, not to the claim profile, so the
# audience sits on this client rather than in scnehaux-provider -- otherwise every provider token
# would be valid at every API. It names identity-control-api, the keyless resource the bootstrap
# ceremony registers, never the Admin API client (STD-IAM-002 3.1), written exactly as
# identity-control writes an audience mapper.
$mappers = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId/protocol-mappers/models"
if (-not ($mappers | Where-Object { $_.name -eq "audience-identity-control-api" })) {
    Invoke-RestMethod -Method Post -Headers $H -ContentType "application/json" `
        -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId/protocol-mappers/models" -Body (@{
            name           = "audience-identity-control-api"
            protocol       = "openid-connect"
            protocolMapper = "oidc-audience-mapper"
            config         = @{
                "included.client.audience"  = "identity-control-api"
                "access.token.claim"        = "true"
                "id.token.claim"            = "false"
                "introspection.token.claim" = "true"
            }
        } | ConvertTo-Json -Depth 6) | Out-Null
    Write-Host "      audience mapper created"
}

# The claim profile: the kernel's scope, attached to this client and never a realm default.
Invoke-RestMethod -Method Put -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId/default-client-scopes/$($providerScope.id)" | Out-Null
Write-Host "      scnehaux-provider attached"

Write-Host ""
Write-Host "keycloak ready."
Write-Host "  service client   identity-control (manage-users, view-users, manage-organizations, view-organizations), key $keyDir\identity-control.pem"
Write-Host "  registration     identity-control-registration (manage-clients, view-clients, view-events), key $keyDir\identity-control-registration.pem"
Write-Host "  caller client    identity-control-caller (Authorization Code + PKCE S256, scnehaux-provider, L0), key $keyDir\identity-control-caller.pem"
Write-Host ""
Write-Host "No user exists yet. Next: ./scripts/dev-database.ps1 then ./scripts/dev-bootstrap.ps1"
