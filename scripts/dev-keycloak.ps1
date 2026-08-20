# Prepares a local Keycloak so identity-control can be run against it.
#
# Idempotent: every step checks before it writes, so re-running after a partial failure is
# safe. Nothing here is a deployment mechanism — the production kernel is configured by the
# platform team under ADR-IAM-001, and this script exists so a developer can reproduce the
# realm shape that ADR and STD-IAM-002 require without clicking through the admin console.
#
# SECRETS: every credential is read from the environment. Nothing is defaulted and nothing is
# written to a file, so this script can live in the repository.
#
#   $env:KC_ADMIN_PASSWORD            = '...'   # Keycloak bootstrap admin
#   $env:IDENTITY_CONTROL_SECRET      = '...'   # the service's Admin API client secret
#   $env:IDENTITY_CALLER_SECRET       = '...'   # harness caller client secret
#
# This script creates no user. The first Principal is created by the bootstrap ceremony
# (`scripts/dev-bootstrap.ps1`), because ADR-IAM-001 §5.8 gives that authority to the Identity
# Control Service and nothing else. An earlier version of this script minted one out-of-band and
# said so in a comment; the ceremony exists so that comment is no longer needed.
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
$serviceSecret   = Require-Env "IDENTITY_CONTROL_SECRET"
$callerSecret    = Require-Env "IDENTITY_CALLER_SECRET"

$tokenBody = @{
    grant_type = "password"
    client_id  = "admin-cli"
    username   = $kcAdmin
    password   = $kcAdminPassword
}
$adminToken = (Invoke-RestMethod -Method Post -ContentType "application/x-www-form-urlencoded" `
    -Uri "$kcBase/realms/master/protocol/openid-connect/token" -Body $tokenBody).access_token
$H = @{ Authorization = "Bearer $adminToken" }

# ---------------------------------------------------------------------------------------------
# 1. Realm
# ---------------------------------------------------------------------------------------------
Write-Host "[1/5] realm $realm"
$realms = Invoke-RestMethod -Uri "$kcBase/admin/realms" -Headers $H
if ($realms | Where-Object { $_.realm -eq $realm }) {
    Write-Host "      exists"
} else {
    # Token lifetimes come from STD-IAM-002 3.3. 900s is lifetime class L2, which is what an
    # interactive control-plane operator session is assigned.
    $payload = @{
        realm                 = $realm
        enabled               = $true
        accessTokenLifespan   = 900
        ssoSessionIdleTimeout = 1800
        registrationAllowed   = $false
        resetPasswordAllowed  = $false
    }
    Invoke-RestMethod -Method Post -Uri "$kcBase/admin/realms" -Headers $H `
        -Body ($payload | ConvertTo-Json -Depth 6) -ContentType "application/json" | Out-Null
    Write-Host "      created"
}

# ---------------------------------------------------------------------------------------------
# 2. Signing key
# ---------------------------------------------------------------------------------------------
Write-Host "[2/5] PS256 / 3072-bit signing key"
# A fresh realm is provisioned with a 2048-bit RS256 key. STD-IAM-002 3.2.2 requires PS256 at
# 3072 bits, and ADR-IAM-002 records why: FAPI 2.0 prohibits RS256, and the verifier in
# foundation-platform permits exactly one algorithm so an attacker cannot negotiate a weaker
# one. The default key is therefore not merely suboptimal — the verifier rejects every token
# signed with it. Found by pointing the running service at a default realm.
$components = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/components?parent=$realm&type=org.keycloak.keys.KeyProvider"
if ($components | Where-Object { $_.name -eq "scnehaux-ps256" }) {
    Write-Host "      exists"
} else {
    $key = @{
        name         = "scnehaux-ps256"
        providerId   = "rsa-generated"
        providerType = "org.keycloak.keys.KeyProvider"
        parentId     = $realm
        config       = @{
            priority  = @("200")
            enabled   = @("true")
            active    = @("true")
            algorithm = @("PS256")
            keySize   = @("3072")
        }
    }
    Invoke-RestMethod -Method Post -Uri "$kcBase/admin/realms/$realm/components" -Headers $H `
        -Body ($key | ConvertTo-Json -Depth 6) -ContentType "application/json" | Out-Null
    Write-Host "      created"
}

# ---------------------------------------------------------------------------------------------
# 3. User profile attributes
# ---------------------------------------------------------------------------------------------
Write-Host "[3/5] Scnehaux user attributes"
# Keycloak 24+ silently discards attributes the user profile does not declare. Without this,
# identity-control's create call succeeds, the attribute never lands, and the token carries no
# principal_id — a failure with no error anywhere in the chain.
#
# Declared rather than solved by enabling unmanaged attributes: `edit` is restricted to admin,
# so a user cannot set their own principal_id through the account console.
$profile = Invoke-RestMethod -Uri "$kcBase/admin/realms/$realm/users/profile" -Headers $H
$attributes = [System.Collections.ArrayList]::new()
foreach ($existing in $profile.attributes) { [void]$attributes.Add($existing) }

$changed = $false
foreach ($name in @("scnehaux_principal_id", "scnehaux_subject_type", "scnehaux_workload_owner")) {
    if ($attributes | Where-Object { $_.name -eq $name }) { continue }
    [void]$attributes.Add([pscustomobject]@{
        name        = $name
        displayName = $name
        multivalued = $false
        permissions = [pscustomobject]@{ view = @("admin"); edit = @("admin") }
        validations = [pscustomobject]@{}
        annotations = [pscustomobject]@{}
    })
    $changed = $true
}
if ($changed) {
    $profile.attributes = $attributes.ToArray()
    Invoke-RestMethod -Method Put -Uri "$kcBase/admin/realms/$realm/users/profile" -Headers $H `
        -Body ($profile | ConvertTo-Json -Depth 12) -ContentType "application/json" | Out-Null
    Write-Host "      declared"
} else {
    Write-Host "      already declared"
}

# Messages go to the host, not the pipeline: a function's pipeline output is its return value,
# so a Write-Output here would be appended to the client id this function returns.
function Upsert-Client($payload) {
    $existing = Invoke-RestMethod -Headers $H `
        -Uri "$kcBase/admin/realms/$realm/clients?clientId=$($payload.clientId)"
    if ($existing.Count -gt 0) { return $existing[0].id }
    Invoke-RestMethod -Method Post -Uri "$kcBase/admin/realms/$realm/clients" -Headers $H `
        -Body ($payload | ConvertTo-Json -Depth 8) -ContentType "application/json" | Out-Null
    return (Invoke-RestMethod -Headers $H `
        -Uri "$kcBase/admin/realms/$realm/clients?clientId=$($payload.clientId)")[0].id
}

# ---------------------------------------------------------------------------------------------
# 4. The service client
# ---------------------------------------------------------------------------------------------
Write-Host "[4/5] client identity-control"
$serviceClientId = Upsert-Client @{
    clientId                  = "identity-control"
    name                      = "Identity Control Service"
    enabled                   = $true
    protocol                  = "openid-connect"
    publicClient              = $false
    serviceAccountsEnabled    = $true
    standardFlowEnabled       = $false
    directAccessGrantsEnabled = $false
    secret                    = $serviceSecret
}

# Narrow roles, not realm-admin. TDD-identity-control-001 gives this service authority to create
# and read users and to manage clients; it is given no authority to read credentials, and
# realm-admin would hand it every authority the realm has.
$realmManagement = (Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients?clientId=realm-management")[0]
$available = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$($realmManagement.id)/roles"
$wanted = @("manage-users", "view-users", "manage-clients", "view-clients")
$grant = @($available | Where-Object { $wanted -contains $_.name } |
    ForEach-Object { @{ id = $_.id; name = $_.name } })

$serviceAccount = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$serviceClientId/service-account-user"
Invoke-RestMethod -Method Post -Headers $H -ContentType "application/json" `
    -Uri "$kcBase/admin/realms/$realm/users/$($serviceAccount.id)/role-mappings/clients/$($realmManagement.id)" `
    -Body (ConvertTo-Json $grant -Depth 5) | Out-Null
Write-Host "      roles: $(($grant | ForEach-Object { $_.name }) -join ', ')"

# ---------------------------------------------------------------------------------------------
# 5. The harness caller client
# ---------------------------------------------------------------------------------------------
Write-Host "[5/5] client identity-control-caller"
# Direct access grant is enabled for this client and this client alone, so a developer can get a
# token without a browser. STD-IAM-001 3.2 forbids the flow outside development; the client name
# says so, and it exists in no environment this script is not run against.
$callerClientId = Upsert-Client @{
    clientId                  = "identity-control-caller"
    name                      = "Identity Control Caller (local harness only)"
    enabled                   = $true
    protocol                  = "openid-connect"
    publicClient              = $false
    serviceAccountsEnabled    = $false
    standardFlowEnabled       = $true
    directAccessGrantsEnabled = $true
    secret                    = $callerSecret
    attributes                = @{ "access.token.signed.response.alg" = "PS256" }
}

$mappers = @(
    # The verifier requires `aud` to contain this service. Keycloak does not add it on its own
    # for a token minted for a different client.
    @{
        name           = "identity-control-audience"
        protocol       = "openid-connect"
        protocolMapper = "oidc-audience-mapper"
        config         = @{
            "included.custom.audience" = "identity-control"
            "access.token.claim"       = "true"
            "id.token.claim"           = "false"
        }
    },
    # STD-IAM-002 3.2.1 requires principal_id on an internal-audience token. Its source is a user
    # attribute only an admin can write, so it is not something a caller can assert.
    @{
        name           = "principal-id"
        protocol       = "openid-connect"
        protocolMapper = "oidc-usermodel-attribute-mapper"
        config         = @{
            "user.attribute"       = "scnehaux_principal_id"
            "claim.name"           = "principal_id"
            "jsonType.label"       = "String"
            "access.token.claim"   = "true"
            "id.token.claim"       = "true"
            "userinfo.token.claim" = "true"
            "multivalued"          = "false"
        }
    },
    @{
        name           = "subject-type"
        protocol       = "openid-connect"
        protocolMapper = "oidc-usermodel-attribute-mapper"
        config         = @{
            "user.attribute"       = "scnehaux_subject_type"
            "claim.name"           = "subject_type"
            "jsonType.label"       = "String"
            "access.token.claim"   = "true"
            "id.token.claim"       = "true"
            "userinfo.token.claim" = "true"
            "multivalued"          = "false"
        }
    }
)

$installed = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId/protocol-mappers/models"
foreach ($mapper in $mappers) {
    if ($installed | Where-Object { $_.name -eq $mapper.name }) { continue }
    Invoke-RestMethod -Method Post -Headers $H -ContentType "application/json" `
        -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId/protocol-mappers/models" `
        -Body ($mapper | ConvertTo-Json -Depth 6) | Out-Null
    Write-Host "      mapper $($mapper.name) created"
}

# ---------------------------------------------------------------------------------------------
# The first Principal is deliberately NOT created here.
# ---------------------------------------------------------------------------------------------
# ADR-IAM-001 5.8 gives the authority to issue a principal_id to the Identity Control Service
# and to nothing else. A script that wrote the attribute directly would be the out-of-band
# creation TDD-identity-control-001 prohibits, and an earlier version of this file did exactly
# that with a comment admitting it. Run the ceremony instead:
#
#   ./scripts/dev-bootstrap.ps1

Write-Host ""
Write-Host "keycloak ready."
Write-Host "  realm                 $realm"
Write-Host "  service client        identity-control (service account, narrow realm-management roles)"
Write-Host "  caller client         identity-control-caller (direct access grant, local harness only)"
Write-Host "  signing key           PS256 / 3072-bit"
Write-Host ""
Write-Host "No user exists yet. Next: ./scripts/dev-database.ps1 then ./scripts/dev-bootstrap.ps1"
