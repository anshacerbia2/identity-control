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
# (`scripts/dev-bootstrap.ps1`), because ADR-IAM-001 §5.11 gives that authority to the Identity
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
    # Token lifetime comes from STD-IAM-002 3.3, and the class follows from the audience rather
    # than from taste. identity-control mints enterprise Principals: irreversible, and belonging
    # to no Tenant. That is the `privileged` class in its `provider-scope` form per 3.1.1, which
    # is lifetime class L0 -- 240 seconds.
    #
    # An earlier revision set 900s and called it L2. L2 is the external and partner class; using
    # it here put a fifteen-minute lifetime on the one surface in the estate that can create
    # identities, and STD-IAM-001 3.4 makes lifetime the second term of every revocation
    # enforcement delay.
    $payload = @{
        realm                 = $realm
        enabled               = $true
        accessTokenLifespan   = 240
        ssoSessionIdleTimeout = 1800
        registrationAllowed   = $false
        resetPasswordAllowed  = $false
    }
    Invoke-RestMethod -Method Post -Uri "$kcBase/admin/realms" -Headers $H `
        -Body ($payload | ConvertTo-Json -Depth 6) -ContentType "application/json" | Out-Null
    Write-Host "      created"
}


# The realm's internal id, not its name.
#
# A key provider is a component whose parentId must be the realm id, and Keycloak 26 generates
# that as a UUID. Passing the realm name instead stores the component and attaches it to
# nothing: the create returns 201, the component is readable at ?parent=<name>, and the realm
# keeps signing with its default 2048-bit PS256 key. The failure then surfaces three steps
# later as the verifier rejecting every token with "signing material is unavailable", because
# STD-IAM-002 3.2.2 requires 3072 bits. Nothing in between reports an error, which is why the
# outcome is asserted at the end of this block rather than trusted.
$realmId = (Invoke-RestMethod -Uri "$kcBase/admin/realms/$realm" -Headers $H).id
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
    -Uri "$kcBase/admin/realms/$realm/components?parent=$realmId&type=org.keycloak.keys.KeyProvider"
if ($components | Where-Object { $_.name -eq "scnehaux-ps256" }) {
    Write-Host "      exists"
} else {
    $key = @{
        name         = "scnehaux-ps256"
        providerId   = "rsa-generated"
        providerType = "org.keycloak.keys.KeyProvider"
        parentId     = $realmId
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

# Assert the outcome, not the call.
#
# The published JWKS is what the verifier reads, so that is what gets checked. A component created
# under the wrong parent, a keySize Keycloak silently declined, or a default provider outranking
# this one all produce the same symptom -- tokens signed with a key the verifier refuses -- and
# none of them makes the create call fail.
$jwks = Invoke-RestMethod -Uri "$kcBase/realms/$realm/protocol/openid-connect/certs"
$signing = $jwks.keys | Where-Object { $_.alg -eq "PS256" -and $_.use -eq "sig" }
if (-not $signing) {
    throw "the realm publishes no PS256 signing key; the verifier permits no other algorithm"
}
$widest = 0
foreach ($k in $signing) {
    $padded = $k.n.Replace("-", "+").Replace("_", "/")
    $padded += ("=" * ((4 - $padded.Length % 4) % 4))
    $bits = [Convert]::FromBase64String($padded).Length * 8
    if ($bits -gt $widest) { $widest = $bits }
}
if ($widest -lt 3072) {
    throw "the widest published PS256 key is $widest bits; STD-IAM-002 3.2.2 requires at least 3072"
}
Write-Host "      published PS256 key is $widest bits"

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
foreach ($name in @("scnehaux_principal_id", "scnehaux_subject_type", "scnehaux_workload_owner",
                    "scnehaux_provider_scope")) {
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
    if ($existing.Count -gt 0) {
        # Update, not skip. A create-only helper means every configuration change after the
        # first run is silently not applied, and a setup script that reports success while
        # applying nothing is worse than one that fails.
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
# Authorization Code with PKCE, and no direct access grant.
#
# STD-IAM-001 3.2 prohibits the Resource Owner Password Credentials grant for every client,
# and it could not have satisfied this profile anyway: STD-IAM-002 3.2 makes auth_time
# mandatory for a privileged token, and the kernel records an authentication instant only for
# an authentication ceremony. A direct grant has none, so the claim was structurally absent
# rather than misconfigured. scripts/dev-token.ps1 drives the real flow without a browser.
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
    secret                    = $callerSecret
    attributes                = @{
        "access.token.signed.response.alg" = "PS256"
        # S256 rather than plain. Plain offers no protection against an intercepted code,
        # which is the reason 3.2 names the method rather than only the extension.
        "pkce.code.challenge.method"       = "S256"
    }
}

# STD-IAM-002 3.2.1 requires the claim set to be projected through an audience-specific client
# scope, not through client-level mappers and never through a realm default. The reason is in the
# standard: a mapper carrying principal_id as a realm default would disclose an enterprise
# correlation identifier to every client including external ones.
#
# The scope here is `scnehaux-provider`, the provider-scope form of the `privileged` profile:
# principal_id, subject_type, provider_scope, acr, auth_time -- and no tenant_id or version claim,
# because a provider operation belongs to no Tenant.
$scopeName = "scnehaux-provider"
Write-Host "      client scope $scopeName"

$existingScopes = Invoke-RestMethod -Headers $H -Uri "$kcBase/admin/realms/$realm/client-scopes"
$scope = $existingScopes | Where-Object { $_.name -eq $scopeName }
if (-not $scope) {
    Invoke-RestMethod -Method Post -Headers $H -ContentType "application/json" `
        -Uri "$kcBase/admin/realms/$realm/client-scopes" -Body (@{
            name        = $scopeName
            description = "Privileged provider-scope claim profile. STD-IAM-002 3.2.1."
            protocol    = "openid-connect"
            attributes  = @{
                # NOT a default scope. `include.in.token.scope` keeps the scope name out of the
                # `scope` claim; the mappers still run because the scope is attached to the client.
                "include.in.token.scope" = "false"
                "display.on.consent.screen" = "false"
            }
        } | ConvertTo-Json -Depth 6) | Out-Null
    $existingScopes = Invoke-RestMethod -Headers $H -Uri "$kcBase/admin/realms/$realm/client-scopes"
    $scope = $existingScopes | Where-Object { $_.name -eq $scopeName }
    Write-Host "        created"
}

function Attr-Mapper($name, $attribute, $claim, $type) {
    @{
        name           = $name
        protocol       = "openid-connect"
        protocolMapper = "oidc-usermodel-attribute-mapper"
        config         = @{
            "user.attribute"       = $attribute
            "claim.name"           = $claim
            "jsonType.label"       = $type
            "access.token.claim"   = "true"
            "id.token.claim"       = "true"
            "userinfo.token.claim" = "false"
            "multivalued"          = "false"
        }
    }
}

$scopeMappers = @(
    # The verifier requires `aud` to name this service. Keycloak does not add it on its own for a
    # token minted for a different client.
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
    # Sourced from user attributes only an admin can write, so a caller cannot assert its own
    # principal_id or widen its own provider scope.
    (Attr-Mapper "principal-id"   "scnehaux_principal_id"   "principal_id"   "String"),
    (Attr-Mapper "subject-type"   "scnehaux_subject_type"   "subject_type"   "String"),
    (Attr-Mapper "provider-scope" "scnehaux_provider_scope" "provider_scope" "String"),
    # acr and auth_time are mandatory for every privileged token per 3.2. auth_time comes from the
    # kernel's own session state rather than an attribute, because an attribute could not tell a
    # step-up requirement when the Principal actually authenticated.
    @{
        name           = "acr"
        protocol       = "openid-connect"
        protocolMapper = "oidc-acr-mapper"
        config         = @{ "access.token.claim" = "true"; "id.token.claim" = "true" }
    },
    # auth_time is not an attribute and not derivable from one. Keycloak records the
    # authentication instant as the AUTH_TIME session note, so the claim is projected from
    # there. An attribute could not carry it: 3.2 makes auth_time mandatory for privileged
    # precisely so a step-up requirement can be evaluated against when the Principal actually
    # authenticated, and an admin-written attribute would be a value the kernel never observed.
    @{
        name           = "auth-time"
        protocol       = "openid-connect"
        protocolMapper = "oidc-usersessionmodel-note-mapper"
        config         = @{
            "user.session.note"  = "AUTH_TIME"
            "claim.name"         = "auth_time"
            "jsonType.label"     = "long"
            "access.token.claim" = "true"
            "id.token.claim"     = "true"
        }
    }
)

$installedScopeMappers = Invoke-RestMethod -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/client-scopes/$($scope.id)/protocol-mappers/models"
foreach ($mapper in $scopeMappers) {
    if ($installedScopeMappers | Where-Object { $_.name -eq $mapper.name }) { continue }
    Invoke-RestMethod -Method Post -Headers $H -ContentType "application/json" `
        -Uri "$kcBase/admin/realms/$realm/client-scopes/$($scope.id)/protocol-mappers/models" `
        -Body ($mapper | ConvertTo-Json -Depth 6) | Out-Null
    Write-Host "        mapper $($mapper.name) created"
}

# Attached as an optional-by-name but always-requested scope: `default` here means the client
# always gets it, which is what "the registration attaches exactly one profile scope" requires.
# It is attached to this client and is NOT a realm default scope.
Invoke-RestMethod -Method Put -Headers $H `
    -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId/default-client-scopes/$($scope.id)" | Out-Null
Write-Host "        attached to identity-control-caller"

# The client's own lifetime, not just the realm ceiling. STD-IAM-002 3.3 forbids a lifetime longer
# than the class per client, and a realm default is a value a client can be configured past.
$callerClient = Invoke-RestMethod -Headers $H -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId"
$callerAttrs = @{}
if ($callerClient.attributes) { $callerClient.attributes.PSObject.Properties | ForEach-Object { $callerAttrs[$_.Name] = $_.Value } }
$callerAttrs["access.token.signed.response.alg"] = "PS256"
$callerAttrs["access.token.lifespan"] = "240"
$callerClient | Add-Member -NotePropertyName attributes -NotePropertyValue $callerAttrs -Force
Invoke-RestMethod -Method Put -Headers $H -ContentType "application/json" `
    -Uri "$kcBase/admin/realms/$realm/clients/$callerClientId" `
    -Body ($callerClient | ConvertTo-Json -Depth 10) | Out-Null
Write-Host "        access token lifetime pinned to 240s (class L0)"

# ---------------------------------------------------------------------------------------------
# The first Principal is deliberately NOT created here.
# ---------------------------------------------------------------------------------------------
# ADR-IAM-001 5.11 gives the authority to issue a principal_id to the Identity Control Service
# and to nothing else. A script that wrote the attribute directly would be the out-of-band
# creation TDD-identity-control-001 prohibits, and an earlier version of this file did exactly
# that with a comment admitting it. Run the ceremony instead:
#
#   ./scripts/dev-bootstrap.ps1

Write-Host ""
Write-Host "keycloak ready."
Write-Host "  realm                 $realm"
Write-Host "  service client        identity-control (service account, narrow realm-management roles)"
Write-Host "  caller client         identity-control-caller (Authorization Code + PKCE S256)"
Write-Host "  signing key           PS256 / 3072-bit"
Write-Host ""
Write-Host "No user exists yet. Next: ./scripts/dev-database.ps1 then ./scripts/dev-bootstrap.ps1"
