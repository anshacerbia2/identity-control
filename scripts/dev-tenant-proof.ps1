# The Tenant context, end to end against the live kernel (TDD-identity-control-002 2.3.0, ADR-IAM-006).
#
# It stands in for Organization Control: it registers a delivering workload, and posts Membership and
# Tenant events to POST /v1/deliveries as that workload, the way Organization Control's dispatcher
# does. The converger then makes the kernel's Organizations match, and a sign-in through an internal
# client that holds the organization scope shows the result:
#
#   1. a Tenant activated and a Membership granted: a token asked for organization:<tenant> carries
#      that tenant_id, flat;
#   2. the Membership revoked: a new token for the Tenant carries no tenant_id, and the refresh token
#      issued for it is refused.
#
# Two phases, because the service reads its delivering workload at start:
#
#   pwsh ./scripts/dev-tenant-proof.ps1 -Phase setup -State <file>   # prints DELIVERY_PRINCIPAL_ID=<id>
#   (set IDENTITY_DELIVERY_PRINCIPAL_ID to it and restart identity-control)
#   pwsh ./scripts/dev-tenant-proof.ps1 -Phase prove -State <file>
#
# Environment: as scripts/dev-smoke.ps1 (IDENTITY_API_URL, KC_BASE_URL, IDENTITY_CALLER_KEY_FILE,
# IDENTITY_CALLER_PASSWORD, IDENTITY_OPERATOR_TOTP_FILE). Keys are made for each run in the state
# file's directory, because a registered key is never registered again. None is printed.

param(
    [Parameter(Mandatory = $true)] [ValidateSet("setup", "prove")] [string] $Phase,
    [Parameter(Mandatory = $true)] [string] $State
)

$ErrorActionPreference = "Stop"

$api    = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8090" }
$kcBase = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$realm  = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }

Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"

$client = New-Object System.Net.Http.HttpClient

function Send-Json($method, $path, $body, $bearer, $idempotencyKey) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$api$path")
    if ($bearer) {
        $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $bearer)
    }
    if ($idempotencyKey) { $request.Headers.Add("Idempotency-Key", $idempotencyKey) }
    if ($body) {
        $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    }
    $response = $client.SendAsync($request).Result
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result }
}

function Decode-Claims([string] $jwt) {
    $s = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json
}

# New-UuidV7 is an RFC 9562 version 7 identifier, as the envelope's id is.
function New-UuidV7 {
    $bytes = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    for ($i = 5; $i -ge 0; $i--) { $bytes[$i] = [byte]($ms -band 0xff); $ms = $ms -shr 8 }
    $bytes[6] = ($bytes[6] -band 0x0f) -bor 0x70
    $bytes[8] = ($bytes[8] -band 0x3f) -bor 0x80
    $hex = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    return "$($hex.Substring(0,8))-$($hex.Substring(8,4))-$($hex.Substring(12,4))-$($hex.Substring(16,4))-$($hex.Substring(20,12))"
}

# New-RunKey writes a fresh RSA key's PKCS#8 PEM beside the state file and returns its public JWK.
function New-RunKey([string] $path) {
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    try {
        $pem = "-----BEGIN PRIVATE KEY-----`n" +
            [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), [Base64FormattingOptions]::InsertLineBreaks) +
            "`n-----END PRIVATE KEY-----`n"
        [System.IO.File]::WriteAllText($path, $pem)
        if ($IsLinux -or $IsMacOS) { chmod 600 $path }
        $public = $rsa.ExportParameters($false)
        return @{ kty = "RSA"; n = (ConvertTo-Base64Url $public.Modulus); e = (ConvertTo-Base64Url $public.Exponent) }
    } finally { $rsa.Dispose() }
}

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" }
    else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$keyDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($State))

if ($Phase -eq "setup") {
    $provider = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
        -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
    $operator = (Decode-Claims $provider).principal_id
    $run = [Guid]::NewGuid().ToString("N").Substring(0, 10)

    Write-Host "1. register a resource, a delivering workload, and an internal client"
    $resource = "tenant-proof-api-$run"
    $r = Send-Json "POST" "/v1/registrations" (@{ client_key = $resource; profile = "resource"; audience_class = "internal"
            application_ref = "tenant-proof"; lifetime_class = "L1" } | ConvertTo-Json -Compress) $provider "tp-resource-$run"
    Expect "resource registered" $r.code 201

    $deliveryClient = "tenant-proof-delivery-$run"
    $deliveryKey = Join-Path $keyDir "$deliveryClient.pem"
    $jwk = New-RunKey $deliveryKey
    $r = Send-Json "POST" "/v1/workloads" (@{ display_name = "Tenant proof delivery"
            purpose = "Stands in for Organization Control's dispatcher in the Tenant context proof"
            workload_type = "service"; owner_principal_id = $operator; client_key = $deliveryClient
            application_ref = "tenant-proof"; audience = @("identity-control-api"); public_key = $jwk
        } | ConvertTo-Json -Compress -Depth 4) $provider "tp-delivery-$run"
    Expect "delivering workload created" $r.code 201
    $deliveryPrincipal = if ($r.code -eq 201) { ($r.body | ConvertFrom-Json).principal_id } else { "" }
    if ($r.code -ne 201) { Write-Host "        $($r.body)" }

    $appClient = "tenant-proof-app-$run"
    $appKey = Join-Path $keyDir "$appClient.pem"
    $jwk = New-RunKey $appKey
    $r = Send-Json "POST" "/v1/registrations" (@{ client_key = $appClient; profile = "confidential"
            audience_class = "internal"; application_ref = "tenant-proof"; audience = @($resource)
            redirect_uris = @("http://127.0.0.1:8099/callback"); public_key = $jwk
        } | ConvertTo-Json -Compress -Depth 4) $provider "tp-app-$run"
    Expect "internal client registered" $r.code 201
    if ($r.code -ne 201) { Write-Host "        $($r.body)" }

    @{ run = $run; operator = $operator; delivery_client = $deliveryClient; delivery_key = $deliveryKey
        delivery_principal = $deliveryPrincipal; app_client = $appClient; app_key = $appKey } |
        ConvertTo-Json -Compress | Set-Content -NoNewline $State
    if ($failures -gt 0) { exit 1 }
    Write-Output "DELIVERY_PRINCIPAL_ID=$deliveryPrincipal"
    exit 0
}

# --- prove ---
$s = Get-Content -Raw $State | ConvertFrom-Json
$issuer = Get-RealmIssuer $kcBase $realm
$tokenUrl = "$kcBase/realms/$realm/protocol/openid-connect/token"

function Get-DeliveryToken {
    $assertion = New-ClientAssertion -KeyFile $s.delivery_key -ClientId $s.delivery_client -Audience $issuer
    return (Invoke-RestMethod -Method Post -Uri $tokenUrl -Body @{
            grant_type = "client_credentials"; client_id = $s.delivery_client
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion = $assertion }).access_token
}

$position = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
function Deliver([string] $type, $data) {
    $script:position++
    $envelope = @{ specversion = "1.0"; id = (New-UuidV7); source = "/systems/organization-control"; type = $type
        time = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); datacontenttype = "application/json"
        streamposition = $script:position; data = $data } | ConvertTo-Json -Compress -Depth 6
    return Send-Json "POST" "/v1/deliveries" $envelope (Get-DeliveryToken) $null
}

# Sign-InFor signs the operator in through the internal client, asking for one Tenant. The kernel
# refuses organization:<alias> for an Organization it does not hold yet, by redirecting with an error,
# which the sign-in reports as an exception: that is a refusal, returned as $null, not a failure here.
function Sign-InFor([string] $tenant) {
    try {
        return Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
            -KeyFile $s.app_key -ClientId $s.app_client -Scope "openid organization:$tenant" -FullResponse @operatorTotp
    } catch {
        $script:lastRefusal = $_.Exception.Message
        return $null
    }
}

function Tenant-Of($response) {
    if ($null -eq $response) { return $null }
    return (Decode-Claims $response.access_token).tenant_id
}

$tenant = New-UuidV7
$membership = New-UuidV7

Write-Host "2. a Tenant activated and a Membership granted, delivered as Organization Control"
$r = Deliver "com.scnehaux.organization.tenant.lifecycle.activated" @{ tenant_id = $tenant; organization_id = (New-UuidV7)
    tenant_status = "active"; tenant_version = 1; tenant_security_version = 1 }
Expect "tenant activation accepted" $r.code 202
if ($r.code -ne 202) { Write-Host "        $($r.body)" }
$r = Deliver "com.scnehaux.organization.membership.lifecycle.granted" @{ membership_id = $membership
    principal_id = $s.operator; tenant_id = $tenant; workspace_id = $null; membership_status = "active"
    membership_version = 1; tenant_security_version = 1 }
Expect "membership grant accepted" $r.code 202
if ($r.code -ne 202) { Write-Host "        $($r.body)" }

Write-Host "3. a token for the Tenant carries it"
$granted = $null
for ($i = 0; $i -lt 30; $i++) {
    $granted = Sign-InFor $tenant
    if ((Tenant-Of $granted) -eq $tenant) { break }
    Start-Sleep -Seconds 1
}
if ($null -eq $granted) {
    Write-Host "  FAIL  no token for the Tenant within 30 s: $script:lastRefusal"
    exit 1
}
$claims = Decode-Claims $granted.access_token
Expect "tenant_id" $claims.tenant_id $tenant
Expect "no nested organization claim" ($claims.PSObject.Properties.Name -contains 'organization') $false
Expect "a refresh token was issued" ([bool]$granted.refresh_token) $true

Write-Host "4. the Membership revoked"
$r = Deliver "com.scnehaux.organization.membership.security.revoked" @{ membership_id = $membership
    principal_id = $s.operator; tenant_id = $tenant; workspace_id = $null; membership_status = "revoked"
    membership_version = 2; tenant_security_version = 1 }
Expect "membership revocation accepted" $r.code 202
$after = $null
for ($i = 0; $i -lt 30; $i++) {
    $after = Sign-InFor $tenant
    if ($null -eq (Tenant-Of $after)) { break }
    Start-Sleep -Seconds 1
}
# Either outcome withholds the Tenant: a sign-in refused, or a token without tenant_id.
$outcome = if ($null -eq $after) { "refused: $script:lastRefusal" } else { "a token without tenant_id" }
Write-Host "        a new sign-in for the Tenant: $outcome"
Expect "a new sign-in for the Tenant carries no tenant_id" ($null -eq (Tenant-Of $after)) $true

$assertion = New-ClientAssertion -KeyFile $s.app_key -ClientId $s.app_client -Audience $issuer
$form = "grant_type=refresh_token&client_id=$([uri]::EscapeDataString($s.app_client))" +
    "&client_assertion_type=$([uri]::EscapeDataString('urn:ietf:params:oauth:client-assertion-type:jwt-bearer'))" +
    "&client_assertion=$([uri]::EscapeDataString($assertion))&refresh_token=$([uri]::EscapeDataString($granted.refresh_token))"
$request = New-Object System.Net.Http.HttpRequestMessage("POST", $tokenUrl)
$request.Content = New-Object System.Net.Http.StringContent($form, [System.Text.Encoding]::UTF8, "application/x-www-form-urlencoded")
$refresh = $client.SendAsync($request).Result
$refreshBody = $refresh.Content.ReadAsStringAsync().Result
Expect "the refresh issued for the Tenant is refused" ([int]$refresh.StatusCode) 400
$refreshError = try { ($refreshBody | ConvertFrom-Json).error } catch { "" }
Expect "as invalid_grant" $refreshError "invalid_grant"

Write-Host ""
if ($failures -gt 0) { Write-Host "$failures case(s) failed."; exit 1 }
Write-Host "the Tenant context holds end to end."
