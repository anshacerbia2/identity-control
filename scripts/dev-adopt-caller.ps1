# Brings identity-control-caller under registration on a development server
# (TDD-identity-control-003 §Adoption, deploy/dev/README.md §First start).
#
# deploy/dev/create-kernel-clients.sh makes the development caller in the kernel before this service
# can register a confidential client, so it is adopted: a plan first, then, with -Apply, the
# adoption, held to the key it already authenticates with. It is the declaration dev-smoke.ps1
# step 9b adopts in CI:
#   - confidential, privileged in the provider-scope form, so its tokens keep acr and auth_time,
#     which every provider route requires (STD-IAM-002 §3.1.1);
#   - identity-control-api in its audience, as the script's audience mapper names it;
#   - its callback, http://127.0.0.1:8099/callback, which dev-token.ps1 listens on.
# The script made it before the token profile, so token_format and audience_scope converge with the
# adoption.
#
# SECRETS: read from the environment, as dev-smoke.ps1 reads them.
#   $env:IDENTITY_CALLER_KEY_FILE      the caller's private key: the token is signed with it, and its
#                                      public half is the key the adoption is held to. Never printed.
#   $env:IDENTITY_CALLER_PASSWORD      the bootstrap operator's password
#   $env:IDENTITY_OPERATOR_TOTP_FILE   optional, the operator's TOTP file (dev-token.ps1)
#
# Usage, from the repository root after `set -a; . deploy/dev/.env; set +a`:
#   pwsh ./scripts/dev-adopt-caller.ps1            # plan
#   pwsh ./scripts/dev-adopt-caller.ps1 -Apply     # adopt

param(
    [string] $RedirectUri = "http://127.0.0.1:8099/callback",
    [switch] $Apply
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$api = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8082" }
foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "$name is required."
    }
}

Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"

$rsa = Read-ClientKey $env:IDENTITY_CALLER_KEY_FILE
try {
    $parameters = $rsa.ExportParameters($false)
    $public = @{ kty = "RSA"; n = (ConvertTo-Base64Url $parameters.Modulus); e = (ConvertTo-Base64Url $parameters.Exponent) }
} finally { $rsa.Dispose() }

$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp

$declaration = @{
    client_key      = "identity-control-caller"
    profile         = "confidential"
    audience_class  = "privileged"
    privileged_form = "provider-scope"
    application_ref = "identity-control-dev"
    redirect_uris   = @($RedirectUri)
    audience        = @("identity-control-api")
    public_keys     = @($public)
    converge        = @("token_format", "audience_scope")
}

$client = New-Object System.Net.Http.HttpClient
function Send-Adopt($body, $idempotencyKey) {
    $request = New-Object System.Net.Http.HttpRequestMessage("POST", "$api/v1/registrations:adopt")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $request.Headers.Add("X-Administrative-Reason", "the development caller comes under registration")
    if ($idempotencyKey) { $request.Headers.Add("Idempotency-Key", $idempotencyKey) }
    $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    $response = $client.SendAsync($request).Result
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result }
}

$plan = Send-Adopt (($declaration + @{ dry_run = $true }) | ConvertTo-Json -Compress -Depth 5) $null
if ($plan.code -eq 409) {
    Write-Host "identity-control-caller is registered already; nothing to adopt."
    exit 0
}
if ($plan.code -ne 200) {
    throw "the plan was refused with $($plan.code): $($plan.body)"
}
$planned = ($plan.body | ConvertFrom-Json).plan
Write-Host "plan: adoptable=$($planned.adoptable)"
foreach ($difference in $planned.differences) {
    if ($difference.differs) {
        Write-Host ("  differs  {0,-16} {1}" -f $difference.field_class, $difference.policy)
    }
}
if (-not $planned.adoptable) {
    if ($planned.PSObject.Properties.Name -contains 'refusal') { Write-Host "refusal: $($planned.refusal)" }
    throw "the caller is not adoptable as declared. A redirect_uris or client_keys difference is fixed in the declaration, never in the console."
}
if (-not $Apply) {
    Write-Host "dry run only; run again with -Apply to adopt."
    exit 0
}

$adopted = Send-Adopt ($declaration | ConvertTo-Json -Compress -Depth 5) "dev-adopt-identity-control-caller"
if ($adopted.code -ne 201) {
    throw "the adoption was refused with $($adopted.code): $($adopted.body)"
}
$registration = ($adopted.body | ConvertFrom-Json).registration
Write-Host "adopted: registration_id=$($registration.registration_id) privileged_form=$($registration.privileged_form)"
