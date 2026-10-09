# The check that ends deploy/dev/README.md §First start (step 11): the server runs with
# IDENTITY_UNMANAGED_CLIENTS=disable and IDENTITY_TOKEN_TYPE=enforce, and still serves its callers.
#
#   1. the bootstrap operator signs in through identity-control-caller, and the access token is typed
#      at+jwt (STD-IAM-002 §3.2, TDD-identity-control-001 §Caller Token): enforce would refuse it otherwise;
#   2. a provider call answers 200 under enforce;
#   3. a registration sweep runs, and no client is recorded unmanaged: under disable it would have been
#      disabled, the caller or the BFF with every open session (TDD-identity-control-003 §Adoption).
#
# It reads and sweeps, and changes no registration. Safe on the development server and in deploy-dev.
#
# Environment: as scripts/dev-smoke.ps1 (IDENTITY_API_URL, KC_BASE_URL, IDENTITY_CALLER_KEY_FILE,
# IDENTITY_CALLER_PASSWORD, IDENTITY_OPERATOR_TOTP_FILE). Nothing secret is printed.
#
#   pwsh ./scripts/dev-production-switches.ps1

$ErrorActionPreference = "Stop"

$api = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8082" }
foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "$name is required." }
}
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" }
    else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

function Decode-Part([string] $jwt, [int] $index) {
    $part = $jwt.Split('.')[$index].Replace('-', '+').Replace('_', '/')
    switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
}

$http = New-Object System.Net.Http.HttpClient
function Call($method, $path, $token) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$api$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $response = $http.SendAsync($request).Result
    $text = $response.Content.ReadAsStringAsync().Result
    $json = $null
    if ($text) { try { $json = $text | ConvertFrom-Json } catch { $json = $null } }
    return @{ code = [int]$response.StatusCode; json = $json }
}

$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
Write-Host "1. the caller's token is typed at+jwt"
$token = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
    -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
Expect "typ" (Decode-Part $token 0).typ "at+jwt"

Write-Host "2. a provider call answers under enforce"
Expect "GET /v1/registrations" (Call "GET" "/v1/registrations?limit=1" $token).code 200

Write-Host "3. a sweep records no unmanaged client"
Expect "POST /v1/registrations:reconcile" (Call "POST" "/v1/registrations:reconcile" $token).code 200
$drift = Call "GET" "/v1/registrations:drift" $token
Expect "the drift status is read" $drift.code 200
$unmanaged = @($drift.json.findings | Where-Object { $_.finding_class -eq "unmanaged" })
foreach ($finding in $unmanaged) { Write-Host "        unmanaged: $($finding.client_key)" }
Expect "no client is unmanaged" $unmanaged.Count 0

Write-Host ""
if ($failures -gt 0) { Write-Host "$failures check(s) failed."; exit 1 }
Write-Host "the server runs in the production settings and serves its callers."
