# Runs the BFF's adoption procedure against a stack, as STD-GLB-009 1.3.0 requires of a procedure step:
# deploy-dev calls it after identity-experience's create-bff-client.sh has made the client the way it
# made it on the development server.
#
#   1. a wrong declaration, internal, is refused at the plan on audience_profile
#      (ADR-IAM-001 §5.12 rule 3, TDD-identity-control-003 1.30.0);
#   2. dev-adopt-bff.ps1 plans, then adopts with -Apply;
#   3. the adopted BFF's own token, from the kernel's login at aal2, carries acr and auth_time, names
#      identity-control-api, and is served on a provider route;
#   4. a second run of the procedure finds the BFF registered and changes nothing.
#
# SECRETS: read from the environment, as dev-smoke.ps1 reads them. The BFF's key pair is the one
# identity-kernel's new-client-key.sh made for the stack; nothing read from either file is printed.
#
# Usage: pwsh ./scripts/dev-bff-adoption-proof.ps1 -BffJwkFile <public JWK> -BffKeyFile <private PEM>

param(
    [Parameter(Mandatory = $true)] [string] $BffJwkFile,
    [Parameter(Mandatory = $true)] [string] $BffKeyFile
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$api = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8090" }
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
$client = New-Object System.Net.Http.HttpClient

function Send($method, $path, $body, $bearer) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$api$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $bearer)
    $request.Headers.Add("X-Administrative-Reason", "deploy-dev: the BFF adoption procedure")
    if ($body) {
        $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    }
    $response = $client.SendAsync($request).Result
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result }
}

function Decode-Segment($segment) {
    $s = $segment.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))
}

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) {
        Write-Host "  ok    $label ($got)"
    } else {
        Write-Host "  FAIL  $label (got $got, want $want)"
        $script:failures++
    }
}

$jwk = Get-Content -Raw -Path $BffJwkFile | ConvertFrom-Json
$public = @{ kty = "RSA"; n = $jwk.n; e = $jwk.e }

Write-Host "1. a wrong declaration is refused at the plan"
$wrong = @{ client_key = "identity-experience-bff"; profile = "confidential"; audience_class = "internal"
    application_ref = "identity-experience"; redirect_uris = @("http://127.0.0.1:8090/auth/callback")
    audience = @("identity-control-api"); public_keys = @($public)
    converge = @("token_format", "audience_scope"); dry_run = $true } | ConvertTo-Json -Compress -Depth 5
$r = Send "POST" "/v1/registrations:adopt" $wrong $token
Expect "planned" $r.code 200
if ($r.code -eq 200) {
    $plan = ($r.body | ConvertFrom-Json).plan
    Expect "not adoptable" $plan.adoptable $false
    Expect "refused on audience_profile" ($plan.refusal -like "audience_profile*") $true
}

Write-Host ""
Write-Host "2. the procedure plans, then adopts"
& "$PSScriptRoot\dev-adopt-bff.ps1" -BffJwkFile $BffJwkFile
& "$PSScriptRoot\dev-adopt-bff.ps1" -BffJwkFile $BffJwkFile -Apply

Write-Host ""
Write-Host "3. the adopted BFF's own token is a provider's"
$bffToken = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
    -ClientId "identity-experience-bff" -KeyFile $BffKeyFile -RedirectUri "http://127.0.0.1:8090/auth/callback" @operatorTotp
$parts = $bffToken.Split('.')
$header = Decode-Segment $parts[0] | ConvertFrom-Json
$claims = Decode-Segment $parts[1] | ConvertFrom-Json
$names = $claims.PSObject.Properties.Name
Expect "typ at+jwt" $header.typ "at+jwt"
Expect "acr aal2" $(if ($names -contains 'acr') { $claims.acr } else { '' }) "aal2"
Expect "auth_time present" ($names -contains 'auth_time') $true
Expect "aud names identity-control-api" (@($claims.aud) -contains "identity-control-api") $true
Expect "no tenant_id" ($names -contains 'tenant_id') $false
$r = Send "GET" "/v1/registrations?limit=1" $null $bffToken
Expect "served on a provider route" $r.code 200

Write-Host ""
Write-Host "4. a second run changes nothing"
& "$PSScriptRoot\dev-adopt-bff.ps1" -BffJwkFile $BffJwkFile

if ($failures -gt 0) {
    Write-Host ""
    Write-Host "$failures check(s) failed"
    exit 1
}
Write-Host ""
Write-Host "the BFF adoption procedure holds"
