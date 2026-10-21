# Enrolment's caller and limits against the running service and the live kernel (ADR-IAM-011 §5.8,
# TDD-identity-control-001 1.27.0 §Enrolment From an Invitation). It stands in for Identity
# Experience's BFF: a workload made for this run, with its own key.
#
#   1. a provider makes the workload, and before it is registered its token is refused (403);
#   2. a provider registers it as an enrolment caller, with a reason; the record lists it;
#   3. without Forwarded, a request is 400 and counted nowhere;
#   4. with Forwarded, five requests from one client address are counted and answered (503 here, since
#      this stack runs no Organization Control: the same for every token), and the sixth is 429 with
#      Retry-After, before Organization Control would be asked;
#   5. :verify of an enrolment that does not exist is the one refusal, five times, and the sixth is 429;
#   6. a provider retires it, and its next request is refused (403).
#
# organization-control's deploy-dev runs the whole enrolment against the real Organization Control.
#
# Environment: as scripts/dev-smoke.ps1 (IDENTITY_API_URL, KC_BASE_URL, IDENTITY_CALLER_KEY_FILE,
# IDENTITY_CALLER_PASSWORD, IDENTITY_OPERATOR_TOTP_FILE). The workload's key is made for the run in
# -KeyDir and never printed.
#
#   pwsh ./scripts/dev-enrolment-proof.ps1 -KeyDir <directory>
param([Parameter(Mandatory = $true)] [string] $KeyDir)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. "$PSScriptRoot\dev-env.ps1"
$api    = Get-DevApiUrl
$kcBase = Get-DevKernelUrl
$realm  = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$operatorTotp = Get-DevOperatorTotp
$client = New-Object System.Net.Http.HttpClient
$run = [Guid]::NewGuid().ToString("N").Substring(0, 10)

$provider = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
    -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp

function Send([string] $method, [string] $path, [string] $body, [string] $bearer, [string] $key, [string] $forwarded) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$api$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $bearer)
    $request.Headers.Add("X-Administrative-Reason", "deploy-dev: the enrolment proof")
    if ($key) { $request.Headers.Add("Idempotency-Key", "$key-$run") }
    if ($forwarded) { $null = $request.Headers.TryAddWithoutValidation("Forwarded", $forwarded) }
    if ($null -ne $body) { $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json") }
    $response = $client.SendAsync($request).Result
    $retry = if ($response.Headers.RetryAfter) { $response.Headers.RetryAfter.ToString() } else { "" }
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result; retry = $retry }
}

function Decode-Claims([string] $jwt) {
    $s = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json
}

# New-RunKey writes a fresh RSA key's PKCS#8 PEM in the key directory and returns its public JWK.
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
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" } else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

Write-Host "1. a stand-in for the BFF's workload, refused before it is registered"
$operator = (Decode-Claims $provider).principal_id
$name = "enrolment-proof-bff-$run"
New-Item -ItemType Directory -Force -Path $KeyDir | Out-Null
$keyFile = Join-Path $KeyDir "$name.pem"
$jwk = New-RunKey $keyFile
$r = Send "POST" "/v1/workloads" (@{ display_name = "Enrolment proof BFF"
        purpose = "Stands in for Identity Experience's BFF in the enrolment proof"
        workload_type = "service"; owner_principal_id = $operator; client_key = $name
        application_ref = "enrolment-proof"; audience = @("identity-control-api"); public_key = $jwk
    } | ConvertTo-Json -Compress -Depth 4) $provider "ep-workload"
Expect "the workload is created" $r.code 201
if ($r.code -ne 201) { Write-Host "        $($r.body)"; exit 1 }
$workload = ($r.body | ConvertFrom-Json).principal_id
$issuer = Get-RealmIssuer $kcBase $realm
function Workload-Token {
    $assertion = New-ClientAssertion -KeyFile $keyFile -ClientId $name -Audience $issuer
    return (Invoke-RestMethod -Method Post -Uri "$kcBase/realms/$realm/protocol/openid-connect/token" -Body @{
            grant_type = "client_credentials"; client_id = $name
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion = $assertion }).access_token
}
$bff = Workload-Token
$forwarded = "for=198.51.100.$([int](Get-Random -Minimum 1 -Maximum 254));proto=https"
$r = Send "POST" "/v1/enrolments" '{"token":"not-an-invitation"}' $bff "" $forwarded
Expect "an unregistered workload is refused" $r.code 403

Write-Host "2. a provider registers it, with a reason"
$r = Send "POST" "/v1/enrolment-callers" (@{ principal_id = $workload; purpose = "the enrolment proof's BFF" } |
        ConvertTo-Json -Compress) $provider "ep-register"
Expect "registered" $r.code 201
$r = Send "GET" "/v1/enrolment-callers" $null $provider "" ""
Expect "the record lists it" ([bool](($r.body | ConvertFrom-Json).enrolment_callers | Where-Object { $_.principal_id -eq $workload })) $true

Write-Host "3. no Forwarded, no count"
$r = Send "POST" "/v1/enrolments" '{"token":"not-an-invitation"}' $bff "" ""
Expect "a request without the client address is 400" $r.code 400

Write-Host "4. five requests from one client address, then 429"
for ($i = 1; $i -le 5; $i++) {
    $r = Send "POST" "/v1/enrolments" "{`"token`":`"t-$i-$run`"}" $bff "" $forwarded
    Expect "request $i is counted and answered without Organization Control" $r.code 503
}
$r = Send "POST" "/v1/enrolments" '{"token":"t-6"}' $bff "" $forwarded
Expect "the sixth is 429" $r.code 429
Expect "with Retry-After" ([bool]($r.retry -match '^\d+$' -and [int]$r.retry -ge 1 -and [int]$r.retry -le 60)) $true

Write-Host "5. :verify of no enrolment is the one refusal, then 429"
$detail = $null
for ($i = 1; $i -le 5; $i++) {
    $r = Send "POST" "/v1/enrolments/$([Guid]::NewGuid()):verify" '{"code":"12345678"}' $bff "" $forwarded
    Expect "verify $i is refused" $r.code 400
    $d = ($r.body | ConvertFrom-Json).detail
    if ($null -eq $detail) { $detail = $d } else { Expect "  with the one detail" $d $detail }
}
$r = Send "POST" "/v1/enrolments/$([Guid]::NewGuid()):verify" '{"code":"12345678"}' $bff "" $forwarded
Expect "the sixth verify is 429" $r.code 429

Write-Host "6. retired, refused"
$r = Send "POST" "/v1/enrolment-callers/$($workload):retire" $null $provider "ep-retire" ""
Expect "retired" $r.code 200
$r = Send "POST" "/v1/enrolments" '{"token":"t-7"}' $bff "" "for=203.0.113.200"
Expect "the retired workload is refused" $r.code 403

Remove-Item -Force $keyFile
if ($failures -gt 0) { Write-Host ""; Write-Host "$failures check(s) failed"; exit 1 }
Write-Host ""
Write-Host "the enrolment caller and its limits hold"
