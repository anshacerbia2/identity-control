# A session removed through the Identity Control API reaches a registered client by OpenID Connect
# Back-Channel Logout, against the live kernel (ADR-IAM-009, TDD-identity-control-003 1.37.0):
#
#   1. a confidential client is registered through POST /v1/registrations, as the BFF is on a new
#      server: privileged, provider-scope, identity-control-api in its audience, its own key, and a
#      backchannel_logout_uri naming the receiver (scripts/dev-logout-receiver.py);
#   2. the bootstrap operator signs in through that client;
#   3. the session is ended at POST /v1/me/sessions/{security_ref}:terminate, followed until final;
#   4. the receiver holds a logout token for that client and that session: typed logout+jwt, PS256,
#      the realm as issuer, the client as audience, the back-channel logout event, the session's sid,
#      and no nonce (Back-Channel Logout 1.0 §2.4, §2.6), within the command budget.
#
# The receiver must listen where the kernel can reach it: on a CI runner, the kernel's Docker
# network gateway. It ends one session of the bootstrap operator: for a kernel that lives for a CI
# job, never a shared server.
#
# SECRETS: read from the environment, as dev-session-removal-proof.ps1 reads them. None is printed.
#   IDENTITY_CALLER_KEY_FILE, IDENTITY_CALLER_PASSWORD, IDENTITY_OPERATOR_TOTP_FILE   the sign-in
#
# Usage: pwsh ./scripts/dev-back-channel-logout-proof.ps1 -ReceiverUrl http://172.18.0.1:8199/back-channel-logout `
#            -Received /path/to/received.jsonl -WorkDir /path/to/a/private/directory

param(
    [Parameter(Mandatory = $true)] [string] $ReceiverUrl,
    [Parameter(Mandatory = $true)] [string] $Received,
    [Parameter(Mandatory = $true)] [string] $WorkDir
)

$ErrorActionPreference = "Stop"

$api    = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8082" }
$kcBase = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$realm  = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
$commandBudget = 2.0
$propagationBudget = 60.0

foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "$name is required."
    }
}
if ($PSVersionTable.PSEdition -ne 'Core') { throw "PowerShell 7 is needed to make a PKCS#8 key for the run" }

Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"

$http = New-Object System.Net.Http.HttpClient

function Send($method, $url, $body, $bearer, $headers) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, $url)
    if ($bearer) {
        $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $bearer)
    }
    if ($headers) { foreach ($k in $headers.Keys) { $request.Headers.Add($k, $headers[$k]) } }
    if ($null -ne $body) {
        $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    }
    $response = $http.SendAsync($request).Result
    $text = $response.Content.ReadAsStringAsync().Result
    $json = $null
    if ($text) { try { $json = $text | ConvertFrom-Json } catch { $json = $null } }
    return @{ code = [int]$response.StatusCode; json = $json; text = $text }
}

function Decode-Part([string] $jwt, [int] $index) {
    $s = $jwt.Split('.')[$index].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json
}

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" }
    else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$redirect = "http://127.0.0.1:8099/callback"

Write-Host "1. a confidential client is registered with a back-channel logout URI"
$provider = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
    -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
$run = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$clientKey = "logout-proof-$run"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$keyFile = Join-Path $WorkDir "$clientKey.pem"
$rsa = [System.Security.Cryptography.RSA]::Create(3072)
try {
    $pem = "-----BEGIN PRIVATE KEY-----`n" +
        [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), [Base64FormattingOptions]::InsertLineBreaks) +
        "`n-----END PRIVATE KEY-----`n"
    [System.IO.File]::WriteAllText($keyFile, $pem)
    if (-not $IsWindows) { & chmod 600 $keyFile }
    $public = $rsa.ExportParameters($false)
    $jwk = @{ kty = "RSA"; n = (ConvertTo-Base64Url $public.Modulus); e = (ConvertTo-Base64Url $public.Exponent) }
} finally { $rsa.Dispose() }
$registration = @{ client_key = $clientKey; profile = "confidential"; audience_class = "privileged"
    privileged_form = "provider-scope"; application_ref = "identity-control-dev"; redirect_uris = @($redirect)
    audience = @("identity-control-api"); public_key = $jwk; backchannel_logout_uri = $ReceiverUrl } |
    ConvertTo-Json -Compress -Depth 4
$r = Send "POST" "$api/v1/registrations" $registration $provider @{ "Idempotency-Key" = "logout-proof-$run" }
Expect "registered" $r.code 201
if ($r.code -ne 201) { Write-Host "        $($r.text)"; exit 1 }
Expect "the registration names the URI" $r.json.backchannel_logout_uri $ReceiverUrl

Write-Host "2. the bootstrap operator signs in through it"
$signin = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
    -ClientId $clientKey -KeyFile $keyFile -RedirectUri $redirect -FullResponse @operatorTotp
$claims = Decode-Part $signin.access_token 1
Expect "the token names the session" ([bool]$claims.sid) $true

Write-Host "3. that session is ended through the Identity Control API"
$sessions = Send "GET" "$api/v1/me/sessions" $null $signin.access_token $null
Expect "the sessions are listed" $sessions.code 200
$current = @($sessions.json.sessions | Where-Object { $_.current -eq $true })
Expect "this session is marked current" $current.Count 1
if ($current.Count -ne 1) { Write-Host "        $($sessions.text)"; exit 1 }
$before = if (Test-Path $Received) { @(Get-Content $Received).Count } else { 0 }
$watch = [System.Diagnostics.Stopwatch]::StartNew()
$r = Send "POST" "$api/v1/me/sessions/$($current[0].security_ref):terminate" $null $signin.access_token `
    @{ "Idempotency-Key" = "logout-proof-end-$run" }
Expect "accepted" ($r.code -in @(200, 202)) $true
if ($r.code -notin @(200, 202)) { Write-Host "        $($r.text)"; exit 1 }
$operation = $r.json
for ($i = 0; $i -lt 600 -and $operation.state -notin @("applied", "refused", "unresolved"); $i++) {
    Start-Sleep -Milliseconds 100
    $operation = (Send "GET" "$api/v1/me/security-operations/$($operation.operation_id)" $null $signin.access_token $null).json
}
Expect "applied" $operation.state "applied"

Write-Host "4. the kernel posted a logout token for that session"
$record = $null
for ($i = 0; $i -lt 600 -and -not $record; $i++) {
    if (Test-Path $Received) {
        $lines = @(Get-Content $Received)
        if ($lines.Count -gt $before) { $record = $lines[$before] | ConvertFrom-Json }
    }
    if (-not $record) { Start-Sleep -Milliseconds 100 }
}
$watch.Stop()
$delay = [math]::Round($watch.Elapsed.TotalSeconds, 3)
Expect "a logout request arrived" ([bool]$record) $true
if (-not $record) { exit 1 }
Expect "posted as a form" ($record.content_type -like "application/x-www-form-urlencoded*") $true
Expect "carrying a logout_token" ([bool]$record.logout_token) $true
$header = Decode-Part $record.logout_token 0
$token = Decode-Part $record.logout_token 1
$issuer = Get-RealmIssuer $kcBase $realm
$logoutEvent = "http://schemas.openid.net/event/backchannel-logout"
Expect "typed logout+jwt" $header.typ "logout+jwt"
Expect "signed PS256, which the BFF accepts alone" $header.alg "PS256"
Expect "issued by the realm" $token.iss $issuer
Expect "for this client" (@($token.aud) -contains $clientKey) $true
Expect "the back-channel logout event" (($token.events.PSObject.Properties.Name) -contains $logoutEvent) $true
Expect "naming the ended session" $token.sid $claims.sid
Expect "naming its subject" $token.sub $claims.sub
Expect "carrying no nonce" ($token.PSObject.Properties.Name -contains 'nonce') $false
Write-Host "        command accepted to logout token received: $delay s"
if ($delay -gt $propagationBudget) {
    Write-Host "  FAIL  the logout token took $delay s, over SAD-001 §7.7's 60 s propagation budget"
    $failures++
} elseif ($delay -gt $commandBudget) {
    Write-Host "::warning::the logout token took $delay s, over the 2 s command budget"
}

$summary = @("## Back-channel logout · a registered client", "",
    "| Registered | Ended | Received | Delay |", "| :-- | :-- | :-- | :-- |",
    "| ``$clientKey`` with ``backchannel_logout_uri`` | ``POST /v1/me/sessions/{ref}:terminate`` | logout token, ``sid`` of the session | $delay s |")
if ($env:GITHUB_STEP_SUMMARY) { $summary | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8 }

Remove-Item -Force $keyFile
Write-Host ""
if ($failures -gt 0) { Write-Host "$failures check(s) failed."; exit 1 }
Write-Host "a session removal reaches the registered client by the back channel."
