# Session removal's accept-to-enforcement delay, measured against the live kernel
# (TDD-identity-control-005 2.10.0 §Enforcement Delay; SAD-001 §7.7; ROADMAP §Gates, Production gate).
#
#   1. the bootstrap operator signs in, and the kernel lists that session;
#   2. POST /v1/me/sessions:terminate-all, followed until the operation is final;
#   3. the delay is the operation's applied_at less its created_at: acceptance is the committed
#      operation, and applied is written only once the read-back finds the session list empty;
#   4. the kernel lists no session for the operator, and the refresh token from step 1 is refused.
#
# The figure goes to the job summary. Above IDENTITY_SECURITY_COMMAND_BUDGET (2 s) is a warning; above
# SAD-001 §7.7's 60-second propagation budget the script fails.
#
# It ends every session of the bootstrap operator: for a kernel that lives for a CI job, never a
# shared server.
#
# SECRETS: read from the environment, as dev-proof-b.ps1 reads them. None is printed.
#   IDENTITY_CALLER_KEY_FILE, IDENTITY_CALLER_PASSWORD, IDENTITY_OPERATOR_TOTP_FILE   the sign-in
#   KC_BOOTSTRAP_ADMIN_USERNAME, KC_BOOTSTRAP_ADMIN_PASSWORD   the kernel's own session list
# KC_BASE_URL is where the login form is served, KC_ADMIN_URL the kernel's private /admin address.
#
# Usage: pwsh ./scripts/dev-session-removal-proof.ps1

$ErrorActionPreference = "Stop"

$api       = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8082" }
$kcBase    = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$kcAdmin   = if ($env:KC_ADMIN_URL) { $env:KC_ADMIN_URL } else { "http://127.0.0.1:8081" }
$realm     = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
$adminUser = if ($env:KC_BOOTSTRAP_ADMIN_USERNAME) { $env:KC_BOOTSTRAP_ADMIN_USERNAME } else { "admin" }
$commandBudget = 2.0
$propagationBudget = 60.0

foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD", "KC_BOOTSTRAP_ADMIN_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "$name is required."
    }
}

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

function Admin-Token {
    $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $form["grant_type"] = "password"
    $form["client_id"] = "admin-cli"
    $form["username"] = $adminUser
    $form["password"] = $env:KC_BOOTSTRAP_ADMIN_PASSWORD
    $response = $http.PostAsync("$kcAdmin/realms/master/protocol/openid-connect/token",
        (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result
    if (-not $response.IsSuccessStatusCode) { throw "the console administrator could not log in: $([int]$response.StatusCode)" }
    return ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json).access_token
}

function Decode-Claims([string] $jwt) {
    $s = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json
}

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" }
    else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }

Write-Host "1. the bootstrap operator signs in"
$signin = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
    -KeyFile $env:IDENTITY_CALLER_KEY_FILE -FullResponse @operatorTotp
$claims = Decode-Claims $signin.access_token
$admin = Admin-Token
$users = @((Send "GET" "$kcAdmin/admin/realms/$realm/users?username=bootstrap-operator&exact=true" $null $admin).json)
Expect "the kernel holds the operator" $users.Count 1
$userId = $users[0].id
$before = @((Send "GET" "$kcAdmin/admin/realms/$realm/users/$userId/sessions" $null $admin).json)
Expect "the kernel lists the session" (@($before | Where-Object { $_.id -eq $claims.sid }).Count) 1

Write-Host "2. every session ends"
$watch = [System.Diagnostics.Stopwatch]::StartNew()
$r = Send "POST" "$api/v1/me/sessions:terminate-all" $null $signin.access_token @{ "Idempotency-Key" = "session-removal-$([Guid]::NewGuid().ToString('N'))" }
Expect "accepted" ($r.code -in @(200, 202)) $true
if ($r.code -notin @(200, 202)) {
    Write-Host "        $($r.text)"
    exit 1
}
$operation = $r.json
for ($i = 0; $i -lt 600 -and $operation.state -notin @("applied", "refused", "unresolved"); $i++) {
    Start-Sleep -Milliseconds 100
    $operation = (Send "GET" "$api/v1/me/security-operations/$($operation.operation_id)" $null $signin.access_token $null).json
}
$watch.Stop()
Expect "applied" $operation.state "applied"
if ($operation.state -ne "applied") { exit 1 }

$created = [datetimeoffset]$operation.created_at
$applied = [datetimeoffset]$operation.applied_at
$delay = [math]::Round(($applied - $created).TotalSeconds, 3)
$observed = [math]::Round($watch.Elapsed.TotalSeconds, 3)
Write-Host "        accepted to enforced: $delay s (the caller saw it final after $observed s)"

Write-Host "3. the kernel holds no session, and the refresh is refused"
$admin = Admin-Token
$after = @((Send "GET" "$kcAdmin/admin/realms/$realm/users/$userId/sessions" $null $admin).json)
Expect "no session left" $after.Count 0
if ($signin.PSObject.Properties.Name -contains 'refresh_token' -and $signin.refresh_token) {
    $issuer = Get-RealmIssuer $kcBase $realm
    $assertion = New-ClientAssertion -KeyFile $env:IDENTITY_CALLER_KEY_FILE -ClientId "identity-control-caller" -Audience $issuer
    $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $form["grant_type"] = "refresh_token"
    $form["client_id"] = "identity-control-caller"
    $form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    $form["client_assertion"] = $assertion
    $form["refresh_token"] = $signin.refresh_token
    $refresh = $http.PostAsync("$kcBase/realms/$realm/protocol/openid-connect/token",
        (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result
    Expect "the refresh is refused" ([int]$refresh.StatusCode) 400
    $refreshError = try { ($refresh.Content.ReadAsStringAsync().Result | ConvertFrom-Json).error } catch { "" }
    Expect "as invalid_grant" $refreshError "invalid_grant"
} else {
    Write-Host "        the sign-in issued no refresh token; the kernel's session list is the evidence"
}

$verdict = if ($delay -gt $propagationBudget) { "over the 60 s propagation budget" }
    elseif ($delay -gt $commandBudget) { "within the 60 s budget, over the 2 s command budget" }
    else { "within the 2 s command budget" }
Write-Host "        $verdict"
if ($delay -gt $propagationBudget) {
    Write-Host "  FAIL  session removal took $delay s, over SAD-001 §7.7's 60 s propagation budget"
    $failures++
} elseif ($delay -gt $commandBudget) {
    Write-Host "::warning::session removal took $delay s, over IDENTITY_SECURITY_COMMAND_BUDGET (2 s)"
}

$summary = @("## Accept-to-enforcement · session removal", "",
    "| Class | Accepted | Enforced | Delay | Bound |", "| :-- | :-- | :-- | :-- | :-- |",
    ('| Session (`sessions.terminate-all`) | operation committed | kernel session list empty | ' + "$delay s" +
        ' | 2 s command budget; 60 s propagation budget (SAD-001 §7.7) |'),
    "", "The caller saw the operation final after $observed s.")
if ($env:GITHUB_STEP_SUMMARY) { $summary | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8 }

Write-Host ""
if ($failures -gt 0) { Write-Host "$failures check(s) failed."; exit 1 }
Write-Host "session removal is enforced within budget."
