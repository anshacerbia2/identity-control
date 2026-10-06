# Account security notifications against a live kernel (TDD-identity-control-008, ADR-IAM-007).
# deploy-dev runs it after dev-kernel-events-proof.ps1, whose sweep recorded the bootstrap operator's
# TOTP enrolment from the smoke suite's first sign-in:
#
#   1. the operator's creation email is its notification address;
#   2. the enrolment requested authenticator_bound (otp) and recovery_codes_issued, each to that one
#      address;
#   3. the development stand-in accepted them: each reads submitted;
#   4. the operator's own addresses (1.2.0): an added address waits for its code, a wrong code is
#      refused, its proof request goes to it alone and the stand-in accepts it without the code ever
#      being shown, the pending address is removed, and the last active address cannot be.
#
# SECRETS: read from the environment, as dev-smoke.ps1 reads them. No address is printed.
#
# Usage: pwsh ./scripts/dev-notifications-proof.ps1

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$api = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8090" }
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
$client = New-Object System.Net.Http.HttpClient

function Decode-Claims([string] $jwt) {
    $s = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json
}
$operator = (Decode-Claims $token).principal_id

function Read([string] $path, [string] $field) {
    $request = New-Object System.Net.Http.HttpRequestMessage("GET", "$api$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $request.Headers.Add("X-Administrative-Reason", "deploy-dev: account security notifications")
    $response = $client.SendAsync($request).Result
    $body = $response.Content.ReadAsStringAsync().Result
    if ([int]$response.StatusCode -ne 200) { throw "$path answered $([int]$response.StatusCode): $body" }
    return @(($body | ConvertFrom-Json).$field)
}

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" } else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

Write-Host "1. the operator's notification address"
$addresses = Read "/v1/principals/$operator/notification-addresses" "notification_addresses"
$active = @($addresses | Where-Object { $_.state -eq "active" })
Expect "one active address" $active.Count 1
Expect "it is the creation address" $(if ($active.Count -gt 0) { $active[0].origin } else { "" }) "creation"

Write-Host ""
Write-Host "2. the enrolment's notifications, each to that address"
$notifications = Read "/v1/principals/$operator/security-notifications" "security_notifications"
$bound = @($notifications | Where-Object { $_.event -eq "authenticator_bound" -and $_.details.authenticator -eq "otp" })
$codes = @($notifications | Where-Object { $_.event -eq "recovery_codes_issued" })
Expect "authenticator_bound (otp) requested" ($bound.Count -ge 1) $true
Expect "recovery_codes_issued requested" ($codes.Count -ge 1) $true
Expect "to one recipient" $(if ($bound.Count -gt 0) { $bound[0].recipients } else { 0 }) 1

Write-Host ""
Write-Host "3. the stand-in accepts them"
$deadline = (Get-Date).AddSeconds(60)
do {
    $notifications = Read "/v1/principals/$operator/security-notifications" "security_notifications"
    $waiting = @($notifications | Where-Object { $_.state -eq "requested" })
    if ($waiting.Count -eq 0) { break }
    Start-Sleep -Seconds 5
} while ((Get-Date) -lt $deadline)
Expect "none waiting" $waiting.Count 0
$failed = @($notifications | Where-Object { $_.state -in @("failed", "no_address") })
Expect "none failed" $failed.Count 0
$submitted = @($notifications | Where-Object {
        $_.event -in @("authenticator_bound", "recovery_codes_issued") -and $_.state -eq "submitted" })
Expect "the enrolment's are submitted" ($submitted.Count -ge 2) $true

Write-Host ""
Write-Host "4. the operator's own addresses"
# A fresh sign-in: adding and removing an address need a recent aal2, and the first token may be near
# the end of its lifetime.
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
function Send([string] $method, [string] $path, [string] $body) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$api$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $request.Headers.Add("Idempotency-Key", [Guid]::NewGuid().ToString())
    if ($body) { $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json") }
    $response = $client.SendAsync($request).Result
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result }
}
$added = Send "POST" "/v1/me/notification-addresses" '{"address":"second-operator-address@scnehaux.local"}'
Expect "an address is added" $added.code 201
$pending = if ($added.code -eq 201) { ($added.body | ConvertFrom-Json).notification_address } else { $null }
Expect "and waits for its code" $(if ($pending) { $pending.state } else { "" }) "pending"
if ($pending) {
    $wrong = Send "POST" "/v1/me/notification-addresses/$($pending.address_id):verify" '{"code":"00000000"}'
    Expect "a wrong code is refused" $wrong.code 400
    $deadline = (Get-Date).AddSeconds(60)
    do {
        $proofs = @(Read "/v1/principals/$operator/security-notifications" "security_notifications" |
            Where-Object { $_.event -eq "notification_address_proof" })
        if ($proofs.Count -gt 0 -and $proofs[0].state -eq "submitted") { break }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    Expect "its proof is requested to it alone" $(if ($proofs.Count -gt 0) { $proofs[0].recipients } else { 0 }) 1
    Expect "and the stand-in accepts it" $(if ($proofs.Count -gt 0) { $proofs[0].state } else { "" }) "submitted"
    $removed = Send "POST" "/v1/me/notification-addresses/$($pending.address_id):remove" $null
    Expect "the pending address is removed" $removed.code 204
}
$own = @((Send "GET" "/v1/me/notification-addresses" $null).body | ConvertFrom-Json).notification_addresses
$last = @($own | Where-Object { $_.state -eq "active" })
Expect "one active address remains" $last.Count 1
if ($last.Count -eq 1) {
    $refused = Send "POST" "/v1/me/notification-addresses/$($last[0].address_id):remove" $null
    Expect "the last active address cannot be removed" $refused.code 409
}

if ($failures -gt 0) {
    Write-Host ""
    Write-Host "$failures check(s) failed"
    exit 1
}
Write-Host ""
Write-Host "account security notifications hold"
