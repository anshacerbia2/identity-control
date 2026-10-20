# Account security notifications against a live kernel (TDD-identity-control-008, ADR-IAM-007).
# deploy-dev runs it after dev-kernel-events-proof.ps1, whose sweep recorded the bootstrap operator's
# TOTP enrolment from the smoke suite's first sign-in:
#
#   1. the operator's creation email is its notification address;
#   2. the enrolment requested authenticator_bound (otp) and recovery_codes_issued, each to that one
#      address;
#   3. the development adapter handed them over: each reads submitted;
#   4. the operator's own addresses (1.2.0): an added address waits for its code, a wrong code is
#      refused, and the right one, read from the development mail catcher, proves it (1.7.0); the
#      others are told; it is removed, and the last active address cannot be;
#   5. the creation address is proven (1.7.0): :send-proof sends a code to it alone, a second send while
#      the code is good is refused, and the code from the catcher proves it;
#   6. with -TenantState, the identifier match (1.7.0, ADR-ORG-007 §5.3): Organization Control's
#      workload, from dev-tenant-proof.ps1's state, is answered true for the proven address and false
#      for any other or for an unknown Principal, and a person's token is refused.
#
# Steps 4 and 5 read the code from the mail catcher's API (Mailpit, -MailpitUrl), the only place it is
# readable; IDENTITY_NOTIFICATION_DELIVERY is smtp-catcher. With the stand-in instead, no code can be
# read, and they prove only that a wrong code leaves the address waiting.
#
# SECRETS: read from the environment, as dev-smoke.ps1 reads them. No address or code is printed.
#
# Usage: pwsh ./scripts/dev-notifications-proof.ps1 [-MailpitUrl http://127.0.0.1:8025] [-TenantState <file>]

param(
    [string] $MailpitUrl = $(if ($env:MAILPIT_URL) { $env:MAILPIT_URL } else { "http://127.0.0.1:8025" }),
    [string] $TenantState = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. "$PSScriptRoot\dev-env.ps1"   # IDENTITY_API_URL, KC_BASE_URL, the operator TOTP: derived from deploy/dev/.env
$api = Get-DevApiUrl
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$operatorTotp = Get-DevOperatorTotp
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

# The newest code the catcher holds for an address, waiting for the dispatcher to hand it over. Empty
# when no catcher answers: the stand-in delivers nothing.
function Read-Code([string] $address, [datetime] $after) {
    $deadline = (Get-Date).AddSeconds(60)
    do {
        try {
            $listed = Invoke-RestMethod -Uri "$MailpitUrl/api/v1/messages?limit=100" -TimeoutSec 5
        } catch {
            return ""
        }
        foreach ($m in @($listed.messages)) {
            $to = @($m.To | ForEach-Object { $_.Address })
            if ($to -contains $address -and $m.Subject -like "*code*" -and ([datetime]$m.Created).ToUniversalTime() -ge $after) {
                $message = Invoke-RestMethod -Uri "$MailpitUrl/api/v1/message/$($m.ID)" -TimeoutSec 5
                if ($message.Text -match 'Your code is (\d{8})') { return $Matches[1] }
            }
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return ""
}
$catcher = $true
try { $null = Invoke-RestMethod -Uri "$MailpitUrl/api/v1/messages?limit=1" -TimeoutSec 5 } catch { $catcher = $false }
Write-Host "  the mail catcher answers: $catcher"

$second = "second-operator-address-$([Guid]::NewGuid().ToString('N').Substring(0, 8))@scnehaux.local"
$addedAt = (Get-Date).ToUniversalTime().AddSeconds(-5)
$added = Send "POST" "/v1/me/notification-addresses" "{`"address`":`"$second`"}"
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
    Expect "and handed over" $(if ($proofs.Count -gt 0) { $proofs[0].state } else { "" }) "submitted"
    if ($catcher) {
        $code = Read-Code $second $addedAt
        Expect "the catcher holds its code" ($code.Length) 8
        $right = Send "POST" "/v1/me/notification-addresses/$($pending.address_id):verify" "{`"code`":`"$code`"}"
        Expect "the right code proves it" $right.code 204
        $changed = @(Read "/v1/principals/$operator/security-notifications" "security_notifications" |
            Where-Object { $_.event -eq "notification_address_changed" -and $_.details.change -eq "added" })
        Expect "the address held before is told" ($changed.Count -ge 1) $true
    }
    $removed = Send "POST" "/v1/me/notification-addresses/$($pending.address_id):remove" $null
    Expect "the added address is removed" $removed.code 204
}
$own = @((Send "GET" "/v1/me/notification-addresses" $null).body | ConvertFrom-Json).notification_addresses
$last = @($own | Where-Object { $_.state -eq "active" })
Expect "one active address remains" $last.Count 1
if ($last.Count -eq 1) {
    $refused = Send "POST" "/v1/me/notification-addresses/$($last[0].address_id):remove" $null
    Expect "the last active address cannot be removed" $refused.code 409
}

Write-Host ""
Write-Host "5. the creation address is proven with a code"
$creation = if ($last.Count -eq 1) { $last[0] } else { $null }
if ($creation -and -not ($creation.PSObject.Properties.Name -contains "verified_at")) {
    $sentAt = (Get-Date).ToUniversalTime().AddSeconds(-5)
    $sent = Send "POST" "/v1/me/notification-addresses/$($creation.address_id):send-proof" $null
    Expect "a code is sent to it" $sent.code 200
    $again = Send "POST" "/v1/me/notification-addresses/$($creation.address_id):send-proof" $null
    Expect "a second send while it is good is refused" $again.code 409
    if ($catcher) {
        $code = Read-Code $creation.address $sentAt
        Expect "the catcher holds its code" ($code.Length) 8
        $proven = Send "POST" "/v1/me/notification-addresses/$($creation.address_id):verify" "{`"code`":`"$code`"}"
        Expect "the code proves it" $proven.code 204
        $now = @((Send "GET" "/v1/me/notification-addresses" $null).body | ConvertFrom-Json).notification_addresses |
            Where-Object { $_.address_id -eq $creation.address_id }
        Expect "it is proven" ($now.PSObject.Properties.Name -contains "verified_at") $true
    }
} elseif ($creation) {
    Write-Host "  ok    the creation address is proven already"
}

if ($TenantState -and (Test-Path $TenantState)) {
    Write-Host ""
    Write-Host "6. the identifier match, as Organization Control's workload"
    $s = Get-Content -Raw $TenantState | ConvertFrom-Json
    $kcBase = Get-DevKernelUrl
    $issuer = Get-RealmIssuer $kcBase "scnehaux"
    $assertion = New-ClientAssertion -KeyFile $s.delivery_key -ClientId $s.delivery_client -Audience $issuer
    $workload = (Invoke-RestMethod -Method Post -Uri "$kcBase/realms/scnehaux/protocol/openid-connect/token" -Body @{
            grant_type = "client_credentials"; client_id = $s.delivery_client
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion = $assertion }).access_token
    function Ask([string] $principal, [string] $address, [string] $bearer) {
        $request = New-Object System.Net.Http.HttpRequestMessage("POST", "$api/v1/principals/$principal/identifiers:match")
        $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $bearer)
        $request.Content = New-Object System.Net.Http.StringContent("{`"address`":`"$address`"}", [System.Text.Encoding]::UTF8, "application/json")
        $response = $client.SendAsync($request).Result
        return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result }
    }
    if ($catcher -and $creation) {
        $yes = Ask $operator $creation.address.ToUpperInvariant() $workload
        Expect "a proven address matches, without case" "$($yes.code) $($yes.body.Trim())" '200 {"match":true}'
    }
    $no = Ask $operator "nobody-$([Guid]::NewGuid().ToString('N'))@scnehaux.local" $workload
    Expect "another address does not" "$($no.code) $($no.body.Trim())" '200 {"match":false}'
    $unknown = Ask ([Guid]::NewGuid().ToString()) $(if ($creation) { $creation.address } else { "a@scnehaux.local" }) $workload
    Expect "an unknown Principal is answered alike" "$($unknown.code) $($unknown.body.Trim())" '200 {"match":false}'
    $person = Ask $operator "a@scnehaux.local" $token
    Expect "a person's token is refused" $person.code 401
}

if ($failures -gt 0) {
    Write-Host ""
    Write-Host "$failures check(s) failed"
    exit 1
}
Write-Host ""
Write-Host "account security notifications hold"
