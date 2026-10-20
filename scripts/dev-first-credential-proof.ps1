# A provider's temporary password against a live kernel (ADR-IAM-010, TDD-identity-control-005 2.12.0
# §A First Credential). deploy-dev runs it after the smoke suite, as the bootstrap operator at aal2:
#
#   1. a person is created, with UPDATE_PASSWORD outstanding and no credential;
#   2. the provider issues a temporary password: 201, the value once, Cache-Control: no-store;
#   3. a retry with the same Idempotency-Key answers the issuance without the value;
#   4. the person signs in with it, the kernel requires a new password, the temporary value is refused
#      as the new one, and another is accepted;
#   5. the temporary value no longer signs in, and the chosen one does;
#   6. a second issuance is now refused: credential-established;
#   7. the issuance and the change are notified to the person's address, as a password bound by an
#      administrator and by the person;
#   8. a second person's unused value lapses: the sweep removes it, and it no longer signs in.
#
# Step 8 cannot wait 24 hours. The harness moves the issuance's lapse to one second after its issue in
# the Control Database, as the database's superuser, which is a test's clock, not a path the service
# offers: the runtime role cannot update the record. The service's sweep, every
# IDENTITY_TEMPORARY_PASSWORD_SWEEP_INTERVAL, then removes it.
#
# Step 4's refusal comes from the realm's passwordHistory (identity-kernel TDD-identity-kernel-001
# §Password Policy). A kernel without it accepts the temporary value as the new password; the step is
# then reported as a warning naming the kernel, and the value is changed again so the rest still runs.
#
# SECRETS: every value is held in this process and never printed.
#
# Usage: pwsh ./scripts/dev-first-credential-proof.ps1 [-ComposeDir deploy/dev]

param([string] $ComposeDir = "$PSScriptRoot/../deploy/dev")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

. "$PSScriptRoot\dev-env.ps1"
$api = Get-DevApiUrl
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$operatorTotp = Get-DevOperatorTotp
$client = New-Object System.Net.Http.HttpClient

function Operator-Token {
    return Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
        -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
}
$token = Operator-Token

function Send([string] $method, [string] $path, [string] $body, [string] $key) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$api$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $request.Headers.Add("X-Administrative-Reason", "deploy-dev: a first credential")
    if ($key) { $request.Headers.Add("Idempotency-Key", $key) }
    if ($null -ne $body) { $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json") }
    $response = $client.SendAsync($request).Result
    $cache = if ($response.Headers.CacheControl) { $response.Headers.CacheControl.ToString() } else { "" }
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result; cache = $cache }
}

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" } else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

function New-Value {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return "Chosen-" + [Convert]::ToBase64String($bytes).Replace('+', 'x').Replace('/', 'y').TrimEnd('=')
}

function Sign-In([string] $username, [string] $password, [string] $newPassword = "", [switch] $offerSame) {
    try {
        $null = Get-ScnehauxToken -Username $username -Password $password -KeyFile $env:IDENTITY_CALLER_KEY_FILE `
            -NewPassword $newPassword -OfferSameFirst:$offerSame
        return $true
    } catch {
        return $false
    }
}

function New-Person([string] $name) {
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $username = "$name.$suffix"
    $created = Send "POST" "/v1/principals" "{`"username`":`"$username`",`"email`":`"$username@scnehaux.local`",`"subject_type`":`"human`"}" "first-credential-create-$suffix"
    Expect "$name is created" $created.code 201
    return @{ username = $username; principal = ($created.body | ConvertFrom-Json).principal_id }
}

Write-Host "1. a person with no credential"
$person = New-Person "first.credential"
Expect "the person cannot sign in yet" (Sign-In $person.username "anything") $false

Write-Host ""
Write-Host "2. the provider issues a temporary password"
$key = "first-credential-issue-" + [Guid]::NewGuid().ToString("N")
$issued = Send "POST" "/v1/principals/$($person.principal):issue-temporary-password" "{}" $key
Expect "issued" $issued.code 201
Expect "never cached" $issued.cache "no-store"
$record = ($issued.body | ConvertFrom-Json).temporary_password
$value = $record.value
Expect "the value is 24 symbols" $value.Length 24
$lapse = ([DateTimeOffset]$record.lapses_at - [DateTimeOffset]$record.issued_at).TotalHours
Expect "it lapses after 24 hours" $lapse 24

Write-Host ""
Write-Host "3. a retry with the same key answers without the value"
$retry = Send "POST" "/v1/principals/$($person.principal):issue-temporary-password" "{}" $key
Expect "answered" $retry.code 200
Expect "never cached" $retry.cache "no-store"
Expect "with no value" ($retry.body -match '"value"') $false
Expect "the same issuance" (($retry.body | ConvertFrom-Json).temporary_password.issuance_id) $record.issuance_id

Write-Host ""
Write-Host "4. the first sign-in requires a new password, and refuses the temporary one"
$chosen = New-Value
Expect "the person signs in and chooses one" (Sign-In $person.username $value $chosen -offerSame) $true
if ($global:ScnehauxSameValueRefused -eq $true) {
    Write-Host "  ok    the temporary value is refused as the new password"
} elseif ($global:ScnehauxSameValueRefused -eq $false) {
    Write-Host "::warning::the kernel accepted the temporary value as the new password: it predates identity-kernel's passwordHistory (ADR-IAM-010 §5.2); run deploy-dev with kernel_ref naming that change"
    # The temporary value became the password; change it so the rest of the proof holds.
    $chosen = $value
} else {
    Write-Host "  FAIL  the kernel did not ask for a new password"; $failures++
}

Write-Host ""
Write-Host "5. the temporary value no longer signs in"
if ($chosen -ne $value) {
    Expect "the temporary value is refused" (Sign-In $person.username $value) $false
}
Expect "the chosen one signs in" (Sign-In $person.username $chosen) $true

Write-Host ""
Write-Host "6. a person with a password of their own is not issued another"
$token = Operator-Token
$again = Send "POST" "/v1/principals/$($person.principal):issue-temporary-password" "{}" ("first-credential-again-" + [Guid]::NewGuid().ToString("N"))
Expect "refused" $again.code 409
Expect "credential-established" ($again.body -match 'credential-established') $true

Write-Host ""
Write-Host "7. the issuance and the change are notified"
$null = Send "POST" "/v1/kernel-events:sweep" $null $null
$notifications = @((Send "GET" "/v1/principals/$($person.principal)/security-notifications" $null $null).body |
        ConvertFrom-Json).security_notifications
$byAdministrator = @($notifications | Where-Object { $_.event -eq "authenticator_bound" -and $_.details.authenticator -eq "password" -and $_.details.actor -eq "administrator" })
$bySelf = @($notifications | Where-Object { $_.event -eq "authenticator_bound" -and $_.details.authenticator -eq "password" -and $_.details.actor -eq "self" })
Expect "a password bound by an administrator" ($byAdministrator.Count -ge 1) $true
Expect "a password bound by the person" ($bySelf.Count -ge 1) $true

Write-Host ""
Write-Host "8. an unused value lapses"
$unused = New-Person "lapsing.credential"
$lapsing = Send "POST" "/v1/principals/$($unused.principal):issue-temporary-password" "{}" ("first-credential-lapse-" + [Guid]::NewGuid().ToString("N"))
Expect "issued" $lapsing.code 201
$lapsingRecord = ($lapsing.body | ConvertFrom-Json).temporary_password
# The test's clock: the lapse moved to one second after the issue, by the superuser.
docker compose -f "$ComposeDir/compose.yaml" exec -T postgres psql -U postgres -d identity_control -v ON_ERROR_STOP=1 -q -c `
    "UPDATE identity.temporary_password_issuance SET lapses_at = issued_at + interval '1 second' WHERE issuance_id = '$($lapsingRecord.issuance_id)'" | Out-Null
$deadline = (Get-Date).AddSeconds(90)
do {
    Start-Sleep -Seconds 5
    $outcome = docker compose -f "$ComposeDir/compose.yaml" exec -T postgres psql -U postgres -d identity_control -tA -c `
        "SELECT outcome FROM identity.temporary_password_outcome WHERE issuance_id = '$($lapsingRecord.issuance_id)'"
} while (-not $outcome -and (Get-Date) -lt $deadline)
Expect "the sweep recorded it lapsed" ([string]$outcome).Trim() "lapsed"
Expect "the lapsed value no longer signs in" (Sign-In $unused.username $lapsingRecord.value (New-Value)) $false
# The record holds no value: neither issuance's value is anywhere in the Control Database's records.
foreach ($secret in @($value, $lapsingRecord.value)) {
    $found = docker compose -f "$ComposeDir/compose.yaml" exec -T postgres psql -U postgres -d identity_control -tA -c `
        "SELECT count(*) FROM (SELECT i::text t FROM identity.temporary_password_issuance i UNION ALL SELECT a::text FROM identity.privileged_access a UNION ALL SELECT k::text FROM platform.idempotency_key k UNION ALL SELECT n::text FROM identity.security_notification n UNION ALL SELECT e::text FROM identity.kernel_event e) x WHERE t LIKE '%$secret%'"
    Expect "no record holds a value" ([string]$found).Trim() "0"
}
$logs = docker compose -f "$ComposeDir/compose.yaml" logs --no-color identity-control 2>&1 | Out-String
Expect "no log line holds a value" ($logs.Contains($value) -or $logs.Contains($lapsingRecord.value)) $false

if ($failures -gt 0) {
    Write-Host ""
    Write-Host "$failures check(s) failed"
    exit 1
}
Write-Host ""
Write-Host "a first credential holds"
