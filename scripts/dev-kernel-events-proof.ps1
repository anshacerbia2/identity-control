# Proves the kernel event record against a live kernel (TDD-identity-control-007): deploy-dev runs it
# after the smoke suite, whose sign-ins and registrations left user and admin events in the kernel's
# native store.
#
#   1. a sweep reads both kinds and records them;
#   2. a second sweep reads them again, in the overlap, and records nothing new.
#
# SECRETS: read from the environment, as dev-smoke.ps1 reads them.
#
# Usage: pwsh ./scripts/dev-kernel-events-proof.ps1

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$api = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8090" }
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
$client = New-Object System.Net.Http.HttpClient

function Sweep {
    $request = New-Object System.Net.Http.HttpRequestMessage("POST", "$api/v1/kernel-events:sweep")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $response = $client.SendAsync($request).Result
    $body = $response.Content.ReadAsStringAsync().Result
    if ([int]$response.StatusCode -ne 200) { throw "the sweep answered $([int]$response.StatusCode): $body" }
    $kinds = @{}
    foreach ($kind in ($body | ConvertFrom-Json).kinds) { $kinds[$kind.kind] = $kind }
    return $kinds
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

Write-Host "1. a sweep records the kernel's user and admin events"
$first = Sweep
foreach ($kind in @("user", "admin")) {
    Write-Host "        $kind read=$($first[$kind].read) recorded=$($first[$kind].recorded) truncated=$($first[$kind].truncated)"
    Expect "$kind events recorded" ($first[$kind].recorded -gt 0) $true
    Expect "$kind read whole" $first[$kind].truncated $false
}

Write-Host ""
Write-Host "2. a second sweep reads them again and records nothing new"
$second = Sweep
foreach ($kind in @("user", "admin")) {
    Write-Host "        $kind read=$($second[$kind].read) recorded=$($second[$kind].recorded)"
    Expect "$kind read again in the overlap" ($second[$kind].read -ge $first[$kind].recorded) $true
    Expect "$kind recorded nothing new" $second[$kind].recorded 0
}

if ($failures -gt 0) {
    Write-Host ""
    Write-Host "$failures check(s) failed"
    exit 1
}
Write-Host ""
Write-Host "the kernel event record holds"
