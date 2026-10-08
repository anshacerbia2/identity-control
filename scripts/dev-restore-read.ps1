# The restore drill's read of known data (scripts/dev-restore-drill.sh, STD-GLB-002 §Restore
# Evidence): one page of registrations through the API, as the bootstrap operator, written to -Out as
# the service answered it. The drill reads before the backup and again on the restored database, and
# requires the two answers to be identical. A page with no registration is refused: there would be
# nothing to compare.
#
# SECRETS: read from the environment, as dev-smoke.ps1 reads them. Nothing is printed but the count.
#
# Usage: pwsh ./scripts/dev-restore-read.ps1 -Out read.json

param(
    [Parameter(Mandatory = $true)] [string] $Out
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
$request = New-Object System.Net.Http.HttpRequestMessage("GET", "$api/v1/registrations?limit=100")
$request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
$request.Headers.Add("X-Administrative-Reason", "deploy-dev: the restore drill")
$response = $client.SendAsync($request).Result
$body = $response.Content.ReadAsStringAsync().Result
if ([int]$response.StatusCode -ne 200) {
    throw "GET /v1/registrations answered $([int]$response.StatusCode): $body"
}
$count = @(($body | ConvertFrom-Json).registrations).Count
if ($count -eq 0) { throw "GET /v1/registrations read no registration; the drill would compare nothing" }
Set-Content -NoNewline -Path $Out -Value $body
Write-Host "  read $count registrations"
