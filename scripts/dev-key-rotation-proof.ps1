# Proves a rotation of one of this service's Keycloak Admin API credentials, after
# deploy/dev/rotate-client-key.sh ran with ROTATE_KEEP_PREVIOUS set (ROADMAP §Gates, Production gate:
# "Keycloak administration credential rotation rehearsed"):
#
#   1. the kernel issues the client a token for an assertion signed with the new key;
#   2. it refuses one signed with the previous key, as invalid_client;
#   3. the restarted service reaches the kernel with the credential: identity-control enumerates the
#      kernel's users on POST /v1/principals:reconcile, and identity-control-registration's sweep on
#      POST /v1/registrations:reconcile ends converged, not unresolved.
#
# SECRETS: the two key files, and a provider-scope token's, as dev-smoke.ps1 reads them. None is printed.
#
# Usage: pwsh ./scripts/dev-key-rotation-proof.ps1 -Client identity-control `
#            -KeyFile deploy/dev/keys/identity-control.pem -PreviousKeyFile deploy/dev/keys/identity-control-previous.pem

param(
    [Parameter(Mandatory = $true)] [ValidateSet("identity-control", "identity-control-registration")] [string] $Client,
    [Parameter(Mandatory = $true)] [string] $KeyFile,
    [Parameter(Mandatory = $true)] [string] $PreviousKeyFile
)

$ErrorActionPreference = "Stop"

$api    = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8082" }
$kcBase = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$realm  = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }

Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"

$http = New-Object System.Net.Http.HttpClient
$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" }
    else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

$issuer = Get-RealmIssuer $kcBase $realm
function Client-Token([string] $key) {
    $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $form["grant_type"] = "client_credentials"
    $form["client_id"] = $Client
    $form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    $form["client_assertion"] = New-ClientAssertion -KeyFile $key -ClientId $Client -Audience $issuer
    $response = $http.PostAsync("$kcBase/realms/$realm/protocol/openid-connect/token",
        (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result
    $err = try { ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json).error } catch { "" }
    return @{ code = [int]$response.StatusCode; error = $err }
}

Write-Host "$Client, after its rotation"
$r = Client-Token $KeyFile
Expect "the new key is accepted" $r.code 200
$r = Client-Token $PreviousKeyFile
Expect "the previous key is refused" $r.code 401
Expect "as invalid_client" $r.error "invalid_client"

$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$token = Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
    -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
function Post([string] $path) {
    $request = New-Object System.Net.Http.HttpRequestMessage("POST", "$api$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $response = $http.SendAsync($request).Result
    $text = $response.Content.ReadAsStringAsync().Result
    $json = $null
    if ($text) { try { $json = $text | ConvertFrom-Json } catch { $json = $null } }
    return @{ code = [int]$response.StatusCode; json = $json; text = $text }
}

if ($Client -eq "identity-control") {
    $r = Post "/v1/principals:reconcile"
    Expect "the service enumerates the kernel's users with the new key" $r.code 200
    if ($r.code -ne 200) { Write-Host "        $($r.text)" }
} else {
    # A sweep the schedule or another replica holds is deferred, and asked again.
    $run = $null
    for ($i = 0; $i -lt 30; $i++) {
        $r = Post "/v1/registrations:reconcile"
        if ($r.code -eq 200 -and -not ($r.json.PSObject.Properties.Name -contains 'deferred' -and $r.json.deferred)) {
            $run = $r.json.run
            break
        }
        Start-Sleep -Seconds 2
    }
    Expect "a registration sweep ran" ($null -ne $run) $true
    if ($null -ne $run) {
        Expect "and reached the kernel with the new key" ($run.outcome -ne "unresolved") $true
        Write-Host "        sweep outcome: $($run.outcome)"
    }
}

Write-Host ""
if ($failures -gt 0) { Write-Host "$failures check(s) failed."; exit 1 }
Write-Host "$Client rotated, and the previous key no longer works."
