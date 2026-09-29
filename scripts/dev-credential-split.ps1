# Asserts that the two Admin API credentials hold what their designs say, and nothing else.
#
#   identity-control               users only (TDD-identity-control-001). It cannot read or change a
#                                  client, and cannot read admin events.
#   identity-control-registration  clients and admin events only (TDD-identity-control-003). It
#                                  cannot read or create a user.
#
# Split, one leaked key cannot both mint a Principal and register a client that redirects its
# tokens. A role added to either service account by hand would join the two again, so each
# refusal is asserted rather than assumed.
#
# SECRETS: read from the environment.
#   $env:IDENTITY_KEYCLOAK_CLIENT_KEY_FILE              = '...'   # each client's private key
#   $env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE = '...'
#
# KC_ADMIN_URL is the kernel's private address, where /admin is reachable.
#
# Usage: pwsh ./scripts/dev-credential-split.ps1

$ErrorActionPreference = "Stop"

$kcBase = if ($env:KC_ADMIN_URL) { $env:KC_ADMIN_URL } else { "http://127.0.0.1:8081" }
$realm  = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }

foreach ($name in @("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "$name is required."
    }
}

. "$PSScriptRoot\client-assertion.ps1"
Add-Type -AssemblyName System.Net.Http
$client = New-Object System.Net.Http.HttpClient
$issuer = Get-RealmIssuer $kcBase $realm

function Get-ServiceToken($clientId, $keyFile) {
    $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $form["grant_type"] = "client_credentials"
    $form["client_id"] = $clientId
    $form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    $form["client_assertion"] = New-ClientAssertion -KeyFile $keyFile -ClientId $clientId -Audience $issuer
    $response = $client.PostAsync("$kcBase/realms/$realm/protocol/openid-connect/token",
        (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result
    if (-not $response.IsSuccessStatusCode) {
        throw "$clientId could not obtain a token: $([int]$response.StatusCode) $($response.Content.ReadAsStringAsync().Result)"
    }
    return ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json).access_token
}

function Get-Status($method, $path, $bearer, $body) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$kcBase/admin/realms/$realm$path")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $bearer)
    if ($null -ne $body) {
        $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    }
    return [int]$client.SendAsync($request).Result.StatusCode
}

$failures = @()
function Expect($name, $want, $got) {
    if ($got -eq $want) {
        Write-Host "ok    $name ($got)"
    } else {
        Write-Host "FAIL  $name (got $got, want $want)"
        $script:failures += $name
    }
}

$users = Get-ServiceToken "identity-control" $env:IDENTITY_KEYCLOAK_CLIENT_KEY_FILE
$registration = Get-ServiceToken "identity-control-registration" $env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE

# A probe body that no successful call would leave behind: each is expected to be refused before it
# is read. A POST that did succeed would be the failure itself, and its object is left for the
# stack logs to show.
$probeClient = '{"clientId":"credential-split-probe","enabled":false}'
$probeUser = '{"username":"credential-split-probe","enabled":false}'

Expect "registration reads clients"          200 (Get-Status Get "/clients?max=1" $registration)
Expect "registration reads admin events"     200 (Get-Status Get "/admin-events?max=1" $registration)
Expect "registration cannot read users"      403 (Get-Status Get "/users?max=1" $registration)
Expect "registration cannot create a user"   403 (Get-Status Post "/users" $registration $probeUser)

Expect "users path reads users"              200 (Get-Status Get "/users?max=1" $users)
Expect "users path cannot read clients"      403 (Get-Status Get "/clients?max=1" $users)
Expect "users path cannot create a client"   403 (Get-Status Post "/clients" $users $probeClient)
Expect "users path cannot read admin events" 403 (Get-Status Get "/admin-events?max=1" $users)

if ($failures.Count -gt 0) {
    throw "the credential split does not hold: $($failures -join '; ')"
}
Write-Host "the two Admin API credentials are split as designed"
