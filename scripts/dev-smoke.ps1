# Exercises a running identity-control end to end.
#
# Each case is a property from the governance documents rather than a happy-path call, so a
# regression shows up as a named failure:
#
#   1. an unauthenticated mutation is refused              EAD-006 8, fail closed
#   2. the probes answer without a credential              an orchestrator cannot authenticate
#   3. a human Principal is created                        TDD-identity-control-001
#   4. a replayed Idempotency-Key returns the same id      STD-GLB-002
#   5. a workload without an owner is refused              accountability is structural
#   6. a workload with an owner is created
#   7. an unknown field is refused                         no client-supplied keycloak_user_id
#   8. a missing Idempotency-Key is refused
#  10. the registration sweep runs and reports    TDD-identity-control-003, Proof B step 4
#   9. clients are registered from desired state  TDD-identity-control-003, Proof B step 5
#
# SECRETS: read from the environment.
#   $env:IDENTITY_CALLER_KEY_FILE = '...'   # the caller's private key, printed by create-kernel-clients.sh
#   $env:IDENTITY_CALLER_PASSWORD = '...'
#
# Usage: pwsh ./scripts/dev-smoke.ps1

$ErrorActionPreference = "Stop"

$api    = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8090" }
$kcBase = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$realm  = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }

foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "$name is required."
    }
}

Add-Type -AssemblyName System.Net.Http

# Authorization Code with PKCE, driven by scripts/dev-token.ps1. The direct access grant this
# used to call is prohibited by STD-IAM-001 3.2 and could not have produced a conformant
# privileged token: auth_time exists only for an authentication ceremony.
. "$PSScriptRoot\dev-token.ps1"
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE

function Decode-Segment($segment) {
    $s = $segment.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))
}

$parts   = $token.Split('.')
$header  = Decode-Segment $parts[0] | ConvertFrom-Json
$payload = Decode-Segment $parts[1] | ConvertFrom-Json

Write-Host "token: alg=$($header.alg) principal_id=$($payload.principal_id) aud=$($payload.aud -join ',') lifetime=$($payload.exp - $payload.iat)s"
if ($header.alg -ne "PS256") { throw "the token is $($header.alg); the verifier permits PS256 only" }

$client = New-Object System.Net.Http.HttpClient

# Invoke-WebRequest raises on a 4xx and its exception does not carry a readable body, which makes
# a problem+json response look empty. HttpClient returns the response either way.
function Send-Json($method, $path, $body, $bearer, $idempotencyKey) {
    $request = New-Object System.Net.Http.HttpRequestMessage($method, "$api$path")
    if ($bearer) {
        $request.Headers.Authorization =
            New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $bearer)
    }
    if ($idempotencyKey) { $request.Headers.Add("Idempotency-Key", $idempotencyKey) }
    if ($body) {
        $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    }
    $response = $client.SendAsync($request).Result
    return @{
        code = [int]$response.StatusCode
        body = $response.Content.ReadAsStringAsync().Result
    }
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

Write-Host ""
Write-Host "1. unauthenticated mutation"
$r = Send-Json "POST" "/v1/principals" '{"username":"nobody","subject_type":"human"}' $null "smoke-unauth"
Expect "refused" $r.code 401

Write-Host ""
Write-Host "2. probes without a credential"
foreach ($probe in @("/healthz", "/readyz")) {
    $p = Send-Json "GET" $probe $null $null $null
    Expect $probe $p.code 200
}

Write-Host ""
Write-Host "3. create a human Principal"
$humanKey  = "smoke-human-0001"
$humanBody = '{"username":"alice.operator","email":"alice@scnehaux.local","subject_type":"human"}'
$first = Send-Json "POST" "/v1/principals" $humanBody $token $humanKey
Expect "created" $first.code 201
Write-Host "        $($first.body)"

Write-Host ""
Write-Host "4. replay the same Idempotency-Key"
$second = Send-Json "POST" "/v1/principals" $humanBody $token $humanKey
Expect "created" $second.code 201
if ($first.code -eq 201 -and $second.code -eq 201) {
    $a = ($first.body | ConvertFrom-Json).principal_id
    $b = ($second.body | ConvertFrom-Json).principal_id
    Expect "identifier is unchanged" $b $a
}

Write-Host ""
Write-Host "5. workload without an owner"
$r = Send-Json "POST" "/v1/principals" '{"username":"svc.reporting","subject_type":"workload"}' $token "smoke-workload-unowned"
Expect "refused" $r.code 400
Write-Host "        $($r.body)"

Write-Host ""
Write-Host "6. workload with an owner"
$owner = $payload.principal_id
$r = Send-Json "POST" "/v1/principals" `
    "{`"username`":`"svc.reporting`",`"subject_type`":`"workload`",`"workload_owner`":`"$owner`"}" `
    $token "smoke-workload-0001"
Expect "created" $r.code 201
Write-Host "        $($r.body)"

Write-Host ""
Write-Host "7. unknown field"
$r = Send-Json "POST" "/v1/principals" `
    '{"username":"bob","subject_type":"human","keycloak_user_id":"injected"}' $token "smoke-unknown-field"
Expect "refused" $r.code 400

Write-Host ""
Write-Host "8. missing Idempotency-Key"
$r = Send-Json "POST" "/v1/principals" '{"username":"carol","subject_type":"human"}' $token $null
Expect "refused" $r.code 400

Write-Host ""
Write-Host "9. register a resource and a public client"
$r = Send-Json "POST" "/v1/registrations" `
    '{"client_key":"smoke-orders","profile":"resource","audience_class":"internal","application_ref":"smoke","lifetime_class":"L1"}' `
    $token "smoke-register-orders"
Expect "resource registered" $r.code 201
$r = Send-Json "POST" "/v1/registrations" `
    '{"client_key":"smoke-web","profile":"public","audience_class":"internal","application_ref":"smoke","audience":["smoke-orders"],"redirect_uris":["http://127.0.0.1:9999/callback"]}' `
    $token "smoke-register-web"
Expect "public client registered" $r.code 201
if ($r.code -eq 201) {
    $web = $r.body | ConvertFrom-Json
    Expect "state" $web.state "active"
    Expect "lifespan derived from L1" $web.access_token_lifespan 540
    $g = Send-Json "GET" "/v1/registrations/$($web.registration_id)" $null $token $null
    Expect "read back" $g.code 200
}
$r = Send-Json "POST" "/v1/registrations" `
    '{"client_key":"identity-control-caller","profile":"public","audience_class":"internal","application_ref":"smoke","redirect_uris":["http://127.0.0.1:8099/callback"]}' `
    $token "smoke-register-taken"
Expect "an unregistered kernel client's key is refused" $r.code 409
$r = Send-Json "POST" "/v1/registrations" `
    '{"client_key":"smoke-wild","profile":"public","audience_class":"internal","application_ref":"smoke","redirect_uris":["https://*.example.com/cb"]}' `
    $token "smoke-register-wild"
Expect "a wildcard redirect is refused" $r.code 400
Write-Host ""
Write-Host "10. the registration sweep is observable"
$r = Send-Json "GET" "/v1/registrations:drift" $null $null $null
Expect "refused without a token" $r.code 401
$r = Send-Json "POST" "/v1/registrations:reconcile" $null $token $null
Expect "a sweep runs on request" $r.code 200
if ($r.code -eq 200) {
    $sweep = $r.body | ConvertFrom-Json
    # deferred is omitted unless true, and the script runs under strict mode, so it is looked up.
    $deferred = $sweep.PSObject.Properties.Name -contains 'deferred'
    $outcome = if ($deferred) { "deferred" } else { $sweep.run.outcome }
    Write-Host "        outcome=$outcome attribution=$($sweep.run.attribution)"
    # Converged: what case 9 registered matches the kernel. Attribution true: the
    # registration credential read the kernel's admin events. Anything else is a wiring fault.
    if (-not $deferred) {
        Expect "the run converged" $sweep.run.outcome "converged"
        Expect "admin events were readable" $sweep.run.attribution $true
    }
}
$r = Send-Json "GET" "/v1/registrations:drift" $null $token $null
Expect "the last run is reported" $r.code 200
if ($r.code -eq 200) {
    Expect "a last run exists" ([bool](($r.body | ConvertFrom-Json).last_run)) $true
}
Write-Host ""
if ($failures -gt 0) {
    Write-Host "$failures case(s) failed."
    exit 1
}
Write-Host "all cases passed."
