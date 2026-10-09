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
#   6. a workload is refused on the Principal path         its identity lives on its client's service account
#   7. an unknown field is refused                         no client-supplied keycloak_user_id
#   8. a missing Idempotency-Key is refused
#  9b. the development caller is adopted          ADR-IAM-001 5.12, TDD-identity-control-003 Adoption
#  10. the registration sweep runs and reports    TDD-identity-control-003, Proof B step 4
#   9. clients are registered from desired state  TDD-identity-control-003, Proof B step 5
#      and a resource's lifetime class moves its caller's lifespan          ADR-IAM-003 5.9
#  11. a workload is created, and its own token names it    TDD-identity-control-004
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
# Every provider route requires aal2 (ADR-IAM-004). With IDENTITY_OPERATOR_TOTP_FILE set, as the CI stack
# sets it, the operator's TOTP is enrolled into that file on first use and read from it after.
$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp

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
Write-Host "6. a workload on the Principal path"
# A user created through POST /users is not the one a client credentials token is issued for, so a
# workload made here would carry its identity into no token. Workloads go through /v1/workloads.
$owner = $payload.principal_id
$r = Send-Json "POST" "/v1/principals" `
    "{`"username`":`"svc.reporting`",`"subject_type`":`"workload`",`"workload_owner`":`"$owner`"}" `
    $token "smoke-workload-principal-path"
Expect "refused" $r.code 400
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
$orders = if ($r.code -eq 201) { $r.body | ConvertFrom-Json } else { $null }
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

    # A lifetime-class change against the real kernel (ADR-IAM-003 5.9, TDD-identity-control-003
    # 1.37.0): the apply moves the caller's lifespan with its resource's class, which step 10's sweep
    # then finds as the classes derive it. It toggles, so a rerun on a long-lived server changes it
    # back rather than proposing the registered class again.
    function Send-ChangeOf($registrationId, $body, $key) {
        $change = New-Object System.Net.Http.HttpRequestMessage("POST", "$api/v1/registrations/$registrationId/changes")
        $change.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
        $change.Headers.Add("X-Administrative-Reason", "smoke: a lifetime-class change reaches the kernel")
        $change.Headers.Add("Idempotency-Key", $key)
        $change.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
        $sent = $client.SendAsync($change).Result
        return @{ code = [int]$sent.StatusCode; body = $sent.Content.ReadAsStringAsync().Result }
    }
    if ($orders) {
        $resource = (Send-Json "GET" "/v1/registrations/$($orders.registration_id)" $null $token $null).body | ConvertFrom-Json
        $nextClass = if ($resource.lifetime_class -eq "L1") { "L0" } else { "L1" }
        $lifetime = Send-ChangeOf $orders.registration_id `
            "{`"lifetime_class`":`"$nextClass`",`"expected_version`":$($resource.version)}" `
            "smoke-lifetime-change-$([Guid]::NewGuid().ToString('N'))"
        Expect "lifetime-class change applied" $lifetime.code 201
        if ($lifetime.code -ne 201) { Write-Host "        $($lifetime.body)" }
        $caller = (Send-Json "GET" "/v1/registrations/$($web.registration_id)" $null $token $null).body | ConvertFrom-Json
        if (@($caller.audience) -contains "smoke-orders") {
            Expect "the caller's lifespan follows the class" $caller.access_token_lifespan $(if ($nextClass -eq "L0") { 240 } else { 540 })
        }
        $g = Send-Json "GET" "/v1/registrations/$($web.registration_id)" $null $token $null
    }

    # An audience change against the real kernel (TDD-identity-control-003 Registration Changes):
    # the apply rewrites the client's audience mappers, which only the fake was checked against
    # before. It toggles, so a rerun on a long-lived server changes it back rather than proposing
    # the registered audience again.
    $current = $g.body | ConvertFrom-Json
    # @(...) around the if: PowerShell unrolls a branch's array, so a bare if yields $null or a lone
    # string rather than an array.
    $next = @(if (@($current.audience) -notcontains "smoke-orders") { "smoke-orders" })
    $audienceJson = if ($next.Count -eq 0) { "[]" } else { "[`"" + ($next -join "`",`"") + "`"]" }
    $changeBody = "{`"audience`":$audienceJson,`"expected_version`":$($current.version)}"
    $changeKey = "smoke-audience-change-$([Guid]::NewGuid().ToString('N'))"
    function Send-Change($key) {
        $change = New-Object System.Net.Http.HttpRequestMessage("POST", "$api/v1/registrations/$($web.registration_id)/changes")
        $change.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
        $change.Headers.Add("X-Administrative-Reason", "smoke: an audience change reaches the kernel")
        if ($key) { $change.Headers.Add("Idempotency-Key", $key) }
        $change.Content = New-Object System.Net.Http.StringContent($changeBody, [System.Text.Encoding]::UTF8, "application/json")
        $sent = $client.SendAsync($change).Result
        return @{ code = [int]$sent.StatusCode; body = $sent.Content.ReadAsStringAsync().Result }
    }
    # STD-GLB-001 1.4.0: a command without a key is refused before it is read.
    Expect "an audience change without an Idempotency-Key is refused" (Send-Change $null).code 400
    $answer = Send-Change $changeKey
    Expect "audience change applied" $answer.code 201
    if ($answer.code -ne 201) { Write-Host "        $($answer.body)" }
    # The retry is answered from its key. Run again, the change would be refused: its
    # expected_version is no longer the registration's.
    $retried = Send-Change $changeKey
    Expect "its retry with the same key is answered the first response" $retried.code 201
    $firstId = if ($answer.code -eq 201) { ($answer.body | ConvertFrom-Json).change_id } else { "" }
    $retriedId = if ($retried.code -eq 201) { ($retried.body | ConvertFrom-Json).change_id } else { "-" }
    Expect "the same change" ($retriedId -eq $firstId -and $firstId) $true
    $after = (Send-Json "GET" "/v1/registrations/$($web.registration_id)" $null $token $null).body | ConvertFrom-Json
    Expect "audience written" ((@($after.audience) -join ",")) ($next -join ",")
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
Write-Host "9b. adopt the development caller"
# identity-control-caller is created by create-kernel-clients.sh before this service can register it,
# so it is adopted: a plan first, then the adoption, held to the key it already authenticates with. Its
# declared audience is identity-control-api, the resource the ceremony registered and its audience
# mapper names; an L0 resource derives its 240 seconds.
$callerRsa = Read-ClientKey $env:IDENTITY_CALLER_KEY_FILE
try {
    $callerPublic = $callerRsa.ExportParameters($false)
    $callerJwk = @{ kty = "RSA"; n = (ConvertTo-Base64Url $callerPublic.Modulus); e = (ConvertTo-Base64Url $callerPublic.Exponent) }
} finally { $callerRsa.Dispose() }
$declaration = @{ client_key = "identity-control-caller"; profile = "confidential"; audience_class = "privileged"
    application_ref = "identity-control-dev"; redirect_uris = @("http://127.0.0.1:8099/callback"); public_keys = @($callerJwk)
    audience = @("identity-control-api")
    # The script made the caller before the token profile: no at+jwt attribute, no client_id mapper, and
    # the realm's scopes rather than its own. Both converge as part of the adoption.
    converge = @("token_format", "audience_scope") }
$reasonHeader = "smoke: the development caller comes under registration"
function Send-Adopt($body, $idempotencyKey) {
    $request = New-Object System.Net.Http.HttpRequestMessage("POST", "$api/v1/registrations:adopt")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $request.Headers.Add("X-Administrative-Reason", $reasonHeader)
    if ($idempotencyKey) { $request.Headers.Add("Idempotency-Key", $idempotencyKey) }
    $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    $response = $client.SendAsync($request).Result
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result }
}
$plan = Send-Adopt (($declaration + @{ dry_run = $true }) | ConvertTo-Json -Compress -Depth 5) $null
if ($plan.code -eq 409) {
    # A second run on the same server: the caller is registered already.
    Write-Host "        already registered"
} else {
    Expect "planned" $plan.code 200
    if ($plan.code -eq 200) {
        Expect "adoptable as declared" ($plan.body | ConvertFrom-Json).plan.adoptable $true
        $r = Send-Adopt ($declaration | ConvertTo-Json -Compress -Depth 5) "smoke-adopt-caller"
        Expect "adopted" $r.code 201
    }
}

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
Write-Host "11. a workload, end to end"
# The workload's deployable holds its private key; here that is a key made for this run. The smoke
# then authenticates as the workload with it and reads its own token: principal_id, subject_type and
# workload_owner come from the client's service-account user, and acr is absent (STD-IAM-002 3.2).
# A fresh key and client_key each run, because a registered key is never registered again.
if ($PSVersionTable.PSEdition -ne 'Core') {
    Write-Host "  skip  PowerShell 7 is needed to make a PKCS#8 key for the run"
} else {
    $run = [Guid]::NewGuid().ToString("N").Substring(0, 12)
    $workloadClient = "smoke-job-$run"
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    $keyFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "$workloadClient.pem")
    try {
        $pem = "-----BEGIN PRIVATE KEY-----`n" +
            [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), [Base64FormattingOptions]::InsertLineBreaks) +
            "`n-----END PRIVATE KEY-----`n"
        [System.IO.File]::WriteAllText($keyFile, $pem)
        $public = $rsa.ExportParameters($false)
        $jwk = @{ kty = "RSA"; n = (ConvertTo-Base64Url $public.Modulus); e = (ConvertTo-Base64Url $public.Exponent) }
        $body = @{
            display_name = "Smoke job"; purpose = "Proves a workload authenticates as itself"; workload_type = "job"
            owner_principal_id = $owner; client_key = $workloadClient; application_ref = "smoke"; public_key = $jwk
        } | ConvertTo-Json -Compress -Depth 4
        $r = Send-Json "POST" "/v1/workloads" $body $token "smoke-workload-$run"
        Expect "created" $r.code 201
        if ($r.code -eq 201) {
            $created = $r.body | ConvertFrom-Json
            Expect "state" $created.state "active"
            Expect "owner" $created.owner_principal_id $owner

            $issuer = Get-RealmIssuer $kcBase $realm
            $assertion = New-ClientAssertion -KeyFile $keyFile -ClientId $workloadClient -Audience $issuer
            $grant = Invoke-RestMethod -Method Post -Uri "$kcBase/realms/$realm/protocol/openid-connect/token" -Body @{
                grant_type = "client_credentials"; client_id = $workloadClient
                client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                client_assertion = $assertion
            }
            $claims = Decode-Segment $grant.access_token.Split('.')[1] | ConvertFrom-Json
            Expect "principal_id" $claims.principal_id $created.principal_id
            Expect "subject_type" $claims.subject_type "workload"
            Expect "workload_owner" $claims.workload_owner $owner
            Expect "no acr" ($claims.PSObject.Properties.Name -contains 'acr') $false
            Expect "no refresh token" ($grant.PSObject.Properties.Name -contains 'refresh_token') $false
        }
    } finally {
        $rsa.Dispose()
        Remove-Item -Force -ErrorAction SilentlyContinue $keyFile
    }
}

Write-Host ""
if ($failures -gt 0) {
    Write-Host "$failures case(s) failed."
    exit 1
}
Write-Host "all cases passed."
