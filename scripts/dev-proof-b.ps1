# Proof B: drift between registered desired state and live Keycloak is detected, classified,
# reconciled, and shown to converge (identity-control ROADMAP §Proof B, RESPONSE-4 §4).
#
# It runs against a real kernel and the running service, and changes clients the way an
# administrator in the console does: through the Admin API, as the kernel's bootstrap administrator,
# so every change carries the admin event that attributes it.
#
#   1. the reconciler runs on a schedule, and its last run is observable
#   2. an access token lifespan changed in the console is repaired, attributed, with its
#      convergence time recorded
#   3. a redirect URI changed in the console blocks the client, keeps the changed value, and only
#      an operator's reconcile lifts it
#   4. a change covered by a drift exception is left in place until the exception expires, and
#      is then repaired
#   5. a client deleted in the console is held as a finding, not recreated, until an operator's
#      reconcile recreates it: deletion is how a compromised client is contained
#   6. a Principal whose Keycloak user is deleted is reported, not recreated, and an operator's
#      :relink provisions a new user carrying the same principal_id
#  6b. users made in the console are accounted for (TDD-identity-control-001 1.13.0): one with no
#      principal_id is unmapped, one carrying an identifier no mapping holds is an orphan, both
#      disabled under IDENTITY_UNMAPPED_USERS=disable; a second user carrying a Principal's
#      identifier disables both and quarantines the mapping; no service-account user is a finding;
#      deleting the users resolves their findings
#   7. a workload's keys rotate with an overlap and revoke at once, and a key added in the console
#      blocks the client until an operator's reconcile puts back exactly the registered keys; its
#      grants are its last authentication, its owner reviews it, and its client deleted in the
#      console is rebuilt under the same principal_id (TDD-identity-control-004 1.5.0)
#   8. a client created in the console, which no registration describes, is recorded unmanaged and
#      left alone in report mode, and its finding converges once it is gone
#   9. a suspended client stays disabled with its not-before, a console re-enable is repaired, a
#      restore enables it, and a retirement follows a suspension, deletes the client, and frees
#      its client_key (ADR-IAM-001 5.13)
#  10. an unreachable Keycloak is 'unresolved', and the sweep converges once it is back
#
# SECRETS: read from the environment.
#   IDENTITY_CALLER_KEY_FILE, IDENTITY_CALLER_PASSWORD  a provider-scope token, as dev-smoke.ps1
#   KC_BOOTSTRAP_ADMIN_USERNAME, KC_BOOTSTRAP_ADMIN_PASSWORD   the console administrator
#
# KC_BASE_URL is where the login form is served, KC_ADMIN_URL the kernel's private address where
# /admin is reachable, and KERNEL_KEYCLOAK_CONTAINER the container scenario 10 stops. It is for a
# kernel that exists for the length of a CI job. Scenario 10 stops Keycloak: never run it against a
# shared server.
#
# Usage: pwsh ./scripts/dev-proof-b.ps1

$ErrorActionPreference = "Stop"

$api       = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8082" }
$kcAdmin   = if ($env:KC_ADMIN_URL) { $env:KC_ADMIN_URL } else { "http://127.0.0.1:8081" }
$realm     = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
$container = if ($env:KERNEL_KEYCLOAK_CONTAINER) { $env:KERNEL_KEYCLOAK_CONTAINER } else { "scnehaux-identity-dev-keycloak-1" }
$adminUser = if ($env:KC_BOOTSTRAP_ADMIN_USERNAME) { $env:KC_BOOTSTRAP_ADMIN_USERNAME } else { "admin" }

foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD", "KC_BOOTSTRAP_ADMIN_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "$name is required."
    }
}

Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"

$http = New-Object System.Net.Http.HttpClient
$http.Timeout = [TimeSpan]::FromSeconds(60)

$callback = "http://127.0.0.1:9998/callback"
$takeover = "https://attacker.example.net/callback"

# Under strict mode an absent property throws, and the service omits empty fields. A function that`n# returns an empty array returns $null to its caller, so its call sites are wrapped in @().
function Get-Prop($object, [string] $name) {
    if ($null -ne $object -and $object.PSObject.Properties.Name -contains $name) { return $object.$name }
    return $null
}

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

# A provider-scope token lives 240 seconds (L0), so it is renewed well before that.
$script:apiToken = $null
$script:apiTokenAt = [datetime]::MinValue
function Api($method, $path, $body, $headers) {
    if (((Get-Date) - $script:apiTokenAt).TotalSeconds -gt 150) {
        $operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
        $script:apiToken = Get-ScnehauxToken -Username "bootstrap-operator" `
            -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
        $script:apiTokenAt = Get-Date
    }
    return Send $method "$api$path" $body $script:apiToken $headers
}

# The console administrator. Master-realm admin tokens live a minute.
$script:adminToken = $null
$script:adminTokenAt = [datetime]::MinValue
function Admin-Token {
    if (((Get-Date) - $script:adminTokenAt).TotalSeconds -gt 30) {
        $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $form["grant_type"] = "password"
        $form["client_id"] = "admin-cli"
        $form["username"] = $adminUser
        $form["password"] = $env:KC_BOOTSTRAP_ADMIN_PASSWORD
        $response = $http.PostAsync("$kcAdmin/realms/master/protocol/openid-connect/token",
            (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result
        if (-not $response.IsSuccessStatusCode) { throw "the console administrator could not log in: $([int]$response.StatusCode)" }
        $script:adminToken = ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json).access_token
        $script:adminTokenAt = Get-Date
    }
    return $script:adminToken
}

function Kc($method, $path, $body) { return Send $method "$kcAdmin/admin/realms/$realm$path" $body (Admin-Token) $null }

# The administrator's user identifier, which admin events name. Read from the master realm rather
# than from the token: admin-cli's access token carries no sub claim.
function Administrator-ID {
    $users = (Send "GET" "$kcAdmin/admin/realms/master/users?username=$adminUser&exact=true" $null (Admin-Token) $null).json
    foreach ($user in @($users)) { if ($user.username -eq $adminUser) { return $user.id } }
    throw "the console administrator $adminUser was not found in the master realm"
}

# A console change: read the client, change it, write it back.
function Console-Change($clientUuid, [scriptblock] $change) {
    $client = (Kc "GET" "/clients/$clientUuid" $null).json
    & $change $client
    $r = Kc "PUT" "/clients/$clientUuid" ($client | ConvertTo-Json -Depth 20)
    if ($r.code -ne 204) { throw "the console change was refused: $($r.code) $($r.text)" }
}

function Live($clientUuid) { return (Kc "GET" "/clients/$clientUuid" $null).json }

function Lifespan($client) { return [int](Get-Prop $client.attributes "access.token.lifespan") }

# A sweep now. Another replica's, or the schedule's, defers it, and it is asked again.
function Sweep {
    for ($i = 0; $i -lt 30; $i++) {
        $r = Api "POST" "/v1/registrations:reconcile" $null $null
        if ($r.code -eq 200 -and -not (Get-Prop $r.json "deferred")) { return $r.json }
        Start-Sleep -Seconds 2
    }
    throw "no sweep ran within a minute"
}

# The first of a registration's findings the predicate accepts, sweeping until one appears.
function Wait-Finding($registrationId, [scriptblock] $accept, [int] $timeout = 90) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        [void](Sweep)
        $findings = (Api "GET" "/v1/registrations/$registrationId/findings" $null $null).json.findings
        foreach ($f in $findings) { if (& $accept $f) { return $f } }
        Start-Sleep -Seconds 2
    }
    throw "no matching finding within ${timeout}s"
}

function Since($f, [datetimeoffset] $at) {
    $changed = Get-Prop $f "changed_at"
    $detected = [datetimeoffset](Get-Prop $f "detected_at")
    if ($changed) { return ([datetimeoffset]$changed) -ge $at.AddSeconds(-5) }
    return $detected -ge $at.AddSeconds(-5)
}

function Decode-Segment($segment) {
    $t = $segment.Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($t))
}

function Seconds($from, $to) { return [math]::Round((([datetimeoffset]$to) - ([datetimeoffset]$from)).TotalSeconds, 2) }

$failures = 0
$results = New-Object System.Collections.Generic.List[object]
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" }
    else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}
function Record($scenario, $outcome, $evidence) {
    $results.Add([pscustomobject]@{ Scenario = $scenario; Outcome = $outcome; Evidence = $evidence })
}

Write-Host "0. register the proof's client"
$r = Api "POST" "/v1/registrations" '{"client_key":"proofb-orders","profile":"resource","audience_class":"internal","application_ref":"proof-b","lifetime_class":"L1"}' @{ "Idempotency-Key" = "proofb-register-orders" }
Expect "resource registered" $r.code 201
$r = Api "POST" "/v1/registrations" "{`"client_key`":`"proofb-web`",`"profile`":`"public`",`"audience_class`":`"internal`",`"application_ref`":`"proof-b`",`"audience`":[`"proofb-orders`"],`"redirect_uris`":[`"$callback`"]}" @{ "Idempotency-Key" = "proofb-register-web" }
Expect "public client registered" $r.code 201
$registration = $r.json.registration_id
$clientUuid = (Kc "GET" "/clients?clientId=proofb-web&search=false" $null).json[0].id
$actor = Administrator-ID
Write-Host "        registration $registration, client $clientUuid, console administrator $actor"

Write-Host ""
Write-Host "1. the reconciler runs on a schedule"
$before = Get-Prop ((Api "GET" "/v1/registrations:drift" $null $null).json.last_run) "run_id"
$deadline = (Get-Date).AddSeconds(90)
$after = $before
while ((Get-Date) -lt $deadline -and $after -eq $before) {
    Start-Sleep -Seconds 3
    $after = Get-Prop ((Api "GET" "/v1/registrations:drift" $null $null).json.last_run) "run_id"
}
Expect "a scheduled run followed without being asked" ($after -ne $before) $true
Record "Schedule" "a run started unprompted" "last run $before, then $after"

Write-Host ""
Write-Host "2. access token lifespan changed in the console: repaired"
$at = [datetimeoffset]::UtcNow
Console-Change $clientUuid { param($c) $c.attributes."access.token.lifespan" = "3600" }
$f = Wait-Finding $registration { param($f) (Get-Prop $f "field_class") -eq "token_lifespan" -and $f.finding_class -eq "repaired" -and (Get-Prop $f "converged_at") -and (Since $f $at) }
Expect "attributed to the console administrator" (Get-Prop $f "actor") $actor
Expect "lifespan restored" (Lifespan (Live $clientUuid)) 540
$lifespanConvergence = Seconds $f.changed_at $f.converged_at
Expect "converged within 60s of the change" ($lifespanConvergence -lt 60) $true
Record "Lifespan 540 -> 3600 in the console" "repaired, attributed" "converged $lifespanConvergence s after the change"

Write-Host ""
Write-Host "3. redirect URI changed in the console: blocked"
$at = [datetimeoffset]::UtcNow
Console-Change $clientUuid { param($c) $c.redirectUris = @($callback, $takeover) }
$f = Wait-Finding $registration { param($f) (Get-Prop $f "field_class") -eq "redirect_uris" -and $f.finding_class -eq "blocked" -and (Since $f $at) }
$live = Live $clientUuid
Expect "client disabled" $live.enabled $false
Expect "changed URI kept for investigation" ($live.redirectUris -contains $takeover) $true
$blockedAfter = Seconds $f.changed_at $f.detected_at
[void](Sweep)
Expect "a later sweep leaves it blocked" (Live $clientUuid).enabled $false
$r = Api "POST" "/v1/registrations:reconcile" "{`"findings`":[`"$($f.finding_id)`"]}" @{ "X-Administrative-Reason" = "proof-b: takeover URI reviewed and removed" }
Expect "operator's reconcile accepted" $r.code 200
$live = Live $clientUuid
Expect "client re-enabled" $live.enabled $true
Expect "desired URI restored" (($live.redirectUris | Sort-Object) -join ",") $callback
Record "Takeover redirect URI in the console" "blocked, lifted by an operator" "blocked $blockedAfter s after the change"

Write-Host ""
Write-Host "4. a drift exception, then its expiry"
$r = Api "POST" "/v1/registrations/$registration/drift-exceptions" "{`"field_class`":`"token_lifespan`",`"actor`":`"$actor`",`"reason`":`"proof-b: sanctioned change`",`"duration_seconds`":40}" $null
Expect "exception granted" $r.code 201
$expires = [datetimeoffset]$r.json.expires_at
$at = [datetimeoffset]::UtcNow
Console-Change $clientUuid { param($c) $c.attributes."access.token.lifespan" = "900" }
$f = Wait-Finding $registration { param($f) (Get-Prop $f "field_class") -eq "token_lifespan" -and $f.finding_class -eq "sanctioned" -and (Since $f $at) }
[void](Sweep)
Expect "left in place while sanctioned" (Lifespan (Live $clientUuid)) 900
$wait = [math]::Ceiling(($expires - [datetimeoffset]::UtcNow).TotalSeconds) + 2
if ($wait -gt 0) { Start-Sleep -Seconds $wait }
$sanctioned = $f.finding_id
$f = Wait-Finding $registration { param($f) $f.finding_id -eq $sanctioned -and $f.finding_class -eq "repaired" -and (Get-Prop $f "converged_at") }
Expect "repaired once the exception expired" (Lifespan (Live $clientUuid)) 540
Expect "still attributed after its event left the window" (Get-Prop $f "actor") $actor
$afterExpiry = Seconds $expires $f.converged_at
Record "Lifespan change under an exception" "sanctioned, then repaired at expiry" "converged $afterExpiry s after the exception expired"

Write-Host ""
Write-Host "5. a client deleted in the console is held, not recreated"
$at = [datetimeoffset]::UtcNow
Expect "the console administrator deletes the client" (Kc "DELETE" "/clients/$clientUuid" $null).code 204
$f = Wait-Finding $registration { param($f) $f.finding_class -eq "missing" -and (Since $f $at) }
Expect "attributed to the console administrator" (Get-Prop $f "actor") $actor
[void](Sweep)
Expect "a later sweep leaves it deleted" @((Kc "GET" "/clients?clientId=proofb-web&search=false" $null).json).Count 0
$r = Api "POST" "/v1/registrations:reconcile" "{`"findings`":[`"$($f.finding_id)`"]}" @{ "X-Administrative-Reason" = "proof-b: the deletion was reviewed; restore the client" }
Expect "operator's reconcile accepted" $r.code 200
$restored = @((Kc "GET" "/clients?clientId=proofb-web&search=false" $null).json)
Expect "recreated by the operator's reconcile" $restored.Count 1
Expect "as a new client" ($restored[0].id -ne $clientUuid) $true
$closed = @((Api "GET" "/v1/registrations/$registration/findings" $null $null).json.findings | Where-Object { $_.finding_id -eq $f.finding_id })
Expect "the finding closed as recreated" $closed[0].finding_class "recreated"
Record "Client deleted in the console" "held; recreated only by an operator" "no sweep recreated it"
$clientUuid = $restored[0].id

Write-Host "6. portability: a Principal outlives its Keycloak user"
$r = Api "POST" "/v1/principals" '{"username":"proofb.portable","email":"portable@scnehaux.local","subject_type":"human"}' @{ "Idempotency-Key" = "proofb-portable" }
Expect "Principal created" $r.code 201
$principal = $r.json.principal_id
function Users-Carrying($principalId) { return @((Kc "GET" "/users?q=scnehaux_principal_id:$principalId&exact=true" $null).json) }
$original = @(Users-Carrying $principal)[0].id
Expect "the console administrator deletes the user" (Kc "DELETE" "/users/$original" $null).code 204
$r = Api "POST" "/v1/principals:reconcile" $null $null
Expect "the sweep ran" $r.code 200
$listed = @((Api "GET" "/v1/principals:dangling" $null $null).json.dangling | Where-Object { $_.principal_id -eq $principal })
Expect "the mapping is reported dangling" $listed.Count 1
Expect "the sweep recreated nothing" @(Users-Carrying $principal).Count 0
Expect "a relink without a reason is refused" (Api "POST" "/v1/principals/${principal}:relink" $null $null).code 400
$r = Api "POST" "/v1/principals/${principal}:relink" $null @{ "X-Administrative-Reason" = "proof-b: the user was deleted by mistake" }
Expect "relinked" $r.code 200
Expect "active again" (Get-Prop $r.json "state") "active"
$carriers = @(Users-Carrying $principal)
Expect "exactly one user carries the same principal_id" $carriers.Count 1
Expect "and it is a new user" ($carriers[0].id -ne $original) $true
$listed = @((Api "GET" "/v1/principals:dangling" $null $null).json.dangling | Where-Object { $_.principal_id -eq $principal })
Expect "no longer dangling" $listed.Count 0
Expect "a relink while the user exists is refused" (Api "POST" "/v1/principals/${principal}:relink" $null @{ "X-Administrative-Reason" = "again" }).code 409
Record "User deleted in the console" "reported, then relinked by an operator" "same principal_id, new user $($carriers[0].id)"

Write-Host ""
Write-Host "6b. users made in the console are accounted for"
$run6 = [Guid]::NewGuid().ToString("N").Substring(0, 8)
function Console-User($username, $principalId) {
    $user = @{ username = $username; enabled = $true; firstName = "Proof"; lastName = "B"; email = "$username@scnehaux.local" }
    if ($principalId) { $user.attributes = @{ scnehaux_principal_id = @($principalId) } }
    $r = Kc "POST" "/users" ($user | ConvertTo-Json -Compress -Depth 4)
    if ($r.code -ne 201) { throw "the console could not create $username`: $($r.code) $($r.text)" }
    return @((Kc "GET" "/users?username=$username&exact=true" $null).json)[0].id
}
$r = Api "POST" "/v1/principals" "{`"username`":`"proofb.duplicated.$run6`",`"email`":`"duplicated.$run6@scnehaux.local`",`"subject_type`":`"human`"}" @{ "Idempotency-Key" = "proofb-duplicated-$run6" }
Expect "a Principal to duplicate" $r.code 201
$duplicated = $r.json.principal_id
$duplicatedOwn = @(Users-Carrying $duplicated)[0].id
$stray = Console-User "proofb-stray-$run6" $null
$forged = Console-User "proofb-forged-$run6" ([Guid]::NewGuid().ToString())
$copy = Console-User "proofb-copy-$run6" $duplicated
$r = Api "POST" "/v1/principals:reconcile" $null $null
Expect "the sweep ran" $r.code 200
$open = @((Api "GET" "/v1/principals:unmapped" $null $null).json.unmapped)
function Finding-For($username) { return @($open | Where-Object { (Get-Prop $_ "username") -eq $username }) }
Expect "the console user is unmapped" (Finding-For "proofb-stray-$run6")[0].finding_class "unmapped"
Expect "the forged identifier is an orphan" (Finding-For "proofb-forged-$run6")[0].finding_class "orphan"
Expect "the second carrier is a duplicate" (Finding-For "proofb-copy-$run6")[0].finding_class "duplicate"
Expect "naming the Principal" (Get-Prop (Finding-For "proofb-copy-$run6")[0] "principal_id") $duplicated
Expect "no service-account user is a finding" @($open | Where-Object { "$(Get-Prop $_ 'username')" -like "service-account-*" }).Count 0
Expect "the unmapped user is disabled" (Kc "GET" "/users/$stray" $null).json.enabled $false
Expect "the orphan is disabled" (Kc "GET" "/users/$forged" $null).json.enabled $false
Expect "the duplicate is disabled" (Kc "GET" "/users/$copy" $null).json.enabled $false
Expect "and so is the Principal's own user" (Kc "GET" "/users/$duplicatedOwn" $null).json.enabled $false
foreach ($user in @($stray, $forged, $copy)) { [void](Kc "DELETE" "/users/$user" $null) }
[void](Api "POST" "/v1/principals:reconcile" $null $null)
$left = @((Api "GET" "/v1/principals:unmapped" $null $null).json.unmapped | Where-Object { "$(Get-Prop $_ 'username')" -like "proofb-*-$run6" })
Expect "deleting the users resolves their findings" $left.Count 0
Record "Users made in the console" "unmapped, orphan and duplicate recorded and disabled" "resolved once the users were deleted"

Write-Host ""
Write-Host "7. client keys: rotation, revocation, and a key added in the console"
if ($PSVersionTable.PSEdition -ne 'Core') {
    Write-Host "  skip  PowerShell 7 is needed to make PKCS#8 keys for the run"
} else {
    # Keys made for this run. The workload's deployable holds its private keys; here they are temp
    # files, removed at the end. A fresh client_key each run, because a registered key is never
    # registered again.
    $keyFiles = @()
    function New-RunKey([string] $name) {
        $rsa = [System.Security.Cryptography.RSA]::Create(3072)
        try {
            $file = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "$name.pem")
            [System.IO.File]::WriteAllText($file, "-----BEGIN PRIVATE KEY-----`n" +
                [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), [Base64FormattingOptions]::InsertLineBreaks) +
                "`n-----END PRIVATE KEY-----`n")
            $script:keyFiles += $file
            $public = $rsa.ExportParameters($false)
            $n = ConvertTo-Base64Url $public.Modulus
            $e = ConvertTo-Base64Url $public.Exponent
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $kid = ConvertTo-Base64Url ($sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes('{"e":"' + $e + '","kty":"RSA","n":"' + $n + '"}')))
            return @{ file = $file; jwk = @{ kty = "RSA"; n = $n; e = $e }; kid = $kid }
        } finally { $rsa.Dispose() }
    }
    # The token endpoint's answer to a client credentials grant signed with the key: 200 when the
    # kernel accepts the key, anything else when it does not.
    $issuer = Get-RealmIssuer $kcAdmin $realm
    function Token-Status([string] $clientId, $key) {
        $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $form["grant_type"] = "client_credentials"
        $form["client_id"] = $clientId
        $form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        $form["client_assertion"] = New-ClientAssertion -KeyFile $key.file -ClientId $clientId -Audience $issuer
        $response = $http.PostAsync("$kcAdmin/realms/$realm/protocol/openid-connect/token",
            (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result
        return [int]$response.StatusCode
    }
    try {
        $run = [Guid]::NewGuid().ToString("N").Substring(0, 10)
        $job = "proofb-job-$run"
        $a = New-RunKey "$job-a"; $b = New-RunKey "$job-b"; $c = New-RunKey "$job-c"
        $owner = (Decode-Segment $script:apiToken.Split('.')[1] | ConvertFrom-Json).principal_id
        $body = @{ display_name = "Proof B job"; purpose = "Proves client keys rotate, revoke and are guarded"
            workload_type = "job"; owner_principal_id = $owner; client_key = $job; application_ref = "proof-b"
            public_key = $a.jwk } | ConvertTo-Json -Compress -Depth 4
        $r = Api "POST" "/v1/workloads" $body @{ "Idempotency-Key" = "proofb-workload-$run" }
        Expect "workload created with key A" $r.code 201
        $keyRegistration = $r.json.registration_id
        $jobPrincipal = $r.json.principal_id
        $jobUuid = (Kc "GET" "/clients?clientId=$job&search=false" $null).json[0].id
        Expect "key A authenticates" (Token-Status $job $a) 200

        $r = Api "POST" "/v1/registrations/$keyRegistration/keys" (@{ public_key = $b.jwk } | ConvertTo-Json -Compress -Depth 4) $null
        Expect "key B registered, a rotation" $r.code 201
        Expect "during the overlap key A authenticates" (Token-Status $job $a) 200
        Expect "and so does key B" (Token-Status $job $b) 200

        $retiring = @($r.json.keys | Where-Object { $_.state -eq "retiring" })
        Expect "key A is the retiring key" (Get-Prop $retiring[0] "kid") $a.kid
        $r = Api "POST" "/v1/registrations/$keyRegistration/keys/$($retiring[0].key_id):revoke" $null @{ "X-Administrative-Reason" = "proof-b: key A is revoked at once" }
        Expect "key A revoked" $r.code 200
        Expect "key A is refused on the next request" ((Token-Status $job $a) -ne 200) $true
        Expect "key B still authenticates" (Token-Status $job $b) 200

        $at = [datetimeoffset]::UtcNow
        Console-Change $jobUuid { param($cl)
            $cl.attributes."jwks.string" = (@{ keys = @(
                @{ kty = "RSA"; kid = $b.kid; use = "sig"; alg = "PS256"; n = $b.jwk.n; e = $b.jwk.e },
                @{ kty = "RSA"; kid = $c.kid; use = "sig"; alg = "PS256"; n = $c.jwk.n; e = $c.jwk.e }) } | ConvertTo-Json -Compress -Depth 5)
        }
        $f = Wait-Finding $keyRegistration { param($f) (Get-Prop $f "field_class") -eq "client_keys" -and $f.finding_class -eq "blocked" -and (Since $f $at) }
        Expect "attributed to the console administrator" (Get-Prop $f "actor") $actor
        Expect "the client is disabled" (Live $jobUuid).enabled $false
        Expect "the added key does not authenticate" ((Token-Status $job $c) -ne 200) $true
        $keyBlocked = Seconds $f.changed_at $f.detected_at
        $r = Api "POST" "/v1/registrations:reconcile" "{`"findings`":[`"$($f.finding_id)`"]}" @{ "X-Administrative-Reason" = "proof-b: the console key was reviewed and removed" }
        Expect "operator's reconcile accepted" $r.code 200
        Expect "the client is re-enabled" (Live $jobUuid).enabled $true
        $held = ((Live $jobUuid).attributes."jwks.string" | ConvertFrom-Json).keys
        Expect "the JWKS holds exactly the registered key" (@($held | ForEach-Object { $_.kid }) -join ",") $b.kid
        Expect "key B authenticates again" (Token-Status $job $b) 200
        Expect "the console key is refused" ((Token-Status $job $c) -ne 200) $true
        Record "Workload keys: rotate, revoke, console key" "overlap held, revocation at once, console key blocked" "blocked $keyBlocked s after the change"

        # A workload's user is its client's service account, which the user listing may not return:
        # the Principal sweep reads it directly rather than report it dangling (TDD-identity-control-001 1.13.0).
        Expect "the Principal sweep ran" (Api "POST" "/v1/principals:reconcile" $null $null).code 200
        Expect "the workload is not reported dangling" @((Api "GET" "/v1/principals:dangling" $null $null).json.dangling | Where-Object { $_.principal_id -eq $jobPrincipal }).Count 0
        Expect "and still authenticates after the sweep" (Token-Status $job $b) 200

        # TDD-identity-control-004 1.5.0. Its client credentials grants are its last authentication,
        # which the kernel event record writes (TDD-identity-control-007 1.1.0).
        Expect "the kernel event record swept" (Api "POST" "/v1/kernel-events:sweep" $null $null).code 200
        Expect "the workload's last authentication is recorded" ($null -ne (Get-Prop (Api "GET" "/v1/workloads/$jobPrincipal" $null $null).json "last_seen_at")) $true
        $r = Api "POST" "/v1/workloads/${jobPrincipal}:review" $null @{ "X-Administrative-Reason" = "proof-b: still needed, purpose and owner hold" }
        Expect "its owner reviews it" $r.code 200
        Expect "and the review is recorded" ($null -ne (Get-Prop $r.json "last_reviewed_at")) $true
        $r = Api "POST" "/v1/workloads:sweep" $null $null
        Expect "the workload sweep ran" $r.code 200
        Expect "and orphaned nothing" (Get-Prop $r.json "orphaned") 0

        # A workload's client deleted in the console is rebuilt under the same principal_id and keys.
        Expect "a rebuild while the client exists is refused" (Api "POST" "/v1/workloads/${jobPrincipal}:rebuild" $null @{ "X-Administrative-Reason" = "proof-b" }).code 409
        Expect "the console administrator deletes the workload's client" (Kc "DELETE" "/clients/$jobUuid" $null).code 204
        Expect "the deleted client's key no longer authenticates" ((Token-Status $job $b) -ne 200) $true
        $r = Api "POST" "/v1/workloads/${jobPrincipal}:rebuild" $null @{ "X-Administrative-Reason" = "proof-b: its client was deleted in the console" }
        Expect "the workload's client is rebuilt" $r.code 200
        $rebuiltUuid = (Kc "GET" "/clients?clientId=$job&search=false" $null).json[0].id
        Expect "as a new client" ($rebuiltUuid -ne $jobUuid) $true
        Expect "key B authenticates the rebuilt client" (Token-Status $job $b) 200
        Expect "the workload is not reported dangling after the rebuild" @((Api "GET" "/v1/principals:dangling" $null $null).json.dangling | Where-Object { $_.principal_id -eq $jobPrincipal }).Count 0
        $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $form["grant_type"] = "client_credentials"; $form["client_id"] = $job
        $form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        $form["client_assertion"] = New-ClientAssertion -KeyFile $b.file -ClientId $job -Audience $issuer
        $token = ($http.PostAsync("$kcAdmin/realms/$realm/protocol/openid-connect/token",
            (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result.Content.ReadAsStringAsync().Result | ConvertFrom-Json).access_token
        Expect "its token carries the same principal_id" (Decode-Segment $token.Split('.')[1] | ConvertFrom-Json).principal_id $jobPrincipal
        Record "Workload client deleted in the console" "rebuilt by :rebuild" "same principal_id, new client"
    } finally {
        foreach ($file in $keyFiles) { Remove-Item -Force -ErrorAction SilentlyContinue $file }
    }
}

Write-Host ""
Write-Host "8. a client no registration describes"
$at = [datetimeoffset]::UtcNow
$stray = "proofb-stray-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
$r = Kc "POST" "/clients" "{`"clientId`":`"$stray`",`"enabled`":true,`"publicClient`":true,`"redirectUris`":[`"$callback`"]}"
Expect "the console administrator creates a client" $r.code 201
$strayUuid = (Kc "GET" "/clients?clientId=$stray&search=false" $null).json[0].id
$f = $null
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline -and -not $f) {
    [void](Sweep)
    $open = (Api "GET" "/v1/registrations:drift" $null $null).json.findings
    $f = @($open | Where-Object { $_.finding_class -eq "unmanaged" -and $_.client_key -eq $stray })[0]
    if (-not $f) { Start-Sleep -Seconds 2 }
}
Expect "recorded unmanaged" ([bool]$f) $true
if ($f) { Expect "attributed to the console administrator" (Get-Prop $f "actor") $actor }
Expect "left enabled in report mode" (Live $strayUuid).enabled $true
Expect "the console administrator deletes it" (Kc "DELETE" "/clients/$strayUuid" $null).code 204
[void](Sweep)
$open = (Api "GET" "/v1/registrations:drift" $null $null).json.findings
Expect "its finding converged once it was gone" @($open | Where-Object { $_.finding_class -eq "unmanaged" -and $_.client_key -eq $stray }).Count 0
Record "Client created in the console" "recorded unmanaged, left alone in report mode" "converged once deleted"

Write-Host ""
Write-Host "9. suspension, restoration, and retirement"
$life = "proofb-life-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
$r = Api "POST" "/v1/registrations" "{`"client_key`":`"$life`",`"profile`":`"public`",`"audience_class`":`"internal`",`"application_ref`":`"proof-b`",`"redirect_uris`":[`"$callback`"]}" @{ "Idempotency-Key" = "proofb-register-$life" }
Expect "a public client registered" $r.code 201
$lifeRegistration = $r.json.registration_id
$lifeUuid = (Kc "GET" "/clients?clientId=$life&search=false" $null).json[0].id
function Lifecycle($action) {
    return Api "POST" "/v1/registrations/${lifeRegistration}:$action" $null @{ "X-Administrative-Reason" = "proof-b: $action" }
}
$r = Lifecycle "suspend"
Expect "suspended" $r.code 200
Expect "state" (Get-Prop $r.json "state") "suspended"
$client = Live $lifeUuid
$notBefore = [long](Get-Prop $client "notBefore")
Expect "the client is disabled" $client.enabled $false
Expect "the client carries a not-before" ($notBefore -gt 0) $true

$at = [datetimeoffset]::UtcNow
Console-Change $lifeUuid { param($c) $c.enabled = $true; $c.notBefore = 0 }
$f = Wait-Finding $lifeRegistration { param($f) (Get-Prop $f "field_class") -eq "suspension" -and (Since $f $at) }
Expect "a console re-enable is repaired" $f.finding_class "repaired"
Expect "attributed to the console administrator" (Get-Prop $f "actor") $actor
$client = Live $lifeUuid
Expect "disabled again" $client.enabled $false
Expect "with its not-before back" ([long](Get-Prop $client "notBefore")) $notBefore

$r = Lifecycle "restore"
Expect "restored" $r.code 200
Expect "the restored client is enabled" (Live $lifeUuid).enabled $true
Expect "an active client is not retired" (Lifecycle "retire").code 409
Expect "suspended again" (Lifecycle "suspend").code 200
$r = Lifecycle "retire"
Expect "retired" $r.code 200
Expect "state" (Get-Prop $r.json "state") "retired"
Expect "the kernel client is deleted" (Kc "GET" "/clients/$lifeUuid" $null).code 404
$r = Api "POST" "/v1/registrations" "{`"client_key`":`"$life`",`"profile`":`"public`",`"audience_class`":`"internal`",`"application_ref`":`"proof-b`",`"redirect_uris`":[`"$callback`"]}" @{ "Idempotency-Key" = "proofb-reregister-$life" }
Expect "its client_key registers again" $r.code 201
Record "Suspend, restore, retire" "held disabled with its not-before, restored, deleted" "re-enable repaired $(Seconds $at ([datetimeoffset]$f.detected_at)) s after it"

Write-Host ""
Write-Host "10. Keycloak unreachable: unresolved, then converged"
# A fresh token first: none can be issued while the kernel is down, and the service verifies this
# one against the key set it already holds.
$script:apiTokenAt = [datetime]::MinValue
[void](Api "GET" "/v1/registrations:drift" $null $null)
$at = [datetimeoffset]::UtcNow
docker stop $container | Out-Null
$deadline = (Get-Date).AddSeconds(90)
$unresolved = $null
while ((Get-Date) -lt $deadline -and -not $unresolved) {
    [void](Api "POST" "/v1/registrations:reconcile" $null $null)
    $run = (Api "GET" "/v1/registrations:drift" $null $null).json.last_run
    if ((Get-Prop $run "outcome") -eq "unresolved" -and ([datetimeoffset]$run.started_at) -ge $at) { $unresolved = $run }
    else { Start-Sleep -Seconds 2 }
}
Expect "a sweep against a stopped kernel is unresolved" ([bool]$unresolved) $true
docker start $container | Out-Null
$back = $false
for ($i = 0; $i -lt 90 -and -not $back; $i++) {
    try { $back = (Send "GET" "$kcAdmin/realms/$realm/.well-known/openid-configuration" $null $null $null).code -eq 200 } catch { $back = $false }
    if (-not $back) { Start-Sleep -Seconds 2 }
}
Expect "Keycloak is back" $back $true
$restarted = [datetimeoffset]::UtcNow
$run = $null
for ($i = 0; $i -lt 30; $i++) {
    $run = (Sweep).run
    if ($run.outcome -eq "converged") { break }
    Start-Sleep -Seconds 2
}
Expect "the first sweeps after it returns converge" $run.outcome "converged"
Expect "with attribution" $run.attribution $true
$recovered = Seconds $restarted ([datetimeoffset]$run.finished_at)
Record "Keycloak stopped" "unresolved while down, converged after" "converged $recovered s after it answered again"

Write-Host ""
$summary = @("## Proof B · Keycloak drift", "", "| Scenario | Outcome | Evidence |", "| :-- | :-- | :-- |")
foreach ($row in $results) { $summary += "| $($row.Scenario) | $($row.Outcome) | $($row.Evidence) |" }
$summary | ForEach-Object { Write-Host $_ }
if ($env:GITHUB_STEP_SUMMARY) { $summary | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8 }

if ($failures -gt 0) {
    Write-Host "$failures check(s) failed."
    exit 1
}
Write-Host "Proof B holds."
