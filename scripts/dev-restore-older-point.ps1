# The restore drill's older point (TDD-identity-control-001 1.18.0 §Restore Evidence,
# docs/runbooks/control-database-restore.md §After a restore to an older point). scripts/dev-restore-drill.sh
# runs it in three phases around its backup, so the Control Database it restores is older than the
# kernel, as a real restore is, and the reconciliation the runbook prescribes is carried out and checked:
#
#   before        with the service up, before the backup: a resource, a public client and a Principal
#                 registered, and a Tenant activated and converged;
#   after-backup  with the service up again, after the backup: a Principal created, a confidential
#                 client registered, the public client's redirect URIs changed, the Principal
#                 suspended, and a Membership granted in the Tenant; each reaches the kernel;
#   reconcile     on the restored database, started in report mode as the runbook's step 7 says: what
#                 the service sees of each change, then the runbook's reconciliation, then the result.
#
# What the runbook prescribes, case by case:
#   a client registered after the backup   unmanaged; adopted, which converges its finding
#   a registration changed after it        redirect_uris blocks the client; the operator applies the
#                                          restored state, then repeats the change through the API
#   a security command after it            the record is gone and the kernel keeps the effect; the
#                                          command is repeated so the record exists again
#   a Membership granted after it          the sweep takes the member out of the Organization as an
#                                          extra member; Organization Control's repair restores it,
#                                          delivered here as its dispatcher would (the Tenant proof's
#                                          delivering workload stands in, as scripts/dev-tenant-proof.ps1)
#   a Principal created after it           an orphan, recorded and left enabled in report; no route binds
#                                          its identifier again, which the evidence records as a gap
#
# The reconcile phase writes older-point-evidence.json beside the state file. It changes a kernel that
# lives for one CI job, never a shared server.
#
# Environment: as scripts/dev-tenant-proof.ps1 (IDENTITY_API_URL, KC_BASE_URL, KC_ADMIN_URL,
# KC_BOOTSTRAP_ADMIN_USERNAME, KC_BOOTSTRAP_ADMIN_PASSWORD, IDENTITY_CALLER_KEY_FILE,
# IDENTITY_CALLER_PASSWORD, IDENTITY_OPERATOR_TOTP_FILE), and -TenantState, the Tenant proof's state
# file, for its delivering workload.
#
#   pwsh ./scripts/dev-restore-older-point.ps1 -Phase before -State <file> -TenantState <file>

param(
    [Parameter(Mandatory = $true)] [ValidateSet("before", "after-backup", "reconcile")] [string] $Phase,
    [Parameter(Mandatory = $true)] [string] $State,
    [Parameter(Mandatory = $true)] [string] $TenantState
)

$ErrorActionPreference = "Stop"

$api     = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8082" }
$kcBase  = if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }
$kcAdmin = if ($env:KC_ADMIN_URL) { $env:KC_ADMIN_URL } else { "http://127.0.0.1:8080" }
$realm   = if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }
$adminUser = if ($env:KC_BOOTSTRAP_ADMIN_USERNAME) { $env:KC_BOOTSTRAP_ADMIN_USERNAME } else { "admin" }
foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD", "KC_BOOTSTRAP_ADMIN_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "$name is required." }
}
if ($PSVersionTable.PSEdition -ne 'Core') { throw "PowerShell 7 is needed to make a PKCS#8 key for the run" }

Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$http = New-Object System.Net.Http.HttpClient
$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }

$failures = 0
function Expect($label, $got, $want) {
    if ($got -eq $want) { Write-Host "  ok    $label ($got)" }
    else { Write-Host "  FAIL  $label (got $got, want $want)"; $script:failures++ }
}

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
    # Every command carries an Idempotency-Key (STD-GLB-001 1.4.0), one per call; a sweep ignores it.
    if ($method -eq "POST" -and $url.StartsWith($api) -and -not ($headers -and $headers.ContainsKey("Idempotency-Key"))) {
        $request.Headers.Add("Idempotency-Key", [Guid]::NewGuid().ToString())
    }
    if ($null -ne $body) {
        $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    }
    $response = $http.SendAsync($request).Result
    $text = $response.Content.ReadAsStringAsync().Result
    $json = $null
    if ($text) { try { $json = $text | ConvertFrom-Json } catch { $json = $null } }
    return @{ code = [int]$response.StatusCode; json = $json; text = $text }
}

# The bootstrap operator's provider token, renewed well inside its lifetime and the step-up age.
$script:apiToken = $null
$script:apiTokenAt = [datetime]::MinValue
function Api($method, $path, $body, $headers) {
    if (((Get-Date) - $script:apiTokenAt).TotalSeconds -gt 150) {
        $script:apiToken = Get-ScnehauxToken -Username "bootstrap-operator" `
            -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp
        $script:apiTokenAt = Get-Date
    }
    return Send $method "$api$path" $body $script:apiToken $headers
}

function Reason([string] $why) { return @{ "X-Administrative-Reason" = "restore drill: $why" } }

# Kc reads the kernel as its console administrator. Master-realm admin tokens live a minute.
$script:adminToken = $null
$script:adminTokenAt = [datetime]::MinValue
function Kc([string] $path) {
    if (((Get-Date) - $script:adminTokenAt).TotalSeconds -gt 30) {
        $form = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $form["grant_type"] = "password"; $form["client_id"] = "admin-cli"
        $form["username"] = $adminUser; $form["password"] = $env:KC_BOOTSTRAP_ADMIN_PASSWORD
        $response = $http.PostAsync("$kcAdmin/realms/master/protocol/openid-connect/token",
            (New-Object System.Net.Http.FormUrlEncodedContent($form))).Result
        if (-not $response.IsSuccessStatusCode) { throw "the console administrator could not log in: $([int]$response.StatusCode)" }
        $script:adminToken = ($response.Content.ReadAsStringAsync().Result | ConvertFrom-Json).access_token
        $script:adminTokenAt = Get-Date
    }
    $r = Send "GET" "$kcAdmin/admin/realms/$realm$path" $null $script:adminToken $null
    if ($r.code -ne 200) { throw "the kernel answered $($r.code) to GET $path" }
    return $r.json
}

function Client-Of([string] $clientKey) { return @(Kc "/clients?clientId=$clientKey&search=false")[0] }
function Members-Of([string] $tenant) {
    $org = @(Kc "/organizations?search=$tenant&exact=true" | Where-Object { $_.name -eq $tenant })
    if ($org.Count -ne 1) { return @() }
    return @(Kc "/organizations/$($org[0].id)/members?first=0&max=1000" | ForEach-Object { $_.id })
}

# New-UuidV7 is an RFC 9562 version 7 identifier, as an envelope's id is.
function New-UuidV7 {
    $bytes = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    for ($i = 5; $i -ge 0; $i--) { $bytes[$i] = [byte]($ms -band 0xff); $ms = $ms -shr 8 }
    $bytes[6] = ($bytes[6] -band 0x0f) -bor 0x70
    $bytes[8] = ($bytes[8] -band 0x3f) -bor 0x80
    $hex = -join ($bytes | ForEach-Object { $_.ToString("x2") })
    return "$($hex.Substring(0,8))-$($hex.Substring(8,4))-$($hex.Substring(12,4))-$($hex.Substring(16,4))-$($hex.Substring(20,12))"
}

# Deliver posts one event to /v1/deliveries as Organization Control's dispatcher does, as the Tenant
# proof's delivering workload.
$tenantProof = Get-Content -Raw $TenantState | ConvertFrom-Json
$issuer = Get-RealmIssuer $kcBase $realm
function Deliver([string] $type, $data) {
    $assertion = New-ClientAssertion -KeyFile $tenantProof.delivery_key -ClientId $tenantProof.delivery_client -Audience $issuer
    $token = (Invoke-RestMethod -Method Post -Uri "$kcBase/realms/$realm/protocol/openid-connect/token" -Body @{
            grant_type = "client_credentials"; client_id = $tenantProof.delivery_client
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion = $assertion }).access_token
    $envelope = @{ specversion = "1.0"; id = (New-UuidV7); source = "/systems/organization-control"; type = $type
        time = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); datacontenttype = "application/json"
        streamposition = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); data = $data } | ConvertTo-Json -Compress -Depth 8
    return Send "POST" "$api/v1/deliveries" $envelope $token $null
}

function Wait-Until([scriptblock] $condition, [int] $seconds = 60) {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $seconds) {
        if (& $condition) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Operation-Applied($accepted) {
    $operation = $accepted.json
    for ($i = 0; $i -lt 150 -and (Get-Prop $operation "state") -notin @("applied", "refused", "unresolved"); $i++) {
        Start-Sleep -Milliseconds 200
        $operation = (Api "GET" "/v1/security-operations/$(Get-Prop $operation 'operation_id')" $null $null).json
    }
    return (Get-Prop $operation "state")
}

$redirectBefore = "http://127.0.0.1:8101/callback"
$redirectAfter = "http://127.0.0.1:8102/callback"

if ($Phase -eq "before") {
    $run = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    Write-Host "older point, before the backup ($run)"
    $resource = "rd-api-$run"
    $r = Api "POST" "/v1/registrations" (@{ client_key = $resource; profile = "resource"; audience_class = "internal"
            application_ref = "restore-drill"; lifetime_class = "L1" } | ConvertTo-Json -Compress) $null
    Expect "a resource registered" $r.code 201
    $r = Api "POST" "/v1/registrations" (@{ client_key = "rd-before-$run"; profile = "public"; audience_class = "internal"
            application_ref = "restore-drill"; audience = @($resource); redirect_uris = @($redirectBefore) } | ConvertTo-Json -Compress) $null
    Expect "a public client registered" $r.code 201
    $before = Get-Prop $r.json "registration_id"
    $r = Api "POST" "/v1/principals" "{`"username`":`"rd.suspended.$run`",`"email`":`"rd.suspended.$run@scnehaux.local`",`"subject_type`":`"human`"}" $null
    Expect "a Principal created" $r.code 201
    $suspended = Get-Prop $r.json "principal_id"
    $tenant = New-UuidV7
    $r = Deliver "com.scnehaux.organization.tenant.lifecycle.activated" @{ tenant_id = $tenant; organization_id = (New-UuidV7)
        tenant_status = "active"; tenant_version = 1; tenant_security_version = 1 }
    Expect "a Tenant activated" $r.code 202
    $org = Wait-Until { @(Kc "/organizations?search=$tenant&exact=true" | Where-Object { $_.name -eq $tenant }).Count -eq 1 }
    Expect "its Organization converged" $org $true
    @{ run = $run; resource = $resource; before = $before; suspended = $suspended; tenant = $tenant } |
        ConvertTo-Json -Compress | Set-Content -NoNewline $State
    if ($failures -gt 0) { exit 1 }
    exit 0
}

$s = Get-Content -Raw $State | ConvertFrom-Json
function Decode-Claims([string] $jwt) {
    $part = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
}
$operator = (Decode-Claims (Get-ScnehauxToken -Username "bootstrap-operator" -Password $env:IDENTITY_CALLER_PASSWORD `
            -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp)).principal_id
$operatorUser = @(Kc "/users?username=bootstrap-operator&exact=true")[0].id

if ($Phase -eq "after-backup") {
    Write-Host "older point, after the backup: changes the restored database will not hold"
    $r = Api "POST" "/v1/principals" "{`"username`":`"rd.after.$($s.run)`",`"email`":`"rd.after.$($s.run)@scnehaux.local`",`"subject_type`":`"human`"}" $null
    Expect "a Principal created" $r.code 201
    $after = Get-Prop $r.json "principal_id"

    $keyFile = Join-Path (Split-Path -Parent $State) "rd-after-$($s.run).pem"
    $rsa = [System.Security.Cryptography.RSA]::Create(3072)
    try {
        $pem = "-----BEGIN PRIVATE KEY-----`n" +
            [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), [Base64FormattingOptions]::InsertLineBreaks) +
            "`n-----END PRIVATE KEY-----`n"
        [System.IO.File]::WriteAllText($keyFile, $pem)
        if (-not $IsWindows) { & chmod 600 $keyFile }
        $public = $rsa.ExportParameters($false)
        $jwk = @{ kty = "RSA"; n = (ConvertTo-Base64Url $public.Modulus); e = (ConvertTo-Base64Url $public.Exponent) }
    } finally { $rsa.Dispose() }
    $r = Api "POST" "/v1/registrations" (@{ client_key = "rd-after-$($s.run)"; profile = "confidential"
            audience_class = "internal"; application_ref = "restore-drill"; audience = @($s.resource)
            redirect_uris = @($redirectBefore); public_key = $jwk } | ConvertTo-Json -Compress -Depth 4) $null
    Expect "a confidential client registered" $r.code 201

    $read = Api "GET" "/v1/registrations/$($s.before)" $null $null
    $r = Api "POST" "/v1/registrations/$($s.before)/changes" (@{ redirect_uris = @($redirectAfter)
            expected_version = (Get-Prop $read.json "version") } | ConvertTo-Json -Compress) (Reason "the callback moves")
    Expect "the public client's redirect URIs changed" "$($r.code) $(Get-Prop $r.json 'state')" "201 applied"

    $principal = Api "GET" "/v1/principals/$($s.suspended)" $null $null
    $r = Api "POST" "/v1/principals/$($s.suspended):suspend" "{`"expected_version`":$(Get-Prop $principal.json 'security_version')}" (Reason "contain before the backup is restored")
    Expect "the Principal suspended" (Operation-Applied $r) "applied"

    $membership = New-UuidV7
    $r = Deliver "com.scnehaux.organization.membership.lifecycle.granted" @{ membership_id = $membership
        principal_id = $operator; tenant_id = $s.tenant; workspace_id = $null; membership_status = "active"
        membership_version = 1; tenant_security_version = 1 }
    Expect "a Membership granted" $r.code 202
    Expect "the kernel made the member" (Wait-Until { (Members-Of $s.tenant) -contains $operatorUser }) $true

    $s | Add-Member -NotePropertyName after -NotePropertyValue $after -Force
    $s | Add-Member -NotePropertyName membership -NotePropertyValue $membership -Force
    $s | Add-Member -NotePropertyName after_key -NotePropertyValue $keyFile -Force
    $s | Add-Member -NotePropertyName after_jwk -NotePropertyValue $jwk -Force
    $s | ConvertTo-Json -Compress -Depth 4 | Set-Content -NoNewline $State
    if ($failures -gt 0) { exit 1 }
    exit 0
}

# --- reconcile: on the restored database, in report mode ---
Write-Host "older point, restored: what the service sees, then the runbook's reconciliation"
$cases = [System.Collections.Generic.List[object]]::new()
function Case($name, $seen, $reconciliation, $result, [bool] $ok) {
    $cases.Add([pscustomobject]@{ case = $name; after_restore = $seen; reconciliation = $reconciliation; result = $result; ok = $ok })
}
[void](Api "POST" "/v1/registrations:reconcile" $null $null)
[void](Api "POST" "/v1/principals:reconcile" $null $null)

Write-Host "1. a client registered after the backup"
$afterKey = "rd-after-$($s.run)"
$open = @((Api "GET" "/v1/registrations:drift" $null $null).json.findings |
        Where-Object { $_.finding_class -eq "unmanaged" -and $_.client_key -eq $afterKey })
Expect "recorded unmanaged" $open.Count 1
Expect "and left enabled in report mode" (Client-Of $afterKey).enabled $true
$declaration = @{ client_key = $afterKey; profile = "confidential"; audience_class = "internal"; application_ref = "restore-drill"
    redirect_uris = @($redirectBefore); audience = @($s.resource); public_keys = @($s.after_jwk) }
$plan = Api "POST" "/v1/registrations:adopt" (($declaration + @{ dry_run = $true }) | ConvertTo-Json -Compress -Depth 5) (Reason "the client was registered after the backup")
Expect "its adoption plan is adoptable" "$($plan.code) $(Get-Prop (Get-Prop $plan.json 'plan') 'adoptable')" "200 True"
$adopted = Api "POST" "/v1/registrations:adopt" ($declaration | ConvertTo-Json -Compress -Depth 5) (Reason "the client was registered after the backup")
Expect "adopted" $adopted.code 201
[void](Api "POST" "/v1/registrations:reconcile" $null $null)
$still = @((Api "GET" "/v1/registrations:drift" $null $null).json.findings |
        Where-Object { $_.finding_class -eq "unmanaged" -and $_.client_key -eq $afterKey })
Expect "its unmanaged finding converged" $still.Count 0
Case "client registered after the backup" "unmanaged, left enabled (report)" "adopted from its declaration" `
    "registered again; unmanaged finding converged" ($open.Count -eq 1 -and $adopted.code -eq 201 -and $still.Count -eq 0)

Write-Host "2. a registration changed after the backup"
$beforeKey = "rd-before-$($s.run)"
$blocked = @((Api "GET" "/v1/registrations/$($s.before)/findings" $null $null).json.findings |
        Where-Object { (Get-Prop $_ "field_class") -eq "redirect_uris" -and -not (Get-Prop $_ "converged_at") })
Expect "the restored redirect URIs are a difference" $blocked.Count 1
Expect "which blocks the client" (Client-Of $beforeKey).enabled $false
$finding = Get-Prop ($blocked | Select-Object -First 1) "finding_id"
$r = Api "POST" "/v1/registrations:reconcile" "{`"findings`":[`"$finding`"]}" (Reason "apply the restored state, then repeat the change")
Expect "the operator applies the restored state" $r.code 200
Expect "the client is enabled with the restored URIs" "$((Client-Of $beforeKey).enabled) $(@((Client-Of $beforeKey).redirectUris) -join ',')" "True $redirectBefore"
$read = Api "GET" "/v1/registrations/$($s.before)" $null $null
$r = Api "POST" "/v1/registrations/$($s.before)/changes" (@{ redirect_uris = @($redirectAfter)
        expected_version = (Get-Prop $read.json "version") } | ConvertTo-Json -Compress) (Reason "repeat the change the backup lost")
Expect "the change repeated through the API" "$($r.code) $(Get-Prop $r.json 'state')" "201 applied"
[void](Api "POST" "/v1/registrations:reconcile" $null $null)
$left = @((Api "GET" "/v1/registrations/$($s.before)/findings" $null $null).json.findings | Where-Object { -not (Get-Prop $_ "converged_at") })
$final = Client-Of $beforeKey
Expect "the client holds the repeated change, with nothing open" "$($final.enabled) $(@($final.redirectUris) -join ',') $($left.Count)" "True $redirectAfter 0"
Case "registration changed after the backup" "redirect_uris difference; client blocked and disabled" `
    "operator's reconcile applied the restored state; the change repeated through the API" `
    "client enabled with the repeated change, no open finding" ($blocked.Count -eq 1 -and $final.enabled -and $left.Count -eq 0)

Write-Host "3. a security command after the backup"
$read = Api "GET" "/v1/principals/$($s.suspended)" $null $null
$userId = @(Kc "/users?username=rd.suspended.$($s.run)&exact=true")[0]
Expect "the record is gone: the Principal reads active" (Get-Prop $read.json "state") "active"
Expect "the kernel kept the effect: the user is disabled" $userId.enabled $false
$r = Api "POST" "/v1/principals/$($s.suspended):suspend" "{`"expected_version`":$(Get-Prop $read.json 'security_version')}" (Reason "repeat the suspension the backup lost")
$repeated = Operation-Applied $r
Expect "the suspension repeated" $repeated "applied"
$again = Get-Prop (Api "GET" "/v1/principals/$($s.suspended)" $null $null).json "state"
Expect "the Principal reads suspended again" $again "suspended"
Case "security command after the backup" "record gone; Principal active while its user stays disabled" `
    "the suspension repeated" "suspended, the record exists again" ($repeated -eq "applied" -and $again -eq "suspended")

Write-Host "4. a Membership granted after the backup"
$out = Wait-Until { -not ((Members-Of $s.tenant) -contains $operatorUser) }
Expect "the sweep took the member out" $out $true
$extra = @((Api "GET" "/v1/projections/tenant-context:findings?class=extra_member&limit=500" $null $null).json.findings |
        Where-Object { (Get-Prop $_ "tenant_id") -eq $s.tenant })
Expect "recorded as an extra member" ($extra.Count -ge 1) $true
$report = (Api "GET" "/v1/projections/tenant-context/report" $null $null).json
Expect "the report lacks the Membership" @($report.rows | Where-Object { $_.membership_id -eq $s.membership }).Count 0
$r = Deliver "com.scnehaux.organization.projection.repair.reconciled" @{ consumer_id = "identity-control"; mark = 0
    findings = @(@{ classification = "missing"; membership_id = $s.membership; state = @{ membership_id = $s.membership
                principal_id = $operator; tenant_id = $s.tenant; workspace_id = $null; membership_status = "active"
                membership_version = 1; tenant_security_version = 1 } }) }
Expect "Organization Control's repair delivered" $r.code 202
$back = Wait-Until { (Members-Of $s.tenant) -contains $operatorUser }
Expect "the member is back" $back $true
$report = (Api "GET" "/v1/projections/tenant-context/report" $null $null).json
$held = @($report.rows | Where-Object { $_.membership_id -eq $s.membership }).Count
Expect "the report holds the Membership" $held 1
Case "Membership granted after the backup" "the sweep removed the member as extra_member (fails closed)" `
    "Organization Control's repair delivered the authoritative state" "member restored; the report matches" `
    ($out -and $back -and $held -eq 1)

Write-Host "5. a Principal created after the backup"
$orphan = @((Api "GET" "/v1/principals:unmapped" $null $null).json.unmapped | Where-Object { (Get-Prop $_ "username") -eq "rd.after.$($s.run)" })
$first = $orphan | Select-Object -First 1
Expect "recorded as an orphan" (Get-Prop $first "finding_class") "orphan"
Expect "left enabled in report mode" (Get-Prop $first "user_disabled") $false
Expect "carrying the identifier the API issued" (Get-Prop $first "claimed_principal_id") $s.after
Case "Principal created after the backup" "orphan: a kernel user carrying an identifier no mapping holds; enabled (report)" `
    "none built: no route binds an orphan's identifier to a mapping again" `
    "gap: the principal_id stays unknown here; under disable the user would be disabled" ($orphan.Count -eq 1)

Remove-Item -Force -ErrorAction SilentlyContinue $s.after_key
$evidence = @{ standard = "STD-GLB-002 §Restore Evidence"; runbook = "docs/runbooks/control-database-restore.md §After a restore to an older point"
    started_in = "report"; cases = $cases }
$evidence | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path (Split-Path -Parent $State) "older-point-evidence.json")
if ($env:GITHUB_STEP_SUMMARY) {
    $lines = @("### Restore to an older point", "", "| Made after the backup | Seen after the restore | Reconciliation | Result |",
        "| :-- | :-- | :-- | :-- |")
    foreach ($c in $cases) { $lines += "| $($c.case) | $($c.after_restore) | $($c.reconciliation) | $($c.result) |" }
    $lines | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}
Write-Host ""
if ($failures -gt 0) { Write-Host "$failures check(s) failed."; exit 1 }
Write-Host "a restore to an older point is reconciled as the runbook says."
