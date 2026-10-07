# Brings identity-experience-bff under registration on a development server
# (TDD-identity-control-003 §Adoption, deploy/dev/README.md §Adopting the BFF).
#
# identity-experience's deploy/dev/create-bff-client.sh made the BFF's client in the kernel before
# this service could register a confidential client, so it is adopted: a plan first, then, with
# -Apply, the adoption, held to the keys it already authenticates with.
#
# The declaration is the client create-bff-client.sh made:
#   - confidential, privileged in the provider-scope form, so it keeps scnehaux-provider and its
#     tokens keep acr and auth_time, which every provider route requires (STD-IAM-002 §3.1.1);
#   - identity-control-api in its audience, as the script's audience mapper names it;
#   - the BFF's callback on a developer's machine, http://127.0.0.1:8090/auth/callback.
# The script made it before the token profile, so token_format and audience_scope converge with the
# adoption: the at+jwt attribute and the client_id mapper are added, and the scopes become the
# profile's own, scnehaux-profile optional among them.
#
# SECRETS: read from the environment, as dev-smoke.ps1 reads them.
#   $env:IDENTITY_CALLER_KEY_FILE      the development caller's private key
#   $env:IDENTITY_CALLER_PASSWORD      the bootstrap operator's password
#   $env:IDENTITY_OPERATOR_TOTP_FILE   optional, the operator's TOTP file (dev-token.ps1)
# Each BFF file is a PUBLIC JWK, the one scripts/new-client-key.mjs wrote beside a private key. A file
# holding a private member is refused, and nothing read from one is printed.
#
# KEYS: every key the client holds, one file each, and no more than two, because an adoption declares
# exactly the one or two keys the client authenticates with (TDD-identity-control-003 §Adoption): a
# client given two keys with identity-kernel's set-client-key.sh, one per developer device, is
# declared with both, or the plan shows a client_keys difference. The first file is recorded active
# and a second retiring: the second stops working when IDENTITY_CLIENT_KEY_ROTATION_OVERLAP ends,
# so the key that must keep working goes first.
#
# Usage:
#   pwsh ./scripts/dev-adopt-bff.ps1 -BffJwkFile ./identity-experience-bff.jwk.json           # plan
#   pwsh ./scripts/dev-adopt-bff.ps1 -BffJwkFile ./identity-experience-bff.jwk.json -Apply    # adopt
#   pwsh ./scripts/dev-adopt-bff.ps1 -BffJwkFile ./laptop-a.jwk.json,./laptop-b.jwk.json      # two keys
# The files are a comma-separated list, which also reaches the script whole through pwsh -File.

param(
    [Parameter(Mandatory = $true)] [string[]] $BffJwkFile,
    [string] $RedirectUri = "http://127.0.0.1:8090/auth/callback",
    [switch] $Apply
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$api = if ($env:IDENTITY_API_URL) { $env:IDENTITY_API_URL } else { "http://127.0.0.1:8090" }
foreach ($name in @("IDENTITY_CALLER_KEY_FILE", "IDENTITY_CALLER_PASSWORD")) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "$name is required."
    }
}

# pwsh -File hands "a.jwk.json,b.jwk.json" over as one string; a call from a session, as an array.
$files = @($BffJwkFile | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($files.Count -lt 1 -or $files.Count -gt 2) {
    throw "give one or two public JWK files: an adoption declares the 1 to 2 keys the client holds."
}
$publicKeys = @(foreach ($file in $files) {
    $jwk = Get-Content -Raw -Path $file | ConvertFrom-Json
    $members = $jwk.PSObject.Properties.Name
    foreach ($private in @("d", "p", "q", "dp", "dq", "qi")) {
        if ($members -contains $private) {
            throw "$file holds a private key member; pass the public JWK, never the private key."
        }
    }
    if ($jwk.kty -ne "RSA" -or -not ($members -contains "n") -or -not ($members -contains "e")) {
        throw "$file is not an RSA public JWK."
    }
    @{ kty = "RSA"; n = $jwk.n; e = $jwk.e }
})

Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot\dev-token.ps1"
$operatorTotp = if ($env:IDENTITY_OPERATOR_TOTP_FILE) { @{ OperatorTotpFile = $env:IDENTITY_OPERATOR_TOTP_FILE } } else { @{} }
$token = Get-ScnehauxToken -Username "bootstrap-operator" `
    -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE @operatorTotp

$declaration = @{
    client_key      = "identity-experience-bff"
    profile         = "confidential"
    audience_class  = "privileged"
    privileged_form = "provider-scope"
    application_ref = "identity-experience"
    redirect_uris   = @($RedirectUri)
    audience        = @("identity-control-api")
    public_keys     = $publicKeys
    converge        = @("token_format", "audience_scope")
}

$client = New-Object System.Net.Http.HttpClient
function Send-Adopt($body, $idempotencyKey) {
    $request = New-Object System.Net.Http.HttpRequestMessage("POST", "$api/v1/registrations:adopt")
    $request.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $token)
    $request.Headers.Add("X-Administrative-Reason", "the BFF comes under registration")
    if ($idempotencyKey) { $request.Headers.Add("Idempotency-Key", $idempotencyKey) }
    $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
    $response = $client.SendAsync($request).Result
    return @{ code = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().Result }
}

$plan = Send-Adopt (($declaration + @{ dry_run = $true }) | ConvertTo-Json -Compress -Depth 5) $null
if ($plan.code -eq 409) {
    Write-Host "identity-experience-bff is registered already; nothing to adopt."
    exit 0
}
if ($plan.code -ne 200) {
    throw "the plan was refused with $($plan.code): $($plan.body)"
}
$planned = ($plan.body | ConvertFrom-Json).plan
Write-Host "plan: adoptable=$($planned.adoptable) declared_keys=$($publicKeys.Count)"
foreach ($difference in $planned.differences) {
    if ($difference.differs) {
        Write-Host ("  differs  {0,-16} {1}" -f $difference.field_class, $difference.policy)
    }
}
if (-not $planned.adoptable) {
    if ($planned.PSObject.Properties.Name -contains 'refusal') { Write-Host "refusal: $($planned.refusal)" }
    throw "the BFF is not adoptable as declared. A redirect_uris or client_keys difference is fixed in the declaration, never in the console: for client_keys, pass every public JWK the client holds."
}
if (-not $Apply) {
    Write-Host "dry run only; run again with -Apply to adopt."
    exit 0
}

$adopted = Send-Adopt ($declaration | ConvertTo-Json -Compress -Depth 5) "dev-adopt-identity-experience-bff"
if ($adopted.code -ne 201) {
    throw "the adoption was refused with $($adopted.code): $($adopted.body)"
}
$registration = ($adopted.body | ConvertFrom-Json).registration
Write-Host "adopted: registration_id=$($registration.registration_id) privileged_form=$($registration.privileged_form)"
