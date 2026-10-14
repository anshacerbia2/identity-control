# The addresses and the operator TOTP the dev-*.ps1 scripts use, derived from deploy/dev/.env.
#
# Dot-source it (dev-token.ps1 does). An operator loads .env into the shell once, from the repository
# root, and runs the scripts with nothing else exported:
#
#   set -a; . deploy/dev/.env; set +a
#   pwsh ./scripts/dev-smoke.ps1
#
# Each value is, in this order: the variable named below when it is set, which overrides the
# derivation (CI and a laptop's local run set them); the value derived from .env; and otherwise an error
# that says what to set.
#
#   Get-DevApiUrl            IDENTITY_API_URL; else http://127.0.0.1:$IDENTITY_CONTROL_PORT, the loopback
#                            port compose.yaml publishes the API on, 8082 when unset as there.
#   Get-DevKernelUrl         KC_BASE_URL; else the origin (scheme, host and port) of KEYCLOAK_ISSUER, which
#                            is the kernel's public origin, where its login form is served.
#   Get-DevOperatorTotpFile  IDENTITY_OPERATOR_TOTP_FILE; else deploy/dev/keys/operator-totp.json under
#                            the repository root when that file exists; else none, and the sign-in is aal1.
#   Get-DevOperatorTotp      the same, as the splat Get-ScnehauxToken takes: @{ OperatorTotpFile = ... }.
#
# The TOTP file holds a secret; nothing here reads or prints its contents.

function Get-DevApiUrl {
    if ($env:IDENTITY_API_URL) { return $env:IDENTITY_API_URL.TrimEnd('/') }
    $port = if ($env:IDENTITY_CONTROL_PORT) { $env:IDENTITY_CONTROL_PORT.Trim() } else { "8082" }
    if ($port -notmatch '^[0-9]{1,5}$' -or [int]$port -lt 1 -or [int]$port -gt 65535) {
        throw "IDENTITY_CONTROL_PORT is '$port', not a port number: fix it in deploy/dev/.env, or set IDENTITY_API_URL."
    }
    return "http://127.0.0.1:$port"
}

function Get-DevKernelUrl {
    if ($env:KC_BASE_URL) { return $env:KC_BASE_URL.TrimEnd('/') }
    if (-not $env:KEYCLOAK_ISSUER) {
        throw "neither KC_BASE_URL nor KEYCLOAK_ISSUER is set: load deploy/dev/.env first (set -a; . deploy/dev/.env; set +a), or set KC_BASE_URL to the kernel's public origin."
    }
    $issuer = $null
    if (-not [Uri]::TryCreate($env:KEYCLOAK_ISSUER.Trim(), [UriKind]::Absolute, [ref]$issuer) -or
        ($issuer.Scheme -ne "https" -and $issuer.Scheme -ne "http") -or -not $issuer.Host) {
        throw "KEYCLOAK_ISSUER is '$($env:KEYCLOAK_ISSUER)', not an absolute http(s) URL such as https://<the kernel host>/realms/scnehaux: fix it in deploy/dev/.env, or set KC_BASE_URL."
    }
    # The origin alone: the realm path is the scripts' own (KC_REALM), and a default port is left out.
    return $issuer.GetLeftPart([UriPartial]::Authority)
}

function Get-DevOperatorTotpFile {
    if ($env:IDENTITY_OPERATOR_TOTP_FILE) { return $env:IDENTITY_OPERATOR_TOTP_FILE }
    # From this file's location, not the working directory: scripts/ is one level under the root.
    $path = Join-Path (Split-Path -Parent $PSScriptRoot) (Join-Path "deploy" (Join-Path "dev" (Join-Path "keys" "operator-totp.json")))
    if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    return $null
}

function Get-DevOperatorTotp {
    $file = Get-DevOperatorTotpFile
    if ($file) { return @{ OperatorTotpFile = $file } }
    # On stderr, so a caller reading the script's output is not disturbed. The path only, never contents.
    [Console]::Error.WriteLine("note: no operator TOTP (IDENTITY_OPERATOR_TOTP_FILE unset, deploy/dev/keys/operator-totp.json absent): signing in at aal1, which provider routes refuse")
    return @{}
}
