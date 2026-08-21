# Obtains an access token through Authorization Code with PKCE, without a browser.
#
# Dot-source it and call Get-ScnehauxToken.
#
# WHY THIS EXISTS, rather than a direct access grant.
#
# The harness originally used the Resource Owner Password Credentials grant because it is one HTTP
# call. Two things then turned out to be true at once:
#
#   1. STD-IAM-001 §3.2 prohibits that grant for every client. A client receiving and forwarding
#      the Principal's password holds credential material §3.1 forbids it from holding, and every
#      abuse control, MFA step, and passkey ceremony the kernel applies sits outside the path.
#
#   2. It cannot satisfy the profile even if it were permitted. STD-IAM-002 §3.2 makes `auth_time`
#      mandatory for a `privileged` token, and the kernel records an authentication instant only
#      for an authentication ceremony. A direct grant has none, so Keycloak emits no AUTH_TIME
#      session note and the claim is structurally absent — not missing configuration.
#
# The second point is the interesting one: the prohibited grant could not produce a conformant
# token, so weakening the profile to accommodate the harness would have meant weakening it to
# accommodate a grant the standard already refused. Driving the real flow was cheaper than either.
#
# This script therefore performs the flow the standard requires: PKCE `S256`, the kernel's own
# login form, one authorization code, exchanged once. No password reaches the client as a token
# request parameter — it is posted to the kernel's authentication endpoint, which is where §3.1
# says credential material belongs.

Add-Type -AssemblyName System.Web
Set-StrictMode -Version Latest

# Add-LoopbackCookies copies Set-Cookie values into the session with Secure cleared.
#
# Split on a comma that is followed by a cookie name, rather than on every comma: a cookie value
# may contain one, and a naive split would truncate KC_RESTART, whose value is a JWE.
function Add-LoopbackCookies {
    param($Response, $Session, [string] $Origin)

    $raw = $Response.Headers["Set-Cookie"]
    if (-not $raw) { return }

    $host_ = ([uri]$Origin).Host
    foreach ($entry in ($raw -split ',(?=\s*[A-Za-z_][A-Za-z0-9_\-]*=)')) {
        $parts = $entry.Trim() -split ';'
        $pair = $parts[0]
        $eq = $pair.IndexOf('=')
        if ($eq -lt 1) { continue }

        $cookie = New-Object System.Net.Cookie
        $cookie.Name = $pair.Substring(0, $eq).Trim()
        $cookie.Value = $pair.Substring($eq + 1).Trim()
        $cookie.Domain = $host_
        $cookie.Path = "/"
        $cookie.Secure = $false

        foreach ($attribute in $parts[1..($parts.Count - 1)]) {
            $name, $value = ($attribute.Trim() -split '=', 2)
            if ($name -ieq "Path" -and $value) { $cookie.Path = $value }
        }
        try { $Session.Cookies.Add($cookie) } catch { }
    }
}

function Get-ScnehauxToken {
    param(
        [Parameter(Mandatory = $true)] [string] $Username,
        [Parameter(Mandatory = $true)] [string] $Password,
        [string] $KcBase   = $(if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }),
        [string] $Realm    = $(if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }),
        [string] $ClientId = "identity-control-caller",
        [Parameter(Mandatory = $true)] [string] $ClientSecret,
        [string] $RedirectUri = "http://127.0.0.1:8099/callback"
    )

    $ErrorActionPreference = "Stop"

    # PKCE. The verifier is 32 random bytes base64url-encoded; the challenge is its SHA-256, also
    # base64url. S256 rather than plain, per §3.2 — plain offers no protection against an
    # intercepted code, which is the whole reason the extension exists.
    $bytes = New-Object byte[] 32
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $verifier = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $challengeBytes = $sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($verifier))
    $sha.Dispose()
    $challenge = [Convert]::ToBase64String($challengeBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $stateBytes = New-Object byte[] 16
    $rng2 = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $rng2.GetBytes($stateBytes)
    $rng2.Dispose()
    $state = [Convert]::ToBase64String($stateBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $authorize = "$KcBase/realms/$Realm/protocol/openid-connect/auth" +
        "?client_id=$([uri]::EscapeDataString($ClientId))" +
        "&response_type=code" +
        "&scope=openid" +
        "&redirect_uri=$([uri]::EscapeDataString($RedirectUri))" +
        "&state=$state" +
        "&code_challenge=$challenge" +
        "&code_challenge_method=S256"

    # One cookie jar across both requests. The kernel's login form is bound to a session cookie,
    # and posting the form without it produces "Restart login cookie not found" rather than a
    # credential failure — a distinction worth knowing when this breaks.
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $page = Invoke-WebRequest -Uri $authorize -WebSession $session -UseBasicParsing -MaximumRedirection 5

    # Keycloak marks AUTH_SESSION_ID, KC_RESTART, and KC_AUTH_SESSION_HASH `Secure; SameSite=None`.
    # A browser accepts them here anyway, because `http://localhost` is a secure context by
    # specification. System.Net.CookieContainer implements no such exception and silently drops
    # all three, so the cookie jar comes back empty and the POST below is rejected.
    #
    # This re-adds them with the Secure flag cleared, which emulates the browser's loopback
    # exemption rather than weakening the kernel's policy: over a real network the cookies stay
    # Secure and this code path is never reached, because a real deployment serves HTTPS.
    Add-LoopbackCookies -Response $page -Session $session -Origin $KcBase

    # The form action carries the execution and tab identifiers the kernel needs to correlate the
    # POST with the authentication flow it started. Parsed from the page rather than reconstructed,
    # because those values are the kernel's internal state and not a stable URL shape.
    if ($page.Content -notmatch '(?s)<form[^>]*\saction="([^"]+)"') {
        throw "no login form was returned by the authorization endpoint; is standardFlowEnabled set on $ClientId?"
    }
    $action = [System.Web.HttpUtility]::HtmlDecode($Matches[1])

    # A 302 to the redirect URI is success, and the Location header carries the code. Nothing
    # listens on that port, so the redirect must not be followed.
    #
    # HttpWebRequest rather than Invoke-WebRequest: `-MaximumRedirection 0` in PowerShell 5.1
    # raises MaximumRedirectExceeded, an InvalidOperationException whose Response is not reachable,
    # so the 302 that means success is indistinguishable from a transport failure. AllowAutoRedirect
    # = $false returns the response itself.
    $request = [System.Net.HttpWebRequest]::Create($action)
    $request.Method = "POST"
    $request.AllowAutoRedirect = $false
    $request.CookieContainer = $session.Cookies
    $request.ContentType = "application/x-www-form-urlencoded"

    $form = "username=$([uri]::EscapeDataString($Username))&password=$([uri]::EscapeDataString($Password))"
    $body = [System.Text.Encoding]::ASCII.GetBytes($form)
    $request.ContentLength = $body.Length
    $stream = $request.GetRequestStream()
    $stream.Write($body, 0, $body.Length)
    $stream.Close()

    $codeUri = $null
    try {
        $response = $request.GetResponse()
        try {
            $status = [int]$response.StatusCode
            if ($status -ge 300 -and $status -lt 400) {
                $codeUri = $response.Headers["Location"]
            } else {
                # 200 means the form was redisplayed: the credential was refused, or the account
                # has a pending required action.
                throw "the kernel answered $status rather than redirecting; the credential was refused, or a required action is pending"
            }
        } finally { $response.Close() }
    } catch [System.Net.WebException] {
        $errorResponse = $_.Exception.Response
        if (-not $errorResponse) { throw }
        $codeUri = $errorResponse.Headers["Location"]
        $errorResponse.Close()
        if (-not $codeUri) { throw }
    }
    if (-not $codeUri) { throw "the authentication POST returned no redirect carrying an authorization code" }

    $query = [System.Web.HttpUtility]::ParseQueryString(([uri]$codeUri).Query)
    if ($query["error"]) { throw "the kernel refused the authorization: $($query["error"])" }
    if ($query["state"] -ne $state) { throw "the state parameter did not match; refusing the code" }
    $code = $query["code"]
    if (-not $code) { throw "no authorization code in the redirect" }

    $token = Invoke-RestMethod -Method Post -ContentType "application/x-www-form-urlencoded" `
        -Uri "$KcBase/realms/$Realm/protocol/openid-connect/token" -Body @{
            grant_type    = "authorization_code"
            code          = $code
            redirect_uri  = $RedirectUri
            client_id     = $ClientId
            client_secret = $ClientSecret
            code_verifier = $verifier
        }
    return $token.access_token
}
