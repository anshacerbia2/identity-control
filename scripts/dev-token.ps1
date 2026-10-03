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
. "$PSScriptRoot\client-assertion.ps1"

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

# Get-TotpCode is RFC 6238 with the realm's policy: HmacSHA1, 30-second steps, six digits. Keycloak
# keys the HMAC with the secret's bytes as its enrollment page carries them (identity-kernel's
# compat/levels_test.go computes it the same way).
function Get-TotpStep {
    return [long][Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30)
}

function Get-TotpCode([string] $Secret, [long] $Step) {
    $message = [BitConverter]::GetBytes($Step)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($message) }
    $hmac = New-Object System.Security.Cryptography.HMACSHA1 -ArgumentList (, [System.Text.Encoding]::UTF8.GetBytes($Secret))
    $hash = $hmac.ComputeHash($message)
    $hmac.Dispose()
    $offset = $hash[$hash.Length - 1] -band 0x0f
    $value = (([int]$hash[$offset] -band 0x7f) -shl 24) -bor ([int]$hash[$offset + 1] -shl 16) -bor `
        ([int]$hash[$offset + 2] -shl 8) -bor [int]$hash[$offset + 3]
    return ($value % 1000000).ToString("000000")
}

# Get-HiddenInputs reads a form's hidden fields, which the kernel carries its state in.
function Get-HiddenInputs([string] $Content) {
    $fields = [ordered]@{}
    foreach ($element in [regex]::Matches($Content, '<input[^>]*type="hidden"[^>]*>')) {
        if ($element.Value -match 'name="([^"]+)"') {
            $name = $Matches[1]
            $value = if ($element.Value -match 'value="([^"]*)"') { [System.Web.HttpUtility]::HtmlDecode($Matches[1]) } else { "" }
            $fields[$name] = $value
        }
    }
    return $fields
}

# Find-OtpCredential is the identifier of the OTP credential the code page lists under a label, for
# an account that holds more than one.
function Find-OtpCredential([string] $Content, [string] $Label) {
    foreach ($radio in [regex]::Matches($Content, '<input[^>]*name="selectedCredentialId"[^>]*>')) {
        if ($radio.Value -match 'id="([^"]+)"') { $inputId = $Matches[1] } else { continue }
        if ($radio.Value -match 'value="([^"]+)"') { $credentialId = $Matches[1] } else { continue }
        $pattern = '(?s)for="' + [regex]::Escape($inputId) + '".*?</label>'
        $labelElement = [regex]::Match($Content, $pattern)
        if ($labelElement.Success -and $labelElement.Value -match [regex]::Escape($Label)) { return $credentialId }
    }
    return $null
}

function Get-ScnehauxToken {
    param(
        [Parameter(Mandatory = $true)] [string] $Username,
        [Parameter(Mandatory = $true)] [string] $Password,
        [string] $KcBase   = $(if ($env:KC_BASE_URL) { $env:KC_BASE_URL } else { "http://127.0.0.1:8081" }),
        [string] $Realm    = $(if ($env:KC_REALM) { $env:KC_REALM } else { "scnehaux" }),
        [string] $ClientId = "identity-control-caller",
        # The caller's private key. The code is exchanged with an assertion signed by it; the
        # client holds no secret (ADR-IAM-001 §5.12).
        [Parameter(Mandatory = $true)] [string] $KeyFile,
        [string] $RedirectUri = "http://127.0.0.1:8099/callback",
        # The authentication level to ask for (ADR-IAM-004). Every provider route requires aal2, so
        # a token for one is asked with -AcrValues aal2 and the current code from the person's
        # authenticator app in -Otp. The first TOTP is enrolled in a browser: sign in to the Admin
        # Portal, which asks for aal2 and shows the kernel's enrollment page.
        [string] $AcrValues = "",
        [string] $Otp = "",
        # A development server's own TOTP for this account (ADR-IAM-004 §5.5): a JSON file holding its
        # label and secret, from which the code is computed. Never printed.
        [string] $TotpSecretFile = "",
        # Enrolls that TOTP: signs in at aal2 with -Otp, the one code read from the person's own
        # authenticator, then asks the kernel to set up another TOTP (kc_action=CONFIGURE_TOTP), and
        # writes its secret here, mode 0600. Refuses when the file exists.
        [string] $EnrollTotpFile = "",
        [string] $TotpLabel = "dev-server",
        # Both of the above for automation that owns its account: enrolls into the file when it is
        # absent, then signs in at aal2 with it. For an account with no TOTP yet, such as a CI stack's
        # bootstrap operator, enrolling needs no -Otp: binding a first second factor takes the
        # account's highest level, which is aal1 (NIST SP 800-63B-4 4.1.2.1).
        [string] $OperatorTotpFile = ""
    )

    if ($OperatorTotpFile) {
        $AcrValues = "aal2"
        if (Test-Path $OperatorTotpFile) { $TotpSecretFile = $OperatorTotpFile } else { $EnrollTotpFile = $OperatorTotpFile }
    }
    if ($EnrollTotpFile) {
        if (Test-Path $EnrollTotpFile) { throw "$EnrollTotpFile exists; a server holds one TOTP for this account" }
        # With -Otp the account already holds a TOTP: the sign-in reaches aal2 with the person's code,
        # and the kernel's application-initiated action sets up another one. Without it, the account
        # has none, and the aal2 sign-in itself enrolls the first.
        $AcrValues = "aal2"
    }

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
        "&code_challenge_method=S256" +
        $(if ($AcrValues) { "&acr_values=$([uri]::EscapeDataString($AcrValues))" } else { "" }) +
        $(if ($EnrollTotpFile -and $Otp) { "&max_age=0&kc_action=CONFIGURE_TOTP" } else { "" })

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
    function Send-LoginForm([string] $Action, [string] $Form) {
        $request = [System.Net.HttpWebRequest]::Create($Action)
        $request.Method = "POST"
        $request.AllowAutoRedirect = $false
        $request.CookieContainer = $session.Cookies
        $request.ContentType = "application/x-www-form-urlencoded"
        $body = [System.Text.Encoding]::ASCII.GetBytes($Form)
        $request.ContentLength = $body.Length
        $stream = $request.GetRequestStream()
        $stream.Write($body, 0, $body.Length)
        $stream.Close()
        try {
            $response = $request.GetResponse()
        } catch [System.Net.WebException] {
            $response = $_.Exception.Response
            if (-not $response) { throw }
        }
        try {
            # The same loopback exemption as for the first page: the code page's cookies must reach
            # the code's POST.
            Add-LoopbackCookies -Response @{ Headers = @{ "Set-Cookie" = $response.Headers["Set-Cookie"] } } `
                -Session $session -Origin $KcBase
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            return @{
                Status   = [int]$response.StatusCode
                Location = $response.Headers["Location"]
                Content  = $reader.ReadToEnd()
            }
        } finally { $response.Close() }
    }

    $answer = Send-LoginForm $action "username=$([uri]::EscapeDataString($Username))&password=$([uri]::EscapeDataString($Password))"
    # Further pages of the same sign-in: the code a level of two factors asks for, and, when
    # enrolling, the kernel's page that sets up another TOTP.
    $enrolledSecret = $null
    for ($step = 0; $step -lt 4 -and $answer.Status -eq 200; $step++) {
        $content = $answer.Content
        if ($content -notmatch '(?s)<form[^>]*\saction="([^"]+)"') { throw "the kernel answered a page with no form" }
        $next = [System.Web.HttpUtility]::HtmlDecode($Matches[1])
        $fields = Get-HiddenInputs $content
        if ($content -match 'name="totpSecret"') {
            if (-not $EnrollTotpFile) {
                throw "the kernel asks to enroll a TOTP authenticator first: sign in to the Admin Portal in a browser once, then pass the app's code in -Otp"
            }
            $enrolledSecret = $fields["totpSecret"]
            $enrolledStep = Get-TotpStep
            $fields["totp"] = Get-TotpCode $enrolledSecret $enrolledStep
            $fields["userLabel"] = $TotpLabel
        } elseif ($content -match 'name="otp"') {
            if ($Otp) {
                $fields["otp"] = $Otp
                $Otp = ""
            } elseif ($TotpSecretFile) {
                $stored = Get-Content -Raw $TotpSecretFile | ConvertFrom-Json
                $credential = Find-OtpCredential $content $stored.label
                if ($credential) { $fields["selectedCredentialId"] = $credential }
                # The kernel accepts a code once (the realm's OTP policy does not allow reuse), so a
                # second sign-in in the same 30 seconds waits for the next step.
                $step = Get-TotpStep
                $last = if ($stored.PSObject.Properties.Name -contains 'last') { [long]$stored.last } else { -1 }
                if ($step -le $last) {
                    Start-Sleep -Seconds (30 - ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % 30) + 1)
                    $step = Get-TotpStep
                }
                $fields["otp"] = Get-TotpCode $stored.secret $step
                @{ label = $stored.label; secret = $stored.secret; last = $step } | ConvertTo-Json -Compress |
                    Set-Content -NoNewline $TotpSecretFile
            } else {
                throw "the kernel asks for a one-time code: pass -Otp, or -TotpSecretFile on a development server"
            }
        } else {
            throw "the kernel showed a page this script does not answer"
        }
        $form = ($fields.GetEnumerator() | ForEach-Object { "$([uri]::EscapeDataString($_.Key))=$([uri]::EscapeDataString([string]$_.Value))" }) -join "&"
        $answer = Send-LoginForm $next $form
    }
    if ($enrolledSecret -and $answer.Status -ge 300 -and $answer.Status -lt 400) {
        # Written only once the kernel accepted the code it was set up with. Never printed.
        @{ label = $TotpLabel; secret = $enrolledSecret; last = $enrolledStep } | ConvertTo-Json -Compress |
            Set-Content -NoNewline $EnrollTotpFile
        if ($IsLinux -or $IsMacOS) { chmod 600 $EnrollTotpFile }
        Write-Host "enrolled the TOTP '$TotpLabel'; its secret is in $EnrollTotpFile"
    }
    $codeUri = $null
    if ($answer.Status -ge 300 -and $answer.Status -lt 400) {
        $codeUri = $answer.Location
    } else {
        # 200 means a form was redisplayed: the credential or the code was refused, or the account
        # has a pending required action.
        throw "the kernel answered $($answer.Status) rather than redirecting; the credential or code was refused, or a required action is pending"
    }
    if (-not $codeUri) { throw "the authentication POST returned no redirect carrying an authorization code" }

    $query = [System.Web.HttpUtility]::ParseQueryString(([uri]$codeUri).Query)
    if ($query["error"]) { throw "the kernel refused the authorization: $($query["error"])" }
    # A redirect that is not to the redirect URI is the kernel interrupting the login -- a required action,
    # or an incomplete profile -- rather than a forged response, and saying so is what makes it fixable.
    if (-not $codeUri.StartsWith($RedirectUri)) { throw "the login was interrupted: the kernel redirected to $(($codeUri -split '\?')[0]) rather than the redirect URI; complete the account's pending action or profile" }
    if ($query["state"] -ne $state) { throw "the state parameter did not match; refusing the code" }
    $code = $query["code"]
    if (-not $code) { throw "no authorization code in the redirect" }

    $assertion = New-ClientAssertion -KeyFile $KeyFile -ClientId $ClientId -Audience (Get-RealmIssuer $KcBase $Realm)
    $token = Invoke-RestMethod -Method Post -ContentType "application/x-www-form-urlencoded" `
        -Uri "$KcBase/realms/$Realm/protocol/openid-connect/token" -Body @{
            grant_type            = "authorization_code"
            code                  = $code
            redirect_uri          = $RedirectUri
            client_id             = $ClientId
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion      = $assertion
            code_verifier         = $verifier
        }
    return $token.access_token
}
