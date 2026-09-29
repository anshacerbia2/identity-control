# Signs an RFC 7523 client assertion with a client's private key. Dot-source it and call
# New-ClientAssertion.
#
# Every client of this service authenticates with its own key by signed JWT, never a client secret
# (ADR-IAM-001 §5.12, STD-IAM-001 §3.2). The Go service signs in internal/keycloak/clientkey.go.
# This is the same assertion for the scripts: PS256, the key's RFC 7638 thumbprint as kid, the
# client as iss and sub, the realm's issuer as aud, a fresh jti, and a one-minute expiry.
#
# It runs on Windows PowerShell 5.1 (.NET Framework, which cannot read PKCS#8 into RSA without CNG)
# and on PowerShell 7, which CI uses on Linux.

Set-StrictMode -Version Latest

function ConvertTo-Base64Url([byte[]] $Bytes) {
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Read-ClientKey([string] $KeyFile) {
    $pem = [System.IO.File]::ReadAllText($KeyFile)
    if ($pem -notmatch '-----BEGIN PRIVATE KEY-----') {
        throw "$KeyFile is not a PKCS#8 PEM private key"
    }
    $der = [Convert]::FromBase64String(($pem -replace '-----[^-]+-----', '' -replace '\s', ''))
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $read = 0
        $rsa.ImportPkcs8PrivateKey($der, [ref] $read)
    } else {
        $cng = [System.Security.Cryptography.CngKey]::Import($der, [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $rsa = New-Object System.Security.Cryptography.RSACng($cng)
    }
    if ($rsa.KeySize -lt 3072) { throw "$KeyFile is $($rsa.KeySize) bits; at least 3072 are required" }
    return $rsa
}

# Get-RealmIssuer reads the realm's issuer from discovery. The address a script reaches the kernel
# on is not always the issuer, and the assertion must name the issuer.
function Get-RealmIssuer([string] $KcBase, [string] $Realm) {
    return (Invoke-RestMethod -Uri "$KcBase/realms/$Realm/.well-known/openid-configuration").issuer
}

function New-ClientAssertion {
    param(
        [Parameter(Mandatory = $true)] [string] $KeyFile,
        [Parameter(Mandatory = $true)] [string] $ClientId,
        [Parameter(Mandatory = $true)] [string] $Audience
    )
    $rsa = Read-ClientKey $KeyFile
    try {
        $public = $rsa.ExportParameters($false)
        $n = ConvertTo-Base64Url $public.Modulus
        $e = ConvertTo-Base64Url $public.Exponent
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $kid = ConvertTo-Base64Url ($sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes('{"e":"' + $e + '","kty":"RSA","n":"' + $n + '"}')))

        $jtiBytes = New-Object byte[] 32
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($jtiBytes)
        $rng.Dispose()
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        $header = '{"alg":"PS256","typ":"JWT","kid":"' + $kid + '"}'
        $claims = (@{ iss = $ClientId; sub = $ClientId; aud = $Audience; jti = (ConvertTo-Base64Url $jtiBytes); iat = $now; exp = $now + 60 } | ConvertTo-Json -Compress)
        $utf8 = [System.Text.Encoding]::UTF8
        $input_ = (ConvertTo-Base64Url $utf8.GetBytes($header)) + '.' + (ConvertTo-Base64Url $utf8.GetBytes($claims))
        $signature = $rsa.SignData([System.Text.Encoding]::ASCII.GetBytes($input_),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pss)
        return $input_ + '.' + (ConvertTo-Base64Url $signature)
    } finally {
        $rsa.Dispose()
    }
}
