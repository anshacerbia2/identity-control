package keycloak

// This service's Admin API clients authenticate with a key pair they hold, never a shared secret
// (ADR-IAM-001 §5.12, STD-IAM-001 §3.2). This file is that half: reading the private key from its
// file, and signing the RFC 7523 assertion the token endpoint is sent.
//
// It is the twin of identity-kernel's internal/admin/clientkey.go. That module takes no
// dependencies and keeps its packages internal, so the two cannot share code. Both follow the same
// rules: RSA of at least 3072 bits, PS256, a kid that is the key's RFC 7638 thumbprint, the realm's
// issuer as audience, and a fresh jti on every assertion.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// MinClientKeyBits is the smallest RSA modulus a client key may have (STD-IAM-001 §3.2, the floor
// STD-IAM-002 §3.2.2 sets for signing keys).
const MinClientKeyBits = 3072

// ClientAssertionType is the RFC 7523 client assertion type.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// assertionLifetime bounds how long a signed assertion is accepted. The kernel refuses one presented
// twice, so the window only has to cover the request that carries it.
const assertionLifetime = time.Minute

// ClientKey is a client's private key and the identifier its public half is registered under.
type ClientKey struct {
	ID      string
	private *rsa.PrivateKey
}

// LoadClientKey reads a client key from a PEM file: the form every deployable is given its key in.
func LoadClientKey(path string) (*ClientKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// The path is configuration and safe to name. The content is never read into a message.
		return nil, fmt.Errorf("keycloak: reading the client key at %s: %w", path, err)
	}
	return ParseClientKey(raw)
}

// ParseClientKey reads an RSA private key in PKCS#8 or PKCS#1 PEM and refuses one below
// MinClientKeyBits.
func ParseClientKey(pemBytes []byte) (*ClientKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("keycloak: the client key is not PEM")
	}
	var private *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("keycloak: the client key is not a PKCS#8 key")
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("keycloak: the client key is not an RSA key")
		}
		private = rsaKey
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("keycloak: the client key is not a PKCS#1 key")
		}
		private = parsed
	default:
		return nil, fmt.Errorf("keycloak: a %q PEM block is not a private key", block.Type)
	}
	return ClientKeyFromRSA(private)
}

// ClientKeyFromRSA wraps an RSA private key, refusing one below MinClientKeyBits.
func ClientKeyFromRSA(private *rsa.PrivateKey) (*ClientKey, error) {
	if bits := private.N.BitLen(); bits < MinClientKeyBits {
		return nil, fmt.Errorf("keycloak: the client key is %d bits; at least %d are required", bits, MinClientKeyBits)
	}
	return &ClientKey{ID: Thumbprint(&private.PublicKey), private: private}, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of an RSA public key.
func Thumbprint(public *rsa.PublicKey) string {
	canonical := `{"e":"` + b64(big.NewInt(int64(public.E)).Bytes()) + `","kty":"RSA","n":"` + b64(public.N.Bytes()) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

// ClientAssertion signs an RFC 7523 client assertion: the client names itself as issuer and
// subject, the realm's issuer is the audience, and a fresh jti makes it single-use.
func (k *ClientKey) ClientAssertion(clientID, audience string, now time.Time) (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("keycloak: minting a jti: %w", err)
	}
	header, err := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "kid": k.ID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": audience, "jti": b64(nonce[:]),
		"iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPSS(rand.Reader, k.private, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", fmt.Errorf("keycloak: signing the client assertion: %w", err)
	}
	return input + "." + b64(signature), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
