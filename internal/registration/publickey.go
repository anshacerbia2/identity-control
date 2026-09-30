package registration

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// ErrPrivateKey is a submitted key carrying private material. The key is refused and nothing of it
// is recorded or logged. Whoever sent it has exposed it, so the message says to generate another
// rather than to fix the request.
var ErrPrivateKey = errors.New("registration: the key carries private material and is refused; " +
	"it has been exposed by being sent, so generate a new key pair and submit only its public key")

// privateMembers are the JWK members that carry private material: RSA's private exponent and CRT
// values, the other-primes list, and a symmetric key's value. client_key_public_only refuses the
// same list in the database.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// publicMembers are the only members a submitted key may carry. Anything else is refused rather
// than dropped, so a caller is never told a key was accepted that differs from the one it sent.
var publicMembers = map[string]bool{"kty": true, "kid": true, "use": true, "alg": true, "n": true, "e": true}

var kidPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// PublicKey is a submitted key once validated: the JWK the kernel is given, and the RFC 7638
// thumbprint that makes one key pair belong to one client only.
type PublicKey struct {
	JWK        keycloak.JWK
	Thumbprint string
}

// parsePublicKey validates a submitted JWK against TDD-identity-control-003 §Validation: an RSA
// public key of at least keycloak.MinClientKeyBits, for signatures, PS256 if it names an algorithm,
// and nothing private. A key naming no kid is registered under its thumbprint, which is what every
// Scnehaux key tool names its keys by.
//
// No error message carries any part of the key: a refused key is never echoed.
func parsePublicKey(raw json.RawMessage) (PublicKey, error) {
	invalid := func(rule string) error { return fmt.Errorf("%w: public_key %s", ErrInvalid, rule) }

	if len(strings.TrimSpace(string(raw))) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return PublicKey{}, invalid("is required: a confidential or workload client authenticates with a registered key")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return PublicKey{}, invalid("must be a JWK object")
	}
	// Private material first, so a private key is always named as one, whatever else is wrong with it.
	for _, member := range privateMembers {
		if _, ok := members[member]; ok {
			return PublicKey{}, ErrPrivateKey
		}
	}
	values := map[string]string{}
	for member, value := range members {
		if !publicMembers[member] {
			return PublicKey{}, invalid("may carry only kty, kid, use, alg, n and e")
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return PublicKey{}, invalid("members must be strings")
		}
		values[member] = text
	}

	switch {
	case values["kty"] != "RSA":
		return PublicKey{}, invalid("must be an RSA key")
	case values["alg"] != "" && values["alg"] != "PS256":
		return PublicKey{}, invalid("must name PS256 if it names an algorithm (STD-IAM-001 §3.2)")
	case values["use"] != "" && values["use"] != "sig":
		return PublicKey{}, invalid("must be for signatures if it names a use")
	}

	modulus, err := base64.RawURLEncoding.DecodeString(values["n"])
	if err != nil || len(modulus) == 0 {
		return PublicKey{}, invalid("must carry its modulus n, base64url without padding")
	}
	exponent, err := base64.RawURLEncoding.DecodeString(values["e"])
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return PublicKey{}, invalid("must carry its exponent e, base64url without padding")
	}
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}
	switch {
	case public.N.BitLen() < keycloak.MinClientKeyBits:
		return PublicKey{}, invalid(fmt.Sprintf("must be at least %d bits (STD-IAM-001 §3.2)", keycloak.MinClientKeyBits))
	case public.E < 3 || public.E%2 == 0:
		return PublicKey{}, invalid("has an exponent no RSA key uses")
	}

	thumbprint := keycloak.Thumbprint(public)
	kid := values["kid"]
	if kid == "" {
		kid = thumbprint
	}
	if !kidPattern.MatchString(kid) {
		return PublicKey{}, invalid("kid must be 1 to 128 letters, digits, '.', '_' or '-'")
	}
	// Re-encoded rather than stored as sent, so the recorded key is exactly its public members and a
	// modulus sent with a leading zero byte is the same key as one sent without.
	return PublicKey{
		JWK: keycloak.JWK{
			KID: kid,
			N:   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		},
		Thumbprint: thumbprint,
	}, nil
}

// submitted reports whether a request carries a public key at all.
func submitted(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}
