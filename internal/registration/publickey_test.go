package registration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// testKeyPair is a client key pair as a client would hold it: the private key it signs with, and
// the public JWK it submits.
type testKeyPair struct {
	private *rsa.PrivateKey
	public  json.RawMessage
	kid     string
}

// testKey is a fresh key pair. Thumbprints are unique across every client, so no two registrations
// in one run may share a pair.
func testKey(t *testing.T) testKeyPair {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, keycloak.MinClientKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	return pairFrom(t, private)
}

func pairFrom(t *testing.T, private *rsa.PrivateKey) testKeyPair {
	t.Helper()
	kid := keycloak.Thumbprint(&private.PublicKey)
	public, err := json.Marshal(map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "PS256",
		"n": b64(private.N.Bytes()), "e": b64(big.NewInt(int64(private.E)).Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	return testKeyPair{private: private, public: public, kid: kid}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwkWith is a key's JWK with members changed: a value of nil removes the member.
func jwkWith(t *testing.T, key testKeyPair, change map[string]any) json.RawMessage {
	t.Helper()
	var members map[string]any
	if err := json.Unmarshal(key.public, &members); err != nil {
		t.Fatal(err)
	}
	for member, value := range change {
		if value == nil {
			delete(members, member)
			continue
		}
		members[member] = value
	}
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAPublicKeyIsRegisteredAsItsPublicMembersOnly(t *testing.T) {
	key := testKey(t)
	parsed, err := parsePublicKey(key.public)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Thumbprint != keycloak.Thumbprint(&key.private.PublicKey) || parsed.JWK.KID != key.kid ||
		parsed.JWK.N != b64(key.private.N.Bytes()) || parsed.JWK.E != "AQAB" {
		t.Errorf("parsed = %+v", parsed)
	}

	// A key naming no kid, no algorithm and no use is registered under its thumbprint.
	bare, err := parsePublicKey(jwkWith(t, key, map[string]any{"kid": nil, "alg": nil, "use": nil}))
	if err != nil {
		t.Fatal(err)
	}
	if bare.JWK.KID != parsed.Thumbprint {
		t.Errorf("a key without a kid was registered as %q, want its thumbprint", bare.JWK.KID)
	}

	// A modulus sent with a leading zero byte is the same key, and is recorded without it.
	padded, err := parsePublicKey(jwkWith(t, key, map[string]any{"n": b64(append([]byte{0}, key.private.N.Bytes()...))}))
	if err != nil {
		t.Fatal(err)
	}
	if padded.Thumbprint != parsed.Thumbprint || padded.JWK.N != parsed.JWK.N {
		t.Error("a zero-padded modulus was recorded as a different key")
	}
}

// A private member is refused as private material, whatever else the key carries, and no part of
// the key reaches the error.
func TestAPrivateKeyIsRefusedAndNeverEchoed(t *testing.T) {
	key := testKey(t)
	secret := b64(key.private.D.Bytes())
	for _, member := range privateMembers {
		_, err := parsePublicKey(jwkWith(t, key, map[string]any{member: secret}))
		if !errors.Is(err, ErrPrivateKey) {
			t.Errorf("a key carrying %q answered %v, want ErrPrivateKey", member, err)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), key.kid) {
			t.Errorf("the refusal of %q echoes the key: %v", member, err)
		}
	}
	// Even a key that is wrong in every other way is named as private first.
	if _, err := parsePublicKey(json.RawMessage(`{"kty":"oct","k":"c2VjcmV0"}`)); !errors.Is(err, ErrPrivateKey) {
		t.Errorf("a symmetric key answered %v, want ErrPrivateKey", err)
	}
}

func TestAPublicKeyOutsideTheProfileIsRefused(t *testing.T) {
	key := testKey(t)
	short, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]json.RawMessage{
		"nothing":             nil,
		"null":                json.RawMessage(`null`),
		"not an object":       json.RawMessage(`"a key"`),
		"a 2048-bit key":      pairFrom(t, short).public,
		"an EC key":           jwkWith(t, key, map[string]any{"kty": "EC"}),
		"RS256":               jwkWith(t, key, map[string]any{"alg": "RS256"}),
		"alg none":            jwkWith(t, key, map[string]any{"alg": "none"}),
		"for encryption":      jwkWith(t, key, map[string]any{"use": "enc"}),
		"a certificate chain": jwkWith(t, key, map[string]any{"x5c": []string{"MIIB"}}),
		"a key URL":           jwkWith(t, key, map[string]any{"x5u": "https://keys.example.com"}),
		"a number member":     jwkWith(t, key, map[string]any{"e": 65537}),
		"no modulus":          jwkWith(t, key, map[string]any{"n": nil}),
		"a padded modulus":    jwkWith(t, key, map[string]any{"n": b64(key.private.N.Bytes()) + "=="}),
		"an even exponent":    jwkWith(t, key, map[string]any{"e": b64([]byte{0x01, 0x00, 0x00})}),
		"an exponent of one":  jwkWith(t, key, map[string]any{"e": b64([]byte{0x01})}),
		"a huge exponent":     jwkWith(t, key, map[string]any{"e": b64([]byte{1, 2, 3, 4, 5})}),
		"a kid with a space":  jwkWith(t, key, map[string]any{"kid": "my key"}),
		"a kid too long":      jwkWith(t, key, map[string]any{"kid": strings.Repeat("k", 129)}),
	} {
		if _, err := parsePublicKey(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s answered %v, want ErrInvalid", name, err)
		}
	}
}

// The client a registration describes holds its keys only when its profile authenticates with one.
func TestTheSpecHoldsKeysOnlyForAKeyedProfile(t *testing.T) {
	keys := []keycloak.JWK{{KID: "k1", N: "bg", E: "AQAB"}}
	confidential := spec(Registration{ClientKey: "bff", Profile: ProfileConfidential, RedirectURIs: []string{"https://a"},
		AccessTokenLifespan: 540}, keys)
	if !confidential.Confidential || len(confidential.Keys) != 1 || confidential.Validate() != nil {
		t.Errorf("confidential spec = %+v", confidential)
	}
	workload := spec(Registration{ClientKey: "job", Profile: ProfileWorkload, AccessTokenLifespan: 540}, keys)
	if !workload.Workload || len(workload.Keys) != 1 || workload.Validate() != nil {
		t.Errorf("workload spec = %+v", workload)
	}
	public := spec(Registration{ClientKey: "web", Profile: ProfilePublic, RedirectURIs: []string{"https://a"},
		AccessTokenLifespan: 540}, keys)
	if !public.Public || len(public.Keys) != 0 {
		t.Errorf("public spec = %+v", public)
	}
}

// validate refuses what needs nothing but the request, before any key is parsed or anything is read.
func TestValidationRefusesAProfileItsShapeContradicts(t *testing.T) {
	caller := [16]byte{1}
	base := Request{RegisteredBy: caller, ClientKey: "c", ApplicationRef: "app", AudienceClass: "internal"}
	for name, c := range map[string]struct {
		change func(*Request)
		ok     bool
	}{
		"a confidential client": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfileConfidential, []string{"https://a.example.com/cb"}
		}, true},
		"a confidential client, no redirect": {func(r *Request) { r.Profile = ProfileConfidential }, false},
		"a workload":                         {func(r *Request) { r.Profile, r.AudienceClass = ProfileWorkload, "workload" }, true},
		"a workload with a redirect": {func(r *Request) {
			r.Profile, r.AudienceClass, r.RedirectURIs = ProfileWorkload, "workload", []string{"https://a.example.com/cb"}
		}, false},
		"a workload in the internal class": {func(r *Request) { r.Profile = ProfileWorkload }, false},
		"a public client with a key": {func(r *Request) {
			r.Profile, r.RedirectURIs, r.PublicKey = ProfilePublic, []string{"https://a.example.com/cb"}, json.RawMessage(`{}`)
		}, false},
		"a resource with a key": {func(r *Request) {
			r.Profile, r.LifetimeClass, r.PublicKey = ProfileResource, "L1", json.RawMessage(`{}`)
		}, false},
		"a public client with a null key": {func(r *Request) {
			r.Profile, r.RedirectURIs, r.PublicKey = ProfilePublic, []string{"https://a.example.com/cb"}, json.RawMessage(`null`)
		}, true},
		// ADR-IAM-009 §5.1: a back end that holds sessions receives logout tokens, at an absolute URI
		// with no fragment (OpenID Connect Back-Channel Logout 1.0 §2.2).
		"a confidential client with a back-channel logout URI": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfileConfidential, []string{"https://a.example.com/cb"}
			r.BackChannelLogoutURI = "https://a.example.com/auth/back-channel-logout"
		}, true},
		"a confidential client with an http back-channel logout URI": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfileConfidential, []string{"https://a.example.com/cb"}
			r.BackChannelLogoutURI = "http://bff.internal:8090/auth/back-channel-logout"
		}, true},
		"a public client with a back-channel logout URI": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfilePublic, []string{"https://a.example.com/cb"}
			r.BackChannelLogoutURI = "https://a.example.com/logout"
		}, false},
		"a workload with a back-channel logout URI": {func(r *Request) {
			r.Profile, r.AudienceClass, r.BackChannelLogoutURI = ProfileWorkload, "workload", "https://a.example.com/logout"
		}, false},
		"a back-channel logout URI with a fragment": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfileConfidential, []string{"https://a.example.com/cb"}
			r.BackChannelLogoutURI = "https://a.example.com/logout#x"
		}, false},
		"a relative back-channel logout URI": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfileConfidential, []string{"https://a.example.com/cb"}
			r.BackChannelLogoutURI = "/auth/back-channel-logout"
		}, false},
		"a back-channel logout URI with credentials": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfileConfidential, []string{"https://a.example.com/cb"}
			r.BackChannelLogoutURI = "https://user:pw@a.example.com/logout"
		}, false},
		"a back-channel logout URI on another scheme": {func(r *Request) {
			r.Profile, r.RedirectURIs = ProfileConfidential, []string{"https://a.example.com/cb"}
			r.BackChannelLogoutURI = "ftp://a.example.com/logout"
		}, false},
	} {
		req := base
		c.change(&req)
		err := validate(req)
		if c.ok && err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
		if !c.ok && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s answered %v, want ErrInvalid", name, err)
		}
	}
}
