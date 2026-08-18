package httpapi_test

// The middleware is tested through a real verifier and real signed tokens, not through a fake
// claim set. verify.Claims populates its extras only from a verified payload, so a hand-built one
// could not carry `principal_id` at all — and the property under test is precisely that the
// caller scope comes from a claim the issuer signed.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
)

const (
	authIssuer   = "https://identity.scnehaux.com/realms/scnehaux"
	authAudience = "identity-control"
	authKeyID    = "key-2026-08"
)

var (
	authKey  *rsa.PrivateKey
	authNow  = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	authOnce = func() *rsa.PrivateKey {
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			panic(err)
		}
		return key
	}
)

func signingKeyForAuth(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	if authKey == nil {
		authKey = authOnce()
	}
	return authKey
}

// realVerifier builds the verifier this service actually configures, including its own claim rule.
func realVerifier(t *testing.T) *verify.Verifier {
	t.Helper()
	v, err := verify.New(verify.Config{
		Issuer:      authIssuer,
		Audience:    authAudience,
		Keys:        verify.StaticKeys{authKeyID: &signingKeyForAuth(t).PublicKey},
		Requirement: httpapi.Requirement(),
		Now:         func() time.Time { return authNow },
	})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return v
}

// token signs a compact token carrying the supplied claims over the valid registered set.
func token(t *testing.T, extra map[string]any) string {
	t.Helper()

	payload := map[string]any{
		"iss": authIssuer,
		"sub": "protocol-subject",
		"aud": []string{authAudience},
		"iat": authNow.Add(-time.Minute).Unix(),
		"exp": authNow.Add(10 * time.Minute).Unix(),
	}
	for name, value := range extra {
		payload[name] = value
	}

	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}

	signed := encode(map[string]any{"alg": "PS256", "kid": authKeyID, "typ": "JWT"}) + "." + encode(payload)

	digest := crypto.SHA256.New()
	digest.Write([]byte(signed))
	signature, err := rsa.SignPSS(rand.Reader, signingKeyForAuth(t), crypto.SHA256, digest.Sum(nil),
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("SignPSS: %v", err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func validClaims() map[string]any {
	return map[string]any{
		"principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71",
		"subject_type": "human",
	}
}

// scopeEcho reports the caller scope the middleware established, so a test can assert what
// reached the handler rather than what the middleware was given.
func scopeEcho(t *testing.T, verifier httpapi.TokenVerifier) http.Handler {
	t.Helper()
	middleware, err := httpapi.Authenticate(verifier)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope, ok := httpapi.CallerScope(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("no caller scope reached the handler"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(scope))
	}))
}

func bearerRequest(header string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/principals", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

// TestCallerScopeComesFromTheSignedClaim is the property the whole idempotency model rests on. A
// scope derived from the request would let one caller claim or replay another caller's key, and
// scoping keys per caller is worth nothing if the caller names itself.
func TestCallerScopeComesFromTheSignedClaim(t *testing.T) {
	w := httptest.NewRecorder()
	scopeEcho(t, realVerifier(t)).ServeHTTP(w,
		bearerRequest("Bearer "+token(t, validClaims())))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "principal:019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71" {
		t.Errorf("caller scope = %q", got)
	}
}

// TestTheScopeIsNotTheProtocolSubject states why `sub` is not used. `sub` is issuer-scoped and may
// be pairwise, so two tokens for one Principal can carry different values — which would let the
// same caller claim two idempotency keys and defeat the deduplication the key exists for.
func TestTheScopeIsNotTheProtocolSubject(t *testing.T) {
	w := httptest.NewRecorder()
	scopeEcho(t, realVerifier(t)).ServeHTTP(w,
		bearerRequest("Bearer "+token(t, validClaims())))

	if strings.Contains(w.Body.String(), "protocol-subject") {
		t.Errorf("the caller scope is derived from sub: %s", w.Body.String())
	}
}

// TestARequestHeaderCannotChangeTheCaller closes the substitution attack directly.
func TestARequestHeaderCannotChangeTheCaller(t *testing.T) {
	request := bearerRequest("Bearer " + token(t, validClaims()))
	request.Header.Set("X-Caller-Scope", "principal:someone-else")
	request.Header.Set("X-Principal-Id", "019235f1-0000-7000-8000-000000000000")

	w := httptest.NewRecorder()
	scopeEcho(t, realVerifier(t)).ServeHTTP(w, request)

	if got := w.Body.String(); got != "principal:019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71" {
		t.Errorf("a request header changed the caller scope: %q", got)
	}
}

// TestAbsentOrMalformedCredentialIsRefusedWithoutVerifying covers the shapes a client sends by
// accident and the ones an attacker sends on purpose. None reaches the verifier, so a malformed
// header costs no signature check.
func TestAbsentOrMalformedCredentialIsRefusedWithoutVerifying(t *testing.T) {
	cases := map[string]string{
		"absent":               "",
		"no scheme":            "abc.def.ghi",
		"wrong scheme":         "Basic dXNlcjpwYXNz",
		"bearer with no token": "Bearer",
		"bearer with spaces":   "Bearer    ",
	}

	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			counted := &countingVerifier{inner: realVerifier(t)}
			w := httptest.NewRecorder()
			scopeEcho(t, counted).ServeHTTP(w, bearerRequest(header))

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}
			if counted.calls != 0 {
				t.Errorf("the verifier ran %d times for a malformed credential", counted.calls)
			}
		})
	}
}

// TestSchemeIsCaseInsensitiveAndTokenIsNot is RFC 7235 for the scheme and opacity for the token.
// Normalising the token would accept a variant the issuer never signed.
func TestSchemeIsCaseInsensitiveAndTokenIsNot(t *testing.T) {
	signed := token(t, validClaims())

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			counted := &countingVerifier{inner: realVerifier(t)}
			w := httptest.NewRecorder()
			scopeEcho(t, counted).ServeHTTP(w, bearerRequest(scheme+" "+signed))

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d for scheme %q: %s", w.Code, scheme, w.Body.String())
			}
			if counted.lastToken != signed {
				t.Error("the token was modified before verification")
			}
		})
	}

	// The token itself is case sensitive: a flipped character is a different signature input.
	flipped := strings.ToUpper(signed[:1]) + signed[1:]
	if flipped != signed {
		w := httptest.NewRecorder()
		scopeEcho(t, realVerifier(t)).ServeHTTP(w, bearerRequest("Bearer "+flipped))
		if w.Code == http.StatusOK {
			t.Error("a token with a flipped character was accepted")
		}
	}
}

// TestEveryRejectionProducesTheSameDocument is deliberate. The distinction between a bad signature
// and a wrong audience matters to an operator reading logs and not to the presenter of the token,
// and revealing it tells an attacker which half of a forgery to fix.
func TestEveryRejectionProducesTheSameDocument(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	forged := func(t *testing.T) string {
		t.Helper()
		payload := map[string]any{
			"iss": authIssuer, "sub": "s", "aud": []string{authAudience},
			"exp": authNow.Add(time.Minute).Unix(),
		}
		for k, v := range validClaims() {
			payload[k] = v
		}
		encode := func(value any) string {
			raw, _ := json.Marshal(value)
			return base64.RawURLEncoding.EncodeToString(raw)
		}
		signed := encode(map[string]any{"alg": "PS256", "kid": authKeyID}) + "." + encode(payload)
		digest := crypto.SHA256.New()
		digest.Write([]byte(signed))
		signature, _ := rsa.SignPSS(rand.Reader, other, crypto.SHA256, digest.Sum(nil),
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
	}

	rejected := map[string]string{
		"bad signature":   forged(t),
		"wrong audience":  token(t, map[string]any{"aud": []string{"organization-control"}, "principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71", "subject_type": "human"}),
		"expired":         token(t, map[string]any{"exp": authNow.Add(-time.Hour).Unix(), "principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71", "subject_type": "human"}),
		"no principal_id": token(t, map[string]any{"subject_type": "human"}),
		"no subject_type": token(t, map[string]any{"principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71"}),
		"unknown subject": token(t, map[string]any{"principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71", "subject_type": "service"}),
		"malformed":       "not.a.token",
	}

	var bodies []string
	for name, signed := range rejected {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			scopeEcho(t, realVerifier(t)).ServeHTTP(w, bearerRequest("Bearer "+signed))

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			for _, leak := range []string{"signature", "issuer", "audience", "expired", "kid", "principal_id", "subject_type"} {
				if strings.Contains(strings.ToLower(body), leak) {
					t.Errorf("the response names %q: %s", leak, body)
				}
			}
			bodies = append(bodies, body)
		})
	}

	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("rejection documents differ, so they distinguish the failure:\n%s\n%s",
				bodies[0], bodies[i])
		}
	}
}

// TestRequirementRejectsEitherMissingClaim exercises the rule this service supplies. It is where
// STD-IAM-002 §3.5 rule 6 is enforced, because foundation-platform may not name the claim.
func TestRequirementRejectsEitherMissingClaim(t *testing.T) {
	cases := map[string]map[string]any{
		"neither claim":        {},
		"no principal_id":      {"subject_type": "human"},
		"no subject_type":      {"principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71"},
		"unknown subject type": {"principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71", "subject_type": "agent"},
	}

	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := realVerifier(t).Verify(token(t, claims)); err == nil {
				t.Fatal("the requirement accepted a token it should refuse")
			}
		})
	}

	// A workload token satisfies the rule too: the claim must be one of the two values, not one
	// specific value.
	if _, err := realVerifier(t).Verify(token(t, map[string]any{
		"principal_id": "019236a1-8c4a-7c1e-9d0b-3f4a2b6e5d71", "subject_type": "workload",
	})); err != nil {
		t.Errorf("a workload token was refused: %v", err)
	}
}

// TestRequirementMessagesNameTheClaimAndNotItsValue matters because the verifier wraps this error
// and a caller may log it. A value quoted here would travel further than the token did.
func TestRequirementMessagesNameTheClaimAndNotItsValue(t *testing.T) {
	_, err := realVerifier(t).Verify(token(t, map[string]any{
		"principal_id": "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71", "subject_type": "agent",
	}))
	if err == nil {
		t.Fatal("an unknown subject_type was accepted")
	}
	if !strings.Contains(err.Error(), httpapi.SubjectTypeClaim) {
		t.Errorf("the error does not name the offending claim: %v", err)
	}
	for _, value := range []string{"agent", "019235f1-8c4a-7c1e-9d0b-3f4a2b6e5d71"} {
		if strings.Contains(err.Error(), value) {
			t.Errorf("the error quotes a claim value %q: %v", value, err)
		}
	}
}

func TestAuthenticateRejectsANilVerifier(t *testing.T) {
	if _, err := httpapi.Authenticate(nil); err == nil {
		t.Fatal("Authenticate accepted a nil verifier")
	}
}

// countingVerifier wraps a real verifier and records how it was called.
type countingVerifier struct {
	inner     httpapi.TokenVerifier
	calls     int
	lastToken string
}

func (c *countingVerifier) Verify(token string) (verify.Claims, error) {
	c.calls++
	c.lastToken = token
	return c.inner.Verify(token)
}
