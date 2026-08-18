package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/verify"
)

// PrincipalIDClaim is the canonical enterprise subject identifier.
//
// The name lives here rather than in foundation-platform because that module is forbidden from
// naming a domain concept. STD-IAM-002 §3.5 requires this claim on every internal, privileged,
// and workload audience token, and this package is the closest place to the boundary that is
// allowed to say so.
const PrincipalIDClaim = "principal_id"

// SubjectTypeClaim distinguishes a human Principal from a workload one.
const SubjectTypeClaim = "subject_type"

// Requirement is the claim rule this service supplies to the shared verifier.
//
// Two checks, and neither is decoration. STD-IAM-002 §3.5 rule 6 rejects an internal-audience
// token without `principal_id`, because a partially migrated estate in which some domains key on
// `sub` and others on `principal_id` is worse than either choice applied consistently. And
// §3.2.1 requires `subject_type`, because a product enforcing a rule that applies only to humans
// reads that claim rather than inferring from a naming convention.
//
// Neither message includes a claim value. The verifier wraps this error and a caller may log it,
// so a value quoted here would travel further than the token did.
func Requirement() verify.ClaimRequirement {
	return verify.RequirementFunc(func(claims verify.Claims) error {
		if _, ok := claims.String(PrincipalIDClaim); !ok {
			return fmt.Errorf("the %s claim is absent", PrincipalIDClaim)
		}
		subjectType, ok := claims.String(SubjectTypeClaim)
		if !ok {
			return fmt.Errorf("the %s claim is absent", SubjectTypeClaim)
		}
		if subjectType != "human" && subjectType != "workload" {
			return fmt.Errorf("the %s claim is not human or workload", SubjectTypeClaim)
		}
		return nil
	})
}

// TokenVerifier is the verification this middleware performs.
//
// An interface rather than *verify.Verifier so the middleware can be tested without generating a
// key and signing a token, and so this package depends on the one method it uses.
type TokenVerifier interface {
	Verify(token string) (verify.Claims, error)
}

// Authenticate returns the middleware that establishes the caller.
//
// The caller scope is derived from the verified claims and placed in the context, which is the
// only place CallerScope reads from. A header or body field naming the caller therefore has no
// effect: one caller must not be able to claim or replay another caller's idempotency key, and
// scoping keys per caller is worth nothing if the scope is caller-supplied.
//
// Every failure is 401 with the same problem type and no detail about which check failed. The
// distinction matters to an operator reading logs and not to the presenter of the token, and
// telling a caller whether its signature or its audience was wrong is telling an attacker which
// half of a forgery to fix.
func Authenticate(verifier TokenVerifier) (fhttp.Middleware, error) {
	if verifier == nil {
		return nil, errors.New("httpapi: a token verifier is required")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				fhttp.Problem(w, r, fhttp.AuthenticationRequired,
					"A bearer token is required")
				return
			}

			claims, err := verifier.Verify(token)
			if err != nil {
				fhttp.Problem(w, r, fhttp.AuthenticationRequired,
					"The bearer token is not valid for this resource")
				return
			}

			// The scope is the canonical identifier rather than `sub`. `sub` is the
			// issuer-scoped protocol subject and may be pairwise, so two tokens for one
			// Principal can carry different values — which would let the same caller claim two
			// idempotency keys and defeat the deduplication the key exists for.
			principal, _ := claims.String(PrincipalIDClaim)
			next.ServeHTTP(w, r.WithContext(WithCallerScope(r.Context(), "principal:"+principal)))
		})
	}, nil
}

// bearerToken reads the credential from the Authorization header.
//
// The scheme is matched case-insensitively per RFC 7235 and the token is not. A token is opaque
// bytes, and normalising it would accept a variant the issuer never signed.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}

	scheme, credential, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return "", false
	}
	return credential, true
}
