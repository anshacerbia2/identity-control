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

// This service is a `privileged` audience in the `provider-scope` form, per STD-IAM-002 §3.1.1.
//
// The classification is not a label; it decides four things at once. Creating a Principal is
// irreversible, so the audience class is `privileged` rather than `internal`. It belongs to no
// Tenant, so the scope form is `provider-scope`: `provider_scope` is mandatory and `tenant_id` is
// prohibited. `privileged` makes `acr` and `auth_time` mandatory. And `L0` fixes the token
// lifetime at four minutes, which is the tightest class the profile defines.
//
// Classifying it as `internal` — which an earlier revision of the local realm did — would have
// required `tenant_id` on a token whose action has no Tenant, and would have permitted a
// fifteen-minute lifetime on the one surface that can mint enterprise identities.
const (
	// ProviderScopeClaim names the bounded provider authority the operation runs under.
	ProviderScopeClaim = "provider_scope"

	// TenantIDClaim is read only to reject it. A provider-scope token asserting a Tenant is a
	// token whose scope form cannot be determined, and §3.5 rule 9 refuses that rather than
	// guessing the narrower reading.
	TenantIDClaim = "tenant_id"

	// AuthContextClassClaim and AuthTimeClaim are the elevated assurance claims §3.2 makes
	// mandatory for every privileged token.
	AuthContextClassClaim = "acr"
	AuthTimeClaim         = "auth_time"
)

// ProviderScopeIdentityControl is the only scope this service accepts.
//
// A registered value rather than any non-empty string, per §3.1.1: an unregistered or unbounded
// scope is refused, because "all Tenants" is precisely what PAD-PLT-002 §5.2 requires cross-tenant
// administration never to be.
const ProviderScopeIdentityControl = "provider:identity-control"

// Requirement is the claim rule this service supplies to the shared verifier.
//
// It implements the `privileged` / `provider-scope` column of STD-IAM-002 §3.2 plus rules 7, 8,
// and 9 of §3.5. Each check is a rejection the standard states, and the prohibitions matter as
// much as the requirements: a claim that MUST NOT be present is one whose presence means the token
// was minted for a different scope form than the one being enforced here.
//
// No message includes a claim value. The verifier wraps this error and a caller may log it, so a
// value quoted here would travel further than the token did.
func Requirement() verify.ClaimRequirement {
	return verify.RequirementFunc(func(claims verify.Claims) error {
		// §3.5 rule 7 — the canonical identifier. A partially migrated estate in which some
		// domains key on `sub` and others on `principal_id` is worse than either choice applied
		// consistently.
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

		// §3.5 rule 9 — the scope form must be unambiguous. Both claims present, or neither,
		// leaves the token's bounded authority undetermined.
		scope, hasScope := claims.String(ProviderScopeClaim)
		_, hasTenant := claims.String(TenantIDClaim)
		switch {
		case hasScope && hasTenant:
			return fmt.Errorf("the token carries both %s and %s", ProviderScopeClaim, TenantIDClaim)
		case hasTenant:
			return fmt.Errorf("the %s claim is prohibited on a provider-scope audience", TenantIDClaim)
		case !hasScope:
			return fmt.Errorf("the %s claim is absent", ProviderScopeClaim)
		case scope != ProviderScopeIdentityControl:
			return fmt.Errorf("the %s claim is not a scope this resource accepts", ProviderScopeClaim)
		}

		// §3.2 — elevated assurance is mandatory for privileged, in both scope forms. Without
		// `auth_time` a step-up requirement cannot be evaluated at all, so its absence is a
		// rejection rather than a downgrade to whatever the token happens to carry.
		if _, ok := claims.String(AuthContextClassClaim); !ok {
			return fmt.Errorf("the %s claim is absent", AuthContextClassClaim)
		}
		if _, ok := claims.Int64(AuthTimeClaim); !ok {
			return fmt.Errorf("the %s claim is absent", AuthTimeClaim)
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
