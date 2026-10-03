package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/providerauthority"
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

// This service is a `privileged` audience (STD-IAM-002 §3.1.1, §3.2).
//
// It holds the projection of the provider:identity-control grants, so a provider's token carries
// no provider_scope: who is a provider is read from this service's records for each request, by the
// token's principal_id (ADR-ORG-002 §5.3, TDD-identity-control-006). A caller that is not a
// provider is a registration owner, the `resource-scoped` form, whose authority is the ownership
// recorded for the registration a request names. Both forms present the same token: principal_id,
// subject_type human, acr and auth_time, and no tenant_id. `privileged` makes `acr` and `auth_time`
// mandatory, and `L0` fixes the lifetime at four minutes.
const (
	// ProviderScopeClaim is read only to refuse it. No resource checks a provider grant from a
	// claim and none is issued (STD-IAM-002 §3.1.1), so a token carrying one was minted by a
	// client still configured for the old profile, and is refused rather than read as an owner's.
	ProviderScopeClaim = "provider_scope"

	// TenantIDClaim is read only to reject it. This service's operations belong to no Tenant,
	// and a token asserting one was minted for the tenant-scoped form (§3.5 rule 9).
	TenantIDClaim = "tenant_id"

	// AuthContextClassClaim and AuthTimeClaim are the elevated assurance claims §3.2 makes
	// mandatory for every privileged token.
	AuthContextClassClaim = "acr"
	AuthTimeClaim         = "auth_time"
)

// Requirement is the claim rule this service supplies to the shared verifier.
//
// It implements the `privileged` column of STD-IAM-002 §3.2 plus rules 7, 9 and 10 of §3.5. Each
// check is a rejection the standard states, and the prohibitions matter as much as the
// requirements: a claim that MUST NOT be present is one whose presence means the token was minted
// for a different form than the one enforced here.
//
// No message includes a claim value. The verifier wraps this error and a caller may log it, so a
// value quoted here would travel further than the token did.
func Requirement() verify.ClaimRequirement {
	return verify.RequirementFunc(func(claims verify.Claims) error {
		// §3.5 rule 7 — the canonical identifier. A partially migrated estate in which some
		// domains key on `sub` and others on `principal_id` is worse than either choice applied
		// consistently. It is the key the provider decision reads, so it must be one.
		principal, ok := claims.String(PrincipalIDClaim)
		if !ok {
			return fmt.Errorf("the %s claim is absent", PrincipalIDClaim)
		}
		if _, err := id.Parse(principal); err != nil {
			return fmt.Errorf("the %s claim is not a UUID", PrincipalIDClaim)
		}

		// §3.5 rule 10 — a provider and an owner are both people. A workload's token is never an
		// owner's, and a workload holds no provider authority here.
		subjectType, ok := claims.String(SubjectTypeClaim)
		if !ok {
			return fmt.Errorf("the %s claim is absent", SubjectTypeClaim)
		}
		if subjectType != "human" {
			return fmt.Errorf("the %s claim is not human", SubjectTypeClaim)
		}

		switch {
		case claims.Has(ProviderScopeClaim):
			return fmt.Errorf("the %s claim is not accepted; provider authority is read from this service's records", ProviderScopeClaim)
		case claims.Has(TenantIDClaim):
			return fmt.Errorf("the %s claim is prohibited on this audience", TenantIDClaim)
		}

		// §3.2 — elevated assurance is mandatory for privileged. Without `auth_time` a step-up
		// requirement cannot be evaluated at all, so its absence is a rejection rather than a
		// downgrade to whatever the token happens to carry.
		if _, ok := claims.String(AuthContextClassClaim); !ok {
			return fmt.Errorf("the %s claim is absent", AuthContextClassClaim)
		}
		if _, ok := claims.Int64(AuthTimeClaim); !ok {
			return fmt.Errorf("the %s claim is absent", AuthTimeClaim)
		}
		return nil
	})
}

// ProviderDecider decides whether the caller is a provider for this request:
// *providerauthority.Decider in production.
type ProviderDecider interface {
	Decide(ctx context.Context, principal id.UUID) (providerauthority.Decision, error)
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
//
// Provider authority is decided here, after verification, from this service's records
// (TDD-identity-control-006 §The Provider Decision). A decision that cannot be read answers 503:
// serving the caller as an owner would turn an unreadable record into a quiet downgrade, and
// serving it as a provider would fail open.
func Authenticate(verifier TokenVerifier, providers ProviderDecider, logger *slog.Logger) (fhttp.Middleware, error) {
	if verifier == nil {
		return nil, errors.New("httpapi: a token verifier is required")
	}
	if providers == nil {
		return nil, errors.New("httpapi: a provider decision is required")
	}
	if logger == nil {
		return nil, errors.New("httpapi: a logger is required")
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
			parsed, err := id.Parse(principal)
			if err != nil {
				fhttp.Problem(w, r, fhttp.AuthenticationRequired,
					"The bearer token is not valid for this resource")
				return
			}
			ctx := WithCallerScope(r.Context(), "principal:"+principal)
			// The Requirement refused a token without them, so both are present: how and when the
			// caller last authenticated, which a command's step-up reads (RFC 9470).
			acr, _ := claims.String(AuthContextClassClaim)
			authTime, _ := claims.Int64(AuthTimeClaim)
			ctx = WithAssurance(ctx, acr, time.Unix(authTime, 0).UTC())
			// The Keycloak session the token belongs to, which a person's own session list marks as
			// current (STD-IAM-002 §3.2 admits sid; TDD-identity-control-005 §Self-Service as Built).
			if sid, ok := claims.String("sid"); ok {
				ctx = WithSessionID(ctx, sid)
			}

			// A provider is a Principal this service's records say is one, for this request. Any
			// other caller is a registration owner, whose authority is read per route from the
			// ownership records (TDD-identity-control-003 §Registration Ownership).
			decision, err := providers.Decide(ctx, parsed)
			if err != nil {
				logger.ErrorContext(ctx, "the provider decision could not be read",
					slog.String("principal_id", principal), slog.String("error", err.Error()))
				fhttp.Problem(w, r, fhttp.DependencyUnavailable,
					"Provider authority could not be determined")
				return
			}
			switch {
			case decision.Provider:
				ctx = withProvider(ctx, decision.Emergency)
				// Every use of break-glass authority is reported (ADR-ORG-002 §5.2).
				if decision.Emergency {
					logger.WarnContext(ctx, "emergency provider authority used",
						slog.String("principal_id", principal), slog.String("basis", decision.Basis),
						slog.String("method", r.Method), slog.String("path", r.URL.Path))
				}
			case decision.Stale:
				logger.WarnContext(ctx, "an activation in force was not honored; the provider projection is stale",
					slog.String("principal_id", principal), slog.String("reason", decision.StaleReason))
			}
			next.ServeHTTP(w, r.WithContext(ctx))
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

// ReportTokenType wraps a verifier for IDENTITY_TOKEN_TYPE=report. A token whose header typ is not
// at+jwt is accepted, as the verifier without RequireAccessTokenType accepts it, and logged with the
// client it was issued to, so an operator sees which clients still need the token profile before the
// server moves to enforce (TDD-identity-control-001 §Caller Token). The log carries no claim value
// but the client identifier.
func ReportTokenType(verifier TokenVerifier, logger *slog.Logger) TokenVerifier {
	return reportingVerifier{verifier: verifier, logger: logger}
}

type reportingVerifier struct {
	verifier TokenVerifier
	logger   *slog.Logger
}

func (v reportingVerifier) Verify(token string) (verify.Claims, error) {
	claims, err := v.verifier.Verify(token)
	if err != nil {
		return claims, err
	}
	if typ := claims.TokenType(); !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		client, _ := claims.String("azp")
		v.logger.Warn("a caller's token is not typed at+jwt; IDENTITY_TOKEN_TYPE=enforce would refuse it",
			slog.String("typ", typ), slog.String("client", client))
	}
	return claims, nil
}
