package httpapi

// Enrolment from an invitation at the transport (ADR-IAM-011 §5.1 to §5.9, TDD-identity-control-001
// 1.27.0 §Enrolment From an Invitation). The two routes are anonymous as to the person and not as to
// the caller: Identity Experience's BFF calls them as a workload registered in
// identity.enrolment_caller, and forwards the client address in Forwarded. They are mounted apart
// from every caller route, behind this verification alone, as the identifier match is.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/observability"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/enrolment"
)

// Enrolments runs the two commands: *enrolment.Service.
type Enrolments interface {
	Request(ctx context.Context, in enrolment.RequestInput) (id.UUID, error)
	Verify(ctx context.Context, in enrolment.VerifyInput) (enrolment.Completed, error)
}

// EnrolmentAdmission reads the record of admitted BFF workloads: *enrolment.Callers.
type EnrolmentAdmission interface {
	Admitted(ctx context.Context, principal id.UUID) (bool, error)
}

// EnrolmentCallerRequirement admits a workload token with no Tenant and no provider scope. Which
// workload may call is the record's question, asked for each request after verification.
func EnrolmentCallerRequirement() verify.ClaimRequirement {
	return verify.RequirementFunc(func(claims verify.Claims) error {
		if _, ok := claims.String(PrincipalIDClaim); !ok {
			return errors.New("the principal_id claim is absent")
		}
		if subjectType, _ := claims.String(SubjectTypeClaim); subjectType != "workload" {
			return errors.New("the subject_type claim is not workload")
		}
		if claims.Has(TenantIDClaim) || claims.Has(ProviderScopeClaim) {
			return errors.New("an enrolment caller's token carries no tenant or provider scope")
		}
		return nil
	})
}

// maxEnrolmentBody bounds one request: a token or a code, in JSON.
const maxEnrolmentBody = 1 << 10

// refusedDetail is the one answer to every refused code (ADR-IAM-011 §5.2, §5.9), the same as an
// address proof's wrong code.
const refusedDetail = "The code is wrong, has expired, or has been tried too often; start again from the invitation link"

// enrolmentRoutes serves both routes behind the caller check.
func enrolmentRoutes(verifier TokenVerifier, callers EnrolmentAdmission, enrolments Enrolments) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if verifier == nil || callers == nil || enrolments == nil {
			fhttp.Problem(w, r, fhttp.DependencyUnavailable, "Enrolment is not configured")
			return
		}
		token, ok := bearerToken(r)
		if !ok {
			fhttp.Problem(w, r, fhttp.AuthenticationRequired, "A bearer token is required")
			return
		}
		claims, err := verifier.Verify(token)
		if err != nil {
			fhttp.Problem(w, r, fhttp.AuthenticationRequired, "The bearer token is not valid for this resource")
			return
		}
		raw, _ := claims.String(PrincipalIDClaim)
		caller, err := id.Parse(raw)
		if err != nil {
			fhttp.Problem(w, r, fhttp.Forbidden, "The token names no workload")
			return
		}
		admitted, err := callers.Admitted(r.Context(), caller)
		switch {
		case err != nil:
			fhttp.Problem(w, r, fhttp.DependencyUnavailable, "The enrolment callers could not be read")
			return
		case !admitted:
			fhttp.Problem(w, r, fhttp.Forbidden, "The workload is not a registered enrolment caller")
			return
		}
		// Read on this workload's call alone, and only now (ADR-IAM-011 §5.8).
		address, ok := ClientAddress(r.Header.Values("Forwarded"))
		if !ok {
			fhttp.Problem(w, r, fhttp.ValidationFailed,
				"Forwarded must carry the client address in its first element's for parameter")
			return
		}
		defer func() { _ = r.Body.Close() }()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrolmentBody))
		decoder.DisallowUnknownFields()

		action := r.PathValue("enrolment_action")
		if action == "" {
			var body struct {
				Token string `json:"token"`
			}
			if err := decoder.Decode(&body); err != nil || strings.TrimSpace(body.Token) == "" {
				fhttp.Problem(w, r, fhttp.ValidationFailed, "The body is not {\"token\": \"...\"}")
				return
			}
			enrolmentID, err := enrolments.Request(r.Context(), enrolment.RequestInput{
				Caller: caller, ClientAddress: address, Token: strings.TrimSpace(body.Token)})
			if err != nil {
				writeEnrolmentError(w, r, err)
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]string{"enrolment_id": enrolmentID.String()})
			return
		}

		rawID, verb, _ := strings.Cut(action, ":")
		if verb != "verify" {
			fhttp.Problem(w, r, fhttp.NotFound, "No such enrolment action")
			return
		}
		// A malformed identifier names no enrolment: the one refusal, after the address is counted.
		enrolmentID, err := id.Parse(rawID)
		if err != nil || enrolmentID.IsNil() {
			enrolmentID = unknownEnrolment
		}
		var body struct {
			Code string `json:"code"`
		}
		if err := decoder.Decode(&body); err != nil {
			fhttp.Problem(w, r, fhttp.ValidationFailed, "The body is not {\"code\": \"...\"}")
			return
		}
		correlation := ""
		if value, ok := observability.CorrelationID(r.Context()); ok {
			correlation = value.String()
		}
		completed, err := enrolments.Verify(r.Context(), enrolment.VerifyInput{Caller: caller, ClientAddress: address,
			EnrolmentID: enrolmentID, Code: body.Code, Correlation: correlation})
		if err != nil {
			writeEnrolmentError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, completed)
	})
}

// unknownEnrolment stands in for an identifier that does not parse: a UUID no enrolment holds.
var unknownEnrolment = id.MustParse("00000000-0000-7000-8000-000000000000")

func writeEnrolmentError(w http.ResponseWriter, r *http.Request, err error) {
	var limited *enrolment.Limited
	switch {
	case errors.As(err, &limited):
		w.Header().Set("Retry-After", strconv.FormatInt(limited.RetryAfter, 10))
		fhttp.Problem(w, r, fhttp.RateLimited, "Too many enrolment requests from this client address; retry later")
	case errors.Is(err, enrolment.ErrRefused):
		fhttp.Problem(w, r, fhttp.ValidationFailed, refusedDetail)
	case errors.Is(err, enrolment.ErrInvalid):
		fhttp.Problem(w, r, fhttp.ValidationFailed, "The request is not a valid enrolment request")
	case errors.Is(err, enrolment.ErrUnavailable):
		fhttp.Problem(w, r, fhttp.DependencyUnavailable, "Enrolment could not be completed now; retry")
	default:
		fhttp.Problem(w, r, fhttp.Internal, "Enrolment could not be completed")
	}
}

// ClientAddress reads the client address from the first element of Forwarded, as RFC 7239 §4 writes
// it, and answers the form the limits count: an IPv4 address as itself, an IPv6 address as its /64
// prefix (ADR-IAM-011 §5.8). Only the first element's for parameter is read. A missing header, a
// missing for, "unknown", an obfuscated identifier and anything that is not an address are refused.
func ClientAddress(values []string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	header := strings.Join(values, ",")
	first, _, _ := strings.Cut(header, ",")
	for _, pair := range strings.Split(first, ";") {
		name, value, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "for") {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil && strings.HasPrefix(value, `"`) {
			value = unquoted
		}
		return countedAddress(value)
	}
	return "", false
}

func countedAddress(node string) (string, bool) {
	host := node
	switch {
	case strings.HasPrefix(node, "["):
		end := strings.Index(node, "]")
		if end < 0 {
			return "", false
		}
		host = node[1:end]
		rest := node[end+1:]
		if rest != "" && !validPort(strings.TrimPrefix(rest, ":")) {
			return "", false
		}
	case strings.Count(node, ":") == 1:
		h, port, err := net.SplitHostPort(node)
		if err != nil || !validPort(port) {
			return "", false
		}
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.Unmap().String(), true
	}
	if strings.Contains(node, ":") && !strings.HasPrefix(node, "[") {
		// RFC 7239 §6: an IPv6 address is "enclosed in square brackets".
		return "", false
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return "", false
	}
	return prefix.String(), true
}

func validPort(port string) bool {
	if port == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536
}
