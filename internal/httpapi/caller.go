// Package httpapi is the inbound HTTP surface of the Identity Control Service.
//
// It sits on the fixed middleware chain foundation-platform supplies, so recovery,
// correlation, logging, timeout, and load shedding are not re-implemented here. What this
// package owns is routing, request decoding, and the mapping from a domain error to a problem
// document — and nothing else. There is no authorization decision in this package, because an
// authorization decision made in a transport layer is one the domain cannot see.
package httpapi

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// callerScopeKey carries the authenticated caller through the request context.
type callerScopeKey struct{}

// WithCallerScope records the authenticated caller.
//
// It is exported because the authentication middleware that establishes identity is supplied
// by the composition root, per TDD-foundation-platform-002: this library provides the call
// site and the consuming system provides the decision. Until that middleware exists, no
// request carries a scope and every mutation is refused, which is the correct failure.
func WithCallerScope(ctx context.Context, scope string) context.Context {
	if strings.TrimSpace(scope) == "" {
		return ctx
	}
	return context.WithValue(ctx, callerScopeKey{}, scope)
}

// CallerScope returns the authenticated caller and whether one is present.
//
// The scope is what an idempotency key is claimed under. Deriving it from the request — a
// header, a query parameter, a body field — would let one caller claim or replay another
// caller's key, so it comes only from a value an authentication middleware placed in the
// context.
func CallerScope(ctx context.Context) (string, bool) {
	scope, ok := ctx.Value(callerScopeKey{}).(string)
	return scope, ok && strings.TrimSpace(scope) != ""
}

// IdempotencyHeader is the header a mutation must carry.
const IdempotencyHeader = "Idempotency-Key"

// idempotencyKey reads and bounds the key.
//
// The length bound matches what platform.idempotency_key accepts. Rejecting an over-long key
// here rather than at the database means the caller is told the key is too long instead of
// receiving an internal error from a constraint they cannot see.
func idempotencyKey(r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get(IdempotencyHeader))
	if key == "" || len(key) > 255 {
		return "", false
	}
	return key, true
}

type providerKey struct{}

// withProvider records that the authenticated caller holds provider authority. Only the
// authentication middleware sets it, from the provider decision for this request.
//
// emergency is whether the decision's basis was emergency authority, which every record of the
// caller's privileged access carries (TDD-identity-control-005 §Evidence).
func withProvider(ctx context.Context, emergency bool) context.Context {
	return context.WithValue(ctx, providerKey{}, providerState{emergency: emergency})
}

type providerState struct{ emergency bool }

// WithProvider is withProvider for tests in other packages, which establish a caller without a
// token, as WithCallerScope is.
func WithProvider(ctx context.Context) context.Context { return withProvider(ctx, false) }

// ProviderEmergency reports whether the caller is a provider by emergency authority.
func ProviderEmergency(ctx context.Context) bool {
	state, ok := ctx.Value(providerKey{}).(providerState)
	return ok && state.emergency
}

// IsProvider reports whether the caller holds provider authority. A caller without it is a
// registration owner, served only by the owner routes.
func IsProvider(ctx context.Context) bool {
	_, provider := ctx.Value(providerKey{}).(providerState)
	return provider
}

type assuranceKey struct{}

type assurance struct {
	acr      string
	authTime time.Time
}

// WithAssurance records how and when the caller last authenticated, from the verified token's acr
// and auth_time. The authentication middleware sets it; tests in other packages set it directly.
func WithAssurance(ctx context.Context, acr string, authTime time.Time) context.Context {
	return context.WithValue(ctx, assuranceKey{}, assurance{acr: acr, authTime: authTime})
}

// Assurance returns the caller's acr and auth_time, and whether the request carries them.
func Assurance(ctx context.Context) (string, time.Time, bool) {
	a, ok := ctx.Value(assuranceKey{}).(assurance)
	return a.acr, a.authTime, ok
}
