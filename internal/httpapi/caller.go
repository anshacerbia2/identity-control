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
