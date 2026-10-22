package enrolment

// The enrolment limits (ADR-IAM-011 §5.8, TDD-identity-control-001 1.27.0 §Enrolment From an
// Invitation). Each count is kept in identity.enrolment_count under a keyed hash of the address or the
// invitation, never either itself, and is deleted once its window ends.

import (
	"context"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// Rule is one counted limit: at most Limit in Window.
type Rule struct {
	Name   string
	Limit  int
	Window time.Duration
}

// The limits of ADR-IAM-011 §5.8.
var (
	// RequestRules bound POST /v1/enrolments from one client address.
	RequestRules = []Rule{{"request:minute", 5, time.Minute}, {"request:hour", 20, time.Hour}}
	// VerifyRules bound :verify from one client address.
	VerifyRules = []Rule{{"verify:minute", 5, time.Minute}, {"verify:hour", 30, time.Hour}}
	// MessageRules bound the mail sent for one invitation: a code, or the message in its place.
	MessageRules = []Rule{{"message:hour", 3, time.Hour}, {"message:day", 5, 24 * time.Hour}}
	// FailureRule bounds the failed codes for one invitation.
	FailureRule = Rule{"failure:day", 15, 24 * time.Hour}
)

// countPurpose is the keyed hash's purpose: a hash made for the counts says nothing elsewhere.
const countPurpose = "enrolment-count"

// Hasher is the keyed hash: *securityref.Codec.
type Hasher interface {
	KeyedHash(purpose, value string) string
}

func addressKey(h Hasher, address string) string {
	return h.KeyedHash(countPurpose, "address:"+address)
}

func invitationKey(h Hasher, invitation id.UUID) string {
	return h.KeyedHash(countPurpose, "invitation:"+invitation.String())
}

// countStatement adds one to a count, starting a new window when the last one has ended, and answers
// the count, how long the window still runs, in seconds rounded up.
const countStatement = `INSERT INTO identity.enrolment_count (key_hash, rule, window_ends_at, count)
VALUES ($1, $2, now() + $3::interval, 1)
ON CONFLICT (key_hash, rule) DO UPDATE SET
    count = CASE WHEN identity.enrolment_count.window_ends_at <= now() THEN 1
                 ELSE identity.enrolment_count.count + 1 END,
    window_ends_at = CASE WHEN identity.enrolment_count.window_ends_at <= now() THEN now() + $3::interval
                          ELSE identity.enrolment_count.window_ends_at END
RETURNING count, ceil(extract(epoch FROM window_ends_at - now()))::bigint`

// readStatement is a count in its window, or zero.
const readStatement = `SELECT coalesce((SELECT count FROM identity.enrolment_count
    WHERE key_hash = $1 AND rule = $2 AND window_ends_at > now()), 0)`

func interval(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }

// count adds one to every rule for the key, and answers whether any is past its limit and the seconds
// until the longest exceeded window ends.
func count(ctx context.Context, tx db.Tx, key string, rules []Rule) (exceeded bool, retryAfter int64, err error) {
	for _, rule := range rules {
		var n int
		var remaining int64
		if err := tx.QueryRow(ctx, countStatement, key, rule.Name, interval(rule.Window)).Scan(&n, &remaining); err != nil {
			return false, 0, fmt.Errorf("enrolment: count %s: %w", rule.Name, err)
		}
		if n > rule.Limit {
			exceeded = true
			retryAfter = max(retryAfter, max(remaining, 1))
		}
	}
	return exceeded, retryAfter, nil
}

// atLimit reports whether any rule's count for the key has reached its limit, adding nothing.
func atLimit(ctx context.Context, tx db.Tx, key string, rules []Rule) (bool, error) {
	for _, rule := range rules {
		var n int
		if err := tx.QueryRow(ctx, readStatement, key, rule.Name).Scan(&n); err != nil {
			return false, fmt.Errorf("enrolment: read %s: %w", rule.Name, err)
		}
		if n >= rule.Limit {
			return true, nil
		}
	}
	return false, nil
}
