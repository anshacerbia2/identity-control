package httpapi

// Which routes require an Idempotency-Key, and how a retry is answered (STD-GLB-001 1.4.0 §Commands
// Require an Idempotency-Key; TDD-identity-control-003 1.35.0 §The Idempotency-Key on Every Command).
//
// A command, a POST a person or an operator sends to change authoritative state, must carry one. A
// retried command without a key is a second command: a second owner grant, a second key revoked, a
// second relink. The IETF draft the standard cites says what to answer a request without one: "the
// resource SHOULD reply with an HTTP 400 status code" (draft-ietf-httpapi-idempotency-key-header-07
// §2.7).
//
// Every mutating route is in exactly one of three tables, and TestEveryMutatingRouteIsClassified
// fails on one that is in none, or in two:
//   - serviceKeyed: the service claims the key in the transaction of its effect, and replays it;
//   - replayedKey: the key is required here, and replay records the response for the retry;
//   - keyOptional: no key is required, with the reason a repeat cannot act twice.
// adoptKey is the one route whose requirement depends on its body: a plan is a read, an adoption a
// command.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/idempotency"
	"github.com/anshacerbia2/foundation-platform/observability"
)

// missingKey is the 400 detail. It says what the key is for, because a client that only learns the
// header is missing tends to send a constant, which turns every later command into a replay of the
// first one.
const missingKey = "This route changes state and requires an " + IdempotencyHeader + " header of at most " +
	"255 characters: a value unique to this command, sent again unchanged when the same command is retried"

// serviceKeyed names the commands whose service claims the key in the transaction of its effect
// (foundation-platform's idempotency, or the security operation's own key), and answers a retry from
// it. The route checks only that the key is present.
var serviceKeyed = map[string]string{
	"POST /v1/principals":                                                      "provisioning claims it with the pending mapping (TDD-identity-control-001)",
	"POST /v1/principals/{target}":                                             ":suspend and :restore are security operations keyed per actor (TDD-identity-control-005); :relink is replayed here",
	"POST /v1/registrations":                                                   "registration claims it with the pending registration (TDD-identity-control-003)",
	"POST /v1/workloads":                                                       "the workload path claims it with the pending workload (TDD-identity-control-004)",
	"POST /v1/me/sessions/{session_action}":                                    "a security operation, keyed per actor (TDD-identity-control-005)",
	"POST /v1/me/sessions:terminate-all":                                       "a security operation, keyed per actor",
	"POST /v1/me/authenticators/{authenticator_action}":                        "a security operation, keyed per actor",
	"POST /v1/principals/{principal_id}/sessions:terminate-all":                "a security operation, keyed per actor",
	"POST /v1/principals/{principal_id}/authenticators/{authenticator_action}": "a security operation, keyed per actor",
}

// replayedKey names the commands whose key this package claims before the handler runs and
// completes with the handler's response.
var replayedKey = map[string]string{
	"POST /v1/registrations/{registration_id}":                         "suspend, restore, retire",
	"POST /v1/registrations/{registration_id}/drift-exceptions":        "a drift exception granted",
	"POST /v1/registrations/{registration_id}/keys":                    "a key registered, rotating the active one",
	"POST /v1/registrations/{registration_id}/keys/{key_action}":       "a key revoked",
	"POST /v1/registrations/{registration_id}/owners":                  "an owner granted",
	"POST /v1/registrations/{registration_id}/owners/{owner_action}":   "an owner revoked",
	"POST /v1/registrations/{registration_id}/changes":                 "a change proposed",
	"POST /v1/registrations/{registration_id}/changes/{change_action}": "a change approved, rejected or withdrawn",
	"POST /v1/application-developers":                                  "a standing granted",
	"POST /v1/application-developers/{developer_action}":               "a standing revoked",
	"POST /v1/registration-requests":                                   "a registration requested",
	"POST /v1/registration-requests/{request_action}":                  "a request approved, rejected or withdrawn",
	"POST /v1/workloads/{target}":                                      "suspend, restore, retire, rebuild, reassign, review",
	"POST /v1/security-operations/{operation_action}":                  "a re-drive",
	"POST /v1/me/notification-addresses":                               "an address added",
	"POST /v1/me/notification-addresses/{address_action}":              "an address verified or removed",
}

// adoptKey is POST /v1/registrations:adopt: the adoption requires the key and the service claims it;
// its plan, dry_run, is a read carried in a body and needs none (TDD-identity-control-003 §Adoption).
const adoptKey = "POST /v1/registrations:adopt"

// keyOptional names every other mutating route, with the reason a repeat cannot act twice
// (STD-GLB-001 1.4.0: a read carried in a body, a monotonic report, a sweep or a comparison, or a
// report identified by a correlation identifier it already carries). A key on them is ignored.
var keyOptional = map[string]string{
	"POST /v1/principals:reconcile": "a sweep: pending recovery and the Principal sweep, whose repeat " +
		"finds nothing left to do or the same findings (TDD-identity-control-001)",
	"POST /v1/registrations:reconcile": "a sweep: a repeat finds the same divergences; the findings an " +
		"operator names converge once, and a repeat finds them converged (TDD-identity-control-003)",
	"POST /v1/workloads:sweep": "a sweep: orphans, unused workloads and overdue reviews, each staged " +
		"by time, so a repeat finds the same stage (TDD-identity-control-004)",
	"POST /v1/kernel-events:sweep": "a sweep: it copies the kernel's events after the recorded position, " +
		"and a repeat finds none left (TDD-identity-control-007)",
	"POST /v1/me/authenticators:enroll": "a read carried in a body: it answers the kernel action that " +
		"enrolls; the enrolment happens at the kernel, and the row it writes is evidence of the request " +
		"(TDD-identity-control-005)",
	"POST /v1/deliveries": "a report identified by the identifier it carries: each event's id passes " +
		"the inbox guard, so a repeat is acknowledged and applied once (TDD-identity-control-006)",
}

// KeyStore opens the transaction a claim is made and completed in. The pool satisfies it.
type KeyStore interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// commands holds what the key wrappers need.
type commands struct {
	ledger    keyLedger
	telemetry *observability.Telemetry
}

// newCommands records keys in store; a nil store records nothing.
func newCommands(store KeyStore, telemetry *observability.Telemetry) commands {
	if store == nil {
		return commands{telemetry: telemetry}
	}
	return commands{ledger: poolLedger{store: store}, telemetry: telemetry}
}

// keyLedger claims a key, records its answer, and releases it. poolLedger keeps it in
// platform.idempotency_key; a test keeps it in memory.
type keyLedger interface {
	take(ctx context.Context, claim keyClaim) (*storedAnswer, error)
	complete(ctx context.Context, claim keyClaim, status int, body []byte) error
	release(ctx context.Context, claim keyClaim) error
}

// presentKey refuses a request without a usable key. A blank value is no key: no claim would be
// made, and the caller would believe its retries were safe.
func presentKey(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := idempotencyKey(r); ok {
		return true
	}
	httpapi.Problem(w, r, httpapi.ValidationFailed, missingKey)
	return false
}

// cmd requires the key on a command whose service claims it. It runs inside the caller check, so
// a caller the route does not admit is told so before it is told about a header.
func (c commands) cmd(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if presentKey(w, r) {
			next(w, r)
		}
	}
}

// maxKeyedBody bounds what is buffered to compute a digest. Every body on these routes is a small
// JSON command; a larger one is refused rather than silently unclaimed.
const maxKeyedBody = 1 << 20

// replay requires the key and answers a retry with the response the first request got.
//
// The claim is made in its own transaction before the handler runs, and completed with the
// handler's 2xx response after it. Any other answer releases the key: a refusal changed nothing,
// and a corrected retry must run rather than be told the refusal again. Two windows remain, both
// in the safe direction:
//   - a request still running answers its concurrent retry 409 request-in-progress;
//   - a process that dies after the effect commits and before the completion leaves the key in
//     progress, so its retries are refused rather than applied twice.
//
// A handler answering 5xx after a partial effect is retried as it was before keys were required;
// each of these commands refuses a repeat from its own state (TDD-identity-control-003 1.35.0).
func (c commands) replay(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := idempotencyKey(r)
		if !ok {
			httpapi.Problem(w, r, httpapi.ValidationFailed, missingKey)
			return
		}
		if c.ledger == nil {
			// No store, as in a unit test of a handler: the key is required, and not recorded.
			next(w, r)
			return
		}
		caller, ok := CallerScope(r.Context())
		if !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxKeyedBody+1))
		if err != nil {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body could not be read")
			return
		}
		if len(body) > maxKeyedBody {
			httpapi.Problem(w, r, httpapi.ValidationFailed,
				fmt.Sprintf("A request carrying an %s may not exceed %d bytes", IdempotencyHeader, maxKeyedBody))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Its own namespace: a key a service claims for its own command never meets one claimed here.
		// Method and path are in the digest, so one key on two routes with the same body is a conflict.
		claim := keyClaim{scope: "route:" + caller, key: key,
			digest: idempotency.Digest([]byte(r.Method), []byte(r.URL.Path), body)}
		stored, err := c.ledger.take(r.Context(), claim)
		switch {
		case errors.Is(err, idempotency.ErrConflict):
			httpapi.Problem(w, r, httpapi.IdempotencyKeyConflict, "The Idempotency-Key was used for another request")
			return
		case errors.Is(err, idempotency.ErrInProgress):
			httpapi.Problem(w, r, httpapi.RequestInProgress, "A request with this Idempotency-Key is in progress, "+
				"or ended without recording its answer; retry with the same key later")
			return
		case err != nil:
			httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The Idempotency-Key could not be claimed; retry")
			return
		case stored != nil:
			stored.write(w)
			return
		}

		captured := &capture{ResponseWriter: w, status: http.StatusOK}
		next(captured, r)

		if captured.status < 200 || captured.status > 299 {
			if err := c.ledger.release(r.Context(), claim); err != nil {
				c.warn(r, "the Idempotency-Key of a refused command was not released", err)
			}
			return
		}
		if captured.overflow {
			c.warn(r, "the answer to a command is too large to record for its Idempotency-Key",
				errors.New("response body over the bound"))
			return
		}
		if err := c.ledger.complete(r.Context(), claim, captured.status, captured.body.Bytes()); err != nil {
			// Logged, never surfaced: the command committed and the caller has its answer. Its retries
			// are refused as in progress rather than replayed, which is the safe direction.
			c.warn(r, "the answer to a command was not recorded for its Idempotency-Key", err)
		}
	}
}

func (c commands) warn(r *http.Request, message string, err error) {
	if c.telemetry != nil {
		c.telemetry.Logger(r.Context()).WarnContext(r.Context(), message, slog.String("error", err.Error()))
	}
}

// keyClaim is one key, claimed in platform.idempotency_key.
type keyClaim struct{ scope, key, digest string }

// storedAnswer is a completed command's answer, replayed to its retry.
type storedAnswer struct {
	status int
	body   json.RawMessage
}

func (s storedAnswer) write(w http.ResponseWriter) {
	if s.status == http.StatusNoContent || len(s.body) == 0 || string(s.body) == "null" {
		w.WriteHeader(s.status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s.status)
	_, _ = w.Write(s.body)
}

// poolLedger keeps keys in platform.idempotency_key, through foundation-platform's idempotency.
type poolLedger struct{ store KeyStore }

// take claims the key, or returns the answer its first request recorded.
func (p poolLedger) take(ctx context.Context, k keyClaim) (*storedAnswer, error) {
	var stored *storedAnswer
	err := p.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		result, err := idempotency.Claim(ctx, tx, k.scope, k.key, k.digest)
		if err != nil {
			return err
		}
		if result.State == idempotency.StateReplay {
			stored = &storedAnswer{status: result.Status, body: result.Body}
		}
		return nil
	})
	return stored, err
}

// complete records the answer. A body that is not JSON, or none, is recorded as null.
func (p poolLedger) complete(ctx context.Context, k keyClaim, status int, body []byte) error {
	recorded := json.RawMessage("null")
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && json.Valid(trimmed) {
		recorded = json.RawMessage(trimmed)
	}
	return p.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return idempotency.Complete(ctx, tx, k.scope, k.key, k.digest, status, recorded)
	})
}

const releaseStatement = `DELETE FROM platform.idempotency_key
WHERE scope = $1 AND key = $2 AND request_digest = $3 AND completed_at IS NULL`

// release gives the key back after a refusal.
func (p poolLedger) release(ctx context.Context, k keyClaim) error {
	return p.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, releaseStatement, k.scope, k.key, k.digest)
		return err
	})
}

// capture records the response for its key, and writes it through.
type capture struct {
	http.ResponseWriter
	status   int
	written  bool
	body     bytes.Buffer
	overflow bool
}

func (c *capture) WriteHeader(status int) {
	if !c.written {
		c.status, c.written = status, true
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *capture) Write(p []byte) (int, error) {
	if !c.written {
		c.WriteHeader(http.StatusOK)
	}
	if c.body.Len()+len(p) <= maxKeyedBody {
		c.body.Write(p)
	} else {
		c.overflow = true
	}
	return c.ResponseWriter.Write(p)
}
