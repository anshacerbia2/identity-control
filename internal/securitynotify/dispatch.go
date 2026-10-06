package securitynotify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// Deliverer hands a request to the Notification Platform, or to the development stand-in. It answers
// the platform's reference for the accepted request.
type Deliverer interface {
	Deliver(ctx context.Context, request Request) (string, error)
}

// Transactor opens a transaction.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// The dispatch policy (TDD-identity-control-008 §Dispatch).
const (
	DispatchInterval = 15 * time.Second
	dispatchBatch    = 50
	maxAttempts      = 10
	maxBackoff       = time.Hour
)

// Dispatcher hands due requests to the deliverer, one transaction each.
type Dispatcher struct {
	tx      Transactor
	deliver Deliverer
	logger  *slog.Logger
}

// NewDispatcher builds the dispatcher.
func NewDispatcher(tx Transactor, deliver Deliverer, logger *slog.Logger) (*Dispatcher, error) {
	if tx == nil || deliver == nil {
		return nil, errors.New("securitynotify: a transactor and a deliverer are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Dispatcher{tx: tx, deliver: deliver, logger: logger}, nil
}

// takeStatement locks one due request. SKIP LOCKED lets several replicas dispatch, none handing a
// request over twice. Its recipients are read from the addresses it was requested for, whatever their
// state now.
const takeStatement = `SELECT n.notification_id::text, n.principal_id::text, n.event, n.occurred_at, n.details::text,
       n.attempts,
       ARRAY(SELECT a.address FROM identity.notification_address a
             WHERE a.address_id = ANY(n.recipients) ORDER BY a.added_at, a.address_id)
FROM identity.security_notification n
WHERE n.state = 'requested' AND n.next_attempt_at <= now()
ORDER BY n.next_attempt_at, n.notification_id
LIMIT 1
FOR UPDATE OF n SKIP LOCKED`

const submittedStatement = `UPDATE identity.security_notification
SET state = 'submitted', platform_ref = $2, submitted_at = now(), attempts = attempts + 1, last_error = NULL
WHERE notification_id = $1`

const retryStatement = `UPDATE identity.security_notification
SET attempts = $2, next_attempt_at = now() + $3::interval, last_error = $4,
    state = CASE WHEN $2 >= $5 THEN 'failed' ELSE 'requested' END
WHERE notification_id = $1`

// Dispatch hands over every due request, up to the batch, and answers how many it handed over.
func (d *Dispatcher) Dispatch(ctx context.Context) (int, error) {
	handed := 0
	for range dispatchBatch {
		done, err := d.one(ctx)
		if err != nil {
			return handed, err
		}
		if !done {
			return handed, nil
		}
		handed++
	}
	return handed, nil
}

// one takes one due request and hands it over. It answers false when none is due.
func (d *Dispatcher) one(ctx context.Context) (bool, error) {
	taken := false
	err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, takeStatement)
		if err != nil {
			return err
		}
		var (
			r                     Request
			notificationID, princ string
			details               string
			attempts              int
		)
		if rows.Next() {
			taken = true
			err = rows.Scan(&notificationID, &princ, &r.Event, &r.OccurredAt, &details, &attempts, &r.Addresses)
		}
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
		if err != nil || !taken {
			return err
		}
		if r.NotificationID, err = id.Parse(notificationID); err != nil {
			return err
		}
		if r.PrincipalID, err = id.Parse(princ); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(details), &r.Details); err != nil {
			return err
		}
		r.OccurredAt = r.OccurredAt.UTC()

		ref, deliverErr := d.deliver.Deliver(ctx, r)
		if deliverErr == nil {
			_, err = tx.Exec(ctx, submittedStatement, notificationID, ref)
			return err
		}
		attempts++
		backoff := time.Duration(1<<min(attempts, 6)) * time.Minute
		backoff = min(backoff, maxBackoff)
		if _, err := tx.Exec(ctx, retryStatement, notificationID, attempts, fmt.Sprintf("%d seconds", int(backoff.Seconds())),
			deliverErr.Error(), maxAttempts); err != nil {
			return err
		}
		attrs := []any{slog.String("notification_id", notificationID), slog.String("event", r.Event),
			slog.Int("attempts", attempts), slog.String("error", deliverErr.Error())}
		if attempts >= maxAttempts {
			d.logger.ErrorContext(ctx, "an account security notification failed; the person was not told", attrs...)
		} else {
			d.logger.WarnContext(ctx, "an account security notification was not handed over; it is retried", attrs...)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("securitynotify: dispatch: %w", err)
	}
	return taken, nil
}
