package securitynotify

// Enrolment messages: mail to an invited address that no Principal holds yet (ADR-IAM-011 §5.1, §5.2,
// §5.9; TDD-identity-control-001 1.27.0 §Enrolment From an Invitation). They queue in
// identity.enrolment_message, as a Principal's notifications queue in identity.security_notification,
// and the same dispatcher hands them over with the same backoff and attempts. The address and the
// sealed code are held until then, and cleared with the outcome.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/securityref"
)

// EnrolmentPurpose is what an enrolment code is sealed for.
const EnrolmentPurpose = "enrolment-deliver"

// The two kinds of enrolment message, as identity.enrolment_message names them.
const (
	EnrolmentKindCode    = "code"
	EnrolmentKindAccount = "account_exists"
)

const queueEnrolmentStatement = `INSERT INTO identity.enrolment_message
    (message_id, enrolment_id, kind, address, sealed_secret)
VALUES ($1, $2::uuid, $3, $4, $5)`

// QueueEnrolmentCode queues an enrolment's code for its address, sealed for the enrolment alone.
func QueueEnrolmentCode(ctx context.Context, tx db.Tx, sealer Sealer, enrolmentID id.UUID, address, code string) error {
	if sealer == nil || enrolmentID.IsNil() || address == "" || code == "" {
		return errors.New("securitynotify: an enrolment code needs a sealer, its enrolment, an address and a code")
	}
	sealed, err := sealer.Seal(securityref.KindEnrolmentCode, enrolmentID, EnrolmentPurpose, "", code)
	if err != nil {
		return fmt.Errorf("securitynotify: seal the enrolment code: %w", err)
	}
	messageID, err := id.NewV7()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, queueEnrolmentStatement, messageID.String(), enrolmentID.String(), EnrolmentKindCode,
		address, sealed); err != nil {
		return fmt.Errorf("securitynotify: queue the enrolment code: %w", err)
	}
	return nil
}

// QueueAccountExists queues the message that takes a code's place when the address is held already
// (ADR-IAM-011 §5.9). It names no enrolment: none is made.
func QueueAccountExists(ctx context.Context, tx db.Tx, address string) error {
	if address == "" {
		return errors.New("securitynotify: an account message needs an address")
	}
	messageID, err := id.NewV7()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, queueEnrolmentStatement, messageID.String(), nil, EnrolmentKindAccount, address,
		nil); err != nil {
		return fmt.Errorf("securitynotify: queue the account message: %w", err)
	}
	return nil
}

const takeEnrolmentStatement = `SELECT message_id::text, coalesce(enrolment_id::text, ''), kind, address,
       coalesce(sealed_secret, ''), attempts, requested_at
FROM identity.enrolment_message
WHERE state = 'requested' AND next_attempt_at <= now()
ORDER BY next_attempt_at, message_id
LIMIT 1
FOR UPDATE SKIP LOCKED`

const enrolmentSubmittedStatement = `UPDATE identity.enrolment_message
SET state = 'submitted', platform_ref = $2, submitted_at = now(), attempts = attempts + 1, last_error = NULL,
    sealed_secret = NULL, address = NULL
WHERE message_id = $1`

const enrolmentUnopenableStatement = `UPDATE identity.enrolment_message
SET state = 'failed', attempts = attempts + 1, last_error = $2, sealed_secret = NULL, address = NULL
WHERE message_id = $1`

const enrolmentRetryStatement = `UPDATE identity.enrolment_message
SET attempts = $2::integer, next_attempt_at = now() + $3::interval, last_error = $4,
    state = CASE WHEN $2::integer >= $5::integer THEN 'failed' ELSE 'requested' END,
    sealed_secret = CASE WHEN $2::integer >= $5::integer THEN NULL ELSE sealed_secret END,
    address = CASE WHEN $2::integer >= $5::integer THEN NULL ELSE address END
WHERE message_id = $1`

// oneEnrolment hands over one due enrolment message. It reports whether there was one.
func (d *Dispatcher) oneEnrolment(ctx context.Context) (bool, error) {
	taken := false
	err := d.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, takeEnrolmentStatement)
		if err != nil {
			return err
		}
		var (
			messageID, enrolment, kind, address, sealed string
			attempts                                    int
			requested                                   time.Time
		)
		if rows.Next() {
			taken = true
			err = rows.Scan(&messageID, &enrolment, &kind, &address, &sealed, &attempts, &requested)
		}
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
		if err != nil || !taken {
			return err
		}
		r := Request{Event: EventEnrolmentAccount, OccurredAt: requested.UTC(), Addresses: []string{address},
			Details: map[string]string{}}
		if r.NotificationID, err = id.Parse(messageID); err != nil {
			return err
		}
		if kind == EnrolmentKindCode {
			r.Event = EventEnrolmentCode
			enrolmentID, err := id.Parse(enrolment)
			if err != nil {
				return err
			}
			opened, ok := d.openEnrolmentCode(enrolmentID, sealed)
			if !ok {
				d.logger.ErrorContext(ctx, "an enrolment code could not be handed over; it expired or cannot be opened",
					slog.String("message_id", messageID))
				_, err := tx.Exec(ctx, enrolmentUnopenableStatement, messageID, "the enrolment code expired before it was handed over")
				return err
			}
			r.Code = opened
		}
		ref, deliverErr := d.deliver.Deliver(ctx, r)
		if deliverErr == nil {
			_, err = tx.Exec(ctx, enrolmentSubmittedStatement, messageID, ref)
			return err
		}
		attempts++
		backoff := min(time.Duration(1<<min(attempts, 6))*time.Minute, maxBackoff)
		if _, err := tx.Exec(ctx, enrolmentRetryStatement, messageID, attempts,
			fmt.Sprintf("%d seconds", int(backoff.Seconds())), deliverErr.Error(), maxAttempts); err != nil {
			return err
		}
		attrs := []any{slog.String("message_id", messageID), slog.String("event", r.Event),
			slog.Int("attempts", attempts), slog.String("error", deliverErr.Error())}
		if attempts >= maxAttempts {
			d.logger.ErrorContext(ctx, "an enrolment message failed; the invited person was not told", attrs...)
		} else {
			d.logger.WarnContext(ctx, "an enrolment message was not handed over; it is retried", attrs...)
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("securitynotify: dispatch an enrolment message: %w", err)
	}
	return taken, nil
}

func (d *Dispatcher) openEnrolmentCode(enrolmentID id.UUID, sealed string) (string, bool) {
	if d.sealer == nil || sealed == "" {
		return "", false
	}
	ref, err := d.sealer.Open(sealed, securityref.KindEnrolmentCode, enrolmentID, EnrolmentPurpose)
	if err != nil {
		return "", false
	}
	return ref.KernelID, true
}
