package securitynotify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// Requester records a notification request for a classified event, in the caller's transaction.
type Requester struct {
	newID  func() (id.UUID, error)
	logger *slog.Logger
}

// NewRequester builds the requester.
func NewRequester(logger *slog.Logger) *Requester {
	if logger == nil {
		logger = slog.Default()
	}
	return &Requester{newID: id.NewV7, logger: logger}
}

// requestStatement records one request: the Principal the kernel user maps to, and the addresses it
// holds now as the recipients. A kernel user no mapping holds, such as a service account, records
// nothing. A source key already recorded records nothing, so a sweep that reads an event twice
// requests it once.
const requestStatement = `WITH p AS (
    SELECT principal_id FROM identity.principal_mapping WHERE keycloak_user_id = $1 AND realm = $2
), a AS (
    SELECT coalesce(array_agg(address_id ORDER BY added_at, address_id), '{}'::uuid[]) AS ids
    FROM identity.notification_address
    WHERE principal_id = (SELECT principal_id FROM p) AND state = 'active'
)
INSERT INTO identity.security_notification
    (notification_id, principal_id, event, source_key, occurred_at, details, recipients, state)
SELECT $3, p.principal_id, $4, $5, $6, $7::jsonb, a.ids,
       CASE WHEN cardinality(a.ids) = 0 THEN 'no_address' ELSE 'requested' END
FROM p, a
ON CONFLICT (source_key) DO NOTHING
RETURNING principal_id::text, state`

// FromKernelEvent requests the notification a kernel event calls for, if it calls for one. It runs in
// the sweep's transaction, for an event recorded for the first time, so the request and the event
// commit together.
func (r *Requester) FromKernelEvent(ctx context.Context, tx db.Tx, realm keycloak.Realm, e keycloak.KernelEvent) error {
	notified, ok := Classify(e)
	if !ok {
		return nil
	}
	notificationID, err := r.newID()
	if err != nil {
		return err
	}
	details, err := json.Marshal(notified.Details)
	if err != nil {
		return err
	}
	sourceKey := fmt.Sprintf("kernel:%s:%s:%s", realm, e.Kind, e.ID)
	// A query rather than QueryRow: no row is the expected answer for a kernel user who is not a
	// Principal and for an event requested already, and this module reads no driver error type.
	rows, err := tx.Query(ctx, requestStatement, notified.Subject, string(realm), notificationID.String(), notified.Event,
		sourceKey, e.Time.UTC(), string(details))
	if err != nil {
		return fmt.Errorf("securitynotify: request %s for %s: %w", notified.Event, sourceKey, err)
	}
	var principal, state string
	recorded := rows.Next()
	if recorded {
		err = rows.Scan(&principal, &state)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return fmt.Errorf("securitynotify: request %s for %s: %w", notified.Event, sourceKey, err)
	}
	if !recorded {
		return nil
	}
	attrs := []any{slog.String("notification_id", notificationID.String()), slog.String("principal_id", principal),
		slog.String("event", notified.Event), slog.Time("occurred_at", e.Time.UTC())}
	if state == StateNoAddress {
		r.logger.ErrorContext(ctx, "an account security event was recorded for a Principal with no notification address; "+
			"the person cannot be told", attrs...)
		return nil
	}
	r.logger.InfoContext(ctx, "account security notification requested", attrs...)
	return nil
}

// restoreStatement records the request for a restored Principal, to the addresses it holds now. An
// operation already requested records nothing.
const restoreStatement = `WITH a AS (
    SELECT coalesce(array_agg(address_id ORDER BY added_at, address_id), '{}'::uuid[]) AS ids
    FROM identity.notification_address
    WHERE principal_id = $2 AND state = 'active'
)
INSERT INTO identity.security_notification
    (notification_id, principal_id, event, source_key, occurred_at, details, recipients, state)
SELECT $1, $2, $3, $4, now(), $5::jsonb, a.ids,
       CASE WHEN cardinality(a.ids) = 0 THEN 'no_address' ELSE 'requested' END
FROM a
ON CONFLICT (source_key) DO NOTHING
RETURNING state`

// FromRestore requests account_recovered for a Principal a provider restored: the last step of
// assisted recovery (TDD-identity-control-008 1.3.0). It runs in the transaction that records the
// restore as applied, so the two commit together.
func (r *Requester) FromRestore(ctx context.Context, tx db.Tx, operationID, principal id.UUID) error {
	notificationID, err := r.newID()
	if err != nil {
		return err
	}
	details, err := json.Marshal(map[string]string{"method": "assisted", "actor": ActorAdministrator})
	if err != nil {
		return err
	}
	sourceKey := "command:operation:" + operationID.String()
	rows, err := tx.Query(ctx, restoreStatement, notificationID.String(), principal.String(), EventAccountRecovered,
		sourceKey, string(details))
	if err != nil {
		return fmt.Errorf("securitynotify: request %s for %s: %w", EventAccountRecovered, sourceKey, err)
	}
	var state string
	recorded := rows.Next()
	if recorded {
		err = rows.Scan(&state)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return fmt.Errorf("securitynotify: request %s for %s: %w", EventAccountRecovered, sourceKey, err)
	}
	if !recorded {
		return nil
	}
	attrs := []any{slog.String("notification_id", notificationID.String()), slog.String("principal_id", principal.String()),
		slog.String("event", EventAccountRecovered), slog.String("operation_id", operationID.String())}
	if state == StateNoAddress {
		r.logger.ErrorContext(ctx, "an account security event was recorded for a Principal with no notification address; "+
			"the person cannot be told", attrs...)
		return nil
	}
	r.logger.InfoContext(ctx, "account security notification requested", attrs...)
	return nil
}

// The request states (TDD-identity-control-008 §Data Model).
const (
	StateRequested = "requested"
	StateSubmitted = "submitted"
	StateFailed    = "failed"
	StateNoAddress = "no_address"
)

// Request is a recorded request, as the adapter receives it.
type Request struct {
	NotificationID id.UUID
	PrincipalID    id.UUID
	Event          string
	OccurredAt     time.Time
	Details        map[string]string
	// Addresses are the recipients fixed at the event.
	Addresses []string
	// Code is a proof request's one-time code, opened from its seal for this hand-over alone. It is
	// never logged.
	Code string
}
