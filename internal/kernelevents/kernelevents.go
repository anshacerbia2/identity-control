// Package kernelevents keeps the kernel event record (TDD-identity-control-007): every user and admin
// event the identity kernel recorded, read from its native store through the Admin API, written once,
// and kept until Audit & Evidence has it (STD-IAM-001 §3.8).
//
// The kernel keeps each kind for 7 days and is the reconciliation source, not the record. Each kind
// is swept in windows that overlap by one interval, so an event recorded at a boundary is read twice,
// and the record is keyed on the kernel's own event identifier, so it is written once.
package kernelevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// Retention is the kernel's event retention (TDD-identity-kernel-003 1.1.0): the first sweep reads it
// whole, and no sweep reads further back.
const Retention = 7 * 24 * time.Hour

// MaxInterval is the longest sweep interval: TDD-identity-kernel-003 §Retention Constraint wants an
// event read at least twice before it expires, with a safety factor of twenty-four.
const MaxInterval = Retention / 24

// Transactor opens a transaction.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// KindResult is what one kind's sweep did.
type KindResult struct {
	Kind string `json:"kind"`
	// Read is the events read in the window; Recorded those recorded for the first time.
	Read     int `json:"read"`
	Recorded int `json:"recorded"`
	// ReadThrough is the kind's mark after the sweep: the newest event time a complete sweep read.
	ReadThrough time.Time `json:"read_through"`
	// Truncated is a read that stopped at its bound: the events it read are recorded, the mark is kept,
	// and the next sweep reads the same window again.
	Truncated bool `json:"truncated"`
}

// Result is one sweep of both kinds.
type Result struct {
	Kinds []KindResult `json:"kinds"`
}

// Sweeper sweeps the kernel's event store into the record.
type Sweeper struct {
	tx       Transactor
	store    keycloak.EventStore
	realm    keycloak.Realm
	interval time.Duration
	now      func() time.Time
	logger   *slog.Logger
	recorded RecordedHook
}

// RecordedHook is called for each event the sweep records for the first time, in the transaction that
// records it, so what it writes commits with the event or not at all. Account security notifications
// are requested this way (TDD-identity-control-008).
type RecordedHook func(ctx context.Context, tx db.Tx, realm keycloak.Realm, event keycloak.KernelEvent) error

// OnRecorded sets the hook. Nil, the default, calls nothing.
func (s *Sweeper) OnRecorded(hook RecordedHook) { s.recorded = hook }

// NewSweeper builds the sweep. The interval is the window overlap as well as the cadence.
func NewSweeper(tx Transactor, store keycloak.EventStore, realm keycloak.Realm, interval time.Duration,
	logger *slog.Logger) (*Sweeper, error) {
	switch {
	case tx == nil || store == nil || realm == "":
		return nil, errors.New("kernelevents: a transactor, an event store and a realm are required")
	case interval <= 0 || interval > MaxInterval:
		return nil, fmt.Errorf("kernelevents: the interval must be positive and at most %s, so an event is read "+
			"at least twice before the kernel's %s retention expires it", MaxInterval, Retention)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{tx: tx, store: store, realm: realm, interval: interval, now: time.Now, logger: logger}, nil
}

// Sweep reads and records both kinds. A kind that fails stops the sweep: the next one reads its
// window again.
func (s *Sweeper) Sweep(ctx context.Context) (Result, error) {
	var result Result
	for _, kind := range []string{keycloak.KindUserEvent, keycloak.KindAdminEvent} {
		kindResult, err := s.sweepKind(ctx, kind)
		if err != nil {
			return result, err
		}
		result.Kinds = append(result.Kinds, kindResult)
		attrs := []any{slog.String("kind", kind), slog.Int("read", kindResult.Read),
			slog.Int("recorded", kindResult.Recorded), slog.Time("read_through", kindResult.ReadThrough)}
		if kindResult.Truncated {
			s.logger.WarnContext(ctx, "the kernel event read reached its bound; the mark holds until a sweep reads the window whole", attrs...)
		} else {
			s.logger.InfoContext(ctx, "kernel events swept", attrs...)
		}
	}
	return result, nil
}

// markStatement is the kind's mark, or the start of the kernel's retention when there is none.
const markStatement = `SELECT coalesce((SELECT read_through FROM identity.kernel_event_mark
    WHERE realm = $1 AND kind = $2), $3::timestamptz)`

const insertStatement = `INSERT INTO identity.kernel_event
    (realm, kind, kc_event_id, occurred_at, event_type, kc_user_id, principal_id, client_id, session_id,
     ip_address, error, resource_type, resource_path, details)
VALUES ($1, $2, $3, $4, $5, nullif($6, ''),
        (SELECT principal_id FROM identity.principal_mapping WHERE keycloak_user_id = $6 AND realm = $1 AND $6 <> ''),
        nullif($7, ''), nullif($8, ''), nullif($9, ''), nullif($10, ''), nullif($11, ''), nullif($12, ''), $13::jsonb)
ON CONFLICT (realm, kind, kc_event_id) DO NOTHING`

// lastSeenStatement moves a workload's last authentication forward to a client credentials grant its
// service-account user made (TDD-identity-control-007 1.1.0, TDD-identity-control-004 §Unused Workload
// Detection). It never moves it back: an older event read late changes nothing.
const lastSeenStatement = `UPDATE identity.workload w
SET last_seen_at = $3
FROM identity.principal_mapping m
WHERE m.realm = $1 AND m.keycloak_user_id = $2 AND m.subject_type = 'workload'
  AND w.principal_id = m.principal_id AND (w.last_seen_at IS NULL OR w.last_seen_at < $3)`

// clientLogin is the kernel's event type for a successful client credentials grant.
const clientLogin = "CLIENT_LOGIN"

// saveMarkStatement records the sweep. read_through only moves forward, and a truncated read
// passes the mark it started from, which leaves it where it was.
const saveMarkStatement = `INSERT INTO identity.kernel_event_mark
    (realm, kind, read_through, swept_at, last_read, last_recorded)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (realm, kind) DO UPDATE
SET read_through  = greatest(identity.kernel_event_mark.read_through, excluded.read_through),
    swept_at      = excluded.swept_at,
    last_read     = excluded.last_read,
    last_recorded = excluded.last_recorded
RETURNING read_through`

func (s *Sweeper) sweepKind(ctx context.Context, kind string) (KindResult, error) {
	now := s.now().UTC()
	floor := now.Add(-Retention)
	var mark time.Time
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, markStatement, string(s.realm), kind, floor).Scan(&mark)
	}); err != nil {
		return KindResult{}, fmt.Errorf("kernelevents: read the %s mark: %w", kind, err)
	}
	since := mark.Add(-s.interval)
	if since.Before(floor) {
		since = floor
	}

	events, truncated, err := s.store.KernelEvents(ctx, s.realm, kind, since)
	if err != nil {
		return KindResult{}, fmt.Errorf("kernelevents: read the kernel's %s events: %w", kind, err)
	}
	result := KindResult{Kind: kind, Read: len(events), Truncated: truncated}

	readThrough := mark
	for _, event := range events {
		if event.ID == "" {
			return KindResult{}, fmt.Errorf("kernelevents: %w (%s at %s)", keycloak.ErrNoEventID, event.Type, event.Time)
		}
		if !truncated && event.Time.After(readThrough) {
			readThrough = event.Time
		}
	}

	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, event := range events {
			details, err := json.Marshal(detailsOf(event))
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, insertStatement, string(s.realm), kind, event.ID, event.Time, event.Type,
				event.UserID, event.ClientID, event.SessionID, event.IPAddress, event.Error, event.ResourceType,
				event.ResourcePath, string(details))
			if err != nil {
				return fmt.Errorf("record %s: %w", event.ID, err)
			}
			result.Recorded += int(tag.RowsAffected())
			if tag.RowsAffected() == 1 && event.Kind == keycloak.KindUserEvent && event.Type == clientLogin &&
				event.Error == "" && event.UserID != "" {
				if _, err := tx.Exec(ctx, lastSeenStatement, string(s.realm), event.UserID, event.Time); err != nil {
					return fmt.Errorf("record %s's workload authentication: %w", event.ID, err)
				}
			}
			if tag.RowsAffected() == 1 && s.recorded != nil {
				if err := s.recorded(ctx, tx, s.realm, event); err != nil {
					return err
				}
			}
		}
		return tx.QueryRow(ctx, saveMarkStatement, string(s.realm), kind, readThrough, now, result.Read,
			result.Recorded).Scan(&result.ReadThrough)
	})
	if err != nil {
		return KindResult{}, fmt.Errorf("kernelevents: record the %s events: %w", kind, err)
	}
	result.ReadThrough = result.ReadThrough.UTC()
	return result, nil
}

// detailsOf is what the record keeps beyond the columns: a user event's details, or an admin event's
// representation, each with every credential value redacted (TDD-identity-control-007 §Data Model).
func detailsOf(event keycloak.KernelEvent) map[string]any {
	if event.Kind == keycloak.KindUserEvent {
		details := map[string]any{}
		for key, value := range event.Details {
			details[key] = value
		}
		return redact(details).(map[string]any)
	}
	if strings.TrimSpace(event.Representation) == "" {
		return map[string]any{}
	}
	var representation any
	if err := json.Unmarshal([]byte(event.Representation), &representation); err != nil {
		return map[string]any{"unparsed": true}
	}
	return map[string]any{"representation": redact(representation)}
}

// credentialKeys are the keys whose value is a credential, compared case-insensitively.
var credentialKeys = map[string]bool{
	"credentials": true, "password": true, "secret": true, "clientsecret": true, "privatekey": true,
	"token": true, "access_token": true, "refresh_token": true, "id_token": true,
}

// redact replaces the value under every credential key, at any depth.
func redact(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			if credentialKeys[strings.ToLower(key)] {
				out[key] = "[redacted]"
				continue
			}
			out[key] = redact(inner)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, inner := range v {
			out[i] = redact(inner)
		}
		return out
	default:
		return value
	}
}
