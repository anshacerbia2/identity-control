package registration

// Key expiry warnings (TDD-identity-control-003 §Key Expiry Warnings): a keyed client whose active
// key expires soon, or which holds none, is reported before the scheduled removal stops it
// authenticating. Only the active key counts. A rotation makes the successor the active key, so an
// expiring active key is exactly "no successor registered".

import (
	"context"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// The thresholds §Operational Notes sets.
const (
	KeyExpiryWarning  = 14 * 24 * time.Hour
	KeyExpiryCritical = 3 * 24 * time.Hour
)

// Severities of an expiring key, most urgent first.
const (
	SeverityNoKey    = "no_key"
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
)

// ExpiringKey is one registration the warning names. The key fields are empty for no_key.
type ExpiringKey struct {
	RegistrationID id.UUID    `json:"registration_id"`
	ClientKey      string     `json:"client_key"`
	Profile        string     `json:"profile"`
	Severity       string     `json:"severity"`
	KeyID          *id.UUID   `json:"key_id"`
	KID            string     `json:"kid,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at"`
}

// Expiring is the warning as the API reports it.
type Expiring struct {
	WarningDays   int           `json:"warning_days"`
	CriticalDays  int           `json:"critical_days"`
	Registrations []ExpiringKey `json:"registrations"`
}

// expiringStatement reads every active keyed registration whose last accepted key stops before the
// warning horizon, or which holds none. The key that counts is the active one; a client whose active
// key was revoked mid-rotation still authenticates with its retiring key until the overlap ends, so
// that key counts instead, until its retiring_at. No key material is read.
const expiringStatement = `SELECT r.registration_id::text, r.client_key, r.profile,
       coalesce(k.key_id::text, ''), coalesce(k.kid, ''), k.ends_at
FROM identity.client_registration r
LEFT JOIN LATERAL (
    SELECT key_id, kid,
           CASE WHEN state = 'active' THEN expires_at ELSE least(retiring_at, expires_at) END AS ends_at
    FROM identity.client_key
    WHERE registration_id = r.registration_id AND state IN ('active', 'retiring')
    ORDER BY (state = 'active') DESC
    LIMIT 1) k ON true
WHERE r.realm = $1 AND r.state = 'active' AND r.profile IN ('confidential', 'workload')
  AND (k.key_id IS NULL OR k.ends_at < $2)
ORDER BY (k.key_id IS NULL) DESC, k.ends_at, r.client_key`

// ExpiringKeys reports the registrations whose last accepted key stops within KeyExpiryWarning, or
// which hold no key the kernel accepts, most urgent first. ExpiresAt is when that key stops.
func (s *Service) ExpiringKeys(ctx context.Context) (Expiring, error) {
	now := s.now()
	out := Expiring{
		WarningDays: int(KeyExpiryWarning / (24 * time.Hour)), CriticalDays: int(KeyExpiryCritical / (24 * time.Hour)),
		Registrations: []ExpiringKey{},
	}
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, expiringStatement, string(s.cfg.Realm), now.Add(KeyExpiryWarning))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				entry                 ExpiringKey
				registrationID, keyID string
				expiresAt             *time.Time
			)
			if err := rows.Scan(&registrationID, &entry.ClientKey, &entry.Profile, &keyID, &entry.KID, &expiresAt); err != nil {
				return err
			}
			if entry.RegistrationID, err = id.Parse(registrationID); err != nil {
				return err
			}
			switch {
			case keyID == "":
				entry.Severity = SeverityNoKey
			case expiresAt.Before(now.Add(KeyExpiryCritical)):
				entry.Severity = SeverityCritical
			default:
				entry.Severity = SeverityWarning
			}
			if keyID != "" {
				parsed, err := id.Parse(keyID)
				if err != nil {
					return err
				}
				at := expiresAt.UTC()
				entry.KeyID, entry.ExpiresAt = &parsed, &at
			}
			out.Registrations = append(out.Registrations, entry)
		}
		return rows.Err()
	})
	if err != nil {
		return Expiring{}, fmt.Errorf("registration: read expiring keys: %w", err)
	}
	return out, nil
}
