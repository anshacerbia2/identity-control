package securitynotify

import (
	"context"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// matchStatement answers whether an active human Principal holds the address as a proven one: active,
// with verified_at set, compared without case as the held index compares them (ADR-ORG-007 §5.3,
// TDD-identity-control-008 1.7.0). It is one indexed lookup whatever the answer, and it returns a
// boolean and nothing else, so an unknown Principal, a Principal without the address and one holding
// it unproven are answered alike.
const matchStatement = `SELECT EXISTS (
    SELECT 1
    FROM identity.notification_address a
    JOIN identity.principal_mapping m ON m.principal_id = a.principal_id
    WHERE a.principal_id = $1 AND lower(a.address) = lower($2)
      AND a.state = 'active' AND a.verified_at IS NOT NULL
      AND m.state = 'active' AND m.subject_type = 'human'
)`

// Match answers whether the Principal holds the address as a proven notification address. A malformed
// address is ErrInvalidAddress, which depends on the request alone.
func (a *Addresses) Match(ctx context.Context, principal id.UUID, raw string) (bool, error) {
	address, err := normalized(raw)
	if err != nil {
		return false, err
	}
	var match bool
	err = a.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, matchStatement, principal.String(), address)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&match); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	if err != nil {
		return false, fmt.Errorf("securitynotify: match an address: %w", err)
	}
	return match, nil
}
