package registration

import (
	"context"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

const keyInUseStatement = `SELECT count(*) FROM identity.client_registration
WHERE realm = $1 AND client_key = $2 AND state <> 'retired'`

// unregisteredAudienceStatement counts the audience entries no active resource registration names.
// A token issued for an audience nobody registered has no verifier that would reject it correctly.
const unregisteredAudienceStatement = `SELECT count(*) FROM unnest($2::text[]) AS aud(client_key)
WHERE NOT EXISTS (
    SELECT 1 FROM identity.client_registration resource
    WHERE resource.realm = $1 AND resource.client_key = aud.client_key
      AND resource.profile = 'resource' AND resource.state = 'active')`

const insertPendingStatement = `INSERT INTO identity.client_registration
    (registration_id, realm, client_key, profile, application_authority, application_ref, registered_by,
     audience_class, lifetime_class, audience, redirect_uris, state)
VALUES ($1, $2, $3, $4, 'manual', $5, $6, $7, $8, $9, $10, 'pending')`

func (s *Service) insertPending(ctx context.Context, tx db.Tx, req Request) (Registration, error) {
	var inUse int
	if err := tx.QueryRow(ctx, keyInUseStatement, string(s.cfg.Realm), req.ClientKey).Scan(&inUse); err != nil {
		return Registration{}, fmt.Errorf("registration: check client_key: %w", err)
	}
	if inUse > 0 {
		return Registration{}, ErrKeyTaken
	}
	audience := append([]string{}, req.Audience...)
	var unregistered int
	if err := tx.QueryRow(ctx, unregisteredAudienceStatement, string(s.cfg.Realm), audience).Scan(&unregistered); err != nil {
		return Registration{}, fmt.Errorf("registration: check audience: %w", err)
	}
	if unregistered > 0 {
		return Registration{}, fmt.Errorf("%w: every audience entry must be an active resource registration", ErrInvalid)
	}

	registrationID, err := s.newID()
	if err != nil {
		return Registration{}, fmt.Errorf("registration: mint registration_id: %w", err)
	}
	var lifetime any
	if req.LifetimeClass != "" {
		lifetime = req.LifetimeClass
	}
	redirects := append([]string{}, req.RedirectURIs...)
	if _, err := tx.Exec(ctx, insertPendingStatement, registrationID.String(), string(s.cfg.Realm), req.ClientKey,
		req.Profile, req.ApplicationRef, req.RegisteredBy.String(), req.AudienceClass, lifetime, audience,
		redirects); err != nil {
		return Registration{}, fmt.Errorf("registration: insert pending registration: %w", err)
	}
	return s.read(ctx, tx, registrationID)
}

// readStatement reads one registration with its derived lifespan.
var readStatement = `SELECT r.realm, r.client_key, r.profile, r.audience_class, r.application_authority,
       r.application_ref, r.registered_by::text, r.signing_algorithm, coalesce(r.lifetime_class, ''),
       coalesce(r.audience, '{}'::text[]), coalesce(r.redirect_uris, '{}'::text[]), r.state, r.version,
       r.created_at, ` + LifespanSQL("r.realm", "r.audience") + `
FROM identity.client_registration r
WHERE r.registration_id = $1`

// read goes through Query rather than QueryRow, so an absent registration is no row rather than a
// driver error this package is not allowed to name.
func (s *Service) read(ctx context.Context, tx db.Tx, registrationID id.UUID) (Registration, error) {
	rows, err := tx.Query(ctx, readStatement, registrationID.String())
	if err != nil {
		return Registration{}, fmt.Errorf("registration: read: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Registration{}, fmt.Errorf("registration: read: %w", err)
		}
		return Registration{}, ErrNotFound
	}
	var (
		registration = Registration{ID: registrationID}
		registeredBy string
		createdAt    time.Time
		lifespan     int
	)
	if err := rows.Scan(&registration.Realm, &registration.ClientKey, &registration.Profile,
		&registration.AudienceClass, &registration.ApplicationAuthority, &registration.ApplicationRef, &registeredBy,
		&registration.SigningAlgorithm, &registration.LifetimeClass, &registration.Audience,
		&registration.RedirectURIs, &registration.State, &registration.Version, &createdAt, &lifespan); err != nil {
		return Registration{}, fmt.Errorf("registration: scan: %w", err)
	}
	rows.Close()
	if registration.RegisteredBy, err = id.Parse(registeredBy); err != nil {
		return Registration{}, fmt.Errorf("registration: registered_by: %w", err)
	}
	registration.CreatedAt = createdAt.UTC()
	if registration.Profile != ProfileResource {
		registration.AccessTokenLifespan = lifespan
	}
	return registration, nil
}

const activateStatement = `UPDATE identity.client_registration
SET kc_client_id = $2, state = 'active', activated_at = now(), version = version + 1
WHERE registration_id = $1 AND state = 'pending'`

// retirePendingStatement closes a registration refused before it ever became active. The row is
// kept, as every registration record is, and the partial unique index releases its key.
const retirePendingStatement = `UPDATE identity.client_registration
SET state = 'retired', retired_at = now(), version = version + 1
WHERE registration_id = $1 AND state = 'pending'`

const pendingStatement = `SELECT registration_id::text FROM identity.client_registration
WHERE realm = $1 AND state = 'pending' AND created_at < $2
ORDER BY created_at LIMIT 100`

const relinkStatement = `UPDATE identity.client_registration
SET kc_client_id = $2, version = version + 1
WHERE registration_id = $1 AND state = 'active'`
