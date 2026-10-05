package registration

import (
	"context"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
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
     audience_class, lifetime_class, audience, redirect_uris, state, privileged_form)
VALUES ($1, $2, $3, $4, 'manual', $5, $6, $7, $8, $9, $10, 'pending', $11)`

// insertPending records the registration pending and, for a confidential or workload client, its
// first key as the active key: the key is desired state from the start, so recovery creates the
// client holding it.
func (s *Service) insertPending(ctx context.Context, tx db.Tx, req Request, key *PublicKey) (Registration, error) {
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
	if key != nil {
		owner, _, err := thumbprintOwner(ctx, tx, key.Thumbprint)
		if err != nil {
			return Registration{}, err
		}
		if !owner.IsNil() {
			return Registration{}, ErrKeyInUse
		}
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
		redirects, nullableForm(req.PrivilegedForm)); err != nil {
		return Registration{}, fmt.Errorf("registration: insert pending registration: %w", err)
	}
	if key != nil {
		if err := s.insertKey(ctx, tx, registrationID, *key, req.RegisteredBy, s.now()); err != nil {
			return Registration{}, err
		}
	}
	return s.read(ctx, tx, registrationID)
}

// registrationColumns are one registration with its derived lifespan, in the order scannedRow reads
// them.
var registrationColumns = `r.realm, r.client_key, r.profile, r.audience_class, r.application_authority,
       r.application_ref, r.registered_by::text, r.signing_algorithm, coalesce(r.lifetime_class, ''),
       coalesce(r.audience, '{}'::text[]), coalesce(r.redirect_uris, '{}'::text[]), r.state, r.version,
       r.created_at, coalesce(r.privileged_form, ''), ` + LifespanSQL("r.realm", "r.audience")

// readStatement reads one registration.
var readStatement = `SELECT ` + registrationColumns + `
FROM identity.client_registration r
WHERE r.registration_id = $1`

// listStatement reads one page of a realm's registrations in registration_id order. The identifier
// is a UUIDv7, so that order is creation order, and the cursor is the last identifier returned: a
// keyset on the primary key, which STD-GLB-001 requires in place of an offset.
var listStatement = `SELECT r.registration_id::text, ` + registrationColumns + `
FROM identity.client_registration r
WHERE r.realm = $1
  AND ($2::text = '' OR r.state = $2::text)
  AND ($3::uuid IS NULL OR r.registration_id > $3::uuid)
ORDER BY r.registration_id
LIMIT $4`

// scannedRow receives registrationColumns.
type scannedRow struct {
	registration Registration
	registeredBy string
	createdAt    time.Time
	lifespan     int
}

func (s *scannedRow) targets() []any {
	r := &s.registration
	return []any{&r.Realm, &r.ClientKey, &r.Profile, &r.AudienceClass, &r.ApplicationAuthority, &r.ApplicationRef,
		&s.registeredBy, &r.SigningAlgorithm, &r.LifetimeClass, &r.Audience, &r.RedirectURIs, &r.State, &r.Version,
		&s.createdAt, &r.PrivilegedForm, &s.lifespan}
}

func (s *scannedRow) finish() (Registration, error) {
	registration := s.registration
	registeredBy, err := id.Parse(s.registeredBy)
	if err != nil {
		return Registration{}, fmt.Errorf("registration: registered_by: %w", err)
	}
	registration.RegisteredBy = registeredBy
	registration.CreatedAt = s.createdAt.UTC()
	if registration.Profile != ProfileResource {
		registration.AccessTokenLifespan = s.lifespan
	}
	return registration, nil
}

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
	row := scannedRow{registration: Registration{ID: registrationID}}
	if err := rows.Scan(row.targets()...); err != nil {
		return Registration{}, fmt.Errorf("registration: scan: %w", err)
	}
	rows.Close()
	return row.finish()
}

// list reads one page, and one row more than the page holds, so whether a next page exists is known
// without a second query.
func (s *Service) list(ctx context.Context, tx db.Tx, query ListQuery) (Page, error) {
	var after any
	if !query.After.IsNil() {
		after = query.After.String()
	}
	rows, err := tx.Query(ctx, listStatement, string(s.cfg.Realm), query.State, after, query.Limit+1)
	if err != nil {
		return Page{}, fmt.Errorf("registration: list: %w", err)
	}
	defer rows.Close()
	page := Page{Registrations: []Registration{}}
	for rows.Next() {
		var (
			raw string
			row scannedRow
		)
		if err := rows.Scan(append([]any{&raw}, row.targets()...)...); err != nil {
			return Page{}, fmt.Errorf("registration: scan: %w", err)
		}
		if row.registration.ID, err = id.Parse(raw); err != nil {
			return Page{}, fmt.Errorf("registration: registration_id: %w", err)
		}
		registration, err := row.finish()
		if err != nil {
			return Page{}, err
		}
		page.Registrations = append(page.Registrations, registration)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("registration: list: %w", err)
	}
	if len(page.Registrations) > query.Limit {
		page.Registrations = page.Registrations[:query.Limit]
		next := page.Registrations[query.Limit-1].ID.String()
		page.Next = &next
	}
	return page, nil
}

const activateStatement = `UPDATE identity.client_registration
SET kc_client_id = $2, state = 'active', activated_at = now(), version = version + 1
WHERE registration_id = $1 AND state = 'pending'`

// retirePendingStatement closes a registration refused before it ever became active. The row is
// kept, as every registration record is, and the partial unique index releases its key.
const retirePendingStatement = `UPDATE identity.client_registration
SET state = 'retired', retired_at = now(), version = version + 1
WHERE registration_id = $1 AND state = 'pending'`

// revokeRefusedKeysStatement closes the keys of a registration refused before it became active.
// They never reached the kernel, and are kept as the record of what was submitted; the thumbprint
// stays taken, as every registered key's does, so the refused client registers with a new key pair.
const revokeRefusedKeysStatement = `UPDATE identity.client_key
SET state = 'revoked', revoked_at = $2, revocation_reason = 'the registration was refused before it became active'
WHERE registration_id = $1 AND state <> 'revoked'`

const pendingStatement = `SELECT registration_id::text FROM identity.client_registration
WHERE realm = $1 AND state = 'pending' AND created_at < $2
ORDER BY created_at LIMIT 100`

const relinkStatement = `UPDATE identity.client_registration
SET kc_client_id = $2, version = version + 1
WHERE registration_id = $1 AND state = 'active'`

const clientStatement = `SELECT state, coalesce(kc_client_id, '') FROM identity.client_registration
WHERE registration_id = $1 AND realm = $2`

// Client reports a registration's state and its kernel client, which is empty while it is pending.
// A workload reads it to find the client whose service-account user carries its identity.
func (s *Service) Client(ctx context.Context, registrationID id.UUID) (string, keycloak.ClientUUID, error) {
	var state, client string
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, clientStatement, registrationID.String(), string(s.cfg.Realm))
		if err != nil {
			return fmt.Errorf("registration: read the client: %w", err)
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return ErrNotFound
		}
		return rows.Scan(&state, &client)
	})
	return state, keycloak.ClientUUID(client), err
}

// nullableForm stores a registration's privileged form, NULL for every class but privileged.
func nullableForm(form string) any {
	if form == "" {
		return nil
	}
	return form
}
