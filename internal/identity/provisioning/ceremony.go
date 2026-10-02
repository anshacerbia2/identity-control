package provisioning

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The bootstrap ceremony: the entry point into a realm that has no Principals yet.
//
// `POST /v1/principals` requires a caller holding a `principal_id`, and it is the only path that
// issues one, so a fresh Control Database has no way to reach its first Principal. ADR-IAM-001
// §5.8 records the decision and why a standing break-glass identity was rejected: a one-time
// problem does not justify a permanent capability.
//
// It lives in this package rather than in the command, because it must reuse Provisioner.Create
// exactly. A ceremony that wrote its own creation path would be a second implementation of the
// invariant this package exists to hold, and the two would drift.

// ceremonyRowID is the only value the table's primary key admits.
//
// The single-use guarantee is the primary key plus `CHECK (id = 1)`, not this constant and not
// any check in Go. Two concurrent ceremonies therefore produce one Principal: the loser's insert
// is refused by the database rather than by a race it might win.
const ceremonyRowID = 1

// ceremonyScope is the idempotency scope the ceremony claims under.
//
// It is not a Principal and does not look like one. Every API caller's scope is
// "principal:<uuid>", so this value cannot collide with one, and a key claimed by the ceremony
// can never be replayed or consumed by an authenticated caller.
const ceremonyScope = "ceremony:bootstrap"

var (
	// ErrCeremonyUnnamed reports a ceremony row claimed before principal_id was recorded whose
	// Principal was never created. The row is insert-only, so it cannot be made to name one.
	ErrCeremonyUnnamed = errors.New("provisioning: the ceremony row names no principal_id; it was claimed " +
		"before the column existed and its Principal was never created. Reset this Control Database")

	// ErrCeremonyAlreadyPerformed reports that this Control Database already has its first
	// Principal. It is a refusal rather than a failure: the ceremony is meant to be
	// unrepeatable, so this is the mechanism working.
	ErrCeremonyAlreadyPerformed = errors.New("provisioning: the bootstrap ceremony has already been performed")

	// ErrRegistryNotEmpty reports that Principals exist without a ceremony record. Reaching
	// this means Principals were created some other way — an out-of-band INSERT, or a restored
	// database — and the ceremony refuses rather than adding one more.
	ErrRegistryNotEmpty = errors.New("provisioning: the Principal registry is not empty; the ceremony creates the first Principal only")
)

// CeremonyRequest is one bootstrap ceremony.
type CeremonyRequest struct {
	Realm keycloak.Realm

	// Username and Email describe the first Principal. No credential is supplied: the kernel is
	// told to demand one on first authentication, so this process never holds it.
	Username string
	Email    string

	// Operator is the human running the ceremony, and Reason is why. Both are recorded
	// immutably. A service account name here would defeat the record: the point is that a
	// person is accountable for the one identifier nobody else authorized.
	Operator string
	Reason   string
}

func (r CeremonyRequest) validate() error {
	switch {
	case r.Realm == "":
		return errors.New("provisioning: realm is required")
	case strings.TrimSpace(r.Username) == "":
		return errors.New("provisioning: username is required")
	case strings.TrimSpace(r.Operator) == "":
		return errors.New("provisioning: operator is required; the ceremony records a person, not a process")
	case strings.TrimSpace(r.Reason) == "":
		return errors.New("provisioning: reason is required")
	}
	return nil
}

// CeremonyRecord is the durable evidence of the ceremony.
type CeremonyRecord struct {
	Operator       string
	Reason         string
	IdempotencyKey string

	// PrincipalID is the Principal the ceremony creates, minted when the row is claimed. It is
	// the ceremony's local emergency grant, honored until Organization's first emergency
	// provider:identity-control grant is projected (TDD-identity-control-006 §The Ceremony's
	// Grant). Recorded in the insert-only row, so no later write can move the grant to someone
	// else.
	PrincipalID id.UUID
}

const claimCeremonyStatement = `INSERT INTO identity.bootstrap_ceremony
    (id, operator, reason, idempotency_key, principal_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO NOTHING`

// readCeremonyStatement reads the claimed row and the registry's size in one round trip.
//
// One statement rather than two because both answers must come from the same snapshot as the
// claim: a count taken in a separate statement could be read after another transaction inserted a
// mapping, and the emptiness assertion would be checking a moment that had already passed.
const readCeremonyStatement = `SELECT c.operator,
       c.reason,
       c.idempotency_key,
       coalesce(c.principal_id::text, ''),
       (SELECT count(*) FROM identity.principal_mapping)
FROM identity.bootstrap_ceremony c
WHERE c.id = $1`

// probeCeremonyStatement answers "has the ceremony run" in one row that always exists.
//
// An aggregate rather than a plain SELECT because a no-row result would have to be recognised as
// pgx.ErrNoRows, and arch.json denies this module any import of pgx — the driver is reachable
// only through foundation-platform's db package, which is what keeps a driver type out of a
// domain signature. The table holds at most one row by constraint, so max() is that row's value.
const probeCeremonyStatement = `SELECT count(*),
       coalesce(max(operator), ''),
       coalesce(max(reason), ''),
       coalesce(max(idempotency_key), '')
FROM identity.bootstrap_ceremony`

// Bootstrap performs the ceremony, or resumes one that was interrupted.
//
// The sequence is deliberately two steps with a durable boundary between them:
//
//	claim the ceremony row, asserting the registry is empty   — one transaction
//	create the Principal through the ordinary path            — Provisioner.Create
//
// The claim commits first so that a crash before the Principal exists leaves a record naming the
// operator, the reason, and the idempotency key to resume under. Resuming is what makes the
// ceremony survive a crash without a second Principal appearing: the key was claimed in step
// one, so step two replays instead of minting.
//
// The registry-emptiness check runs only when this call claims the row. On a resumed ceremony the
// registry may legitimately hold the pending mapping the interrupted attempt wrote, and
// re-asserting emptiness would make the ceremony impossible to complete.
func (p *Provisioner) Bootstrap(ctx context.Context, req CeremonyRequest) (Response, CeremonyRecord, error) {
	if err := req.validate(); err != nil {
		return Response{}, CeremonyRecord{}, err
	}

	// The key is derived from the realm rather than random, so a resumed ceremony reaches the
	// same key even if the row read fails and this value is recomputed. It is stored in the row
	// regardless, and the stored value is what step two uses.
	key := fmt.Sprintf("bootstrap:%s", req.Realm)

	// Minted before the claim so the row names the Principal it creates. On a resumed ceremony the
	// insert does nothing and the recorded identifier is read back instead.
	minted, err := p.newID()
	if err != nil {
		return Response{}, CeremonyRecord{}, fmt.Errorf("provisioning: mint principal_id: %w", err)
	}

	var (
		record  CeremonyRecord
		claimed bool
	)

	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		tag, execErr := tx.Exec(ctx, claimCeremonyStatement,
			ceremonyRowID, strings.TrimSpace(req.Operator), strings.TrimSpace(req.Reason), key, minted.String())
		if execErr != nil {
			return fmt.Errorf("provisioning: claim the ceremony row: %w", execErr)
		}
		claimed = tag.RowsAffected() == 1

		// Read back unconditionally. On a resumed ceremony this is the recorded operator and
		// reason, and using them rather than the ones passed in is what makes the record
		// immutable in practice as well as in privilege: a second attempt cannot rewrite who
		// ran the first.
		var (
			existing  int
			principal string
		)
		if scanErr := tx.QueryRow(ctx, readCeremonyStatement, ceremonyRowID).
			Scan(&record.Operator, &record.Reason, &record.IdempotencyKey, &principal, &existing); scanErr != nil {
			return fmt.Errorf("provisioning: read the ceremony row: %w", scanErr)
		}
		// A row claimed before principal_id was recorded, whose Principal was never created, names
		// no one, and the row cannot be rewritten to name someone. Completing it would create a
		// first Principal with no provider authority at all.
		if principal == "" {
			return ErrCeremonyUnnamed
		}
		parsed, parseErr := id.Parse(principal)
		if parseErr != nil {
			return fmt.Errorf("provisioning: the ceremony row names principal_id %q: %w", principal, parseErr)
		}
		record.PrincipalID = parsed

		// The emptiness assertion applies only when this call claimed the row. A resumed
		// ceremony legitimately finds the pending mapping the interrupted attempt wrote, and
		// re-asserting emptiness would make the ceremony impossible to complete.
		if claimed && existing > 0 {
			// Returning an error rolls the claim back, so a refused ceremony leaves no record.
			// A record of a ceremony that did not happen would be worse than none: it would
			// name an operator who created nothing.
			return fmt.Errorf("%w: %d mapping(s) exist", ErrRegistryNotEmpty, existing)
		}
		return nil
	}); err != nil {
		return Response{}, CeremonyRecord{}, err
	}

	if claimed {
		p.logger.InfoContext(ctx, "bootstrap ceremony claimed",
			slog.String("operator", record.Operator),
			slog.String("realm", string(req.Realm)))
	} else {
		p.logger.InfoContext(ctx, "bootstrap ceremony already recorded; resuming under the stored key",
			slog.String("operator", record.Operator),
			slog.String("realm", string(req.Realm)))
	}

	// The ordinary path, unmodified. The ceremony's only privilege is that it does not need an
	// authenticated caller; everything else — the identifier, the two checkpoints, the pending
	// recovery, the kernel payload — is what any Principal gets.
	//
	// A human subject: the kernel is told to demand a credential on first authentication, so no
	// credential passes through this process.
	response, err := p.Create(ctx, CreateRequest{
		CallerScope:    ceremonyScope,
		IdempotencyKey: record.IdempotencyKey,
		Realm:          req.Realm,
		Username:       req.Username,
		Email:          req.Email,
		SubjectType:    keycloak.SubjectHuman,
		principalID:    record.PrincipalID,
	})
	if err != nil {
		return Response{}, record, err
	}
	return response, record, nil
}

// CeremonyPerformed reports whether this Control Database has already been bootstrapped.
//
// Read-only, so a command can refuse before touching the kernel and report the operator on
// record instead of a constraint violation.
func (p *Provisioner) CeremonyPerformed(ctx context.Context) (CeremonyRecord, bool, error) {
	var (
		record CeremonyRecord
		count  int
	)

	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if scanErr := tx.QueryRow(ctx, probeCeremonyStatement).
			Scan(&count, &record.Operator, &record.Reason, &record.IdempotencyKey); scanErr != nil {
			return fmt.Errorf("provisioning: read the ceremony row: %w", scanErr)
		}
		return nil
	}); err != nil {
		return CeremonyRecord{}, false, err
	}
	if count == 0 {
		return CeremonyRecord{}, false, nil
	}
	return record, true, nil
}
