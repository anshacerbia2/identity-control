// Package provisioning owns the canonical Principal identifier and the only authorized
// path that creates one.
//
// Keycloak is the physical system of record for the Principal row. This package is the
// authority for the identifier the rest of the enterprise references. That asymmetry is the
// point: Keycloak enforces no uniqueness on user attributes, so the uniqueness invariant
// for `principal_id` lives in identity.principal_mapping and nowhere else.
package provisioning

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// State is the lifecycle position of a mapping.
type State string

const (
	// StatePending means the identifier is minted and durable, and the kernel call has
	// either not run or not been confirmed. It is the checkpoint recovery works from.
	StatePending State = "pending"

	// StateActive means the kernel holds the Principal and the mapping records its
	// identifier.
	StateActive State = "active"

	// StateQuarantined means an invariant was violated and the mapping is held for
	// investigation. It is reachable from pending and from active.
	StateQuarantined State = "quarantined"

	// StateRetired is the terminal state of a Principal that is no longer in use.
	StateRetired State = "retired"
)

// Errors this package returns. They are distinguished because the caller's branches differ:
// a conflict is a client error, an ambiguity is an operator alert, and a state violation is
// a defect.
var (
	ErrInvalidTransition = errors.New("provisioning: transition is not in the state machine")
	ErrNotFound          = errors.New("provisioning: mapping not found")
	ErrDuplicateInKernel = errors.New("provisioning: more than one kernel user carries this principal_id")
	ErrIdentifierTaken   = errors.New("provisioning: principal_id already exists")

	// ErrWorkloadPath refuses a workload on the human creation and relink paths. A workload's
	// Keycloak user is its client's service-account user, the one a client credentials token is
	// issued for, so a user this path created would carry the workload's identity into no token at
	// all. Workloads are created and rebuilt through the workload path (TDD-identity-control-004).
	ErrWorkloadPath = errors.New("provisioning: a workload is created through POST /v1/workloads, not as a user")
)

// transitions is the state machine from TDD-identity-control-001, expressed as data.
//
// As data rather than as a switch so that the set of legal transitions is enumerable, and a
// test can assert that every transition absent from this table is rejected. A switch
// statement supports asserting the transitions someone remembered to write.
var transitions = map[State][]State{
	StatePending: {StateActive, StateQuarantined},
	// Active to pending is :relink, the one way back: a mapping whose Keycloak user is gone is
	// provisioned again under the same principal_id.
	StateActive:      {StatePending, StateRetired, StateQuarantined},
	StateQuarantined: {},
	StateRetired:     {},
}

// Valid reports whether the state is one this service writes.
func (s State) Valid() bool {
	_, ok := transitions[s]
	return ok
}

// CanTransitionTo reports whether the state machine permits this move.
//
// A transition to the same state is refused rather than treated as a no-op. An idempotent
// caller must recognise "already there" before acting, because a repeated transition that
// silently succeeds hides a second attempt that should have been noticed.
func (s State) CanTransitionTo(next State) bool {
	allowed, known := transitions[s]
	if !known {
		return false
	}
	for _, candidate := range allowed {
		if candidate == next {
			return true
		}
	}
	return false
}

// Mapping is one row of identity.principal_mapping.
type Mapping struct {
	PrincipalID id.UUID

	// KeycloakUserID is empty while the mapping is pending. It never leaves this module:
	// TDD-identity-control-001 requires it absent from every response body.
	KeycloakUserID keycloak.UserID

	Realm keycloak.Realm

	// Username and Email are the creation payload, held so recovery can reconstruct the
	// kernel call from the row alone. They are not the authoritative values: Keycloak owns
	// those, and a change made there is not reflected here.
	Username string
	Email    string

	SubjectType   keycloak.SubjectType
	WorkloadOwner id.UUID
	State         State

	CreatedAt        time.Time
	ActivatedAt      time.Time
	QuarantinedAt    time.Time
	QuarantineReason string
	Version          int

	// The creating request's idempotency claim, written with the pending row so recovery can
	// complete it (TDD-identity-control-001 1.14.0). Empty for a row written before it, and for a
	// workload's mapping, whose claim the workload holds.
	IdempotencyScope string
	IdempotencyKey   string
	RequestDigest    string
}

// Transactor is the transaction source this package needs.
//
// An interface rather than *db.Pool so the orchestration can be tested without a database.
// It carries exactly one method, so it grants no capability beyond opening a transaction.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Repository reads and writes identity.principal_mapping.
//
// Every method takes an explicit transaction handle, per STD-GLB-BE-001 Rule 6. A method
// that opened its own transaction could not be composed into the caller's, and the mapping
// write must commit with the idempotency claim beside it.
type Repository struct{}

const insertPendingStatement = `INSERT INTO identity.principal_mapping
    (principal_id, realm, username, email, subject_type, workload_owner, state,
     idempotency_scope, idempotency_key, request_digest)
VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)
ON CONFLICT (principal_id) DO NOTHING`

// InsertPending records the intent to create a Principal, before the kernel call.
//
// It reports ErrIdentifierTaken when the identifier already exists. UUIDv7 collision is
// vanishingly unlikely, so this firing means a caller reused an identifier — which is worth
// a distinct error rather than a silent success, because the alternative is two Principals
// believing they own one identifier.
func (Repository) InsertPending(ctx context.Context, tx db.Tx, m Mapping) error {
	if db.IsNilTx(tx) {
		return errors.New("provisioning: a transaction handle is required")
	}
	if m.PrincipalID.IsNil() {
		return errors.New("provisioning: principal_id must not be nil")
	}
	if !m.SubjectType.Valid() {
		return fmt.Errorf("provisioning: subject_type %q is not human or workload", m.SubjectType)
	}
	// The username is what recovery rebuilds the kernel call from. A row without one is a
	// mapping recovery can never resolve, so it is refused here rather than at the
	// database, where the failure would name a column instead of a reason.
	if m.Username == "" {
		return errors.New("provisioning: username is required; recovery reconstructs the kernel call from it")
	}

	owner := any(nil)
	if !m.WorkloadOwner.IsNil() {
		owner = m.WorkloadOwner.String()
	}
	email := any(nil)
	if m.Email != "" {
		email = m.Email
	}

	var scope, key, digest any
	if m.IdempotencyKey != "" {
		scope, key, digest = m.IdempotencyScope, m.IdempotencyKey, m.RequestDigest
	}

	tag, err := tx.Exec(ctx, insertPendingStatement,
		m.PrincipalID.String(), string(m.Realm), m.Username, email, string(m.SubjectType), owner,
		scope, key, digest)
	if err != nil {
		return fmt.Errorf("provisioning: insert pending mapping: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrIdentifierTaken
	}
	// The email a person is created with is their first notification address, written with the
	// mapping so no person exists without one (ADR-IAM-007 §5.2, TDD-identity-control-008).
	if m.Email != "" && m.SubjectType == keycloak.SubjectHuman {
		addressID, err := id.NewV7()
		if err != nil {
			return fmt.Errorf("provisioning: notification address identifier: %w", err)
		}
		if _, err := tx.Exec(ctx, insertCreationAddressStatement, addressID.String(), m.PrincipalID.String(), m.Email); err != nil {
			return fmt.Errorf("provisioning: insert the creation notification address: %w", err)
		}
	}
	return nil
}

const insertCreationAddressStatement = `INSERT INTO identity.notification_address
    (address_id, principal_id, channel, address, origin, state)
VALUES ($1, $2, 'email', $3, 'creation', 'active')`

const activateStatement = `UPDATE identity.principal_mapping
SET keycloak_user_id = $2,
    state            = 'active',
    activated_at     = now(),
    version          = version + 1
WHERE principal_id = $1 AND state = 'pending'`

// Activate records the kernel identifier and moves the mapping to active.
//
// The `state = 'pending'` predicate is the concurrency control. Two recovery workers that
// both observe the same pending row will both attempt this, and the second affects no rows
// rather than overwriting the first worker's kernel identifier with its own.
func (Repository) Activate(ctx context.Context, tx db.Tx, principalID id.UUID, userID keycloak.UserID) error {
	if db.IsNilTx(tx) {
		return errors.New("provisioning: a transaction handle is required")
	}
	if userID == "" {
		return errors.New("provisioning: a kernel user identifier is required to activate")
	}

	tag, err := tx.Exec(ctx, activateStatement, principalID.String(), string(userID))
	if err != nil {
		return fmt.Errorf("provisioning: activate mapping: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const retireWorkloadStatement = `UPDATE identity.principal_mapping
SET state = 'retired', version = version + 1
WHERE principal_id = $1 AND subject_type = 'workload' AND state = 'active'`

// RetireWorkload moves a workload Principal's mapping to retired, in the transaction that deleted its
// client and with it the service-account user that was its kernel user (TDD-identity-control-004
// §Suspension, Restoration, and Retirement). Retired is terminal, and the dangling sweep reads only
// active mappings, so a kernel user deleted on purpose is not reported missing. keycloak_user_id is
// kept as the record of which user it was.
func (Repository) RetireWorkload(ctx context.Context, tx db.Tx, principalID id.UUID) error {
	if db.IsNilTx(tx) {
		return errors.New("provisioning: a transaction handle is required")
	}
	tag, err := tx.Exec(ctx, retireWorkloadStatement, principalID.String())
	if err != nil {
		return fmt.Errorf("provisioning: retire the workload mapping: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const setWorkloadOwnerStatement = `UPDATE identity.principal_mapping
SET workload_owner = $2, version = version + 1
WHERE principal_id = $1 AND subject_type = 'workload' AND state = 'active'`

// SetWorkloadOwner records a workload's new accountable owner on its mapping, in the caller's
// transaction, so the mapping and the workload record never name two owners.
func (Repository) SetWorkloadOwner(ctx context.Context, tx db.Tx, principalID, owner id.UUID) error {
	if db.IsNilTx(tx) {
		return errors.New("provisioning: a transaction handle is required")
	}
	if owner.IsNil() {
		return errors.New("provisioning: a workload requires an accountable workload_owner")
	}
	tag, err := tx.Exec(ctx, setWorkloadOwnerStatement, principalID.String(), owner.String())
	if err != nil {
		return fmt.Errorf("provisioning: record the workload owner: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const quarantineStatement = `UPDATE identity.principal_mapping
SET state             = 'quarantined',
    quarantined_at    = now(),
    quarantine_reason = $2,
    version           = version + 1
WHERE principal_id = $1 AND state IN ('pending', 'active')`

// Quarantine holds a mapping for investigation.
//
// The reason is mandatory. A quarantined Principal is an incident record, and one without a
// stated reason cannot be triaged by whoever finds it.
func (Repository) Quarantine(ctx context.Context, tx db.Tx, principalID id.UUID, reason string) error {
	if db.IsNilTx(tx) {
		return errors.New("provisioning: a transaction handle is required")
	}
	if reason == "" {
		return errors.New("provisioning: a quarantine reason is required")
	}

	tag, err := tx.Exec(ctx, quarantineStatement, principalID.String(), reason)
	if err != nil {
		return fmt.Errorf("provisioning: quarantine mapping: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const findStatement = `SELECT principal_id::text,
       coalesce(keycloak_user_id, ''),
       realm,
       username,
       coalesce(email, ''),
       subject_type,
       coalesce(workload_owner::text, ''),
       state,
       version
FROM identity.principal_mapping
WHERE principal_id = $1`

// Find reads one mapping.
func (Repository) Find(ctx context.Context, tx db.Tx, principalID id.UUID) (Mapping, error) {
	if db.IsNilTx(tx) {
		return Mapping{}, errors.New("provisioning: a transaction handle is required")
	}

	var (
		rawPrincipal string
		rawUser      string
		realm        string
		username     string
		email        string
		subjectType  string
		rawOwner     string
		state        string
		version      int
	)
	err := tx.QueryRow(ctx, findStatement, principalID.String()).
		Scan(&rawPrincipal, &rawUser, &realm, &username, &email, &subjectType, &rawOwner, &state, &version)
	if err != nil {
		return Mapping{}, fmt.Errorf("provisioning: find mapping: %w", err)
	}

	return decode(row{rawPrincipal, rawUser, realm, username, email, subjectType, rawOwner, state, version})
}

const pendingStatement = `SELECT principal_id::text,
       coalesce(keycloak_user_id, ''),
       realm,
       username,
       coalesce(email, ''),
       subject_type,
       coalesce(workload_owner::text, ''),
       state,
       version,
       coalesce(idempotency_scope, ''),
       coalesce(idempotency_key, ''),
       coalesce(request_digest, '')
FROM identity.principal_mapping
WHERE state = 'pending' AND created_at < now() - $1::interval
ORDER BY created_at
LIMIT $2`

// PendingOlderThan returns mappings stuck in pending past the recovery threshold.
//
// The age predicate matters: without it recovery would race the creation path it is meant
// to repair, searching the kernel for a user the original request is still creating.
func (Repository) PendingOlderThan(ctx context.Context, tx db.Tx, age time.Duration, limit int) ([]Mapping, error) {
	if db.IsNilTx(tx) {
		return nil, errors.New("provisioning: a transaction handle is required")
	}
	if limit <= 0 {
		return nil, errors.New("provisioning: limit must be positive")
	}

	rows, err := tx.Query(ctx, pendingStatement, age.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("provisioning: read pending mappings: %w", err)
	}
	defer rows.Close()

	var pending []Mapping
	for rows.Next() {
		var (
			rawPrincipal string
			rawUser      string
			realm        string
			username     string
			email        string
			subjectType  string
			rawOwner     string
			state        string
			version      int
			scope        string
			key          string
			digest       string
		)
		if err := rows.Scan(&rawPrincipal, &rawUser, &realm, &username, &email, &subjectType, &rawOwner, &state, &version,
			&scope, &key, &digest); err != nil {
			return nil, fmt.Errorf("provisioning: scan pending mapping: %w", err)
		}
		mapping, decodeErr := decode(row{rawPrincipal, rawUser, realm, username, email, subjectType, rawOwner, state, version})
		if decodeErr != nil {
			return nil, decodeErr
		}
		mapping.IdempotencyScope, mapping.IdempotencyKey, mapping.RequestDigest = scope, key, digest
		pending = append(pending, mapping)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("provisioning: read pending mappings: %w", err)
	}
	return pending, nil
}

// row is the scanned shape of one mapping.
//
// A struct rather than nine positional parameters: the two SELECT statements and decode must
// agree on column order, and a positional signature makes a transposition between two string
// columns compile cleanly and fail at runtime with a value in the wrong field.
type row struct {
	principalID string
	userID      string
	realm       string
	username    string
	email       string
	subjectType string
	owner       string
	state       string
	version     int
}

func decode(r row) (Mapping, error) {
	principalID, err := id.Parse(r.principalID)
	if err != nil {
		return Mapping{}, fmt.Errorf("provisioning: stored principal_id %q is unparseable: %w", r.principalID, err)
	}

	mapping := Mapping{
		PrincipalID:    principalID,
		KeycloakUserID: keycloak.UserID(r.userID),
		Realm:          keycloak.Realm(r.realm),
		Username:       r.username,
		Email:          r.email,
		SubjectType:    keycloak.SubjectType(r.subjectType),
		State:          State(r.state),
		Version:        r.version,
	}
	if r.owner != "" {
		owner, ownerErr := id.Parse(r.owner)
		if ownerErr != nil {
			return Mapping{}, fmt.Errorf("provisioning: stored workload_owner %q is unparseable: %w", r.owner, ownerErr)
		}
		mapping.WorkloadOwner = owner
	}
	if !mapping.State.Valid() {
		return Mapping{}, fmt.Errorf("provisioning: stored state %q is not in the state machine", r.state)
	}
	if mapping.Username == "" {
		return Mapping{}, fmt.Errorf("provisioning: stored mapping %s carries no username; recovery could not rebuild its kernel call", principalID)
	}
	return mapping, nil
}
