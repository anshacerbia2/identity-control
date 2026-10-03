// Package securitystate accepts and executes a provider's security commands on another Principal:
// suspend, restore, end every session, revoke one authenticator (TDD-identity-control-005
// §Containment as Built).
//
// A command is accepted in one transaction that checks the Principal and its version, changes its
// state where the command does, and inserts the operation, so acceptance is durable before any
// kernel call (STD-GLB-011 §3.3). The operation is then executed by a lease: a short transaction
// claims it and commits, the kernel is called, and a second transaction records the outcome with
// its evidence. No transaction is held across a remote call, and a worker that dies leaves the
// operation claimable again when its lease ends.
package securitystate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/securityref"
)

// The operation types, as the database's check names them.
const (
	TypeSuspend      = "suspend"
	TypeRestore      = "restore"
	TypeTerminateAll = "sessions.terminate-all"
	TypeRevoke       = "authenticator.revoke"

	// A person's own commands (TDD-identity-control-005 §Self-Service as Built). A self
	// sessions.terminate-all is the type above with the actor as its subject.
	TypeSessionTerminate    = "session.terminate"
	TypeAuthenticatorRemove = "authenticator.remove"
)

// The operation states.
const (
	StatePending    = "pending"
	StateRetrying   = "retrying"
	StateApplied    = "applied"
	StateRefused    = "refused"
	StateUnresolved = "unresolved"
)

// ResultLastAuthenticator is a revocation the guard refused: it would leave no first factor.
const ResultLastAuthenticator = "last_authenticator"

var (
	// ErrInvalid is a command missing what every administrative mutation carries.
	ErrInvalid = errors.New("securitystate: the command is incomplete")

	// ErrSelfAction is a provider acting on the Principal in its own token.
	ErrSelfAction = errors.New("securitystate: a provider cannot act on itself")

	// ErrNotFound is a Principal this service does not hold, or a reference that does not open for
	// this Principal and purpose. One error for both reference failures, as the codec reports one.
	ErrNotFound = errors.New("securitystate: no such Principal or object")

	// ErrWorkload is a workload Principal, contained through /v1/workloads instead.
	ErrWorkload = errors.New("securitystate: a workload is suspended and restored through /v1/workloads")

	// ErrState is a Principal whose state does not admit the command.
	ErrState = errors.New("securitystate: the Principal's state does not admit this command")

	// ErrVersion is a command naming another version than the Principal's.
	ErrVersion = errors.New("securitystate: the Principal's security version changed")

	// ErrKeyReuse is an Idempotency-Key already used by this actor for another request.
	ErrKeyReuse = errors.New("securitystate: the Idempotency-Key was used for another request")

	// ErrInProgress is the same key accepted concurrently by another request.
	ErrInProgress = errors.New("securitystate: a request with this Idempotency-Key is being accepted")
)

// Transactor is the transaction source: foundation-platform's *db.Pool.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Config bounds the service. Zero values take TDD-identity-control-005 §Configuration's defaults.
type Config struct {
	Realm          keycloak.Realm
	Budget         time.Duration
	AttemptTimeout time.Duration
	MaxAttempts    int
	Lease          time.Duration
	Interval       time.Duration
	BatchSize      int
}

// Actor is who commands, as the request established it.
type Actor struct {
	Principal   id.UUID
	Emergency   bool
	Correlation string
	// Assurance is the token's acr and auth_time, as the operation records them.
	Assurance string
}

// Command is one security command. A self command (Self) is a person acting on their own
// Principal: it carries no reason and no expected version, and its subject is the actor.
type Command struct {
	Self            bool
	Type            string
	Subject         id.UUID
	Ref             string
	ExpectedVersion int64
	Reason          string
	IdempotencyKey  string
	Actor           Actor
}

// Operation is an accepted command as a caller reads it. It never carries the reference.
type Operation struct {
	OperationID id.UUID    `json:"operation_id"`
	PrincipalID id.UUID    `json:"principal_id"`
	Type        string     `json:"operation_type"`
	State       string     `json:"state"`
	Attempts    int        `json:"attempts"`
	ResultCode  string     `json:"result_code,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	AppliedAt   *time.Time `json:"applied_at,omitempty"`
}

// Final reports whether the operation reached a state no execution changes.
func (o Operation) Final() bool {
	return o.State == StateApplied || o.State == StateRefused || o.State == StateUnresolved
}

// Service accepts, executes and reads security operations.
type Service struct {
	tx     Transactor
	kernel keycloak.Containment
	refs   *securityref.Codec
	cfg    Config
	logger *slog.Logger
	newID  func() (id.UUID, error)
	jitter func(limit time.Duration) time.Duration
}

// New builds the service.
func New(tx Transactor, kernel keycloak.Containment, refs *securityref.Codec, cfg Config, logger *slog.Logger) (*Service, error) {
	switch {
	case tx == nil:
		return nil, errors.New("securitystate: a transactor is required")
	case kernel == nil:
		return nil, errors.New("securitystate: a kernel client is required")
	case refs == nil:
		return nil, errors.New("securitystate: a reference codec is required")
	case cfg.Realm == "":
		return nil, errors.New("securitystate: a realm is required")
	case logger == nil:
		return nil, errors.New("securitystate: a logger is required")
	}
	if cfg.Budget <= 0 {
		cfg.Budget = 2 * time.Second
	}
	if cfg.AttemptTimeout <= 0 {
		cfg.AttemptTimeout = 500 * time.Millisecond
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 10 * time.Second
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 10
	}
	return &Service{tx: tx, kernel: kernel, refs: refs, cfg: cfg, logger: logger, newID: id.NewV7, jitter: fullJitter}, nil
}

// Route is the route an operation is commanded on, as its evidence records it. A self command is
// one whose actor is its subject.
func Route(operationType string, self bool) string {
	if self {
		switch operationType {
		case TypeSessionTerminate:
			return "POST /v1/me/sessions/{security_ref}:terminate"
		case TypeTerminateAll:
			return "POST /v1/me/sessions:terminate-all"
		case TypeAuthenticatorRemove:
			return "POST /v1/me/authenticators/{security_ref}:remove"
		}
		return ""
	}
	switch operationType {
	case TypeSuspend:
		return "POST /v1/principals/{principal_id}:suspend"
	case TypeRestore:
		return "POST /v1/principals/{principal_id}:restore"
	case TypeTerminateAll:
		return "POST /v1/principals/{principal_id}/sessions:terminate-all"
	case TypeRevoke:
		return "POST /v1/principals/{principal_id}/authenticators/{security_ref}:revoke"
	}
	return ""
}

// referenced reports whether an operation type names one object by a reference.
func referenced(operationType string) bool {
	return operationType == TypeRevoke || operationType == TypeSessionTerminate || operationType == TypeAuthenticatorRemove
}

func (c Command) validate() error {
	switch {
	case Route(c.Type, c.Self) == "":
		return fmt.Errorf("%w: unknown operation %q", ErrInvalid, c.Type)
	case c.Subject.IsNil() || c.Actor.Principal.IsNil():
		return fmt.Errorf("%w: a subject and an actor are required", ErrInvalid)
	case !c.Self && c.Actor.Principal == c.Subject:
		return ErrSelfAction
	case c.Self && c.Actor.Principal != c.Subject:
		return fmt.Errorf("%w: a self command acts on the caller's own Principal", ErrInvalid)
	case strings.TrimSpace(c.IdempotencyKey) == "" || len(c.IdempotencyKey) > 255:
		return fmt.Errorf("%w: an Idempotency-Key of at most 255 characters is required", ErrInvalid)
	case !c.Self && strings.TrimSpace(c.Reason) == "":
		return fmt.Errorf("%w: an administrative reason is required", ErrInvalid)
	case !c.Self && c.ExpectedVersion < 1:
		return fmt.Errorf("%w: expected_version is required", ErrInvalid)
	case referenced(c.Type) != (c.Ref != ""):
		return fmt.Errorf("%w: a reference names the object a command acts on, and nothing else", ErrInvalid)
	case strings.TrimSpace(c.Actor.Correlation) == "" || strings.TrimSpace(c.Actor.Assurance) == "":
		return fmt.Errorf("%w: a correlation identifier and the caller's assurance are required", ErrInvalid)
	}
	return nil
}

// refBinding is the kind and purpose a command's reference must have been sealed for.
func refBinding(operationType string) (securityref.Kind, string) {
	switch operationType {
	case TypeSessionTerminate:
		return securityref.KindSession, securityref.PurposeSelfSessionTerminate
	case TypeAuthenticatorRemove:
		return securityref.KindCredential, securityref.PurposeSelfAuthenticatorRemove
	default:
		return securityref.KindCredential, securityref.PurposeAdminRevoke
	}
}

// digest is what makes two requests under one key the same request.
func (c Command) digest() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{c.Type, c.Subject.String(), c.Ref,
		strconv.FormatInt(c.ExpectedVersion, 10), c.Reason}, "\x00")))
	return hex.EncodeToString(sum[:])
}

const findByKeyStatement = `SELECT operation_id::text, request_digest FROM identity.security_operation
WHERE actor_principal_id = $1 AND idempotency_key = $2`

const lockMappingStatement = `SELECT subject_type, state, coalesce(keycloak_user_id, '')
FROM identity.principal_mapping WHERE principal_id = $1 AND realm = $2 FOR UPDATE`

const openFindingStatement = `SELECT EXISTS (SELECT 1 FROM identity.principal_finding
WHERE principal_id = $1 AND resolved_at IS NULL)`

const insertSubjectStatement = `INSERT INTO identity.security_subject_state (principal_id) VALUES ($1)
ON CONFLICT (principal_id) DO NOTHING`

const lockSubjectStatement = `SELECT version, next_sequence FROM identity.security_subject_state
WHERE principal_id = $1 FOR UPDATE`

const advanceSubjectStatement = `UPDATE identity.security_subject_state
SET version = version + 1, next_sequence = next_sequence + 1, updated_at = now() WHERE principal_id = $1`

const moveMappingStatement = `UPDATE identity.principal_mapping SET state = $2, version = version + 1
WHERE principal_id = $1`

const insertOperationStatement = `INSERT INTO identity.security_operation
    (operation_id, principal_id, subject_sequence, actor_principal_id, idempotency_key, request_digest,
     operation_type, sealed_object_ref, expected_version, reason, correlation_id, assurance, emergency)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (actor_principal_id, idempotency_key) DO NOTHING
RETURNING operation_id::text`

// Accept checks a command and records it durably. A key this actor already used returns its
// operation, before any check that operation's own effect could have changed.
func (s *Service) Accept(ctx context.Context, cmd Command) (Operation, error) {
	if err := cmd.validate(); err != nil {
		return Operation{}, err
	}
	digest := cmd.digest()
	var accepted id.UUID
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		existing, existingDigest, found, err := s.findByKey(ctx, tx, cmd.Actor.Principal, cmd.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if existingDigest != digest {
				return ErrKeyReuse
			}
			accepted = existing
			return nil
		}

		if err := s.admit(ctx, tx, cmd); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, insertSubjectStatement, cmd.Subject.String()); err != nil {
			return fmt.Errorf("securitystate: record the subject: %w", err)
		}
		var version, sequence int64
		if err := tx.QueryRow(ctx, lockSubjectStatement, cmd.Subject.String()).Scan(&version, &sequence); err != nil {
			return fmt.Errorf("securitystate: lock the subject: %w", err)
		}
		// A self command names no version: it records the one it was accepted against.
		if cmd.Self {
			cmd.ExpectedVersion = version
		} else if version != cmd.ExpectedVersion {
			return fmt.Errorf("%w: it is %d, the command names %d", ErrVersion, version, cmd.ExpectedVersion)
		}
		if _, err := tx.Exec(ctx, advanceSubjectStatement, cmd.Subject.String()); err != nil {
			return fmt.Errorf("securitystate: advance the subject: %w", err)
		}
		switch cmd.Type {
		case TypeSuspend:
			if _, err := tx.Exec(ctx, moveMappingStatement, cmd.Subject.String(), "suspended"); err != nil {
				return fmt.Errorf("securitystate: suspend the mapping: %w", err)
			}
		case TypeRestore:
			if _, err := tx.Exec(ctx, moveMappingStatement, cmd.Subject.String(), "active"); err != nil {
				return fmt.Errorf("securitystate: restore the mapping: %w", err)
			}
		}

		operationID, err := s.newID()
		if err != nil {
			return fmt.Errorf("securitystate: mint operation_id: %w", err)
		}
		var ref any
		if cmd.Ref != "" {
			ref = cmd.Ref
		}
		var reason any
		if cmd.Reason != "" {
			reason = cmd.Reason
		}
		rows, err := tx.Query(ctx, insertOperationStatement, operationID.String(), cmd.Subject.String(), sequence,
			cmd.Actor.Principal.String(), cmd.IdempotencyKey, digest, cmd.Type, ref, cmd.ExpectedVersion, reason,
			cmd.Actor.Correlation, cmd.Actor.Assurance, cmd.Actor.Emergency)
		if err != nil {
			return fmt.Errorf("securitystate: record the operation: %w", err)
		}
		inserted := rows.Next()
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("securitystate: record the operation: %w", err)
		}
		if !inserted {
			return ErrInProgress
		}
		accepted = operationID
		return nil
	})
	if err != nil {
		return Operation{}, err
	}
	return s.Get(ctx, accepted)
}

func (s *Service) findByKey(ctx context.Context, tx db.Tx, actor id.UUID, key string) (id.UUID, string, bool, error) {
	rows, err := tx.Query(ctx, findByKeyStatement, actor.String(), key)
	if err != nil {
		return id.UUID{}, "", false, fmt.Errorf("securitystate: look up the key: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return id.UUID{}, "", false, rows.Err()
	}
	var raw, digest string
	if err := rows.Scan(&raw, &digest); err != nil {
		return id.UUID{}, "", false, err
	}
	operationID, err := id.Parse(raw)
	return operationID, digest, true, err
}

// admit checks that the Principal exists, is a person with a kernel user, is in a state the
// command admits, and, for a revocation, that the reference opens for it.
func (s *Service) admit(ctx context.Context, tx db.Tx, cmd Command) error {
	rows, err := tx.Query(ctx, lockMappingStatement, cmd.Subject.String(), string(s.cfg.Realm))
	if err != nil {
		return fmt.Errorf("securitystate: lock the Principal: %w", err)
	}
	if !rows.Next() {
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return ErrNotFound
	}
	var subjectType, state, kernelUser string
	err = rows.Scan(&subjectType, &state, &kernelUser)
	rows.Close()
	if err != nil {
		return fmt.Errorf("securitystate: read the Principal: %w", err)
	}

	switch {
	case subjectType != "human":
		return ErrWorkload
	case kernelUser == "":
		return fmt.Errorf("%w: it has no kernel user", ErrState)
	}
	switch {
	case cmd.Self:
		// A suspended person's token can outlive the suspension by its lifetime; it commands nothing.
		if state != "active" {
			return fmt.Errorf("%w: it is %s, and only an active Principal acts on itself", ErrState, state)
		}
	case cmd.Type == TypeSuspend:
		if state != "active" {
			return fmt.Errorf("%w: it is %s, and only an active Principal is suspended", ErrState, state)
		}
	case cmd.Type == TypeRestore:
		if state != "suspended" {
			return fmt.Errorf("%w: it is %s, and only a suspended Principal is restored", ErrState, state)
		}
		var open bool
		if err := tx.QueryRow(ctx, openFindingStatement, cmd.Subject.String()).Scan(&open); err != nil {
			return fmt.Errorf("securitystate: read the findings: %w", err)
		}
		if open {
			return fmt.Errorf("%w: an unresolved finding names it", ErrState)
		}
	default:
		if state != "active" && state != "suspended" {
			return fmt.Errorf("%w: it is %s", ErrState, state)
		}
	}
	if referenced(cmd.Type) {
		kind, purpose := refBinding(cmd.Type)
		if _, err := s.refs.Open(cmd.Ref, kind, cmd.Subject, purpose); err != nil {
			return ErrNotFound
		}
	}
	return nil
}

const getStatement = `SELECT operation_id::text, principal_id::text, operation_type, state, attempts,
       coalesce(result_code, ''), created_at, applied_at
FROM identity.security_operation WHERE operation_id = $1`

// Get reads one operation.
func (s *Service) Get(ctx context.Context, operationID id.UUID) (Operation, error) {
	var op Operation
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, getStatement, operationID.String())
		if err != nil {
			return fmt.Errorf("securitystate: read the operation: %w", err)
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return ErrNotFound
		}
		var opID, principalID string
		if err := rows.Scan(&opID, &principalID, &op.Type, &op.State, &op.Attempts, &op.ResultCode, &op.CreatedAt,
			&op.AppliedAt); err != nil {
			return fmt.Errorf("securitystate: scan the operation: %w", err)
		}
		if op.OperationID, err = id.Parse(opID); err != nil {
			return err
		}
		op.PrincipalID, err = id.Parse(principalID)
		return err
	})
	return op, err
}

// SecurityVersion is the version a command on the Principal names: 1 before any command.
func (s *Service) SecurityVersion(ctx context.Context, principalID id.UUID) (int64, error) {
	version := int64(1)
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT version FROM identity.security_subject_state WHERE principal_id = $1`,
			principalID.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			return rows.Scan(&version)
		}
		return rows.Err()
	})
	return version, err
}

// Submit accepts a command and executes it within the request budget. The operation it returns is
// final, or still running, for the caller to follow by its identifier.
func (s *Service) Submit(ctx context.Context, cmd Command) (Operation, error) {
	op, err := s.Accept(ctx, cmd)
	if err != nil || op.Final() {
		return op, err
	}
	budget, cancel := context.WithTimeout(ctx, s.cfg.Budget)
	defer cancel()
	if _, err := s.execute(budget, &op.OperationID); err != nil {
		// The operation is accepted and the executor retries it, so the caller is told where it is
		// rather than that it failed.
		s.logger.WarnContext(ctx, "inline execution of a security operation did not finish",
			slog.String("operation_id", op.OperationID.String()), slog.String("error", err.Error()))
	}
	return s.Get(ctx, op.OperationID)
}
