// Package firstcredential issues the temporary password a provider gives a person who has never set
// one, records each issuance without its value, and lapses an unused one (ADR-IAM-010,
// TDD-identity-control-005 2.12.0 §A First Credential).
//
// The value exists in this process for one response. It is generated here, set in the kernel as
// temporary, returned to the handler once, and never written to a row, a log, a trace, an event or an
// idempotency record (STD-IAM-001 2.8.0 §3.1). The kernel stores and verifies it.
package firstcredential

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The value's shape (ADR-IAM-010 §5.1): 24 symbols from Crockford's base32 alphabet, which leaves out
// I, L, O and U so no symbol is read as another, each 5 bits from the operating system's random
// source. 24 x 5 = 120 bits, above NIST SP 800-63B-4 §3.2.12's 112.
const (
	alphabet    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	valueLength = 24
	// ValueBits is the value's strength, asserted by a test.
	ValueBits = valueLength * 5
)

// The lapse bounds: 24 hours by default and at most, at least one hour (STD-IAM-001 2.8.0 §3.1,
// ADR-IAM-010 §5.2).
const (
	DefaultTTL = 24 * time.Hour
	MaxTTL     = 24 * time.Hour
	MinTTL     = time.Hour
)

// The outcomes an issuance ends in, each recorded once, by an insert.
const (
	OutcomeUsed     = "used"
	OutcomeLapsed   = "lapsed"
	OutcomeReplaced = "replaced"
	OutcomeFailed   = "failed"
)

// The refusals a route answers with.
var (
	ErrInvalid               = errors.New("firstcredential: the request is invalid")
	ErrSelf                  = errors.New("firstcredential: a provider cannot issue for the Principal in its own token")
	ErrNotFound              = errors.New("firstcredential: no such Principal")
	ErrState                 = errors.New("firstcredential: the Principal is not an active, linked human")
	ErrCredentialEstablished = errors.New("credential-established: the Principal has set a password of its own")
	ErrUnavailable           = errors.New("firstcredential: the identity kernel is unavailable")
	ErrKeyReuse              = errors.New("firstcredential: the Idempotency-Key was used for another request")
	ErrInProgress            = errors.New("firstcredential: a request with this Idempotency-Key is in progress")
)

// Transactor opens a transaction. The pool satisfies it.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Config is the service's settings.
type Config struct {
	Realm keycloak.Realm
	// TTL is IDENTITY_TEMPORARY_PASSWORD_TTL.
	TTL time.Duration
	// CallTimeout bounds one kernel call.
	CallTimeout time.Duration
	// SweepInterval is how often the lapse sweep runs: IDENTITY_TEMPORARY_PASSWORD_SWEEP_INTERVAL. The
	// sweep ends an issuance up to one interval before its lapse, so none outlives it. Zero is the
	// default, DefaultSweepInterval.
	SweepInterval time.Duration
}

// Actor is the provider who issues, as the request established it.
type Actor struct {
	Principal   id.UUID
	Emergency   bool
	Correlation string
	Assurance   string
	Route       string
}

// Request is one issuance.
type Request struct {
	Actor          Actor
	Subject        id.UUID
	Reason         string
	IdempotencyKey string
}

// Issuance is the record a provider is answered with. Value is set on the first answer alone: it is
// never stored, so a retry's answer, read back from the idempotency record, carries none.
type Issuance struct {
	IssuanceID  id.UUID   `json:"issuance_id"`
	PrincipalID id.UUID   `json:"principal_id"`
	IssuedBy    id.UUID   `json:"issued_by"`
	IssuedAt    time.Time `json:"issued_at"`
	LapsesAt    time.Time `json:"lapses_at"`
	Value       string    `json:"value,omitempty"`
}

// Service issues and lapses temporary passwords.
type Service struct {
	tx     Transactor
	kernel keycloak.FirstCredential
	cfg    Config
	logger *slog.Logger
	newID  func() (id.UUID, error)
	now    func() time.Time
	random func([]byte) (int, error)
}

// New builds the service.
func New(tx Transactor, kernel keycloak.FirstCredential, cfg Config, logger *slog.Logger) (*Service, error) {
	switch {
	case tx == nil || kernel == nil:
		return nil, errors.New("firstcredential: a transactor and a kernel are required")
	case cfg.Realm == "":
		return nil, errors.New("firstcredential: a realm is required")
	case cfg.TTL < MinTTL || cfg.TTL > MaxTTL:
		return nil, fmt.Errorf("firstcredential: the lapse must be between %s and %s", MinTTL, MaxTTL)
	case cfg.CallTimeout <= 0:
		return nil, errors.New("firstcredential: the kernel call timeout must be positive")
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = DefaultSweepInterval
	}
	if cfg.SweepInterval >= cfg.TTL {
		return nil, errors.New("firstcredential: the sweep interval must be shorter than the lapse")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{tx: tx, kernel: kernel, cfg: cfg, logger: logger, newID: id.NewV7, now: time.Now, random: rand.Read}, nil
}

// generate draws the value. A byte's low five bits pick a symbol: 256 is a multiple of 32, so every
// symbol is equally likely.
func (s *Service) generate() (string, error) {
	raw := make([]byte, valueLength)
	if _, err := s.random(raw); err != nil {
		return "", fmt.Errorf("firstcredential: the random source failed: %w", err)
	}
	var b strings.Builder
	b.Grow(valueLength)
	for _, v := range raw {
		b.WriteByte(alphabet[v&31])
	}
	clear(raw)
	return b.String(), nil
}

func (s *Service) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.cfg.CallTimeout)
}

const mappingStatement = `SELECT subject_type, state, coalesce(keycloak_user_id, '')
FROM identity.principal_mapping
WHERE principal_id = $1 AND realm = $2
FOR UPDATE`

const releaseStatement = `DELETE FROM platform.idempotency_key
WHERE scope = $1 AND key = $2 AND request_digest = $3 AND completed_at IS NULL`

const insertIssuanceStatement = `INSERT INTO identity.temporary_password_issuance
    (issuance_id, principal_id, issued_by, reason, correlation_id, emergency, assurance, issued_at, lapses_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

// replaceStatement ends every earlier issuance of the Principal that has no outcome: the kernel holds
// one password, and the new one replaces it.
const replaceStatement = `INSERT INTO identity.temporary_password_outcome (issuance_id, outcome)
SELECT i.issuance_id, 'replaced'
FROM identity.temporary_password_issuance i
WHERE i.principal_id = $1 AND i.issuance_id <> $2
  AND NOT EXISTS (SELECT 1 FROM identity.temporary_password_outcome o WHERE o.issuance_id = i.issuance_id)
ON CONFLICT (issuance_id) DO NOTHING`

const outcomeStatement = `INSERT INTO identity.temporary_password_outcome (issuance_id, outcome)
VALUES ($1, $2)
ON CONFLICT (issuance_id) DO NOTHING`

const evidenceStatement = `INSERT INTO identity.privileged_access
    (access_id, actor_principal_id, subject_principal_id, action, route, reason, result_count, outcome,
     correlation_id, emergency)
VALUES ($1, $2, $3, 'temporary_password.issue', $4, $5, 1, 'applied', $6, $7)`

// Issue generates a temporary password for a Principal that still owes UPDATE_PASSWORD, sets it in
// the kernel as temporary, and records the issuance. It answers the value once. replay is true when
// the Idempotency-Key was completed before: the issuance is answered as recorded, without a value.
//
// The order is what keeps every value the kernel holds accounted for:
//  1. the key is claimed and the Principal locked and checked, in one transaction;
//  2. the kernel is asked whether the user still owes UPDATE_PASSWORD;
//  3. the issuance is recorded, with its lapse, before the kernel holds anything;
//  4. the kernel sets the value as temporary;
//  5. the evidence and the key's answer, without the value, commit.
//
// A process that stops after 3 leaves an issuance the lapse sweep removes whatever the kernel holds,
// and a key in progress that refuses its retries, which is the safe direction.
func (s *Service) Issue(ctx context.Context, req Request) (issued Issuance, replay bool, err error) {
	switch {
	case req.Actor.Principal.IsNil() || req.Subject.IsNil() || strings.TrimSpace(req.Reason) == "" ||
		strings.TrimSpace(req.IdempotencyKey) == "":
		return Issuance{}, false, ErrInvalid
	case req.Actor.Principal == req.Subject:
		return Issuance{}, false, ErrSelf
	}
	scope := "temporary-password:principal:" + req.Actor.Principal.String()
	digest := idempotency.Digest([]byte("issue-temporary-password"), []byte(req.Subject.String()))
	release := func() {
		if err := s.tx.InTx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Tx) error {
			_, err := tx.Exec(ctx, releaseStatement, scope, req.IdempotencyKey, digest)
			return err
		}); err != nil {
			s.logger.WarnContext(ctx, "the Idempotency-Key of a refused temporary password was not released",
				slog.String("error", err.Error()))
		}
	}

	var user keycloak.UserID
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		claim, err := idempotency.Claim(ctx, tx, scope, req.IdempotencyKey, digest)
		switch {
		case errors.Is(err, idempotency.ErrConflict):
			return ErrKeyReuse
		case errors.Is(err, idempotency.ErrInProgress):
			return ErrInProgress
		case err != nil:
			return err
		}
		if claim.State == idempotency.StateReplay {
			replay = true
			return json.Unmarshal(claim.Body, &issued)
		}
		rows, err := tx.Query(ctx, mappingStatement, req.Subject.String(), string(s.cfg.Realm))
		if err != nil {
			return err
		}
		var subjectType, state, kernelUser string
		found := rows.Next()
		if found {
			err = rows.Scan(&subjectType, &state, &kernelUser)
		}
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
		switch {
		case err != nil:
			return err
		case !found:
			return ErrNotFound
		case subjectType != string(keycloak.SubjectHuman) || state != "active" || kernelUser == "":
			return ErrState
		}
		user = keycloak.UserID(kernelUser)
		return nil
	})
	if err != nil || replay {
		// A refused claim's transaction rolled back, so no key is held.
		return issued, replay, err
	}

	callCtx, cancel := s.call(ctx)
	actions, err := s.kernel.UserRequiredActions(callCtx, s.cfg.Realm, user)
	cancel()
	switch {
	case err != nil:
		release()
		return Issuance{}, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	case !keycloak.OwesPassword(actions):
		release()
		return Issuance{}, false, ErrCredentialEstablished
	}

	value, err := s.generate()
	if err != nil {
		release()
		return Issuance{}, false, err
	}
	issuanceID, err := s.newID()
	if err != nil {
		release()
		return Issuance{}, false, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	issued = Issuance{IssuanceID: issuanceID, PrincipalID: req.Subject, IssuedBy: req.Actor.Principal,
		IssuedAt: now, LapsesAt: now.Add(s.cfg.TTL)}
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, insertIssuanceStatement, issuanceID.String(), req.Subject.String(),
			req.Actor.Principal.String(), strings.TrimSpace(req.Reason), req.Actor.Correlation, req.Actor.Emergency,
			req.Actor.Assurance, issued.IssuedAt, issued.LapsesAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, replaceStatement, req.Subject.String(), issuanceID.String())
		return err
	}); err != nil {
		release()
		return Issuance{}, false, fmt.Errorf("firstcredential: record the issuance: %w", err)
	}

	callCtx, cancel = s.call(ctx)
	err = s.kernel.SetTemporaryPassword(callCtx, s.cfg.Realm, user, value)
	cancel()
	if err != nil {
		// The kernel may hold the value or not. The issuance stays open, so the lapse sweep removes
		// whatever it holds; a definite refusal is recorded failed. The key is released, so the
		// provider's retry issues again, which replaces this issuance.
		if !errors.Is(err, keycloak.ErrUnavailable) && !errors.Is(err, keycloak.ErrAmbiguous) &&
			!errors.Is(err, context.DeadlineExceeded) {
			s.recordOutcome(ctx, issuanceID, OutcomeFailed)
		}
		release()
		return Issuance{}, false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	// The key's answer is the issuance without its value.
	body, err := json.Marshal(issued)
	if err != nil {
		return Issuance{}, false, err
	}
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		accessID, err := s.newID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, evidenceStatement, accessID.String(), req.Actor.Principal.String(),
			req.Subject.String(), req.Actor.Route, strings.TrimSpace(req.Reason), req.Actor.Correlation,
			req.Actor.Emergency); err != nil {
			return err
		}
		return idempotency.Complete(ctx, tx, scope, req.IdempotencyKey, digest, 201, body)
	}); err != nil {
		// The kernel holds the value and the issuance is recorded, so it lapses. The provider is not
		// shown a value whose evidence did not commit; the key stays in progress and refuses a retry.
		s.logger.ErrorContext(ctx, "a temporary password was set and its evidence did not commit; it lapses unused",
			slog.String("issuance_id", issuanceID.String()), slog.String("error", err.Error()))
		return Issuance{}, false, fmt.Errorf("firstcredential: record the evidence: %w", err)
	}
	s.logger.InfoContext(ctx, "a temporary password was issued",
		slog.String("issuance_id", issuanceID.String()), slog.String("principal_id", req.Subject.String()),
		slog.String("issued_by", req.Actor.Principal.String()), slog.Time("lapses_at", issued.LapsesAt))
	issued.Value = value
	return issued, false, nil
}

func (s *Service) recordOutcome(ctx context.Context, issuanceID id.UUID, outcome string) {
	if err := s.tx.InTx(context.WithoutCancel(ctx), func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, outcomeStatement, issuanceID.String(), outcome)
		return err
	}); err != nil {
		s.logger.WarnContext(ctx, "a temporary password's outcome was not recorded",
			slog.String("issuance_id", issuanceID.String()), slog.String("outcome", outcome),
			slog.String("error", err.Error()))
	}
}

// EnrolmentRequest is the temporary password an enrolment issues to the person who has just proven
// the invited address (ADR-IAM-011 §5.3, STD-IAM-001 3.1.0 §3.1, the second recipient).
type EnrolmentRequest struct {
	// Caller is the BFF workload that carried the verified code: the issuance's issued_by. No provider
	// acts, so no privileged-access row is written; the enrolment record is the evidence.
	Caller      id.UUID
	Subject     id.UUID
	EnrolmentID id.UUID
	Correlation string
}

// EnrolmentAssurance is what an enrolment's issuance records as its assurance: the address proof,
// in place of a provider's aal2 session (STD-IAM-001 3.1.0 §3.1).
const EnrolmentAssurance = "enrolment-code"

// IssueForEnrolment issues the first temporary password of a Principal an enrolment has just
// created. It follows Issue's order without its idempotency key and its provider evidence: the
// enrolment is completed once, in the transaction that records this issuance's identifier, and a
// retry after a failure here issues again, replacing the earlier issuance as a provider's retry does.
func (s *Service) IssueForEnrolment(ctx context.Context, req EnrolmentRequest) (Issuance, error) {
	if req.Caller.IsNil() || req.Subject.IsNil() || req.EnrolmentID.IsNil() || req.Caller == req.Subject {
		return Issuance{}, ErrInvalid
	}
	var user keycloak.UserID
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, mappingStatement, req.Subject.String(), string(s.cfg.Realm))
		if err != nil {
			return err
		}
		var subjectType, state, kernelUser string
		found := rows.Next()
		if found {
			err = rows.Scan(&subjectType, &state, &kernelUser)
		}
		rows.Close()
		if err == nil {
			err = rows.Err()
		}
		switch {
		case err != nil:
			return err
		case !found:
			return ErrNotFound
		case subjectType != string(keycloak.SubjectHuman) || state != "active" || kernelUser == "":
			return ErrState
		}
		user = keycloak.UserID(kernelUser)
		return nil
	}); err != nil {
		return Issuance{}, err
	}

	callCtx, cancel := s.call(ctx)
	actions, err := s.kernel.UserRequiredActions(callCtx, s.cfg.Realm, user)
	cancel()
	switch {
	case err != nil:
		return Issuance{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	case !keycloak.OwesPassword(actions):
		return Issuance{}, ErrCredentialEstablished
	}
	value, err := s.generate()
	if err != nil {
		return Issuance{}, err
	}
	issuanceID, err := s.newID()
	if err != nil {
		return Issuance{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	issued := Issuance{IssuanceID: issuanceID, PrincipalID: req.Subject, IssuedBy: req.Caller,
		IssuedAt: now, LapsesAt: now.Add(s.cfg.TTL)}
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, insertIssuanceStatement, issuanceID.String(), req.Subject.String(),
			req.Caller.String(), "enrolment "+req.EnrolmentID.String(), req.Correlation, false,
			EnrolmentAssurance, issued.IssuedAt, issued.LapsesAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, replaceStatement, req.Subject.String(), issuanceID.String())
		return err
	}); err != nil {
		return Issuance{}, fmt.Errorf("firstcredential: record the issuance: %w", err)
	}
	callCtx, cancel = s.call(ctx)
	err = s.kernel.SetTemporaryPassword(callCtx, s.cfg.Realm, user, value)
	cancel()
	if err != nil {
		if !errors.Is(err, keycloak.ErrUnavailable) && !errors.Is(err, keycloak.ErrAmbiguous) &&
			!errors.Is(err, context.DeadlineExceeded) {
			s.recordOutcome(ctx, issuanceID, OutcomeFailed)
		}
		return Issuance{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	s.logger.InfoContext(ctx, "a temporary password was issued for an enrolment",
		slog.String("issuance_id", issuanceID.String()), slog.String("principal_id", req.Subject.String()),
		slog.String("enrolment_id", req.EnrolmentID.String()), slog.Time("lapses_at", issued.LapsesAt))
	issued.Value = value
	return issued, nil
}
