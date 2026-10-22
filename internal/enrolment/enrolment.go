// Package enrolment is the third authorized creation path: a person invited to a Tenant who holds no
// account creates one from the invitation, after proving the invited address (ADR-IAM-011 §5.1 to
// §5.9, STD-IAM-001 3.1.0 §3.1, TDD-identity-control-001 1.27.0 §Enrolment From an Invitation).
//
// Request sends a code to the invited address, or the "an account exists" message in its place, and
// answers one way whatever happened. Verify takes the code back and creates the Principal through
// the ordinary path, with a temporary password shown once. No token, invitation identifier, address,
// code or password is ever logged.
package enrolment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/anshacerbia2/identity-control/internal/firstcredential"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/securitynotify"
)

// CodeTTL and CodeAttempts are the code's bounds (ADR-IAM-011 §5.2).
const (
	CodeTTL      = 10 * time.Minute
	CodeAttempts = 5
	codeDigits   = 8
)

// CallerScope is the creation path's idempotency scope; the key is the enrolment identifier, so a
// retry of the same enrolment's create replays its Principal.
const CallerScope = "enrolment"

var (
	// ErrLimited is a client address past one of its limits: 429 with Retry-After (§5.8).
	ErrLimited = errors.New("enrolment: the client address is past its limit")
	// ErrRefused is every refused :verify, one answer for each cause (§5.2, §5.9).
	ErrRefused = errors.New("enrolment: the code is wrong, has expired, or has been tried too often")
	// ErrUnavailable is Organization Control or the kernel that could not be asked: 503, the same for
	// every token and every code.
	ErrUnavailable = errors.New("enrolment: a dependency is unavailable")
)

// Transactor opens a transaction. The pool satisfies it.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Invitation is what Organization Control's resolve answers (ADR-IAM-011 §5.7).
type Invitation struct {
	ID      id.UUID
	Address string
}

// Resolver asks Organization Control which invitation a token names: internal/organization's client,
// adapted by the composition root. Found false is "nothing", whatever the cause.
type Resolver interface {
	Resolve(ctx context.Context, token string) (Invitation, bool, error)
}

// Kernel finds the users whose username or email equals an address: *keycloak.Admin.
type Kernel interface {
	FindByUsernameOrEmail(ctx context.Context, realm keycloak.Realm, value string) ([]keycloak.User, error)
}

// Creator is the ordinary creation path: *provisioning.Provisioner.
type Creator interface {
	Create(ctx context.Context, req provisioning.CreateRequest) (provisioning.Response, error)
}

// Issuer issues the first temporary password: *firstcredential.Service.
type Issuer interface {
	IssueForEnrolment(ctx context.Context, req firstcredential.EnrolmentRequest) (firstcredential.Issuance, error)
}

// Config is the service's settings.
type Config struct {
	Realm keycloak.Realm
	// CallTimeout bounds one call to Organization Control or the kernel.
	CallTimeout time.Duration
}

// Service runs both commands.
type Service struct {
	tx       Transactor
	resolver Resolver
	kernel   Kernel
	creator  Creator
	issuer   Issuer
	sealer   securitynotify.Sealer
	hasher   Hasher
	cfg      Config
	logger   *slog.Logger
	newID    func() (id.UUID, error)
	newCode  func() (string, error)

	requests, verifications, limited metric.Int64Counter
}

// New builds the service.
func New(tx Transactor, resolver Resolver, kernel Kernel, creator Creator, issuer Issuer,
	sealer securitynotify.Sealer, hasher Hasher, cfg Config, logger *slog.Logger, meter metric.Meter) (*Service, error) {
	switch {
	case tx == nil || resolver == nil || kernel == nil || creator == nil || issuer == nil || sealer == nil || hasher == nil:
		return nil, errors.New("enrolment: a transactor, a resolver, a kernel, a creator, an issuer, a sealer and a hasher are required")
	case cfg.Realm == "":
		return nil, errors.New("enrolment: a realm is required")
	case cfg.CallTimeout <= 0:
		return nil, errors.New("enrolment: the call timeout must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("")
	}
	s := &Service{tx: tx, resolver: resolver, kernel: kernel, creator: creator, issuer: issuer, sealer: sealer,
		hasher: hasher, cfg: cfg, logger: logger, newID: id.NewV7, newCode: newCode}
	var err error
	if s.requests, err = meter.Int64Counter("identity.enrolment.requests",
		metric.WithDescription("Enrolment requests by outcome class: sent, held, limited, nothing, collision")); err != nil {
		return nil, err
	}
	if s.verifications, err = meter.Int64Counter("identity.enrolment.verifications",
		metric.WithDescription("Enrolment verifications by outcome: completed, refused, collision")); err != nil {
		return nil, err
	}
	if s.limited, err = meter.Int64Counter("identity.enrolment.limited",
		metric.WithDescription("Enrolment requests answered 429, by route")); err != nil {
		return nil, err
	}
	return s, nil
}

func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", codeDigits, n.Int64()), nil
}

// codeHash binds a code to its enrolment, so a code proves the enrolment it was sent for and no other.
func codeHash(enrolmentID id.UUID, code string) string {
	sum := sha256.Sum256([]byte(enrolmentID.String() + "|" + code))
	return hex.EncodeToString(sum[:])
}

// AddressHash is the record's lasting form of an address: SHA-256 of it lower-cased (§5.3).
func AddressHash(address string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(address)))
	return hex.EncodeToString(sum[:])
}

// Limited carries how long the client address must wait.
type Limited struct{ RetryAfter int64 }

func (l *Limited) Error() string { return ErrLimited.Error() }
func (l *Limited) Unwrap() error { return ErrLimited }

// RequestInput is one POST /v1/enrolments.
type RequestInput struct {
	// Caller is the admitted BFF workload.
	Caller id.UUID
	// ClientAddress is the counted form of the client address: an IPv4 address, or an IPv6 /64.
	ClientAddress string
	Token         string
}

// Outcome classes, for the log and the counter alone: no caller ever sees one.
const (
	outcomeSent      = "sent"
	outcomeHeld      = "held"
	outcomeLimited   = "limited"
	outcomeNothing   = "nothing"
	outcomeCollision = "collision"
)

func (s *Service) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.cfg.CallTimeout)
}

// admit counts one request of the client address under the route's rules.
func (s *Service) admit(ctx context.Context, address string, rules []Rule, route string) error {
	var exceeded bool
	var retry int64
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		exceeded, retry, err = count(ctx, tx, addressKey(s.hasher, address), rules)
		return err
	}); err != nil {
		return err
	}
	if exceeded {
		s.limited.Add(ctx, 1, metric.WithAttributes(attribute.String("route", route)))
		return &Limited{RetryAfter: retry}
	}
	return nil
}

// Request is POST /v1/enrolments (ADR-IAM-011 §5.1, §5.2, §5.8, §5.9). It answers an enrolment
// identifier in every case but a refused address, a malformed request and a dependency that could not
// be asked: the enrolment's when a code was sent, and otherwise a fresh one stored nowhere.
func (s *Service) Request(ctx context.Context, in RequestInput) (id.UUID, error) {
	if in.Caller.IsNil() || in.ClientAddress == "" {
		return id.UUID{}, ErrInvalid
	}
	if err := s.admit(ctx, in.ClientAddress, RequestRules, "request"); err != nil {
		return id.UUID{}, err
	}
	decoy, err := s.newID()
	if err != nil {
		return id.UUID{}, err
	}
	outcome, enrolmentID, err := s.request(ctx, in)
	if err != nil {
		return id.UUID{}, err
	}
	s.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	if outcome == outcomeSent {
		s.logger.InfoContext(ctx, "an enrolment code was queued", slog.String("enrolment_id", enrolmentID.String()))
		return enrolmentID, nil
	}
	s.logger.InfoContext(ctx, "an enrolment request sent no code", slog.String("outcome", outcome))
	return decoy, nil
}

func (s *Service) request(ctx context.Context, in RequestInput) (string, id.UUID, error) {
	callCtx, cancel := s.call(ctx)
	invitation, found, err := s.resolver.Resolve(callCtx, in.Token)
	cancel()
	if err != nil {
		return "", id.UUID{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if !found || invitation.ID.IsNil() {
		return outcomeNothing, id.UUID{}, nil
	}
	address, err := securitynotify.NormalizeAddress(invitation.Address)
	if err != nil {
		// An invitation whose address this service cannot send to is nothing it can act on.
		return outcomeNothing, id.UUID{}, nil
	}
	// The kernel is asked outside the transaction, so no lock waits on it (§5.9).
	kernelHeld, err := s.kernelHolds(ctx, address, id.UUID{})
	if err != nil {
		return "", id.UUID{}, err
	}
	enrolmentID, err := s.newID()
	if err != nil {
		return "", id.UUID{}, err
	}
	code, err := s.newCode()
	if err != nil {
		return "", id.UUID{}, err
	}
	outcome := ""
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// One request for an invitation at a time, so "one open enrolment" holds under concurrency.
		if _, err := tx.Exec(ctx, lockStatement, invitation.ID.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, closeLapsedStatement, invitation.ID.String()); err != nil {
			return err
		}
		var open bool
		if err := tx.QueryRow(ctx, openStatement, invitation.ID.String()).Scan(&open); err != nil {
			return err
		}
		if open {
			outcome = outcomeHeld
			return nil
		}
		key := invitationKey(s.hasher, invitation.ID)
		limited, err := atLimit(ctx, tx, key, MessageRules)
		if err != nil {
			return err
		}
		if limited {
			outcome = outcomeLimited
			return nil
		}
		held := kernelHeld
		if !held {
			if held, err = serviceHolds(ctx, tx, address, id.UUID{}); err != nil {
				return err
			}
		}
		if _, _, err := count(ctx, tx, key, MessageRules); err != nil {
			return err
		}
		if held {
			outcome = outcomeCollision
			// The same queue in every case (§5.9: "the message is sent through the same queue").
			return securitynotify.QueueAccountExists(ctx, tx, address)
		}
		if _, err := tx.Exec(ctx, insertStatement, enrolmentID.String(), invitation.ID.String(), AddressHash(address),
			address, codeHash(enrolmentID, code), interval(CodeTTL), in.Caller.String()); err != nil {
			return err
		}
		outcome = outcomeSent
		return securitynotify.QueueEnrolmentCode(ctx, tx, s.sealer, enrolmentID, address, code)
	})
	if err != nil {
		return "", id.UUID{}, fmt.Errorf("enrolment: request: %w", err)
	}
	return outcome, enrolmentID, nil
}

const lockStatement = `SELECT pg_advisory_xact_lock(hashtextextended('identity.enrolment:' || $1, 0))`

// closeLapsedStatement closes an invitation's open enrolments whose code has lapsed or is used up, so
// the address they held is cleared and a new code may be sent.
const closeLapsedStatement = `UPDATE identity.enrolment
SET state = 'refused', address = NULL, code_hash = NULL, closed_at = now()
WHERE invitation_id = $1 AND state = 'open' AND (code_expires_at <= now() OR attempts >= 5)
  AND (verifying_until IS NULL OR verifying_until <= now())`

const openStatement = `SELECT EXISTS (SELECT 1 FROM identity.enrolment
    WHERE invitation_id = $1 AND state = 'open' AND code_expires_at > now() AND attempts < 5)`

const insertStatement = `INSERT INTO identity.enrolment
    (enrolment_id, invitation_id, address_hash, address, code_hash, code_expires_at, caller_principal_id)
VALUES ($1, $2, $3, $4, $5, now() + $6::interval, $7)`

// serviceHoldsStatement is true when a Principal of this service, other than $2, holds the address:
// an active notification address, proven or not, or a mapping whose username or email it is. Retired
// Principals hold nothing (§5.9).
const serviceHoldsStatement = `SELECT EXISTS (
    SELECT 1 FROM identity.notification_address a
    JOIN identity.principal_mapping m ON m.principal_id = a.principal_id
    WHERE lower(a.address) = lower($1) AND a.state = 'active' AND m.state <> 'retired'
      AND m.principal_id::text <> $2
) OR EXISTS (
    SELECT 1 FROM identity.principal_mapping m
    WHERE (lower(m.username) = lower($1) OR lower(coalesce(m.email, '')) = lower($1))
      AND m.state <> 'retired' AND m.principal_id::text <> $2)`

func serviceHolds(ctx context.Context, tx db.Tx, address string, own id.UUID) (bool, error) {
	var held bool
	err := tx.QueryRow(ctx, serviceHoldsStatement, address, own.String()).Scan(&held)
	return held, err
}

// kernelHolds is true when a kernel user other than own's has the address as its username or email.
func (s *Service) kernelHolds(ctx context.Context, address string, own id.UUID) (bool, error) {
	callCtx, cancel := s.call(ctx)
	users, err := s.kernel.FindByUsernameOrEmail(callCtx, s.cfg.Realm, address)
	cancel()
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	for _, user := range users {
		if own.IsNil() || user.PrincipalID != own {
			return true, nil
		}
	}
	return false, nil
}

// VerifyInput is one POST /v1/enrolments/{enrolment_id}:verify.
type VerifyInput struct {
	Caller        id.UUID
	ClientAddress string
	EnrolmentID   id.UUID
	Code          string
	Correlation   string
}

// Completed is the answer to the right code: the Principal and its temporary password, shown once.
type Completed struct {
	PrincipalID       id.UUID   `json:"principal_id"`
	Username          string    `json:"username"`
	TemporaryPassword string    `json:"temporary_password"`
	LapsesAt          time.Time `json:"lapses_at"`

	issuance id.UUID
}

type enrolmentRow struct {
	invitationID id.UUID
	address      string
	codeHash     string
	attempts     int
	open         bool
}

const lockEnrolmentStatement = `SELECT invitation_id::text, coalesce(address, ''), coalesce(code_hash, ''), attempts,
       state = 'open' AND code_expires_at > now() AND attempts < 5
FROM identity.enrolment WHERE enrolment_id = $1 FOR UPDATE`

const failedAttemptStatement = `UPDATE identity.enrolment
SET attempts = attempts + 1,
    state = CASE WHEN attempts + 1 >= 5 THEN 'refused' ELSE state END,
    address = CASE WHEN attempts + 1 >= 5 THEN NULL ELSE address END,
    code_hash = CASE WHEN attempts + 1 >= 5 THEN NULL ELSE code_hash END,
    closed_at = CASE WHEN attempts + 1 >= 5 THEN now() ELSE closed_at END
WHERE enrolment_id = $1`

const refuseStatement = `UPDATE identity.enrolment
SET state = 'refused', address = NULL, code_hash = NULL, closed_at = now(), verifying_until = NULL
WHERE enrolment_id = $1 AND state = 'open'`

const completeStatement = `UPDATE identity.enrolment
SET state = 'completed', principal_id = $2, issuance_id = $3, address = NULL, code_hash = NULL, closed_at = now(),
    verifying_until = NULL
WHERE enrolment_id = $1 AND state = 'open'`

// ownMappingStatement finds the Principal this enrolment's own create made, by its idempotency key, so
// the double check before a resumed create does not find the enrolment colliding with itself.
const ownMappingStatement = `SELECT coalesce(max(principal_id::text), '') FROM identity.principal_mapping
WHERE idempotency_scope = $1 AND idempotency_key = $2`

// verifyLease is how long one :verify holds an enrolment while it creates the Principal and issues
// the password, with no transaction open across those calls. A second :verify of the enrolment meanwhile
// is unavailable, never a second password; a process that stops lets the lease lapse.
const verifyLease = time.Minute

const leaseStatement = `UPDATE identity.enrolment SET verifying_until = now() + $2::interval
WHERE enrolment_id = $1 AND state = 'open' AND (verifying_until IS NULL OR verifying_until <= now())`

const releaseStatement = `UPDATE identity.enrolment SET verifying_until = NULL WHERE enrolment_id = $1`

// Verify is :verify (ADR-IAM-011 §5.2, §5.3, §5.9). Every refusal is ErrRefused.
//
// The code is checked under the row's lock, and the right code takes a lease on the enrolment in the
// same transaction. The double check, the create and the issuance then run with no transaction open,
// as the creation path requires, and a last transaction completes or refuses the enrolment and ends
// the lease.
func (s *Service) Verify(ctx context.Context, in VerifyInput) (Completed, error) {
	if in.Caller.IsNil() || in.ClientAddress == "" || in.EnrolmentID.IsNil() {
		return Completed{}, ErrInvalid
	}
	if err := s.admit(ctx, in.ClientAddress, VerifyRules, "verify"); err != nil {
		return Completed{}, err
	}
	var (
		row    enrolmentRow
		right  bool
		leased bool
	)
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var found bool
		var err error
		row, found, err = lockEnrolment(ctx, tx, in.EnrolmentID)
		if err != nil || !found || !row.open {
			return err
		}
		key := invitationKey(s.hasher, row.invitationID)
		exhausted, err := atLimit(ctx, tx, key, []Rule{FailureRule})
		if err != nil {
			return err
		}
		if exhausted {
			s.logger.WarnContext(ctx, "an enrolment's invitation has had its failed codes for the day",
				slog.String("enrolment_id", in.EnrolmentID.String()))
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(codeHash(in.EnrolmentID, strings.TrimSpace(in.Code))), []byte(row.codeHash)) != 1 {
			if _, err := tx.Exec(ctx, failedAttemptStatement, in.EnrolmentID.String()); err != nil {
				return err
			}
			_, _, err := count(ctx, tx, key, []Rule{FailureRule})
			return err
		}
		right = true
		tag, err := tx.Exec(ctx, leaseStatement, in.EnrolmentID.String(), interval(verifyLease))
		if err != nil {
			return err
		}
		leased = tag.RowsAffected() == 1
		return nil
	}); err != nil {
		return Completed{}, fmt.Errorf("enrolment: verify: %w", err)
	}
	if !right {
		return s.refused(ctx, in.EnrolmentID, "refused")
	}
	if !leased {
		// Another :verify of this enrolment is running: retry once it ends.
		return Completed{}, fmt.Errorf("%w: the enrolment is being verified", ErrUnavailable)
	}

	completed, outcome, failure := s.create(ctx, in, row)
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		switch {
		case failure != nil:
			_, err := tx.Exec(ctx, releaseStatement, in.EnrolmentID.String())
			return err
		case outcome == "completed":
			_, err := tx.Exec(ctx, completeStatement, in.EnrolmentID.String(), completed.PrincipalID.String(),
				completed.issuance.String())
			return err
		default:
			_, err := tx.Exec(ctx, refuseStatement, in.EnrolmentID.String())
			return err
		}
	}); err != nil {
		return Completed{}, fmt.Errorf("enrolment: verify: %w", err)
	}
	if failure != nil {
		s.logger.WarnContext(ctx, "an enrolment could not be completed now; the same code resumes it",
			slog.String("enrolment_id", in.EnrolmentID.String()), slog.String("error", failure.Error()))
		return Completed{}, failure
	}
	if outcome != "completed" {
		return s.refused(ctx, in.EnrolmentID, outcome)
	}
	s.verifications.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	s.logger.InfoContext(ctx, "an enrolment created a Principal",
		slog.String("enrolment_id", in.EnrolmentID.String()), slog.String("principal_id", completed.PrincipalID.String()))
	completed.issuance = id.UUID{}
	return completed, nil
}

func (s *Service) refused(ctx context.Context, enrolmentID id.UUID, outcome string) (Completed, error) {
	s.verifications.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	s.logger.InfoContext(ctx, "an enrolment verification was refused",
		slog.String("enrolment_id", enrolmentID.String()), slog.String("outcome", outcome))
	return Completed{}, ErrRefused
}

// create is the right code's work, under the lease and outside any transaction: the double check
// again, immediately before the create (§5.9), leaving out only this enrolment's own Principal from an
// earlier, interrupted attempt; the create; and the issuance. It answers the outcome, or a failure that
// leaves the enrolment open for the same code to resume.
func (s *Service) create(ctx context.Context, in VerifyInput, row enrolmentRow) (Completed, string, error) {
	var own id.UUID
	held := false
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var ownRaw string
		if err := tx.QueryRow(ctx, ownMappingStatement, CallerScope, in.EnrolmentID.String()).Scan(&ownRaw); err != nil {
			return err
		}
		if ownRaw != "" {
			var err error
			if own, err = id.Parse(ownRaw); err != nil {
				return err
			}
		}
		var err error
		held, err = serviceHolds(ctx, tx, row.address, own)
		return err
	}); err != nil {
		return Completed{}, "", err
	}
	if !held {
		var err error
		if held, err = s.kernelHolds(ctx, row.address, own); err != nil {
			return Completed{}, "", err
		}
	}
	if held {
		return Completed{}, "collision", nil
	}

	username := strings.ToLower(row.address)
	created, err := s.creator.Create(ctx, provisioning.CreateRequest{
		CallerScope: CallerScope, IdempotencyKey: in.EnrolmentID.String(), Realm: s.cfg.Realm,
		Username: username, Email: row.address, SubjectType: keycloak.SubjectHuman,
		VerifiedEmail: true, QuarantineOnConflict: true,
	})
	switch {
	case errors.Is(err, provisioning.ErrKernelDuplicate):
		return Completed{}, "collision", nil
	case err != nil:
		// Unavailable, ambiguous or still in progress: the mapping waits for recovery, and the same
		// code resumes through the create's key.
		return Completed{}, "", fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	issued, err := s.issuer.IssueForEnrolment(ctx, firstcredential.EnrolmentRequest{
		Caller: in.Caller, Subject: created.PrincipalID, EnrolmentID: in.EnrolmentID, Correlation: in.Correlation})
	switch {
	case errors.Is(err, firstcredential.ErrCredentialEstablished):
		// The person set a password already, after an earlier attempt: nothing is shown again.
		return Completed{}, "refused", nil
	case err != nil:
		return Completed{}, "", fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return Completed{PrincipalID: created.PrincipalID, Username: username, TemporaryPassword: issued.Value,
		LapsesAt: issued.LapsesAt, issuance: issued.IssuanceID}, "completed", nil
}

func lockEnrolment(ctx context.Context, tx db.Tx, enrolmentID id.UUID) (enrolmentRow, bool, error) {
	rows, err := tx.Query(ctx, lockEnrolmentStatement, enrolmentID.String())
	if err != nil {
		return enrolmentRow{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return enrolmentRow{}, false, rows.Err()
	}
	var row enrolmentRow
	var invitation string
	if err := rows.Scan(&invitation, &row.address, &row.codeHash, &row.attempts, &row.open); err != nil {
		return enrolmentRow{}, false, err
	}
	if row.invitationID, err = id.Parse(invitation); err != nil {
		return enrolmentRow{}, false, err
	}
	return row, true, rows.Err()
}

// sweepStatements end what has run its course: every count whose window has ended (§5.8: "each is
// deleted when its window ends"), and every open enrolment whose code has lapsed, clearing its address.
var sweepStatements = []string{
	`DELETE FROM identity.enrolment_count WHERE window_ends_at <= now()`,
	`UPDATE identity.enrolment SET state = 'refused', address = NULL, code_hash = NULL, closed_at = now()
	 WHERE state = 'open' AND code_expires_at <= now() AND (verifying_until IS NULL OR verifying_until <= now())`,
}

// SweepInterval is how often Sweep runs.
const SweepInterval = time.Minute

// Sweep runs the sweep statements and answers how many rows they touched.
func (s *Service) Sweep(ctx context.Context) (int64, error) {
	var touched int64
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, statement := range sweepStatements {
			tag, err := tx.Exec(ctx, statement)
			if err != nil {
				return err
			}
			touched += tag.RowsAffected()
		}
		return nil
	})
	return touched, err
}
