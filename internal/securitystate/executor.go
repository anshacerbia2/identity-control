package securitystate

// The executor (TDD-identity-control-005 §Containment as Built, Execution). One attempt is a claim,
// the kernel calls, and a finish, each claim recorded as an attempt row (STD-GLB-011 §3.4).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// claimStatement selects due operations whose earlier sequences on the same Principal are all final
// and not parked, skipping any another worker holds (PostgreSQL's SKIP LOCKED for a queue-like
// table). %s narrows it to one operation for inline execution.
const claimStatement = `SELECT o.operation_id::text
FROM identity.security_operation o
WHERE o.state IN ('pending', 'retrying') AND o.next_attempt_at <= now() %s
  AND NOT EXISTS (
    SELECT 1 FROM identity.security_operation e
    WHERE e.principal_id = o.principal_id AND e.subject_sequence < o.subject_sequence
      AND e.state IN ('pending', 'retrying', 'unresolved'))
ORDER BY o.next_attempt_at, o.created_at
LIMIT $1
FOR UPDATE OF o SKIP LOCKED`

// leaseStatement takes the claim: one more attempt, hidden from other workers until the lease ends.
const leaseStatement = `UPDATE identity.security_operation
SET attempts = attempts + 1, next_attempt_at = now() + $2 * interval '1 millisecond'
WHERE operation_id = $1
RETURNING attempts, principal_id::text, operation_type, coalesce(sealed_object_ref, ''), actor_principal_id::text,
          coalesce(reason, ''), correlation_id, emergency, redriven_at, created_at`

const attemptStatement = `INSERT INTO identity.security_operation_attempt (operation_id, attempt, lease_until)
VALUES ($1, $2, now() + $3 * interval '1 millisecond')`

const kernelUserStatement = `SELECT coalesce(keycloak_user_id, '') FROM identity.principal_mapping WHERE principal_id = $1`

// claimed is one operation a worker holds for one attempt.
type claimed struct {
	operationID id.UUID
	attempt     int
	subject     id.UUID
	opType      string
	ref         string
	actor       id.UUID
	reason      string
	correlation string
	emergency   bool
	kernelUser  keycloak.UserID
	// redrivenAt is the attempt count at the last re-drive: the budget counts attempts past it.
	redrivenAt int
	createdAt  time.Time
}

// outcome is what one attempt established.
type outcome struct {
	state      string // applied, refused, retrying or unresolved
	resultCode string
	errorClass string
	// removed is the kernel credential an authenticator command deleted; nil when it deleted none.
	removed *keycloak.Credential
}

// RunOnce executes every due operation it can claim, up to the batch size, and reports how many.
func (s *Service) RunOnce(ctx context.Context) (int, error) {
	return s.execute(ctx, nil)
}

// Run executes due operations every interval until ctx ends. The composition root starts it.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("the security operation executor could not claim", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// execute claims and runs due operations: one, when only is set, or a batch.
func (s *Service) execute(ctx context.Context, only *id.UUID) (int, error) {
	work, err := s.claim(ctx, only)
	if err != nil {
		return 0, err
	}
	for _, c := range work {
		s.metric.wait.Record(ctx, seconds(time.Since(c.createdAt)), typed(c.opType))
		started := time.Now()
		result := s.attempt(ctx, c)
		s.metric.duration.Record(ctx, seconds(time.Since(started)), typed(c.opType))
		// The finish is written even when the caller's budget ended during the kernel calls: the
		// effect may have landed, and leaving the outcome to the lease would repeat the calls.
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		err := s.finish(finishCtx, c, result)
		cancel()
		if err != nil {
			return len(work), err
		}
	}
	return len(work), nil
}

func (s *Service) claim(ctx context.Context, only *id.UUID) ([]claimed, error) {
	var work []claimed
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		statement, args := fmt.Sprintf(claimStatement, ""), []any{s.cfg.BatchSize}
		if only != nil {
			statement, args = fmt.Sprintf(claimStatement, "AND o.operation_id = $2"), []any{1, only.String()}
		}
		rows, err := tx.Query(ctx, statement, args...)
		if err != nil {
			return fmt.Errorf("securitystate: claim: %w", err)
		}
		var ids []string
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, raw)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		lease := s.cfg.Lease.Milliseconds()
		for _, raw := range ids {
			var (
				c                  claimed
				subject, actor, kc string
			)
			if err := tx.QueryRow(ctx, leaseStatement, raw, lease).Scan(&c.attempt, &subject, &c.opType, &c.ref,
				&actor, &c.reason, &c.correlation, &c.emergency, &c.redrivenAt, &c.createdAt); err != nil {
				return fmt.Errorf("securitystate: lease: %w", err)
			}
			if _, err := tx.Exec(ctx, attemptStatement, raw, c.attempt, lease); err != nil {
				return fmt.Errorf("securitystate: record the attempt: %w", err)
			}
			// The kernel user is read at execution, not copied at acceptance: a relink since then
			// moved the Principal to another user (STD-GLB-011 §3.13).
			if err := tx.QueryRow(ctx, kernelUserStatement, subject).Scan(&kc); err != nil {
				return fmt.Errorf("securitystate: read the kernel user: %w", err)
			}
			c.kernelUser = keycloak.UserID(kc)
			if c.operationID, err = id.Parse(raw); err != nil {
				return err
			}
			if c.subject, err = id.Parse(subject); err != nil {
				return err
			}
			if c.actor, err = id.Parse(actor); err != nil {
				return err
			}
			work = append(work, c)
		}
		return nil
	})
	return work, err
}

// errReadBack is a call the kernel accepted whose effect did not read back. It is retried.
var errReadBack = errors.New("securitystate: the effect did not read back")

// attempt makes one attempt's kernel calls and classifies what came of them.
func (s *Service) attempt(ctx context.Context, c claimed) outcome {
	if c.kernelUser == "" {
		return outcome{state: StateUnresolved, errorClass: "unlinked"}
	}
	var err error
	switch c.opType {
	case TypeSuspend:
		err = s.suspend(ctx, c.kernelUser)
	case TypeRestore:
		err = s.restore(ctx, c.kernelUser)
	case TypeTerminateAll:
		err = s.terminateAll(ctx, c.kernelUser)
	case TypeRevoke, TypeAuthenticatorRemove:
		var (
			refused string
			removed *keycloak.Credential
		)
		refused, removed, err = s.revoke(ctx, c)
		if err == nil && refused != "" {
			return outcome{state: StateRefused, resultCode: refused}
		}
		if err == nil {
			return outcome{state: StateApplied, resultCode: StateApplied, removed: removed}
		}
	case TypeSessionTerminate:
		var refused string
		refused, err = s.terminateOne(ctx, c)
		if err == nil && refused != "" {
			return outcome{state: StateRefused, resultCode: refused}
		}
	default:
		return outcome{state: StateUnresolved, errorClass: "unknown_operation"}
	}
	if err == nil {
		return outcome{state: StateApplied, resultCode: StateApplied}
	}
	class, permanent := classify(err)
	if permanent || c.attempt-c.redrivenAt >= s.cfg.MaxAttempts {
		return outcome{state: StateUnresolved, errorClass: class}
	}
	return outcome{state: StateRetrying, errorClass: class}
}

// classify names a failure and whether retrying could change it (STD-GLB-011 §3.6).
func classify(err error) (string, bool) {
	switch {
	case errors.Is(err, keycloak.ErrForbidden):
		return "forbidden", true
	case errors.Is(err, keycloak.ErrNotFound):
		return "user_missing", true
	case errors.Is(err, errReadBack):
		return "read_back", false
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout", false
	case errors.Is(err, keycloak.ErrAmbiguous):
		return "ambiguous", false
	default:
		return "unavailable", false
	}
}

// call bounds one Admin API call by the attempt timeout.
func (s *Service) call(ctx context.Context, fn func(context.Context) error) error {
	callCtx, cancel := context.WithTimeout(ctx, s.cfg.AttemptTimeout)
	defer cancel()
	return fn(callCtx)
}

func (s *Service) readUser(ctx context.Context, user keycloak.UserID) (keycloak.User, error) {
	var u keycloak.User
	err := s.call(ctx, func(ctx context.Context) error {
		var err error
		u, err = s.kernel.GetUser(ctx, s.cfg.Realm, user)
		return err
	})
	return u, err
}

func (s *Service) sessionCount(ctx context.Context, user keycloak.UserID) (int, error) {
	var n int
	err := s.call(ctx, func(ctx context.Context) error {
		sessions, err := s.kernel.UserSessions(ctx, s.cfg.Realm, user)
		n = len(sessions)
		return err
	})
	return n, err
}

// suspend disables the user and ends its sessions. A disable alone only pauses them: the kernel
// hands them back on enable (identity-kernel compat run 37125613572), so the logout is required.
func (s *Service) suspend(ctx context.Context, user keycloak.UserID) error {
	if err := s.call(ctx, func(ctx context.Context) error { return s.kernel.DisableUser(ctx, s.cfg.Realm, user) }); err != nil {
		return err
	}
	if err := s.call(ctx, func(ctx context.Context) error { return s.kernel.LogoutUser(ctx, s.cfg.Realm, user) }); err != nil {
		return err
	}
	u, err := s.readUser(ctx, user)
	if err != nil {
		return err
	}
	n, err := s.sessionCount(ctx, user)
	if err != nil {
		return err
	}
	if u.Enabled || n != 0 {
		return fmt.Errorf("%w: enabled %t, %d sessions", errReadBack, u.Enabled, n)
	}
	return nil
}

// restore enables the user. No session comes back with it.
func (s *Service) restore(ctx context.Context, user keycloak.UserID) error {
	if err := s.call(ctx, func(ctx context.Context) error { return s.kernel.EnableUser(ctx, s.cfg.Realm, user) }); err != nil {
		return err
	}
	u, err := s.readUser(ctx, user)
	if err != nil {
		return err
	}
	if !u.Enabled {
		return fmt.Errorf("%w: still disabled", errReadBack)
	}
	return nil
}

func (s *Service) terminateAll(ctx context.Context, user keycloak.UserID) error {
	if err := s.call(ctx, func(ctx context.Context) error { return s.kernel.LogoutUser(ctx, s.cfg.Realm, user) }); err != nil {
		return err
	}
	n, err := s.sessionCount(ctx, user)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("%w: %d sessions", errReadBack, n)
	}
	return nil
}

// secondFactors are the credential types that take a sign-in from aal1 to aal2 (ADR-IAM-004).
var secondFactors = map[string]bool{"otp": true, "webauthn": true}

// holdsAssuranceFloor reports whether the Principal must keep a second factor: a provider, or one
// whose provider activation is in force but not honored while the projection is stale
// (TDD-identity-control-005 §Enrollment and the Assurance Floor). Without a decider, nobody does.
func (s *Service) holdsAssuranceFloor(ctx context.Context, principal id.UUID) (bool, error) {
	if s.cfg.Providers == nil {
		return false, nil
	}
	provider, stale, err := s.cfg.Providers.Holds(ctx, principal)
	if err != nil {
		return false, err
	}
	return provider || stale, nil
}

// firstFactors are the credential types that begin a sign-in: the built-in browser flow's password,
// and a passkey once a flow admits one (TDD-identity-control-005 §Containment as Built).
var firstFactors = map[string]bool{"password": true, "webauthn-passwordless": true}

// revoke deletes one credential unless it is the last first factor. It returns a refusal's result
// code, or an error to classify.
func (s *Service) revoke(ctx context.Context, c claimed) (string, *keycloak.Credential, error) {
	// The handle was checked with its expiry when the command was accepted. Its TTL bounds a
	// browser's use, not an accepted operation's.
	kind, purpose := refBinding(c.opType)
	ref, err := s.refs.OpenAccepted(c.ref, kind, c.subject, purpose)
	if err != nil {
		return "reference", nil, nil
	}
	var credentials []keycloak.Credential
	if err := s.call(ctx, func(ctx context.Context) error {
		var err error
		credentials, err = s.kernel.UserCredentials(ctx, s.cfg.Realm, c.kernelUser)
		return err
	}); err != nil {
		return "", nil, err
	}
	var target *keycloak.Credential
	others, otherSecond := 0, 0
	for i := range credentials {
		switch {
		case credentials[i].ID == ref.KernelID:
			target = &credentials[i]
		case firstFactors[credentials[i].Type]:
			others++
		case secondFactors[credentials[i].Type]:
			otherSecond++
		}
	}
	if target == nil {
		return "", nil, nil // already gone: the read-back agrees
	}
	if firstFactors[target.Type] && others == 0 {
		return ResultLastAuthenticator, nil, nil
	}
	if secondFactors[target.Type] && otherSecond == 0 {
		// The floor keeps a provider who can sign in at two factors. One the kernel has disabled, by a
		// suspension or a permanent lockout, cannot sign in, and assisted recovery revokes their lost
		// factor then (ADR-IAM-005 §5.5).
		u, err := s.readUser(ctx, c.kernelUser)
		if err != nil {
			return "", nil, err
		}
		if u.Enabled {
			floor, err := s.holdsAssuranceFloor(ctx, c.subject)
			if err != nil {
				return "", nil, err
			}
			if floor {
				return ResultAssuranceFloor, nil, nil
			}
		}
	}
	err = s.call(ctx, func(ctx context.Context) error {
		return s.kernel.DeleteCredential(ctx, s.cfg.Realm, c.kernelUser, ref.KernelID)
	})
	// A credential another caller deleted first was not removed by this command, and is told as that
	// caller's removal.
	removed := target
	if errors.Is(err, keycloak.ErrNotFound) {
		removed, err = nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if err := s.call(ctx, func(ctx context.Context) error {
		var err error
		credentials, err = s.kernel.UserCredentials(ctx, s.cfg.Realm, c.kernelUser)
		return err
	}); err != nil {
		return "", nil, err
	}
	for _, credential := range credentials {
		if credential.ID == ref.KernelID {
			return "", nil, fmt.Errorf("%w: the credential is still listed", errReadBack)
		}
	}
	return "", removed, nil
}

// terminateOne ends one of the person's sessions, named by its sealed reference. A session already
// gone counts as ended once the list agrees.
func (s *Service) terminateOne(ctx context.Context, c claimed) (string, error) {
	kind, purpose := refBinding(c.opType)
	ref, err := s.refs.OpenAccepted(c.ref, kind, c.subject, purpose)
	if err != nil {
		return "reference", nil
	}
	err = s.call(ctx, func(ctx context.Context) error { return s.kernel.DeleteSession(ctx, s.cfg.Realm, ref.KernelID) })
	if err != nil && !errors.Is(err, keycloak.ErrNotFound) {
		return "", err
	}
	var sessions []keycloak.Session
	if err := s.call(ctx, func(ctx context.Context) error {
		var err error
		sessions, err = s.kernel.UserSessions(ctx, s.cfg.Realm, c.kernelUser)
		return err
	}); err != nil {
		return "", err
	}
	for _, session := range sessions {
		if session.ID == ref.KernelID {
			return "", fmt.Errorf("%w: the session is still listed", errReadBack)
		}
	}
	return "", nil
}

const finishStatement = `UPDATE identity.security_operation
SET state = $3, result_code = nullif($4, ''), last_error_class = nullif($5, ''),
    applied_at = CASE WHEN $3 = 'applied' THEN now() ELSE applied_at END,
    next_attempt_at = CASE WHEN $3 = 'retrying' THEN now() + $6 * interval '1 millisecond' ELSE next_attempt_at END
WHERE operation_id = $1 AND attempts = $2 AND state IN ('pending', 'retrying')`

const finishAttemptStatement = `UPDATE identity.security_operation_attempt
SET finished_at = now(), outcome = $3, error_class = nullif($4, '')
WHERE operation_id = $1 AND attempt = $2`

const evidenceStatement = `INSERT INTO identity.privileged_access
    (access_id, actor_principal_id, subject_principal_id, action, route, reason, outcome, correlation_id, emergency)
VALUES ($1, $2, $3, $4, $5, nullif($6, ''), $7, $8, $9)`

// finish records an attempt's outcome, and, for a final one, its evidence in the same transaction.
// An attempt whose lease another worker took over finishes nothing.
func (s *Service) finish(ctx context.Context, c claimed, o outcome) error {
	var backoff time.Duration
	if o.state == StateRetrying {
		backoff = s.jitter(min(30*time.Second, time.Second<<c.attempt))
	}
	attemptOutcome := map[string]string{StateApplied: "applied", StateRefused: "refused", StateRetrying: "retry",
		StateUnresolved: "unresolved"}[o.state]
	lost := false
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, finishStatement, c.operationID.String(), c.attempt, o.state, o.resultCode, o.errorClass,
			backoff.Milliseconds())
		if err != nil {
			return fmt.Errorf("securitystate: finish: %w", err)
		}
		if tag.RowsAffected() == 0 {
			s.logger.WarnContext(ctx, "a security operation's lease ended before its attempt finished",
				slog.String("operation_id", c.operationID.String()), slog.Int("attempt", c.attempt))
			s.metric.leaseLost.Add(ctx, 1, typed(c.opType))
			lost = true
			return nil
		}
		if _, err := tx.Exec(ctx, finishAttemptStatement, c.operationID.String(), c.attempt, attemptOutcome,
			o.errorClass); err != nil {
			return fmt.Errorf("securitystate: finish the attempt: %w", err)
		}
		if o.state != StateApplied && o.state != StateRefused {
			return nil
		}
		accessID, err := s.newID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, evidenceStatement, accessID.String(), c.actor.String(), c.subject.String(), c.opType,
			Route(c.opType, c.actor == c.subject), c.reason, o.state, c.correlation, c.emergency); err != nil {
			return fmt.Errorf("securitystate: record the evidence: %w", err)
		}
		if o.state == StateApplied && s.applied != nil {
			op := Applied{OperationID: c.operationID, Type: c.opType, Subject: c.subject, Actor: c.actor,
				Self: c.actor == c.subject}
			if o.removed != nil {
				op.CredentialID, op.CredentialType = o.removed.ID, o.removed.Type
			}
			if err := s.applied(ctx, tx, op); err != nil {
				return fmt.Errorf("securitystate: the applied hook: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if lost {
		return nil
	}
	s.metric.attempts.Add(ctx, 1, typed(c.opType, attribute.String("outcome", attemptOutcome)))
	attrs := []any{slog.String("operation_id", c.operationID.String()), slog.String("operation_type", c.opType),
		slog.String("principal_id", c.subject.String()), slog.Int("attempt", c.attempt),
		slog.String("correlation_id", c.correlation)}
	switch o.state {
	case StateUnresolved:
		// The alert signal (TDD-identity-control-005 §Operational Notes): any unresolved
		// containment is critical, and it blocks the Principal's later commands until resolved.
		s.logger.ErrorContext(ctx, "security operation unresolved", append(attrs, slog.String("error_class", o.errorClass))...)
	case StateRetrying:
		s.logger.WarnContext(ctx, "security operation will be retried", append(attrs,
			slog.String("error_class", o.errorClass), slog.Duration("backoff", backoff))...)
	default:
		s.logger.InfoContext(ctx, "security operation "+o.state, append(attrs, slog.String("result_code", o.resultCode))...)
	}
	return nil
}

// fullJitter is random(0, limit): AWS's full jitter (TDD-identity-control-005 R10).
func fullJitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return rand.N(limit)
}
