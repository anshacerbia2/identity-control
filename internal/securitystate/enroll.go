package securitystate

// Enrolling an authenticator (TDD-identity-control-005 §Enrollment and the Assurance Floor). The
// API authorizes the enrollment and names the kernel action that performs it; the BFF drives the
// action as an OIDC sign-in. No authenticator material passes through here.

import (
	"context"
	"errors"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The kernel actions an enrollment may name, by authenticator type. Nothing else is ever returned.
// webauthn is a second factor beside the password; a passkey replacing it is not offered
// (TDD-identity-control-005 2.7.0). recovery-codes issues a new set of recovery codes, replacing any
// earlier one (ADR-IAM-005 §5.3).
var enrollActions = map[string]string{"totp": "CONFIGURE_TOTP", "webauthn": "webauthn-register",
	"recovery-codes": "CONFIGURE_RECOVERY_AUTHN_CODES"}

// ErrStepUp is an enrollment whose caller has not authenticated at the level binding requires. Level
// is that level: aal2 for a person who already holds a second factor, aal1 otherwise.
type ErrStepUp struct{ Level string }

func (e ErrStepUp) Error() string {
	return fmt.Sprintf("securitystate: enrolling requires an authentication at %s", e.Level)
}

// EnrollmentLevel is the level binding a new authenticator requires of the person: "the maximum AAL
// currently available in the subscriber account" (NIST SP 800-63B-4 §4.1.2.1), which is aal2 once
// they hold a second factor.
func (s *Service) EnrollmentLevel(ctx context.Context, principal id.UUID) (string, error) {
	user, err := s.ownUser(ctx, principal)
	if err != nil {
		return "", err
	}
	var credentials []keycloak.Credential
	if err := s.call(ctx, func(ctx context.Context) error {
		var err error
		credentials, err = s.kernel.UserCredentials(ctx, s.cfg.Realm, user)
		return err
	}); err != nil {
		return "", fmt.Errorf("securitystate: read the authenticators: %w", err)
	}
	for _, credential := range credentials {
		if secondFactors[credential.Type] {
			return "aal2", nil
		}
	}
	return "aal1", nil
}

// Enroll authorizes an enrollment the caller has authenticated for, records it, and returns the
// kernel action that performs it. meets reports whether the caller's authentication meets a level
// and is recent: the transport knows the token, this package the account.
func (s *Service) Enroll(ctx context.Context, actor Actor, authenticatorType string, meets func(level string) bool) (string, error) {
	action, ok := enrollActions[authenticatorType]
	if !ok {
		return "", fmt.Errorf("%w: %q is not an authenticator type this API enrolls", ErrInvalid, authenticatorType)
	}
	level, err := s.EnrollmentLevel(ctx, actor.Principal)
	if err != nil {
		return "", err
	}
	if !meets(level) {
		return "", ErrStepUp{Level: level}
	}
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		accessID, err := s.newID()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, evidenceStatement, accessID.String(), actor.Principal.String(), actor.Principal.String(),
			"authenticator.enroll", "POST /v1/me/authenticators:enroll", "", "served", actor.Correlation, false)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("securitystate: record the enrollment: %w", err)
	}
	return action, nil
}

// IsStepUp reports whether err asks for a step-up, and to which level.
func IsStepUp(err error) (string, bool) {
	var stepUp ErrStepUp
	if errors.As(err, &stepUp) {
		return stepUp.Level, true
	}
	return "", false
}
