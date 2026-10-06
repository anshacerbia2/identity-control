// Package securitynotify decides which account changes are notified and to whom, records each
// notification as evidence, and hands it to a delivery adapter (ADR-IAM-007,
// TDD-identity-control-008). It renders and sends nothing: the Notification Platform delivers.
package securitynotify

import (
	"strings"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The notified events (ADR-IAM-007 §5.1).
const (
	EventAuthenticatorBound   = "authenticator_bound"
	EventAuthenticatorRemoved = "authenticator_removed"
	EventRecoveryCodesIssued  = "recovery_codes_issued"
	EventAccountRecovered     = "account_recovered"
)

// Who acted on the account.
const (
	ActorSelf          = "self"
	ActorAdministrator = "administrator"
)

// Notified is a kernel event classified as one the person is told of.
type Notified struct {
	Event string
	// Subject is the kernel user the change happened to: the user event's own user, or, for an admin
	// event, the {user} in its resource path, since an admin event's user is its actor.
	Subject string
	Details map[string]string
}

// The authenticator types a binding names, as the kernel records them.
var authenticatorTypes = map[string]string{
	"otp":                   "otp",
	"webauthn":              "webauthn",
	"webauthn-passwordless": "webauthn",
}

// Classify maps one kernel event to the notified event it is, as identity-kernel's
// compat/notified_events_test.go proves the pinned release records it, or reports none.
//
//   - a binding is UPDATE_CREDENTIAL naming the credential type; the legacy UPDATE_TOTP beside it is
//     not mapped, or one binding would be told twice;
//   - recovery codes issued are UPDATE_CREDENTIAL naming recovery-authn-codes;
//   - a recovery code used is a LOGIN naming recovery-authn-codes with no required action; the LOGIN
//     ending enrolment names the same type and carries CONFIGURE_RECOVERY_AUTHN_CODES;
//   - a removal through the Admin API is an admin ACTION on users/{user}/credentials/{credential}.
func Classify(e keycloak.KernelEvent) (Notified, bool) {
	if e.Error != "" {
		return Notified{}, false
	}
	switch e.Kind {
	case keycloak.KindUserEvent:
		credential := e.Details["credential_type"]
		switch {
		case e.Type == "UPDATE_CREDENTIAL" && credential == "recovery-authn-codes":
			return Notified{Event: EventRecoveryCodesIssued, Subject: e.UserID,
				Details: map[string]string{"actor": ActorSelf}}, e.UserID != ""
		case e.Type == "UPDATE_CREDENTIAL" && authenticatorTypes[credential] != "":
			return Notified{Event: EventAuthenticatorBound, Subject: e.UserID,
				Details: map[string]string{"authenticator": authenticatorTypes[credential], "actor": ActorSelf}}, e.UserID != ""
		case e.Type == "LOGIN" && credential == "recovery-authn-codes" && e.Details["custom_required_action"] == "":
			return Notified{Event: EventAccountRecovered, Subject: e.UserID,
				Details: map[string]string{"method": "recovery_code", "actor": ActorSelf}}, e.UserID != ""
		}
	case keycloak.KindAdminEvent:
		if e.Type == "ACTION" && e.ResourceType == "USER" {
			parts := strings.Split(e.ResourcePath, "/")
			if len(parts) == 4 && parts[0] == "users" && parts[1] != "" && parts[2] == "credentials" && parts[3] != "" {
				return Notified{Event: EventAuthenticatorRemoved, Subject: parts[1],
					Details: map[string]string{"actor": ActorAdministrator}}, true
			}
		}
	}
	return Notified{}, false
}
