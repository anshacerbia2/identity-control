package securitynotify

import (
	"testing"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The marks identity-kernel's compat/notified_events_test.go proves, and the neighbours that must map
// to nothing (TDD-identity-control-008 §Technical Context).
func TestEachProvenMarkMapsAsTheTableSays(t *testing.T) {
	user := func(typ string, details map[string]string) keycloak.KernelEvent {
		return keycloak.KernelEvent{Kind: keycloak.KindUserEvent, ID: "e", Type: typ, UserID: "kc-user", Details: details}
	}
	for name, c := range map[string]struct {
		event         keycloak.KernelEvent
		want, subject string
		details       map[string]string
	}{
		"a TOTP bound": {user("UPDATE_CREDENTIAL", map[string]string{"credential_type": "otp", "custom_required_action": "CONFIGURE_TOTP"}),
			EventAuthenticatorBound, "kc-user", map[string]string{"authenticator": "otp", "actor": ActorSelf}},
		"a security key bound": {user("UPDATE_CREDENTIAL", map[string]string{"credential_type": "webauthn"}),
			EventAuthenticatorBound, "kc-user", map[string]string{"authenticator": "webauthn", "actor": ActorSelf}},
		"a passkey bound": {user("UPDATE_CREDENTIAL", map[string]string{"credential_type": "webauthn-passwordless"}),
			EventAuthenticatorBound, "kc-user", map[string]string{"authenticator": "webauthn", "actor": ActorSelf}},
		"recovery codes issued": {user("UPDATE_CREDENTIAL", map[string]string{"credential_type": "recovery-authn-codes"}),
			EventRecoveryCodesIssued, "kc-user", map[string]string{"actor": ActorSelf}},
		"a recovery code used": {user("LOGIN", map[string]string{"credential_type": "recovery-authn-codes"}),
			EventAccountRecovered, "kc-user", map[string]string{"method": "recovery_code", "actor": ActorSelf}},
		"a removal through the Admin API": {keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, ID: "a", Type: "ACTION",
			UserID: "kc-operator", ResourceType: "USER", ResourcePath: "users/kc-subject/credentials/c1"},
			EventAuthenticatorRemoved, "kc-subject", map[string]string{"actor": ActorAdministrator}},
		"the enrolment's LOGIN": {user("LOGIN", map[string]string{"credential_type": "recovery-authn-codes",
			"custom_required_action": "CONFIGURE_RECOVERY_AUTHN_CODES"}), "", "", nil},
		"the legacy UPDATE_TOTP": {user("UPDATE_TOTP", map[string]string{"credential_type": "otp"}), "", "", nil},
		"an ordinary sign-in":    {user("LOGIN", map[string]string{"credential_type": "password"}), "", "", nil},
		"a failed binding":       {keycloak.KernelEvent{Kind: keycloak.KindUserEvent, Type: "UPDATE_CREDENTIAL", UserID: "kc-user", Error: "invalid", Details: map[string]string{"credential_type": "otp"}}, "", "", nil},
		"a password changed": {user("UPDATE_CREDENTIAL", map[string]string{"credential_type": "password", "custom_required_action": "UPDATE_PASSWORD"}),
			EventAuthenticatorBound, "kc-user", map[string]string{"authenticator": "password", "actor": ActorSelf}},
		"the legacy UPDATE_PASSWORD": {user("UPDATE_PASSWORD", map[string]string{"credential_type": "password"}), "", "", nil},
		"a key removed by the person": {user("REMOVE_CREDENTIAL", map[string]string{"credential_type": "webauthn", "credential_id": "c1",
			"custom_required_action": "delete_credential"}),
			EventAuthenticatorRemoved, "kc-user", map[string]string{"authenticator": "webauthn", "actor": ActorSelf}},
		"a TOTP removed by the person": {user("REMOVE_CREDENTIAL", map[string]string{"credential_type": "otp"}),
			EventAuthenticatorRemoved, "kc-user", map[string]string{"authenticator": "otp", "actor": ActorSelf}},
		"the sign-in before a removal": {user("LOGIN", map[string]string{"credential_type": "webauthn",
			"custom_required_action": "delete_credential"}), "", "", nil},
		"an admin update of a user": {keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, Type: "UPDATE", ResourceType: "USER", ResourcePath: "users/kc-subject"}, "", "", nil},
		"an admin action elsewhere": {keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, Type: "ACTION", ResourceType: "USER", ResourcePath: "users/kc-subject/logout"}, "", "", nil},
	} {
		got, ok := Classify(c.event)
		if ok != (c.want != "") {
			t.Errorf("%s: notified %t, want %t (%+v)", name, ok, c.want != "", got)
			continue
		}
		if !ok {
			continue
		}
		if got.Event != c.want || got.Subject != c.subject || len(got.Details) != len(c.details) {
			t.Errorf("%s: %+v, want %s for %s with %v", name, got, c.want, c.subject, c.details)
		}
		for k, v := range c.details {
			if got.Details[k] != v {
				t.Errorf("%s: detail %s is %q, want %q", name, k, got.Details[k], v)
			}
		}
	}
}
