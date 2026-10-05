package kernelevents

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

// Every credential value is redacted at any depth (TDD-identity-control-007 §Data Model), whatever the
// kernel's representation carried, and the rest of the representation is kept.
func TestCredentialValuesAreRedactedAtAnyDepth(t *testing.T) {
	event := keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, Representation: `{"username":"ada",
		"credentials":[{"type":"password","value":"hunter2-secret"}],
		"attributes":{"nested":{"Password":"p4ss","clientSecret":"s3cret","keep":"yes"}},
		"tokens":[{"refresh_token":"rt-value","note":"kept"}]}`}
	encoded, err := json.Marshal(detailsOf(event))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2-secret", "p4ss", "s3cret", "rt-value"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the record keeps %q: %s", secret, encoded)
		}
	}
	for _, kept := range []string{`"username":"ada"`, `"keep":"yes"`, `"note":"kept"`} {
		if !strings.Contains(string(encoded), kept) {
			t.Errorf("the record lost %s: %s", kept, encoded)
		}
	}

	user := keycloak.KernelEvent{Kind: keycloak.KindUserEvent, Details: map[string]string{"auth_method": "openid-connect",
		"token": "leaked"}}
	encoded, _ = json.Marshal(detailsOf(user))
	if strings.Contains(string(encoded), "leaked") || !strings.Contains(string(encoded), "openid-connect") {
		t.Errorf("a user event's details recorded as %s", encoded)
	}

	unparsed := keycloak.KernelEvent{Kind: keycloak.KindAdminEvent, Representation: "not json password=x"}
	encoded, _ = json.Marshal(detailsOf(unparsed))
	if string(encoded) != `{"unparsed":true}` {
		t.Errorf("a representation that is not JSON recorded as %s, want it not stored", encoded)
	}
}

// TDD-identity-kernel-003 §Retention Constraint: an interval longer than the retention over twenty-four
// would let an event expire before two sweeps read it.
func TestTheIntervalIsBoundByTheRetention(t *testing.T) {
	store := keycloakfake.NewEvents()
	for _, interval := range []time.Duration{0, -time.Minute, MaxInterval + time.Minute} {
		if _, err := NewSweeper(nopTransactor{}, store, "r", interval, nil); err == nil {
			t.Errorf("an interval of %s was accepted", interval)
		}
	}
	if _, err := NewSweeper(nopTransactor{}, store, "r", MaxInterval, nil); err != nil {
		t.Errorf("an interval of %s was refused: %v", MaxInterval, err)
	}
}
