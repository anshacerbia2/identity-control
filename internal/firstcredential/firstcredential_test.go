package firstcredential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

type noTx struct{}

func (noTx) InTx(context.Context, func(context.Context, db.Tx) error) error {
	return errors.New("no database in a unit test")
}

func service(t *testing.T) *Service {
	t.Helper()
	s, err := New(noTx{}, keycloakfake.New(), Config{Realm: "scnehaux", TTL: DefaultTTL, CallTimeout: time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The value is 24 symbols of Crockford's base32, 120 bits from the random source: above NIST
// SP 800-63B-4 §3.2.12's 112 (ADR-IAM-010 §5.1).
func TestTheValueIsGeneratedWithAtLeast112Bits(t *testing.T) {
	if ValueBits < 112 || len(alphabet) != 32 || strings.ContainsAny(alphabet, "ILOU") {
		t.Fatalf("%d bits from %q", ValueBits, alphabet)
	}
	s := service(t)
	seen := map[string]bool{}
	counts := map[rune]int{}
	for range 2000 {
		v, err := s.generate()
		if err != nil {
			t.Fatal(err)
		}
		if len(v) != valueLength || strings.Trim(v, alphabet) != "" {
			t.Fatalf("%q is not %d symbols of the alphabet", v, valueLength)
		}
		if seen[v] {
			t.Fatal("a value repeated")
		}
		seen[v] = true
		for _, r := range v {
			counts[r]++
		}
	}
	// 48 000 symbols: each of 32 is expected 1 500 times. A symbol never drawn, or drawn far off its
	// share, is a biased mapping.
	for _, r := range alphabet {
		if counts[r] < 1200 || counts[r] > 1800 {
			t.Errorf("symbol %q drawn %d times; want about 1500", r, counts[r])
		}
	}
	s.random = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	if _, err := s.generate(); err == nil {
		t.Fatal("a failed random source produced a value")
	}
}

func TestTheServiceRefusesALapseOutsideItsBounds(t *testing.T) {
	kernel := keycloakfake.New()
	for _, ttl := range []time.Duration{0, 59 * time.Minute, 25 * time.Hour} {
		if _, err := New(noTx{}, kernel, Config{Realm: "r", TTL: ttl, CallTimeout: time.Second}, nil); err == nil {
			t.Errorf("a lapse of %s was accepted", ttl)
		}
	}
	for _, cfg := range []Config{{TTL: time.Hour, CallTimeout: time.Second}, {Realm: "r", TTL: time.Hour}} {
		if _, err := New(noTx{}, kernel, cfg, nil); err == nil {
			t.Errorf("%+v was accepted", cfg)
		}
	}
	if _, err := New(noTx{}, kernel, Config{Realm: "r", TTL: time.Hour, CallTimeout: time.Second,
		SweepInterval: time.Hour}, nil); err == nil {
		t.Error("a sweep interval as long as the lapse was accepted")
	}
	if _, err := New(nil, kernel, Config{Realm: "r", TTL: time.Hour, CallTimeout: time.Second}, nil); err == nil {
		t.Error("a service without a transactor was built")
	}
}

func TestARequestIsRefusedBeforeAnythingIsRead(t *testing.T) {
	s := service(t)
	provider, _ := id.NewV7()
	person, _ := id.NewV7()
	actor := Actor{Principal: provider}
	for name, c := range map[string]struct {
		req  Request
		want error
	}{
		"no reason":   {Request{Actor: actor, Subject: person, IdempotencyKey: "k"}, ErrInvalid},
		"no key":      {Request{Actor: actor, Subject: person, Reason: "r"}, ErrInvalid},
		"no subject":  {Request{Actor: actor, Reason: "r", IdempotencyKey: "k"}, ErrInvalid},
		"own account": {Request{Actor: actor, Subject: provider, Reason: "r", IdempotencyKey: "k"}, ErrSelf},
	} {
		if _, _, err := s.Issue(context.Background(), c.req); !errors.Is(err, c.want) {
			t.Errorf("%s: %v; want %v", name, err, c.want)
		}
	}
}

// Only the person's own password change is a use; every other event is left alone, without reading
// the database.
func TestOnlyThePersonsPasswordChangeIsAUse(t *testing.T) {
	s := service(t)
	for _, e := range []keycloak.KernelEvent{
		{Kind: keycloak.KindAdminEvent, Type: "ACTION", ResourcePath: "users/u/reset-password"},
		{Kind: keycloak.KindUserEvent, Type: "UPDATE_CREDENTIAL", UserID: "u", Details: map[string]string{"credential_type": "otp"}},
		{Kind: keycloak.KindUserEvent, Type: "UPDATE_CREDENTIAL", UserID: "u", Error: "invalid_password",
			Details: map[string]string{"credential_type": "password"}},
		{Kind: keycloak.KindUserEvent, Type: "UPDATE_PASSWORD", UserID: "u", Details: map[string]string{"credential_type": "password"}},
		{Kind: keycloak.KindUserEvent, Type: "LOGIN", UserID: "u"},
	} {
		if err := s.FromKernelEvent(context.Background(), nil, "scnehaux", e); err != nil {
			t.Errorf("%+v: %v", e, err)
		}
	}
}
