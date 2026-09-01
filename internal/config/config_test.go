package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/identity-control/internal/config"
)

// TestLoadRequiresDatabaseURL is the check that matters most here. A process that boots
// without its database URL and reports healthy is worse than one that never boots, so the
// absence has to be a startup error rather than a lazily-discovered nil.
func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_SECRET", "secret")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")

	if _, err := config.Load(); err == nil {
		t.Fatal("Load succeeded without IDENTITY_DATABASE_URL")
	}
}

// TestLoadRequiresRealm states the property the handler depends on: the realm is configuration,
// so a deployable that does not name one must not start. Defaulting it would let a
// misconfigured process administer whichever realm the default happened to name.
func TestLoadRequiresRealm(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "")

	if _, err := config.Load(); err == nil {
		t.Fatal("Load succeeded without IDENTITY_KEYCLOAK_REALM")
	}
}

func TestLoadRejectsWhitespaceOnlyDatabaseURL(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "   ")

	if _, err := config.Load(); err == nil {
		t.Fatal("Load accepted a whitespace-only IDENTITY_DATABASE_URL")
	}
}

// TestLoadAppliesDefaults clears the optional keys before asserting their defaults.
//
// It used to set only the required ones and inherit the rest of the process environment, so it
// asserted "the default applies" while the answer depended on the shell it ran in. A developer
// with IDENTITY_LISTEN_ADDRESS exported — from a .env, a shell profile, or a Makefile that
// exports one — saw `ListenAddress = "127.0.0.1:8097", want :8080`: a failure that says the
// defaults are wrong when the defaults were never consulted.
func TestLoadAppliesDefaults(t *testing.T) {
	for _, key := range []string{
		"IDENTITY_LISTEN_ADDRESS",
		"DB_MAX_CONNS",
		"HTTP_MAX_IN_FLIGHT",
		"HTTP_REQUEST_TIMEOUT",
	} {
		t.Setenv(key, "")
	}

	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_SECRET", "secret")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Deployable != "identity-control" {
		t.Errorf("Deployable = %q, want identity-control", cfg.Deployable)
	}
	if cfg.System != "SAD-001" {
		t.Errorf("System = %q, want SAD-001", cfg.System)
	}
	if cfg.ListenAddress != ":8080" {
		t.Errorf("ListenAddress = %q, want :8080", cfg.ListenAddress)
	}
	if cfg.DBMaxConns != 20 {
		t.Errorf("DBMaxConns = %d, want 20", cfg.DBMaxConns)
	}
	if cfg.HTTPMaxInFlight != 256 {
		t.Errorf("HTTPMaxInFlight = %d, want 256", cfg.HTTPMaxInFlight)
	}
	if cfg.HTTPRequestTimeout != 5*time.Second {
		t.Errorf("HTTPRequestTimeout = %s, want 5s", cfg.HTTPRequestTimeout)
	}
}

func TestLoadOverridesFromEnvironment(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_SECRET", "secret")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
	t.Setenv("IDENTITY_LISTEN_ADDRESS", "127.0.0.1:9090")
	t.Setenv("DB_MAX_CONNS", "8")
	t.Setenv("HTTP_REQUEST_TIMEOUT", "250ms")
	t.Setenv("LOG_LEVEL", "debug")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ListenAddress != "127.0.0.1:9090" {
		t.Errorf("ListenAddress = %q", cfg.ListenAddress)
	}
	if cfg.DBMaxConns != 8 {
		t.Errorf("DBMaxConns = %d, want 8", cfg.DBMaxConns)
	}
	if cfg.HTTPRequestTimeout != 250*time.Millisecond {
		t.Errorf("HTTPRequestTimeout = %s, want 250ms", cfg.HTTPRequestTimeout)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
}

// TestLoadRejectsMalformedValues asserts that a typo is a startup failure rather than a
// silent fallback. A deployment that meant HTTP_MAX_IN_FLIGHT=1000 and typed 1O00 should
// not quietly run at the default while the operator believes otherwise.
func TestLoadRejectsMalformedValues(t *testing.T) {
	cases := map[string]struct{ key, value string }{
		"integer":           {"DB_MAX_CONNS", "twenty"},
		"negative integer":  {"HTTP_MAX_IN_FLIGHT", "-1"},
		"zero integer":      {"DB_MAX_CONNS", "0"},
		"duration":          {"HTTP_READ_TIMEOUT", "10 seconds"},
		"negative duration": {"DB_ACQUIRE_TIMEOUT", "-3s"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
			t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
			t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
			t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
			t.Setenv("IDENTITY_KEYCLOAK_CLIENT_SECRET", "secret")
			t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
			t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
			t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
			t.Setenv(tc.key, tc.value)

			if _, err := config.Load(); err == nil {
				t.Fatalf("Load accepted %s=%q", tc.key, tc.value)
			}
		})
	}
}

// TestLoadReportsEveryProblemAtOnce is why Load joins errors instead of returning the
// first. An operator fixing a deployment wants the whole list; returning one per restart
// turns a five-minute correction into five deploys.
func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "")
	t.Setenv("DB_MAX_CONNS", "nope")
	t.Setenv("HTTP_READ_TIMEOUT", "also-nope")

	_, err := config.Load()
	if err == nil {
		t.Fatal("Load succeeded with three invalid settings")
	}

	message := err.Error()
	for _, want := range []string{"IDENTITY_DATABASE_URL", "DB_MAX_CONNS", "HTTP_READ_TIMEOUT"} {
		if !strings.Contains(message, want) {
			t.Errorf("error does not mention %s; got: %s", want, message)
		}
	}
}
