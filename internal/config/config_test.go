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
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
	t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")

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

func TestLoadAppliesDefaults(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
	t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")

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
	if cfg.ReportAssurance {
		t.Error("IDENTITY_ASSURANCE defaults to report; it enforces unless told otherwise")
	}
	if cfg.StepUpMaxAge != 5*time.Minute || cfg.CommandBudget != 2*time.Second || cfg.AttemptTimeout != 500*time.Millisecond ||
		cfg.MaxAttempts != 3 || cfg.OperationLease != 10*time.Second || cfg.ExecutorInterval != time.Second {
		t.Errorf("security command defaults = %s, %s, %s, %d, %s, %s (TDD-identity-control-005 §Configuration)",
			cfg.StepUpMaxAge, cfg.CommandBudget, cfg.AttemptTimeout, cfg.MaxAttempts, cfg.OperationLease, cfg.ExecutorInterval)
	}
	if cfg.SecurityRefTTL != 10*time.Minute || cfg.AdminSearchMinLength != 3 || cfg.AdminSearchPageSize != 25 {
		t.Errorf("investigation defaults = %s, %d, %d; want 10m, 3, 25 (TDD-identity-control-005 §Configuration)",
			cfg.SecurityRefTTL, cfg.AdminSearchMinLength, cfg.AdminSearchPageSize)
	}
}

func TestALeaseShorterThanASuspensionIsRefused(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
	t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
	t.Setenv("IDENTITY_SECURITY_OPERATION_LEASE", "2s")

	if _, err := config.Load(); err == nil || !strings.Contains(err.Error(), "IDENTITY_SECURITY_OPERATION_LEASE") {
		t.Fatalf("Load with a 2s lease over 500ms calls: %v", err)
	}
}

func TestLoadRequiresTheSecurityRefKeyRing(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
	t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "")

	if _, err := config.Load(); err == nil || !strings.Contains(err.Error(), "IDENTITY_SECURITY_REF_KEY_FILE") {
		t.Fatalf("Load without a key ring: %v", err)
	}
}

func TestLoadOverridesFromEnvironment(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
	t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
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
		"assurance mode":    {"IDENTITY_ASSURANCE", "lenient"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
			t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
			t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
			t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
			t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
			t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
			t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
			t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
			t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
			t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
			t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
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

// The registration path has its own credential (TDD-identity-control-003 §Security Notes), so a
// deployable missing it must not start with the Principal path's credential standing in.
func TestLoadRequiresTheRegistrationCredential(t *testing.T) {
	for _, missing := range []string{"IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE"} {
		t.Run(missing, func(t *testing.T) {
			t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
			t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
			t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
			t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
			t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
			t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
			t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
			t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
			t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
			t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
			t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
			t.Setenv(missing, "")

			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Errorf("Load answered %v, want a problem naming %s", err, missing)
			}
		})
	}
}

func TestTheRegistrationSweepIntervalDefaultsAndIsBoundedByEventRetention(t *testing.T) {
	for _, c := range []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{"", time.Hour, true},
		{"30s", 30 * time.Second, true},
		{"168h", 0, false},
	} {
		t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
		t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
		t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
		t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
		t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
		t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
		t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
		t.Setenv("IDENTITY_REGISTRATION_RECONCILE_INTERVAL", c.value)

		cfg, err := config.Load()
		if c.ok && (err != nil || cfg.RegistrationReconcileInterval != c.want) {
			t.Errorf("%q: interval %s, err %v; want %s", c.value, cfg.RegistrationReconcileInterval, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("%q: an interval as long as the admin-event retention was accepted", c.value)
		}
	}
}

func TestTheClientKeyWindowsDefaultAndTheOverlapIsShorterThanTheLifetime(t *testing.T) {
	for _, c := range []struct {
		lifetime, overlap         string
		wantLifetime, wantOverlap time.Duration
		ok                        bool
	}{
		{"", "", 90 * 24 * time.Hour, 7 * 24 * time.Hour, true},
		{"720h", "24h", 720 * time.Hour, 24 * time.Hour, true},
		{"24h", "24h", 0, 0, false},
		{"24h", "48h", 0, 0, false},
		{"-1h", "", 0, 0, false},
		{"90d", "", 0, 0, false},
	} {
		t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
		t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
		t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
		t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
		t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
		t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
		t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
		t.Setenv("IDENTITY_CLIENT_KEY_LIFETIME", c.lifetime)
		t.Setenv("IDENTITY_CLIENT_KEY_ROTATION_OVERLAP", c.overlap)

		cfg, err := config.Load()
		if c.ok && (err != nil || cfg.ClientKeyLifetime != c.wantLifetime || cfg.ClientKeyRotationOverlap != c.wantOverlap) {
			t.Errorf("%q/%q: lifetime %s, overlap %s, err %v", c.lifetime, c.overlap, cfg.ClientKeyLifetime,
				cfg.ClientKeyRotationOverlap, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%q/%q was accepted", c.lifetime, c.overlap)
		}
	}
}

func TestUnmanagedClientsAreReportedUnlessDisablingIsAsked(t *testing.T) {
	for _, c := range []struct {
		value   string
		disable bool
		ok      bool
	}{{"", false, true}, {"report", false, true}, {"disable", true, true}, {"delete", false, false}} {
		t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
		t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
		t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
		t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
		t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
		t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
		t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
		t.Setenv("IDENTITY_UNMANAGED_CLIENTS", c.value)
		cfg, err := config.Load()
		if c.ok && (err != nil || cfg.DisableUnmanagedClients != c.disable) {
			t.Errorf("%q: disable %v, err %v", c.value, cfg.DisableUnmanagedClients, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%q was accepted", c.value)
		}
	}
}

func TestTheTokenTypeIsReportedUnlessEnforcementIsAsked(t *testing.T) {
	for _, c := range []struct {
		value   string
		enforce bool
		ok      bool
	}{{"", false, true}, {"report", false, true}, {"enforce", true, true}, {"strict", false, false}} {
		t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
		t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
		t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
		t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
		t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
		t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
		t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
		t.Setenv("IDENTITY_TOKEN_TYPE", c.value)
		cfg, err := config.Load()
		if c.ok && (err != nil || cfg.EnforceAccessTokenType != c.enforce) {
			t.Errorf("%q: enforce %v, err %v", c.value, cfg.EnforceAccessTokenType, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%q was accepted", c.value)
		}
	}
}

// IDENTITY_ENVIRONMENT is production unless stated (ADR-IAM-003 §5.1), so a deployment that forgets
// to say gets the two-owner rule.
func TestTheEnvironmentIsProductionUnlessStated(t *testing.T) {
	for _, c := range []struct {
		value      string
		production bool
		ok         bool
	}{
		{"", true, true},
		{"production", true, true},
		{"non-production", false, true},
		{"staging", false, false},
	} {
		t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
		t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
		t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
		t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
		t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
		t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
		t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
		t.Setenv("IDENTITY_ENVIRONMENT", c.value)

		cfg, err := config.Load()
		if c.ok && (err != nil || cfg.Production != c.production) {
			t.Errorf("%q: production %t, err %v; want %t", c.value, cfg.Production, err, c.production)
		}
		if !c.ok && err == nil {
			t.Errorf("%q was accepted", c.value)
		}
	}
}

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
	t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
	t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
	t.Setenv("IDENTITY_TOKEN_ISSUER", "https://identity.example.com/realms/scnehaux")
	t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control")
	t.Setenv("IDENTITY_JWKS_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/certs")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
	t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
	t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
}

func setOrganization(t *testing.T) {
	t.Helper()
	t.Setenv("IDENTITY_ORGANIZATION_BASE_URL", "https://organization.example.com")
	t.Setenv("IDENTITY_WORKLOAD_CLIENT_ID", "identity-control-workload")
	t.Setenv("IDENTITY_WORKLOAD_KEY_FILE", "/keys/identity-control-workload.pem")
	t.Setenv("IDENTITY_WORKLOAD_TOKEN_URL", "https://identity.example.com/realms/scnehaux/protocol/openid-connect/token")
	t.Setenv("IDENTITY_WORKLOAD_AUDIENCE", "https://identity.example.com/realms/scnehaux")
}

// Organization Control is optional, and its workload client is required once it is named
// (TDD-identity-control-006 §Configuration).
func TestOrganizationIsOptionalUntilNamed(t *testing.T) {
	setRequired(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load without Organization Control: %v", err)
	}
	if cfg.Organization.BaseURL != "" || cfg.ProviderFreshness != 60*time.Second {
		t.Errorf("defaults are %+v, %s", cfg.Organization, cfg.ProviderFreshness)
	}

	setOrganization(t)
	t.Setenv("IDENTITY_PROVIDER_FRESHNESS", "45s")
	cfg, err = config.Load()
	if err != nil {
		t.Fatalf("Load with Organization Control: %v", err)
	}
	if cfg.Organization.WorkloadClientID != "identity-control-workload" || cfg.ProviderFreshness != 45*time.Second {
		t.Errorf("loaded %+v, %s", cfg.Organization, cfg.ProviderFreshness)
	}

	for _, name := range []string{
		"IDENTITY_WORKLOAD_CLIENT_ID", "IDENTITY_WORKLOAD_KEY_FILE",
		"IDENTITY_WORKLOAD_TOKEN_URL", "IDENTITY_WORKLOAD_AUDIENCE",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, err := config.Load(); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("Load without %s: %v", name, err)
			}
		})
	}
}

func TestLoadProviderBootstrapRequiresOrganization(t *testing.T) {
	t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
	t.Setenv("IDENTITY_ORGANIZATION_BASE_URL", "")
	if _, err := config.LoadProviderBootstrap(); err == nil || !strings.Contains(err.Error(), "IDENTITY_ORGANIZATION_BASE_URL") {
		t.Errorf("LoadProviderBootstrap without Organization Control: %v", err)
	}

	setOrganization(t)
	cfg, err := config.LoadProviderBootstrap()
	if err != nil {
		t.Fatalf("LoadProviderBootstrap: %v", err)
	}
	if cfg.RuntimeDSN == "" || cfg.Organization.BaseURL != "https://organization.example.com" {
		t.Errorf("loaded %+v", cfg)
	}

	t.Setenv("IDENTITY_DATABASE_URL", "")
	if _, err := config.LoadProviderBootstrap(); err == nil || !strings.Contains(err.Error(), "IDENTITY_DATABASE_URL") {
		t.Errorf("LoadProviderBootstrap without a database: %v", err)
	}
}

// The ceremony registers this service's resource through the registration path's client, under the
// name the service verifies as its audience, so each of the three is required (ADR-IAM-001 §5.11
// rule 5).
func TestLoadBootstrapRequiresWhatRegistersTheResource(t *testing.T) {
	set := func() {
		t.Setenv("IDENTITY_DATABASE_URL", "postgres://runtime@localhost:5432/identity")
		t.Setenv("IDENTITY_KEYCLOAK_REALM", "scnehaux")
		t.Setenv("IDENTITY_KEYCLOAK_BASE_URL", "https://identity.example.com")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_ID", "identity-control")
		t.Setenv("IDENTITY_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control.pem")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID", "identity-control-registration")
		t.Setenv("IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "/keys/identity-control-registration.pem")
		t.Setenv("IDENTITY_SECURITY_REF_KEY_FILE", "/keys/security-ref.json")
		t.Setenv("IDENTITY_TOKEN_AUDIENCE", "identity-control-api")
	}
	set()
	cfg, err := config.LoadBootstrap()
	if err != nil {
		t.Fatalf("LoadBootstrap: %v", err)
	}
	if cfg.TokenAudience != "identity-control-api" || cfg.RegistrationClientID != "identity-control-registration" {
		t.Errorf("loaded %+v", cfg)
	}
	for _, name := range []string{"IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID",
		"IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE", "IDENTITY_TOKEN_AUDIENCE"} {
		t.Run(name, func(t *testing.T) {
			set()
			t.Setenv(name, "")
			if _, err := config.LoadBootstrap(); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("LoadBootstrap without %s: %v", name, err)
			}
		})
	}
}

// The development stand-in for the Notification Platform accepts every notification and delivers
// none, so production refuses it (TDD-identity-control-008 §The Adapter).
func TestTheNotificationStandInIsRefusedInProduction(t *testing.T) {
	for _, c := range []struct {
		environment, delivery string
		ok                    bool
	}{
		{"non-production", "", true},
		{"non-production", "standin", true},
		{"production", "", true},
		{"production", "standin", false},
		{"non-production", "smtp", false},
	} {
		setRequired(t)
		t.Setenv("IDENTITY_ENVIRONMENT", c.environment)
		t.Setenv("IDENTITY_NOTIFICATION_DELIVERY", c.delivery)
		cfg, err := config.Load()
		if (err == nil) != c.ok {
			t.Errorf("%s with %q: err %v, want accepted %t", c.environment, c.delivery, err, c.ok)
		}
		if err == nil && cfg.NotificationDelivery != c.delivery {
			t.Errorf("%s with %q: delivery %q", c.environment, c.delivery, cfg.NotificationDelivery)
		}
	}
}
