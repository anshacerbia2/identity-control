// Package config reads process configuration from the environment and nowhere else.
//
// Twelve-factor, per STD-GLB-009: no file, no flag for a value that differs between
// environments, and no default that would let a misconfigured process start and fail
// later. A required variable that is absent is a startup error, because a service that
// boots without its database URL and reports healthy is worse than one that never boots.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the whole configuration surface of the deployable. It grows as the service
// does; every field here is read once at startup and passed down explicitly rather than
// reached for from a package variable.
type Config struct {
	// Deployable and System label every span, metric, and log line so load and failure
	// are attributable while several systems run the same foundation-platform code.
	Deployable string
	System     string

	ListenAddress string

	// RuntimeDSN connects as identity_runtime. It holds DML and no DDL, so a migration
	// attempted through this pool fails at the database rather than succeeding quietly.
	RuntimeDSN string

	DBMaxConns        int32
	DBMaxConnLifetime time.Duration
	DBAcquireTimeout  time.Duration

	HTTPReadTimeout    time.Duration
	HTTPWriteTimeout   time.Duration
	HTTPRequestTimeout time.Duration
	HTTPMaxInFlight    int64
	HTTPShutdownGrace  time.Duration

	// KeycloakRealm is the single realm this deployable administers.
	KeycloakRealm string

	// KeycloakBaseURL is the kernel root. KeycloakClientID and KeycloakClientSecret are the
	// administration service account, sourced from the approved secret manager. This process
	// is the only one in the estate holding them, per ADR-IAM-001 §5.10.
	KeycloakBaseURL      string
	KeycloakClientID     string
	KeycloakClientSecret string

	// TokenIssuer and TokenAudience are the verifier's contract. The issuer is compared for
	// exact equality, so a value with a stray trailing slash rejects every token rather than
	// accepting a wrong one.
	//
	// JWKSURL is configuration and never read from a token: a token naming its own key source
	// would choose the key that validates it.
	TokenIssuer   string
	TokenAudience string
	JWKSURL       string

	// TokenMaxSkew tolerates clock drift, capped at 60 seconds by STD-IAM-002 §3.5.
	TokenMaxSkew time.Duration

	// ProvisionTimeout bounds one Admin API call. PendingRecoveryAfter must exceed it, or
	// recovery searches the kernel for a user the original request is still creating.
	ProvisionTimeout     time.Duration
	PendingRecoveryAfter time.Duration
	ReconcilePageSize    int

	LogLevel string
}

// Load reads the environment and reports every problem at once.
//
// Collecting errors rather than returning the first is deliberate: an operator fixing a
// deployment wants the whole list, and returning them one per restart turns a five-minute
// correction into five deploys.
func Load() (Config, error) {
	var problems []error

	cfg := Config{
		Deployable: "identity-control",
		System:     "SAD-001",
	}

	cfg.RuntimeDSN = os.Getenv("IDENTITY_DATABASE_URL")
	if strings.TrimSpace(cfg.RuntimeDSN) == "" {
		problems = append(problems, errors.New("IDENTITY_DATABASE_URL is required"))
	}

	cfg.ListenAddress = stringOr("IDENTITY_LISTEN_ADDRESS", ":8080")
	cfg.LogLevel = stringOr("LOG_LEVEL", "info")

	// The realm is configuration rather than caller input. ADR-IAM-001 §5.4 fixes a small
	// static set of realms, and a caller-supplied realm would let one request create a
	// Principal in a realm its authorization never covered.
	cfg.KeycloakRealm = os.Getenv("IDENTITY_KEYCLOAK_REALM")
	if strings.TrimSpace(cfg.KeycloakRealm) == "" {
		problems = append(problems, errors.New("IDENTITY_KEYCLOAK_REALM is required"))
	}

	// Each is required rather than defaulted. A default base URL would point this process at
	// a kernel nobody chose, and a default credential does not exist.
	required := map[string]*string{
		"IDENTITY_KEYCLOAK_BASE_URL":      &cfg.KeycloakBaseURL,
		"IDENTITY_KEYCLOAK_CLIENT_ID":     &cfg.KeycloakClientID,
		"IDENTITY_KEYCLOAK_CLIENT_SECRET": &cfg.KeycloakClientSecret,

		// Each of these is a term in an authentication decision. A default would be a
		// default answer to "who may call this service", which is not a question a
		// fallback value gets to answer.
		"IDENTITY_TOKEN_ISSUER":   &cfg.TokenIssuer,
		"IDENTITY_TOKEN_AUDIENCE": &cfg.TokenAudience,
		"IDENTITY_JWKS_URL":       &cfg.JWKSURL,
	}
	for name, target := range required {
		*target = os.Getenv(name)
		if strings.TrimSpace(*target) == "" {
			problems = append(problems, fmt.Errorf("%s is required", name))
		}
	}

	cfg.TokenMaxSkew = durationOr("IDENTITY_TOKEN_MAX_SKEW", 30*time.Second, &problems)
	cfg.ProvisionTimeout = durationOr("IDENTITY_PROVISION_TIMEOUT", 10*time.Second, &problems)
	cfg.PendingRecoveryAfter = durationOr("IDENTITY_PENDING_RECOVERY_AFTER", 60*time.Second, &problems)
	cfg.ReconcilePageSize = intOr("IDENTITY_RECONCILE_PAGE_SIZE", 200, &problems)

	cfg.DBMaxConns = int32(intOr("DB_MAX_CONNS", 20, &problems))
	cfg.DBMaxConnLifetime = durationOr("DB_MAX_CONN_LIFETIME", 30*time.Minute, &problems)
	cfg.DBAcquireTimeout = durationOr("DB_ACQUIRE_TIMEOUT", 3*time.Second, &problems)

	cfg.HTTPReadTimeout = durationOr("HTTP_READ_TIMEOUT", 10*time.Second, &problems)
	cfg.HTTPWriteTimeout = durationOr("HTTP_WRITE_TIMEOUT", 30*time.Second, &problems)
	cfg.HTTPRequestTimeout = durationOr("HTTP_REQUEST_TIMEOUT", 5*time.Second, &problems)
	cfg.HTTPMaxInFlight = int64(intOr("HTTP_MAX_IN_FLIGHT", 256, &problems))
	cfg.HTTPShutdownGrace = durationOr("HTTP_SHUTDOWN_GRACE", 20*time.Second, &problems)

	if len(problems) > 0 {
		return Config{}, errors.Join(problems...)
	}
	return cfg, nil
}

// BootstrapConfig is what the bootstrap ceremony command needs, and nothing more.
//
// A narrower type rather than reusing Config, because Config requires a token issuer, an
// audience, and a JWKS URL — and this command verifies no token. Demanding them would make the
// configuration surface lie about what the command does, and an operator running a one-time
// ceremony would have to invent three values to satisfy a check that protects nothing.
type BootstrapConfig struct {
	Deployable string
	System     string

	// RuntimeDSN connects as the runtime role. The ceremony writes rows and no DDL, so it
	// deliberately does not use the migration credential: a command that could alter the schema
	// is a command that could remove the constraint making it single-use.
	RuntimeDSN string

	KeycloakRealm        string
	KeycloakBaseURL      string
	KeycloakClientID     string
	KeycloakClientSecret string

	ProvisionTimeout     time.Duration
	PendingRecoveryAfter time.Duration

	LogLevel string
}

// LoadBootstrap reads the environment for the ceremony command.
func LoadBootstrap() (BootstrapConfig, error) {
	var problems []error

	cfg := BootstrapConfig{
		Deployable: "identity-bootstrap",
		System:     "SAD-001",
	}

	required := map[string]*string{
		"IDENTITY_DATABASE_URL":           &cfg.RuntimeDSN,
		"IDENTITY_KEYCLOAK_REALM":         &cfg.KeycloakRealm,
		"IDENTITY_KEYCLOAK_BASE_URL":      &cfg.KeycloakBaseURL,
		"IDENTITY_KEYCLOAK_CLIENT_ID":     &cfg.KeycloakClientID,
		"IDENTITY_KEYCLOAK_CLIENT_SECRET": &cfg.KeycloakClientSecret,
	}
	for name, target := range required {
		*target = os.Getenv(name)
		if strings.TrimSpace(*target) == "" {
			problems = append(problems, fmt.Errorf("%s is required", name))
		}
	}

	cfg.ProvisionTimeout = durationOr("IDENTITY_PROVISION_TIMEOUT", 10*time.Second, &problems)
	cfg.PendingRecoveryAfter = durationOr("IDENTITY_PENDING_RECOVERY_AFTER", 60*time.Second, &problems)
	cfg.LogLevel = stringOr("LOG_LEVEL", "info")

	if len(problems) > 0 {
		return BootstrapConfig{}, errors.Join(problems...)
	}
	return cfg, nil
}

func stringOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func intOr(key string, fallback int, problems *[]error) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		*problems = append(*problems, fmt.Errorf("%s: %q is not an integer", key, raw))
		return fallback
	}
	if value <= 0 {
		*problems = append(*problems, fmt.Errorf("%s: %d must be positive", key, value))
		return fallback
	}
	return value
}

func durationOr(key string, fallback time.Duration, problems *[]error) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		*problems = append(*problems, fmt.Errorf("%s: %q is not a duration", key, raw))
		return fallback
	}
	if value <= 0 {
		*problems = append(*problems, fmt.Errorf("%s: %s must be positive", key, value))
		return fallback
	}
	return value
}
