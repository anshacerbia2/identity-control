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

	"github.com/anshacerbia2/foundation-platform/id"
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

	// KeycloakBaseURL is the kernel root. KeycloakClientID and KeycloakClientKeyFile are the
	// administration service account, sourced from the approved secret manager. This process
	// is the only one in the estate holding them, per ADR-IAM-001 §5.10.
	KeycloakBaseURL       string
	KeycloakClientID      string
	KeycloakClientKeyFile string

	// RegistrationClientID and RegistrationClientKeyFile are the registration path's own Admin API
	// credential, identity-control-registration (TDD-identity-control-003 §Security Notes): clients
	// and admin events, no users. A second credential rather than more roles on the first, so one
	// leaked secret cannot both mint a Principal and register a client that redirects its tokens.
	RegistrationClientID      string
	RegistrationClientKeyFile string

	// RegistrationReconcileInterval is the registration drift sweep cadence. identity-kernel keeps
	// admin events for 7 days, and a change must still carry its event when a sweep reads it.
	RegistrationReconcileInterval time.Duration

	// ClientKeyLifetime is how long a registered client key is valid before it is removed, and
	// ClientKeyRotationOverlap how long the previous key keeps authenticating after the next is
	// registered (TDD-identity-control-003 §Configuration). The overlap is shorter than the lifetime.
	ClientKeyLifetime        time.Duration
	ClientKeyRotationOverlap time.Duration

	// DisableUnmanagedClients is IDENTITY_UNMANAGED_CLIENTS=disable: a Keycloak client no
	// registration describes is disabled, as well as recorded. The default, report, records it only,
	// for an estate whose bootstrap clients are not adopted yet (TDD-identity-control-003).
	DisableUnmanagedClients bool

	// DeliveryPrincipal is IDENTITY_DELIVERY_PRINCIPAL_ID: Organization Control's workload
	// principal_id, the one caller the delivery intake admits (TDD-identity-control-006). Unset, the
	// intake answers 503 and no provider event is accepted.
	DeliveryPrincipal id.UUID

	// Organization is Organization Control as this service's projection consumer reads it, and
	// ProviderFreshness the budget declared at registration (TDD-identity-control-006). An empty
	// Organization.BaseURL reads nothing: the projection is never fresh, and no activation is honored.
	Organization      Organization
	ProviderFreshness time.Duration

	// Production is IDENTITY_ENVIRONMENT=production, the default: a registration keeps at least two
	// owners (ADR-IAM-003 §5.1). Production unless stated, so a deployment that forgets to say
	// gets the stricter rule.
	Production bool

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

	// EnforceAccessTokenType is IDENTITY_TOKEN_TYPE=enforce: a caller's token whose header typ is not
	// at+jwt is refused. The default, report, accepts it and logs it, for a server whose callers'
	// clients predate the token profile (TDD-identity-control-001 §Caller Token).
	EnforceAccessTokenType bool

	// ProvisionTimeout bounds one Admin API call. PendingRecoveryAfter must exceed it, or
	// recovery searches the kernel for a user the original request is still creating.
	ProvisionTimeout     time.Duration
	PendingRecoveryAfter time.Duration
	ReconcilePageSize    int

	// SecurityRefKeyFile is IDENTITY_SECURITY_REF_KEY_FILE, the key ring that seals the opaque
	// security_ref handles (TDD-identity-control-005 §Technical Context). SecurityRefTTL is a
	// handle's life.
	SecurityRefKeyFile string
	SecurityRefTTL     time.Duration

	// AdminSearchMinLength and AdminSearchPageSize bound a provider's Principal search: a query
	// shorter than the floor is refused, and a page holds at most the size (TDD-identity-control-005
	// §Read Authorization and Disclosure).
	AdminSearchMinLength int
	AdminSearchPageSize  int

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
		"IDENTITY_KEYCLOAK_BASE_URL":        &cfg.KeycloakBaseURL,
		"IDENTITY_KEYCLOAK_CLIENT_ID":       &cfg.KeycloakClientID,
		"IDENTITY_KEYCLOAK_CLIENT_KEY_FILE": &cfg.KeycloakClientKeyFile,

		"IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID":       &cfg.RegistrationClientID,
		"IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE": &cfg.RegistrationClientKeyFile,

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
	switch mode := stringOr("IDENTITY_TOKEN_TYPE", "report"); mode {
	case "report":
	case "enforce":
		cfg.EnforceAccessTokenType = true
	default:
		problems = append(problems, fmt.Errorf("IDENTITY_TOKEN_TYPE is %q; it is report or enforce", mode))
	}
	cfg.ProvisionTimeout = durationOr("IDENTITY_PROVISION_TIMEOUT", 10*time.Second, &problems)
	cfg.PendingRecoveryAfter = durationOr("IDENTITY_PENDING_RECOVERY_AFTER", 60*time.Second, &problems)
	cfg.ReconcilePageSize = intOr("IDENTITY_RECONCILE_PAGE_SIZE", 200, &problems)
	cfg.RegistrationReconcileInterval = durationOr("IDENTITY_REGISTRATION_RECONCILE_INTERVAL", time.Hour, &problems)
	if cfg.RegistrationReconcileInterval >= 7*24*time.Hour {
		problems = append(problems, errors.New("IDENTITY_REGISTRATION_RECONCILE_INTERVAL must be shorter than the kernel's 7-day admin-event retention, or a change loses its attribution before a sweep reads it"))
	}

	// Go durations have no day unit, so the 90-day and 7-day defaults are written in hours.
	cfg.ClientKeyLifetime = durationOr("IDENTITY_CLIENT_KEY_LIFETIME", 2160*time.Hour, &problems)
	cfg.ClientKeyRotationOverlap = durationOr("IDENTITY_CLIENT_KEY_ROTATION_OVERLAP", 168*time.Hour, &problems)
	switch {
	case cfg.ClientKeyLifetime <= 0 || cfg.ClientKeyRotationOverlap <= 0:
		problems = append(problems, errors.New("IDENTITY_CLIENT_KEY_LIFETIME and IDENTITY_CLIENT_KEY_ROTATION_OVERLAP must be positive"))
	case cfg.ClientKeyRotationOverlap >= cfg.ClientKeyLifetime:
		problems = append(problems, errors.New("IDENTITY_CLIENT_KEY_ROTATION_OVERLAP must be shorter than IDENTITY_CLIENT_KEY_LIFETIME, or a key would retire after it expired"))
	}

	switch environment := stringOr("IDENTITY_ENVIRONMENT", "production"); environment {
	case "production":
		cfg.Production = true
	case "non-production":
	default:
		problems = append(problems, fmt.Errorf("IDENTITY_ENVIRONMENT is %q; it is production or non-production", environment))
	}
	switch mode := stringOr("IDENTITY_UNMANAGED_CLIENTS", "report"); mode {
	case "report":
	case "disable":
		cfg.DisableUnmanagedClients = true
	default:
		problems = append(problems, fmt.Errorf("IDENTITY_UNMANAGED_CLIENTS is %q; it is report or disable", mode))
	}

	if raw := strings.TrimSpace(os.Getenv("IDENTITY_DELIVERY_PRINCIPAL_ID")); raw != "" {
		parsed, err := id.Parse(raw)
		if err != nil {
			problems = append(problems, fmt.Errorf("IDENTITY_DELIVERY_PRINCIPAL_ID is not a principal_id: %q", raw))
		} else {
			cfg.DeliveryPrincipal = parsed
		}
	}

	cfg.SecurityRefKeyFile = strings.TrimSpace(os.Getenv("IDENTITY_SECURITY_REF_KEY_FILE"))
	if cfg.SecurityRefKeyFile == "" {
		problems = append(problems, errors.New("IDENTITY_SECURITY_REF_KEY_FILE is required"))
	}
	cfg.SecurityRefTTL = durationOr("IDENTITY_SECURITY_REF_TTL", 10*time.Minute, &problems)
	cfg.AdminSearchMinLength = intOr("IDENTITY_ADMIN_SEARCH_MIN_LENGTH", 3, &problems)
	cfg.AdminSearchPageSize = intOr("IDENTITY_ADMIN_SEARCH_PAGE_SIZE", 25, &problems)
	if cfg.SecurityRefTTL <= 0 || cfg.AdminSearchMinLength <= 0 || cfg.AdminSearchPageSize <= 0 {
		problems = append(problems, errors.New("IDENTITY_SECURITY_REF_TTL, IDENTITY_ADMIN_SEARCH_MIN_LENGTH and IDENTITY_ADMIN_SEARCH_PAGE_SIZE must be positive"))
	}

	cfg.Organization = loadOrganization(&problems)
	cfg.ProviderFreshness = durationOr("IDENTITY_PROVIDER_FRESHNESS", 60*time.Second, &problems)

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

// Organization is this service's client of Organization Control: where it is, and the workload
// client this service calls it as, with a private_key_jwt assertion (STD-IAM-001 §3).
type Organization struct {
	BaseURL          string
	WorkloadClientID string
	WorkloadKeyFile  string
	WorkloadTokenURL string
	// WorkloadAudience is the kernel's issuer, which the assertion names (RFC 7523 §3).
	WorkloadAudience string
}

// loadOrganization reads Organization Control's settings. Nothing is required while the base URL is
// unset; once it is, the workload client is.
func loadOrganization(problems *[]error) Organization {
	org := Organization{
		BaseURL:          strings.TrimSpace(os.Getenv("IDENTITY_ORGANIZATION_BASE_URL")),
		WorkloadClientID: strings.TrimSpace(os.Getenv("IDENTITY_WORKLOAD_CLIENT_ID")),
		WorkloadKeyFile:  strings.TrimSpace(os.Getenv("IDENTITY_WORKLOAD_KEY_FILE")),
		WorkloadTokenURL: strings.TrimSpace(os.Getenv("IDENTITY_WORKLOAD_TOKEN_URL")),
		WorkloadAudience: strings.TrimSpace(os.Getenv("IDENTITY_WORKLOAD_AUDIENCE")),
	}
	if org.BaseURL == "" {
		return org
	}
	for _, setting := range []struct{ name, value string }{
		{"IDENTITY_WORKLOAD_CLIENT_ID", org.WorkloadClientID},
		{"IDENTITY_WORKLOAD_KEY_FILE", org.WorkloadKeyFile},
		{"IDENTITY_WORKLOAD_TOKEN_URL", org.WorkloadTokenURL},
		{"IDENTITY_WORKLOAD_AUDIENCE", org.WorkloadAudience},
	} {
		if setting.value == "" {
			*problems = append(*problems, fmt.Errorf("%s is required while IDENTITY_ORGANIZATION_BASE_URL is set", setting.name))
		}
	}
	return org
}

// ProviderBootstrapConfig is what cmd/identity-provider-bootstrap needs: this service's database,
// as the runtime role, and Organization Control.
type ProviderBootstrapConfig struct {
	RuntimeDSN   string
	Organization Organization
	LogLevel     string
}

// LoadProviderBootstrap reads it. Organization Control is required here: the command exists to read
// its snapshot.
func LoadProviderBootstrap() (ProviderBootstrapConfig, error) {
	var problems []error
	cfg := ProviderBootstrapConfig{
		RuntimeDSN: strings.TrimSpace(os.Getenv("IDENTITY_DATABASE_URL")),
		LogLevel:   stringOr("LOG_LEVEL", "info"),
	}
	if cfg.RuntimeDSN == "" {
		problems = append(problems, errors.New("IDENTITY_DATABASE_URL is required"))
	}
	cfg.Organization = loadOrganization(&problems)
	if cfg.Organization.BaseURL == "" {
		problems = append(problems, errors.New("IDENTITY_ORGANIZATION_BASE_URL is required"))
	}
	if len(problems) > 0 {
		return ProviderBootstrapConfig{}, errors.Join(problems...)
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

	KeycloakRealm         string
	KeycloakBaseURL       string
	KeycloakClientID      string
	KeycloakClientKeyFile string

	// The registration path's own Admin API client, and the resource the ceremony registers with
	// it: this service's audience, the one IDENTITY_TOKEN_AUDIENCE names for the running service, so
	// the two cannot disagree (ADR-IAM-001 §5.11 rule 5).
	RegistrationClientID      string
	RegistrationClientKeyFile string
	TokenAudience             string

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
		"IDENTITY_DATABASE_URL":                          &cfg.RuntimeDSN,
		"IDENTITY_KEYCLOAK_REALM":                        &cfg.KeycloakRealm,
		"IDENTITY_KEYCLOAK_BASE_URL":                     &cfg.KeycloakBaseURL,
		"IDENTITY_KEYCLOAK_CLIENT_ID":                    &cfg.KeycloakClientID,
		"IDENTITY_KEYCLOAK_CLIENT_KEY_FILE":              &cfg.KeycloakClientKeyFile,
		"IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID":       &cfg.RegistrationClientID,
		"IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE": &cfg.RegistrationClientKeyFile,
		"IDENTITY_TOKEN_AUDIENCE":                        &cfg.TokenAudience,
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
