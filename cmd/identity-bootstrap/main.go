// Command identity-bootstrap performs the one ceremony that creates a realm's first Principal.
//
// `POST /v1/principals` requires a caller holding a `principal_id`, and it is the only path that
// issues one, so a fresh Control Database has no entry point. This command is it. ADR-IAM-001
// §5.8 records the decision, and TDD-identity-control-001 records the structural guarantees.
//
// It is a command rather than an endpoint on purpose. An endpoint that creates a Principal
// without an authenticated caller is a permanent hole in the API whether or not a guard currently
// closes it, and the guard would be a check on data — the registry is empty in every fresh
// environment, including a restored one and a mistakenly-pointed-at one.
//
// It holds no credential. The kernel user is created owing a credential-setting action, so the
// first human interaction establishes the credential and this process never handles one.
//
//	identity-bootstrap -operator 'ansha@…' -reason 'initial estate stand-up' -username ansha
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/config"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

func main() {
	operator := flag.String("operator", "", "the human performing the ceremony; recorded immutably")
	reason := flag.String("reason", "", "why the ceremony is being performed; recorded immutably")
	username := flag.String("username", "", "username of the first Principal")
	email := flag.String("email", "", "email of the first Principal (optional)")
	resume := flag.String("resume", "", "set to the recorded operator to resume an interrupted ceremony")
	timeout := flag.Duration("timeout", 2*time.Minute, "upper bound on the whole ceremony")
	flag.Parse()

	if err := run(*operator, *reason, *username, *email, *resume, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "identity-bootstrap: %v\n", err)
		os.Exit(1)
	}
}

func run(operator, reason, username, email, resume string, timeout time.Duration) error {
	cfg, err := config.LoadBootstrap()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pool, err := db.Open(ctx, db.Config{
		Name:     "identity-bootstrap",
		DSN:      cfg.RuntimeDSN,
		MaxConns: 2,
	})
	if err != nil {
		return fmt.Errorf("control database: %w", err)
	}
	defer pool.Close()

	kernelKey, err := keycloak.LoadClientKey(cfg.KeycloakClientKeyFile)
	if err != nil {
		return fmt.Errorf("identity kernel client key: %w", err)
	}
	kernel, err := keycloak.NewAdmin(keycloak.AdminConfig{
		BaseURL:   cfg.KeycloakBaseURL,
		Realm:     keycloak.Realm(cfg.KeycloakRealm),
		ClientID:  cfg.KeycloakClientID,
		ClientKey: kernelKey,
		Timeout:   cfg.ProvisionTimeout,
	}, nil)
	if err != nil {
		return fmt.Errorf("identity kernel client: %w", err)
	}

	provisioner, err := provisioning.New(pool, kernel, provisioning.Config{
		ProvisionTimeout:     cfg.ProvisionTimeout,
		PendingRecoveryAfter: cfg.PendingRecoveryAfter,
	}, logger)
	if err != nil {
		return fmt.Errorf("principal provisioner: %w", err)
	}

	// Refuse before touching the kernel when a ceremony is already on record.
	//
	// Bootstrap itself is idempotent — a resumed ceremony replays the stored idempotency key and
	// returns the original identifier — so this check exists for the operator rather than for
	// correctness. Someone running the command twice by accident should be told what already
	// happened, not handed a success that looks like a fresh creation.
	record, performed, err := provisioner.CeremonyPerformed(ctx)
	if err != nil {
		return fmt.Errorf("read the ceremony record: %w", err)
	}
	if performed && resume == "" {
		return fmt.Errorf(
			"%w\n  operator: %s\n  reason:   %s\npass -resume %q to complete an interrupted ceremony",
			provisioning.ErrCeremonyAlreadyPerformed, record.Operator, record.Reason, record.Operator)
	}
	if performed && resume != record.Operator {
		// Naming the recorded operator is the confirmation. It cannot be guessed from the flags
		// and it forces whoever resumes to have read the record first, which is the point of
		// keeping one.
		return fmt.Errorf("-resume %q does not match the recorded operator; refusing", resume)
	}

	response, record, err := provisioner.Bootstrap(ctx, provisioning.CeremonyRequest{
		Realm:    keycloak.Realm(cfg.KeycloakRealm),
		Username: username,
		Email:    email,
		Operator: operator,
		Reason:   reason,
	})
	if err != nil {
		if errors.Is(err, provisioning.ErrRegistryNotEmpty) {
			return fmt.Errorf("%w\nthe ceremony creates the first Principal only; use POST /v1/principals", err)
		}
		return err
	}

	// ADR-IAM-001 §5.11 rule 5: the resource the first call is made to. A token is admitted only when
	// its aud names a registered resource, and registering one through the API would need such a
	// token first. Under the ceremony's own key, so a resumed ceremony completes it once.
	resource, err := registerOwnResource(ctx, pool, cfg, response.PrincipalID, logger)
	if err != nil {
		return fmt.Errorf("the first Principal exists; registering %s failed, so resume the ceremony: %w",
			cfg.TokenAudience, err)
	}

	logger.InfoContext(ctx, "bootstrap ceremony complete",
		slog.String("principal_id", response.PrincipalID.String()),
		slog.String("realm", string(response.Realm)),
		slog.String("operator", record.Operator))

	// Printed to stdout separately from the log so the operator can copy the identifier without
	// parsing JSON. The next step is stated because a Principal owing a credential cannot yet
	// authenticate, and an operator who does not know that reads it as a failure.
	fmt.Printf("\nfirst Principal created\n")
	fmt.Printf("  principal_id  %s\n", response.PrincipalID)
	fmt.Printf("  username      %s\n", username)
	fmt.Printf("  realm         %s\n", response.Realm)
	fmt.Printf("  operator      %s\n", record.Operator)
	fmt.Printf("  resource      %s (registration %s)\n", resource.ClientKey, resource.ID)
	fmt.Printf("\nThis Principal is a provider by the ceremony's grant until Organization's first\n")
	fmt.Printf("emergency provider:identity-control grant is projected (TDD-identity-control-006).\n")
	fmt.Printf("\nThis Principal owes a credential. It cannot authenticate until the kernel's\n")
	fmt.Printf("credential-setting action is completed; this command never held one.\n")
	return nil
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ownResourceScope is the idempotency scope of the ceremony's resource registration. Like the
// ceremony's own scope it is not a Principal's, so no authenticated caller can replay or claim it.
const ownResourceScope = "ceremony:bootstrap"

// registerOwnResource registers this service's resource: keyless, privileged at lifetime class L0,
// registered by the Principal the ceremony created (ADR-IAM-001 §5.11 rule 5, STD-IAM-002 §3.1).
func registerOwnResource(ctx context.Context, pool *db.Pool, cfg config.BootstrapConfig, firstPrincipal id.UUID,
	logger *slog.Logger) (registration.Registration, error) {
	key, err := keycloak.LoadClientKey(cfg.RegistrationClientKeyFile)
	if err != nil {
		return registration.Registration{}, fmt.Errorf("registration kernel client key: %w", err)
	}
	registry, err := keycloak.NewAdmin(keycloak.AdminConfig{
		BaseURL:   cfg.KeycloakBaseURL,
		Realm:     keycloak.Realm(cfg.KeycloakRealm),
		ClientID:  cfg.RegistrationClientID,
		ClientKey: key,
		Timeout:   cfg.ProvisionTimeout,
	}, nil)
	if err != nil {
		return registration.Registration{}, fmt.Errorf("registration kernel client: %w", err)
	}
	registrar, err := registration.New(pool, registry, registration.Config{
		Realm:                keycloak.Realm(cfg.KeycloakRealm),
		CallTimeout:          cfg.ProvisionTimeout,
		PendingRecoveryAfter: cfg.PendingRecoveryAfter,
	}, logger)
	if err != nil {
		return registration.Registration{}, fmt.Errorf("registration service: %w", err)
	}
	return registrar.Register(ctx, registration.Request{
		CallerScope:    ownResourceScope,
		IdempotencyKey: "bootstrap-resource:" + cfg.KeycloakRealm,
		RegisteredBy:   firstPrincipal,
		ClientKey:      cfg.TokenAudience,
		Profile:        registration.ProfileResource,
		AudienceClass:  "privileged",
		ApplicationRef: "identity-control",
		LifetimeClass:  "L0",
	})
}
