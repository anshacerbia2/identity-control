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

	"github.com/anshacerbia2/identity-control/internal/config"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
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

	kernel, err := keycloak.NewAdmin(keycloak.AdminConfig{
		BaseURL:      cfg.KeycloakBaseURL,
		Realm:        keycloak.Realm(cfg.KeycloakRealm),
		ClientID:     cfg.KeycloakClientID,
		ClientSecret: cfg.KeycloakClientSecret,
		Timeout:      cfg.ProvisionTimeout,
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
