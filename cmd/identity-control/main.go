// Command identity-control is the Identity Control Service deployable.
//
// This file is the composition root and the only place in the repository that constructs
// anything. Every dependency is built here and passed down explicitly: no package-level
// singleton, no init() side effect, and nothing started by the act of being linked, per
// STD-GLB-BE-001 rules 8 and 11.
//
// The service owns no authentication, no credential store, no session, and no token. Keycloak
// is the identity kernel and holds all four. What lives here is the canonical Principal
// identifier, the Keycloak context projection, and the control-plane authority around them.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/anshacerbia2/foundation-platform/db"
	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/identity-control/internal/config"
	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet when configuration fails, so this one write goes to
		// stderr directly rather than through a dependency that might be the failure.
		fmt.Fprintf(os.Stderr, "identity-control: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	logger := newLogger(cfg.LogLevel)

	// Signals are wired before anything is acquired. A process that takes a database
	// connection before it can be interrupted is a process that ignores the first SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	telemetry, err := observability.New(observability.Config{
		Deployable: cfg.Deployable,
		System:     cfg.System,
		Logger:     logger,
	})
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}

	// No SessionBinder is supplied, and the omission is a statement. The binder exists so a
	// consumer can issue SET LOCAL for Row-Level Security without foundation-platform naming
	// a tenant. This service is not the tenant authority and holds no tenant-scoped table
	// yet; supplying a binder that bound nothing would make the RLS posture look enforced
	// when it is absent. TDD-organization-control-001 owns the tenant predicate.
	pool, err := db.Open(ctx, db.Config{
		Name:            "identity-control-runtime",
		DSN:             cfg.RuntimeDSN,
		MaxConns:        cfg.DBMaxConns,
		MaxConnLifetime: cfg.DBMaxConnLifetime,
		AcquireTimeout:  cfg.DBAcquireTimeout,
	})
	if err != nil {
		return fmt.Errorf("control database: %w", err)
	}
	defer pool.Close()

	logger.Info("control database connected",
		slog.String("pool", pool.Name()),
		slog.Int("max_conns", int(cfg.DBMaxConns)))

	// The administration credential lives in this process and nowhere else in the estate,
	// per ADR-IAM-001 §5.5. It is read from configuration once, held by the client, and never
	// logged: the startup line below names the realm and the base URL and stops there.
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

	logger.Info("identity kernel configured",
		slog.String("base_url", cfg.KeycloakBaseURL),
		slog.String("realm", cfg.KeycloakRealm))

	provisioner, err := provisioning.New(pool, kernel, provisioning.Config{
		ProvisionTimeout:     cfg.ProvisionTimeout,
		PendingRecoveryAfter: cfg.PendingRecoveryAfter,
		RecoveryBatch:        cfg.ReconcilePageSize,
	}, logger)
	if err != nil {
		return fmt.Errorf("principal provisioner: %w", err)
	}

	principals, err := httpapi.NewPrincipals(provisioner, keycloak.Realm(cfg.KeycloakRealm))
	if err != nil {
		return fmt.Errorf("principal handler: %w", err)
	}

	routes, err := httpapi.Routes(httpapi.RoutesConfig{
		Principals: principals,
		Database:   pool,
		Telemetry:  telemetry,
	})
	if err != nil {
		return fmt.Errorf("routes: %w", err)
	}

	// Authentication is deliberately absent, and every mutation therefore fails closed with
	// 401 until it lands. Chain fixes where an authentication hook runs; supplying one is this
	// service's job, and verifying a token means fetching JWKS and applying the whole
	// STD-IAM-002 §3.5 checklist, which is its own increment.
	//
	// A development mode that trusted a header would have made the route usable today. It is
	// not offered: a permissive authentication path that exists in one environment is a
	// permissive path that reaches production, and EAD-006 §8 requires a security-control
	// failure to fail closed rather than open. The startup log states the reduced capability
	// so an operator is never left guessing why a request is refused.
	logger.Warn("authentication is not configured; every mutation will be refused with 401",
		slog.String("effect", "POST /v1/principals is unavailable until a token verifier is supplied"))

	chain := fhttp.Chain(fhttp.Options{
		Telemetry:   telemetry,
		Timeout:     cfg.HTTPRequestTimeout,
		MaxInFlight: cfg.HTTPMaxInFlight,
	})

	server, err := fhttp.NewServer(cfg.ListenAddress, chain(routes), fhttp.ServerConfig{
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
	})
	if err != nil {
		return fmt.Errorf("http server: %w", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("address", cfg.ListenAddress))
		if listenErr := server.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			serveErr <- listenErr
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutdown signalled", slog.Duration("grace", cfg.HTTPShutdownGrace))
	}

	// Shutdown uses a fresh context. Reusing the cancelled one would abort the drain at the
	// instant it began, which is indistinguishable from having no grace period.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPShutdownGrace)
	defer cancel()
	if err := fhttp.Shutdown(shutdownCtx, server, cfg.HTTPShutdownGrace); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("stopped")
	return nil
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		parsed = slog.LevelDebug
	case "warn":
		parsed = slog.LevelWarn
	case "error":
		parsed = slog.LevelError
	default:
		parsed = slog.LevelInfo
	}
	// JSON to stdout with no vendor agent, per STD-GLB-003. Credential redaction is enforced
	// inside foundation-platform's serializer rather than here, so a caller cannot forget it.
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed}))
}
