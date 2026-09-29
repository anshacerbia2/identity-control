// Command identity-control is the Identity Control Service deployable.
//
// This file is the composition root and the only place in the repository that constructs
// anything. Every dependency is built here and passed down explicitly: no package-level
// singleton, no init() side effect, and nothing started by the act of being linked, per
// STD-GLB-BE-001 rule 10.
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
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/observability"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/config"
	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/reconcile"
	"github.com/anshacerbia2/identity-control/internal/registration"
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
	// per ADR-IAM-001 §5.10. It is a private key, read from its file once, held by the client, and
	// never logged: the startup line below names the realm and the base URL and stops there. The
	// kernel holds only its public half (ADR-IAM-001 §5.12).
	kernelKey, err := keycloak.LoadClientKey(cfg.KeycloakClientKeyFile)
	if err != nil {
		return fmt.Errorf("identity kernel client key: %w", err)
	}
	registryKey, err := keycloak.LoadClientKey(cfg.RegistrationClientKeyFile)
	if err != nil {
		return fmt.Errorf("registration kernel client key: %w", err)
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

	logger.Info("identity kernel configured",
		slog.String("base_url", cfg.KeycloakBaseURL),
		slog.String("realm", cfg.KeycloakRealm))

	provisioner, err := provisioning.New(pool, kernel, provisioning.Config{
		ProvisionTimeout:     cfg.ProvisionTimeout,
		PendingRecoveryAfter: cfg.PendingRecoveryAfter,
		RecoveryBatch:        cfg.ReconcilePageSize,
		Realm:                keycloak.Realm(cfg.KeycloakRealm),
	}, logger)
	if err != nil {
		return fmt.Errorf("principal provisioner: %w", err)
	}

	// The registration path's own credential, and a second client built from it. The reconciler
	// receives only the ClientRegistry this one serves, so the Principal path's credential never
	// reaches a client call, and this one never reaches a user call (TDD-identity-control-003).
	registry, err := keycloak.NewAdmin(keycloak.AdminConfig{
		BaseURL:   cfg.KeycloakBaseURL,
		Realm:     keycloak.Realm(cfg.KeycloakRealm),
		ClientID:  cfg.RegistrationClientID,
		ClientKey: registryKey,
		Timeout:   cfg.ProvisionTimeout,
	}, nil)
	if err != nil {
		return fmt.Errorf("registration kernel client: %w", err)
	}

	registrar, err := registration.New(pool, registry, registration.Config{
		Realm:                keycloak.Realm(cfg.KeycloakRealm),
		CallTimeout:          cfg.ProvisionTimeout,
		PendingRecoveryAfter: cfg.PendingRecoveryAfter,
	}, logger)
	if err != nil {
		return fmt.Errorf("registration service: %w", err)
	}

	reconciler, err := reconcile.New(pool, registry, reconcile.Config{
		Realm:       keycloak.Realm(cfg.KeycloakRealm),
		Interval:    cfg.RegistrationReconcileInterval,
		CallTimeout: cfg.ProvisionTimeout,
		Recreate:    registrar.Recreate,
	}, logger)
	if err != nil {
		return fmt.Errorf("registration reconciler: %w", err)
	}

	registrations, err := httpapi.NewRegistrations(registrar, reconciler)
	if err != nil {
		return fmt.Errorf("registration drift handler: %w", err)
	}

	principals, err := httpapi.NewPrincipals(provisioner, keycloak.Realm(cfg.KeycloakRealm))
	if err != nil {
		return fmt.Errorf("principal handler: %w", err)
	}

	surface, err := httpapi.Routes(httpapi.RoutesConfig{
		Principals:    principals,
		Registrations: registrations,
		Database:      pool,
		Telemetry:     telemetry,
	})
	if err != nil {
		return fmt.Errorf("routes: %w", err)
	}

	// The key source performs no fetch here. A cold replica loads the key set on its first
	// verification, and NewJWKS deliberately touches no network so the composition root decides
	// when that happens rather than the linker.
	keys, err := verify.NewJWKS(verify.JWKSConfig{URL: cfg.JWKSURL})
	if err != nil {
		return fmt.Errorf("jwks source: %w", err)
	}

	// The claim rule is this service's, because STD-IAM-002 §3.5 states it in terms of a claim
	// foundation-platform is forbidden from naming. The verifier refuses to build without one.
	verifier, err := verify.New(verify.Config{
		Issuer:      cfg.TokenIssuer,
		Audience:    cfg.TokenAudience,
		Keys:        keys,
		Requirement: httpapi.Requirement(),
		MaxSkew:     cfg.TokenMaxSkew,
	})
	if err != nil {
		return fmt.Errorf("token verifier: %w", err)
	}

	authentication, err := httpapi.Authenticate(verifier)
	if err != nil {
		return fmt.Errorf("authentication middleware: %w", err)
	}

	logger.Info("token verification configured",
		slog.String("issuer", cfg.TokenIssuer),
		slog.String("audience", cfg.TokenAudience),
		slog.String("jwks_url", cfg.JWKSURL),
		slog.Duration("max_skew", cfg.TokenMaxSkew))

	// Authentication is supplied to Chain rather than wrapped around the mux here, so it runs
	// at the position TDD-foundation-platform-002 fixes: after load shedding, so rejecting
	// overload costs no signature verification, and before the idempotency claim, so a key is
	// always claimed under an authenticated caller.
	apiChain := fhttp.Chain(fhttp.Options{
		Telemetry:      telemetry,
		Timeout:        cfg.HTTPRequestTimeout,
		MaxInFlight:    cfg.HTTPMaxInFlight,
		Authentication: authentication,
	})

	// Probes get the same observability and timeout and neither authentication nor the API's
	// in-flight budget. Both omissions are decisions, not oversights: a probe cannot present a
	// credential, and a readiness check shed by an overloaded API would remove a replica that
	// is still healthy — which is how load shedding turns overload into an outage.
	probeChain := fhttp.Chain(fhttp.Options{
		Telemetry: telemetry,
		Timeout:   cfg.HTTPRequestTimeout,
	})

	server, err := fhttp.NewServer(cfg.ListenAddress, surface.Mount(probeChain, apiChain), fhttp.ServerConfig{
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

	// The registration sweep runs on a schedule from here, the one package allowed to start a
	// goroutine. Every replica schedules it; the reconciler's run claim lets one sweep at a time
	// through, so the others' ticks are skipped rather than duplicated.
	go scheduleSweeps(ctx, provisioner, registrar, reconciler, cfg.RegistrationReconcileInterval, logger)

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

// scheduleSweeps runs a registration sweep at start and then every interval, until ctx ends. A
// sweep cut off by shutdown leaves its run unfinished, which is how a stopped replica's run is
// meant to look, and it stops blocking the next one after two intervals.
func scheduleSweeps(ctx context.Context, provisioner *provisioning.Provisioner, registrar *registration.Service,
	reconciler *reconcile.Reconciler, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		// Principals first: a mapping whose creation was interrupted is recovered, which nothing ran
		// before this schedule existed, and an active mapping whose Keycloak user is gone is reported.
		if recovered, dangling, err := provisioner.Reconcile(ctx); err != nil {
			logger.Error("principal sweep failed", slog.String("error", err.Error()))
		} else if recovered > 0 || dangling > 0 {
			logger.Warn("principal sweep", slog.Int("recovered", recovered), slog.Int("dangling", dangling))
		}
		// Pending registrations first, so a client whose creation was interrupted is adopted before
		// the sweep compares the registrations that are active.
		if resolved, err := registrar.RecoverPending(ctx); err != nil {
			logger.Error("pending registration recovery failed", slog.String("error", err.Error()))
		} else if resolved > 0 {
			logger.Info("pending registrations recovered", slog.Int("resolved", resolved))
		}
		run, err := reconciler.Sweep(ctx)
		switch {
		case errors.Is(err, reconcile.ErrSweepInProgress):
			logger.Debug("registration sweep skipped; another replica is sweeping")
		case err != nil:
			logger.Error("registration sweep failed", slog.String("error", err.Error()))
		default:
			logger.Info("registration sweep finished",
				slog.String("run_id", run.ID.String()),
				slog.String("outcome", string(run.Outcome)),
				slog.Int("findings", run.Findings))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
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
