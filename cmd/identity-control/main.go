// Command identity-control is the Identity Control Service deployable.
//
// This file is the composition root and the only place in the repository that constructs
// anything. Every dependency is built here and passed down explicitly: no package-level
// singleton, no init() side effect, and nothing started by the act of being linked.
//
// The service owns no authentication, no credential, no session, and no token. Keycloak
// is the identity kernel and holds all four. What lives here is the canonical Principal
// identifier, the Keycloak context projection, and the control-plane authority around
// them.
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
	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/observability"

	"github.com/anshacerbia2/identity-control/internal/config"
)

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet when configuration fails, so this one write goes
		// to stderr directly rather than through a dependency that might be the failure.
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

	// No SessionBinder is supplied, and the omission is a statement rather than an
	// oversight. The binder exists so a consumer can issue SET LOCAL for Row-Level
	// Security without foundation-platform naming a tenant. This service is not the
	// tenant authority and holds no tenant-scoped table yet; supplying a binder that
	// bound nothing would make the RLS posture look enforced when it is absent.
	// TDD-organization-control-001 owns the tenant predicate, and organization-control
	// is the deployable that supplies the statement.
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

	// Authentication, Authorization, and Idempotency are left nil deliberately. Chain
	// fixes where they run; supplying them is this service's job and lands with the first
	// route that needs them. A nil hook is skipped, so the ordering guarantee holds
	// without a placeholder that would have to be remembered and removed.
	chain := httpapi.Chain(httpapi.Options{
		Telemetry:   telemetry,
		Timeout:     cfg.HTTPRequestTimeout,
		MaxInFlight: cfg.HTTPMaxInFlight,
	})

	server, err := httpapi.NewServer(cfg.ListenAddress, chain(routes(pool, telemetry)), httpapi.ServerConfig{
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

	// Shutdown uses a fresh context. Reusing the cancelled one would abort the drain at
	// the instant it began, which is indistinguishable from having no grace period.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPShutdownGrace)
	defer cancel()
	if err := httpapi.Shutdown(shutdownCtx, server, cfg.HTTPShutdownGrace); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("stopped")
	return nil
}

// routes is the whole HTTP surface for this slice. The Principal and projection routes
// land in Week 2 and Week 3; what exists now is what the deployment substrate needs.
func routes(pool *db.Pool, telemetry *observability.Telemetry) http.Handler {
	mux := http.NewServeMux()

	// Liveness answers whether the process is running. It touches no dependency on
	// purpose: a liveness probe that fails on a database outage causes the orchestrator
	// to restart every replica during an outage the restart cannot fix.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Readiness answers whether this replica can serve. It pings the Control Database,
	// because a replica that cannot reach it can serve nothing and belongs out of the
	// load balancer rather than returning errors to callers.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			telemetry.Logger(r.Context()).WarnContext(r.Context(), "readiness failed",
				slog.String("error", err.Error()))
			httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The control database is unreachable")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})

	return mux
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
	// JSON to stdout with no vendor agent, per STD-GLB-003. Redaction of credential-shaped
	// values is enforced inside foundation-platform's serializer rather than here, so a
	// caller cannot forget it.
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed}))
}
