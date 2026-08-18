package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/observability"
)

// Prober reports whether a dependency can be reached.
//
// The pool satisfies it. An interface rather than *db.Pool so readiness can be tested without
// a database, and so this package cannot reach past the one method it needs.
type Prober interface {
	Ping(ctx context.Context) error
}

// RoutesConfig supplies what the mux needs.
type RoutesConfig struct {
	Principals *Principals
	Database   Prober
	Telemetry  *observability.Telemetry

	// ReadinessTimeout bounds the dependency check. It is well below any orchestrator probe
	// interval so a slow database produces a failed probe rather than a hung one.
	ReadinessTimeout time.Duration
}

// Routes builds the HTTP surface.
//
// It returns a bare mux. The middleware chain is applied by the composition root, so ordering
// stays in one place: TDD-foundation-platform-002 fixes recovery, correlation, logging,
// timeout, and shedding in that order, and a package that wrapped its own routes could quietly
// reorder them.
func Routes(cfg RoutesConfig) (http.Handler, error) {
	if cfg.Principals == nil {
		return nil, errors.New("httpapi: the Principal handler is required")
	}
	if cfg.Database == nil {
		return nil, errors.New("httpapi: a database prober is required")
	}
	if cfg.ReadinessTimeout <= 0 {
		cfg.ReadinessTimeout = 2 * time.Second
	}

	mux := http.NewServeMux()

	// Liveness touches no dependency on purpose. A probe that fails during a database outage
	// makes the orchestrator restart every replica for a fault a restart cannot fix, which
	// converts a degradation into an outage.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Readiness answers whether this replica can serve. A replica that cannot reach the
	// Control Database can serve nothing, and belongs out of the load balancer rather than
	// returning errors to callers.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), cfg.ReadinessTimeout)
		defer cancel()
		if err := cfg.Database.Ping(ctx); err != nil {
			if cfg.Telemetry != nil {
				cfg.Telemetry.Logger(r.Context()).WarnContext(r.Context(), "readiness failed",
					slog.String("error", err.Error()))
			}
			httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The control database is unreachable")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})

	mux.HandleFunc("POST /v1/principals", cfg.Principals.CreatePrincipal)

	return mux, nil
}
