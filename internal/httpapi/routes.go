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
	Principals    *Principals
	Registrations *Registrations
	Workloads     *Workloads
	Database      Prober
	Telemetry     *observability.Telemetry

	// ReadinessTimeout bounds the dependency check. It is well below any orchestrator probe
	// interval so a slow database produces a failed probe rather than a hung one.
	ReadinessTimeout time.Duration
}

// Surface is the deployable's HTTP surface, split by whether a request can carry a credential.
//
// The split exists because an orchestrator probe cannot authenticate. Returning one mux made
// `chain(routes)` apply the authentication middleware to `/readyz` as well, so every probe
// answered 401 and the replica never entered service — an outage produced by wrapping the
// wrong handler, and found by running the process rather than by reading it.
//
// Two fields rather than a list of exempt paths: an exemption list is edited by whoever adds a
// route, and the failure mode of forgetting is an unauthenticated mutation. Here, a new route
// is unauthenticated only if its author writes it into Probes.
type Surface struct {
	// Probes is liveness and readiness. It carries no authentication and never will.
	Probes http.Handler

	// API is every route that acts on behalf of a caller. It requires an authenticated caller.
	API http.Handler
}

// Routes builds the HTTP surface.
//
// It returns bare muxes. The middleware chain is applied by the composition root, so ordering
// stays in one place: TDD-foundation-platform-002 fixes recovery, correlation, logging,
// timeout, and shedding in that order, and a package that wrapped its own routes could quietly
// reorder them.
func Routes(cfg RoutesConfig) (Surface, error) {
	if cfg.Principals == nil {
		return Surface{}, errors.New("httpapi: the Principal handler is required")
	}
	if cfg.Registrations == nil {
		return Surface{}, errors.New("httpapi: the registration drift handler is required")
	}
	if cfg.Workloads == nil {
		return Surface{}, errors.New("httpapi: the workload handler is required")
	}
	if cfg.Database == nil {
		return Surface{}, errors.New("httpapi: a database prober is required")
	}
	if cfg.ReadinessTimeout <= 0 {
		cfg.ReadinessTimeout = 2 * time.Second
	}

	probes := http.NewServeMux()

	// Liveness touches no dependency on purpose. A probe that fails during a database outage
	// makes the orchestrator restart every replica for a fault a restart cannot fix, which
	// converts a degradation into an outage.
	probes.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Readiness answers whether this replica can serve. A replica that cannot reach the
	// Control Database can serve nothing, and belongs out of the load balancer rather than
	// returning errors to callers.
	probes.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
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

	// Every route is a provider's unless it is an owner route (ADR-IAM-003, TDD-identity-control-003
	// §Registration Ownership). providerOnly refuses an owner before a handler reads anything, and
	// owned admits an owner only to a registration it owns.
	p, owned := providerOnly, cfg.Registrations.owned
	api := http.NewServeMux()
	api.HandleFunc("POST /v1/principals", p(cfg.Principals.CreatePrincipal))
	api.HandleFunc("POST /v1/principals/{target}", p(cfg.Principals.PrincipalAction))
	api.HandleFunc("GET /v1/principals:dangling", p(cfg.Principals.Dangling))
	api.HandleFunc("POST /v1/principals:reconcile", p(cfg.Principals.Reconcile))
	api.HandleFunc("POST /v1/registrations", p(cfg.Registrations.Register))
	api.HandleFunc("GET /v1/registrations", p(cfg.Registrations.ListRegistrations))
	api.HandleFunc("GET /v1/registrations:mine", cfg.Registrations.Mine)
	api.HandleFunc("GET /v1/registrations/{registration_id}", owned(cfg.Registrations.GetRegistration))
	api.HandleFunc("POST /v1/registrations/{registration_id}",
		owned(cfg.Registrations.RegistrationAction, "suspend", "restore"))
	api.HandleFunc("GET /v1/registrations/{registration_id}/findings", owned(cfg.Registrations.Findings))
	api.HandleFunc("GET /v1/registrations:drift", p(cfg.Registrations.Drift))
	api.HandleFunc("GET /v1/registrations:expiring-keys", p(cfg.Registrations.ExpiringKeys))
	api.HandleFunc("POST /v1/registrations:reconcile", p(cfg.Registrations.Reconcile))
	api.HandleFunc("POST /v1/registrations:adopt", p(cfg.Registrations.Adopt))
	api.HandleFunc("POST /v1/registrations/{registration_id}/drift-exceptions", p(cfg.Registrations.GrantException))
	api.HandleFunc("GET /v1/registrations/{registration_id}/drift-exceptions", p(cfg.Registrations.Exceptions))
	api.HandleFunc("POST /v1/registrations/{registration_id}/keys", owned(cfg.Registrations.AddKey))
	api.HandleFunc("GET /v1/registrations/{registration_id}/keys", owned(cfg.Registrations.Keys))
	api.HandleFunc("POST /v1/registrations/{registration_id}/keys/{key_action}", owned(cfg.Registrations.KeyAction))
	api.HandleFunc("POST /v1/registrations/{registration_id}/owners", p(cfg.Registrations.GrantOwner))
	api.HandleFunc("GET /v1/registrations/{registration_id}/owners", owned(cfg.Registrations.Owners))
	api.HandleFunc("POST /v1/registrations/{registration_id}/owners/{owner_action}", p(cfg.Registrations.OwnerAction))
	api.HandleFunc("POST /v1/registrations/{registration_id}/changes", owned(cfg.Registrations.ProposeChange))
	api.HandleFunc("GET /v1/registrations/{registration_id}/changes", owned(cfg.Registrations.Changes))
	// An owner reaches a change action only on a registration it owns; approve and reject then
	// refuse it in the handler, before anything is read, and withdraw is its proposer's.
	api.HandleFunc("POST /v1/registrations/{registration_id}/changes/{change_action}", owned(cfg.Registrations.ChangeAction))
	api.HandleFunc("GET /v1/registrations:changes", p(cfg.Registrations.OpenChanges))
	api.HandleFunc("POST /v1/workloads", p(cfg.Workloads.CreateWorkload))
	api.HandleFunc("GET /v1/workloads/{target}", p(cfg.Workloads.GetWorkload))
	api.HandleFunc("POST /v1/workloads/{target}", p(cfg.Workloads.WorkloadAction))

	return Surface{Probes: probes, API: api}, nil
}

// Mount joins the two halves onto one root mux, each behind the chain its half requires.
//
// The probe patterns are literal and method-qualified, so Go's mux precedence gives them
// priority over the catch-all without either half being able to shadow the other.
func (s Surface) Mount(probeChain, apiChain func(http.Handler) http.Handler) http.Handler {
	root := http.NewServeMux()
	root.Handle("GET /healthz", probeChain(s.Probes))
	root.Handle("GET /readyz", probeChain(s.Probes))
	root.Handle("/", apiChain(s.API))
	return root
}
