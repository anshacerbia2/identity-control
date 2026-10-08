package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
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

	// Security serves a provider's security commands on another Principal (TDD-identity-control-005
	// §Containment as Built). Nil, its routes are not mounted and :suspend and :restore are unknown.
	Security *Security

	// Assurance is IDENTITY_ASSURANCE: the zero value enforces the levels routes require.
	Assurance AssurancePolicy

	// Me serves a person's own sessions and authenticators (TDD-identity-control-005 §Self-Service as
	// Built). Nil, its routes are not mounted.
	Me *Me

	// Investigation serves a provider's reads of another Principal (TDD-identity-control-005). Nil,
	// its routes are not mounted.
	Investigation *Investigation

	// TenantContext serves the Tenant context report (TDD-identity-control-002 2.2.0). Nil, its route
	// is not mounted.
	TenantContext TenantReporter

	// KernelEvents sweeps the kernel's event store into the record on request (TDD-identity-control-007).
	// Nil, its route is not mounted.
	KernelEvents KernelEventSweeper

	// EmergencyGrants reports each projected emergency grant's last use (ADR-ORG-002 §5.2). Nil, its
	// route is not mounted.
	EmergencyGrants EmergencyValidator

	// Deliveries applies Organization's provider grant events, and DeliveryVerifier admits the
	// delivering workload alone (TDD-identity-control-006). Either nil, the intake answers 503.
	Deliveries       Applier
	DeliveryVerifier TokenVerifier

	// Keys is where a command's Idempotency-Key is claimed and its answer recorded, for the routes
	// replayedKey names (commands.go). The pool satisfies it. Nil, as in a handler's unit test, the
	// key is still required and nothing is recorded.
	Keys KeyStore

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

	// Deliveries is the acceptance API Organization Control's dispatcher posts to. It verifies its
	// own caller, the delivering workload, and no caller route's authentication applies to it.
	Deliveries http.Handler
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
	p, owned, creator := providerOnly(cfg.Assurance), cfg.Registrations.owned, cfg.Registrations.creator
	// Every mutating route requires an Idempotency-Key unless keyOptional names it (commands.go,
	// STD-GLB-001 1.4.0). k.cmd checks a key its service claims; k.replay claims it here.
	k := newCommands(cfg.Keys, cfg.Telemetry)
	api := http.NewServeMux()
	api.HandleFunc("POST /v1/principals", p(k.cmd(cfg.Principals.CreatePrincipal)))
	api.HandleFunc("POST /v1/principals/{target}", p(k.cmd(principalAction(cfg, k))))
	api.HandleFunc("GET /v1/principals:dangling", p(cfg.Principals.Dangling))
	api.HandleFunc("GET /v1/principals:unmapped", p(cfg.Principals.Unmapped))
	if cfg.Investigation != nil {
		api.HandleFunc("GET /v1/principals:search", p(cfg.Investigation.Search))
		api.HandleFunc("GET /v1/principals/{principal_id}", p(cfg.Investigation.Principal))
		api.HandleFunc("GET /v1/principals/{principal_id}/sessions", p(cfg.Investigation.Sessions))
		api.HandleFunc("GET /v1/principals/{principal_id}/authenticators", p(cfg.Investigation.Authenticators))
		api.HandleFunc("GET /v1/principals/{principal_id}/federation-links", p(cfg.Investigation.FederationLinks))
		api.HandleFunc("GET /v1/principals/{principal_id}/findings", p(cfg.Investigation.Findings))
		api.HandleFunc("GET /v1/principals/{principal_id}/events", p(cfg.Investigation.Events))
		api.HandleFunc("GET /v1/principals/{principal_id}/notification-addresses", p(cfg.Investigation.NotificationAddresses))
		api.HandleFunc("GET /v1/principals/{principal_id}/security-notifications", p(cfg.Investigation.SecurityNotifications))
	}
	if cfg.KernelEvents != nil {
		api.HandleFunc("POST /v1/kernel-events:sweep", p(kernelEventSweep(cfg.KernelEvents)))
	}
	if cfg.TenantContext != nil {
		api.HandleFunc("GET /v1/projections/tenant-context/report", p(tenantReport(cfg.TenantContext)))
	}
	if cfg.EmergencyGrants != nil {
		api.HandleFunc("GET /v1/provider-grants:emergency-validation", p(emergencyValidation(cfg.EmergencyGrants)))
	}
	// Route class self: any person, acting on the Principal in its token.
	s := selfOnly
	if cfg.Me != nil {
		cfg.Me.assurance = cfg.Assurance
		api.HandleFunc("GET /v1/me/sessions", s(cfg.Me.Sessions))
		api.HandleFunc("POST /v1/me/sessions/{session_action}", s(k.cmd(cfg.Me.SessionAction)))
		api.HandleFunc("POST /v1/me/sessions:terminate-all", s(k.cmd(cfg.Me.TerminateAll)))
		api.HandleFunc("GET /v1/me/authenticators", s(cfg.Me.Authenticators))
		api.HandleFunc("POST /v1/me/authenticators/{authenticator_action}", s(k.cmd(cfg.Me.AuthenticatorAction)))
		api.HandleFunc("POST /v1/me/authenticators:enroll", s(cfg.Me.Enroll))
		api.HandleFunc("GET /v1/me/security-operations/{operation_id}", s(cfg.Me.Operation))
		if cfg.Me.addresses != nil {
			api.HandleFunc("GET /v1/me/notification-addresses", s(cfg.Me.NotificationAddresses))
			api.HandleFunc("POST /v1/me/notification-addresses", s(k.replay(cfg.Me.AddNotificationAddress)))
			api.HandleFunc("POST /v1/me/notification-addresses/{address_action}", s(k.replay(cfg.Me.NotificationAddressAction)))
		}
	}
	if cfg.Security != nil {
		api.HandleFunc("POST /v1/principals/{principal_id}/sessions:terminate-all", p(k.cmd(cfg.Security.TerminateAll)))
		api.HandleFunc("POST /v1/principals/{principal_id}/authenticators/{authenticator_action}", p(k.cmd(cfg.Security.Revoke)))
		api.HandleFunc("GET /v1/security-operations/{operation_id}", p(cfg.Security.Operation))
		api.HandleFunc("GET /v1/security-operations:unresolved", p(cfg.Security.Unresolved))
		api.HandleFunc("POST /v1/security-operations/{operation_action}", p(k.replay(cfg.Security.OperationAction)))
	}
	api.HandleFunc("POST /v1/principals:reconcile", p(cfg.Principals.Reconcile))
	// A provider registers anything; an application developer registers within its bounds.
	api.HandleFunc("POST /v1/registrations", creator(k.cmd(cfg.Registrations.Register)))
	api.HandleFunc("GET /v1/registrations", p(cfg.Registrations.ListRegistrations))
	api.HandleFunc("GET /v1/registrations:mine", cfg.Registrations.Mine)
	api.HandleFunc("GET /v1/registrations:standing", cfg.Registrations.Standing)
	api.HandleFunc("GET /v1/registrations/{registration_id}", owned(cfg.Registrations.GetRegistration))
	api.HandleFunc("POST /v1/registrations/{registration_id}",
		owned(k.replay(cfg.Registrations.RegistrationAction), "suspend", "restore"))
	api.HandleFunc("GET /v1/registrations/{registration_id}/findings", owned(cfg.Registrations.Findings))
	api.HandleFunc("GET /v1/registrations:drift", p(cfg.Registrations.Drift))
	api.HandleFunc("GET /v1/registrations:expiring-keys", p(cfg.Registrations.ExpiringKeys))
	api.HandleFunc("POST /v1/registrations:reconcile", p(cfg.Registrations.Reconcile))
	api.HandleFunc("POST /v1/registrations:adopt", p(cfg.Registrations.Adopt))
	api.HandleFunc("POST /v1/registrations/{registration_id}/drift-exceptions", p(k.replay(cfg.Registrations.GrantException)))
	api.HandleFunc("GET /v1/registrations/{registration_id}/drift-exceptions", p(cfg.Registrations.Exceptions))
	api.HandleFunc("POST /v1/registrations/{registration_id}/keys", owned(k.replay(cfg.Registrations.AddKey)))
	api.HandleFunc("GET /v1/registrations/{registration_id}/keys", owned(cfg.Registrations.Keys))
	api.HandleFunc("POST /v1/registrations/{registration_id}/keys/{key_action}", owned(k.replay(cfg.Registrations.KeyAction)))
	api.HandleFunc("POST /v1/registrations/{registration_id}/owners", p(k.replay(cfg.Registrations.GrantOwner)))
	api.HandleFunc("GET /v1/registrations/{registration_id}/owners", owned(cfg.Registrations.Owners))
	api.HandleFunc("POST /v1/registrations/{registration_id}/owners/{owner_action}", p(k.replay(cfg.Registrations.OwnerAction)))
	api.HandleFunc("POST /v1/registrations/{registration_id}/changes", owned(k.replay(cfg.Registrations.ProposeChange)))
	api.HandleFunc("GET /v1/registrations/{registration_id}/changes", owned(cfg.Registrations.Changes))
	// An owner reaches a change action only on a registration it owns; approve and reject then
	// refuse it in the handler, before anything is read, and withdraw is its proposer's.
	api.HandleFunc("POST /v1/registrations/{registration_id}/changes/{change_action}", owned(k.replay(cfg.Registrations.ChangeAction)))
	api.HandleFunc("GET /v1/registrations:changes", p(cfg.Registrations.OpenChanges))
	api.HandleFunc("GET /v1/application-developers", p(cfg.Registrations.ApplicationDevelopers))
	api.HandleFunc("POST /v1/application-developers", p(k.replay(cfg.Registrations.GrantApplicationDeveloper)))
	api.HandleFunc("POST /v1/application-developers/{developer_action}", p(k.replay(cfg.Registrations.DeveloperAction)))
	// A request is a provider's or an application developer's; approving, rejecting and the queue
	// are a provider's, refused to anyone else in the handler, and withdrawing is the proposer's.
	api.HandleFunc("POST /v1/registration-requests", creator(k.replay(cfg.Registrations.ProposeRegistration)))
	api.HandleFunc("GET /v1/registration-requests", p(cfg.Registrations.RequestQueue))
	api.HandleFunc("GET /v1/registration-requests:mine", creator(cfg.Registrations.MyRequests))
	api.HandleFunc("POST /v1/registration-requests/{request_action}", creator(k.replay(cfg.Registrations.RequestAction)))
	api.HandleFunc("POST /v1/workloads", p(k.cmd(cfg.Workloads.CreateWorkload)))
	api.HandleFunc("GET /v1/workloads/{target}", p(cfg.Workloads.GetWorkload))
	// :review is the workload owner's; every other action a provider's (TDD-identity-control-004 1.5.0).
	ownedWorkload := cfg.Workloads.owned(cfg.Assurance)
	api.HandleFunc("POST /v1/workloads/{target}", ownedWorkload(k.replay(cfg.Workloads.WorkloadAction)))
	api.HandleFunc("POST /v1/workloads:sweep", p(cfg.Workloads.Sweep))
	api.HandleFunc("GET /v1/workloads:orphaned", p(cfg.Workloads.Orphaned))
	api.HandleFunc("GET /v1/workloads:unused", p(cfg.Workloads.Unused))
	api.HandleFunc("GET /v1/workloads:reviews-overdue", p(cfg.Workloads.ReviewsOverdue))

	return Surface{Probes: probes, API: api, Deliveries: deliveryIntake(cfg.DeliveryVerifier, cfg.Deliveries)}, nil
}

// Mount joins the two halves onto one root mux, each behind the chain its half requires.
//
// The probe patterns are literal and method-qualified, so Go's mux precedence gives them
// priority over the catch-all without either half being able to shadow the other.
//
// The delivery intake takes the probe chain -- observability and timeout, no caller authentication --
// because it verifies its own caller, which no caller route would admit.
func (s Surface) Mount(probeChain, apiChain func(http.Handler) http.Handler) http.Handler {
	root := http.NewServeMux()
	root.Handle("GET /healthz", probeChain(s.Probes))
	root.Handle("GET /readyz", probeChain(s.Probes))
	if s.Deliveries != nil {
		root.Handle("POST /v1/deliveries", probeChain(s.Deliveries))
	}
	root.Handle("/", apiChain(reasonHeaders(s.API)))
	return root
}

// principalAction dispatches POST /v1/principals/{target} by its action: :relink to the Principal
// path, replayed here, and :suspend and :restore to the security commands when they are mounted,
// which key themselves.
func principalAction(cfg RoutesConfig, k commands) http.HandlerFunc {
	relink := k.replay(cfg.Principals.PrincipalAction)
	return func(w http.ResponseWriter, r *http.Request) {
		subject, action, _ := strings.Cut(r.PathValue("target"), ":")
		switch {
		case action == "suspend" && cfg.Security != nil:
			cfg.Security.Suspend(w, r, subject)
		case action == "restore" && cfg.Security != nil:
			cfg.Security.Restore(w, r, subject)
		default:
			relink(w, r)
		}
	}
}
