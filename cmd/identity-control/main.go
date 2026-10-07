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

	"go.opentelemetry.io/otel/metric"

	"github.com/anshacerbia2/foundation-platform/db"
	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/observability"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/config"
	"github.com/anshacerbia2/identity-control/internal/delivery"
	"github.com/anshacerbia2/identity-control/internal/httpapi"
	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/investigation"
	"github.com/anshacerbia2/identity-control/internal/kernelevents"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/organization"
	"github.com/anshacerbia2/identity-control/internal/providerauthority"
	"github.com/anshacerbia2/identity-control/internal/reconcile"
	"github.com/anshacerbia2/identity-control/internal/registration"
	"github.com/anshacerbia2/identity-control/internal/securitynotify"
	"github.com/anshacerbia2/identity-control/internal/securityref"
	"github.com/anshacerbia2/identity-control/internal/securitystate"
	"github.com/anshacerbia2/identity-control/internal/tenantcontext"
	"github.com/anshacerbia2/identity-control/internal/workload"
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

	// The Collector, when one is configured, as organization-control exports to it. Without it every
	// metric and span goes to the no-op providers, which is said once here rather than discovered as
	// an empty dashboard.
	var exported *observability.Exported
	if cfg.OTLPEndpoint != "" {
		exported, err = observability.Export(ctx, observability.ExportConfig{
			Endpoint: cfg.OTLPEndpoint, Deployable: cfg.Deployable, System: cfg.System,
		})
		if err != nil {
			return fmt.Errorf("telemetry export: %w", err)
		}
		defer func() {
			flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := exported.Shutdown(flush); err != nil {
				logger.Warn("telemetry flush on shutdown", slog.String("error", err.Error()))
			}
		}()
	} else {
		logger.Warn("OTEL_EXPORTER_OTLP_ENDPOINT is unset: no metric or trace leaves this process")
	}
	telemetryConfig := observability.Config{Deployable: cfg.Deployable, System: cfg.System, Logger: logger}
	if exported != nil {
		telemetryConfig.MeterProvider, telemetryConfig.TracerProvider = exported.MeterProvider, exported.TracerProvider
	}
	telemetry, err := observability.New(telemetryConfig)
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
		KeyLifetime:          cfg.ClientKeyLifetime,
		RotationOverlap:      cfg.ClientKeyRotationOverlap,
		Production:           cfg.Production,
	}, logger)
	if err != nil {
		return fmt.Errorf("registration service: %w", err)
	}

	// The service's own Admin API clients are exempt from the unmanaged rule beside the kernel's
	// built-in ones: a controller's credentials are bootstrapped outside what it controls
	// (ADR-IAM-001 §5.12).
	exempt := append(append([]string{}, reconcile.BuiltInClients...), cfg.KeycloakClientID, cfg.RegistrationClientID)
	reconciler, err := reconcile.New(pool, registry, reconcile.Config{
		Realm:            keycloak.Realm(cfg.KeycloakRealm),
		Interval:         cfg.RegistrationReconcileInterval,
		CallTimeout:      cfg.ProvisionTimeout,
		Recreate:         registrar.Recreate,
		ExemptClients:    exempt,
		DisableUnmanaged: cfg.DisableUnmanagedClients,
	}, logger)
	if err != nil {
		return fmt.Errorf("registration reconciler: %w", err)
	}

	registrations, err := httpapi.NewRegistrations(registrar, reconciler)
	if err != nil {
		return fmt.Errorf("registration drift handler: %w", err)
	}

	// A workload spans both credentials: the registration credential creates its client and reads
	// the client's service-account user, and the Principal credential writes the workload's identity
	// on that user. Each port is handed only the credential that serves it.
	workloads, err := workload.New(pool, registrar, registry, kernel, workload.Config{
		Realm:                keycloak.Realm(cfg.KeycloakRealm),
		CallTimeout:          cfg.ProvisionTimeout,
		PendingRecoveryAfter: cfg.PendingRecoveryAfter,
	}, logger)
	if err != nil {
		return fmt.Errorf("workload service: %w", err)
	}
	workloadHandler, err := httpapi.NewWorkloads(workloads)
	if err != nil {
		return fmt.Errorf("workload handler: %w", err)
	}

	principals, err := httpapi.NewPrincipals(provisioner, keycloak.Realm(cfg.KeycloakRealm))
	if err != nil {
		return fmt.Errorf("principal handler: %w", err)
	}

	// The executor's metrics go to the exported meter provider, or nowhere.
	var meter metric.Meter
	if exported != nil {
		meter = exported.MeterProvider.Meter("github.com/anshacerbia2/identity-control/internal/securitystate")
		// The key expiry gauge (TDD-identity-control-003 1.31.0), under its own package's scope.
		if err := registrar.Instrument(exported.MeterProvider.Meter(
			"github.com/anshacerbia2/identity-control/internal/registration")); err != nil {
			return fmt.Errorf("key expiry gauge: %w", err)
		}
	}

	// A provider's reads of another Principal (TDD-identity-control-005). The kernel's security
	// state is read with the Principal credential, which holds view-users; the handles that name a
	// session or authenticator are sealed with the service's own key ring.
	refKeys, err := securityref.LoadKeyRing(cfg.SecurityRefKeyFile)
	if err != nil {
		return err
	}
	refs, err := securityref.New(refKeys, cfg.SecurityRefTTL)
	if err != nil {
		return err
	}
	investigator, err := investigation.New(pool, kernel, refs, investigation.Config{
		Realm:          keycloak.Realm(cfg.KeycloakRealm),
		SearchMinRunes: cfg.AdminSearchMinLength,
		SearchPageSize: cfg.AdminSearchPageSize,
		CallTimeout:    cfg.ProvisionTimeout,
	})
	if err != nil {
		return fmt.Errorf("investigation service: %w", err)
	}
	investigationHandler, err := httpapi.NewInvestigation(investigator)
	if err != nil {
		return fmt.Errorf("investigation handler: %w", err)
	}
	// The security commands contain a Principal through the same credential (TDD-identity-control-005
	// §Containment as Built). The executor runs in this process beside the API, as the sweeps do.
	securityCommands, err := securitystate.New(pool, kernel, refs, securitystate.Config{
		Realm:          keycloak.Realm(cfg.KeycloakRealm),
		Budget:         cfg.CommandBudget,
		AttemptTimeout: cfg.AttemptTimeout,
		MaxAttempts:    cfg.MaxAttempts,
		Lease:          cfg.OperationLease,
		Interval:       cfg.ExecutorInterval,
		Meter:          meter,
	}, logger)
	if err != nil {
		return fmt.Errorf("security command service: %w", err)
	}
	securityHandler, err := httpapi.NewSecurity(securityCommands, cfg.StepUpMaxAge)
	if err != nil {
		return fmt.Errorf("security command handler: %w", err)
	}
	meHandler, err := httpapi.NewMe(securityCommands, cfg.StepUpMaxAge)
	if err != nil {
		return fmt.Errorf("self-service handler: %w", err)
	}
	// A person's own notification addresses, each proven with a code sealed under the same key ring
	// as every other handle, for its lifetime (TDD-identity-control-008 1.2.0).
	addresses, err := securitynotify.NewAddresses(pool, refs, cfg.SecurityRefTTL)
	if err != nil {
		return fmt.Errorf("notification addresses: %w", err)
	}
	meHandler.UseAddresses(addresses)

	// The key source performs no fetch here. A cold replica loads the key set on its first
	// verification, and NewJWKS deliberately touches no network so the composition root decides
	// when that happens rather than the linker.
	keys, err := verify.NewJWKS(verify.JWKSConfig{URL: cfg.JWKSURL})
	if err != nil {
		return fmt.Errorf("jwks source: %w", err)
	}

	// The provider authority projection's intake (TDD-identity-control-006). It verifies its own
	// caller, Organization Control's workload, with the same issuer, audience and keys and a claim
	// rule that admits that workload alone. Unconfigured, the intake answers 503.
	// The kernel event record (TDD-identity-control-007): read with the registration credential, which
	// already holds view-events, the one role both of the kernel's event stores need.
	kernelEvents, err := kernelevents.NewSweeper(pool, registry, keycloak.Realm(cfg.KeycloakRealm),
		cfg.KernelEventInterval, logger)
	if err != nil {
		return fmt.Errorf("kernel event sweep: %w", err)
	}
	// Each kernel event recorded for the first time that ADR-IAM-007 notifies requests its notification
	// in the same transaction (TDD-identity-control-008).
	requester := securitynotify.NewRequester(logger)
	kernelEvents.OnRecorded(requester.FromKernelEvent)
	// The security commands request their own notifications in the transaction that records them
	// applied: a provider's restore, the last step of assisted recovery (TDD-identity-control-008
	// 1.3.0), and an authenticator removed by the person or a provider, told as who acted (1.4.0).
	realm := keycloak.Realm(cfg.KeycloakRealm)
	securityCommands.OnApplied(func(ctx context.Context, tx db.Tx, op securitystate.Applied) error {
		switch {
		case op.Type == securitystate.TypeRestore && !op.Self:
			return requester.FromRestore(ctx, tx, op.OperationID, op.Subject)
		case (op.Type == securitystate.TypeRevoke || op.Type == securitystate.TypeAuthenticatorRemove) &&
			op.CredentialID != "":
			return requester.FromRemoval(ctx, tx, realm, op.Subject, op.CredentialID, op.CredentialType, op.Self)
		}
		return nil
	})

	routesConfig := httpapi.RoutesConfig{
		KernelEvents:  kernelEvents,
		Principals:    principals,
		Registrations: registrations,
		Workloads:     workloadHandler,
		Investigation: investigationHandler,
		Security:      securityHandler,
		Me:            meHandler,
		Assurance:     httpapi.AssurancePolicy{Report: cfg.ReportAssurance, Logger: logger},
		Database:      pool,
		Telemetry:     telemetry,
	}
	projection, err := providerauthority.New(pool)
	if err != nil {
		return fmt.Errorf("provider authority projection: %w", err)
	}
	desired, err := tenantcontext.NewDesired(pool)
	if err != nil {
		return fmt.Errorf("tenant context intake: %w", err)
	}
	routesConfig.TenantContext = desired
	if !cfg.DeliveryPrincipal.IsNil() {
		deliveryVerifier, err := verify.New(verify.Config{
			Issuer: cfg.TokenIssuer, Audience: cfg.TokenAudience, Keys: keys,
			Requirement:            httpapi.DeliveryRequirement(cfg.DeliveryPrincipal),
			MaxSkew:                cfg.TokenMaxSkew,
			RequireAccessTokenType: cfg.EnforceAccessTokenType,
		})
		if err != nil {
			return fmt.Errorf("delivery verifier: %w", err)
		}
		router, err := delivery.NewRouter(
			delivery.Route{Types: providerauthority.EventTypes, Applier: projection},
			delivery.Route{Types: tenantcontext.EventTypes, Applier: desired})
		if err != nil {
			return fmt.Errorf("delivery routes: %w", err)
		}
		routesConfig.Deliveries, routesConfig.DeliveryVerifier = router, deliveryVerifier
		logger.Info("the delivery intake admits Organization Control's workload",
			slog.String("principal_id", cfg.DeliveryPrincipal.String()))
	} else {
		logger.Warn("IDENTITY_DELIVERY_PRINCIPAL_ID is unset; the provider authority intake accepts no delivery")
	}

	// The projection's freshness, read from Organization Control's frontier as this service's
	// workload (TDD-identity-control-006 §Freshness). Unconfigured, nothing is read and the
	// projection is never fresh, so no activation is honored.
	var (
		freshness *providerauthority.Freshness
		frontier  *organization.Client
	)
	if cfg.Organization.BaseURL != "" {
		if freshness, err = providerauthority.NewFreshness(cfg.ProviderFreshness); err != nil {
			return fmt.Errorf("provider authority freshness: %w", err)
		}
		if frontier, err = organization.NewWorkload(organizationWorkload(cfg.Organization)); err != nil {
			return err
		}
	} else {
		logger.Warn("IDENTITY_ORGANIZATION_BASE_URL is unset; the provider projection is never fresh and no activation is honored")
	}

	// The provider decision reads the projection and the held freshness, never the network. A
	// typed nil would read as a configured freshness, so an unconfigured one stays a nil interface.
	var held providerauthority.FreshnessReader
	if freshness != nil {
		held = freshness
	}
	providers, err := providerauthority.NewDecider(pool, held)
	if err != nil {
		return fmt.Errorf("provider decision: %w", err)
	}
	// Each projected emergency grant's last use, reported on its route (ADR-ORG-002 §5.2).
	routesConfig.EmergencyGrants = providers

	surface, err := httpapi.Routes(routesConfig)
	if err != nil {
		return fmt.Errorf("routes: %w", err)
	}

	// The claim rule is this service's, because STD-IAM-002 §3.5 states it in terms of a claim
	// foundation-platform is forbidden from naming. The verifier refuses to build without one.
	verifier, err := verify.New(verify.Config{
		Issuer:                 cfg.TokenIssuer,
		Audience:               cfg.TokenAudience,
		Keys:                   keys,
		Requirement:            httpapi.Requirement(),
		MaxSkew:                cfg.TokenMaxSkew,
		RequireAccessTokenType: cfg.EnforceAccessTokenType,
	})
	if err != nil {
		return fmt.Errorf("token verifier: %w", err)
	}

	var tokens httpapi.TokenVerifier = verifier
	if cfg.ReportAssurance {
		logger.Warn("IDENTITY_ASSURANCE=report: provider routes serve tokens below aal2 and log them; enforce once the kernel maps the levels")
	}
	if !cfg.EnforceAccessTokenType {
		tokens = httpapi.ReportTokenType(verifier, logger)
	}
	// The assurance floor reads the same provider decision: a provider keeps a second factor.
	securityCommands.UseProviders(providerHolder{providers})
	authentication, err := httpapi.Authenticate(tokens, providers, logger)
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
	go securityCommands.Run(ctx)
	// The Tenant context converger makes the kernel's Organizations match the desired state the
	// delivery intake keeps (TDD-identity-control-002 2.0.0), through the Principal credential.
	converger, err := tenantcontext.NewConverger(pool, kernel, tenantcontext.ConvergerConfig{
		Realm:          keycloak.Realm(cfg.KeycloakRealm),
		Interval:       cfg.ProjectionInterval,
		AttemptTimeout: cfg.ProjectionAttemptTimeout,
		Lease:          cfg.ProjectionLease,
		MaxAttempts:    cfg.ProjectionMaxAttempts,
	}, logger, meter)
	if err != nil {
		return fmt.Errorf("tenant context converger: %w", err)
	}
	go converger.Run(ctx)
	// The reconciliation sweep reads Organization's snapshot as this service's workload, when one is
	// configured, and sweeps the kernel either way (TDD-identity-control-002 2.1.0).
	var snapshotSource tenantcontext.SnapshotSource
	if frontier != nil {
		snapshotSource = frontier
	}
	tenantSweep, err := tenantcontext.NewReconciler(desired, pool, kernel, keycloak.Realm(cfg.KeycloakRealm),
		snapshotSource, logger)
	if err != nil {
		return fmt.Errorf("tenant context reconciler: %w", err)
	}
	go scheduleTenantSweeps(ctx, tenantSweep, cfg.ProjectionReconcileInterval, logger)
	go scheduleKernelEventSweeps(ctx, kernelEvents, cfg.KernelEventInterval, logger)
	// The dispatcher hands requested notifications to the delivery adapter. With none configured the
	// requests are recorded and wait for the Notification Platform (TDD-identity-control-008).
	if cfg.NotificationDelivery == "standin" {
		dispatcher, err := securitynotify.NewDispatcher(pool, securitynotify.StandIn{Logger: logger}, logger)
		if err != nil {
			return fmt.Errorf("security notification dispatcher: %w", err)
		}
		dispatcher.WithSealer(refs)
		logger.Warn("IDENTITY_NOTIFICATION_DELIVERY=standin: account security notifications are accepted and not delivered")
		go scheduleNotificationDispatch(ctx, dispatcher, logger)
	}
	go scheduleSweeps(ctx, provisioner, registrar, workloads, reconciler, providers, cfg.RegistrationReconcileInterval, logger)
	if freshness != nil {
		go freshness.Poll(ctx, projection, frontier, providerauthority.PollInterval, logger)
	}

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
	workloads *workload.Service,
	reconciler *reconcile.Reconciler, providers *providerauthority.Decider, interval time.Duration, logger *slog.Logger) {
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
		// Pending workloads after pending registrations: a workload whose client creation was lost
		// finds its registration active, and binds its identity to the client's service account.
		if finished, err := workloads.RecoverPending(ctx); err != nil {
			logger.Error("pending workload recovery failed", slog.String("error", err.Error()))
		} else if finished > 0 {
			logger.Info("pending workloads recovered", slog.Int("finished", finished))
		}
		// Client keys whose rotation overlap or lifetime ended are removed before the sweep reads the
		// clients, so a retiring key is gone within one interval of its overlap ending.
		if removed, err := registrar.ExpireKeys(ctx); err != nil {
			logger.Error("client key expiry failed", slog.String("error", err.Error()))
		} else if removed > 0 {
			logger.Info("expired client keys removed", slog.Int("keys", removed))
		}
		// The key expiry warning, before the sweep: a log alert can fire on it without a metrics
		// pipeline (TDD-identity-control-003 §Key Expiry Warnings).
		if expiring, err := registrar.ExpiringKeys(ctx); err != nil {
			logger.Error("client key expiry warning could not be read", slog.String("error", err.Error()))
		} else {
			for _, key := range expiring.Registrations {
				level, message := slog.LevelWarn, "a client key expires within the warning threshold and no successor is registered"
				switch key.Severity {
				case registration.SeverityCritical:
					level, message = slog.LevelError, "a client key expires within the critical threshold and no successor is registered"
				case registration.SeverityNoKey:
					level, message = slog.LevelError, "a keyed client holds no active key and cannot authenticate"
				}
				attrs := []slog.Attr{slog.String("client_key", key.ClientKey), slog.String("severity", key.Severity)}
				if key.ExpiresAt != nil {
					attrs = append(attrs, slog.String("kid", key.KID), slog.Time("expires_at", *key.ExpiresAt))
				}
				logger.LogAttrs(ctx, level, message, attrs...)
			}
		}
		// Changes waiting for a provider's approval (TDD-identity-control-003 §Operational Notes):
		// a warning past three days, an error past seven, so an approval backlog alerts.
		if waiting, err := registrar.OpenChanges(ctx); err != nil {
			logger.Error("waiting registration changes could not be read", slog.String("error", err.Error()))
		} else {
			for _, change := range waiting {
				age := time.Since(change.ProposedAt)
				level := slog.LevelWarn
				switch {
				case age > registration.ChangeCriticalAge:
					level = slog.LevelError
				case age <= registration.ChangeWarningAge:
					continue
				}
				logger.LogAttrs(ctx, level, "a registration change has waited past its approval threshold",
					slog.String("client_key", change.ClientKey), slog.String("change_id", change.ID.String()),
					slog.Time("proposed_at", change.ProposedAt))
			}
		}
		// An emergency grant unused for 90 days is overdue for validation (ADR-ORG-002 §5.2). It is
		// still in force; the warning asks its holder to use it on purpose.
		if report, err := providers.EmergencyValidation(ctx, time.Now()); err != nil {
			logger.Error("the emergency grant validation report could not be read", slog.String("error", err.Error()))
		} else {
			for _, grant := range report {
				if !grant.Overdue {
					continue
				}
				attrs := []slog.Attr{slog.String("grant_id", grant.GrantID.String()),
					slog.String("principal_id", grant.PrincipalID.String()), slog.Time("due_at", grant.DueAt)}
				if grant.LastUsedAt != nil {
					attrs = append(attrs, slog.Time("last_used_at", *grant.LastUsedAt))
				}
				logger.LogAttrs(ctx, slog.LevelWarn, "an emergency provider grant has not been used in 90 days; its "+
					"holder validates it by signing in and making a request with a reason that says it is a drill", attrs...)
			}
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

// organizationWorkload is the configured workload client, in the client's terms.
func organizationWorkload(cfg config.Organization) organization.Workload {
	return organization.Workload{
		BaseURL: cfg.BaseURL, ClientID: cfg.WorkloadClientID, KeyFile: cfg.WorkloadKeyFile,
		TokenURL: cfg.WorkloadTokenURL, Audience: cfg.WorkloadAudience,
	}
}

// providerHolder adapts the provider decision to the assurance floor's question: does the Principal
// hold provider authority, or an activation the projection's freshness held back?
type providerHolder struct{ decider *providerauthority.Decider }

func (p providerHolder) Holds(ctx context.Context, principal id.UUID) (bool, bool, error) {
	decision, err := p.decider.Decide(ctx, principal)
	return decision.Provider, decision.Stale, err
}

// scheduleTenantSweeps runs the Tenant context reconciliation every interval, the first at once.
func scheduleTenantSweeps(ctx context.Context, sweep *tenantcontext.Reconciler, interval time.Duration,
	logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := sweep.Sweep(ctx); err != nil && ctx.Err() == nil {
			logger.Error("tenant context sweep failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// scheduleNotificationDispatch hands due account security notifications to the adapter every
// interval, the first at once (TDD-identity-control-008 §Dispatch).
func scheduleNotificationDispatch(ctx context.Context, dispatcher *securitynotify.Dispatcher, logger *slog.Logger) {
	ticker := time.NewTicker(securitynotify.DispatchInterval)
	defer ticker.Stop()
	for {
		if _, err := dispatcher.Dispatch(ctx); err != nil && ctx.Err() == nil {
			logger.Error("security notification dispatch failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// scheduleKernelEventSweeps sweeps the kernel's event store into the record every interval, the first
// at once (TDD-identity-control-007). A failed sweep is logged; the next reads the same window.
func scheduleKernelEventSweeps(ctx context.Context, sweeper *kernelevents.Sweeper, interval time.Duration,
	logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := sweeper.Sweep(ctx); err != nil && ctx.Err() == nil {
			logger.Error("kernel event sweep failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
