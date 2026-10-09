package httpapi

// The Tenant context projection's operational read (TDD-identity-control-002 2.2.0 §The Report an
// Operator Posts): the positioned report an operator posts to organization-control's reconcile route.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	httpapi "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/tenantcontext"
)

// TenantReporter reads the report.
type TenantReporter interface {
	Report(ctx context.Context) (tenantcontext.Report, error)
}

// tenantReport handles GET /v1/projections/tenant-context/report.
func tenantReport(reporter TenantReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := callerPrincipal(r); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		report, err := reporter.Report(r.Context())
		if err != nil {
			httpapi.Problem(w, r, httpapi.Internal, "The Tenant context report could not be read")
			return
		}
		writeJSON(w, http.StatusOK, report)
	}
}

// TenantOperator is the projection's operator surface (TDD-identity-control-002 2.5.0 §Operator
// Routes): the Tenants not converged, the findings, a re-drive of one Tenant, and a sweep now.
type TenantOperator interface {
	Unconverged(ctx context.Context) ([]tenantcontext.Unconverged, error)
	Findings(ctx context.Context, class string, limit int) ([]tenantcontext.Finding, error)
	Redrive(ctx context.Context, tenant, by id.UUID, reason string) error
	Sweep(ctx context.Context) (tenantcontext.SweepResult, error)
}

// tenantUnconverged handles GET /v1/projections/tenant-context:unconverged.
func tenantUnconverged(operator TenantOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := callerPrincipal(r); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		tenants, err := operator.Unconverged(r.Context())
		if err != nil {
			httpapi.Problem(w, r, httpapi.Internal, "The unconverged Tenants could not be read")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
	}
}

// tenantFindings handles GET /v1/projections/tenant-context:findings[?class=…][&limit=…].
func tenantFindings(operator TenantOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := callerPrincipal(r); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		limit := 0
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 500 {
				httpapi.Problem(w, r, httpapi.ValidationFailed, "limit is a whole number from 1 to 500")
				return
			}
			limit = parsed
		}
		findings, err := operator.Findings(r.Context(), r.URL.Query().Get("class"), limit)
		switch {
		case errors.Is(err, tenantcontext.ErrUnknownClass):
			httpapi.Problem(w, r, httpapi.ValidationFailed,
				"class is one of missing_member, extra_member, organization_state, unknown_organization")
		case err != nil:
			httpapi.Problem(w, r, httpapi.Internal, "The projection findings could not be read")
		default:
			writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
		}
	}
}

// tenantAction handles POST /v1/projections/tenant-context/tenants/{tenant_id}:redrive, with a reason.
func tenantAction(operator TenantOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := callerPrincipal(r)
		if !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		raw, action, _ := strings.Cut(r.PathValue("tenant_action"), ":")
		if action != "redrive" {
			httpapi.Problem(w, r, httpapi.NotFound, "No such Tenant action")
			return
		}
		tenant, err := id.Parse(raw)
		if err != nil {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "tenant_id is not a valid identifier")
			return
		}
		reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
		if reason == "" {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "A re-drive requires an X-Administrative-Reason header")
			return
		}
		switch err := operator.Redrive(r.Context(), tenant, principal, reason); {
		case errors.Is(err, tenantcontext.ErrUnknownTenant):
			httpapi.Problem(w, r, httpapi.NotFound, "The desired state holds no such Tenant")
		case err != nil:
			httpapi.Problem(w, r, httpapi.Internal, "The Tenant was not marked; retry")
		default:
			writeJSON(w, http.StatusAccepted, map[string]any{"tenant_id": tenant, "state": "pending"})
		}
	}
}

// tenantSweep handles POST /v1/projections/tenant-context:sweep: the scheduled sweep, now.
func tenantSweep(operator TenantOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := callerPrincipal(r); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		result, err := operator.Sweep(r.Context())
		if err != nil {
			httpapi.Problem(w, r, httpapi.DependencyUnavailable,
				"The sweep did not finish; its run is recorded unresolved. Retry")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"run_id": result.RunID, "outcome": result.Outcome, "mark": result.Mark,
			"snapshot_rows": result.SnapshotRows, "snapshot_read": result.SnapshotErr == nil,
			"unknown_organizations": result.Unknown, "tenants_marked": result.Marked})
	}
}
