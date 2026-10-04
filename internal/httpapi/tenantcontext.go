package httpapi

// The Tenant context projection's operational read (TDD-identity-control-002 2.2.0 §The Report an
// Operator Posts): the positioned report an operator posts to organization-control's reconcile route.

import (
	"context"
	"net/http"

	httpapi "github.com/anshacerbia2/foundation-platform/httpapi"

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
