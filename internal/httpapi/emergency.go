package httpapi

// The validation report of the projected emergency grants (ADR-ORG-002 §5.2,
// TDD-identity-control-006 §Emergency Grant Validation).

import (
	"context"
	"net/http"
	"time"

	httpapi "github.com/anshacerbia2/foundation-platform/httpapi"

	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

// EmergencyValidator reads each projected emergency grant's last use: *providerauthority.Decider.
type EmergencyValidator interface {
	EmergencyValidation(ctx context.Context, now time.Time) ([]providerauthority.EmergencyValidation, error)
}

// emergencyValidation handles GET /v1/provider-grants:emergency-validation: every active emergency
// grant of provider:identity-control with its last use, the oldest due first.
func emergencyValidation(validator EmergencyValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := callerPrincipal(r); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		report, err := validator.EmergencyValidation(r.Context(), time.Now())
		if err != nil {
			httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The emergency grants could not be read")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"scope":                  providerauthority.Scope,
			"validation_period_days": int(providerauthority.ValidationPeriod.Hours() / 24),
			"grants":                 report,
		})
	}
}
