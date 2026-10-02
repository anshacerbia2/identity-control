package httpapi

// The acceptance API Organization Control's dispatcher posts provider grant events to
// (TDD-identity-control-006 §API, ADR-GLB-018 §5.4). It admits Organization Control's workload alone,
// and it is mounted apart from every caller route, behind its own verification.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/anshacerbia2/foundation-platform/event"
	fhttp "github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/outbox"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

// maxDeliveryBody bounds one delivery. An event carries one grant's state, a few hundred bytes.
const maxDeliveryBody = 64 << 10

// DeliveryRequirement admits a token naming Organization Control's workload and no one else: a
// workload, with exactly the configured principal_id. Every caller route refuses a workload token
// that is not this service's own business, so the intake's caller is unambiguous.
func DeliveryRequirement(organization id.UUID) verify.ClaimRequirement {
	return verify.RequirementFunc(func(claims verify.Claims) error {
		if organization.IsNil() {
			return errors.New("no delivering workload is configured")
		}
		principal, ok := claims.String(PrincipalIDClaim)
		if !ok {
			return fmt.Errorf("the %s claim is absent", PrincipalIDClaim)
		}
		if subjectType, _ := claims.String(SubjectTypeClaim); subjectType != "workload" {
			return fmt.Errorf("the %s claim is not workload", SubjectTypeClaim)
		}
		if principal != organization.String() {
			return errors.New("the token names a workload other than Organization Control's")
		}
		if claims.Has(TenantIDClaim) || claims.Has(ProviderScopeClaim) {
			return errors.New("a delivery token carries no tenant or provider scope")
		}
		return nil
	})
}

// Applier applies one delivered event: the provider authority projection.
type Applier interface {
	Apply(ctx context.Context, envelope event.Envelope) (providerauthority.Outcome, error)
}

// deliveryIntake verifies the delivering workload's token, decodes the envelope, and applies it.
//
// The application receipt marker is set only where the assertion "this consumer holds this event's
// effect" is true (ADR-GLB-016 §5.4): applied, or already applied. A superseded event was discarded,
// so it carries none, and a dead letter for it closes as SUPERSEDED on the newer event's receipt.
func deliveryIntake(verifier TokenVerifier, applier Applier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verifier == nil || applier == nil {
			// Unconfigured: no provider event is accepted, and the dispatcher retries rather than
			// dead-lettering, because the event is not at fault.
			fhttp.Problem(w, r, fhttp.DependencyUnavailable, "The delivery intake is not configured")
			return
		}
		token, ok := bearerToken(r)
		if !ok {
			fhttp.Problem(w, r, fhttp.AuthenticationRequired, "A bearer token is required")
			return
		}
		if _, err := verifier.Verify(token); err != nil {
			fhttp.Problem(w, r, fhttp.AuthenticationRequired, "The bearer token is not valid for this resource")
			return
		}

		defer func() { _ = r.Body.Close() }()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDeliveryBody))
		var envelope event.Envelope
		if err := decoder.Decode(&envelope); err != nil {
			fhttp.Problem(w, r, fhttp.ValidationFailed, "The delivery is not a CloudEvents envelope")
			return
		}

		outcome, err := applier.Apply(r.Context(), envelope)
		switch {
		case errors.Is(err, providerauthority.ErrUnknownType), errors.Is(err, providerauthority.ErrMalformed):
			// Poison: redelivering an event this projection cannot apply fails identically forever.
			fhttp.Problem(w, r, fhttp.ValidationFailed, err.Error())
			return
		case err != nil:
			fhttp.Problem(w, r, fhttp.DependencyUnavailable, "The delivery could not be applied")
			return
		}
		if outcome.Applied() {
			w.Header().Set(outbox.ApplicationReceiptHeader, outbox.ApplicationReceiptApplied)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]bool{
			"duplicate": outcome.Duplicate, "superseded": outcome.Superseded,
		})
	})
}
