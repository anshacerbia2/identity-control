package httpapi_test

import (
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/verify"

	"github.com/anshacerbia2/identity-control/internal/httpapi"
)

// The intake's claim rule, through a real verifier and real signed tokens: Organization Control's
// workload and nothing else.
func TestTheDeliveryRequirementNamesOneWorkload(t *testing.T) {
	organization := id.MustParse("01a0fc67-3cc0-7011-95cb-e160cc46b541")
	verifier := func(principal id.UUID) *verify.Verifier {
		v, err := verify.New(verify.Config{
			Issuer: authIssuer, Audience: authAudience,
			Keys:        verify.StaticKeys{authKeyID: &signingKeyForAuth(t).PublicKey},
			Requirement: httpapi.DeliveryRequirement(principal),
			Now:         func() time.Time { return authNow },
		})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for name, c := range map[string]struct {
		claims map[string]any
		ok     bool
	}{
		"Organization Control's workload": {map[string]any{"principal_id": organization.String(), "subject_type": "workload"}, true},
		"another workload":                {map[string]any{"principal_id": "01a0fc67-3cc0-7011-95cb-e160cc46b542", "subject_type": "workload"}, false},
		"a person with that id":           {map[string]any{"principal_id": organization.String(), "subject_type": "human"}, false},
		"a provider scope": {map[string]any{"principal_id": organization.String(), "subject_type": "workload",
			"provider_scope": "provider:identity-control"}, false},
		"no principal_id": {map[string]any{"subject_type": "workload"}, false},
	} {
		_, err := verifier(organization).Verify(token(t, c.claims))
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := verifier(id.UUID{}).Verify(token(t, map[string]any{
		"principal_id": organization.String(), "subject_type": "workload"})); err == nil {
		t.Error("an unconfigured requirement admitted a token")
	}
}
