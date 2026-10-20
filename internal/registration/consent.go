package registration

// Consent follows the audience class (STD-IAM-002 1.9.0 §3.6, ADR-IAM-003 §5.11 as amended
// 2026-10-20; TDD-identity-control-003 1.39.0 §Consent).
//
// An external registration requires consent, and every scope it releases is shown on the consent
// screen; an internal, privileged or workload one never does, because its recorded registration is the
// administrative consent. OpenID Connect requires an authorization decision "before releasing
// information to the Relying Party", given interactively or "via previous administrative consent"
// (OpenID Connect Core §3.1.2.4). It is derived, never a field of the registration: Auth0's
// "Third-party applications always require consent and cannot skip the consent dialog" leaves nothing
// for a registrant to choose.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/db"
)

// ConsentRequired is whether a client of the profile and class asks a person's consent at sign-in:
// an external client a person signs in to, and nothing else. A resource is an audience nobody signs
// in to, and a workload signs in as itself.
func ConsentRequired(profile, audienceClass string) bool {
	return audienceClass == "external" && (profile == ProfilePublic || profile == ProfileConfidential)
}

// MarshalJSON adds the derived consent_required to a registration as the API reports it, so a console
// says whether a client asks consent without deriving it again.
func (r Registration) MarshalJSON() ([]byte, error) {
	type plain Registration
	return json.Marshal(struct {
		plain
		ConsentRequired bool `json:"consent_required"`
	}{plain(r), ConsentRequired(r.Profile, r.AudienceClass)})
}

var lifetimeStatement = `SELECT ` + LifespanSQL("r.realm", "r.audience") + `
FROM identity.client_registration r
WHERE r.realm = $1 AND r.client_key = $2 AND r.state <> 'retired' AND r.profile <> 'resource'`

// AccessTokenLifetime is the access token lifetime a client's registration bounds it to, in
// seconds, and whether a registration describes the client: what a person withdrawing a consent is
// told an already issued token can still live (TDD-identity-control-005 §Session and Consent
// Semantics).
func (s *Service) AccessTokenLifetime(ctx context.Context, clientKey string) (int, bool, error) {
	var (
		seconds    int
		registered bool
	)
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, lifetimeStatement, string(s.cfg.Realm), clientKey)
		if err != nil {
			return fmt.Errorf("registration: read %s's lifetime: %w", clientKey, err)
		}
		defer rows.Close()
		if rows.Next() {
			registered = true
			return rows.Scan(&seconds)
		}
		return rows.Err()
	})
	return seconds, registered, err
}
