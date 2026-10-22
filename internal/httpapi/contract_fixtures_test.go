package httpapi_test

import (
	"encoding/json"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

// The route tests' stubs stand in for services that return complete records. A stub that returned a
// zero record would answer what no service does (an empty profile, a null list), and the contract test
// would flag the stub, not the handler. These fill what a test left unset, to values a service
// records, and leave what the test set.

var fixtureTime = time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)

func fill[T comparable](value *T, with T) {
	var zero T
	if *value == zero {
		*value = with
	}
}

// aRegistration completes a registration the way the service records one.
func aRegistration(r registration.Registration) registration.Registration {
	fill(&r.Realm, "scnehaux")
	fill(&r.ClientKey, "web")
	fill(&r.Profile, "public")
	fill(&r.AudienceClass, "internal")
	fill(&r.ApplicationAuthority, "authority")
	fill(&r.ApplicationRef, "app")
	fill(&r.SigningAlgorithm, "PS256")
	fill(&r.State, "active")
	fill(&r.Version, 1)
	fill(&r.CreatedAt, fixtureTime)
	if r.Audience == nil {
		r.Audience = []string{}
	}
	if r.RedirectURIs == nil {
		r.RedirectURIs = []string{}
	}
	return r
}

func aRegistrationPage(page registration.Page) registration.Page {
	for i := range page.Registrations {
		page.Registrations[i] = aRegistration(page.Registrations[i])
	}
	return page
}

// aChange completes a change of the kind its fields name.
func aChange(c registration.Change) registration.Change {
	if c.Kind == "" {
		switch {
		case c.Audience != nil:
			c.Kind = "audience"
		case c.LifetimeClass != nil:
			c.Kind = "lifetime_class"
		case c.BackChannelLogoutURI != nil:
			c.Kind = "backchannel_logout_uri"
		default:
			c.Kind = "redirect_uris"
		}
	}
	fill(&c.ClientKey, "web")
	fill(&c.BaseVersion, 1)
	fill(&c.ProposedAt, fixtureTime)
	fill(&c.State, "proposed")
	return c
}

var fixtureJWK = json.RawMessage(`{"kty":"RSA","kid":"k1","use":"sig","alg":"PS256","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs9-QtihUrBjCuM7p6rQq5Q6SyZbAYAJ9xlEIX_Cpz5xz4g_m5eh6kVzQm0OSZqq1JMr0hpCzRALL5j8qMgCp7yuy2OvaGHCztr7VnLzaKLBfAPoEapoeVRn6H0F4EiLw8rVGWvDWf1jXjnhN8_VzTcZoiu6HDRxcrbTHgLxCmw","e":"AQAB"}`)

func aKey(k registration.Key) registration.Key {
	fill(&k.KID, "k1")
	fill(&k.Thumbprint, "thumbprint")
	if k.PublicJWK == nil {
		k.PublicJWK = fixtureJWK
	}
	fill(&k.State, registration.KeyActive)
	fill(&k.RegisteredAt, fixtureTime)
	fill(&k.ExpiresAt, fixtureTime.Add(90*24*time.Hour))
	return k
}

func aKeySet(keys []registration.Key) []registration.Key {
	for i := range keys {
		keys[i] = aKey(keys[i])
	}
	return keys
}

func aRegistrationRequest(r registration.RegistrationRequest) registration.RegistrationRequest {
	fill(&r.ClientKey, "web")
	if r.Request == nil {
		r.Request = json.RawMessage(`{"client_key":"web"}`)
	}
	if r.Owners == nil {
		r.Owners = []id.UUID{}
	}
	fill(&r.ProposedAt, fixtureTime)
	fill(&r.State, "proposed")
	return r
}
