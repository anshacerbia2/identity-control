package registration

// Adoption: a client created before this service existed, by a bootstrap script, comes under
// registration by an explicit, planned, recorded command (ADR-IAM-001 §5.12,
// TDD-identity-control-003 §Adoption). Ordinary registration refuses such a client, because
// adopting on a matching name would take over a client someone else configured.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The field classes an adoption compares, and what each allows.
const (
	PolicyRepair = "repair"
	PolicyBlock  = "block"

	ClassTokenLifespan = "token_lifespan"
	ClassAudienceScope = "audience_scope"
	ClassEnabled       = "enabled"
	ClassRedirectURIs  = "redirect_uris"
	ClassClientKeys    = "client_keys"
	ClassTokenFormat   = "token_format"
)

// convergeable are the repairable classes an adoption may converge when the request names them.
var convergeable = []string{ClassTokenLifespan, ClassAudienceScope, ClassEnabled, ClassTokenFormat}

var (
	// ErrNotAdoptable is an adoption the plan refuses: a blocking class differs, or a repairable one
	// differs and the request does not name it. The result carries the plan.
	ErrNotAdoptable = errors.New("registration: the client does not match the declaration")

	// ErrNoClient is an adoption naming a client_key no Keycloak client holds.
	ErrNoClient = errors.New("registration: no Keycloak client holds that client_key")
)

// AdoptRequest is one adoption: the registration it declares, the keys the client already holds,
// why, and whether to plan only.
type AdoptRequest struct {
	Request

	// PublicKeys are the one or two public keys the client authenticates with now, the first the
	// active one. Two when the client is adopted in the middle of a rotation.
	PublicKeys []json.RawMessage

	Reason string

	// DryRun plans only.
	DryRun bool

	// Converge names the repairable field classes the caller accepts converging.
	Converge []string
}

// Difference is one field class of the plan.
type Difference struct {
	FieldClass string `json:"field_class"`
	Policy     string `json:"policy"`
	Desired    any    `json:"desired"`
	Observed   any    `json:"observed"`
	Differs    bool   `json:"differs"`
}

// Plan is how the client differs from the declaration, and whether it can be adopted as asked.
type Plan struct {
	ClientKey   string       `json:"client_key"`
	Adoptable   bool         `json:"adoptable"`
	Refusal     string       `json:"refusal,omitempty"`
	Differences []Difference `json:"differences"`

	// The declaration's profile and audience class, which the scope sets are derived from.
	profile, audienceClass string
}

// AdoptResult is the plan, and the registration when the client was adopted.
type AdoptResult struct {
	Plan         Plan          `json:"plan"`
	Registration *Registration `json:"registration,omitempty"`
}

// Adopt plans an adoption and, unless it is a dry run, performs it.
func (s *Service) Adopt(ctx context.Context, req AdoptRequest) (AdoptResult, error) {
	invalid := func(rule string) error { return fmt.Errorf("%w: %s", ErrInvalid, rule) }
	switch {
	case strings.TrimSpace(req.Reason) == "":
		return AdoptResult{}, invalid("an adoption requires a reason")
	case !req.DryRun && (strings.TrimSpace(req.CallerScope) == "" || strings.TrimSpace(req.IdempotencyKey) == ""):
		return AdoptResult{}, invalid("an adoption requires a caller and an Idempotency-Key")
	case req.Profile != ProfileConfidential:
		return AdoptResult{}, invalid("only a confidential client is adopted; a workload is created through its workload, and a public client or resource holds no key")
	case len(req.PublicKeys) == 0 || len(req.PublicKeys) > keycloak.MaxClientKeys:
		return AdoptResult{}, invalid(fmt.Sprintf("an adoption declares the 1 to %d public keys the client holds", keycloak.MaxClientKeys))
	case submitted(req.PublicKey):
		return AdoptResult{}, invalid("an adoption declares public_keys, not public_key")
	}
	for _, class := range req.Converge {
		if !slices.Contains(convergeable, class) {
			return AdoptResult{}, invalid("converge names only token_lifespan, audience_scope, enabled or token_format")
		}
	}
	if err := validate(req.Request); err != nil {
		return AdoptResult{}, err
	}
	keys := make([]PublicKey, 0, len(req.PublicKeys))
	for _, raw := range req.PublicKeys {
		key, err := parsePublicKey(raw)
		if err != nil {
			return AdoptResult{}, err
		}
		for _, other := range keys {
			if other.Thumbprint == key.Thumbprint {
				return AdoptResult{}, invalid("the public keys are one key")
			}
		}
		keys = append(keys, key)
	}
	declaredKeys := make([]keycloak.JWK, 0, len(keys))
	for _, key := range keys {
		declaredKeys = append(declaredKeys, key.JWK)
	}

	if !req.DryRun {
		// A completed adoption replays before the checks: its client_key is registered by then, and
		// the retry must answer what the first request answered.
		if replayed, ok, err := s.replayedAdoption(ctx, req); err != nil || ok {
			return replayed, err
		}
	}

	scopeName := managedScopes[req.AudienceClass]
	scopeID, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (string, error) {
		return s.kernel.ClientScopeID(ctx, s.cfg.Realm, scopeName)
	})
	if errors.Is(err, keycloak.ErrNotFound) {
		return AdoptResult{}, fmt.Errorf("%w: %s", ErrScopeUndeclared, scopeName)
	}
	if err != nil {
		return AdoptResult{}, err
	}

	lifespan, err := s.checkAdoptable(ctx, req.Request, keys)
	if err != nil {
		return AdoptResult{}, err
	}

	found, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) ([]keycloak.Client, error) {
		return s.kernel.FindClients(ctx, s.cfg.Realm, req.ClientKey)
	})
	if err != nil {
		return AdoptResult{}, err
	}
	if len(found) != 1 {
		return AdoptResult{}, ErrNoClient
	}
	client, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.Client, error) {
		return s.kernel.GetClient(ctx, s.cfg.Realm, found[0].ID)
	})
	if err != nil {
		return AdoptResult{}, err
	}
	scopes, err := LiveScopes(ctx, s.kernel, s.cfg.Realm, client.ID, s.cfg.CallTimeout)
	if err != nil {
		return AdoptResult{}, err
	}

	plan := planAdoption(req, client, scopes, scopeName, lifespan, declaredKeys)
	if req.DryRun {
		return AdoptResult{Plan: plan}, nil
	}
	if !plan.Adoptable {
		return AdoptResult{Plan: plan}, ErrNotAdoptable
	}

	// The named repairable differences converge before anything is recorded: left behind by a failed
	// commit, they are changes to a client that is still unmanaged, and the adoption retried finds
	// nothing left to converge.
	converged, err := s.converge(ctx, plan, client, scopeID, lifespan)
	if err != nil {
		return AdoptResult{Plan: plan}, err
	}

	var result AdoptResult
	requestDigest := adoptDigest(req)
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		claim, err := idempotency.Claim(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest)
		if err != nil {
			return err
		}
		if claim.State == idempotency.StateReplay {
			return json.Unmarshal(claim.Body, &result)
		}
		registration, err := s.insertAdopted(ctx, tx, req, client, keys, plan, converged)
		if err != nil {
			return err
		}
		result = AdoptResult{Plan: plan, Registration: &registration}
		body, err := json.Marshal(result)
		if err != nil {
			return err
		}
		return idempotency.Complete(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest, 201, body)
	})
	if err != nil {
		return AdoptResult{Plan: plan}, err
	}
	s.logger.WarnContext(ctx, "a client created outside this service was adopted",
		slog.String("client_key", req.ClientKey), slog.String("adopted_by", req.RegisteredBy.String()))
	return result, nil
}

func adoptDigest(req AdoptRequest) string {
	body, _ := json.Marshal(struct {
		AdoptRequest
		RegisteredBy string
	}{req, req.RegisteredBy.String()})
	return idempotency.Digest(body)
}

// errFreshClaim rolls back the claim replayedAdoption takes only to look.
var errFreshClaim = errors.New("registration: the adoption has not completed")

// replayedAdoption answers the stored result when this Idempotency-Key completed an adoption. A key
// never seen is claimed and rolled back, so the adoption itself claims it afresh.
func (s *Service) replayedAdoption(ctx context.Context, req AdoptRequest) (AdoptResult, bool, error) {
	var result AdoptResult
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		claim, err := idempotency.Claim(ctx, tx, req.CallerScope, req.IdempotencyKey, adoptDigest(req))
		if err != nil {
			return err
		}
		if claim.State != idempotency.StateReplay {
			return errFreshClaim
		}
		return json.Unmarshal(claim.Body, &result)
	})
	switch {
	case errors.Is(err, errFreshClaim):
		return AdoptResult{}, false, nil
	case err != nil:
		return AdoptResult{}, false, err
	}
	return result, true, nil
}

var adoptLifespanStatement = `SELECT ` + LifespanSQL("$1::text", "$2::text[]")

// checkAdoptable holds the declaration to what the Control Database knows: its client_key is not
// registered, its audience names registered resources only, and none of its keys is registered to
// any client. It returns the lifespan the declared audience derives.
func (s *Service) checkAdoptable(ctx context.Context, req Request, keys []PublicKey) (int, error) {
	var lifespan int
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var inUse int
		if err := tx.QueryRow(ctx, keyInUseStatement, string(s.cfg.Realm), req.ClientKey).Scan(&inUse); err != nil {
			return fmt.Errorf("registration: check client_key: %w", err)
		}
		if inUse > 0 {
			return ErrKeyTaken
		}
		audience := append([]string{}, req.Audience...)
		var unregistered int
		if err := tx.QueryRow(ctx, unregisteredAudienceStatement, string(s.cfg.Realm), audience).Scan(&unregistered); err != nil {
			return fmt.Errorf("registration: check audience: %w", err)
		}
		if unregistered > 0 {
			return fmt.Errorf("%w: every audience entry must be an active resource registration", ErrInvalid)
		}
		for _, key := range keys {
			owner, _, err := thumbprintOwner(ctx, tx, key.Thumbprint)
			if err != nil {
				return err
			}
			if !owner.IsNil() {
				return ErrKeyInUse
			}
		}
		return tx.QueryRow(ctx, adoptLifespanStatement, string(s.cfg.Realm), audience).Scan(&lifespan)
	})
	return lifespan, err
}

// planAdoption compares the client with the declaration, per field class.
func planAdoption(req AdoptRequest, client keycloak.Client, scopes ScopeSets, scopeName string, lifespan int,
	keys []keycloak.JWK) Plan {
	desiredScopes, _ := DesiredScopes(req.Profile, req.AudienceClass)
	sortedSets := func(sets ScopeSets) ScopeSets {
		return ScopeSets{Default: sortedStrings(sets.Default), Optional: sortedStrings(sets.Optional)}
	}
	kids := func(keys []keycloak.JWK) []string {
		out := []string{}
		for _, key := range keys {
			out = append(out, key.KID)
		}
		slices.Sort(out)
		return out
	}
	desiredURIs, observedURIs := sortedStrings(req.RedirectURIs), sortedStrings(client.RedirectURIs)
	plan := Plan{ClientKey: req.ClientKey, profile: req.Profile, audienceClass: req.AudienceClass, Differences: []Difference{
		{FieldClass: ClassTokenLifespan, Policy: PolicyRepair, Desired: lifespan, Observed: client.AccessTokenLifespan,
			Differs: client.AccessTokenLifespan != lifespan},
		{FieldClass: ClassAudienceScope, Policy: PolicyRepair, Desired: sortedSets(desiredScopes),
			Observed: sortedSets(scopes), Differs: !SameScopes(scopes, desiredScopes)},
		{FieldClass: ClassTokenFormat, Policy: PolicyRepair,
			Desired:  map[string]any{"at_jwt": true, "client_id": req.ClientKey},
			Observed: map[string]any{"at_jwt": client.RFC9068, "client_id": client.ClientIDClaim},
			Differs:  !client.RFC9068 || client.ClientIDClaim != req.ClientKey},
		{FieldClass: ClassEnabled, Policy: PolicyRepair, Desired: true, Observed: client.Enabled, Differs: !client.Enabled},
		{FieldClass: ClassRedirectURIs, Policy: PolicyBlock, Desired: desiredURIs, Observed: observedURIs,
			Differs: !slices.Equal(desiredURIs, observedURIs)},
		{FieldClass: ClassClientKeys, Policy: PolicyBlock,
			Desired: map[string]any{"authenticator": "client-jwt", "held_jwks": true, "kids": kids(keys)},
			Observed: map[string]any{"authenticator": client.Credential.Authenticator, "held_jwks": client.Credential.HeldJWKS,
				"unreadable": client.Credential.Unreadable, "kids": kids(client.Credential.Keys)},
			Differs: !client.Credential.ByKeys(keys)},
	}}
	plan.Adoptable = true
	for _, difference := range plan.Differences {
		if !difference.Differs {
			continue
		}
		switch {
		case difference.Policy == PolicyBlock:
			plan.Adoptable = false
			plan.Refusal = difference.FieldClass + " differs from the declaration; the declaration must match what the client runs with"
			return plan
		case !slices.Contains(req.Converge, difference.FieldClass) && plan.Refusal == "":
			plan.Adoptable = false
			plan.Refusal = difference.FieldClass + " differs from the declaration; name it in converge to converge it"
		}
	}
	return plan
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	slices.Sort(out)
	return slices.Compact(out)
}

// converge applies the named repairable differences and returns their classes.
func (s *Service) converge(ctx context.Context, plan Plan, client keycloak.Client, scopeID string, lifespan int) ([]string, error) {
	converged := []string{}
	for _, difference := range plan.Differences {
		if !difference.Differs || difference.Policy != PolicyRepair {
			continue
		}
		var err error
		switch difference.FieldClass {
		case ClassTokenLifespan:
			value := lifespan
			_, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, client.ID, keycloak.ClientPatch{AccessTokenLifespan: &value})
			})
		case ClassAudienceScope:
			desired, _ := DesiredScopes(plan.profile, plan.audienceClass)
			err = ConvergeScopes(ctx, s.kernel, s.cfg.Realm, client.ID, desired, s.cfg.CallTimeout)
		case ClassTokenFormat:
			clientKey := plan.ClientKey
			_, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, client.ID, keycloak.ClientPatch{TokenFormat: &clientKey})
			})
		case ClassEnabled:
			enabled := true
			_, err = call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, client.ID, keycloak.ClientPatch{Enabled: &enabled})
			})
		}
		if err != nil {
			return nil, fmt.Errorf("registration: converge %s: %w", difference.FieldClass, err)
		}
		converged = append(converged, difference.FieldClass)
	}
	return converged, nil
}

const insertAdoptedStatement = `INSERT INTO identity.client_registration
    (registration_id, kc_client_id, realm, client_key, profile, application_authority, application_ref, registered_by,
     audience_class, lifetime_class, audience, redirect_uris, state, activated_at)
VALUES ($1, $2, $3, $4, $5, 'manual', $6, $7, $8, $9, $10, $11, 'active', now())`

const insertAdoptionStatement = `INSERT INTO identity.registration_adoption
    (adoption_id, registration_id, kc_client_id, adopted_by, reason, observed, converged)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`

const retireAdoptedKeyStatement = `UPDATE identity.client_key SET state = 'retiring', retiring_at = $3
WHERE registration_id = $1 AND kid = $2`

// insertAdopted records the adopted registration active, its keys, and the adoption.
func (s *Service) insertAdopted(ctx context.Context, tx db.Tx, req AdoptRequest, client keycloak.Client,
	keys []PublicKey, plan Plan, converged []string) (Registration, error) {
	registrationID, err := s.newID()
	if err != nil {
		return Registration{}, fmt.Errorf("registration: mint registration_id: %w", err)
	}
	var lifetime any
	if req.LifetimeClass != "" {
		lifetime = req.LifetimeClass
	}
	if _, err := tx.Exec(ctx, insertAdoptedStatement, registrationID.String(), string(client.ID), string(s.cfg.Realm),
		req.ClientKey, req.Profile, req.ApplicationRef, req.RegisteredBy.String(), req.AudienceClass, lifetime,
		append([]string{}, req.Audience...), append([]string{}, req.RedirectURIs...)); err != nil {
		return Registration{}, fmt.Errorf("registration: record the adopted registration: %w", err)
	}
	now := s.now()
	// Recorded in reverse, so the first declared key is inserted last and is the active one: at most
	// one key is active, and the second declared key is the one still retiring.
	for i := len(keys) - 1; i >= 0; i-- {
		if i < len(keys)-1 {
			if _, err := tx.Exec(ctx, retireAdoptedKeyStatement, registrationID.String(), keys[i+1].JWK.KID,
				now.Add(s.cfg.RotationOverlap)); err != nil {
				return Registration{}, fmt.Errorf("registration: record the retiring key: %w", err)
			}
		}
		if err := s.insertKey(ctx, tx, registrationID, keys[i], req.RegisteredBy, now); err != nil {
			return Registration{}, err
		}
	}
	observed := map[string]any{}
	for _, difference := range plan.Differences {
		observed[difference.FieldClass] = difference.Observed
	}
	observedJSON, err := json.Marshal(observed)
	if err != nil {
		return Registration{}, err
	}
	adoptionID, err := s.newID()
	if err != nil {
		return Registration{}, fmt.Errorf("registration: mint adoption_id: %w", err)
	}
	if _, err := tx.Exec(ctx, insertAdoptionStatement, adoptionID.String(), registrationID.String(), string(client.ID),
		req.RegisteredBy.String(), strings.TrimSpace(req.Reason), string(observedJSON), converged); err != nil {
		return Registration{}, fmt.Errorf("registration: record the adoption: %w", err)
	}
	return s.read(ctx, tx, registrationID)
}
