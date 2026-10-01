package registration

// The token profile a registered client holds (TDD-identity-control-003 §Profiles, STD-IAM-002 §3.2,
// §3.2.1): the at+jwt header, a client_id mapper, and closed sets of default and optional client
// scopes. Registration applies them, adoption converges them, and the reconciler compares and
// repairs them, so the sets are defined once, here.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The kernel's scopes a registered client holds beside its managed audience scope.
const (
	// ScopeBasic gives sub and auth_time.
	ScopeBasic = "basic"
	// ScopeACR gives acr. A workload does not hold it: it puts acr=1 into a client credentials token.
	ScopeACR = "acr"
	// ScopeProfile gives a first-party BFF the name it shows, in its ID token only. A confidential
	// client holds it as an optional scope and requests it at sign-in.
	ScopeProfile = "scnehaux-profile"
)

// ScopeSets are a client's default and optional client scopes, by name.
type ScopeSets struct {
	Default  []string `json:"default"`
	Optional []string `json:"optional"`
}

// DesiredScopes are the closed sets a client of this profile and audience class holds. ok is false
// for a resource, which is issued no token and whose scopes are not governed.
func DesiredScopes(profile, audienceClass string) (ScopeSets, bool) {
	if profile == ProfileResource {
		return ScopeSets{}, false
	}
	desired := ScopeSets{Default: []string{ScopeBasic, managedScopes[audienceClass]}, Optional: []string{}}
	if profile != ProfileWorkload {
		desired.Default = append(desired.Default, ScopeACR)
	}
	if profile == ProfileConfidential {
		desired.Optional = append(desired.Optional, ScopeProfile)
	}
	slices.Sort(desired.Default)
	return desired, true
}

// SameScopes reports whether the live sets are the desired ones, ignoring order.
func SameScopes(live, desired ScopeSets) bool {
	sorted := func(values []string) []string {
		out := append([]string{}, values...)
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(sorted(live.Default), sorted(desired.Default)) &&
		slices.Equal(sorted(live.Optional), sorted(desired.Optional))
}

// ScopeKernel is the part of the kernel the scope sets are read and written through.
type ScopeKernel interface {
	ClientScopeID(ctx context.Context, realm keycloak.Realm, name string) (string, error)
	DefaultClientScopes(ctx context.Context, realm keycloak.Realm, client keycloak.ClientUUID) ([]string, error)
	OptionalClientScopes(ctx context.Context, realm keycloak.Realm, client keycloak.ClientUUID) ([]string, error)
	AddDefaultClientScope(ctx context.Context, realm keycloak.Realm, client keycloak.ClientUUID, scopeID string) error
	RemoveDefaultClientScope(ctx context.Context, realm keycloak.Realm, client keycloak.ClientUUID, scopeID string) error
	AddOptionalClientScope(ctx context.Context, realm keycloak.Realm, client keycloak.ClientUUID, scopeID string) error
	RemoveOptionalClientScope(ctx context.Context, realm keycloak.Realm, client keycloak.ClientUUID, scopeID string) error
}

// LiveScopes reads the client's two sets.
func LiveScopes(ctx context.Context, kernel ScopeKernel, realm keycloak.Realm, client keycloak.ClientUUID,
	timeout time.Duration) (ScopeSets, error) {
	defaults, err := call(ctx, timeout, func(ctx context.Context) ([]string, error) {
		return kernel.DefaultClientScopes(ctx, realm, client)
	})
	if err != nil {
		return ScopeSets{}, fmt.Errorf("registration: read the default scopes: %w", err)
	}
	optional, err := call(ctx, timeout, func(ctx context.Context) ([]string, error) {
		return kernel.OptionalClientScopes(ctx, realm, client)
	})
	if err != nil {
		return ScopeSets{}, fmt.Errorf("registration: read the optional scopes: %w", err)
	}
	return ScopeSets{Default: defaults, Optional: optional}, nil
}

// ConvergeScopes makes the client's sets exactly the desired ones: every scope outside them is
// detached first, so a scope moving between the sets is never in both, and every missing one is then
// attached. A scope the realm does not declare is skipped; the caller has already refused a
// registration whose managed scope is undeclared. Idempotent, so recovery and recreation run it again.
func ConvergeScopes(ctx context.Context, kernel ScopeKernel, realm keycloak.Realm, client keycloak.ClientUUID,
	desired ScopeSets, timeout time.Duration) error {
	live, err := LiveScopes(ctx, kernel, realm, client, timeout)
	if err != nil {
		return err
	}
	scopeID := func(name string) (string, bool, error) {
		id, err := call(ctx, timeout, func(ctx context.Context) (string, error) {
			return kernel.ClientScopeID(ctx, realm, name)
		})
		if errors.Is(err, keycloak.ErrNotFound) {
			return "", false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("registration: find %s: %w", name, err)
		}
		return id, true, nil
	}
	type set struct {
		live, want     []string
		attach, detach func(context.Context, keycloak.Realm, keycloak.ClientUUID, string) error
	}
	sets := []set{
		{live.Default, desired.Default, kernel.AddDefaultClientScope, kernel.RemoveDefaultClientScope},
		{live.Optional, desired.Optional, kernel.AddOptionalClientScope, kernel.RemoveOptionalClientScope},
	}
	for _, s := range sets {
		for _, name := range s.live {
			if slices.Contains(s.want, name) {
				continue
			}
			id, found, err := scopeID(name)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			if _, err := call(ctx, timeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, s.detach(ctx, realm, client, id)
			}); err != nil {
				return fmt.Errorf("registration: detach %s: %w", name, err)
			}
		}
	}
	for _, s := range sets {
		for _, name := range s.want {
			if slices.Contains(s.live, name) {
				continue
			}
			id, found, err := scopeID(name)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
			if _, err := call(ctx, timeout, func(ctx context.Context) (struct{}, error) {
				return struct{}{}, s.attach(ctx, realm, client, id)
			}); err != nil {
				return fmt.Errorf("registration: attach %s: %w", name, err)
			}
		}
	}
	return nil
}
