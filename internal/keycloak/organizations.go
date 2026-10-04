package keycloak

// The Organizations Admin API the Tenant context projection calls (TDD-identity-control-002 2.0.0,
// ADR-IAM-006). Each Tenant is an Organization whose name and alias are the tenant_id. The Principal
// credential calls these with manage-organizations and view-organizations, which Keycloak 26.7.5's
// organization permissions accept in place of manage-realm; adding or removing a member also needs
// manage-users on that user, which it already holds.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Organization is the part of a kernel Organization the projection reads.
type Organization struct {
	ID      string
	Name    string
	Alias   string
	Enabled bool
}

// TenantOrganizations is what the Tenant context converger calls. *Admin implements it.
type TenantOrganizations interface {
	// FindOrganization finds the Organization named exactly name. Found is false when none is.
	FindOrganization(ctx context.Context, realm Realm, name string) (org Organization, found bool, err error)
	GetOrganization(ctx context.Context, realm Realm, id string) (Organization, error)
	// CreateOrganization creates an Organization whose name and alias are name, with no domain.
	CreateOrganization(ctx context.Context, realm Realm, name string, enabled bool) (string, error)
	SetOrganizationEnabled(ctx context.Context, realm Realm, id string, enabled bool) error
	OrganizationMembers(ctx context.Context, realm Realm, id string) ([]UserID, error)
	// AddOrganizationMember adds a member; one who already belongs is done, not an error.
	AddOrganizationMember(ctx context.Context, realm Realm, id string, user UserID) error
	// RemoveOrganizationMember removes a member; one who does not belong is done, not an error.
	RemoveOrganizationMember(ctx context.Context, realm Realm, id string, user UserID) error
	// ListOrganizations lists every Organization, for the reconciliation sweep.
	ListOrganizations(ctx context.Context, realm Realm) ([]Organization, error)
}

// ErrTooManyOrganizations is a listing longer than one sweep reads.
var ErrTooManyOrganizations = errors.New("keycloak: more organizations than one enumeration reads")

// organizationPage is how many entries one listing request asks for, and maxOrganizationPages how
// many pages a listing reads before it refuses: a bound, not an expectation.
const (
	organizationPage     = 500
	maxOrganizationPages = 200
)

type organizationRepresentation struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Alias   string `json:"alias"`
	Enabled bool   `json:"enabled"`
}

func (r organizationRepresentation) organization() Organization {
	return Organization{ID: r.ID, Name: r.Name, Alias: r.Alias, Enabled: r.Enabled}
}

func (a *Admin) organizationsPath(realm Realm) string {
	return "/admin/realms/" + url.PathEscape(string(realm)) + "/organizations"
}

func (a *Admin) organizationPath(realm Realm, id string) string {
	return a.organizationsPath(realm) + "/" + url.PathEscape(id)
}

// FindOrganization searches by exact name. Keycloak's exact search matches a name or one of the
// Organization's domains; a projected Organization has no domain, and the result is filtered to an
// equal name here as well.
func (a *Admin) FindOrganization(ctx context.Context, realm Realm, name string) (Organization, bool, error) {
	if name == "" {
		return Organization{}, false, errors.New("keycloak: an organization name is required")
	}
	response, err := a.do(ctx, http.MethodGet, a.organizationsPath(realm),
		url.Values{"search": {name}, "exact": {"true"}, "briefRepresentation": {"true"}}, nil, false)
	if err != nil {
		return Organization{}, false, err
	}
	defer response.Close()
	var listed []organizationRepresentation
	if err := json.Unmarshal(response.body, &listed); err != nil {
		return Organization{}, false, fmt.Errorf("keycloak: decode organizations: %w", err)
	}
	for _, r := range listed {
		if r.Name == name {
			return r.organization(), true, nil
		}
	}
	return Organization{}, false, nil
}

// GetOrganization reads one Organization. One that is gone is ErrNotFound.
func (a *Admin) GetOrganization(ctx context.Context, realm Realm, id string) (Organization, error) {
	if id == "" {
		return Organization{}, errors.New("keycloak: an organization identifier is required")
	}
	response, err := a.do(ctx, http.MethodGet, a.organizationPath(realm, id), nil, nil, false)
	if err != nil {
		return Organization{}, err
	}
	defer response.Close()
	var r organizationRepresentation
	if err := json.Unmarshal(response.body, &r); err != nil {
		return Organization{}, fmt.Errorf("keycloak: decode organization: %w", err)
	}
	return r.organization(), nil
}

// CreateOrganization creates the Tenant's Organization. A lost response is ambiguous: the caller
// finds the Organization by its name before it creates another.
func (a *Admin) CreateOrganization(ctx context.Context, realm Realm, name string, enabled bool) (string, error) {
	if name == "" {
		return "", errors.New("keycloak: an organization name is required")
	}
	response, err := a.do(ctx, http.MethodPost, a.organizationsPath(realm), nil, map[string]any{
		"name": name, "alias": name, "enabled": enabled,
		"description": "Projected by identity-control from Organization Control's Tenant; not an authority.",
	}, true)
	if err != nil {
		return "", err
	}
	defer response.Close()
	if created := string(userIDFromLocation(response.location)); created != "" {
		return created, nil
	}
	return "", fmt.Errorf("keycloak: created an organization but the Location header carried no identifier: %w",
		ErrAmbiguous)
}

// SetOrganizationEnabled writes enabled over the Organization's own representation, so every other
// field Keycloak holds goes back unchanged.
func (a *Admin) SetOrganizationEnabled(ctx context.Context, realm Realm, id string, enabled bool) error {
	if id == "" {
		return errors.New("keycloak: an organization identifier is required")
	}
	response, err := a.do(ctx, http.MethodGet, a.organizationPath(realm, id), nil, nil, false)
	if err != nil {
		return err
	}
	var representation map[string]any
	err = json.Unmarshal(response.body, &representation)
	response.Close()
	if err != nil {
		return fmt.Errorf("keycloak: decode organization: %w", err)
	}
	representation["enabled"] = enabled
	updated, err := a.do(ctx, http.MethodPut, a.organizationPath(realm, id), nil, representation, false)
	if err != nil {
		return err
	}
	updated.Close()
	return nil
}

// OrganizationMembers lists the members' user identifiers, every page.
func (a *Admin) OrganizationMembers(ctx context.Context, realm Realm, id string) ([]UserID, error) {
	if id == "" {
		return nil, errors.New("keycloak: an organization identifier is required")
	}
	var members []UserID
	for page := 0; page < maxOrganizationPages; page++ {
		response, err := a.do(ctx, http.MethodGet, a.organizationPath(realm, id)+"/members", url.Values{
			"first": {strconv.Itoa(page * organizationPage)}, "max": {strconv.Itoa(organizationPage)},
			"briefRepresentation": {"true"},
		}, nil, false)
		if err != nil {
			return nil, err
		}
		var listed []struct {
			ID string `json:"id"`
		}
		err = json.Unmarshal(response.body, &listed)
		response.Close()
		if err != nil {
			return nil, fmt.Errorf("keycloak: decode organization members: %w", err)
		}
		for _, m := range listed {
			members = append(members, UserID(m.ID))
		}
		if len(listed) < organizationPage {
			return members, nil
		}
	}
	return nil, ErrTooManyOrganizations
}

// AddOrganizationMember adds the user. Keycloak answers 409 for one who already belongs.
func (a *Admin) AddOrganizationMember(ctx context.Context, realm Realm, id string, user UserID) error {
	if id == "" || user == "" {
		return errors.New("keycloak: an organization and a user identifier are required")
	}
	response, err := a.do(ctx, http.MethodPost, a.organizationPath(realm, id)+"/members", nil, string(user), false)
	if errors.Is(err, ErrConflict) {
		return nil
	}
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

// RemoveOrganizationMember removes the user. Keycloak answers 404 for one who does not belong.
func (a *Admin) RemoveOrganizationMember(ctx context.Context, realm Realm, id string, user UserID) error {
	if id == "" || user == "" {
		return errors.New("keycloak: an organization and a user identifier are required")
	}
	response, err := a.do(ctx, http.MethodDelete,
		a.organizationPath(realm, id)+"/members/"+url.PathEscape(string(user)), nil, nil, false)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

// ListOrganizations lists every Organization in the realm.
func (a *Admin) ListOrganizations(ctx context.Context, realm Realm) ([]Organization, error) {
	var all []Organization
	for page := 0; page < maxOrganizationPages; page++ {
		response, err := a.do(ctx, http.MethodGet, a.organizationsPath(realm), url.Values{
			"first": {strconv.Itoa(page * organizationPage)}, "max": {strconv.Itoa(organizationPage)},
			"briefRepresentation": {"true"},
		}, nil, false)
		if err != nil {
			return nil, err
		}
		var listed []organizationRepresentation
		err = json.Unmarshal(response.body, &listed)
		response.Close()
		if err != nil {
			return nil, fmt.Errorf("keycloak: decode organizations: %w", err)
		}
		for _, r := range listed {
			all = append(all, r.organization())
		}
		if len(listed) < organizationPage {
			return all, nil
		}
	}
	return nil, ErrTooManyOrganizations
}

var _ TenantOrganizations = (*Admin)(nil)
