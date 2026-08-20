package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
)

// AdminConfig configures the Admin REST client.
type AdminConfig struct {
	// BaseURL is the kernel root, without a trailing path.
	BaseURL string

	// Realm is the realm this client administers.
	Realm Realm

	// TokenRealm is the realm the service account authenticates against. It is usually the
	// same realm, and is separate because a deployment may hold its administration account
	// in a dedicated realm.
	TokenRealm Realm

	// ClientID and ClientSecret are the service account credential. They come from the
	// approved secret manager and are never present in configuration or in an image.
	ClientID     string
	ClientSecret string

	// Timeout bounds one HTTP round trip.
	Timeout time.Duration

	// TokenLeeway is how long before expiry a cached token is refreshed. Without leeway a
	// token that expires in transit produces a 401 the caller reads as a permission
	// problem rather than as a stale token.
	TokenLeeway time.Duration
}

func (c *AdminConfig) applyDefaults() {
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.TokenLeeway <= 0 {
		c.TokenLeeway = 30 * time.Second
	}
	if c.TokenRealm == "" {
		c.TokenRealm = c.Realm
	}
}

func (c AdminConfig) validate() error {
	switch {
	case strings.TrimSpace(c.BaseURL) == "":
		return errors.New("keycloak: base URL is required")
	case c.Realm == "":
		return errors.New("keycloak: realm is required")
	case c.ClientID == "":
		return errors.New("keycloak: client id is required")
	case c.ClientSecret == "":
		return errors.New("keycloak: client secret is required")
	}
	if _, err := url.Parse(c.BaseURL); err != nil {
		return fmt.Errorf("keycloak: base URL is unparseable: %w", err)
	}
	return nil
}

// Admin is the supported-interface Admin REST client.
//
// It implements AdminClient over documented endpoints only. ADR-IAM-001 §5.2 prohibits a
// private account-console endpoint and any direct write to the Keycloak database, so the
// operations here are the whole surface this service couples to.
type Admin struct {
	cfg    AdminConfig
	client *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// NewAdmin constructs the client.
func NewAdmin(cfg AdminConfig, client *http.Client) (*Admin, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &Admin{cfg: cfg, client: client}, nil
}

var _ AdminClient = (*Admin)(nil)

// CreateUser performs the only authorized Principal creation call.
//
// The identifier and subject classification travel inside the creation payload, so the
// Principal never exists in the kernel without the claim source its audience profile
// requires. Setting the attribute in a second call would create exactly the window
// TDD-identity-control-001 removes.
func (a *Admin) CreateUser(ctx context.Context, req CreateUserRequest) (UserID, error) {
	if err := req.Validate(); err != nil {
		return "", err
	}

	attributes := map[string][]string{
		AttrPrincipalID: {req.PrincipalID.String()},
		AttrSubjectType: {string(req.SubjectType)},
	}
	if !req.WorkloadOwner.IsNil() {
		attributes[AttrWorkloadOwner] = []string{req.WorkloadOwner.String()}
	}

	payload := map[string]any{
		"username":   req.Username,
		"enabled":    true,
		"attributes": attributes,
	}
	if req.Email != "" {
		payload["email"] = req.Email
	}
	// A required action is an instruction to the kernel, never a credential. It is what lets
	// this service create a human Principal without holding the credential that Principal will
	// authenticate with. Omitted for a workload, which authenticates by client credential.
	if actions := req.RequiredActions(); len(actions) > 0 {
		payload["requiredActions"] = actions
	}

	// mutating: true. A transport failure on a create is reported as ambiguous rather than
	// unavailable, because the request may have been written and the response lost. The
	// caller must read the kernel back rather than retry blindly, which is what stops a
	// second Principal appearing for one request.
	response, err := a.do(ctx, http.MethodPost,
		fmt.Sprintf("/admin/realms/%s/users", url.PathEscape(string(req.Realm))), nil, payload, true)
	if err != nil {
		return "", err
	}
	defer response.Close()

	userID := userIDFromLocation(response.location)
	if userID != "" {
		return userID, nil
	}

	// A 201 without a usable Location is ambiguous rather than a failure: the user was
	// created and we do not know its identifier. Recovery resolves it by attribute search,
	// which is the same path a lost response takes.
	return "", fmt.Errorf("keycloak: created a user but the Location header carried no identifier: %w", ErrAmbiguous)
}

// FindByPrincipalID returns every user whose canonical identifier attribute equals the value.
//
// The kernel's attribute query semantics are unsettled against the pinned release, so the
// result is filtered to exact equality here. A prefix or substring query therefore cannot
// widen what this method returns, and the caller's cardinality check remains the second half
// of the same defence.
func (a *Admin) FindByPrincipalID(ctx context.Context, realm Realm, principalID id.UUID) ([]User, error) {
	if principalID.IsNil() {
		return nil, errors.New("keycloak: refusing to search for a nil principal_id")
	}

	query := url.Values{}
	query.Set("q", fmt.Sprintf("%s:%s", AttrPrincipalID, principalID.String()))
	// The attribute is unique by invariant, so a page larger than a handful only matters
	// when that invariant is already violated — which is the case the caller quarantines.
	query.Set("max", "20")

	users, err := a.listUsers(ctx, realm, query)
	if err != nil {
		return nil, err
	}

	exact := make([]User, 0, len(users))
	for _, user := range users {
		if user.PrincipalID == principalID {
			exact = append(exact, user)
		}
	}
	return exact, nil
}

// ListUsers enumerates a page for the reconciliation sweep.
func (a *Admin) ListUsers(ctx context.Context, realm Realm, page Page) ([]User, error) {
	if page.Max <= 0 {
		return nil, errors.New("keycloak: page.Max must be positive")
	}

	query := url.Values{}
	query.Set("first", strconv.Itoa(page.First))
	query.Set("max", strconv.Itoa(page.Max))
	return a.listUsers(ctx, realm, query)
}

func (a *Admin) listUsers(ctx context.Context, realm Realm, query url.Values) ([]User, error) {
	response, err := a.do(ctx, http.MethodGet,
		fmt.Sprintf("/admin/realms/%s/users", url.PathEscape(string(realm))), query, nil, false)
	if err != nil {
		return nil, err
	}
	defer response.Close()

	var representations []userRepresentation
	if err := json.Unmarshal(response.body, &representations); err != nil {
		return nil, fmt.Errorf("keycloak: decode user list: %w", err)
	}

	users := make([]User, 0, len(representations))
	for _, representation := range representations {
		users = append(users, representation.toUser())
	}
	return users, nil
}

// DisableUser disables a user and is idempotent.
//
// Disable rather than delete is deliberate: a false positive caused by a reconciler defect is
// recoverable, and the deletion of a Principal is not.
func (a *Admin) DisableUser(ctx context.Context, realm Realm, userID UserID) error {
	if userID == "" {
		return errors.New("keycloak: a user identifier is required")
	}

	// Not marked mutating. The update is idempotent, so a lost response costs a repeated
	// call rather than a duplicated effect, and reporting it as ambiguous would send the
	// caller into a read-back it does not need.
	response, err := a.do(ctx, http.MethodPut,
		fmt.Sprintf("/admin/realms/%s/users/%s",
			url.PathEscape(string(realm)), url.PathEscape(string(userID))),
		nil, map[string]any{"enabled": false}, false)
	if err != nil {
		return err
	}
	response.Close()
	return nil
}

// userRepresentation is the subset of the kernel representation this service reads.
//
// Fields the kernel returns and this service must not hold — credentials, federated identities,
// required actions — are absent rather than ignored, so a future edit cannot start depending on
// one without adding it here first.
type userRepresentation struct {
	ID         string              `json:"id"`
	Username   string              `json:"username"`
	Email      string              `json:"email"`
	Enabled    bool                `json:"enabled"`
	Attributes map[string][]string `json:"attributes"`
}

func (r userRepresentation) toUser() User {
	user := User{
		ID:       UserID(r.ID),
		Username: r.Username,
		Email:    r.Email,
		Enabled:  r.Enabled,
	}

	// An unparseable or absent attribute leaves the identifier nil, which Mapped reports as
	// unmapped. That is a reconciler finding rather than an error: a user carrying a
	// malformed identifier reached the kernel through a path that should be closed, and
	// failing the whole enumeration would stop the sweep that is meant to detect it.
	if parsed, err := id.Parse(firstAttribute(r.Attributes, AttrPrincipalID)); err == nil {
		user.PrincipalID = parsed
	}
	user.SubjectType = SubjectType(firstAttribute(r.Attributes, AttrSubjectType))
	if parsed, err := id.Parse(firstAttribute(r.Attributes, AttrWorkloadOwner)); err == nil {
		user.WorkloadOwner = parsed
	}
	return user
}

func firstAttribute(attributes map[string][]string, name string) string {
	values := attributes[name]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func userIDFromLocation(location string) UserID {
	if location == "" {
		return ""
	}
	trimmed := strings.TrimRight(location, "/")
	index := strings.LastIndex(trimmed, "/")
	if index < 0 || index == len(trimmed)-1 {
		return ""
	}
	return UserID(trimmed[index+1:])
}
