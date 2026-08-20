// Package keycloakfake is an in-memory AdminClient for tests.
//
// It is a separate package so that no production binary links it. The alternative — a fake
// beside the real client in one package — puts test scaffolding inside the process that
// holds the administration credential.
//
// # What this fake is for
//
// It exists to make the failures that matter reachable. The whole creation and recovery
// suite of TDD-identity-control-001 is about what happens when a remote call is lost, when
// two users carry one identifier, or when a user appears without one. None of those occur
// on a healthy server, so a test that needs a healthy server tests nothing interesting.
//
// # What it is not
//
// It is not a Keycloak emulator, and it makes no claim about the pinned release's
// behaviour. Whether attribute search is exact-match is answered by the integration suite
// against a real kernel. This fake's SearchSemantics exists so the caller is correct under
// either answer before that answer arrives.
package keycloakfake

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// SearchSemantics selects how FindByPrincipalID matches, so a caller can be proven correct
// under either answer to the open proof-of-concept question.
type SearchSemantics int

const (
	// SearchExact matches the attribute value exactly. This is the assumed behaviour.
	SearchExact SearchSemantics = iota

	// SearchSubstring matches any user whose attribute contains the query as a substring,
	// which is the pessimistic reading of the Keycloak attribute query. A caller that
	// filters and checks cardinality is unaffected; one that takes the first result is
	// not, and this mode is what makes that difference visible in a test.
	SearchSubstring
)

// Client is an in-memory AdminClient.
//
// Every field that changes behaviour is exported so a test states its scenario in the test
// body rather than through a constructor with six arguments.
type Client struct {
	mu sync.Mutex

	// SearchMode selects attribute-search semantics. The zero value is exact match.
	SearchMode SearchSemantics

	// FailCreate, when set, is returned by CreateUser instead of performing it. Setting it
	// to keycloak.ErrAmbiguous while AmbiguousCreateSucceeds is true reproduces the
	// failure the recovery path exists for: the create happened and the caller was not
	// told.
	FailCreate error

	// AmbiguousCreateSucceeds makes a failed CreateUser still record the user. It models
	// a response lost after the kernel committed.
	AmbiguousCreateSucceeds bool

	// FailFind, FailList, and FailDisable are returned by their operations when set.
	FailFind    error
	FailList    error
	FailDisable error

	// Calls counts each operation, so a test can assert that a repeated idempotency key
	// performed no remote call.
	Calls Calls

	users  map[keycloak.UserID]stored
	nextID int
}

// Calls records how many times each operation ran.
type Calls struct {
	CreateUser        int
	FindByPrincipalID int
	ListUsers         int
	DisableUser       int
}

type stored struct {
	realm keycloak.Realm
	user  keycloak.User

	// requiredActions is what the create call told the kernel to demand. The port's User type
	// deliberately carries no such field — this service must not read one back — so it is held
	// beside the user rather than on it, and reachable only through RequiredActions below.
	requiredActions []string
}

// New returns an empty fake.
func New() *Client {
	return &Client{users: make(map[keycloak.UserID]stored)}
}

var _ keycloak.AdminClient = (*Client)(nil)

// CreateUser records a user and returns its assigned identifier.
func (c *Client) CreateUser(ctx context.Context, req keycloak.CreateUserRequest) (keycloak.UserID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := req.Validate(); err != nil {
		return "", err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.Calls.CreateUser++

	// Username uniqueness is a real Keycloak constraint, so the fake enforces it. Without
	// it a test would never exercise the conflict branch.
	for _, existing := range c.users {
		if existing.realm == req.Realm && strings.EqualFold(existing.user.Username, req.Username) {
			return "", fmt.Errorf("username %q: %w", req.Username, keycloak.ErrConflict)
		}
	}

	if c.FailCreate != nil && !c.AmbiguousCreateSucceeds {
		return "", c.FailCreate
	}

	c.nextID++
	userID := keycloak.UserID(fmt.Sprintf("kc-user-%04d", c.nextID))
	c.users[userID] = stored{
		realm: req.Realm,
		user: keycloak.User{
			ID:            userID,
			Username:      req.Username,
			Email:         req.Email,
			Enabled:       true,
			PrincipalID:   req.PrincipalID,
			SubjectType:   req.SubjectType,
			WorkloadOwner: req.WorkloadOwner,
		},
		requiredActions: req.RequiredActions(),
	}

	// The user is recorded and the caller is told the call failed. This is the state the
	// pending-mapping recovery path exists to resolve.
	if c.FailCreate != nil {
		return "", c.FailCreate
	}
	return userID, nil
}

// FindByPrincipalID returns matching users under the configured search semantics.
//
// Both modes filter to exact equality before returning, which is what the port requires of
// a real implementation. SearchSubstring widens what the simulated kernel would have
// returned, not what this method yields, so a caller depending on the port's contract stays
// correct while one that assumed a single result does not.
func (c *Client) FindByPrincipalID(ctx context.Context, realm keycloak.Realm, principalID id.UUID) ([]keycloak.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.Calls.FindByPrincipalID++

	if c.FailFind != nil {
		return nil, c.FailFind
	}
	if principalID.IsNil() {
		return nil, fmt.Errorf("keycloakfake: refusing to search for a nil principal_id")
	}

	query := principalID.String()
	var found []keycloak.User
	for _, entry := range c.users {
		if entry.realm != realm || entry.user.PrincipalID.IsNil() {
			continue
		}
		value := entry.user.PrincipalID.String()

		switch c.SearchMode {
		case SearchSubstring:
			if !strings.Contains(value, query) {
				continue
			}
		default:
			if value != query {
				continue
			}
		}

		// The exactness filter the port mandates, applied after the simulated kernel
		// response. A substring hit that is not equal is discarded here.
		if value != query {
			continue
		}
		found = append(found, entry.user)
	}
	return found, nil
}

// ListUsers returns a page of users in a stable order.
func (c *Client) ListUsers(ctx context.Context, realm keycloak.Realm, page keycloak.Page) ([]keycloak.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.Calls.ListUsers++

	if c.FailList != nil {
		return nil, c.FailList
	}
	if page.Max <= 0 {
		return nil, fmt.Errorf("keycloakfake: page.Max must be positive")
	}

	// Insertion order, reconstructed from the assigned identifier. A map iteration order
	// would make a paged sweep return overlapping or missing pages between calls, which
	// would make a reconciliation test pass or fail at random.
	ordered := make([]keycloak.User, 0, len(c.users))
	for i := 1; i <= c.nextID; i++ {
		entry, ok := c.users[keycloak.UserID(fmt.Sprintf("kc-user-%04d", i))]
		if ok && entry.realm == realm {
			ordered = append(ordered, entry.user)
		}
	}

	if page.First >= len(ordered) {
		return nil, nil
	}
	end := min(page.First+page.Max, len(ordered))
	return ordered[page.First:end], nil
}

// DisableUser disables a user and is idempotent.
func (c *Client) DisableUser(ctx context.Context, realm keycloak.Realm, userID keycloak.UserID) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.Calls.DisableUser++

	if c.FailDisable != nil {
		return c.FailDisable
	}

	entry, ok := c.users[userID]
	if !ok || entry.realm != realm {
		return fmt.Errorf("user %q: %w", userID, keycloak.ErrNotFound)
	}
	entry.user.Enabled = false
	c.users[userID] = entry
	return nil
}

// --- test inspection helpers ---
//
// These read and mutate state a real Admin API would not expose, so they are named to make
// that obvious and are used only to construct a scenario or assert an outcome.

// Seed inserts a user directly, modelling one that reached the kernel outside the
// authorized creation path. A nil principalID produces the unmapped case.
func (c *Client) Seed(realm keycloak.Realm, username string, principalID id.UUID, subjectType keycloak.SubjectType) keycloak.UserID {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.nextID++
	userID := keycloak.UserID(fmt.Sprintf("kc-user-%04d", c.nextID))
	c.users[userID] = stored{
		realm: realm,
		user: keycloak.User{
			ID:          userID,
			Username:    username,
			Enabled:     true,
			PrincipalID: principalID,
			SubjectType: subjectType,
		},
	}
	return userID
}

// User returns a recorded user for assertion.
func (c *Client) User(userID keycloak.UserID) (keycloak.User, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.users[userID]
	return entry.user, ok
}

// RequiredActions returns what the create call told the kernel to demand of this user.
//
// It exists so a test can assert that a human Principal is created owing a credential the
// service never supplied. Nothing in production reads this: the port has no such field, which is
// what stops this service from developing an opinion about a user's credential state.
func (c *Client) RequiredActions(userID keycloak.UserID) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.users[userID].requiredActions
}

// Count returns how many users the fake holds.
func (c *Client) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.users)
}
