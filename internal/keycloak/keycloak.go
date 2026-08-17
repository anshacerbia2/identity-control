// Package keycloak is the port through which this service reaches the identity kernel.
//
// It is the only package permitted to name a Keycloak concept. Everything above it works
// in canonical terms — a `principal_id`, a realm, a subject type — and never sees the
// kernel's own identifier. ADR-IAM-001 §5.2 restricts this boundary to supported
// interfaces: the Admin REST API and the published protocol endpoints, never a private
// account-console endpoint and never the Keycloak database.
//
// # Why the kernel identifier is a distinct type
//
// UserID is its own type rather than a string so that returning it from an HTTP handler is
// a compile error rather than a review finding. TDD-identity-control-001 requires it to be
// absent from every response body, and a bare string would satisfy every signature it
// should not reach.
//
// # Why search returns a slice
//
// FindByPrincipalID returns every match rather than one user, and that shape is the seam
// the open proof-of-concept question sits behind. Whether Keycloak's attribute query is
// exact-match or a prefix or substring match is unanswered against the pinned release, and
// the answer changes what the kernel returns for a query — not what this service must do
// about it. The recovery algorithm already branches on none, one, and more than one, so a
// slice makes the caller correct under either answer, and keycloakfake can produce both.
package keycloak

import (
	"context"
	"errors"
	"fmt"

	"github.com/anshacerbia2/foundation-platform/id"
)

// Sentinel errors. A caller distinguishes them because the recovery and reconciliation
// paths in TDD-identity-control-001 take different branches, and a single opaque error
// would collapse those branches into a retry loop.
var (
	// ErrNotFound means the kernel has no such object. It is a fact, not a failure.
	ErrNotFound = errors.New("keycloak: not found")

	// ErrConflict means the kernel refused a create because the object already exists,
	// by username or email. Retrying cannot help.
	ErrConflict = errors.New("keycloak: conflict")

	// ErrUnavailable means the call did not reach a decision: a connection failure, a
	// 5xx, or a rejected request. Retrying may help.
	ErrUnavailable = errors.New("keycloak: unavailable")

	// ErrAmbiguous means the request left this process and no answer came back, so the
	// side effect may or may not have happened. It is separate from ErrUnavailable
	// because it forbids a blind retry: the caller must read the kernel state back
	// before acting, and a create retried blindly after an ambiguous outcome is how a
	// second Principal appears.
	ErrAmbiguous = errors.New("keycloak: ambiguous outcome")

	// ErrForbidden means the administration credential lacks the role for this call. It
	// is never transient and never retried; it is a misconfigured service account.
	ErrForbidden = errors.New("keycloak: forbidden")
)

// Realm names a Keycloak realm. ADR-IAM-001 §5.4 fixes a small, static set of realms and
// prohibits a realm per Tenant, so this is configuration rather than a request parameter.
type Realm string

// UserID is the kernel's own identifier for a user.
//
// It never leaves this module. TDD-identity-control-001 requires it to be absent from
// every response body, and a test asserts that. Persisting it is permitted only in
// identity.principal_mapping, where it is the recovery index.
type UserID string

// SubjectType distinguishes a human Principal from a workload one.
//
// STD-IAM-001 §3.7 requires workload identity to be distinguishable in every audit record
// and authorization decision by an explicit claim rather than by a naming convention. This
// type is the source of that claim.
type SubjectType string

const (
	SubjectHuman    SubjectType = "human"
	SubjectWorkload SubjectType = "workload"
)

// Valid reports whether the subject type is one this service mints.
func (s SubjectType) Valid() bool {
	return s == SubjectHuman || s == SubjectWorkload
}

// Attribute names carried on the Keycloak user representation. They are the claim source
// the realm's protocol mappers project into a token, so the spelling is a contract with
// identity-kernel rather than an internal detail.
const (
	AttrPrincipalID   = "scnehaux_principal_id"
	AttrSubjectType   = "scnehaux_subject_type"
	AttrWorkloadOwner = "scnehaux_workload_owner"
)

// CreateUserRequest is the sole authorized Principal creation payload.
//
// Every claim-source attribute is present in this one call. TDD-identity-control-001
// removes rather than compensates for the window in which a Principal exists without its
// canonical identifier, and that requires creating the user and setting the attributes in
// a single request.
type CreateUserRequest struct {
	Realm    Realm
	Username string
	Email    string

	// PrincipalID is minted before this call so that the identifier is inside the
	// creation payload. It doubles as the recovery index: if the response is lost, the
	// caller finds the created user by searching for this value.
	PrincipalID id.UUID

	SubjectType SubjectType

	// WorkloadOwner is the accountable human Principal. It is required for a workload
	// and must be nil for a human, which the constraint on
	// identity.principal_mapping also enforces.
	WorkloadOwner id.UUID
}

// Validate rejects a request the kernel would accept but the enterprise would not.
//
// The checks run here rather than only at the API edge because this is the last point
// before the remote call, and a repair script or a recovery path that reaches the port
// directly must be held to the same invariants as an HTTP caller.
func (r CreateUserRequest) Validate() error {
	if r.Realm == "" {
		return fmt.Errorf("keycloak: realm is required")
	}
	if r.Username == "" {
		return fmt.Errorf("keycloak: username is required")
	}
	if r.PrincipalID.IsNil() {
		return fmt.Errorf("keycloak: principal_id is required and must not be nil")
	}
	if !r.SubjectType.Valid() {
		return fmt.Errorf("keycloak: subject_type %q is not human or workload", r.SubjectType)
	}
	if r.SubjectType == SubjectWorkload && r.WorkloadOwner.IsNil() {
		return fmt.Errorf("keycloak: a workload requires an accountable workload_owner")
	}
	if r.SubjectType == SubjectHuman && !r.WorkloadOwner.IsNil() {
		return fmt.Errorf("keycloak: a human must not carry a workload_owner")
	}
	return nil
}

// User is the subset of the kernel representation this service reads.
//
// It deliberately carries no credential field, no session field, and no federated-identity
// field. Those exist in the kernel and STD-IAM-001 §3.3 prohibits this service from holding
// them, so they are absent from the type rather than ignored at the call site.
type User struct {
	ID       UserID
	Username string
	Email    string
	Enabled  bool

	// PrincipalID is the parsed canonical identifier. It is nil when the attribute is
	// absent, which is the unmapped-Principal finding the reconciler acts on rather than
	// an error to swallow: a user without it reached the kernel through a creation path
	// that should be closed.
	PrincipalID id.UUID

	SubjectType   SubjectType
	WorkloadOwner id.UUID
}

// Mapped reports whether this user carries a canonical identifier.
func (u User) Mapped() bool { return !u.PrincipalID.IsNil() }

// Page is a bounded window over an enumeration.
//
// Enumeration is paged rather than complete because the reconciliation sweep grows linearly
// with Principal count, and TDD-identity-control-001 rate-limits it so reconciliation
// cannot consume capacity reserved for authentication.
type Page struct {
	First int
	Max   int
}

// AdminClient is the supported-interface surface this service uses.
//
// Every method maps to one documented Admin REST operation. The interface is small on
// purpose: ADR-IAM-001 §5.2 makes vendor replaceability a function of how narrow this
// surface is, and each method added here is a coupling a kernel upgrade can break.
type AdminClient interface {
	// CreateUser performs the only authorized Principal creation call. It returns the
	// kernel identifier parsed from the response.
	//
	// On ErrAmbiguous the caller must not retry blindly: it resolves the outcome through
	// FindByPrincipalID, because the create may have succeeded.
	CreateUser(ctx context.Context, req CreateUserRequest) (UserID, error)

	// FindByPrincipalID returns every user whose canonical identifier attribute matches.
	//
	// The slice is the contract. Exactly one match is the expected case; none means the
	// create did not happen; more than one is a uniqueness violation the kernel cannot
	// prevent, and the caller quarantines rather than picking one.
	//
	// An implementation MUST filter the kernel's response to exact equality on the
	// attribute value before returning, so a prefix or substring query semantics cannot
	// widen the result set. The caller still checks cardinality, because defence for an
	// invariant this important belongs on both sides.
	FindByPrincipalID(ctx context.Context, realm Realm, principalID id.UUID) ([]User, error)

	// ListUsers enumerates a page of users for the reconciliation sweep.
	ListUsers(ctx context.Context, realm Realm, page Page) ([]User, error)

	// DisableUser disables a user. It is the containment action for an unmapped, orphan,
	// or duplicate finding.
	//
	// Disable rather than delete is deliberate and is asserted by test: a false positive
	// caused by a reconciler defect is recoverable, and the deletion of a Principal is
	// not. It is idempotent — disabling an already-disabled user succeeds.
	DisableUser(ctx context.Context, realm Realm, userID UserID) error
}
