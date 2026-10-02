package registration

// Registration changes (ADR-IAM-003 §5.2, TDD-identity-control-003 §Registration Changes): a
// change to a registration's redirect URIs or its audience, proposed by an owner or a provider. In non-production
// it is applied at once. In production it waits until a provider other than its proposer approves
// it, a rule the database holds as well as this code. A change is pinned to the version it was
// proposed against, so what the approver sees is what the proposer saw, and nothing is deleted: a
// change is the record of who asked for what, who decided, and why.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// The states a change moves through. Only a proposed change is open; every other state is final.
const (
	ChangeProposed   = "proposed"
	ChangeApplied    = "applied"
	ChangeRejected   = "rejected"
	ChangeWithdrawn  = "withdrawn"
	ChangeSuperseded = "superseded"
)

// How long a change may wait for approval before it is reported: a warning, then an error
// (TDD-identity-control-003 §Operational Notes).
const (
	ChangeWarningAge  = 3 * 24 * time.Hour
	ChangeCriticalAge = 7 * 24 * time.Hour
)

// The kinds of change.
const (
	ChangeRedirectURIs = "redirect_uris"
	ChangeAudience     = "audience"
)

// The decisions on a proposed change.
const (
	DecisionApprove  = "approve"
	DecisionReject   = "reject"
	DecisionWithdraw = "withdraw"
)

var (
	// ErrVersionConflict is a change proposed against a version the registration no longer has.
	ErrVersionConflict = errors.New("registration: the registration changed since it was read")

	// ErrChangeOpen is a second open change on a registration that already has one.
	ErrChangeOpen = errors.New("registration: another change to this registration is waiting for a decision")

	// ErrChangeNotFound is a decision naming no change of this registration.
	ErrChangeNotFound = errors.New("registration: no such change")

	// ErrChangeDecided is a decision on a change that is no longer proposed.
	ErrChangeDecided = errors.New("registration: the change is already decided")

	// ErrSelfApproval is a provider approving, or rejecting, its own proposal (NIST AC-5).
	ErrSelfApproval = errors.New("registration: a change is decided by a provider other than its proposer")

	// ErrNotProvider is a provider's decision asked for by an owner. The transport refuses an owner
	// first; this is the same rule held where the decision is made.
	ErrNotProvider = errors.New("registration: approving or rejecting a change requires provider authority")

	// ErrNotProposer is a withdrawal by anyone but the change's proposer.
	ErrNotProposer = errors.New("registration: only the proposer withdraws a change")

	// ErrNotResourceOwner is an owner's audience change adding a resource it does not own: that
	// resource's owners did not agree to this client. A provider adds any registered resource.
	ErrNotResourceOwner = errors.New("registration: an owner adds to an audience only resources it owns")

	// ErrSuperseded is an approval of a change whose registration moved since it was proposed. The
	// change is recorded superseded, and is proposed again against the registration as it is.
	ErrSuperseded = errors.New("registration: the registration changed since this was proposed; propose it again")
)

// Change is one proposed change, open or decided.
type Change struct {
	ID                   id.UUID    `json:"change_id"`
	Registration         id.UUID    `json:"registration_id"`
	ClientKey            string     `json:"client_key"`
	BaseVersion          int64      `json:"base_version"`
	Kind                 string     `json:"kind"`
	PreviousRedirectURIs []string   `json:"previous_redirect_uris"`
	RedirectURIs         []string   `json:"redirect_uris"`
	PreviousAudience     []string   `json:"previous_audience"`
	Audience             []string   `json:"audience"`
	ApprovalRequired     bool       `json:"approval_required"`
	ProposedBy           id.UUID    `json:"proposed_by"`
	ProposalReason       string     `json:"proposal_reason"`
	ProposedAt           time.Time  `json:"proposed_at"`
	State                string     `json:"state"`
	DecidedBy            *id.UUID   `json:"decided_by"`
	DecisionReason       string     `json:"decision_reason,omitempty"`
	DecidedAt            *time.Time `json:"decided_at"`
}

// Proposal is a change asked for: the redirect URIs or the audience the registration should have,
// the version the caller read, who asks and why. Exactly one of RedirectURIs and Audience is set.
type Proposal struct {
	RegistrationID  id.UUID
	RedirectURIs    []string
	Audience        *[]string
	ExpectedVersion int64
	ProposedBy      id.UUID
	Reason          string

	// Provider is whether the proposer holds provider authority, which adds any registered resource
	// to an audience. An owner adds only resources it owns.
	Provider bool
}

// kind is what the proposal changes.
func (p Proposal) kind() string {
	if p.Audience != nil {
		return ChangeAudience
	}
	return ChangeRedirectURIs
}

func (p Proposal) validate() error {
	switch {
	case p.RegistrationID.IsNil() || p.ProposedBy.IsNil():
		return fmt.Errorf("%w: a change names the registration and who asks", ErrInvalid)
	case p.ExpectedVersion <= 0:
		return fmt.Errorf("%w: expected_version is the registration's version as read, and is required", ErrInvalid)
	case strings.TrimSpace(p.Reason) == "":
		return fmt.Errorf("%w: a change requires a reason", ErrInvalid)
	case p.Audience != nil && p.RedirectURIs != nil:
		return fmt.Errorf("%w: a change is to redirect_uris or to audience, not both", ErrInvalid)
	case p.Audience != nil:
		return validateAudience(*p.Audience)
	case len(p.RedirectURIs) == 0:
		return fmt.Errorf("%w: a public or confidential client needs at least one redirect URI", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, uri := range p.RedirectURIs {
		if err := validateRedirect(uri); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if seen[uri] {
			return fmt.Errorf("%w: a redirect URI is listed twice", ErrInvalid)
		}
		seen[uri] = true
	}
	return nil
}

// validateAudience applies the rules that need nothing but the list: each entry a client_key, named
// once. Whether each is a registered resource is read in the proposal's transaction.
func validateAudience(audience []string) error {
	seen := map[string]bool{}
	for _, resource := range audience {
		if !clientKeyPattern.MatchString(resource) {
			return fmt.Errorf("%w: an audience entry is not a client_key", ErrInvalid)
		}
		if seen[resource] {
			return fmt.Errorf("%w: an audience names a resource twice", ErrInvalid)
		}
		seen[resource] = true
	}
	return nil
}

// sortedAudience is the audience as it is stored and compared: its order carries no meaning.
func sortedAudience(audience []string) []string {
	out := append([]string{}, audience...)
	slices.Sort(out)
	return out
}

// Decision is an approval, a rejection or a withdrawal of one change.
type Decision struct {
	RegistrationID id.UUID
	ChangeID       id.UUID
	Decision       string
	DecidedBy      id.UUID
	Reason         string
}

func (d Decision) validate() error {
	switch {
	case d.RegistrationID.IsNil() || d.ChangeID.IsNil() || d.DecidedBy.IsNil():
		return fmt.Errorf("%w: a decision names the registration, the change and who decides", ErrInvalid)
	case !slices.Contains([]string{DecisionApprove, DecisionReject, DecisionWithdraw}, d.Decision):
		return fmt.Errorf("%w: a change is approved, rejected or withdrawn", ErrInvalid)
	case strings.TrimSpace(d.Reason) == "":
		return fmt.Errorf("%w: a decision requires a reason", ErrInvalid)
	}
	return nil
}

const lockChangedRegistrationStatement = `SELECT profile, state, coalesce(kc_client_id, ''), version,
       coalesce(redirect_uris, '{}'::text[]), client_key, coalesce(audience, '{}'::text[])
FROM identity.client_registration
WHERE registration_id = $1 AND realm = $2
FOR UPDATE`

type changedRegistration struct {
	profile      string
	state        string
	client       keycloak.ClientUUID
	version      int64
	redirectURIs []string
	clientKey    string
	audience     []string
}

func (s *Service) lockChanged(ctx context.Context, tx db.Tx, registrationID id.UUID) (changedRegistration, error) {
	rows, err := tx.Query(ctx, lockChangedRegistrationStatement, registrationID.String(), string(s.cfg.Realm))
	if err != nil {
		return changedRegistration{}, fmt.Errorf("registration: lock the registration: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return changedRegistration{}, fmt.Errorf("registration: lock the registration: %w", err)
		}
		return changedRegistration{}, ErrNotFound
	}
	var (
		locked changedRegistration
		client string
	)
	if err := rows.Scan(&locked.profile, &locked.state, &client, &locked.version, &locked.redirectURIs,
		&locked.clientKey, &locked.audience); err != nil {
		return changedRegistration{}, fmt.Errorf("registration: scan the registration: %w", err)
	}
	locked.client = keycloak.ClientUUID(client)
	locked.audience = sortedAudience(locked.audience)
	return locked, nil
}

var changeColumns = `c.change_id::text, c.registration_id::text, r.client_key, c.base_version, c.kind,
       c.previous_redirect_uris, c.redirect_uris, c.previous_audience, c.audience,
       c.approval_required, c.proposed_by::text,
       c.proposal_reason, c.proposed_at, c.state, coalesce(c.decided_by::text, ''),
       coalesce(c.decision_reason, ''), c.decided_at`

var changeStatement = `SELECT ` + changeColumns + `
FROM identity.registration_change c
JOIN identity.client_registration r ON r.registration_id = c.registration_id
WHERE c.change_id = $1 AND c.registration_id = $2`

var openChangeStatement = `SELECT ` + changeColumns + `
FROM identity.registration_change c
JOIN identity.client_registration r ON r.registration_id = c.registration_id
WHERE c.registration_id = $1 AND c.state = 'proposed'`

var registrationChangesStatement = `SELECT ` + changeColumns + `
FROM identity.registration_change c
JOIN identity.client_registration r ON r.registration_id = c.registration_id
WHERE c.registration_id = $1 AND r.realm = $2
ORDER BY c.proposed_at DESC, c.change_id DESC
LIMIT 100`

var openChangesStatement = `SELECT ` + changeColumns + `
FROM identity.registration_change c
JOIN identity.client_registration r ON r.registration_id = c.registration_id
WHERE r.realm = $1 AND c.state = 'proposed'
ORDER BY c.proposed_at, c.change_id`

const insertChangeStatement = `INSERT INTO identity.registration_change
    (change_id, registration_id, base_version, kind, previous_redirect_uris, redirect_uris,
     previous_audience, audience, approval_required, proposed_by, proposal_reason, proposed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

const decideChangeStatement = `UPDATE identity.registration_change
SET state = $2, decided_by = $3, decision_reason = $4, decided_at = $5
WHERE change_id = $1 AND state = 'proposed'`

const changeRedirectsStatement = `UPDATE identity.client_registration
SET redirect_uris = $2, version = version + 1
WHERE registration_id = $1`

const changeAudienceStatement = `UPDATE identity.client_registration
SET audience = $2, version = version + 1
WHERE registration_id = $1`

// audienceLifespanStatement is the lifespan an audience derives (STD-IAM-002 §3.3), read before the
// kernel is patched with it.
var audienceLifespanStatement = `SELECT ` + LifespanSQL("$1", "$2::text[]")

func scanChange(row interface{ Scan(dest ...any) error }) (Change, error) {
	var (
		change                             Change
		changeID, registrationID, proposer string
		decidedBy                          string
	)
	if err := row.Scan(&changeID, &registrationID, &change.ClientKey, &change.BaseVersion, &change.Kind,
		&change.PreviousRedirectURIs, &change.RedirectURIs, &change.PreviousAudience, &change.Audience,
		&change.ApprovalRequired, &proposer,
		&change.ProposalReason, &change.ProposedAt, &change.State, &decidedBy,
		&change.DecisionReason, &change.DecidedAt); err != nil {
		return Change{}, err
	}
	var err error
	for _, field := range []struct {
		raw  string
		into *id.UUID
	}{{changeID, &change.ID}, {registrationID, &change.Registration}, {proposer, &change.ProposedBy}} {
		if *field.into, err = id.Parse(field.raw); err != nil {
			return Change{}, err
		}
	}
	if decidedBy != "" {
		parsed, err := id.Parse(decidedBy)
		if err != nil {
			return Change{}, err
		}
		change.DecidedBy = &parsed
	}
	change.ProposedAt = change.ProposedAt.UTC()
	if change.DecidedAt != nil {
		at := change.DecidedAt.UTC()
		change.DecidedAt = &at
	}
	return change, nil
}

func readChanges(ctx context.Context, tx db.Tx, statement string, args ...any) ([]Change, error) {
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("registration: read changes: %w", err)
	}
	defer rows.Close()
	changes := []Change{}
	for rows.Next() {
		change, err := scanChange(rows)
		if err != nil {
			return nil, fmt.Errorf("registration: scan a change: %w", err)
		}
		changes = append(changes, change)
	}
	return changes, rows.Err()
}

// readChange reads the one change a statement names, or ErrChangeNotFound.
func readChange(ctx context.Context, tx db.Tx, statement string, args ...any) (Change, error) {
	changes, err := readChanges(ctx, tx, statement, args...)
	if err != nil {
		return Change{}, err
	}
	if len(changes) == 0 {
		return Change{}, ErrChangeNotFound
	}
	return changes[0], nil
}

// ProposeChange records a change to a registration's redirect URIs. It answers the change and
// whether it was recorded now: an open proposal by the same caller with the same URIs is the same
// change, retried after a lost answer, and is returned as it is. In non-production the change is
// applied before it returns.
func (s *Service) ProposeChange(ctx context.Context, proposal Proposal) (Change, bool, error) {
	if err := proposal.validate(); err != nil {
		return Change{}, false, err
	}
	var (
		change  Change
		created bool
	)
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lockChanged(ctx, tx, proposal.RegistrationID)
		if err != nil {
			return err
		}
		kind := proposal.kind()
		var audience []string
		if kind == ChangeAudience {
			audience = sortedAudience(*proposal.Audience)
		}
		switch {
		case kind == ChangeRedirectURIs && locked.profile != ProfilePublic && locked.profile != ProfileConfidential:
			return fmt.Errorf("%w: only a public or confidential client has redirect URIs", ErrInvalid)
		case kind == ChangeAudience && locked.profile == ProfileResource:
			return fmt.Errorf("%w: a resource has no audience", ErrInvalid)
		case locked.state != StateActive:
			return fmt.Errorf("%w: only an active registration is changed; this one is %s", ErrInvalidTransition, locked.state)
		}
		open, err := readChange(ctx, tx, openChangeStatement, proposal.RegistrationID.String())
		switch {
		case err == nil && open.ProposedBy == proposal.ProposedBy && open.Kind == kind &&
			slices.Equal(open.RedirectURIs, proposal.RedirectURIs) && slices.Equal(open.Audience, audience):
			change = open
			return nil
		case err == nil:
			return fmt.Errorf("%w: change %s, proposed %s", ErrChangeOpen, open.ID, open.ProposedAt.Format(time.RFC3339))
		case !errors.Is(err, ErrChangeNotFound):
			return err
		}
		switch {
		case locked.version != proposal.ExpectedVersion:
			return fmt.Errorf("%w: expected version %d, the registration is at %d",
				ErrVersionConflict, proposal.ExpectedVersion, locked.version)
		case kind == ChangeRedirectURIs && slices.Equal(locked.redirectURIs, proposal.RedirectURIs):
			return fmt.Errorf("%w: these are the registered redirect URIs already", ErrInvalid)
		case kind == ChangeAudience && slices.Equal(locked.audience, audience):
			return fmt.Errorf("%w: this is the registered audience already", ErrInvalid)
		}
		if kind == ChangeAudience {
			if err := s.admitAudience(ctx, tx, locked, audience, proposal); err != nil {
				return err
			}
		}

		changeID, err := s.newID()
		if err != nil {
			return fmt.Errorf("registration: mint change_id: %w", err)
		}
		at := s.now()
		var previousRedirects, redirects, previousAudience, nextAudience any
		if kind == ChangeRedirectURIs {
			previousRedirects, redirects = locked.redirectURIs, proposal.RedirectURIs
		} else {
			previousAudience, nextAudience = locked.audience, audience
		}
		if _, err := tx.Exec(ctx, insertChangeStatement, changeID.String(), proposal.RegistrationID.String(),
			locked.version, kind, previousRedirects, redirects, previousAudience, nextAudience, s.cfg.Production,
			proposal.ProposedBy.String(), strings.TrimSpace(proposal.Reason), at); err != nil {
			return fmt.Errorf("registration: record the change: %w", err)
		}
		created = true
		if !s.cfg.Production {
			// No approval is required, so the proposer's own reason is the decision's.
			pending := Change{Kind: kind, RedirectURIs: proposal.RedirectURIs, Audience: audience}
			if err := s.apply(ctx, tx, locked, proposal.RegistrationID, pending); err != nil {
				return err
			}
			if err := decide(ctx, tx, changeID, ChangeApplied, proposal.ProposedBy, proposal.Reason, at); err != nil {
				return err
			}
		}
		change, err = readChange(ctx, tx, changeStatement, changeID.String(), proposal.RegistrationID.String())
		return err
	})
	if err != nil {
		s.logFailure(ctx, "proposing a change", proposal.RegistrationID, err)
		return Change{}, false, err
	}
	return change, created, nil
}

// expectedChangeErrors are the refusals a caller is told about precisely. Anything else reaches the
// caller as "not applied, retry" with no cause, so it is logged here with the cause.
var expectedChangeErrors = []error{ErrInvalid, ErrVersionConflict, ErrChangeOpen, ErrChangeDecided,
	ErrSuperseded, ErrInvalidTransition, ErrSelfApproval, ErrNotProvider, ErrNotProposer,
	ErrNotResourceOwner, ErrChangeNotFound, ErrNotFound}

// logFailure records a change that failed for a reason the caller is not told: the kernel or the
// database refused it. The error names the operation that failed and no secret.
func (s *Service) logFailure(ctx context.Context, operation string, registrationID id.UUID, err error) {
	for _, expected := range expectedChangeErrors {
		if errors.Is(err, expected) {
			return
		}
	}
	s.logger.ErrorContext(ctx, "a registration change was not applied",
		slog.String("operation", operation),
		slog.String("registration_id", registrationID.String()),
		slog.String("error", err.Error()))
}

// DecideChange approves, rejects or withdraws a proposed change. provider is whether the caller
// holds provider authority: an approval and a rejection are a provider's, and never the
// proposer's; a withdrawal is the proposer's alone. An approval of a change whose registration
// moved since it was proposed records it superseded and returns ErrSuperseded.
func (s *Service) DecideChange(ctx context.Context, decision Decision, provider bool) (Change, error) {
	if err := decision.validate(); err != nil {
		return Change{}, err
	}
	var (
		change     Change
		superseded bool
	)
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lockChanged(ctx, tx, decision.RegistrationID)
		if err != nil {
			return err
		}
		current, err := readChange(ctx, tx, changeStatement, decision.ChangeID.String(), decision.RegistrationID.String())
		if err != nil {
			return err
		}
		switch {
		case decision.Decision == DecisionWithdraw && current.ProposedBy != decision.DecidedBy:
			return ErrNotProposer
		case decision.Decision != DecisionWithdraw && !provider:
			return ErrNotProvider
		case decision.Decision != DecisionWithdraw && current.ProposedBy == decision.DecidedBy:
			return ErrSelfApproval
		case current.State != ChangeProposed:
			return fmt.Errorf("%w: it is %s", ErrChangeDecided, current.State)
		}

		at := s.now()
		state := map[string]string{DecisionReject: ChangeRejected, DecisionWithdraw: ChangeWithdrawn}[decision.Decision]
		if decision.Decision == DecisionApprove {
			switch {
			case locked.version != current.BaseVersion || locked.state != StateActive:
				state, superseded = ChangeSuperseded, true
			default:
				if err := s.apply(ctx, tx, locked, decision.RegistrationID, current); err != nil {
					return err
				}
				state = ChangeApplied
			}
		}
		if err := decide(ctx, tx, decision.ChangeID, state, decision.DecidedBy, decision.Reason, at); err != nil {
			return err
		}
		change, err = readChange(ctx, tx, changeStatement, decision.ChangeID.String(), decision.RegistrationID.String())
		return err
	})
	if err != nil {
		s.logFailure(ctx, "deciding a change", decision.RegistrationID, err)
		return Change{}, err
	}
	if superseded {
		return change, ErrSuperseded
	}
	return change, nil
}

func decide(ctx context.Context, tx db.Tx, changeID id.UUID, state string, by id.UUID, reason string, at time.Time) error {
	tag, err := tx.Exec(ctx, decideChangeStatement, changeID.String(), state, by.String(), strings.TrimSpace(reason), at)
	if err != nil {
		return fmt.Errorf("registration: record the decision: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrChangeDecided
	}
	return nil
}

// admitAudience refuses an audience entry that is not an active registered resource, or that is the
// registration itself, and an owner's addition of a resource it does not own. Removing is never
// refused: a narrower audience only takes access away.
func (s *Service) admitAudience(ctx context.Context, tx db.Tx, locked changedRegistration, audience []string, proposal Proposal) error {
	if slices.Contains(audience, locked.clientKey) {
		return fmt.Errorf("%w: a registration is not its own audience", ErrInvalid)
	}
	var unregistered int
	if err := tx.QueryRow(ctx, unregisteredAudienceStatement, string(s.cfg.Realm), audience).Scan(&unregistered); err != nil {
		return fmt.Errorf("registration: read the audience: %w", err)
	}
	if unregistered > 0 {
		return fmt.Errorf("%w: an audience names only active registered resources", ErrInvalid)
	}
	if proposal.Provider {
		return nil
	}
	var added []string
	for _, resource := range audience {
		if !slices.Contains(locked.audience, resource) {
			added = append(added, resource)
		}
	}
	if len(added) == 0 {
		return nil
	}
	var owned int
	if err := tx.QueryRow(ctx, ownsAllStatement, string(s.cfg.Realm), proposal.ProposedBy.String(), added).Scan(&owned); err != nil {
		return fmt.Errorf("registration: read the audience's owners: %w", err)
	}
	if owned != len(added) {
		return ErrNotResourceOwner
	}
	return nil
}

// apply writes the change into desired state and the kernel client, under the row lock the caller
// holds. The kernel is written before the commit, as a restore writes it: a kernel that refuses or
// does not answer rolls the change back, and the caller retries.
func (s *Service) apply(ctx context.Context, tx db.Tx, locked changedRegistration, registrationID id.UUID, change Change) error {
	if change.Kind == ChangeAudience {
		return s.applyAudience(ctx, tx, locked, registrationID, change.Audience)
	}
	uris := change.RedirectURIs
	if _, err := tx.Exec(ctx, changeRedirectsStatement, registrationID.String(), uris); err != nil {
		return fmt.Errorf("registration: write the redirect URIs: %w", err)
	}
	if locked.client == "" {
		return nil
	}
	redirects := append([]string{}, uris...)
	if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, locked.client, keycloak.ClientPatch{RedirectURIs: &redirects})
	}); err != nil {
		return fmt.Errorf("registration: write the redirect URIs to the client: %w", err)
	}
	return nil
}

// applyAudience writes the audience and the lifespan it derives, and makes the kernel client's
// audience mappers exactly that set (TDD-identity-control-003 §Registration Changes).
func (s *Service) applyAudience(ctx context.Context, tx db.Tx, locked changedRegistration, registrationID id.UUID, audience []string) error {
	audience = sortedAudience(audience)
	if _, err := tx.Exec(ctx, changeAudienceStatement, registrationID.String(), audience); err != nil {
		return fmt.Errorf("registration: write the audience: %w", err)
	}
	if locked.client == "" {
		return nil
	}
	var lifespan int
	if err := tx.QueryRow(ctx, audienceLifespanStatement, string(s.cfg.Realm), audience).Scan(&lifespan); err != nil {
		return fmt.Errorf("registration: derive the lifespan: %w", err)
	}
	if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.kernel.PatchClient(ctx, s.cfg.Realm, locked.client,
			keycloak.ClientPatch{Audience: &audience, AccessTokenLifespan: &lifespan})
	}); err != nil {
		return fmt.Errorf("registration: write the audience to the client: %w", err)
	}
	return nil
}

// Changes lists one registration's changes, newest first, at most 100.
func (s *Service) Changes(ctx context.Context, registrationID id.UUID) ([]Change, error) {
	var changes []Change
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := s.read(ctx, tx, registrationID); err != nil {
			return err
		}
		var err error
		changes, err = readChanges(ctx, tx, registrationChangesStatement, registrationID.String(), string(s.cfg.Realm))
		return err
	})
	return changes, err
}

// OpenChanges lists every proposed change in the realm, oldest first: the approval queue.
func (s *Service) OpenChanges(ctx context.Context) ([]Change, error) {
	var changes []Change
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		changes, err = readChanges(ctx, tx, openChangesStatement, string(s.cfg.Realm))
		return err
	})
	return changes, err
}
