package registration

// Registration requests (ADR-IAM-003 §5.3, TDD-identity-control-003 §Registration Requests): a
// production registration is created only by approval. An application developer proposes it,
// naming at least two owners, and a provider other than the proposer approves it. The approval,
// the owners and the registration's reservation commit together, and nothing is deleted: a request
// is the record of who asked for which client, who decided, and why.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// The states a request moves through. Only a proposed request is open.
const (
	RequestProposed  = "proposed"
	RequestApproved  = "approved"
	RequestRejected  = "rejected"
	RequestWithdrawn = "withdrawn"
)

var (
	// ErrRequestNotNeeded is a request outside production, where an application developer
	// registers directly.
	ErrRequestNotNeeded = errors.New("registration: outside production a registration is created directly; nothing is requested")

	// ErrRequestOpen is a second open request for a client_key that already has one.
	ErrRequestOpen = errors.New("registration: another request for this client_key is waiting for a decision")

	// ErrRequestNotFound is a decision naming no request of this realm.
	ErrRequestNotFound = errors.New("registration: no such request")
)

// RegistrationRequest is one request, open or decided. Request is the registration document as
// POST /v1/registrations takes it.
type RegistrationRequest struct {
	ID             id.UUID         `json:"request_id"`
	ClientKey      string          `json:"client_key"`
	Request        json.RawMessage `json:"request"`
	Owners         []id.UUID       `json:"owners"`
	ProposedBy     id.UUID         `json:"proposed_by"`
	ProposalReason string          `json:"proposal_reason"`
	ProposedAt     time.Time       `json:"proposed_at"`
	State          string          `json:"state"`
	DecidedBy      *id.UUID        `json:"decided_by"`
	DecisionReason string          `json:"decision_reason,omitempty"`
	DecidedAt      *time.Time      `json:"decided_at"`
	RegistrationID *id.UUID        `json:"registration_id"`
}

// RegistrationProposal is a request asked for: the document, with its proposer as RegisteredBy and
// Developer set when the proposer asks on application developer standing, the owners it names, and
// why.
type RegistrationProposal struct {
	Request Request
	Owners  []id.UUID
	Reason  string
}

// document is the stored registration document: what POST /v1/registrations takes, with a public
// key re-encoded to its public members.
type document struct {
	ClientKey      string          `json:"client_key"`
	Profile        string          `json:"profile"`
	AudienceClass  string          `json:"audience_class"`
	PrivilegedForm string          `json:"privileged_form,omitempty"`
	ApplicationRef string          `json:"application_ref"`
	LifetimeClass  string          `json:"lifetime_class,omitempty"`
	Audience       []string        `json:"audience,omitempty"`
	RedirectURIs   []string        `json:"redirect_uris,omitempty"`
	PublicKey      json.RawMessage `json:"public_key,omitempty"`
}

func (p RegistrationProposal) validate() error {
	switch {
	case p.Request.RegisteredBy.IsNil():
		return fmt.Errorf("%w: a request names who proposes it", ErrInvalid)
	case strings.TrimSpace(p.Reason) == "":
		return fmt.Errorf("%w: a request requires a reason", ErrInvalid)
	}
	distinct := []id.UUID{}
	for _, owner := range p.Owners {
		if owner.IsNil() {
			return fmt.Errorf("%w: an owner is not a valid identifier", ErrInvalid)
		}
		if !slices.Contains(distinct, owner) {
			distinct = append(distinct, owner)
		}
	}
	if len(distinct) < MinProductionOwners {
		return fmt.Errorf("%w: a production registration names at least two distinct owners (ADR-IAM-003 §5.1)", ErrInvalid)
	}
	return nil
}

var requestColumns = `q.request_id::text, q.client_key, q.request, q.owners::text[], q.proposed_by::text,
       q.proposal_reason, q.proposed_at, q.state, coalesce(q.decided_by::text, ''),
       coalesce(q.decision_reason, ''), q.decided_at, coalesce(q.registration_id::text, '')`

var requestStatement = `SELECT ` + requestColumns + `
FROM identity.registration_request q WHERE q.request_id = $1 AND q.realm = $2`

var openRequestStatement = `SELECT ` + requestColumns + `
FROM identity.registration_request q WHERE q.realm = $1 AND q.client_key = $2 AND q.state = 'proposed'`

var queueStatement = `SELECT ` + requestColumns + `
FROM identity.registration_request q WHERE q.realm = $1 AND q.state = 'proposed'
ORDER BY q.proposed_at, q.request_id`

var mineRequestsStatement = `SELECT ` + requestColumns + `
FROM identity.registration_request q WHERE q.realm = $1 AND q.proposed_by = $2
ORDER BY q.proposed_at DESC, q.request_id DESC
LIMIT 100`

const insertRequestStatement = `INSERT INTO identity.registration_request
    (request_id, realm, client_key, request, owners, proposed_by, proposal_reason, proposed_at)
VALUES ($1, $2, $3, $4, $5::uuid[], $6, $7, $8)`

const decideRequestStatement = `UPDATE identity.registration_request
SET state = $2, decided_by = $3, decision_reason = $4, decided_at = $5, registration_id = $6
WHERE request_id = $1 AND state = 'proposed'`

func readRequests(ctx context.Context, tx db.Tx, statement string, args ...any) ([]RegistrationRequest, error) {
	rows, err := tx.Query(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("registration: read requests: %w", err)
	}
	defer rows.Close()
	out := []RegistrationRequest{}
	for rows.Next() {
		var (
			request                               RegistrationRequest
			requestID, proposer, decidedBy, regID string
			owners                                []string
			body                                  []byte
		)
		if err := rows.Scan(&requestID, &request.ClientKey, &body, &owners, &proposer, &request.ProposalReason,
			&request.ProposedAt, &request.State, &decidedBy, &request.DecisionReason, &request.DecidedAt, &regID); err != nil {
			return nil, fmt.Errorf("registration: scan a request: %w", err)
		}
		request.Request = json.RawMessage(body)
		if request.ID, err = id.Parse(requestID); err != nil {
			return nil, err
		}
		if request.ProposedBy, err = id.Parse(proposer); err != nil {
			return nil, err
		}
		for _, raw := range owners {
			owner, err := id.Parse(raw)
			if err != nil {
				return nil, err
			}
			request.Owners = append(request.Owners, owner)
		}
		for _, field := range []struct {
			raw  string
			into **id.UUID
		}{{decidedBy, &request.DecidedBy}, {regID, &request.RegistrationID}} {
			if field.raw == "" {
				continue
			}
			parsed, err := id.Parse(field.raw)
			if err != nil {
				return nil, err
			}
			*field.into = &parsed
		}
		request.ProposedAt = request.ProposedAt.UTC()
		if request.DecidedAt != nil {
			at := request.DecidedAt.UTC()
			request.DecidedAt = &at
		}
		out = append(out, request)
	}
	return out, rows.Err()
}

func readRequest(ctx context.Context, tx db.Tx, statement string, args ...any) (RegistrationRequest, error) {
	requests, err := readRequests(ctx, tx, statement, args...)
	if err != nil {
		return RegistrationRequest{}, err
	}
	if len(requests) == 0 {
		return RegistrationRequest{}, ErrRequestNotFound
	}
	return requests[0], nil
}

// documentOf is the stored form of a request: its fields, and a public key reduced to its public
// members. A private key was refused before this is reached.
func documentOf(req Request) (json.RawMessage, error) {
	doc := document{ClientKey: req.ClientKey, Profile: req.Profile, AudienceClass: req.AudienceClass,
		PrivilegedForm: req.PrivilegedForm, ApplicationRef: strings.TrimSpace(req.ApplicationRef), LifetimeClass: req.LifetimeClass,
		Audience: req.Audience, RedirectURIs: req.RedirectURIs}
	if keyed(req.Profile) {
		parsed, err := parsePublicKey(req.PublicKey)
		if err != nil {
			return nil, err
		}
		jwk, err := json.Marshal(map[string]string{"kty": "RSA", "kid": parsed.JWK.KID, "n": parsed.JWK.N, "e": parsed.JWK.E})
		if err != nil {
			return nil, err
		}
		doc.PublicKey = jwk
	}
	return json.Marshal(doc)
}

func requestOf(raw json.RawMessage) (Request, error) {
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Request{}, fmt.Errorf("registration: read a stored request: %w", err)
	}
	return Request{ClientKey: doc.ClientKey, Profile: doc.Profile, AudienceClass: doc.AudienceClass,
		PrivilegedForm: doc.PrivilegedForm, ApplicationRef: doc.ApplicationRef, LifetimeClass: doc.LifetimeClass, Audience: doc.Audience,
		RedirectURIs: doc.RedirectURIs, PublicKey: doc.PublicKey}, nil
}

// eligibleOwners refuses an owner that is not an active person.
func eligibleOwners(ctx context.Context, tx db.Tx, owners []id.UUID) error {
	for _, owner := range owners {
		var eligible bool
		if err := tx.QueryRow(ctx, eligibleOwnerStatement, owner.String()).Scan(&eligible); err != nil {
			return fmt.Errorf("registration: read an owner: %w", err)
		}
		if !eligible {
			return fmt.Errorf("%w: %s", ErrOwnerNotEligible, owner)
		}
	}
	return nil
}

func uniqueOwners(owners []id.UUID) []id.UUID {
	out := []id.UUID{}
	for _, owner := range owners {
		if !slices.Contains(out, owner) {
			out = append(out, owner)
		}
	}
	return out
}

func ownerStrings(owners []id.UUID) []string {
	out := make([]string, 0, len(owners))
	for _, owner := range owners {
		out = append(out, owner.String())
	}
	return out
}

// ProposeRegistration records a request for a production registration. It answers the request and
// whether it was recorded now: an open request by the same proposer with the same document and
// owners is the same request, retried after a lost answer.
func (s *Service) ProposeRegistration(ctx context.Context, proposal RegistrationProposal) (RegistrationRequest, bool, error) {
	if !s.cfg.Production {
		return RegistrationRequest{}, false, ErrRequestNotNeeded
	}
	if err := proposal.validate(); err != nil {
		return RegistrationRequest{}, false, err
	}
	req := proposal.Request.normalized()
	if err := validate(req); err != nil {
		return RegistrationRequest{}, false, err
	}
	if req.Developer {
		if err := developerBounds(req); err != nil {
			return RegistrationRequest{}, false, err
		}
	}
	body, err := documentOf(req)
	if err != nil {
		return RegistrationRequest{}, false, err
	}
	owners := uniqueOwners(proposal.Owners)

	var (
		recorded RegistrationRequest
		created  bool
	)
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		open, err := readRequest(ctx, tx, openRequestStatement, string(s.cfg.Realm), req.ClientKey)
		switch {
		case err == nil && open.ProposedBy == req.RegisteredBy && sameDocument(open.Request, body) &&
			slices.Equal(open.Owners, owners):
			recorded = open
			return nil
		case err == nil:
			return fmt.Errorf("%w: request %s", ErrRequestOpen, open.ID)
		case !errors.Is(err, ErrRequestNotFound):
			return err
		}
		var inUse int
		if err := tx.QueryRow(ctx, keyInUseStatement, string(s.cfg.Realm), req.ClientKey).Scan(&inUse); err != nil {
			return fmt.Errorf("registration: check client_key: %w", err)
		}
		if inUse > 0 {
			return ErrKeyTaken
		}
		if err := eligibleOwners(ctx, tx, owners); err != nil {
			return err
		}
		if req.Developer {
			if err := s.ownsAudience(ctx, tx, req); err != nil {
				return err
			}
		}
		requestID, err := s.newID()
		if err != nil {
			return fmt.Errorf("registration: mint request_id: %w", err)
		}
		if _, err := tx.Exec(ctx, insertRequestStatement, requestID.String(), string(s.cfg.Realm), req.ClientKey,
			body, ownerStrings(owners), req.RegisteredBy.String(), strings.TrimSpace(proposal.Reason), s.now()); err != nil {
			return fmt.Errorf("registration: record the request: %w", err)
		}
		created = true
		recorded, err = readRequest(ctx, tx, requestStatement, requestID.String(), string(s.cfg.Realm))
		return err
	})
	if err != nil {
		return RegistrationRequest{}, false, err
	}
	return recorded, created, nil
}

func sameDocument(a, b json.RawMessage) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return string(l) == string(r)
}

// ownsAudience refuses a developer's audience naming a resource the developer does not own.
func (s *Service) ownsAudience(ctx context.Context, tx db.Tx, req Request) error {
	if len(req.Audience) == 0 {
		return nil
	}
	var owned int
	if err := tx.QueryRow(ctx, ownsAllStatement, string(s.cfg.Realm), req.RegisteredBy.String(), req.Audience).Scan(&owned); err != nil {
		return fmt.Errorf("registration: read the audience's owners: %w", err)
	}
	if owned != len(uniqueStrings(req.Audience)) {
		return fmt.Errorf("%w: an application developer's audience names only resources it owns", ErrDeveloperScope)
	}
	return nil
}

// RequestDecision is an approval, a rejection or a withdrawal of one request.
type RequestDecision struct {
	RequestID id.UUID
	Decision  string
	DecidedBy id.UUID
	Reason    string
}

func (d RequestDecision) validate() error {
	switch {
	case d.RequestID.IsNil() || d.DecidedBy.IsNil():
		return fmt.Errorf("%w: a decision names the request and who decides", ErrInvalid)
	case !slices.Contains([]string{DecisionApprove, DecisionReject, DecisionWithdraw}, d.Decision):
		return fmt.Errorf("%w: a request is approved, rejected or withdrawn", ErrInvalid)
	case strings.TrimSpace(d.Reason) == "":
		return fmt.Errorf("%w: a decision requires a reason", ErrInvalid)
	}
	return nil
}

// requestScope is the Idempotency-Key scope of an approved request's registration: the request
// itself, whichever provider approves it, so two approvals register one client.
const requestScope = "registration-request"

// DecideRegistration approves, rejects or withdraws a proposed request. provider is whether the
// caller holds provider authority: approving and rejecting are a provider's, never the proposer's;
// withdrawing is the proposer's alone. An approval registers the document as the proposer's.
func (s *Service) DecideRegistration(ctx context.Context, decision RequestDecision, provider bool) (RegistrationRequest, error) {
	if err := decision.validate(); err != nil {
		return RegistrationRequest{}, err
	}
	var current RegistrationRequest
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		current, err = readRequest(ctx, tx, requestStatement, decision.RequestID.String(), string(s.cfg.Realm))
		return err
	}); err != nil {
		return RegistrationRequest{}, err
	}
	switch {
	case decision.Decision == DecisionWithdraw && current.ProposedBy != decision.DecidedBy:
		return RegistrationRequest{}, ErrNotProposer
	case decision.Decision != DecisionWithdraw && !provider:
		return RegistrationRequest{}, ErrNotProvider
	case decision.Decision != DecisionWithdraw && current.ProposedBy == decision.DecidedBy:
		return RegistrationRequest{}, ErrSelfApproval
	case current.State == RequestApproved && decision.Decision == DecisionApprove &&
		current.DecidedBy != nil && *current.DecidedBy == decision.DecidedBy:
		// The same approval retried after a lost answer.
		return current, nil
	case current.State != RequestProposed:
		return RegistrationRequest{}, fmt.Errorf("%w: it is %s", ErrChangeDecided, current.State)
	}

	at := s.now()
	if decision.Decision != DecisionApprove {
		state := map[string]string{DecisionReject: RequestRejected, DecisionWithdraw: RequestWithdrawn}[decision.Decision]
		err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return decideRequest(ctx, tx, current.ID, state, decision.DecidedBy, decision.Reason, at, nil)
		})
		if err != nil {
			return RegistrationRequest{}, err
		}
		return s.request(ctx, current.ID)
	}

	req, err := requestOf(current.Request)
	if err != nil {
		return RegistrationRequest{}, err
	}
	req.CallerScope, req.IdempotencyKey, req.RegisteredBy = requestScope, current.ID.String(), current.ProposedBy
	grantReason := fmt.Sprintf("named in registration request %s, approved: %s", current.ID, strings.TrimSpace(decision.Reason))
	req.reserved = func(ctx context.Context, tx db.Tx, registration Registration) error {
		if err := eligibleOwners(ctx, tx, current.Owners); err != nil {
			return err
		}
		for _, owner := range current.Owners {
			ownershipID, err := s.newID()
			if err != nil {
				return fmt.Errorf("registration: mint ownership_id: %w", err)
			}
			if _, err := tx.Exec(ctx, grantOwnerStatement, ownershipID.String(), registration.ID.String(),
				owner.String(), decision.DecidedBy.String(), grantReason); err != nil {
				return fmt.Errorf("registration: grant an owner: %w", err)
			}
		}
		return decideRequest(ctx, tx, current.ID, RequestApproved, decision.DecidedBy, decision.Reason, at, &registration.ID)
	}
	_, registerErr := s.Register(ctx, req)
	approved, err := s.request(ctx, current.ID)
	if err != nil {
		return RegistrationRequest{}, err
	}
	if approved.State == RequestApproved {
		// The reservation committed with the approval. A kernel that did not confirm the client leaves
		// the registration pending, which recovery completes; the registration's state says so.
		if registerErr != nil {
			s.logger.Warn("an approved registration request's client was not confirmed by the kernel; recovery completes it",
				"request_id", current.ID.String(), "error", registerErr.Error())
		}
		return approved, nil
	}
	if registerErr == nil {
		registerErr = fmt.Errorf("%w: it is %s", ErrChangeDecided, approved.State)
	}
	return RegistrationRequest{}, registerErr
}

func decideRequest(ctx context.Context, tx db.Tx, requestID id.UUID, state string, by id.UUID, reason string,
	at time.Time, registrationID *id.UUID) error {
	var registration any
	if registrationID != nil {
		registration = registrationID.String()
	}
	tag, err := tx.Exec(ctx, decideRequestStatement, requestID.String(), state, by.String(), strings.TrimSpace(reason),
		at, registration)
	if err != nil {
		return fmt.Errorf("registration: record the decision: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrChangeDecided
	}
	return nil
}

func (s *Service) request(ctx context.Context, requestID id.UUID) (RegistrationRequest, error) {
	var request RegistrationRequest
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		request, err = readRequest(ctx, tx, requestStatement, requestID.String(), string(s.cfg.Realm))
		return err
	})
	return request, err
}

// RequestQueue lists every open request in the realm, oldest first: the approval queue.
func (s *Service) RequestQueue(ctx context.Context) ([]RegistrationRequest, error) {
	var requests []RegistrationRequest
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		requests, err = readRequests(ctx, tx, queueStatement, string(s.cfg.Realm))
		return err
	})
	return requests, err
}

// MyRequests lists the requests the Principal proposed, newest first, at most 100.
func (s *Service) MyRequests(ctx context.Context, principal id.UUID) ([]RegistrationRequest, error) {
	var requests []RegistrationRequest
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		requests, err = readRequests(ctx, tx, mineRequestsStatement, string(s.cfg.Realm), principal.String())
		return err
	})
	return requests, err
}
