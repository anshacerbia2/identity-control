// Package workload creates workload Principals and keeps their accountable owner
// (TDD-identity-control-004).
//
// A workload is a Principal like a human: one principal_id, minted the same way, carried in its
// token as principal_id with subject_type=workload. What differs is how it reaches the kernel. It
// authenticates as its own client with a registered key and the client credentials grant, and that
// grant issues its token for the client's service-account user. So its Keycloak user is that
// service-account user, never one created with POST /users, and its claim-source attributes are
// written there (TDD-identity-kernel-001 §Claim Projection).
//
// Creation has one durable checkpoint before any kernel call, and it holds everything recovery
// needs: the minted principal_id, the owner, and the reserved client registration, in one
// transaction. A crash anywhere after it leaves a pending workload the scheduled recovery finishes,
// and never a Keycloak user or client whose owner nobody recorded.
//
// What this package does not do yet, and why:
//
//   - The owner is checked as an active human Principal only. Where the workload may act is its
//     Membership, which organization-control grants like any other binding; this service holds no
//     Membership data and does not need any to create an identity.
//   - An agent workload is refused: bounded delegation and the act claim are not built.
//   - Suspension, restoration and retirement are in lifecycle.go; orphan handling, unused detection
//     and overdue reviews in sweep.go; the owner's review in review.go; rebuilding a deleted client in
//     rebuild.go (TDD-identity-control-004 1.5.0).
package workload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

// Types a workload may declare. An agent is representable and refused until delegation is built.
const (
	TypeService   = "service"
	TypeJob       = "job"
	TypeConnector = "connector"
	TypeAgent     = "agent"
)

// States a workload may be in.
const (
	StatePending   = "pending"
	StateActive    = "active"
	StateOrphaned  = "orphaned"
	StateSuspended = "suspended"
	StateRetired   = "retired"
)

var (
	// ErrInvalid is a request a validation rule refuses. Its message names the rule.
	ErrInvalid = errors.New("workload: invalid request")

	// ErrOwnerNotEligible is an owner that is not an active human Principal of this realm.
	ErrOwnerNotEligible = errors.New("workload: the owner must be an active human Principal")

	// ErrAgentNotBuilt is an agent workload, whose bounded delegation is not built. An agent
	// without it would be a workload claiming a capability the platform cannot enforce.
	ErrAgentNotBuilt = errors.New("workload: agent workloads need bounded delegation, which is not built")

	// ErrNotFound is an unknown workload.
	ErrNotFound = errors.New("workload: no such workload")

	// ErrInvalidTransition is a change the workload's state does not permit.
	ErrInvalidTransition = errors.New("workload: the workload's state does not permit this")

	// ErrRefused is a creation refused because an unregistered Keycloak client holds its client_key.
	ErrRefused = errors.New("workload: the client_key is held by a Keycloak client no registration describes")
)

// Transactor is the transaction source this package needs.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Registrar is the registration path a workload's client goes through (TDD-identity-control-003).
type Registrar interface {
	Prepare(ctx context.Context, req registration.Request) (registration.Prepared, error)
	Reserve(ctx context.Context, tx db.Tx, prepared registration.Prepared) (registration.Registration, error)
	Realize(ctx context.Context, prepared registration.Prepared, reserved registration.Registration,
		outcome registration.Outcome) (registration.Registration, keycloak.ClientUUID, error)
	Client(ctx context.Context, registrationID id.UUID) (string, keycloak.ClientUUID, error)

	// The workload lifecycle stops the client through these, inside its own transaction, because
	// the registration lifecycle refuses a workload's client.
	SuspendWorkloadWithin(ctx context.Context, tx db.Tx, change registration.StateChange) error
	RestoreWorkloadWithin(ctx context.Context, tx db.Tx, change registration.StateChange) error
	RetireWorkloadWithin(ctx context.Context, tx db.Tx, change registration.StateChange) error
	ConvergeSuspension(ctx context.Context, registrationID id.UUID) error

	// A rebuild creates the client inside the workload's transaction, and discards it when that
	// transaction fails (TDD-identity-control-004 1.5.0 §Rebuilding a Workload's Client).
	RebuildWorkloadClientWithin(ctx context.Context, tx db.Tx, change registration.StateChange) (keycloak.ClientUUID, error)
	DiscardClient(ctx context.Context, client keycloak.ClientUUID) error
}

// Config bounds the service.
type Config struct {
	Realm keycloak.Realm

	// CallTimeout bounds one Admin API call.
	CallTimeout time.Duration

	// PendingRecoveryAfter is the age at which a pending workload enters recovery. It must exceed
	// CallTimeout, or recovery races the request it is repairing.
	PendingRecoveryAfter time.Duration

	// The workload sweep's thresholds (TDD-identity-control-004 §Configuration): an orphan is
	// escalated after OrphanEscalateAfter and suspended after OrphanSuspendAfter, a workload not seen
	// for UnusedThreshold is unused, and an owner reviews every ReviewInterval. An overdue review is
	// escalated after OrphanEscalateAfter too. Zero takes the default.
	OrphanEscalateAfter time.Duration
	OrphanSuspendAfter  time.Duration
	UnusedThreshold     time.Duration
	ReviewInterval      time.Duration
}

// The defaults TDD-identity-control-004 §Configuration states.
const (
	DefaultOrphanEscalateAfter = 7 * 24 * time.Hour
	DefaultOrphanSuspendAfter  = 30 * 24 * time.Hour
	DefaultUnusedThreshold     = 90 * 24 * time.Hour
	DefaultReviewInterval      = 90 * 24 * time.Hour
)

// Service creates workloads, reads them, and moves their ownership.
//
// It holds two kernel ports because two credentials serve it: the registration credential reads a
// client's service-account user, and the Principal credential writes the workload's identity on that
// user. Neither credential can do the other's half (TDD-identity-control-003 §Security Notes).
type Service struct {
	tx        Transactor
	registrar Registrar
	clients   keycloak.ClientRegistry
	users     keycloak.AdminClient
	repo      provisioning.Repository
	cfg       Config
	logger    *slog.Logger
	newID     func() (id.UUID, error)
	now       func() time.Time
}

// New constructs the service.
func New(tx Transactor, registrar Registrar, clients keycloak.ClientRegistry, users keycloak.AdminClient,
	cfg Config, logger *slog.Logger) (*Service, error) {
	switch {
	case tx == nil:
		return nil, errors.New("workload: a transaction source is required")
	case registrar == nil:
		return nil, errors.New("workload: a registrar is required")
	case clients == nil || users == nil:
		return nil, errors.New("workload: both kernel ports are required")
	case logger == nil:
		return nil, errors.New("workload: a logger is required")
	case cfg.Realm == "":
		return nil, errors.New("workload: a realm is required")
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 10 * time.Second
	}
	if cfg.PendingRecoveryAfter <= 0 {
		cfg.PendingRecoveryAfter = 60 * time.Second
	}
	if cfg.OrphanEscalateAfter <= 0 {
		cfg.OrphanEscalateAfter = DefaultOrphanEscalateAfter
	}
	if cfg.OrphanSuspendAfter <= 0 {
		cfg.OrphanSuspendAfter = DefaultOrphanSuspendAfter
	}
	if cfg.UnusedThreshold <= 0 {
		cfg.UnusedThreshold = DefaultUnusedThreshold
	}
	if cfg.ReviewInterval <= 0 {
		cfg.ReviewInterval = DefaultReviewInterval
	}
	if cfg.OrphanEscalateAfter >= cfg.OrphanSuspendAfter {
		return nil, fmt.Errorf("workload: OrphanEscalateAfter (%s) must be shorter than OrphanSuspendAfter (%s)",
			cfg.OrphanEscalateAfter, cfg.OrphanSuspendAfter)
	}
	if cfg.PendingRecoveryAfter <= cfg.CallTimeout {
		return nil, fmt.Errorf("workload: PendingRecoveryAfter (%s) must exceed CallTimeout (%s)",
			cfg.PendingRecoveryAfter, cfg.CallTimeout)
	}
	return &Service{tx: tx, registrar: registrar, clients: clients, users: users, cfg: cfg, logger: logger,
		newID: id.NewV7, now: func() time.Time { return time.Now().UTC() }}, nil
}

// CreateRequest is one workload creation.
type CreateRequest struct {
	// CallerScope and IdempotencyKey make the creation retryable.
	CallerScope    string
	IdempotencyKey string

	// CreatedBy is the authenticated caller, recorded on the workload and as the registering
	// Principal of its client.
	CreatedBy id.UUID

	DisplayName   string          `json:"display_name"`
	Purpose       string          `json:"purpose"`
	WorkloadType  string          `json:"workload_type"`
	Owner         id.UUID         `json:"owner_principal_id"`
	TeamReference string          `json:"team_reference"`
	ClientKey     string          `json:"client_key"`
	Application   string          `json:"application_ref"`
	Audience      []string        `json:"audience"`
	PublicKey     json.RawMessage `json:"public_key"`
}

// Workload is a workload as the API reports it. It carries no kernel identifier and nothing secret.
type Workload struct {
	PrincipalID     id.UUID    `json:"principal_id"`
	RegistrationID  id.UUID    `json:"registration_id"`
	ClientKey       string     `json:"client_key"`
	DisplayName     string     `json:"display_name"`
	Purpose         string     `json:"purpose"`
	WorkloadType    string     `json:"workload_type"`
	Owner           id.UUID    `json:"owner_principal_id"`
	TeamReference   string     `json:"team_reference,omitempty"`
	OwnerRecordedAt time.Time  `json:"owner_recorded_at"`
	State           string     `json:"state"`
	OrphanedAt      *time.Time `json:"orphaned_at"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	CreatedBy       id.UUID    `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	ActivatedAt     *time.Time `json:"activated_at"`

	// LastReviewedAt is the owner's latest review, and ReviewDueAt when the next is due, for an active
	// or orphaned workload (TDD-identity-control-004 1.5.0 §Periodic Review).
	LastReviewedAt *time.Time `json:"last_reviewed_at"`
	ReviewDueAt    *time.Time `json:"review_due_at,omitempty"`
}

const (
	maxDisplayName   = 200
	maxPurpose       = 2000
	maxTeamReference = 200
)

func validate(req CreateRequest) error {
	invalid := func(rule string) error { return fmt.Errorf("%w: %s", ErrInvalid, rule) }
	switch {
	case strings.TrimSpace(req.CallerScope) == "" || strings.TrimSpace(req.IdempotencyKey) == "":
		return invalid("a caller and an Idempotency-Key are required")
	case req.CreatedBy.IsNil():
		return invalid("the creating Principal is required")
	case strings.TrimSpace(req.DisplayName) == "" || len(req.DisplayName) > maxDisplayName:
		return invalid(fmt.Sprintf("display_name is required, at most %d characters", maxDisplayName))
	case strings.TrimSpace(req.Purpose) == "" || len(req.Purpose) > maxPurpose:
		return invalid(fmt.Sprintf("purpose is required, at most %d characters: a workload whose purpose nobody wrote down is one nobody can decide to retire", maxPurpose))
	case len(req.TeamReference) > maxTeamReference:
		return invalid(fmt.Sprintf("team_reference is at most %d characters", maxTeamReference))
	case req.Owner.IsNil():
		return invalid("owner_principal_id is required: every workload has an accountable human owner (STD-IAM-001 §3.7)")
	}
	switch req.WorkloadType {
	case TypeService, TypeJob, TypeConnector:
	case TypeAgent:
		return ErrAgentNotBuilt
	default:
		return invalid("workload_type must be service, job or connector")
	}
	return nil
}

func digest(req CreateRequest) string {
	body, _ := json.Marshal(struct {
		CreateRequest
		CreatedBy string
		Owner     string
	}{req, req.CreatedBy.String(), req.Owner.String()})
	return idempotency.Digest(body)
}

func call[T any](ctx context.Context, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(callCtx)
}

// Create performs the one authorized workload creation.
//
//	claim the key, check the owner, mint the principal_id,
//	reserve the client registration, record the workload pending    — one transaction
//	create the workload's client, holding its public key             — remote, registration credential
//	write the workload's identity on the client's service account    — remote, Principal credential
//	record the mapping, activate the workload, complete the key      — one transaction
func (s *Service) Create(ctx context.Context, req CreateRequest) (Workload, error) {
	if err := validate(req); err != nil {
		return Workload{}, err
	}
	prepared, err := s.registrar.Prepare(ctx, registration.Request{
		RegisteredBy: req.CreatedBy, ClientKey: req.ClientKey, Profile: registration.ProfileWorkload,
		AudienceClass: "workload", ApplicationRef: req.Application, Audience: req.Audience, PublicKey: req.PublicKey,
	})
	if err != nil {
		return Workload{}, err
	}

	requestDigest := digest(req)
	var (
		created  Workload
		reserved registration.Registration
		replay   bool
	)
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		claim, err := idempotency.Claim(ctx, tx, req.CallerScope, req.IdempotencyKey, requestDigest)
		if err != nil {
			return err
		}
		if claim.State == idempotency.StateReplay {
			replay = true
			if claim.Status != 201 {
				return ErrRefused
			}
			return json.Unmarshal(claim.Body, &created)
		}
		if err := s.ownerEligible(ctx, tx, req.Owner); err != nil {
			return err
		}
		principalID, err := s.newID()
		if err != nil {
			return fmt.Errorf("workload: mint principal_id: %w", err)
		}
		if reserved, err = s.registrar.Reserve(ctx, tx, prepared); err != nil {
			return err
		}
		created = Workload{PrincipalID: principalID, RegistrationID: reserved.ID, ClientKey: reserved.ClientKey,
			DisplayName: strings.TrimSpace(req.DisplayName), Purpose: strings.TrimSpace(req.Purpose),
			WorkloadType: req.WorkloadType, Owner: req.Owner, TeamReference: strings.TrimSpace(req.TeamReference),
			State: StatePending, CreatedBy: req.CreatedBy}
		return insertPending(ctx, tx, created, req.CallerScope, req.IdempotencyKey, requestDigest)
	})
	if err != nil || replay {
		return created, err
	}

	pending := pendingWorkload{Workload: created, scope: req.CallerScope, key: req.IdempotencyKey, digest: requestDigest}
	_, client, err := s.registrar.Realize(ctx, prepared, reserved, registration.Outcome{
		Refused: func(ctx context.Context, tx db.Tx) error { return s.refuse(ctx, tx, pending) },
	})
	if errors.Is(err, registration.ErrKeyTaken) {
		return Workload{}, ErrRefused
	}
	if err != nil {
		s.logger.WarnContext(ctx, "the workload's client did not confirm; the workload is left pending for recovery",
			slog.String("principal_id", created.PrincipalID.String()), slog.String("error", err.Error()))
		return Workload{}, err
	}
	bound, err := s.bind(ctx, pending, client)
	if err != nil {
		// Left pending on purpose: recovery binds it, and completes the caller's key.
		s.logger.WarnContext(ctx, "the workload's identity was not bound; the workload is left pending for recovery",
			slog.String("principal_id", created.PrincipalID.String()), slog.String("error", err.Error()))
		return Workload{}, err
	}
	return bound, nil
}

const ownerStatement = `SELECT subject_type, state FROM identity.principal_mapping
WHERE principal_id = $1 AND realm = $2`

// ownerEligible holds the owner to what this service knows: an active human Principal of this realm.
// A workload cannot own a workload, because accountability that ends at a machine ends nowhere.
func (s *Service) ownerEligible(ctx context.Context, tx db.Tx, owner id.UUID) error {
	rows, err := tx.Query(ctx, ownerStatement, owner.String(), string(s.cfg.Realm))
	if err != nil {
		return fmt.Errorf("workload: read the owner: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return ErrOwnerNotEligible
	}
	var subjectType, state string
	if err := rows.Scan(&subjectType, &state); err != nil {
		return err
	}
	if subjectType != string(keycloak.SubjectHuman) || state != string(provisioning.StateActive) {
		return ErrOwnerNotEligible
	}
	return nil
}

// pendingWorkload is a pending workload with the idempotency claim its creation holds.
type pendingWorkload struct {
	Workload
	scope, key, digest string
}

// bind writes the workload's identity on its client's service-account user, records the mapping to
// that user, activates the workload, and completes the creating request's key. Every step is
// idempotent, so recovery runs it again safely after a crash anywhere inside it.
func (s *Service) bind(ctx context.Context, pending pendingWorkload, client keycloak.ClientUUID) (Workload, error) {
	serviceAccount, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (keycloak.User, error) {
		return s.clients.ServiceAccountUser(ctx, s.cfg.Realm, client)
	})
	if err != nil {
		return Workload{}, fmt.Errorf("workload: read the client's service-account user: %w", err)
	}
	if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
		return struct{}{}, s.users.WriteWorkloadIdentity(ctx, s.cfg.Realm, serviceAccount.ID, pending.PrincipalID, pending.Owner)
	}); err != nil {
		return Workload{}, fmt.Errorf("workload: write the workload's identity: %w", err)
	}

	var active Workload
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		// Counted first, as the Principal path does: Repository.Find reads one row and has no
		// not-found answer of its own. A mapping already written is a bind that ran before.
		var mapped int
		if err := tx.QueryRow(ctx, mappingCountStatement, pending.PrincipalID.String()).Scan(&mapped); err != nil {
			return fmt.Errorf("workload: read the mapping: %w", err)
		}
		if mapped == 0 {
			if err := s.repo.InsertPending(ctx, tx, provisioning.Mapping{
				PrincipalID: pending.PrincipalID, Realm: s.cfg.Realm, Username: serviceAccount.Username,
				SubjectType: keycloak.SubjectWorkload, WorkloadOwner: pending.Owner,
			}); err != nil {
				return err
			}
			if err := s.repo.Activate(ctx, tx, pending.PrincipalID, serviceAccount.ID); err != nil {
				return err
			}
		} else {
			mapping, err := s.repo.Find(ctx, tx, pending.PrincipalID)
			if err != nil {
				return err
			}
			if mapping.KeycloakUserID != serviceAccount.ID {
				return fmt.Errorf("workload: %s is mapped to another Keycloak user", pending.PrincipalID)
			}
		}
		tag, err := tx.Exec(ctx, activateStatement, pending.PrincipalID.String(), s.now())
		if err != nil {
			return fmt.Errorf("workload: activate: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: %s is no longer pending", ErrInvalidTransition, pending.PrincipalID)
		}
		if active, err = s.read(ctx, tx, pending.PrincipalID); err != nil {
			return err
		}
		body, err := json.Marshal(active)
		if err != nil {
			return err
		}
		return idempotency.Complete(ctx, tx, pending.scope, pending.key, pending.digest, 201, body)
	})
	if err != nil {
		return Workload{}, err
	}
	s.logger.InfoContext(ctx, "a workload was created",
		slog.String("principal_id", active.PrincipalID.String()), slog.String("client_key", active.ClientKey))
	return active, nil
}

// refuse retires a pending workload whose client_key an unregistered client holds, and completes the
// creating request's key with the refusal, in the transaction that retires its registration.
func (s *Service) refuse(ctx context.Context, tx db.Tx, pending pendingWorkload) error {
	if _, err := tx.Exec(ctx, retirePendingStatement, pending.PrincipalID.String()); err != nil {
		return fmt.Errorf("workload: retire the refused workload: %w", err)
	}
	return idempotency.Complete(ctx, tx, pending.scope, pending.key, pending.digest, 409,
		json.RawMessage(`{"error":"client_key in use by an unregistered Keycloak client"}`))
}

// RecoverPending finishes workloads whose creation was interrupted, and returns how many it
// finished. It runs after pending registrations are recovered, so a workload whose client creation
// was lost finds its registration active, and binds its identity. One failure does not stop the
// others.
func (s *Service) RecoverPending(ctx context.Context) (int, error) {
	var pending []pendingWorkload
	if err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		pending, err = pendingOlderThan(ctx, tx, s.now().Add(-s.cfg.PendingRecoveryAfter), string(s.cfg.Realm))
		return err
	}); err != nil {
		return 0, fmt.Errorf("workload: read pending workloads: %w", err)
	}
	resolved := 0
	for _, workload := range pending {
		state, client, err := s.registrar.Client(ctx, workload.RegistrationID)
		switch {
		case err != nil:
			s.logger.ErrorContext(ctx, "a pending workload's registration could not be read; continuing",
				slog.String("principal_id", workload.PrincipalID.String()), slog.String("error", err.Error()))
			continue
		case state == "pending":
			// Its client is not realized yet; registration recovery resolves it first.
			continue
		case state == "retired":
			err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error { return s.refuse(ctx, tx, workload) })
		case state == "active":
			_, err = s.bind(ctx, workload, client)
		default:
			err = fmt.Errorf("workload: its registration is %s", state)
		}
		if err != nil {
			s.logger.ErrorContext(ctx, "recovery of one workload failed; continuing",
				slog.String("principal_id", workload.PrincipalID.String()), slog.String("error", err.Error()))
			continue
		}
		resolved++
	}
	return resolved, nil
}

// Get reads one workload.
func (s *Service) Get(ctx context.Context, principalID id.UUID) (Workload, error) {
	var workload Workload
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		workload, err = s.read(ctx, tx, principalID)
		return err
	})
	return workload, err
}

// ReassignRequest moves a workload to a new accountable owner.
type ReassignRequest struct {
	PrincipalID id.UUID
	NewOwner    id.UUID
	ChangedBy   id.UUID
	Reason      string
}

// Reassign moves a workload to a new owner: an active human Principal other than the current one.
// It writes the new owner on the workload's service-account user inside the transaction that records
// it, so the token and the record never name two owners, and it clears an orphaned workload back to
// active. The change is recorded, insert-only, with who made it and why.
func (s *Service) Reassign(ctx context.Context, req ReassignRequest) (Workload, error) {
	switch {
	case req.NewOwner.IsNil() || req.ChangedBy.IsNil():
		return Workload{}, fmt.Errorf("%w: a reassignment names the new owner and the Principal making it", ErrInvalid)
	case strings.TrimSpace(req.Reason) == "":
		return Workload{}, fmt.Errorf("%w: a reassignment requires a reason", ErrInvalid)
	case req.NewOwner == req.PrincipalID:
		return Workload{}, ErrOwnerNotEligible
	}
	changeID, err := s.newID()
	if err != nil {
		return Workload{}, fmt.Errorf("workload: mint change_id: %w", err)
	}

	var moved Workload
	err = s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		locked, err := s.lock(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		switch {
		case locked.State != StateActive && locked.State != StateOrphaned:
			return fmt.Errorf("%w: a %s workload cannot be reassigned", ErrInvalidTransition, locked.State)
		case locked.Owner == req.NewOwner:
			return fmt.Errorf("%w: the workload is already owned by that Principal", ErrInvalid)
		}
		if err := s.ownerEligible(ctx, tx, req.NewOwner); err != nil {
			return err
		}
		mapping, err := s.repo.Find(ctx, tx, req.PrincipalID)
		if err != nil {
			return err
		}
		if _, err := call(ctx, s.cfg.CallTimeout, func(ctx context.Context) (struct{}, error) {
			return struct{}{}, s.users.WriteWorkloadIdentity(ctx, s.cfg.Realm, mapping.KeycloakUserID, req.PrincipalID, req.NewOwner)
		}); err != nil {
			return fmt.Errorf("workload: write the new owner: %w", err)
		}
		now := s.now()
		if _, err := tx.Exec(ctx, reassignStatement, req.PrincipalID.String(), req.NewOwner.String(), now); err != nil {
			return fmt.Errorf("workload: record the new owner: %w", err)
		}
		if err := s.repo.SetWorkloadOwner(ctx, tx, req.PrincipalID, req.NewOwner); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, ownerChangeStatement, changeID.String(), req.PrincipalID.String(),
			locked.Owner.String(), req.NewOwner.String(), req.ChangedBy.String(), strings.TrimSpace(req.Reason), now); err != nil {
			return fmt.Errorf("workload: record the change of owner: %w", err)
		}
		moved, err = s.read(ctx, tx, req.PrincipalID)
		return err
	})
	if err != nil {
		return Workload{}, err
	}
	s.logger.WarnContext(ctx, "a workload was reassigned to a new owner",
		slog.String("principal_id", moved.PrincipalID.String()))
	return moved, nil
}
