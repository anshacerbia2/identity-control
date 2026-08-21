package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// CreateRequest is one Principal creation.
type CreateRequest struct {
	// CallerScope is the authenticated caller the idempotency key is scoped to. A key is
	// per-caller so one caller cannot claim or replay another's, per
	// TDD-foundation-platform-001.
	CallerScope string

	// IdempotencyKey is mandatory. A creation path without one cannot be retried safely,
	// and a caller that cannot retry safely will retry unsafely.
	IdempotencyKey string

	Realm         keycloak.Realm
	Username      string
	Email         string
	SubjectType   keycloak.SubjectType
	WorkloadOwner id.UUID

	// ProviderScope is set by the bootstrap ceremony and by nothing else. ADR-IAM-001 §5.6 keeps
	// the authority for a provider grant in the Organization Platform; validateCreate refuses it
	// on any request that did not come from the ceremony.
	ProviderScope string
}

// Response is what a caller receives. It carries no kernel identifier, and the type is the
// reason: there is no field to populate, so no handler can leak one by mistake.
type Response struct {
	PrincipalID id.UUID              `json:"principal_id"`
	SubjectType keycloak.SubjectType `json:"subject_type"`
	Realm       keycloak.Realm       `json:"realm"`
}

// Config bounds the provisioner's behaviour.
type Config struct {
	// ProvisionTimeout is the upper bound on one kernel call.
	ProvisionTimeout time.Duration

	// PendingRecoveryAfter is the age at which a pending mapping enters recovery. It must
	// exceed ProvisionTimeout, or recovery races the request it is repairing.
	PendingRecoveryAfter time.Duration

	// RecoveryBatch bounds one recovery sweep.
	RecoveryBatch int
}

func (c *Config) applyDefaults() {
	if c.ProvisionTimeout <= 0 {
		c.ProvisionTimeout = 10 * time.Second
	}
	if c.PendingRecoveryAfter <= 0 {
		c.PendingRecoveryAfter = 60 * time.Second
	}
	if c.RecoveryBatch <= 0 {
		c.RecoveryBatch = 100
	}
}

func (c Config) validate() error {
	if c.PendingRecoveryAfter <= c.ProvisionTimeout {
		return fmt.Errorf(
			"provisioning: PendingRecoveryAfter (%s) must exceed ProvisionTimeout (%s), "+
				"or recovery searches the kernel for a user the original request is still creating",
			c.PendingRecoveryAfter, c.ProvisionTimeout)
	}
	return nil
}

// Provisioner mints Principals and repairs the ones whose creation was interrupted.
type Provisioner struct {
	tx     Transactor
	kernel keycloak.AdminClient
	repo   Repository
	cfg    Config
	logger *slog.Logger

	// newID is a seam for tests that need a deterministic or colliding identifier. It is
	// not configuration: production always mints a UUIDv7.
	newID func() (id.UUID, error)
}

// New constructs a Provisioner.
func New(tx Transactor, kernel keycloak.AdminClient, cfg Config, logger *slog.Logger) (*Provisioner, error) {
	if tx == nil {
		return nil, errors.New("provisioning: a transaction source is required")
	}
	if kernel == nil {
		return nil, errors.New("provisioning: a kernel client is required")
	}
	if logger == nil {
		return nil, errors.New("provisioning: a logger is required")
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Provisioner{tx: tx, kernel: kernel, cfg: cfg, logger: logger, newID: id.NewV7}, nil
}

// Create performs the only authorized Principal creation.
//
// The path has one durable checkpoint before the remote call and one after, and the order is
// what makes it recoverable:
//
//	claim the key, mint the identifier, write the pending mapping   — one transaction
//	create the kernel user with the identifier inside the payload   — remote
//	record the kernel identifier, activate, complete the key        — one transaction
//
// The identifier is minted and durable before the kernel is touched, so a crash anywhere
// after the first commit leaves a pending row that names the identifier to search for. The
// alternative — call the kernel first and record afterwards — leaves a user in the kernel
// that nothing on our side can find.
func (p *Provisioner) Create(ctx context.Context, req CreateRequest) (Response, error) {
	if err := validateCreate(req); err != nil {
		return Response{}, err
	}

	digest := requestDigest(req)

	var (
		principalID id.UUID
		replay      *Response
	)

	// Checkpoint one. The claim and the pending mapping commit together: a claimed key
	// with no mapping would report the request in progress forever, and a mapping with no
	// claim would let a retry mint a second identifier.
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		result, claimErr := idempotency.Claim(ctx, tx, req.CallerScope, req.IdempotencyKey, digest)
		switch {
		case errors.Is(claimErr, idempotency.ErrConflict):
			return claimErr
		case errors.Is(claimErr, idempotency.ErrInProgress):
			return claimErr
		case claimErr != nil:
			return claimErr
		}

		if result.State == idempotency.StateReplay {
			stored, decodeErr := decodeStoredResponse(result.Body)
			if decodeErr != nil {
				return decodeErr
			}
			replay = &stored
			return nil
		}

		minted, idErr := p.newID()
		if idErr != nil {
			return fmt.Errorf("provisioning: mint principal_id: %w", idErr)
		}
		principalID = minted

		return p.repo.InsertPending(ctx, tx, Mapping{
			PrincipalID:   minted,
			Realm:         req.Realm,
			Username:      req.Username,
			Email:         req.Email,
			SubjectType:   req.SubjectType,
			WorkloadOwner: req.WorkloadOwner,
		})
	})
	if err != nil {
		return Response{}, err
	}

	// A replayed key performs no remote call. That is the property the exit criterion
	// names, and it is achieved by returning here rather than by a guard further down.
	if replay != nil {
		return *replay, nil
	}

	response := Response{PrincipalID: principalID, SubjectType: req.SubjectType, Realm: req.Realm}

	callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
	defer cancel()

	userID, createErr := p.kernel.CreateUser(callCtx, keycloak.CreateUserRequest{
		Realm:         req.Realm,
		Username:      req.Username,
		Email:         req.Email,
		PrincipalID:   principalID,
		SubjectType:   req.SubjectType,
		WorkloadOwner: req.WorkloadOwner,
		ProviderScope: req.ProviderScope,
	})
	if createErr != nil {
		// The mapping stays pending on purpose. Rolling it back would discard the
		// identifier that is the only way to find the user if the call actually
		// succeeded, which is precisely the ErrAmbiguous case.
		p.logger.WarnContext(ctx, "kernel create did not confirm; mapping left pending for recovery",
			slog.String("principal_id", principalID.String()),
			slog.String("error", createErr.Error()))
		return Response{}, fmt.Errorf("provisioning: create kernel user: %w", createErr)
	}

	// Checkpoint two.
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if activateErr := p.repo.Activate(ctx, tx, principalID, userID); activateErr != nil {
			return activateErr
		}
		body, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			return fmt.Errorf("provisioning: encode stored response: %w", marshalErr)
		}
		return idempotency.Complete(ctx, tx, req.CallerScope, req.IdempotencyKey, digest, 201, body)
	}); err != nil {
		// The kernel user exists and the mapping is still pending. Recovery adopts it
		// rather than creating a second one, which is the crash-recovery case the exit
		// criterion names.
		p.logger.ErrorContext(ctx, "kernel user created but activation did not commit; recovery will adopt it",
			slog.String("principal_id", principalID.String()),
			slog.String("error", err.Error()))
		return Response{}, err
	}

	return response, nil
}

// RecoverPending resolves mappings whose creation was interrupted.
//
// It returns the number of mappings resolved. The three branches are the whole algorithm,
// and the cardinality of the kernel search decides which one runs:
//
//	exactly one match  → adopt it: record the identifier and activate
//	no match           → the create never landed; retry it with the same principal_id
//	more than one      → a uniqueness violation the kernel cannot prevent; quarantine
//
// Retrying with the same identifier is what makes the operation idempotent across a crash
// between the remote call and the local commit. A fresh identifier would create a second
// Principal for one request.
//
// It takes no request. A sweep resolves many mappings, each with its own creation payload,
// so a single request passed in would have applied one caller's username to every mapping it
// touched. The payload is read from the row, which is why identity.principal_mapping carries
// it — recorded as a departure in TDD-identity-control-001.
func (p *Provisioner) RecoverPending(ctx context.Context) (int, error) {
	var pending []Mapping
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var readErr error
		pending, readErr = p.repo.PendingOlderThan(ctx, tx, p.cfg.PendingRecoveryAfter, p.cfg.RecoveryBatch)
		return readErr
	}); err != nil {
		return 0, err
	}

	resolved := 0
	for _, mapping := range pending {
		if err := p.recoverOne(ctx, mapping); err != nil {
			// One unrecoverable mapping does not stop the sweep. A single kernel error
			// would otherwise leave every later mapping unexamined, and the sweep's value
			// is that it is exhaustive.
			p.logger.ErrorContext(ctx, "recovery of one mapping failed; continuing the sweep",
				slog.String("principal_id", mapping.PrincipalID.String()),
				slog.String("error", err.Error()))
			continue
		}
		resolved++
	}
	return resolved, nil
}

func (p *Provisioner) recoverOne(ctx context.Context, mapping Mapping) error {
	callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
	defer cancel()

	found, err := p.kernel.FindByPrincipalID(callCtx, mapping.Realm, mapping.PrincipalID)
	if err != nil {
		return fmt.Errorf("provisioning: search kernel for pending mapping: %w", err)
	}

	switch {
	case len(found) == 1:
		return p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return p.repo.Activate(ctx, tx, mapping.PrincipalID, found[0].ID)
		})

	case len(found) == 0:
		// Rebuilt from the row, with the original identifier. Every field comes from the
		// durable mapping, so the retried call is the same call the interrupted request
		// intended rather than an approximation of it.
		userID, createErr := p.kernel.CreateUser(callCtx, keycloak.CreateUserRequest{
			Realm:         mapping.Realm,
			Username:      mapping.Username,
			Email:         mapping.Email,
			PrincipalID:   mapping.PrincipalID,
			SubjectType:   mapping.SubjectType,
			WorkloadOwner: mapping.WorkloadOwner,
		})
		if createErr != nil {
			return fmt.Errorf("provisioning: retry kernel create: %w", createErr)
		}
		return p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return p.repo.Activate(ctx, tx, mapping.PrincipalID, userID)
		})

	default:
		// Disable every match before quarantining the mapping. Disabling rather than
		// deleting is deliberate: a false positive from a reconciler defect is
		// recoverable and a deleted Principal is not.
		for _, user := range found {
			if disableErr := p.kernel.DisableUser(callCtx, mapping.Realm, user.ID); disableErr != nil {
				return fmt.Errorf("provisioning: disable duplicate %q: %w", user.ID, disableErr)
			}
		}
		if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
			return p.repo.Quarantine(ctx, tx, mapping.PrincipalID,
				fmt.Sprintf("%d kernel users carry this principal_id", len(found)))
		}); err != nil {
			return err
		}
		p.logger.ErrorContext(ctx, "duplicate principal_id in the kernel; both users disabled and mapping quarantined",
			slog.String("principal_id", mapping.PrincipalID.String()),
			slog.Int("matches", len(found)))
		return ErrDuplicateInKernel
	}
}

func validateCreate(req CreateRequest) error {
	switch {
	case req.CallerScope == "":
		return errors.New("provisioning: caller scope is required")
	case req.IdempotencyKey == "":
		return errors.New("provisioning: an Idempotency-Key is required")
	case req.Realm == "":
		return errors.New("provisioning: realm is required")
	case req.Username == "":
		return errors.New("provisioning: username is required")
	case !req.SubjectType.Valid():
		return fmt.Errorf("provisioning: subject_type %q is not human or workload", req.SubjectType)
	case req.SubjectType == keycloak.SubjectWorkload && req.WorkloadOwner.IsNil():
		return errors.New("provisioning: a workload requires an accountable workload_owner")
	case req.SubjectType == keycloak.SubjectHuman && !req.WorkloadOwner.IsNil():
		return errors.New("provisioning: a human must not carry a workload_owner")
	// ADR-IAM-001 §5.6 places the authority for a provider grant in the Organization Platform, so
	// no ordinary creation may carry one. Refused here rather than at the HTTP edge, because a
	// repair script or a future caller reaching this package directly must be held to the same
	// rule as a request — and the ceremony sets the field after this check by design.
	case req.CallerScope != ceremonyScope && req.ProviderScope != "":
		return errors.New("provisioning: only the bootstrap ceremony may grant a provider_scope")
	}
	return nil
}

// requestDigest binds the key to the request that claimed it.
//
// Every field that changes the outcome is included. A key replayed with a different username
// must conflict rather than return the first request's identifier, because the caller asked
// for something else and a stored response would answer the wrong question.
func requestDigest(req CreateRequest) string {
	owner := ""
	if !req.WorkloadOwner.IsNil() {
		owner = req.WorkloadOwner.String()
	}
	return idempotency.Digest(
		[]byte(req.Realm),
		[]byte(req.Username),
		[]byte(req.Email),
		[]byte(req.SubjectType),
		[]byte(owner),
	)
}

func decodeStoredResponse(body json.RawMessage) (Response, error) {
	if len(body) == 0 {
		return Response{}, errors.New("provisioning: replayed key carries no stored response")
	}
	var stored Response
	if err := json.Unmarshal(body, &stored); err != nil {
		return Response{}, fmt.Errorf("provisioning: decode stored response: %w", err)
	}
	if stored.PrincipalID.IsNil() {
		return Response{}, errors.New("provisioning: stored response carries no principal_id")
	}
	return stored, nil
}
