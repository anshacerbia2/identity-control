package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"
	"github.com/anshacerbia2/foundation-platform/idempotency"

	"github.com/anshacerbia2/identity-control/internal/reconcile"
	"github.com/anshacerbia2/identity-control/internal/registration"
)

// AdministrativeReasonHeader carries why an operator is overriding what the reconciler decided.
// It is recorded on the finding it resolves.
const AdministrativeReasonHeader = "X-Administrative-Reason"

// Reconciler is the registration drift surface (TDD-identity-control-003 §API / Interface).
type Reconciler interface {
	Status(ctx context.Context) (reconcile.Status, error)
	FindingsFor(ctx context.Context, registration id.UUID) ([]reconcile.Finding, error)
	Sweep(ctx context.Context) (reconcile.Run, error)
	Resolve(ctx context.Context, resolution reconcile.Resolution) error
	GrantException(ctx context.Context, exception reconcile.Exception, lasting time.Duration) (reconcile.Exception, error)
	ExceptionsFor(ctx context.Context, registration id.UUID) ([]reconcile.Exception, error)
}

// Registrar is the registration path (TDD-identity-control-003 §Registration Path).
type Registrar interface {
	Register(ctx context.Context, req registration.Request) (registration.Registration, error)
	Get(ctx context.Context, registrationID id.UUID) (registration.Registration, error)
	List(ctx context.Context, query registration.ListQuery) (registration.Page, error)

	// The client key surface (TDD-identity-control-003 §Client Key Rotation).
	Keys(ctx context.Context, registrationID id.UUID) ([]registration.Key, error)
	AddKey(ctx context.Context, registrationID id.UUID, publicKey json.RawMessage, by id.UUID) ([]registration.Key, bool, error)
	RevokeKey(ctx context.Context, registrationID, keyID, by id.UUID, reason string) ([]registration.Key, error)

	// Adopt brings a client created before this service existed under registration (ADR-IAM-001
	// §5.12, TDD-identity-control-003 §Adoption).
	Adopt(ctx context.Context, req registration.AdoptRequest) (registration.AdoptResult, error)

	// The lifecycle (ADR-IAM-001 §5.13, TDD-identity-control-003 §Suspension, Restoration, and
	// Retirement).
	Suspend(ctx context.Context, change registration.StateChange) (registration.Registration, error)
	Restore(ctx context.Context, change registration.StateChange) (registration.Registration, error)
	Retire(ctx context.Context, change registration.StateChange) (registration.Registration, error)

	// ExpiringKeys is the key expiry warning (TDD-identity-control-003 §Key Expiry Warnings).
	ExpiringKeys(ctx context.Context) (registration.Expiring, error)

	// Ownership (ADR-IAM-003, TDD-identity-control-003 §Registration Ownership).
	Owns(ctx context.Context, principal, registrationID id.UUID) (bool, error)
	Mine(ctx context.Context, principal id.UUID) ([]registration.Registration, error)
	Owners(ctx context.Context, registrationID id.UUID) ([]registration.Owner, error)
	GrantOwner(ctx context.Context, change registration.OwnershipChange) ([]registration.Owner, error)
	RevokeOwner(ctx context.Context, change registration.OwnershipChange) ([]registration.Owner, error)
}

// Registrations serves the registration and drift routes.
type Registrations struct {
	registrar  Registrar
	reconciler Reconciler
}

// NewRegistrations constructs the handler.
func NewRegistrations(registrar Registrar, reconciler Reconciler) (*Registrations, error) {
	if registrar == nil {
		return nil, errors.New("httpapi: a registrar is required")
	}
	if reconciler == nil {
		return nil, errors.New("httpapi: a reconciler is required")
	}
	return &Registrations{registrar: registrar, reconciler: reconciler}, nil
}

// registerRequest is the wire shape. The realm, the Application authority, the signing algorithm
// and the registering Principal are absent on purpose: configuration, the interim manual
// authority, the PS256 baseline, and the authenticated caller decide them.
type registerRequest struct {
	ClientKey      string          `json:"client_key"`
	Profile        string          `json:"profile"`
	AudienceClass  string          `json:"audience_class"`
	ApplicationRef string          `json:"application_ref"`
	LifetimeClass  string          `json:"lifetime_class"`
	Audience       []string        `json:"audience"`
	RedirectURIs   []string        `json:"redirect_uris"`
	PublicKey      json.RawMessage `json:"public_key"`
}

// Register handles POST /v1/registrations.
func (h *Registrations) Register(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	key, ok := idempotencyKey(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.ValidationFailed,
			"A non-empty Idempotency-Key header of at most 255 characters is required")
		return
	}
	var body registerRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid registration document")
		return
	}
	scope, _ := CallerScope(r.Context())
	created, err := h.registrar.Register(r.Context(), registration.Request{
		CallerScope: scope, IdempotencyKey: key, RegisteredBy: principal,
		ClientKey: body.ClientKey, Profile: body.Profile, AudienceClass: body.AudienceClass,
		ApplicationRef: body.ApplicationRef, LifetimeClass: body.LifetimeClass,
		Audience: body.Audience, RedirectURIs: body.RedirectURIs, PublicKey: body.PublicKey,
	})
	if err != nil {
		writeRegistrationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// adoptRequest is the registration document with the keys the client already holds, a plan-only
// switch, and the repairable field classes the caller accepts converging.
type adoptRequest struct {
	ClientKey      string            `json:"client_key"`
	Profile        string            `json:"profile"`
	AudienceClass  string            `json:"audience_class"`
	ApplicationRef string            `json:"application_ref"`
	LifetimeClass  string            `json:"lifetime_class"`
	Audience       []string          `json:"audience"`
	RedirectURIs   []string          `json:"redirect_uris"`
	PublicKeys     []json.RawMessage `json:"public_keys"`
	DryRun         bool              `json:"dry_run"`
	Converge       []string          `json:"converge"`
}

// Adopt handles POST /v1/registrations:adopt. A dry run answers 200 with the plan and changes
// nothing; an adoption answers 201 with the plan and the registration. A refusal names the field
// class that stopped it, and a dry run shows the whole plan.
func (h *Registrations) Adopt(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "An adoption requires an X-Administrative-Reason header")
		return
	}
	var body adoptRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid adoption document")
		return
	}
	key := ""
	if !body.DryRun {
		var ok bool
		if key, ok = idempotencyKey(r); !ok {
			httpapi.Problem(w, r, httpapi.ValidationFailed,
				"An adoption requires a non-empty Idempotency-Key header of at most 255 characters")
			return
		}
	}
	scope, _ := CallerScope(r.Context())
	result, err := h.registrar.Adopt(r.Context(), registration.AdoptRequest{
		Request: registration.Request{CallerScope: scope, IdempotencyKey: key, RegisteredBy: principal,
			ClientKey: body.ClientKey, Profile: body.Profile, AudienceClass: body.AudienceClass,
			ApplicationRef: body.ApplicationRef, LifetimeClass: body.LifetimeClass, Audience: body.Audience,
			RedirectURIs: body.RedirectURIs},
		PublicKeys: body.PublicKeys, Reason: reason, DryRun: body.DryRun, Converge: body.Converge,
	})
	switch {
	case errors.Is(err, registration.ErrNotAdoptable):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "Not adopted: "+result.Plan.Refusal)
	case errors.Is(err, registration.ErrNoClient):
		httpapi.Problem(w, r, httpapi.NotFound, "No Keycloak client holds that client_key")
	case errors.Is(err, registration.ErrKeyTaken):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "The client_key is already registered")
	case err != nil:
		writeRegistrationError(w, r, err)
	case body.DryRun:
		writeJSON(w, http.StatusOK, result)
	default:
		writeJSON(w, http.StatusCreated, result)
	}
}

// GetRegistration handles GET /v1/registrations/{registration_id}.
func (h *Registrations) GetRegistration(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	registrationID, err := id.Parse(r.PathValue("registration_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	found, err := h.registrar.Get(r.Context(), registrationID)
	if err != nil {
		writeRegistrationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, found)
}

// ListRegistrations handles GET /v1/registrations: one page of the realm's registrations in
// creation order, `?after=<registration_id>&limit=<1..100>&state=<state>`. The cursor is a
// registration_id, never an offset (STD-GLB-001 §Pagination).
func (h *Registrations) ListRegistrations(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	params := r.URL.Query()
	query := registration.ListQuery{State: params.Get("state")}
	if raw := params.Get("after"); raw != "" {
		after, err := id.Parse(raw)
		if err != nil {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "after is not a valid registration_id")
			return
		}
		query.After = after
	}
	if raw := params.Get("limit"); raw != "" {
		// Zero is how the service is asked for its default, so a written limit must be at least one:
		// a caller who writes zero is asking for nothing, not for fifty.
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "limit must be a whole number of at least 1")
			return
		}
		query.Limit = limit
	}
	page, err := h.registrar.List(r.Context(), query)
	if err != nil {
		if errors.Is(err, registration.ErrInvalid) {
			httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
			return
		}
		httpapi.Problem(w, r, httpapi.Internal, "The registrations could not be read")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// Findings handles GET /v1/registrations/{registration_id}/findings: that client's divergences,
// newest first, converged ones included.
func (h *Registrations) Findings(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	registrationID, err := id.Parse(r.PathValue("registration_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	findings, err := h.reconciler.FindingsFor(r.Context(), registrationID)
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The findings could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

func writeRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, registration.ErrInvalid), errors.Is(err, registration.ErrScopeUndeclared),
		errors.Is(err, registration.ErrPrivateKey):
		// Each message names a rule, never a stored or submitted value: a refused key is never
		// echoed, and a private one least of all.
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, registration.ErrKeyTaken):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"The client_key is registered, or held by a Keycloak client no registration describes")
	case errors.Is(err, registration.ErrKeyInUse):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"The public key is already registered, to this client or another; a revoked key is never registered again")
	case errors.Is(err, registration.ErrRotationInProgress):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"A key is still retiring; register the next key after its overlap ends, or revoke it first")
	case errors.Is(err, registration.ErrNotKeyed):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "A public client or a resource holds no key")
	case errors.Is(err, registration.ErrNotActive):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "The registration is not active")
	case errors.Is(err, registration.ErrKeyNotLive):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"The key is not an active or retiring key of this registration")
	case errors.Is(err, registration.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such registration")
	case errors.Is(err, idempotency.ErrConflict):
		httpapi.Problem(w, r, httpapi.IdempotencyKeyConflict, "The key was first used with a different request")
	case errors.Is(err, idempotency.ErrInProgress):
		httpapi.Problem(w, r, httpapi.RequestInProgress,
			"An identical request is already in progress; retry after it completes")
	default:
		httpapi.Problem(w, r, httpapi.DependencyUnavailable,
			"The identity kernel did not confirm the registration; retry with the same Idempotency-Key")
	}
}

// Keys handles GET /v1/registrations/{registration_id}/keys: the client's public keys, newest first,
// revoked ones included.
func (h *Registrations) Keys(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	registrationID, err := id.Parse(r.PathValue("registration_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	keys, err := h.registrar.Keys(r.Context(), registrationID)
	if err != nil {
		writeRegistrationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

type addKeyRequest struct {
	PublicKey json.RawMessage `json:"public_key"`
}

// AddKey handles POST /v1/registrations/{registration_id}/keys: the next public key, which starts a
// rotation. It answers 201 when the key was added, and 200 when it already was the client's active
// key, which is how a retry after a lost response is told the rotation happened.
func (h *Registrations) AddKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	registrationID, err := id.Parse(r.PathValue("registration_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	var body addKeyRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid key document")
		return
	}
	keys, added, err := h.registrar.AddKey(r.Context(), registrationID, body.PublicKey, principal)
	if err != nil {
		writeRegistrationError(w, r, err)
		return
	}
	status := http.StatusOK
	if added {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"keys": keys})
}

// RegistrationAction handles POST /v1/registrations/{registration_id}:suspend, :restore and :retire.
// The action is part of the last segment, because the mux matches whole segments.
func (h *Registrations) RegistrationAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	raw, action, _ := strings.Cut(r.PathValue("registration_id"), ":")
	var apply func(context.Context, registration.StateChange) (registration.Registration, error)
	switch action {
	case "suspend":
		apply = h.registrar.Suspend
	case "restore":
		apply = h.registrar.Restore
	case "retire":
		apply = h.registrar.Retire
	default:
		httpapi.Problem(w, r, httpapi.NotFound, "No such registration action")
		return
	}
	registrationID, err := id.Parse(raw)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A lifecycle action requires an X-Administrative-Reason header")
		return
	}
	changed, err := apply(r.Context(), registration.StateChange{RegistrationID: registrationID, ChangedBy: principal,
		Reason: reason})
	if err != nil {
		writeLifecycleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, changed)
}

func writeLifecycleError(w http.ResponseWriter, r *http.Request, err error) {
	var inUse *registration.ResourceInUseError
	switch {
	case errors.As(err, &inUse):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"The resource is in the audience of other registrations: "+strings.Join(inUse.Dependents, ", "))
	case errors.Is(err, registration.ErrWorkloadLifecycle):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused,
			"A workload's client is suspended, restored or retired through its workload")
	case errors.Is(err, registration.ErrInvalidTransition):
		// The message names the rule and the state, never a stored value.
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, err.Error())
	case errors.Is(err, registration.ErrInvalid):
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, registration.ErrNotFound):
		httpapi.Problem(w, r, httpapi.NotFound, "No such registration")
	default:
		httpapi.Problem(w, r, httpapi.DependencyUnavailable,
			"The identity kernel did not confirm the change; retry the same action")
	}
}

// KeyAction handles POST /v1/registrations/{registration_id}/keys/{key_id}:revoke. The action is
// part of the last segment, as it is for Principals, because the mux matches whole segments.
func (h *Registrations) KeyAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	registrationID, err := id.Parse(r.PathValue("registration_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	rawKey, action, _ := strings.Cut(r.PathValue("key_action"), ":")
	if action != "revoke" {
		httpapi.Problem(w, r, httpapi.NotFound, "No such key action")
		return
	}
	keyID, err := id.Parse(rawKey)
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "key_id is not a valid identifier")
		return
	}
	reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
	if reason == "" {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "Revoking a key requires an X-Administrative-Reason header")
		return
	}
	keys, err := h.registrar.RevokeKey(r.Context(), registrationID, keyID, principal, reason)
	if err != nil {
		writeRegistrationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// callerPrincipal is the authenticated Principal, which a resolution and an exception record.
func callerPrincipal(r *http.Request) (id.UUID, bool) {
	scope, ok := CallerScope(r.Context())
	if !ok {
		return id.UUID{}, false
	}
	raw, ok := strings.CutPrefix(scope, "principal:")
	if !ok {
		return id.UUID{}, false
	}
	principal, err := id.Parse(raw)
	if err != nil {
		return id.UUID{}, false
	}
	return principal, true
}

// Drift handles GET /v1/registrations:drift: the last run first, then every open finding.
func (h *Registrations) Drift(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	status, err := h.reconciler.Status(r.Context())
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The drift status could not be read")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// ExpiringKeys handles GET /v1/registrations:expiring-keys: every active keyed registration whose
// active key expires within the warning threshold, or which holds none, most urgent first.
func (h *Registrations) ExpiringKeys(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	expiring, err := h.registrar.ExpiringKeys(r.Context())
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The expiring keys could not be read")
		return
	}
	writeJSON(w, http.StatusOK, expiring)
}

type reconcileRequest struct {
	Findings []string `json:"findings"`
}

type reconcileResponse struct {
	Run      *reconcile.Run   `json:"run"`
	Status   reconcile.Status `json:"status"`
	Deferred bool             `json:"deferred,omitempty"`
}

// Reconcile handles POST /v1/registrations:reconcile. It runs a sweep now. Naming findings, with
// X-Administrative-Reason, also applies desired state to those blocked or unattributed findings
// first, which a scheduled sweep never does on its own.
func (h *Registrations) Reconcile(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	var body reconcileRequest
	if r.ContentLength != 0 {
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid reconcile document")
			return
		}
	}

	if len(body.Findings) > 0 {
		reason := strings.TrimSpace(r.Header.Get(AdministrativeReasonHeader))
		if reason == "" {
			httpapi.Problem(w, r, httpapi.ValidationFailed,
				"Applying desired state to findings requires an X-Administrative-Reason header")
			return
		}
		findings := make([]id.UUID, 0, len(body.Findings))
		for _, raw := range body.Findings {
			finding, err := id.Parse(raw)
			if err != nil {
				httpapi.Problem(w, r, httpapi.ValidationFailed, "A named finding is not a valid identifier")
				return
			}
			findings = append(findings, finding)
		}
		if err := h.reconciler.Resolve(r.Context(), reconcile.Resolution{
			Findings: findings, ResolvedBy: principal, Reason: reason}); err != nil {
			writeReconcileError(w, r, err)
			return
		}
	}

	response := reconcileResponse{}
	run, err := h.reconciler.Sweep(r.Context())
	switch {
	case errors.Is(err, reconcile.ErrSweepInProgress):
		// Another replica is sweeping. The resolution above is recorded either way, and that
		// sweep, or the next, reports the rest.
		response.Deferred = true
	case err != nil:
		writeReconcileError(w, r, err)
		return
	default:
		response.Run = &run
	}
	if response.Status, err = h.reconciler.Status(r.Context()); err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The drift status could not be read")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type exceptionRequest struct {
	FieldClass      string `json:"field_class"`
	Actor           string `json:"actor"`
	Reason          string `json:"reason"`
	DurationSeconds int    `json:"duration_seconds"`
}

// GrantException handles POST /v1/registrations/{registration_id}/drift-exceptions.
func (h *Registrations) GrantException(w http.ResponseWriter, r *http.Request) {
	principal, ok := callerPrincipal(r)
	if !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	registration, err := id.Parse(r.PathValue("registration_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	var body exceptionRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The request body is not a valid drift exception document")
		return
	}
	exception, err := h.reconciler.GrantException(r.Context(), reconcile.Exception{
		Registration: registration,
		FieldClass:   reconcile.FieldClass(body.FieldClass),
		Actor:        body.Actor,
		Reason:       body.Reason,
		GrantedBy:    principal,
	}, time.Duration(body.DurationSeconds)*time.Second)
	if err != nil {
		writeReconcileError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, exception)
}

// Exceptions handles GET /v1/registrations/{registration_id}/drift-exceptions: that client's drift
// exceptions, newest first, expired ones included.
func (h *Registrations) Exceptions(w http.ResponseWriter, r *http.Request) {
	if _, ok := callerPrincipal(r); !ok {
		httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
		return
	}
	registrationID, err := id.Parse(r.PathValue("registration_id"))
	if err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "registration_id is not a valid identifier")
		return
	}
	exceptions, err := h.reconciler.ExceptionsFor(r.Context(), registrationID)
	if err != nil {
		httpapi.Problem(w, r, httpapi.Internal, "The drift exceptions could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exceptions": exceptions})
}

func writeReconcileError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, reconcile.ErrInvalid), errors.Is(err, reconcile.ErrNotResolvable):
		// Both messages name a rule or an identifier the caller sent, never stored state.
		httpapi.Problem(w, r, httpapi.ValidationFailed, err.Error())
	case errors.Is(err, reconcile.ErrNoSuchRegistration):
		httpapi.Problem(w, r, httpapi.NotFound, "No active registration by that identifier")
	default:
		httpapi.Problem(w, r, httpapi.DependencyUnavailable,
			"The identity kernel or the control database did not complete the operation; retry")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
