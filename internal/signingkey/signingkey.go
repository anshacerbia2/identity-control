// Package signingkey is the realm signing keys' registry: each key, each approval of one of its
// transitions, and each transition (ADR-IAM-002 §5.5 Q5 to Q9, amended 2026-10-24;
// TDD-identity-control-001 1.29.0 §The Signing Key Registry).
//
// The identity kernel's rotation steps own the keys and their providers. The registry keeps their
// record and refuses a step the record does not allow: a transition the key's state does not permit,
// one without an approval by someone other than the step's operator, an approval used twice, and a
// destruction recorded without its evidence. It never holds key material, and it has no authority
// over it.
//
// Every table is insert-only for the runtime role (grants.sql). A key's state is its latest
// completed transition.
package signingkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"
)

// The states of ADR-IAM-002 §5.2.
const (
	Staged   = "staged"
	Active   = "active"
	Retiring = "retiring"
	Retired  = "retired"
	Revoked  = "revoked"
)

// The transitions an approval names (ADR-IAM-002 §5.5 Q9). A demotion has none of its own: it is
// written with the activation that causes it, under that activation's approval.
const (
	Activate = "activate"
	Retire   = "retire"
	Abandon  = "abandon"
	Revoke   = "revoke"
)

// The outcomes of a recorded step.
const (
	Completed = "completed"
	Failed    = "failed"
)

// Algorithm is the one algorithm a realm signing key is registered for (ADR-IAM-002 §5.1).
const Algorithm = "PS256"

// minimumModulus is ADR-IAM-002 §5.1's floor.
const minimumModulus = 3072

// abandonedReason is the reason an abandonment's transition row carries (ADR-IAM-002 §5.5 Q6). The
// human reason is the approval's.
const abandonedReason = "abandoned"

// ErrRefused is wrapped by every refusal the registry makes, so the command can tell a refusal from
// a failure to reach the database.
var ErrRefused = errors.New("refused")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Transactor runs a function in one transaction. *db.Pool is one.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Registry reads and writes the registry.
type Registry struct {
	store Transactor
}

// New returns a registry over the Control Database.
func New(store Transactor) *Registry { return &Registry{store: store} }

var kidForm = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// person folds a name for comparison: trimmed, case-folded and with inner whitespace collapsed, so
// one person written twice differently is still one person.
func person(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(name)), " ")
}

func named(fields map[string]string) error {
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			return refuse("%s is empty", name)
		}
	}
	return nil
}

// Thumbprint returns the RFC 7638 thumbprint of an RSA public JWK, and checks that it is an RSA key
// of at least 3072 bits. The members are "e", "kty" and "n", in that order, with no whitespace.
func Thumbprint(jwk []byte) (string, error) {
	var key struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		D   string `json:"d"`
	}
	if err := json.Unmarshal(jwk, &key); err != nil {
		return "", refuse("the public JWK is not JSON: %v", err)
	}
	if key.D != "" {
		return "", refuse("the JWK carries a private key; the registry keeps the public key alone")
	}
	if key.Kty != "RSA" || key.N == "" || key.E == "" {
		return "", refuse("the JWK is not an RSA public key")
	}
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return "", refuse("the JWK's n is not base64url: %v", err)
	}
	if bits := new(big.Int).SetBytes(modulus).BitLen(); bits < minimumModulus {
		return "", refuse("the key is %d bits; ADR-IAM-002 §5.1 requires at least %d", bits, minimumModulus)
	}
	if _, err := base64.RawURLEncoding.DecodeString(key.E); err != nil {
		return "", refuse("the JWK's e is not base64url: %v", err)
	}
	return rsaThumbprint(key.E, key.N), nil
}

// rsaThumbprint is RFC 7638 §3 over an RSA key's required members, in lexicographic order, with no
// whitespace. The members are base64url strings, which JSON needs no escaping for.
func rsaThumbprint(e, n string) string {
	canonical := `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	digest := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// StageRequest registers a key the ceremony made (ADR-IAM-002 §5.5 Q5).
type StageRequest struct {
	Realm, Kid    string
	PublicJWK     []byte
	CustodyRef    string
	Operator      string
	Witness       string
	Reason        string
	CorrelationID string
}

// Stage writes the key's row, once, and its stage transition.
func (r *Registry) Stage(ctx context.Context, req StageRequest) error {
	if err := named(map[string]string{"realm": req.Realm, "custody reference": req.CustodyRef,
		"operator": req.Operator, "witness": req.Witness, "reason": req.Reason,
		"correlation identifier": req.CorrelationID}); err != nil {
		return err
	}
	if person(req.Operator) == person(req.Witness) {
		return refuse("the witness is the operator; two people run a ceremony (STD-IAM-001 §3.10)")
	}
	if !kidForm.MatchString(req.Kid) {
		return refuse("%q is not an RFC 7638 thumbprint", req.Kid)
	}
	thumbprint, err := Thumbprint(req.PublicJWK)
	if err != nil {
		return err
	}
	if thumbprint != req.Kid {
		return refuse("the kid %s is not the JWK's RFC 7638 thumbprint, %s", req.Kid, thumbprint)
	}
	public, err := publicJWK(req.PublicJWK)
	if err != nil {
		return err
	}
	return r.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := lockRealm(ctx, tx, req.Realm); err != nil {
			return err
		}
		exists, err := keyExists(ctx, tx, req.Kid)
		if err != nil {
			return err
		}
		if exists {
			return refuse("the key %s is already registered; a kid is staged once", req.Kid)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity.signing_key
		    (kid, realm, algorithm, public_jwk, custody_ref, operator, witness, reason, correlation_id)
		    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			req.Kid, req.Realm, Algorithm, public, req.CustodyRef, req.Operator, req.Witness, req.Reason,
			req.CorrelationID); err != nil {
			return fmt.Errorf("registering the key: %w", err)
		}
		return insertTransition(ctx, tx, transition{kid: req.Kid, step: "stage", to: Staged, actor: req.Operator,
			reason: req.Reason, correlation: req.CorrelationID, outcome: Completed})
	})
}

// publicJWK keeps the public members alone, as the kernel publishes them.
func publicJWK(jwk []byte) ([]byte, error) {
	var key map[string]any
	if err := json.Unmarshal(jwk, &key); err != nil {
		return nil, refuse("the public JWK is not JSON: %v", err)
	}
	public := map[string]any{"kty": key["kty"], "n": key["n"], "e": key["e"], "alg": Algorithm, "use": "sig"}
	return json.Marshal(public)
}

// allowed is each approved transition's source states and its target (ADR-IAM-002 §5.2, §5.5 Q6, Q7).
var allowed = map[string]struct {
	from []string
	to   string
}{
	Activate: {[]string{Staged}, Active},
	Retire:   {[]string{Retiring}, Retired},
	Abandon:  {[]string{Staged}, Retired},
	Revoke:   {[]string{Staged, Retiring}, Revoked},
}

func allows(transition, state string) error {
	rule, ok := allowed[transition]
	if !ok {
		return refuse("%q is not a transition; one of activate, retire, abandon, revoke", transition)
	}
	for _, from := range rule.from {
		if from == state {
			return nil
		}
	}
	switch {
	case transition == Revoke && state == Active:
		return refuse("the key is active; activate a replacement first, which demotes it, then revoke it " +
			"(ADR-IAM-002 §5.5 Q7)")
	case transition == Activate && state == Retiring:
		return refuse("the key is retiring, and a retiring key is never activated again (ADR-IAM-002 §5.5 Q6)")
	}
	return refuse("the key is %s; %s needs it %s", state, transition, strings.Join(rule.from, " or "))
}

// ApproveRequest approves one transition of one key, for one operator (ADR-IAM-002 §5.5 Q9).
type ApproveRequest struct {
	Realm, Kid, Transition string
	Operator, Approver     string
	Emergency              bool
	Reason, CorrelationID  string
}

// Approve writes an approval. It refuses an approver who is the step's operator, an activation's
// approver who generated the key, and a transition the key's state does not allow now.
func (r *Registry) Approve(ctx context.Context, req ApproveRequest) (id.UUID, error) {
	if err := named(map[string]string{"operator": req.Operator, "approver": req.Approver, "reason": req.Reason,
		"correlation identifier": req.CorrelationID}); err != nil {
		return id.UUID{}, err
	}
	if person(req.Approver) == person(req.Operator) {
		return id.UUID{}, refuse("the approver is the step's operator; a key operation is approved by someone " +
			"else (ADR-IAM-002 §5.5 Q9)")
	}
	if req.Emergency && req.Transition != Activate {
		return id.UUID{}, refuse("only an activation can be an emergency (ADR-IAM-002 §5.5 Q7)")
	}
	approvalID, err := id.NewV7()
	if err != nil {
		return id.UUID{}, err
	}
	err = r.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		key, err := lockKey(ctx, tx, req.Realm, req.Kid)
		if err != nil {
			return err
		}
		if err := allows(req.Transition, key.state); err != nil {
			return err
		}
		if req.Transition == Activate && person(req.Approver) == person(key.operator) {
			return refuse("the approver generated the key; its activation is approved by someone else " +
				"(ADR-IAM-002 §5.5 Q9)")
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity.signing_key_approval
		    (approval_id, kid, transition, operator, approver, emergency, reason, correlation_id)
		    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			approvalID.String(), req.Kid, req.Transition, req.Operator, req.Approver, req.Emergency, req.Reason,
			req.CorrelationID)
		return err
	})
	if err != nil {
		return id.UUID{}, err
	}
	return approvalID, nil
}

// Approval is an approval the registry found unused.
type Approval struct {
	ID         id.UUID
	Kid        string
	Transition string
	Operator   string
	Approver   string
	Emergency  bool
}

// CheckRequest asks whether a step may run now.
type CheckRequest struct {
	Realm, Kid, Transition, Operator string
	// MinAge is how long the key must have been in its current state: the kernel's consumer cache
	// window before an activation, its retirement window before a retirement. An emergency
	// activation does not wait it (ADR-IAM-002 §5.5 Q7).
	MinAge time.Duration
}

// Check returns the newest unused approval of that transition of that key for that operator, when the
// key's state allows the transition and has lasted MinAge. It writes nothing.
func (r *Registry) Check(ctx context.Context, req CheckRequest) (Approval, error) {
	var found Approval
	err := r.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		key, err := readKey(ctx, tx, req.Realm, req.Kid)
		if err != nil {
			return err
		}
		if err := allows(req.Transition, key.state); err != nil {
			return err
		}
		approvals, err := unusedApprovals(ctx, tx, req.Kid, req.Transition)
		if err != nil {
			return err
		}
		for _, approval := range approvals {
			if person(approval.Operator) == person(req.Operator) {
				found = approval
				break
			}
		}
		if found.Kid == "" {
			return refuse("no unused %s approval of %s names %s as its operator (ADR-IAM-002 §5.5 Q9)",
				req.Transition, req.Kid, req.Operator)
		}
		if req.MinAge > 0 && !(found.Transition == Activate && found.Emergency) && key.age < req.MinAge {
			return refuse("the key has been %s for %s; %s needs %s", key.state, key.age.Round(time.Second),
				req.Transition, req.MinAge)
		}
		return nil
	})
	return found, err
}

// RecordRequest records the outcome of a step run under an approval.
type RecordRequest struct {
	Realm      string
	ApprovalID id.UUID
	Outcome    string
	// Evidence is required for a completed retirement, abandonment or revocation, and for a failure:
	// the destruction's proof (ADR-IAM-002 §5.5 Q8), or the error.
	Evidence string
}

// Recorded is one transition the registry wrote.
type Recorded struct {
	Kid, Step, From, To, Outcome string
}

// Record writes the step's transition. A completed activation also demotes the realm's previous
// active key, in the same transaction. A failure changes no state and leaves the approval unused.
func (r *Registry) Record(ctx context.Context, req RecordRequest) ([]Recorded, error) {
	if req.Outcome != Completed && req.Outcome != Failed {
		return nil, refuse("the outcome is %q; completed or failed", req.Outcome)
	}
	var written []Recorded
	err := r.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		approval, err := readApproval(ctx, tx, req.ApprovalID)
		if err != nil {
			return err
		}
		key, err := lockKey(ctx, tx, req.Realm, approval.Kid)
		if err != nil {
			return err
		}
		used, err := approvalUsed(ctx, tx, approval.ID, approval.Kid)
		if err != nil {
			return err
		}
		if used {
			return refuse("the approval %s has completed its transition; an approval is used once "+
				"(ADR-IAM-002 §5.5 Q9)", approval.ID)
		}
		if err := allows(approval.Transition, key.state); err != nil {
			return err
		}
		rule := allowed[approval.Transition]
		reason := approval.reason
		if approval.Transition == Abandon {
			reason = abandonedReason
		}
		row := transition{kid: approval.Kid, step: approval.Transition, from: key.state, to: rule.to,
			actor: approval.Operator, approval: &approval.ID, reason: reason, correlation: approval.correlation,
			outcome: req.Outcome, evidence: strings.TrimSpace(req.Evidence)}
		if req.Outcome == Failed {
			if row.evidence == "" {
				return refuse("a failed step records its error as evidence")
			}
			written = append(written, Recorded{row.kid, row.step, row.from, row.to, Failed})
			return insertTransition(ctx, tx, row)
		}
		if rule.to == Retired || rule.to == Revoked {
			if row.evidence == "" {
				return refuse("the key's destruction is recorded with its evidence, and not before " +
					"(ADR-IAM-002 §5.5 Q8)")
			}
		} else {
			row.evidence = ""
		}
		if approval.Transition == Activate {
			previous, err := activeKeys(ctx, tx, req.Realm)
			if err != nil {
				return err
			}
			if err := insertTransition(ctx, tx, row); err != nil {
				return err
			}
			written = append(written, Recorded{row.kid, row.step, row.from, row.to, Completed})
			for _, kid := range previous {
				if kid == approval.Kid {
					continue
				}
				demotion := transition{kid: kid, step: "demote", from: Active, to: Retiring, actor: approval.Operator,
					approval: &approval.ID, reason: "demoted by the activation of " + approval.Kid,
					correlation: approval.correlation, outcome: Completed}
				if err := insertTransition(ctx, tx, demotion); err != nil {
					return err
				}
				written = append(written, Recorded{kid, "demote", Active, Retiring, Completed})
			}
			return nil
		}
		written = append(written, Recorded{row.kid, row.step, row.from, row.to, Completed})
		return insertTransition(ctx, tx, row)
	})
	if err != nil {
		return nil, err
	}
	return written, nil
}

// KeyState is one key and its state.
type KeyState struct {
	Kid        string    `json:"kid"`
	Realm      string    `json:"realm"`
	State      string    `json:"state"`
	Since      time.Time `json:"since"`
	StagedAt   time.Time `json:"staged_at"`
	Operator   string    `json:"operator"`
	CustodyRef string    `json:"custody_ref"`
}

// State lists the realm's keys, or one, with their states, oldest first.
func (r *Registry) State(ctx context.Context, realm, kid string) ([]KeyState, error) {
	var states []KeyState
	err := r.store.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT k.kid, k.realm, t.to_state, t.occurred_at, k.staged_at, k.operator, k.custody_ref
		      FROM identity.signing_key k
		      JOIN LATERAL (SELECT to_state, occurred_at FROM identity.signing_key_transition
		                     WHERE kid = k.kid AND outcome = 'completed'
		                     ORDER BY occurred_at DESC, transition_id DESC LIMIT 1) t ON true
		     WHERE k.realm = $1 AND ($2 = '' OR k.kid = $2)
		     ORDER BY k.staged_at, k.kid`, realm, kid)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s KeyState
			if err := rows.Scan(&s.Kid, &s.Realm, &s.State, &s.Since, &s.StagedAt, &s.Operator, &s.CustodyRef); err != nil {
				return err
			}
			states = append(states, s)
		}
		return rows.Err()
	})
	return states, err
}

type keyRow struct {
	kid, realm, operator, state string
	age                         time.Duration
}

const keyStatement = `SELECT k.kid, k.realm, k.operator, t.to_state, extract(epoch FROM now() - t.occurred_at)
      FROM identity.signing_key k
      JOIN LATERAL (SELECT to_state, occurred_at FROM identity.signing_key_transition
                     WHERE kid = k.kid AND outcome = 'completed'
                     ORDER BY occurred_at DESC, transition_id DESC LIMIT 1) t ON true
     WHERE k.kid = $1`

func scanKey(ctx context.Context, tx db.Tx, statement, realm, kid string) (keyRow, error) {
	rows, err := tx.Query(ctx, statement, kid)
	if err != nil {
		return keyRow{}, err
	}
	defer rows.Close()
	var key keyRow
	found := false
	for rows.Next() {
		var seconds float64
		if err := rows.Scan(&key.kid, &key.realm, &key.operator, &key.state, &seconds); err != nil {
			return keyRow{}, err
		}
		key.age = time.Duration(seconds * float64(time.Second))
		found = true
	}
	if err := rows.Err(); err != nil {
		return keyRow{}, err
	}
	if !found {
		return keyRow{}, refuse("the key %s is not registered", kid)
	}
	if key.realm != realm {
		return keyRow{}, refuse("the key %s belongs to realm %s, not %s", kid, key.realm, realm)
	}
	return key, nil
}

func readKey(ctx context.Context, tx db.Tx, realm, kid string) (keyRow, error) {
	return scanKey(ctx, tx, keyStatement, realm, kid)
}

// lockRealm holds a transaction-level advisory lock on the realm's registry, so two writes run one
// after the other: two activations cannot each demote the same key or leave two active, and two
// steps on one key cannot both pass its state check. An advisory lock rather than FOR UPDATE, which
// needs UPDATE on the table, and the runtime holds none: the registry is insert-only (grants.sql).
func lockRealm(ctx context.Context, tx db.Tx, realm string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('signing-key:' || $1, 0))`, realm)
	return err
}

// lockKey takes the realm's lock and reads the key.
func lockKey(ctx context.Context, tx db.Tx, realm, kid string) (keyRow, error) {
	if err := lockRealm(ctx, tx, realm); err != nil {
		return keyRow{}, err
	}
	return readKey(ctx, tx, realm, kid)
}

func keyExists(ctx context.Context, tx db.Tx, kid string) (bool, error) {
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM identity.signing_key WHERE kid = $1`, kid).Scan(&count)
	return count > 0, err
}

// activeKeys are the realm's keys whose state is active.
func activeKeys(ctx context.Context, tx db.Tx, realm string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT k.kid FROM identity.signing_key k
	      JOIN LATERAL (SELECT to_state FROM identity.signing_key_transition
	                     WHERE kid = k.kid AND outcome = 'completed'
	                     ORDER BY occurred_at DESC, transition_id DESC LIMIT 1) t ON true
	     WHERE k.realm = $1 AND t.to_state = 'active'
	     ORDER BY k.kid`, realm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var kids []string
	for rows.Next() {
		var kid string
		if err := rows.Scan(&kid); err != nil {
			return nil, err
		}
		kids = append(kids, kid)
	}
	return kids, rows.Err()
}

type approvalRow struct {
	Approval
	reason, correlation string
}

func readApproval(ctx context.Context, tx db.Tx, approvalID id.UUID) (approvalRow, error) {
	rows, err := tx.Query(ctx, `SELECT approval_id::text, kid, transition, operator, approver, emergency, reason, correlation_id
	      FROM identity.signing_key_approval WHERE approval_id = $1`, approvalID.String())
	if err != nil {
		return approvalRow{}, err
	}
	defer rows.Close()
	var a approvalRow
	found := false
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw, &a.Kid, &a.Transition, &a.Operator, &a.Approver, &a.Emergency, &a.reason,
			&a.correlation); err != nil {
			return approvalRow{}, err
		}
		if a.ID, err = id.Parse(raw); err != nil {
			return approvalRow{}, err
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return approvalRow{}, err
	}
	if !found {
		return approvalRow{}, refuse("no approval %s exists", approvalID)
	}
	return a, nil
}

func unusedApprovals(ctx context.Context, tx db.Tx, kid, transition string) ([]Approval, error) {
	rows, err := tx.Query(ctx, `SELECT a.approval_id::text, a.kid, a.transition, a.operator, a.approver, a.emergency
	      FROM identity.signing_key_approval a
	     WHERE a.kid = $1 AND a.transition = $2
	       AND NOT EXISTS (SELECT 1 FROM identity.signing_key_transition t
	                        WHERE t.approval_id = a.approval_id AND t.kid = a.kid AND t.outcome = 'completed')
	     ORDER BY a.approved_at DESC, a.approval_id DESC`, kid, transition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var approvals []Approval
	for rows.Next() {
		var a Approval
		var raw string
		if err := rows.Scan(&raw, &a.Kid, &a.Transition, &a.Operator, &a.Approver, &a.Emergency); err != nil {
			return nil, err
		}
		if a.ID, err = id.Parse(raw); err != nil {
			return nil, err
		}
		approvals = append(approvals, a)
	}
	return approvals, rows.Err()
}

func approvalUsed(ctx context.Context, tx db.Tx, approvalID id.UUID, kid string) (bool, error) {
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM identity.signing_key_transition
	     WHERE approval_id = $1 AND kid = $2 AND outcome = 'completed'`, approvalID.String(), kid).Scan(&count)
	return count > 0, err
}

type transition struct {
	kid, step, from, to, actor string
	approval                   *id.UUID
	reason, correlation        string
	outcome, evidence          string
}

func insertTransition(ctx context.Context, tx db.Tx, t transition) error {
	transitionID, err := id.NewV7()
	if err != nil {
		return err
	}
	var from, evidence any
	if t.from != "" {
		from = t.from
	}
	if t.evidence != "" {
		evidence = t.evidence
	}
	var approval any
	if t.approval != nil {
		approval = t.approval.String()
	}
	_, err = tx.Exec(ctx, `INSERT INTO identity.signing_key_transition
	    (transition_id, kid, step, from_state, to_state, actor, approval_id, reason, correlation_id, outcome, evidence)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		transitionID.String(), t.kid, t.step, from, t.to, t.actor, approval, t.reason, t.correlation, t.outcome, evidence)
	if err != nil {
		return fmt.Errorf("recording the %s of %s: %w", t.step, t.kid, err)
	}
	return nil
}
