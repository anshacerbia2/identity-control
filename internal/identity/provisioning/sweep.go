package provisioning

// The Principal sweep (TDD-identity-control-001 §Reconciliation Sweep, 1.13.0). Keycloak enforces
// neither of the two invariants this service's identifier depends on, attribute presence and
// attribute uniqueness, so the sweep is the compensating control for both: it enumerates the
// realm's users and accounts for every one of them against the mappings.
//
//   - unmapped: a user carrying no identifier, outside every authorized creation path;
//   - orphan: a user carrying an identifier no mapping holds;
//   - duplicate: a second user carrying an identifier whose mapping points at another user that
//     still exists;
//   - dangling: an active mapping whose user is gone.
//
// Every kernel read happens before anything is written, so an enumeration or a confirmation that
// fails part way records nothing: an unread page is not a missing user.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// Finding classes the sweep records.
const (
	FindingDangling  = "dangling"
	FindingUnmapped  = "unmapped"
	FindingOrphan    = "orphan"
	FindingDuplicate = "duplicate"
)

// sweepPages bounds one enumeration. A realm larger than this is refused rather than read in part,
// because users past the bound would be reported missing.
const sweepPages = 1000

// SweepResult is what one sweep found: how many pending mappings recovery resolved, and how many
// users or mappings each branch found, already-open findings included.
type SweepResult struct {
	Recovered int `json:"recovered"`
	Dangling  int `json:"dangling"`
	Unmapped  int `json:"unmapped"`
	Orphan    int `json:"orphan"`
	Duplicate int `json:"duplicate"`
}

// UserFinding is an open unmapped, orphan or duplicate finding, as GET /v1/principals:unmapped
// reports it. It carries no kernel identifier: the username is what lets an operator find the user.
type UserFinding struct {
	FindingID          id.UUID   `json:"finding_id"`
	Class              string    `json:"finding_class"`
	PrincipalID        *id.UUID  `json:"principal_id,omitempty"`
	ClaimedPrincipalID string    `json:"claimed_principal_id,omitempty"`
	Username           string    `json:"username,omitempty"`
	UserDisabled       bool      `json:"user_disabled"`
	DetectedAt         time.Time `json:"detected_at"`
}

// Reconcile runs pending recovery and then the sweep, as the schedule does.
func (p *Provisioner) Reconcile(ctx context.Context) (SweepResult, error) {
	recovered, err := p.RecoverPending(ctx)
	if err != nil {
		return SweepResult{}, err
	}
	result, err := p.Sweep(ctx)
	result.Recovered = recovered
	return result, err
}

// FindDangling runs the sweep and reports how many dangling mappings it found.
func (p *Provisioner) FindDangling(ctx context.Context) (int, error) {
	result, err := p.Sweep(ctx)
	return result.Dangling, err
}

// sweptMapping is one mapping as the sweep reads it.
type sweptMapping struct {
	principal   id.UUID
	user        keycloak.UserID
	state       string
	activatedAt *time.Time
}

// openFinding is an open finding the sweep may resolve or keep.
type openFinding struct {
	class     string
	user      keycloak.UserID
	principal string
}

// sweepState is what the Control Database holds, read once after the enumeration.
type sweepState struct {
	mappings map[id.UUID]sweptMapping
	pending  map[id.UUID]bool
	open     []openFinding
}

// userAction is one finding the sweep will record, decided before anything is written.
type userAction struct {
	class   string
	user    keycloak.User
	claimed string
	mapping *sweptMapping

	// alsoDisable is the mapping's own user, which a duplicate disables beside the extra one.
	alsoDisable *keycloak.User
}

const sweepMappingsStatement = `SELECT principal_id::text, coalesce(keycloak_user_id, ''), state, activated_at
FROM identity.principal_mapping WHERE realm = $1`

// A pending workload's identity is on its service-account user before its mapping exists
// (TDD-identity-control-004 §Creation), so its identifier is not an orphan's.
const sweepPendingWorkloadsStatement = `SELECT w.principal_id::text FROM identity.workload w
JOIN identity.client_registration r ON r.registration_id = w.registration_id
WHERE w.state = 'pending' AND r.realm = $1`

const sweepOpenFindingsStatement = `SELECT finding_class, keycloak_user_id, coalesce(principal_id::text, '')
FROM identity.principal_finding WHERE realm = $1 AND resolved_at IS NULL`

const insertDanglingStatement = `INSERT INTO identity.principal_finding
    (finding_id, principal_id, finding_class, keycloak_user_id, realm)
VALUES ($1, $2, 'dangling', $3, $4)
ON CONFLICT (realm, finding_class, keycloak_user_id) WHERE resolved_at IS NULL DO NOTHING`

const insertUserFindingStatement = `INSERT INTO identity.principal_finding
    (finding_id, principal_id, finding_class, keycloak_user_id, realm, claimed_principal_id, username, user_disabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (realm, finding_class, keycloak_user_id) WHERE resolved_at IS NULL
DO UPDATE SET user_disabled = identity.principal_finding.user_disabled OR EXCLUDED.user_disabled`

const resolveAbsentUserStatement = `UPDATE identity.principal_finding
SET resolved_at = now(), resolution = 'user_absent'
WHERE realm = $1 AND finding_class = $2 AND keycloak_user_id = $3 AND resolved_at IS NULL`

// quarantineDuplicateStatement holds a mapping a second user answers for. The user it names is part
// of the predicate, so a mapping rebound since the sweep read it is left alone.
const quarantineDuplicateStatement = `UPDATE identity.principal_mapping
SET state = 'quarantined', quarantined_at = now(), quarantine_reason = $3, version = version + 1
WHERE principal_id = $1 AND keycloak_user_id = $2 AND state IN ('active', 'suspended')`

// Sweep enumerates the realm's users and records what it finds.
func (p *Provisioner) Sweep(ctx context.Context) (SweepResult, error) {
	if p.cfg.Realm == "" {
		return SweepResult{}, errors.New("provisioning: a realm is required to sweep")
	}
	realm := p.cfg.Realm
	started := time.Now().UTC()

	users, err := p.enumerate(ctx, realm)
	if err != nil {
		return SweepResult{}, err
	}
	seen := make(map[keycloak.UserID]keycloak.User, len(users))
	for _, user := range users {
		seen[user.ID] = user
	}

	var state sweepState
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		state, err = readSweepState(ctx, tx, realm)
		return err
	}); err != nil {
		return SweepResult{}, err
	}

	// Every kernel read the decisions need, before anything is written. present caches the users read
	// directly: a mapping's own user that the enumeration did not return.
	present := map[keycloak.UserID]*keycloak.User{}
	confirm := func(userID keycloak.UserID) (*keycloak.User, error) {
		if user, ok := seen[userID]; ok {
			return &user, nil
		}
		if cached, ok := present[userID]; ok {
			return cached, nil
		}
		callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
		user, err := p.kernel.GetUser(callCtx, realm, userID)
		cancel()
		switch {
		case errors.Is(err, keycloak.ErrNotFound):
			present[userID] = nil
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("provisioning: read a mapping's user: %w", err)
		}
		present[userID] = &user
		return &user, nil
	}

	var actions []userAction
	for _, user := range users {
		action, err := p.classify(user, state, confirm)
		if err != nil {
			return SweepResult{}, err
		}
		if action != nil {
			actions = append(actions, *action)
		}
	}

	type dangling struct {
		principal id.UUID
		user      keycloak.UserID
	}
	var missing []dangling
	var stillPresent []id.UUID
	for _, mapping := range state.mappings {
		// A mapping activated during the enumeration may point at a user on a page already read.
		if mapping.state != string(StateActive) || mapping.activatedAt == nil || !mapping.activatedAt.Before(started) {
			continue
		}
		user, err := confirm(mapping.user)
		if err != nil {
			return SweepResult{}, err
		}
		if user == nil {
			missing = append(missing, dangling{mapping.principal, mapping.user})
		} else {
			stillPresent = append(stillPresent, mapping.principal)
		}
	}

	// Writes. Each finding is recorded after the kernel change it describes, so a disable that fails
	// stops the sweep with the user unrecorded, and the next sweep finds it again.
	result := SweepResult{Dangling: len(missing)}
	wasOpen := map[string]bool{}
	for _, finding := range state.open {
		wasOpen[finding.class+"/"+string(finding.user)] = true
	}
	for _, action := range actions {
		if err := p.act(ctx, realm, action, wasOpen[action.class+"/"+string(action.user.ID)]); err != nil {
			return result, err
		}
		switch action.class {
		case FindingUnmapped:
			result.Unmapped++
		case FindingOrphan:
			result.Orphan++
		case FindingDuplicate:
			result.Duplicate++
		}
	}

	err = p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, principal := range stillPresent {
			if _, err := tx.Exec(ctx, resolveFindingStatement, principal.String(), "user_present"); err != nil {
				return err
			}
		}
		for _, m := range missing {
			findingID, err := p.newID()
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, insertDanglingStatement, findingID.String(), m.principal.String(), string(m.user), string(realm))
			if err != nil {
				return fmt.Errorf("provisioning: record a dangling mapping: %w", err)
			}
			if tag.RowsAffected() == 1 {
				p.logger.ErrorContext(ctx, "an active Principal's Keycloak user is gone; relinking it is an operator's decision",
					slog.String("principal_id", m.principal.String()))
			}
		}
		// A user a finding named that a complete enumeration no longer returns was deleted: the
		// operator's triage. Dangling findings resolve by their mapping, above.
		for _, finding := range state.open {
			if finding.class == FindingDangling {
				continue
			}
			if _, ok := seen[finding.user]; ok {
				continue
			}
			if _, err := tx.Exec(ctx, resolveAbsentUserStatement, string(realm), finding.class, string(finding.user)); err != nil {
				return fmt.Errorf("provisioning: resolve a finding whose user is gone: %w", err)
			}
		}
		return nil
	})
	return result, err
}

// enumerate reads every user the realm's listing returns.
func (p *Provisioner) enumerate(ctx context.Context, realm keycloak.Realm) ([]keycloak.User, error) {
	var users []keycloak.User
	for page := 0; ; page++ {
		if page == sweepPages {
			return nil, errors.New("provisioning: the realm holds more users than one enumeration reads")
		}
		callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
		batch, err := p.kernel.ListUsers(callCtx, realm, keycloak.Page{First: page * p.cfg.RecoveryBatch, Max: p.cfg.RecoveryBatch})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("provisioning: enumerate users: %w", err)
		}
		users = append(users, batch...)
		if len(batch) < p.cfg.RecoveryBatch {
			return users, nil
		}
	}
}

func readSweepState(ctx context.Context, tx db.Tx, realm keycloak.Realm) (sweepState, error) {
	state := sweepState{mappings: map[id.UUID]sweptMapping{}, pending: map[id.UUID]bool{}}
	rows, err := tx.Query(ctx, sweepMappingsStatement, string(realm))
	if err != nil {
		return state, fmt.Errorf("provisioning: read the mappings: %w", err)
	}
	for rows.Next() {
		var (
			raw, user string
			mapping   sweptMapping
		)
		if err := rows.Scan(&raw, &user, &mapping.state, &mapping.activatedAt); err != nil {
			rows.Close()
			return state, err
		}
		if mapping.principal, err = id.Parse(raw); err != nil {
			rows.Close()
			return state, err
		}
		mapping.user = keycloak.UserID(user)
		state.mappings[mapping.principal] = mapping
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return state, err
	}

	rows, err = tx.Query(ctx, sweepPendingWorkloadsStatement, string(realm))
	if err != nil {
		return state, fmt.Errorf("provisioning: read the pending workloads: %w", err)
	}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return state, err
		}
		principal, err := id.Parse(raw)
		if err != nil {
			rows.Close()
			return state, err
		}
		state.pending[principal] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return state, err
	}

	rows, err = tx.Query(ctx, sweepOpenFindingsStatement, string(realm))
	if err != nil {
		return state, fmt.Errorf("provisioning: read the open findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			finding openFinding
			user    string
		)
		if err := rows.Scan(&finding.class, &user, &finding.principal); err != nil {
			return state, err
		}
		finding.user = keycloak.UserID(user)
		state.open = append(state.open, finding)
	}
	return state, rows.Err()
}

// classify decides what one user is. It returns nil for a user the mappings account for.
func (p *Provisioner) classify(user keycloak.User, state sweepState,
	confirm func(keycloak.UserID) (*keycloak.User, error)) (*userAction, error) {
	claimed := user.ClaimedPrincipalID
	if claimed == "" && !user.PrincipalID.IsNil() {
		claimed = user.PrincipalID.String()
	}
	if claimed == "" {
		// A service-account user without an identifier is its client's: the registration sweep
		// accounts for every client, and disabling this service's own would cut it off the kernel.
		if user.ServiceAccount {
			return nil, nil
		}
		return &userAction{class: FindingUnmapped, user: user}, nil
	}
	principal, err := id.Parse(strings.ToLower(claimed))
	if err != nil {
		return &userAction{class: FindingOrphan, user: user, claimed: claimed}, nil
	}
	mapping, mapped := state.mappings[principal]
	switch {
	case !mapped && state.pending[principal]:
		return nil, nil // workload recovery binds it
	case !mapped:
		return &userAction{class: FindingOrphan, user: user, claimed: claimed}, nil
	case mapping.state == string(StatePending):
		return nil, nil // recovery adopts it, or quarantines a duplicate itself
	case mapping.user == user.ID:
		return nil, nil
	}
	own, err := confirm(mapping.user)
	if err != nil {
		return nil, err
	}
	// An active or suspended mapping whose own user is gone is dangling, or being rebound: :relink's
	// recovery, or a workload's rebuilt client. Only two users that exist are a duplicate.
	if own == nil && (mapping.state == string(StateActive) || mapping.state == stateSuspended) {
		return nil, nil
	}
	return &userAction{class: FindingDuplicate, user: user, mapping: &mapping, alsoDisable: own}, nil
}

// stateSuspended is a contained Principal (TDD-identity-control-005). The provisioning state machine
// does not move a mapping there; the security commands do.
const stateSuspended = "suspended"

// act applies and records one finding.
func (p *Provisioner) act(ctx context.Context, realm keycloak.Realm, action userAction, wasOpen bool) error {
	disable := action.class == FindingDuplicate || p.cfg.DisableUnmapped
	disabled := !action.user.Enabled
	if disable {
		for _, user := range []*keycloak.User{&action.user, action.alsoDisable} {
			if user == nil || !user.Enabled {
				continue
			}
			callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
			err := p.kernel.DisableUser(callCtx, realm, user.ID)
			cancel()
			if err != nil && !errors.Is(err, keycloak.ErrNotFound) {
				return fmt.Errorf("provisioning: disable a %s user: %w", action.class, err)
			}
		}
		disabled = true
	}

	findingID, err := p.newID()
	if err != nil {
		return err
	}
	var principal, claimed, username any
	if action.mapping != nil {
		principal = action.mapping.principal.String()
	}
	if action.class == FindingOrphan {
		claimed = action.claimed
	}
	if action.user.Username != "" {
		username = action.user.Username
	}
	quarantined := false
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if action.class == FindingDuplicate {
			tag, err := tx.Exec(ctx, quarantineDuplicateStatement, action.mapping.principal.String(),
				string(action.mapping.user), "the sweep found a second Keycloak user carrying this principal_id")
			if err != nil {
				return fmt.Errorf("provisioning: quarantine a duplicated mapping: %w", err)
			}
			quarantined = tag.RowsAffected() == 1
		}
		_, err := tx.Exec(ctx, insertUserFindingStatement, findingID.String(), principal, action.class,
			string(action.user.ID), string(realm), claimed, username, disabled)
		if err != nil {
			return fmt.Errorf("provisioning: record a %s finding: %w", action.class, err)
		}
		return nil
	}); err != nil {
		return err
	}

	if wasOpen && !quarantined {
		return nil
	}
	attrs := []slog.Attr{slog.String("finding_class", action.class), slog.String("username", action.user.Username),
		slog.Bool("disabled", disabled)}
	switch action.class {
	case FindingUnmapped:
		p.logger.LogAttrs(ctx, slog.LevelError, "a Keycloak user carries no principal_id; it came from outside every authorized creation path", attrs...)
	case FindingOrphan:
		p.logger.LogAttrs(ctx, slog.LevelError, "a Keycloak user carries a principal_id no mapping holds",
			append(attrs, slog.String("claimed_principal_id", action.claimed))...)
	case FindingDuplicate:
		p.logger.LogAttrs(ctx, slog.LevelError, "a second Keycloak user carries a Principal's identifier; both users are disabled",
			append(attrs, slog.String("principal_id", action.mapping.principal.String()), slog.Bool("quarantined", quarantined))...)
	}
	return nil
}

const openUserFindingsStatement = `SELECT finding_id::text, finding_class, coalesce(principal_id::text, ''),
       coalesce(claimed_principal_id, ''), coalesce(username, ''), user_disabled, detected_at
FROM identity.principal_finding
WHERE realm = $1 AND resolved_at IS NULL AND finding_class IN ('unmapped', 'orphan', 'duplicate')
ORDER BY detected_at, finding_id`

// Unmapped lists the open unmapped, orphan and duplicate findings, oldest first.
func (p *Provisioner) Unmapped(ctx context.Context) ([]UserFinding, error) {
	out := []UserFinding{}
	err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, openUserFindingsStatement, string(p.cfg.Realm))
		if err != nil {
			return fmt.Errorf("provisioning: read the open findings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				finding             UserFinding
				rawID, rawPrincipal string
			)
			if err := rows.Scan(&rawID, &finding.Class, &rawPrincipal, &finding.ClaimedPrincipalID, &finding.Username,
				&finding.UserDisabled, &finding.DetectedAt); err != nil {
				return err
			}
			if finding.FindingID, err = id.Parse(rawID); err != nil {
				return err
			}
			if rawPrincipal != "" {
				principal, err := id.Parse(rawPrincipal)
				if err != nil {
					return err
				}
				finding.PrincipalID = &principal
			}
			out = append(out, finding)
		}
		return rows.Err()
	})
	return out, err
}
