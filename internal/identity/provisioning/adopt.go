package provisioning

// Re-adopting an orphan's identifier after a restore to an older point (ADR-IAM-001 §5.11 as
// amended 2026-10-20; TDD-identity-control-001 1.23.0 §Re-Adopting an Orphan).
//
// A Principal created after the backup still exists in the kernel, but the restored Control Database
// holds no mapping for it, so the sweep records its user an orphan. Replacing that person with a new
// principal_id would break every reference made to the old one, Organization Control's Memberships
// first: `sub` is "A locally unique and never reassigned identifier within the Issuer for the
// End-User" (OpenID Connect Core §2). So :adopt is the one recorded-decision path by which such an
// identifier re-enters principal_mapping. It plans first, and refuses unless all four checks hold:
//
//  1. an open orphan finding names the identifier;
//  2. exactly one kernel user carries it, and it is the finding's user, a person;
//  3. the identifier is a UUIDv7 whose time is later than the newest mapping the restored database
//     holds, so it cannot have been in the backup;
//  4. a kernel admin event CREATE of that user, made by this service's own Admin API client, carries
//     the identifier.
//
// The mapping lands suspended, with the user disabled and its sessions ended, as :release leaves one.
// An operator's :restore returns it to service: two recorded steps.

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

// The checks an adoption plan reports, in the order ADR-IAM-001 §5.11 states them.
const (
	CheckOrphanFinding    = "orphan_finding"
	CheckOneKernelUser    = "one_kernel_user"
	CheckNewerThanBackup  = "newer_than_backup"
	CheckCreationOnRecord = "creation_on_record"
)

var (
	// ErrNotAdoptable is an adoption a check refuses. The plan says which and why.
	ErrNotAdoptable = errors.New("provisioning: the identifier is not adoptable")

	// ErrSelfAdopt refuses a provider adopting the Principal in its own token, the self-action
	// boundary :release holds (NIST SP 800-53 AC-5).
	ErrSelfAdopt = errors.New("provisioning: an operator cannot adopt their own Principal")

	// ErrAdoptionUnavailable is a Provisioner with no creation journal: check 4 cannot be read.
	ErrAdoptionUnavailable = errors.New("provisioning: the kernel's creation journal is not configured")

	// ErrMapped is an identifier a mapping already holds: nothing to adopt.
	ErrMapped = errors.New("provisioning: a mapping already holds the identifier")
)

// AdoptRequest is a provider adopting an orphan's identifier, or planning to.
type AdoptRequest struct {
	PrincipalID id.UUID
	AdoptedBy   id.UUID
	Reason      string
	DryRun      bool
}

// AdoptCheck is one check of the plan: whether it holds, and what it read.
type AdoptCheck struct {
	Check  string `json:"check"`
	Holds  bool   `json:"holds"`
	Detail string `json:"detail"`
}

// AdoptPlan is the answer of :adopt: the four checks, whether the identifier is adoptable, and when
// it was adopted, the state its mapping landed in.
type AdoptPlan struct {
	PrincipalID id.UUID      `json:"principal_id"`
	Adoptable   bool         `json:"adoptable"`
	Refusal     string       `json:"refusal,omitempty"`
	Checks      []AdoptCheck `json:"checks"`
	Adopted     bool         `json:"adopted"`
	State       string       `json:"state,omitempty"`

	evidence adoptEvidence
}

// adoptEvidence is what the record keeps of each check.
type adoptEvidence struct {
	findingID       id.UUID
	user            keycloak.User
	identifierTime  time.Time
	newestMapping   *time.Time
	creationEventID string
	creationAt      time.Time
}

// UseCreationJournal gives the provisioner the kernel's admin events and the kernel user this
// service's Principal credential acts as, the creator check 4 requires. Without both, :adopt answers
// ErrAdoptionUnavailable.
func (p *Provisioner) UseCreationJournal(journal keycloak.CreationJournal, creator func(context.Context) (string, error)) {
	p.journal, p.creator = journal, creator
}

const adoptFindingStatement = `SELECT finding_id::text, keycloak_user_id
FROM identity.principal_finding
WHERE realm = $1 AND finding_class = 'orphan' AND claimed_principal_id = $2 AND resolved_at IS NULL
ORDER BY detected_at LIMIT 1`

const adoptMappedStatement = `SELECT EXISTS (SELECT 1 FROM identity.principal_mapping WHERE principal_id = $1)`

// newestMappingStatement is the newest instant the restored registry records: its newest mapping's
// creation, or the newest UUIDv7 time among the identifiers it holds, whichever is later.
// uuid_extract_timestamp reads a version 7 UUID's time (PostgreSQL 17, §9.14 UUID Functions).
const newestMappingStatement = `SELECT greatest(max(created_at),
       max(uuid_extract_timestamp(principal_id)) FILTER (WHERE uuid_extract_version(principal_id) = 7))
FROM identity.principal_mapping`

const lockFindingStatement = `SELECT keycloak_user_id FROM identity.principal_finding
WHERE finding_id = $1 AND resolved_at IS NULL FOR UPDATE`

const insertAdoptedStatement = `INSERT INTO identity.principal_mapping
    (principal_id, keycloak_user_id, realm, username, email, subject_type, state, activated_at)
VALUES ($1, $2, $3, $4, $5, 'human', 'suspended', now())
ON CONFLICT (principal_id) DO NOTHING`

const adoptionRecordStatement = `INSERT INTO identity.principal_adoption
    (adoption_id, principal_id, finding_id, realm, keycloak_user_id, identifier_time, newest_mapping_at,
     creation_event_id, creation_event_at, adopted_by, reason)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

const resolveAdoptedStatement = `UPDATE identity.principal_finding
SET resolved_at = now(), resolution = 'adopted'
WHERE finding_id = $1 AND resolved_at IS NULL`

// uuidV7Time is the instant a version 7 UUID carries: "a time-ordered value field derived from the
// widely implemented and well-known Unix Epoch timestamp source, the number of milliseconds since
// midnight 1 Jan 1970 UTC" in its first 48 bits (RFC 9562 §5.7).
func uuidV7Time(u id.UUID) (time.Time, bool) {
	if u.Version() != 7 {
		return time.Time{}, false
	}
	b := u[:]
	ms := int64(b[0])<<40 | int64(b[1])<<32 | int64(b[2])<<24 | int64(b[3])<<16 | int64(b[4])<<8 | int64(b[5])
	return time.UnixMilli(ms).UTC(), true
}

// Adopt plans an adoption and, unless it is a dry run, performs it when every check holds.
func (p *Provisioner) Adopt(ctx context.Context, req AdoptRequest) (AdoptPlan, error) {
	switch {
	case req.AdoptedBy.IsNil():
		return AdoptPlan{}, errors.New("provisioning: the adopting Principal is required")
	case req.AdoptedBy == req.PrincipalID:
		return AdoptPlan{}, ErrSelfAdopt
	case strings.TrimSpace(req.Reason) == "":
		return AdoptPlan{}, ErrReasonRequired
	case p.journal == nil || p.creator == nil:
		return AdoptPlan{}, ErrAdoptionUnavailable
	}
	plan, err := p.planAdoption(ctx, req.PrincipalID)
	if err != nil || req.DryRun {
		return plan, err
	}
	if !plan.Adoptable {
		return plan, fmt.Errorf("%w: %s", ErrNotAdoptable, plan.Refusal)
	}

	adoptionID, err := p.newID()
	if err != nil {
		return plan, fmt.Errorf("provisioning: mint adoption_id: %w", err)
	}
	ev, realm := plan.evidence, p.cfg.Realm
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, lockFindingStatement, ev.findingID.String())
		if err != nil {
			return fmt.Errorf("provisioning: lock the orphan finding: %w", err)
		}
		var user string
		open := rows.Next()
		if open {
			err = rows.Scan(&user)
		}
		rows.Close()
		switch {
		case err != nil:
			return fmt.Errorf("provisioning: lock the orphan finding: %w", err)
		case !open:
			return fmt.Errorf("%w: the orphan finding was resolved while it was being adopted", ErrNotAdoptable)
		}
		if user != string(ev.user.ID) {
			return fmt.Errorf("%w: the orphan finding names another kernel user", ErrNotAdoptable)
		}
		var email any
		if strings.TrimSpace(ev.user.Email) != "" {
			email = ev.user.Email
		}
		tag, err := tx.Exec(ctx, insertAdoptedStatement, req.PrincipalID.String(), string(ev.user.ID), string(realm),
			ev.user.Username, email)
		if err != nil {
			return fmt.Errorf("provisioning: record the adopted mapping: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrMapped
		}
		if email != nil {
			addressID, err := p.newID()
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, insertCreationAddressStatement, addressID.String(), req.PrincipalID.String(),
				ev.user.Email); err != nil {
				return fmt.Errorf("provisioning: record the adopted Principal's address: %w", err)
			}
		}
		var newest any
		if ev.newestMapping != nil {
			newest = *ev.newestMapping
		}
		if _, err := tx.Exec(ctx, adoptionRecordStatement, adoptionID.String(), req.PrincipalID.String(),
			ev.findingID.String(), string(realm), string(ev.user.ID), ev.identifierTime, newest, ev.creationEventID,
			ev.creationAt, req.AdoptedBy.String(), strings.TrimSpace(req.Reason)); err != nil {
			return fmt.Errorf("provisioning: record the adoption: %w", err)
		}
		if _, err := tx.Exec(ctx, resolveAdoptedStatement, ev.findingID.String()); err != nil {
			return fmt.Errorf("provisioning: resolve the orphan finding: %w", err)
		}
		// Containment before the commit, as :release does: a suspended Principal's user is disabled and
		// holds no session. Both calls are idempotent, so a failed adoption that a retry repeats is safe.
		kernelCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
		defer cancel()
		if err := p.kernel.DisableUser(kernelCtx, realm, ev.user.ID); err != nil {
			return fmt.Errorf("provisioning: keep the adopted user disabled: %w", err)
		}
		if err := p.kernel.LogoutUser(kernelCtx, realm, ev.user.ID); err != nil {
			return fmt.Errorf("provisioning: end the adopted user's sessions: %w", err)
		}
		return nil
	}); err != nil {
		return plan, err
	}
	p.logger.WarnContext(ctx, "an orphan's identifier was adopted to suspended; :restore returns it to service",
		slog.String("principal_id", req.PrincipalID.String()),
		slog.String("adopted_by", req.AdoptedBy.String()))
	plan.Adopted, plan.State = true, stateReleased
	return plan, nil
}

// planAdoption reads the four checks. A check that cannot be read because the kernel did not answer
// is an error, not a refusal: an unknown answer is not a "no".
func (p *Provisioner) planAdoption(ctx context.Context, principal id.UUID) (AdoptPlan, error) {
	plan := AdoptPlan{PrincipalID: principal}
	var (
		mapped            bool
		findingID, userID string
		newest            *time.Time
	)
	if err := p.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, adoptMappedStatement, principal.String()).Scan(&mapped); err != nil {
			return fmt.Errorf("provisioning: read the mapping: %w", err)
		}
		rows, err := tx.Query(ctx, adoptFindingStatement, string(p.cfg.Realm), principal.String())
		if err != nil {
			return fmt.Errorf("provisioning: read the orphan finding: %w", err)
		}
		if rows.Next() {
			err = rows.Scan(&findingID, &userID)
		}
		rows.Close()
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, newestMappingStatement).Scan(&newest)
	}); err != nil {
		return plan, err
	}
	if mapped {
		return plan, ErrMapped
	}

	// 1. An open orphan finding names the identifier.
	finding := AdoptCheck{Check: CheckOrphanFinding, Holds: findingID != ""}
	if finding.Holds {
		finding.Detail = "an open orphan finding names it"
		parsed, err := id.Parse(findingID)
		if err != nil {
			return plan, err
		}
		plan.evidence.findingID = parsed
	} else {
		finding.Detail = "no open orphan finding names it; the sweep records one first"
	}

	// 2. Exactly one kernel user carries it, the finding's, a person.
	callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
	found, err := p.kernel.FindByPrincipalID(callCtx, p.cfg.Realm, principal)
	cancel()
	if err != nil {
		return plan, fmt.Errorf("provisioning: search the kernel for the identifier: %w", err)
	}
	one := AdoptCheck{Check: CheckOneKernelUser}
	switch {
	case len(found) != 1:
		one.Detail = fmt.Sprintf("%d kernel users carry it; exactly one must", len(found))
	case finding.Holds && string(found[0].ID) != userID:
		one.Detail = "the one kernel user carrying it is not the orphan finding's"
	case found[0].ServiceAccount || found[0].SubjectType == keycloak.SubjectWorkload:
		one.Detail = "its user is a workload's; a workload is rebuilt through /v1/workloads"
	default:
		one.Holds, one.Detail = true, "exactly one kernel user carries it, a person: "+found[0].Username
		plan.evidence.user = found[0]
	}

	// 3. It cannot have been in the backup.
	newer := AdoptCheck{Check: CheckNewerThanBackup}
	at, v7 := uuidV7Time(principal)
	plan.evidence.identifierTime, plan.evidence.newestMapping = at, newest
	switch {
	case !v7:
		newer.Detail = "it is not a UUIDv7, so it carries no time to compare"
	case newest != nil && !at.After(*newest):
		newer.Detail = fmt.Sprintf("its time %s is not later than the newest mapping, %s", at.Format(time.RFC3339Nano),
			newest.UTC().Format(time.RFC3339Nano))
	case newest == nil:
		newer.Holds, newer.Detail = true, "the restored registry holds no mapping"
	default:
		newer.Holds = true
		newer.Detail = fmt.Sprintf("its time %s is later than the newest mapping, %s", at.Format(time.RFC3339Nano),
			newest.UTC().Format(time.RFC3339Nano))
	}

	// 4. Its creation is on record, by this service's own Admin API client.
	record := AdoptCheck{Check: CheckCreationOnRecord, Detail: "no kernel user to read the creation of"}
	if one.Holds {
		creator, err := p.creator(ctx)
		if err != nil {
			return plan, fmt.Errorf("provisioning: read this service's kernel identity: %w", err)
		}
		callCtx, cancel := context.WithTimeout(ctx, p.cfg.ProvisionTimeout)
		creations, err := p.journal.UserCreations(callCtx, p.cfg.Realm, plan.evidence.user.ID)
		cancel()
		if err != nil {
			return plan, fmt.Errorf("provisioning: read the kernel's admin events: %w", err)
		}
		record.Detail = "no admin event records this service creating the user with this identifier; " +
			"its creation may be past the kernel's event retention, and triage decides"
		for _, creation := range creations {
			if creation.ActorUserID == creator && creation.ClaimedPrincipalID == principal.String() {
				record.Holds = true
				record.Detail = "the kernel's admin event " + creation.EventID + " records this service creating it"
				plan.evidence.creationEventID, plan.evidence.creationAt = creation.EventID, creation.Time.UTC()
				break
			}
		}
	}

	plan.Checks = []AdoptCheck{finding, one, newer, record}
	plan.Adoptable = true
	for _, check := range plan.Checks {
		if !check.Holds {
			plan.Adoptable = false
			plan.Refusal = check.Check + ": " + check.Detail
			break
		}
	}
	return plan, nil
}
