// Package investigation serves a provider's reads of another Principal's identity and security
// state (TDD-identity-control-005 §Read Authorization and Disclosure), and records each read as
// evidence (§Evidence).
//
// Search is bounded, never a listing. A Principal's sessions, authenticators and federation links
// are read from the kernel through its supported Admin API, and no kernel identifier leaves this
// package. Every read writes one row to identity.privileged_access before it is answered, so a read
// that cannot be recorded is not served.
package investigation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/securityref"
)

var (
	// ErrQuery is a search too unspecific to run: empty, wildcard-only, or shorter than the floor.
	ErrQuery = errors.New("investigation: the search is too broad")

	// ErrNotFound is a Principal this service does not hold.
	ErrNotFound = errors.New("investigation: no such Principal")

	// ErrUnlinked is a Principal with no kernel user to read: pending, or its user is gone.
	ErrUnlinked = errors.New("investigation: the Principal has no kernel user to read")
)

// Transactor is the transaction source: foundation-platform's *db.Pool.
type Transactor interface {
	InTx(ctx context.Context, fn func(context.Context, db.Tx) error) error
}

// Config bounds the service.
type Config struct {
	Realm          keycloak.Realm
	SearchMinRunes int
	SearchPageSize int
	CallTimeout    time.Duration
}

// Service is the investigation read path.
type Service struct {
	tx     Transactor
	kernel keycloak.SecurityReader
	refs   *securityref.Codec
	cfg    Config
	newID  func() (id.UUID, error)
}

// New builds the service. refs may be nil: responses then carry no security_ref, and no command can
// name an object.
func New(tx Transactor, kernel keycloak.SecurityReader, refs *securityref.Codec, cfg Config) (*Service, error) {
	switch {
	case tx == nil:
		return nil, errors.New("investigation: a transactor is required")
	case kernel == nil:
		return nil, errors.New("investigation: a kernel reader is required")
	case cfg.Realm == "":
		return nil, errors.New("investigation: a realm is required")
	}
	if cfg.SearchMinRunes <= 0 {
		cfg.SearchMinRunes = 3
	}
	if cfg.SearchPageSize <= 0 {
		cfg.SearchPageSize = 25
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 5 * time.Second
	}
	return &Service{tx: tx, kernel: kernel, refs: refs, cfg: cfg, newID: id.NewV7}, nil
}

// Actor is who reads, as the request established it.
type Actor struct {
	Principal   id.UUID
	Emergency   bool
	Route       string
	Correlation string
}

// Summary is one search result.
type Summary struct {
	PrincipalID id.UUID `json:"principal_id"`
	Username    string  `json:"username"`
	Email       string  `json:"email,omitempty"`
	SubjectType string  `json:"subject_type"`
	State       string  `json:"state"`
}

// Principal is one Principal as an investigator reads it.
type Principal struct {
	Summary
	Realm            string     `json:"realm"`
	WorkloadOwner    *id.UUID   `json:"workload_owner,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ActivatedAt      *time.Time `json:"activated_at"`
	QuarantinedAt    *time.Time `json:"quarantined_at"`
	QuarantineReason string     `json:"quarantine_reason,omitempty"`
	Version          int64      `json:"version"`
	// SecurityVersion is the version a security command on the Principal names as expected_version:
	// 1 before any command (TDD-identity-control-005 §Containment as Built).
	SecurityVersion int64 `json:"security_version"`
}

// Session is one of a Principal's sessions. No IP address, user agent or kernel identifier.
type Session struct {
	Started    time.Time `json:"started"`
	LastAccess time.Time `json:"last_access"`
	Clients    []string  `json:"clients"`
}

// Authenticator is one authenticator's metadata, and a reference a command names it by.
type Authenticator struct {
	SecurityRef string    `json:"security_ref,omitempty"`
	Type        string    `json:"type"`
	Label       string    `json:"label,omitempty"`
	Created     time.Time `json:"created"`
	// RemainingCodes and TotalCodes are how many codes of a recovery-code set are unused, and how
	// many it began with.
	RemainingCodes *int `json:"remaining_codes,omitempty"`
	TotalCodes     *int `json:"total_codes,omitempty"`
}

// FederationLink is a link to an identity provider's account.
type FederationLink struct {
	Provider string `json:"provider"`
	UserName string `json:"user_name"`
}

// Finding is a reconciler finding about the Principal.
type Finding struct {
	FindingID  id.UUID    `json:"finding_id"`
	Class      string     `json:"class"`
	DetectedAt time.Time  `json:"detected_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
	Resolution string     `json:"resolution,omitempty"`
}

// Event is one kernel event in the Principal's record (TDD-identity-control-007): a user event the
// Principal was the subject of, or an admin event it acted in. No IP address, session or kernel
// identifier, and no admin resource path, which names kernel identifiers (TDD-identity-control-005
// §Read Authorization and Disclosure).
type Event struct {
	OccurredAt time.Time `json:"occurred_at"`
	// Kind is user or admin; Role is subject for a user event and actor for an admin event.
	Kind string `json:"kind"`
	Role string `json:"role"`
	// Type is the kernel's: LOGIN, LOGIN_ERROR, LOGOUT, ...; or CREATE, UPDATE, DELETE, ACTION.
	Type         string `json:"type"`
	Outcome      string `json:"outcome"`
	Error        string `json:"error,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
}

// PurposeRevoke is the purpose an authenticator's reference is sealed for: the administrative
// revocation (TDD-identity-control-005 §API).
const PurposeRevoke = securityref.PurposeAdminRevoke

const recordStatement = `INSERT INTO identity.privileged_access
    (access_id, actor_principal_id, subject_principal_id, action, route, query, result_count, outcome,
     correlation_id, emergency)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'served', $8, $9)`

// record writes the evidence of one served read.
func (s *Service) record(ctx context.Context, tx db.Tx, actor Actor, subject *id.UUID, action string, query *string, count int) error {
	accessID, err := s.newID()
	if err != nil {
		return fmt.Errorf("investigation: mint access_id: %w", err)
	}
	var subjectArg any
	if subject != nil {
		subjectArg = subject.String()
	}
	var queryArg any
	if query != nil {
		queryArg = *query
	}
	if _, err := tx.Exec(ctx, recordStatement, accessID.String(), actor.Principal.String(), subjectArg, action,
		actor.Route, queryArg, count, actor.Correlation, actor.Emergency); err != nil {
		return fmt.Errorf("investigation: record the read: %w", err)
	}
	return nil
}

// escapeLike makes a search term literal inside a LIKE pattern.
var escapeLike = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

const searchStatement = `SELECT principal_id::text, username, coalesce(email, ''), subject_type, state
FROM identity.principal_mapping
WHERE realm = $1
  AND (lower(username) LIKE $2 ESCAPE '\' OR lower(coalesce(email, '')) LIKE $2 ESCAPE '\')
ORDER BY username, principal_id
LIMIT $3`

// Search finds Principals whose username or email begins with the query. It is a lookup for one
// subject, never a way to list the population: a query shorter than the floor, or made only of
// wildcards, is refused before anything is read.
//
// It reads the creation payload this service holds rather than enumerating the kernel, so a
// username changed in the console is found by its original value.
func (s *Service) Search(ctx context.Context, actor Actor, query string) ([]Summary, error) {
	query = strings.TrimSpace(query)
	if utf8.RuneCountInString(strings.Trim(query, "*%_ ")) < s.cfg.SearchMinRunes {
		return nil, fmt.Errorf("%w: at least %d characters that are not wildcards", ErrQuery, s.cfg.SearchMinRunes)
	}
	pattern := escapeLike.Replace(strings.ToLower(query)) + "%"
	var results []Summary
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, searchStatement, string(s.cfg.Realm), pattern, s.cfg.SearchPageSize)
		if err != nil {
			return fmt.Errorf("investigation: search: %w", err)
		}
		results = []Summary{}
		for rows.Next() {
			var (
				r   Summary
				pid string
			)
			if err := rows.Scan(&pid, &r.Username, &r.Email, &r.SubjectType, &r.State); err != nil {
				rows.Close()
				return fmt.Errorf("investigation: scan: %w", err)
			}
			if r.PrincipalID, err = id.Parse(pid); err != nil {
				rows.Close()
				return err
			}
			results = append(results, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return s.record(ctx, tx, actor, nil, "search", &query, len(results))
	})
	return results, err
}

const principalStatement = `SELECT m.principal_id::text, m.username, coalesce(m.email, ''), m.subject_type, m.state, m.realm,
       coalesce(m.workload_owner::text, ''), m.created_at, m.activated_at, m.quarantined_at,
       coalesce(m.quarantine_reason, ''), m.version, coalesce(m.keycloak_user_id, ''), coalesce(s.version, 1)
FROM identity.principal_mapping m
LEFT JOIN identity.security_subject_state s ON s.principal_id = m.principal_id
WHERE m.principal_id = $1 AND m.realm = $2`

// readPrincipal reads one mapping and its kernel user identifier, which stays in this package.
func (s *Service) readPrincipal(ctx context.Context, tx db.Tx, principalID id.UUID) (Principal, keycloak.UserID, error) {
	rows, err := tx.Query(ctx, principalStatement, principalID.String(), string(s.cfg.Realm))
	if err != nil {
		return Principal{}, "", fmt.Errorf("investigation: read the Principal: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Principal{}, "", err
		}
		return Principal{}, "", ErrNotFound
	}
	var (
		p                      Principal
		pid, owner, kernelUser string
	)
	if err := rows.Scan(&pid, &p.Username, &p.Email, &p.SubjectType, &p.State, &p.Realm, &owner, &p.CreatedAt,
		&p.ActivatedAt, &p.QuarantinedAt, &p.QuarantineReason, &p.Version, &kernelUser, &p.SecurityVersion); err != nil {
		return Principal{}, "", fmt.Errorf("investigation: scan the Principal: %w", err)
	}
	if p.PrincipalID, err = id.Parse(pid); err != nil {
		return Principal{}, "", err
	}
	if owner != "" {
		parsed, err := id.Parse(owner)
		if err != nil {
			return Principal{}, "", err
		}
		p.WorkloadOwner = &parsed
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return p, keycloak.UserID(kernelUser), nil
}

// Principal reads one Principal.
func (s *Service) Principal(ctx context.Context, actor Actor, principalID id.UUID) (Principal, error) {
	var p Principal
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		if p, _, err = s.readPrincipal(ctx, tx, principalID); err != nil {
			return err
		}
		return s.record(ctx, tx, actor, &principalID, "read.principal", nil, 1)
	})
	return p, err
}

// kernelUser resolves the Principal's kernel user, outside any transaction held across the call.
func (s *Service) kernelUser(ctx context.Context, principalID id.UUID) (keycloak.UserID, error) {
	var user keycloak.UserID
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		var err error
		_, user, err = s.readPrincipal(ctx, tx, principalID)
		return err
	})
	if err != nil {
		return "", err
	}
	if user == "" {
		return "", ErrUnlinked
	}
	return user, nil
}

// served records one kernel read once it has an answer, and the answer is returned only if the
// record commits.
func (s *Service) served(ctx context.Context, actor Actor, principalID id.UUID, action string, count int) error {
	return s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return s.record(ctx, tx, actor, &principalID, action, nil, count)
	})
}

func (s *Service) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.cfg.CallTimeout)
}

// Sessions reads the Principal's sessions from the kernel.
func (s *Service) Sessions(ctx context.Context, actor Actor, principalID id.UUID) ([]Session, error) {
	user, err := s.kernelUser(ctx, principalID)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := s.call(ctx)
	defer cancel()
	raw, err := s.kernel.UserSessions(callCtx, s.cfg.Realm, user)
	if err != nil {
		return nil, fmt.Errorf("investigation: read the sessions: %w", err)
	}
	sessions := make([]Session, 0, len(raw))
	for _, r := range raw {
		sessions = append(sessions, Session{Started: r.Started, LastAccess: r.LastAccess, Clients: r.Clients})
	}
	if err := s.served(ctx, actor, principalID, "read.sessions", len(sessions)); err != nil {
		return nil, err
	}
	return sessions, nil
}

// Authenticators reads the Principal's authenticators' metadata from the kernel, each with a
// reference a revocation names it by.
func (s *Service) Authenticators(ctx context.Context, actor Actor, principalID id.UUID) ([]Authenticator, error) {
	user, err := s.kernelUser(ctx, principalID)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := s.call(ctx)
	defer cancel()
	raw, err := s.kernel.UserCredentials(callCtx, s.cfg.Realm, user)
	if err != nil {
		return nil, fmt.Errorf("investigation: read the authenticators: %w", err)
	}
	authenticators := make([]Authenticator, 0, len(raw))
	for _, r := range raw {
		a := Authenticator{Type: r.Type, Label: r.Label, Created: r.Created, RemainingCodes: r.Remaining,
			TotalCodes: r.Total}
		if s.refs != nil {
			if a.SecurityRef, err = s.refs.Seal(securityref.KindCredential, principalID, PurposeRevoke,
				string(s.cfg.Realm), r.ID); err != nil {
				return nil, err
			}
		}
		authenticators = append(authenticators, a)
	}
	if err := s.served(ctx, actor, principalID, "read.authenticators", len(authenticators)); err != nil {
		return nil, err
	}
	return authenticators, nil
}

// FederationLinks reads the Principal's links to identity providers from the kernel.
func (s *Service) FederationLinks(ctx context.Context, actor Actor, principalID id.UUID) ([]FederationLink, error) {
	user, err := s.kernelUser(ctx, principalID)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := s.call(ctx)
	defer cancel()
	raw, err := s.kernel.UserFederatedIdentities(callCtx, s.cfg.Realm, user)
	if err != nil {
		return nil, fmt.Errorf("investigation: read the federation links: %w", err)
	}
	links := make([]FederationLink, 0, len(raw))
	for _, r := range raw {
		links = append(links, FederationLink{Provider: r.Provider, UserName: r.UserName})
	}
	if err := s.served(ctx, actor, principalID, "read.federation-links", len(links)); err != nil {
		return nil, err
	}
	return links, nil
}

const findingsStatement = `SELECT finding_id::text, finding_class, detected_at, resolved_at, coalesce(resolution, '')
FROM identity.principal_finding
WHERE principal_id = $1
ORDER BY detected_at DESC, finding_id DESC
LIMIT 100`

// Findings reads the reconciler's findings about the Principal, newest first.
func (s *Service) Findings(ctx context.Context, actor Actor, principalID id.UUID) ([]Finding, error) {
	var findings []Finding
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, _, err := s.readPrincipal(ctx, tx, principalID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, findingsStatement, principalID.String())
		if err != nil {
			return fmt.Errorf("investigation: read the findings: %w", err)
		}
		findings = []Finding{}
		for rows.Next() {
			var (
				f   Finding
				fid string
			)
			if err := rows.Scan(&fid, &f.Class, &f.DetectedAt, &f.ResolvedAt, &f.Resolution); err != nil {
				rows.Close()
				return err
			}
			if f.FindingID, err = id.Parse(fid); err != nil {
				rows.Close()
				return err
			}
			findings = append(findings, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return s.record(ctx, tx, actor, &principalID, "read.findings", nil, len(findings))
	})
	return findings, err
}

const eventsStatement = `SELECT occurred_at, kind, event_type, coalesce(error, ''), coalesce(client_id, ''),
       coalesce(resource_type, '')
FROM identity.kernel_event
WHERE principal_id = $1
ORDER BY occurred_at DESC, kc_event_id DESC
LIMIT 100`

// Events reads the Principal's kernel events, newest first: the hundred most recent the record holds
// (TDD-identity-control-005 2.9.0, TDD-identity-control-007).
func (s *Service) Events(ctx context.Context, actor Actor, principalID id.UUID) ([]Event, error) {
	var events []Event
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, _, err := s.readPrincipal(ctx, tx, principalID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, eventsStatement, principalID.String())
		if err != nil {
			return fmt.Errorf("investigation: read the events: %w", err)
		}
		events = []Event{}
		for rows.Next() {
			var e Event
			if err := rows.Scan(&e.OccurredAt, &e.Kind, &e.Type, &e.Error, &e.ClientID, &e.ResourceType); err != nil {
				rows.Close()
				return err
			}
			e.OccurredAt = e.OccurredAt.UTC()
			e.Role, e.Outcome = "subject", "success"
			if e.Kind == "admin" {
				e.Role = "actor"
			}
			if e.Error != "" {
				e.Outcome = "failure"
			}
			events = append(events, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		return s.record(ctx, tx, actor, &principalID, "read.events", nil, len(events))
	})
	return events, err
}
