package securitystate

// A person's reads of their own security state (TDD-identity-control-005 §Self-Service as Built).
// Nothing here is evidenced: a person reading their own state discloses it to no one. Each object
// carries a reference sealed for the caller and a self purpose, which opens on no administrative
// route.

import (
	"context"
	"fmt"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/securityref"
)

// MySession is one of the caller's sessions. Current marks the one the request came from.
type MySession struct {
	SecurityRef string    `json:"security_ref"`
	Started     time.Time `json:"started"`
	LastAccess  time.Time `json:"last_access"`
	Clients     []string  `json:"clients"`
	Current     bool      `json:"current"`
}

// MyAuthenticator is one of the caller's authenticators.
type MyAuthenticator struct {
	SecurityRef string    `json:"security_ref"`
	Type        string    `json:"type"`
	Label       string    `json:"label,omitempty"`
	Created     time.Time `json:"created"`
	// RemainingCodes is how many codes of a recovery-code set are unused (ADR-IAM-005 §5.4).
	RemainingCodes *int `json:"remaining_codes,omitempty"`
}

const ownUserStatement = `SELECT coalesce(keycloak_user_id, '') FROM identity.principal_mapping
WHERE principal_id = $1 AND realm = $2`

// ownUser is the caller's kernel user, which never leaves this package.
func (s *Service) ownUser(ctx context.Context, principal id.UUID) (keycloak.UserID, error) {
	var user string
	err := s.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, ownUserStatement, principal.String(), string(s.cfg.Realm))
		if err != nil {
			return fmt.Errorf("securitystate: read the caller: %w", err)
		}
		defer rows.Close()
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return ErrNotFound
		}
		return rows.Scan(&user)
	})
	if err != nil {
		return "", err
	}
	if user == "" {
		return "", fmt.Errorf("%w: it has no kernel user", ErrState)
	}
	return keycloak.UserID(user), nil
}

// MySessions lists the caller's sessions, marking the one whose identifier is the token's sid.
func (s *Service) MySessions(ctx context.Context, principal id.UUID, sid string) ([]MySession, error) {
	user, err := s.ownUser(ctx, principal)
	if err != nil {
		return nil, err
	}
	var raw []keycloak.Session
	if err := s.call(ctx, func(ctx context.Context) error {
		var err error
		raw, err = s.kernel.UserSessions(ctx, s.cfg.Realm, user)
		return err
	}); err != nil {
		return nil, fmt.Errorf("securitystate: read the sessions: %w", err)
	}
	sessions := make([]MySession, 0, len(raw))
	for _, r := range raw {
		ref, err := s.refs.Seal(securityref.KindSession, principal, securityref.PurposeSelfSessionTerminate,
			string(s.cfg.Realm), r.ID)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, MySession{SecurityRef: ref, Started: r.Started, LastAccess: r.LastAccess,
			Clients: r.Clients, Current: sid != "" && r.ID == sid})
	}
	return sessions, nil
}

// MyAuthenticators lists the caller's authenticators' metadata.
func (s *Service) MyAuthenticators(ctx context.Context, principal id.UUID) ([]MyAuthenticator, error) {
	user, err := s.ownUser(ctx, principal)
	if err != nil {
		return nil, err
	}
	var raw []keycloak.Credential
	if err := s.call(ctx, func(ctx context.Context) error {
		var err error
		raw, err = s.kernel.UserCredentials(ctx, s.cfg.Realm, user)
		return err
	}); err != nil {
		return nil, fmt.Errorf("securitystate: read the authenticators: %w", err)
	}
	authenticators := make([]MyAuthenticator, 0, len(raw))
	for _, r := range raw {
		ref, err := s.refs.Seal(securityref.KindCredential, principal, securityref.PurposeSelfAuthenticatorRemove,
			string(s.cfg.Realm), r.ID)
		if err != nil {
			return nil, err
		}
		authenticators = append(authenticators, MyAuthenticator{SecurityRef: ref, Type: r.Type, Label: r.Label,
			Created: r.Created, RemainingCodes: r.Remaining})
	}
	return authenticators, nil
}

// MyOperation reads an operation whose subject is the caller, and nothing else.
func (s *Service) MyOperation(ctx context.Context, principal, operationID id.UUID) (Operation, error) {
	op, err := s.Get(ctx, operationID)
	if err != nil {
		return Operation{}, err
	}
	if op.PrincipalID != principal {
		return Operation{}, ErrNotFound
	}
	return op, nil
}
