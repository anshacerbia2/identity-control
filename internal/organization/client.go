// Package organization is this service's client of Organization Control, as the projection consumer
// of its provider:identity-control grants (TDD-identity-control-006).
//
// It calls the consumer routes -- the provider authority snapshot, the bootstrap mark, progress, the
// frontier and reconcile -- and the invitation resolve route (ADR-IAM-011 §5.7,
// TDD-identity-control-001 1.26.0 §Enrolment From an Invitation), as this service's workload, with an
// access token from foundation-platform's clientauth. It is the one declared cross-domain call this
// repository makes (arch.json).
package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/clientauth"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/providerauthority"
	"github.com/anshacerbia2/identity-control/internal/tenantcontext"
)

// TokenSource supplies this service's workload token: clientauth.Tokens in production.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	Invalidate()
}

// Config is one consumer at one Organization Control.
type Config struct {
	BaseURL  string
	Consumer string
	Tokens   TokenSource
	// Client defaults to one with a 10 s timeout.
	Client *http.Client
}

// Client calls Organization Control's consumer routes.
type Client struct {
	base     string
	consumer string
	tokens   TokenSource
	http     *http.Client
}

// New builds the client.
func New(cfg Config) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	switch {
	case err != nil || parsed.Scheme == "" || parsed.Host == "":
		return nil, fmt.Errorf("organization: %q is not an absolute URL", cfg.BaseURL)
	case strings.TrimSpace(cfg.Consumer) == "":
		return nil, errors.New("organization: the consumer name is required")
	case cfg.Tokens == nil:
		return nil, errors.New("organization: a workload token source is required")
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{base: strings.TrimRight(parsed.String(), "/"), consumer: cfg.Consumer, tokens: cfg.Tokens, http: client}, nil
}

// Workload is this service's workload client in the kernel, which it calls Organization Control as.
type Workload struct {
	BaseURL  string
	ClientID string
	KeyFile  string
	TokenURL string
	// Audience is the kernel's issuer, which the assertion names (RFC 7523 §3).
	Audience string
}

// NewWorkload builds the client for the provider authority consumer, authenticating with a
// private_key_jwt assertion signed by the key at KeyFile (STD-IAM-001 §3, RFC 7523).
func NewWorkload(w Workload) (*Client, error) {
	key, err := clientauth.LoadKey(w.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("organization: workload key: %w", err)
	}
	tokens, err := clientauth.NewTokens(clientauth.Config{
		TokenURL: w.TokenURL, Audience: w.Audience, ClientID: w.ClientID, Key: key,
	})
	if err != nil {
		return nil, fmt.Errorf("organization: workload token source: %w", err)
	}
	return New(Config{BaseURL: w.BaseURL, Consumer: providerauthority.Consumer, Tokens: tokens})
}

// maxResponse bounds what Organization Control may cost this process in one response.
const maxResponse = 8 << 20

// call sends one request as this service's workload and decodes a 2xx body into out. A 401 drops
// the cached token, so the next call presents a fresh one.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	status, raw, err := c.exchange(ctx, method, path, body)
	if err != nil {
		return err
	}
	if err := refusal(method, path, status); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("organization: decoding %s %s: %w", method, path, err)
	}
	return nil
}

// exchange sends one request as this service's workload and returns the status and the bounded
// body. A 401 drops the cached token, so the next call presents a fresh one.
func (c *Client) exchange(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var encoded io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("organization: encoding the request: %w", err)
		}
		encoded = bytes.NewReader(raw)
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("organization: obtaining the workload token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, encoded)
	if err != nil {
		return 0, nil, fmt.Errorf("organization: building the request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("organization: %s %s: %w", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponse))
	if err != nil {
		return 0, nil, fmt.Errorf("organization: reading %s %s: %w", method, path, err)
	}
	if response.StatusCode == http.StatusUnauthorized {
		c.tokens.Invalidate()
	}
	return response.StatusCode, raw, nil
}

// refusal is the error a status other than 2xx is: ErrRefused for a 403, the status otherwise.
func refusal(method, path string, status int) error {
	if status == http.StatusForbidden {
		return fmt.Errorf("organization: %s %s answered 403: %w", method, path, ErrRefused)
	}
	if status < 200 || status >= 300 {
		// The body is a problem document from Organization Control, naming no secret; its title is
		// enough for an operator, and the status says which way to look.
		return fmt.Errorf("organization: %s %s answered %d", method, path, status)
	}
	return nil
}

// ErrRefused is a request Organization Control answered 403: this consumer is not permitted it, such
// as a snapshot of event types its registration does not subscribe to.
var ErrRefused = errors.New("organization: refused")

// Snapshot is the provider authority snapshot, every page under one mark.
type Snapshot struct {
	Mark   int64
	Grants []providerauthority.Grant
}

type snapshotRequest struct {
	ConsumerID string `json:"consumer_id"`
	PageSize   int    `json:"page_size,omitempty"`
	Cursor     string `json:"cursor,omitempty"`
	Mark       *int64 `json:"mark,omitempty"`
}

type snapshotPage struct {
	HighWaterMark int64                     `json:"high_water_mark"`
	Grants        []providerauthority.Grant `json:"grants"`
	Cursor        string                    `json:"cursor"`
}

// maxPages bounds a snapshot: provider grants are counted in tens, and a cursor that never ends is
// a producer defect rather than a reason to loop forever.
const maxPages = 1000

// ProviderSnapshot reads the whole provider authority snapshot, page by page under the first page's
// mark (TDD-organization-control-002 §Bootstrap Contract).
func (c *Client) ProviderSnapshot(ctx context.Context) (Snapshot, error) {
	var (
		snapshot Snapshot
		cursor   string
		mark     *int64
	)
	for page := 0; page < maxPages; page++ {
		var got snapshotPage
		if err := c.call(ctx, http.MethodPost, "/v1/projections/provider-authority/snapshot",
			snapshotRequest{ConsumerID: c.consumer, Cursor: cursor, Mark: mark}, &got); err != nil {
			return Snapshot{}, err
		}
		if mark == nil {
			first := got.HighWaterMark
			mark, snapshot.Mark = &first, first
		}
		snapshot.Grants = append(snapshot.Grants, got.Grants...)
		if got.Cursor == "" {
			return snapshot, nil
		}
		cursor = got.Cursor
	}
	return Snapshot{}, fmt.Errorf("organization: the snapshot did not end within %d pages", maxPages)
}

type organizationPage struct {
	HighWaterMark int64                       `json:"high_water_mark"`
	Rows          []tenantcontext.SnapshotRow `json:"rows"`
	Cursor        string                      `json:"cursor"`
}

// maxOrganizationPages bounds the Organization snapshot. Its pages hold up to the producer's default
// of 1000 Memberships, so this reads ten million before it refuses.
const maxOrganizationPages = 10000

// OrganizationSnapshot reads the whole Organization snapshot, the active Memberships and their
// Tenants, page by page under the first page's mark (TDD-organization-control-002 §Bootstrap Contract).
func (c *Client) OrganizationSnapshot(ctx context.Context) (int64, []tenantcontext.SnapshotRow, error) {
	var (
		rows   []tenantcontext.SnapshotRow
		cursor string
		mark   *int64
	)
	for page := 0; page < maxOrganizationPages; page++ {
		var got organizationPage
		if err := c.call(ctx, http.MethodPost, "/v1/projections/snapshot",
			snapshotRequest{ConsumerID: c.consumer, Cursor: cursor, Mark: mark}, &got); err != nil {
			return 0, nil, err
		}
		if mark == nil {
			first := got.HighWaterMark
			mark = &first
		}
		rows = append(rows, got.Rows...)
		if got.Cursor == "" {
			return *mark, rows, nil
		}
		cursor = got.Cursor
	}
	return 0, nil, fmt.Errorf("organization: the snapshot did not end within %d pages", maxOrganizationPages)
}

// RecordBootstrap records with Organization Control the mark this consumer bootstrapped from, which
// is what permits its progress reports.
func (c *Client) RecordBootstrap(ctx context.Context, mark int64) error {
	return c.call(ctx, http.MethodPost, "/v1/projections/consumers/"+url.PathEscape(c.consumer)+"/bootstrap",
		map[string]int64{"mark": mark}, nil)
}

// ReportProgress reports the highest stream position this consumer applied.
func (c *Client) ReportProgress(ctx context.Context, appliedMark int64) error {
	return c.call(ctx, http.MethodPost, "/v1/projections/consumers/"+url.PathEscape(c.consumer)+"/progress",
		map[string]int64{"applied_mark": appliedMark}, nil)
}

type frontierResponse struct {
	OldestUnpublishedAgeSeconds float64 `json:"oldest_unpublished_age_seconds"`
	Unpublished                 bool    `json:"unpublished"`
	SecurityDebt                bool    `json:"security_debt"`
}

// Frontier reads this consumer's frontier: what it is owed and whether it carries security debt.
func (c *Client) Frontier(ctx context.Context) (providerauthority.Observation, error) {
	var got frontierResponse
	if err := c.call(ctx, http.MethodGet, "/v1/projections/frontier", nil, &got); err != nil {
		return providerauthority.Observation{}, err
	}
	return providerauthority.Observation{
		Owed:          got.Unpublished,
		OldestOwedAge: time.Duration(got.OldestUnpublishedAgeSeconds * float64(time.Second)),
		SecurityDebt:  got.SecurityDebt,
	}, nil
}

// Reconcile sends this consumer's report to Organization Control's reconcile route, as this
// consumer's workload, and returns what the comparison found (ADR-ORG-001 §5.7,
// TDD-identity-control-002 2.6.0). The body is the report as GET /v1/projections/tenant-context/report
// serves it, the shape the route takes: consumer_id, mark and rows. Until Organization Control admits a
// consumer on the route for its own consumer_id it answers 403, returned as ErrRefused.
func (c *Client) Reconcile(ctx context.Context, report tenantcontext.Report) (tenantcontext.ReconcileResult, error) {
	if report.ConsumerID != c.consumer {
		return tenantcontext.ReconcileResult{}, fmt.Errorf("organization: a report for %q sent as consumer %q", report.ConsumerID, c.consumer)
	}
	var result tenantcontext.ReconcileResult
	if err := c.call(ctx, http.MethodPost, "/v1/projections/reconcile", report, &result); err != nil {
		return tenantcontext.ReconcileResult{}, err
	}
	return result, nil
}

// Invitation is what Organization Control's resolve route answers for one pending, unexpired
// invitation: its identifier and the address it was sent to. It names no Tenant (ADR-IAM-011 §5.7).
type Invitation struct {
	ID      id.UUID
	Address string
}

const resolvePath = "/v1/invitations/resolve"

// The problem types the resolve route answers when there is no invitation to give
// (TDD-identity-control-001 1.26.0 §Enrolment From an Invitation).
const (
	problemNotAcceptable    = "https://problems.scnehaux.com/invitation-not-acceptable"
	problemValidationFailed = "https://problems.scnehaux.com/validation-failed"
)

type resolveRequest struct {
	Token string `json:"token"`
}

type resolveResponse struct {
	InvitationID     string `json:"invitation_id"`
	TargetIdentifier string `json:"target_identifier"`
}

type problem struct {
	Type string `json:"type"`
}

// ResolveInvitation asks Organization Control, as this service's workload, which invitation a token
// names (ADR-IAM-011 §5.7 (a) and (b)). The token travels in the JSON body only, never in the path or
// the query, and neither it nor the address is put in an error. The call changes nothing, so it sends
// no Idempotency-Key.
//
// found is false with no error for the route's one 404 (an unknown, expired, revoked or accepted
// token) and for its 400 (a malformed token): to the enrolment command both are an unknown token. A
// 404 or 400 of any other problem type is an error, since a missing route is not an unknown
// invitation. A 403 is ErrRefused: this workload holds no active invitation:resolve entry there. A
// 401 drops the cached token, as on the consumer routes, and is an error; so is any other status.
func (c *Client) ResolveInvitation(ctx context.Context, token string) (Invitation, bool, error) {
	status, raw, err := c.exchange(ctx, http.MethodPost, resolvePath, resolveRequest{Token: token})
	if err != nil {
		return Invitation{}, false, err
	}
	switch status {
	case http.StatusNotFound, http.StatusBadRequest:
		var got problem
		_ = json.Unmarshal(raw, &got)
		if (status == http.StatusNotFound && got.Type == problemNotAcceptable) ||
			(status == http.StatusBadRequest && got.Type == problemValidationFailed) {
			return Invitation{}, false, nil
		}
		return Invitation{}, false, fmt.Errorf("organization: POST %s answered %d without its problem type", resolvePath, status)
	case http.StatusOK:
	default:
		if err := refusal(http.MethodPost, resolvePath, status); err != nil {
			return Invitation{}, false, err
		}
		// Only a 200 carries an invitation; another 2xx is not the contract.
		return Invitation{}, false, fmt.Errorf("organization: POST %s answered %d", resolvePath, status)
	}
	var got resolveResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		return Invitation{}, false, fmt.Errorf("organization: decoding POST %s: %w", resolvePath, err)
	}
	invitation, err := id.Parse(got.InvitationID)
	if err != nil || invitation.IsNil() {
		return Invitation{}, false, fmt.Errorf("organization: POST %s answered no invitation_id", resolvePath)
	}
	if strings.TrimSpace(got.TargetIdentifier) == "" {
		return Invitation{}, false, fmt.Errorf("organization: POST %s answered no target_identifier", resolvePath)
	}
	return Invitation{ID: invitation, Address: got.TargetIdentifier}, true, nil
}
