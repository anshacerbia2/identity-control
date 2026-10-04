// Package organization is this service's client of Organization Control, as the projection consumer
// of its provider:identity-control grants (TDD-identity-control-006).
//
// It calls the consumer routes only -- the provider authority snapshot, the bootstrap mark, progress
// and the frontier -- as this service's workload, with an access token from foundation-platform's
// clientauth. It is the one declared cross-domain call this repository makes (arch.json).
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
	var encoded io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("organization: encoding the request: %w", err)
		}
		encoded = bytes.NewReader(raw)
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("organization: obtaining the workload token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, encoded)
	if err != nil {
		return fmt.Errorf("organization: building the request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("organization: %s %s: %w", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("organization: reading %s %s: %w", method, path, err)
	}
	if response.StatusCode == http.StatusUnauthorized {
		c.tokens.Invalidate()
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// The body is a problem document from Organization Control, naming no secret; its title is
		// enough for an operator, and the status says which way to look.
		return fmt.Errorf("organization: %s %s answered %d", method, path, response.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("organization: decoding %s %s: %w", method, path, err)
	}
	return nil
}

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
		if err := c.call(ctx, http.MethodPost, "/v1/projections/organization/snapshot",
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
