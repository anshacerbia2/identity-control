package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxResponseBytes bounds what a kernel response may cost this process.
//
// A paged user enumeration is the largest legitimate body, and the page size is ours to
// choose. The bound exists so a misbehaving or compromised kernel cannot drive this service
// out of memory with one response.
const maxResponseBytes = 8 << 20

// response is a completed round trip.
type response struct {
	status   int
	body     []byte
	location string
	closer   io.Closer
}

func (r *response) Close() {
	if r != nil && r.closer != nil {
		_ = r.closer.Close()
	}
}

// do performs one authenticated round trip and maps the outcome onto the sentinel errors.
//
// mutating discriminates the two failure classes that matter. A transport failure on a
// non-idempotent request may mean the request was written and the response lost, so it is
// reported as ErrAmbiguous and the caller must read the kernel state back. The same failure on
// an idempotent request is ErrUnavailable, because repeating it costs a call rather than a
// duplicated effect.
//
// The asymmetry is deliberate and conservative: Go's client does not reliably say whether
// bytes reached the server, so a create treats every transport failure as possibly-succeeded.
// Being wrong in that direction costs one extra read; being wrong in the other direction
// creates a second Principal.
func (a *Admin) do(
	ctx context.Context,
	method, path string,
	query url.Values,
	payload any,
	mutating bool,
) (*response, error) {
	token, err := a.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := strings.TrimRight(a.cfg.BaseURL, "/") + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if payload != nil {
		encoded, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return nil, fmt.Errorf("keycloak: encode request: %w", marshalErr)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("keycloak: build request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	raw, err := a.client.Do(request)
	if err != nil {
		// No status was received. The request may or may not have been processed.
		if mutating {
			return nil, fmt.Errorf("keycloak: %s %s did not return a status: %w", method, path, ErrAmbiguous)
		}
		return nil, fmt.Errorf("keycloak: %s %s failed: %w", method, path, ErrUnavailable)
	}

	body, readErr := io.ReadAll(io.LimitReader(raw.Body, maxResponseBytes))
	if readErr != nil {
		raw.Body.Close()
		// The server answered and the body was lost mid-stream. For a mutation the effect
		// almost certainly landed, so this is ambiguous rather than unavailable.
		if mutating {
			return nil, fmt.Errorf("keycloak: %s %s response was truncated: %w", method, path, ErrAmbiguous)
		}
		return nil, fmt.Errorf("keycloak: %s %s response was truncated: %w", method, path, ErrUnavailable)
	}

	result := &response{
		status:   raw.StatusCode,
		body:     body,
		location: raw.Header.Get("Location"),
		closer:   raw.Body,
	}

	if statusErr := classify(raw.StatusCode, method, path); statusErr != nil {
		result.Close()
		return nil, statusErr
	}
	return result, nil
}

// classify maps an HTTP status onto a sentinel error.
//
// The response body is never included. A kernel error body can quote the request, and the
// request carries the attributes of a Principal, so echoing it upward would put identity data
// into whatever log the caller writes.
func classify(status int, method, path string) error {
	switch {
	case status >= 200 && status < 300:
		return nil

	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		// Not retried and not treated as transient. The administration service account is
		// missing a role, which is a deployment defect: retrying cannot grant it, and
		// treating it as unavailable would hide a misconfiguration behind a backoff.
		return fmt.Errorf("keycloak: %s %s rejected the administration credential: %w",
			method, path, ErrForbidden)

	case status == http.StatusNotFound:
		return fmt.Errorf("keycloak: %s %s: %w", method, path, ErrNotFound)

	case status == http.StatusConflict:
		return fmt.Errorf("keycloak: %s %s: %w", method, path, ErrConflict)

	case status == http.StatusTooManyRequests:
		return fmt.Errorf("keycloak: %s %s was rate limited: %w", method, path, ErrUnavailable)

	case status >= 500:
		return fmt.Errorf("keycloak: %s %s returned status %d: %w", method, path, status, ErrUnavailable)

	default:
		// A 4xx this client did not anticipate is a defect in the request this code built,
		// not a transient condition. It is reported as unavailable rather than silently
		// succeeding, and the status is named so an operator can see which one it was.
		return fmt.Errorf("keycloak: %s %s returned unexpected status %d: %w",
			method, path, status, ErrUnavailable)
	}
}

// tokenResponse is the client-credentials grant response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// accessToken returns a cached token, acquiring one when the cache is empty or near expiry.
//
// The token is acquired with the client-credentials grant and held in memory only. It is never
// logged, never included in an error, and never written anywhere: it grants user creation and
// credential rotation across the realm, which makes it the most valuable string this process
// holds.
func (a *Admin) accessToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Now().Add(a.cfg.TokenLeeway).Before(a.tokenExpiry) {
		return a.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", a.cfg.ClientID)
	form.Set("client_secret", a.cfg.ClientSecret)

	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(a.cfg.BaseURL, "/"), url.PathEscape(string(a.cfg.TokenRealm)))

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("keycloak: build token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	raw, err := a.client.Do(request)
	if err != nil {
		// A token acquisition is idempotent, so a transport failure is never ambiguous.
		return "", fmt.Errorf("keycloak: token endpoint unreachable: %w", ErrUnavailable)
	}
	defer raw.Body.Close()

	body, err := io.ReadAll(io.LimitReader(raw.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("keycloak: token response was truncated: %w", ErrUnavailable)
	}

	if raw.StatusCode == http.StatusUnauthorized || raw.StatusCode == http.StatusForbidden ||
		raw.StatusCode == http.StatusBadRequest {
		// The credential itself is wrong. Reported as forbidden rather than unavailable so a
		// deployment failure is not retried indefinitely behind a backoff. The response body
		// is discarded: an OAuth error response can echo the client identifier.
		return "", fmt.Errorf("keycloak: the administration credential was rejected: %w", ErrForbidden)
	}
	if raw.StatusCode < 200 || raw.StatusCode >= 300 {
		return "", fmt.Errorf("keycloak: token endpoint returned status %d: %w", raw.StatusCode, ErrUnavailable)
	}

	var decoded tokenResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("keycloak: decode token response: %w", ErrUnavailable)
	}
	if decoded.AccessToken == "" {
		return "", fmt.Errorf("keycloak: token response carried no access token: %w", ErrUnavailable)
	}
	if decoded.ExpiresIn <= 0 {
		// A token with no stated lifetime is treated as single-use rather than cached
		// forever. Caching an unknown lifetime is how a service starts presenting an expired
		// token and reading the resulting 401 as a permission problem.
		a.token, a.tokenExpiry = "", time.Time{}
		return decoded.AccessToken, nil
	}

	a.token = decoded.AccessToken
	a.tokenExpiry = time.Now().Add(time.Duration(decoded.ExpiresIn) * time.Second)
	return a.token, nil
}
