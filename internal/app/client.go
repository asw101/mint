package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the REST endpoint for github.com. GitHub Enterprise
// Server installs use https://<host>/api/v3.
const DefaultBaseURL = "https://api.github.com"

// maxResponseBytes caps how much of a response body is read, so a misrouted
// request cannot exhaust memory.
const maxResponseBytes = 4 << 20

// Client calls the App-authenticated subset of the GitHub REST API.
type Client struct {
	AppID     string
	Signer    Signer
	BaseURL   string
	HTTP      *http.Client
	UserAgent string

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Installation is one account an App has been installed on.
type Installation struct {
	ID                  int64             `json:"id"`
	Account             Account           `json:"account"`
	RepositorySelection string            `json:"repository_selection"`
	Permissions         map[string]string `json:"permissions"`
}

// Account is the user or organization owning an installation.
type Account struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// Token is a minted installation access token.
type Token struct {
	Token               string            `json:"token"`
	ExpiresAt           time.Time         `json:"expires_at"`
	Permissions         map[string]string `json:"permissions"`
	RepositorySelection string            `json:"repository_selection"`
	Repositories        []Repository      `json:"repositories,omitempty"`
}

// Repository is a repo a token has been scoped to.
type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// TokenRequest narrows a token below the installation's own grant. Both
// fields are optional; omitting them yields the installation's full access.
type TokenRequest struct {
	// Repositories are bare repo names, not owner/name — the API scopes
	// within the installation's account.
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

// APIError is a non-2xx response from the API.
type APIError struct {
	Status  int
	Message string
	Body    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("github api: %s (HTTP %d)", e.Message, e.Status)
	}
	return fmt.Sprintf("github api: HTTP %d: %s", e.Status, e.Body)
}

// Installations lists every account the App is installed on.
func (c *Client) Installations(ctx context.Context) ([]Installation, error) {
	var all []Installation
	for page := 1; ; page++ {
		var batch []Installation
		path := fmt.Sprintf("/app/installations?per_page=100&page=%d", page)
		if err := c.do(ctx, http.MethodGet, path, nil, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			return all, nil
		}
	}
}

// InstallationForRepo resolves the installation covering a single repository.
func (c *Client) InstallationForRepo(ctx context.Context, owner, repo string) (*Installation, error) {
	var installation Installation
	path := fmt.Sprintf("/repos/%s/%s/installation", owner, repo)
	if err := c.do(ctx, http.MethodGet, path, nil, &installation); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return nil, fmt.Errorf("app is not installed on %s/%s (or cannot see it)", owner, repo)
		}
		return nil, err
	}
	return &installation, nil
}

// Installation fetches a single installation, so a daemon given an explicit
// installation ID can still learn which account it belongs to.
func (c *Client) Installation(ctx context.Context, id int64) (*Installation, error) {
	var installation Installation
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/app/installations/%d", id), nil, &installation); err != nil {
		return nil, err
	}
	return &installation, nil
}

// CreateToken mints an installation access token.
func (c *Client) CreateToken(ctx context.Context, installationID int64, req TokenRequest) (*Token, error) {
	var token Token
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	if err := c.do(ctx, http.MethodPost, path, req, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// JWT mints the App JWT this client authenticates with. Exposed so the CLI
// can print one for debugging.
func (c *Client) JWT() (string, error) {
	return MintJWT(c.Signer, c.AppID, c.now())
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	jwt, err := c.JWT()
	if err != nil {
		return err
	}

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, payload)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", c.userAgent())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return newAPIError(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func newAPIError(status int, body []byte) error {
	apiErr := &APIError{Status: status, Body: strings.TrimSpace(string(body))}
	var parsed struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		apiErr.Message = parsed.Message
	}
	return apiErr
}

func (c *Client) baseURL() string {
	if c.BaseURL == "" {
		return DefaultBaseURL
	}
	return strings.TrimSuffix(c.BaseURL, "/")
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) userAgent() string {
	if c.UserAgent == "" {
		return "ghapp"
	}
	return c.UserAgent
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
