// Package tspolicy reads and writes a tailnet's policy file through the
// Tailscale API.
//
// It exists because the policy file is what grants mint its authority: a broker
// that can mint tokens but cannot manage the grants that authorize minting is
// half a tool, and hand-editing an ACL per environment is exactly the friction
// that makes people put it off.
//
// The credential that can rewrite the policy sits *above* the broker in the
// trust order, not inside it. Nothing here is reachable from the daemon: these
// are operator commands, run deliberately, with their own credentials. See
// Client.Set for the guard, and the package's two credential types for the
// separation that makes the routine paths incapable of writing rather than
// merely disinclined to.
package tspolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is Tailscale's API.
const DefaultBaseURL = "https://api.tailscale.com"

// DefaultTailnet is the API's name for "whichever tailnet this credential
// belongs to", which is the right answer whenever there is only one.
const DefaultTailnet = "-"

// contentType is what the API calls the policy file's format. Asking for
// HuJSON rather than JSON is what preserves comments and trailing commas, and
// the policy file is mostly comments explaining who may reach what: fetching it
// as plain JSON would silently discard the part a human wrote for other humans.
const contentType = "application/hujson"

// Client talks to one tailnet's policy file.
type Client struct {
	// Cred authorizes each request. A read-scoped credential can Fetch and
	// Validate and will be refused by the API on Set.
	Cred Credential
	// Tailnet defaults to DefaultTailnet.
	Tailnet string
	// BaseURL defaults to DefaultBaseURL.
	BaseURL string
	// HTTP defaults to a client with a sensible timeout.
	HTTP *http.Client
}

// Policy is a policy file and the version it was read at.
type Policy struct {
	// Body is the HuJSON source, comments intact.
	Body []byte
	// ETag identifies this exact version. Passing it back to Set is what makes
	// a write a compare-and-swap rather than a clobber: between a fetch and an
	// apply, somebody in the admin console may have changed the same file, and
	// the whole point of managing the ACL from a tool is that it must never be
	// the thing that quietly reverts a human's edit.
	ETag string
}

// Fetch returns the tailnet's current policy file.
func (c *Client) Fetch(ctx context.Context) (*Policy, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/acl", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", contentType)
	resp, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiError("fetch policy", resp, body)
	}
	return &Policy{Body: body, ETag: resp.Header.Get("ETag")}, nil
}

// Validate asks the API whether body would be accepted, without applying it.
//
// This is a real check against the tailnet's own state, not a syntax check: it
// catches a grant naming a tag that does not exist, which is the mistake that
// otherwise shows up as a node silently losing access.
func (c *Client) Validate(ctx context.Context, body []byte) error {
	req, err := c.newRequest(ctx, http.MethodPost, "/acl/validate", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, respBody, err := c.do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return apiError("validate policy", resp, respBody)
	}
	// A 200 does not mean valid. The endpoint answers 200 with a body
	// describing the problem, so a caller that checked only the status would
	// report a broken policy as fine.
	return validationProblem(respBody)
}

// Set replaces the policy file.
//
// etag must be the one from the Fetch this change was written against; an empty
// etag is refused rather than sent, because the API treats a missing If-Match
// as "overwrite whatever is there".
func (c *Client) Set(ctx context.Context, body []byte, etag string) error {
	if strings.TrimSpace(etag) == "" {
		return errors.New("refusing to write the policy file without an ETag: fetch it first, so a concurrent change in the admin console cannot be silently overwritten")
	}
	req, err := c.newRequest(ctx, http.MethodPost, "/acl", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("If-Match", quoteETag(etag))
	resp, respBody, err := c.do(req)
	if err != nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return validationProblem(respBody)
	case http.StatusPreconditionFailed:
		return errors.New("the policy file changed since it was fetched; re-run the diff and try again")
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Errorf("%w: this credential cannot write the policy file (it wants the policy_file scope, not policy_file:read)",
			apiError("set policy", resp, respBody))
	default:
		return apiError("set policy", resp, respBody)
	}
}

func (c *Client) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	tailnet := c.Tailnet
	if tailnet == "" {
		tailnet = DefaultTailnet
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	endpoint := strings.TrimSuffix(base, "/") + "/api/v2/tailnet/" + url.PathEscape(tailnet) + path

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	if c.Cred == nil {
		return nil, errors.New("no credential: see 'mint policy help' for where the secret is read from")
	}
	if err := c.Cred.authorize(ctx, req, c.httpClient()); err != nil {
		return nil, err
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, []byte, error) {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("reach %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	return resp, body, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// quoteETag makes sure the value goes out in the form If-Match wants, whether
// or not the ETag we were handed already carries its quotes.
func quoteETag(etag string) string {
	if strings.HasPrefix(etag, `"`) || strings.HasPrefix(etag, "W/") {
		return etag
	}
	return `"` + etag + `"`
}

// ValidationError is the API reporting that a policy file is not acceptable.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return "policy rejected: " + e.Message }

// validationProblem reads a 200 response for the problem report the validate
// and set endpoints return in place of an error status.
func validationProblem(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var report struct {
		Message string `json:"message"`
		Data    []struct {
			User  string `json:"user"`
			Error string `json:"error"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		// Not a problem report: the endpoint answered with the policy itself,
		// which is what success looks like.
		return nil
	}
	if report.Message == "" && len(report.Data) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString(report.Message)
	for _, d := range report.Data {
		fmt.Fprintf(&b, "\n  %s: %s", d.User, d.Error)
	}
	return &ValidationError{Message: strings.TrimSpace(b.String())}
}

// APIError is a non-success response from the Tailscale API.
type APIError struct {
	Op     string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	body := strings.TrimSpace(e.Body)
	if len(body) > 500 {
		body = body[:500] + "…"
	}
	if body == "" {
		return fmt.Sprintf("%s: %s", e.Op, http.StatusText(e.Status))
	}
	return fmt.Sprintf("%s: %s: %s", e.Op, http.StatusText(e.Status), body)
}

func apiError(op string, resp *http.Response, body []byte) error {
	return &APIError{Op: op, Status: resp.StatusCode, Body: string(body)}
}

// --- credentials ---

// Credential authorizes a request to the Tailscale API.
//
// There are deliberately only two implementations, and neither of them takes a
// secret from a string a caller assembled: a secret that arrives as an argument
// has already been on somebody's command line.
type Credential interface {
	authorize(ctx context.Context, req *http.Request, hc *http.Client) error
}

// APIKey is a tskey-api-… access token. It carries the full permissions of the
// user who created it and expires after about ninety days, so it is a bootstrap
// credential: use it to create the OAuth clients, then stop using it.
type APIKey struct {
	Key string
}

func (k *APIKey) authorize(_ context.Context, req *http.Request, _ *http.Client) error {
	if strings.TrimSpace(k.Key) == "" {
		return errors.New("empty API access token")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k.Key))
	return nil
}

// OAuthClient is a Tailscale OAuth client, exchanged for a one-hour bearer
// token through the client credentials grant.
//
// The exchange happens in this process over HTTPS, so the secret never appears
// in any process's argv. That is not a small detail: the documented way to do
// this is `curl -d client_secret=…`, which publishes the secret to every other
// process running as the same user through /proc/<pid>/cmdline, and undoes on
// the receiving side whatever care went into delivering it.
type OAuthClient struct {
	ID     string
	Secret string

	// BaseURL defaults to DefaultBaseURL; tests point it at a stub.
	BaseURL string

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (o *OAuthClient) authorize(ctx context.Context, req *http.Request, hc *http.Client) error {
	token, err := o.bearer(ctx, hc)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// bearer returns a valid access token, exchanging the client credentials for
// one when the cached token is missing or nearly expired. The token is held in
// memory for the life of the process and never written anywhere.
func (o *OAuthClient) bearer(ctx context.Context, hc *http.Client) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.token != "" && time.Until(o.expires) > time.Minute {
		return o.token, nil
	}

	id := strings.TrimSpace(o.ID)
	secret := strings.TrimSpace(o.Secret)
	if secret == "" {
		return "", errors.New("empty OAuth client secret")
	}
	if id == "" {
		id = ClientIDFromSecret(secret)
	}
	if id == "" {
		return "", errors.New("no OAuth client id, and it could not be read from the secret; pass --client-id")
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {id},
		"client_secret": {secret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange OAuth client credentials: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body of a failed exchange echoes the request in some cases, so
		// it is not safe to print: report the status and nothing else.
		return "", fmt.Errorf("exchange OAuth client credentials: %s", http.StatusText(resp.StatusCode))
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if token.AccessToken == "" {
		return "", errors.New("token response carried no access_token")
	}
	o.token = token.AccessToken
	lifetime := time.Duration(token.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	o.expires = time.Now().Add(lifetime)
	return o.token, nil
}

// tokenURL is where the client credentials are exchanged.
//
// It reads OAuthClient.BaseURL and deliberately not Client.BaseURL: the --api
// flag redirects the policy calls, which is useful against a stub, but nothing
// reachable from a flag or an environment variable may redirect where a secret
// is sent. Only a test sets this field.
func (o *OAuthClient) tokenURL() string {
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	return strings.TrimSuffix(base, "/") + "/api/v2/oauth/token"
}

// ClientIDFromSecret reads the client id out of an OAuth client secret, which
// Tailscale formats as tskey-client-<id>-<random>. It is a convenience so the
// id need not be configured twice; an explicit id always wins.
func ClientIDFromSecret(secret string) string {
	const prefix = "tskey-client-"
	if !strings.HasPrefix(secret, prefix) {
		return ""
	}
	id, _, found := strings.Cut(strings.TrimPrefix(secret, prefix), "-")
	if !found || id == "" {
		return ""
	}
	return prefix + id
}

// ReadSecretFile reads a credential from a file, refusing one that other users
// on the box can read.
//
// The mode check is not ceremony. Taildrop delivers files 0644 by default, and
// this is precisely how a secret that was delivered carefully ends up readable
// by everything running as any user on the machine. Failing here is how that
// gets noticed on the first use rather than never.
//
// A path of "-" reads stdin, so a secret can be piped from somewhere it already
// lives without ever landing on disk.
func ReadSecretFile(path string) (string, error) {
	if path == "-" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<16))
		if err != nil {
			return "", fmt.Errorf("read secret from stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", fmt.Errorf("%s is mode %04o: readable by other users; run chmod 600 %s", path, mode, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return secret, nil
}

// IsNotExist reports whether err is a missing-file error, so callers can tell
// "no credential configured" from "the credential is unusable".
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
