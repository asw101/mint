package tspolicy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &Client{
		Cred:    &APIKey{Key: "tskey-api-test"},
		Tailnet: "example.com",
		BaseURL: server.URL,
		HTTP:    server.Client(),
	}
}

func TestFetchAsksForHuJSONAndKeepsTheETag(t *testing.T) {
	var gotPath, gotAccept, gotAuth string
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAccept, gotAuth = r.URL.Path, r.Header.Get("Accept"), r.Header.Get("Authorization")
		w.Header().Set("ETag", `"abc123"`)
		fmt.Fprint(w, "// a comment the API must not eat\n{\"grants\": []}\n")
	}))

	policy, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if want := "/api/v2/tailnet/example.com/acl"; gotPath != want {
		t.Errorf("got path %q, want %q", gotPath, want)
	}
	// Comments are most of what a policy file says to a human, and asking for
	// JSON instead of HuJSON silently drops them.
	if gotAccept != contentType {
		t.Errorf("got Accept %q, want %q", gotAccept, contentType)
	}
	if gotAuth != "Bearer tskey-api-test" {
		t.Errorf("got Authorization %q", gotAuth)
	}
	if !strings.Contains(string(policy.Body), "a comment") {
		t.Errorf("got body %q", policy.Body)
	}
	if policy.ETag != `"abc123"` {
		t.Errorf("got ETag %q", policy.ETag)
	}
}

func TestFetchReportsAnAPIError(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"invalid credential"}`)
	}))

	if _, err := client.Fetch(context.Background()); err == nil {
		t.Fatal("want an error")
	}
}

func TestSetRefusesWithoutAnETag(t *testing.T) {
	var called bool
	client := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	// Writing with no If-Match tells the API to overwrite whatever is there,
	// which would make this tool the thing that silently reverts a human's
	// edit in the admin console.
	if err := client.Set(context.Background(), []byte("{}"), ""); err == nil {
		t.Fatal("want an error when no ETag is supplied")
	}
	if called {
		t.Error("the request must not be sent at all")
	}
}

func TestSetSendsIfMatch(t *testing.T) {
	var gotIfMatch, gotContentType, gotMethod string
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfMatch, gotContentType, gotMethod = r.Header.Get("If-Match"), r.Header.Get("Content-Type"), r.Method
		fmt.Fprint(w, `{"grants":[]}`)
	}))

	if err := client.Set(context.Background(), []byte(`{"grants":[]}`), "abc123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("got method %q", gotMethod)
	}
	if gotIfMatch != `"abc123"` {
		t.Errorf("got If-Match %q, want a quoted ETag", gotIfMatch)
	}
	if gotContentType != contentType {
		t.Errorf("got Content-Type %q", gotContentType)
	}
}

func TestSetDoesNotDoubleQuoteAnETag(t *testing.T) {
	var gotIfMatch string
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIfMatch = r.Header.Get("If-Match")
		fmt.Fprint(w, "{}")
	}))

	if err := client.Set(context.Background(), []byte("{}"), `"abc123"`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if gotIfMatch != `"abc123"` {
		t.Errorf("got If-Match %q", gotIfMatch)
	}
}

func TestSetExplainsAStaleETag(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
	}))

	err := client.Set(context.Background(), []byte("{}"), "stale")
	if err == nil || !strings.Contains(err.Error(), "changed since it was fetched") {
		t.Fatalf("got %v, want an explanation of the failed precondition", err)
	}
}

func TestSetExplainsAReadOnlyCredential(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"insufficient scope"}`)
	}))

	// This is the expected failure when somebody points apply at the read
	// client, so it has to name the scope rather than echo a bare 403.
	err := client.Set(context.Background(), []byte("{}"), "abc")
	if err == nil || !strings.Contains(err.Error(), "policy_file") {
		t.Fatalf("got %v, want the scope named", err)
	}
}

func TestValidateTreatsAProblemReportAsAFailure(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The endpoint answers 200 and describes the problem in the body, so a
		// caller that only checked the status would call this valid.
		fmt.Fprint(w, `{"message":"unknown tag tag:nope","data":[{"user":"tag:nope","error":"not defined"}]}`)
	}))

	err := client.Validate(context.Background(), []byte("{}"))
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "unknown tag") || !strings.Contains(err.Error(), "not defined") {
		t.Errorf("got %v, want the API's explanation", err)
	}
}

func TestValidateAcceptsAGoodPolicy(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"grants":[]}`)
	}))

	if err := client.Validate(context.Background(), []byte(`{"grants":[]}`)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestOAuthExchangeKeepsTheSecretOutOfTheURL(t *testing.T) {
	var gotQuery, gotForm, gotContentType string
	var exchanges int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			exchanges++
			gotQuery = r.URL.RawQuery
			gotContentType = r.Header.Get("Content-Type")
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			gotForm = r.Form.Encode()
			fmt.Fprint(w, `{"access_token":"tskey-derived","expires_in":3600}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tskey-derived" {
			t.Errorf("got Authorization %q, want the derived bearer", got)
		}
		fmt.Fprint(w, "{}")
	}))
	t.Cleanup(server.Close)

	oauth := &OAuthClient{Secret: "tskey-client-k123CNTRL-abcdef", BaseURL: server.URL}
	client := &Client{Cred: oauth, Tailnet: "-", BaseURL: server.URL, HTTP: server.Client()}

	if _, err := client.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// A secret in the query string lands in every access log between here and
	// Tailscale, which is the same class of mistake as putting it in argv.
	if gotQuery != "" {
		t.Errorf("got query %q, want the credentials in the body", gotQuery)
	}
	if !strings.Contains(gotForm, "client_secret=tskey-client-k123CNTRL-abcdef") {
		t.Errorf("got form %q", gotForm)
	}
	if !strings.Contains(gotForm, "grant_type=client_credentials") {
		t.Errorf("got form %q, want the client credentials grant", gotForm)
	}
	if !strings.Contains(gotForm, "client_id=tskey-client-k123CNTRL") {
		t.Errorf("got form %q, want the id read from the secret", gotForm)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("got Content-Type %q", gotContentType)
	}

	// A second call inside the hour reuses the bearer rather than exchanging
	// again: the token lives in memory for one process and never on disk.
	if _, err := client.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if exchanges != 1 {
		t.Errorf("exchanged %d times, want 1", exchanges)
	}
}

func TestOAuthExchangeDoesNotEchoTheBodyOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// A failed exchange can echo the request back. Reporting that verbatim
		// would print the secret to a terminal and a log.
		fmt.Fprint(w, `{"error":"invalid_client","sent":"client_secret=tskey-client-SECRET"}`)
	}))
	t.Cleanup(server.Close)

	oauth := &OAuthClient{ID: "tskey-client-x", Secret: "tskey-client-SECRET", BaseURL: server.URL}
	client := &Client{Cred: oauth, BaseURL: server.URL, HTTP: server.Client()}

	_, err := client.Fetch(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("the error carries the secret: %v", err)
	}
}

func TestClientIDFromSecret(t *testing.T) {
	for secret, want := range map[string]string{
		"tskey-client-k123CNTRL-abcdefghij": "tskey-client-k123CNTRL",
		"tskey-client-k123CNTRL":            "",
		"tskey-api-abcdef":                  "",
		"":                                  "",
	} {
		if got := ClientIDFromSecret(secret); got != want {
			t.Errorf("ClientIDFromSecret(%q) = %q, want %q", secret, got, want)
		}
	}
}

func TestReadSecretFileRefusesAWorldReadableFile(t *testing.T) {
	// Taildrop lands received files 0644. A secret delivered that way is
	// readable by every user on the box until somebody remembers to fix it,
	// and this is where that gets noticed.
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("tskey-client-x-y"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadSecretFile(path)
	if err == nil {
		t.Fatal("want an error for a 0644 secret")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("got %v, want the fix in the message", err)
	}
}

func TestReadSecretFileAcceptsAPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("  tskey-client-x-y\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	secret, err := ReadSecretFile(path)
	if err != nil {
		t.Fatalf("ReadSecretFile: %v", err)
	}
	if secret != "tskey-client-x-y" {
		t.Errorf("got %q, want the trimmed secret", secret)
	}
}

func TestReadSecretFileRejectsAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadSecretFile(path); err == nil {
		t.Fatal("want an error for an empty secret file")
	}
}

func TestIsNotExist(t *testing.T) {
	_, err := ReadSecretFile(filepath.Join(t.TempDir(), "absent"))
	if !IsNotExist(err) {
		t.Fatalf("got %v, want a not-exist error", err)
	}
}

func TestOAuthExchangeIgnoresTheClientBaseURL(t *testing.T) {
	// --api points the policy calls somewhere; it must not be able to point the
	// credential exchange somewhere. A flag or environment variable that can
	// redirect where a secret is sent is worse than whatever it was added for.
	oauth := &OAuthClient{ID: "tskey-client-x", Secret: "tskey-client-x-y"}
	if got, want := oauth.tokenURL(), DefaultBaseURL+"/api/v2/oauth/token"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// Client.BaseURL is a different field and does not reach it.
	client := &Client{Cred: oauth, BaseURL: "http://attacker.example"}
	_ = client
	if got := oauth.tokenURL(); !strings.HasPrefix(got, DefaultBaseURL) {
		t.Errorf("got %q, want the real API", got)
	}
}
