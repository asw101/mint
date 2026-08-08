package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asw101/tsapp/internal/app"
	"github.com/asw101/tsapp/internal/policy"
	"github.com/asw101/tsapp/internal/server"
)

func TestSplitAll(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{"one", "two"}, "one,two"},
		{[]string{"one,two"}, "one,two"},
		{[]string{"one, two", "three"}, "one,two,three"},
		{[]string{"one,,two,"}, "one,two"},
		{nil, ""},
	}
	for _, tc := range tests {
		if got := strings.Join(splitAll(tc.in), ","); got != tc.want {
			t.Errorf("splitAll(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePermissions(t *testing.T) {
	got, err := parsePermissions([]string{"contents=read", "issues=write"})
	if err != nil {
		t.Fatalf("parsePermissions: %v", err)
	}
	if got["contents"] != "read" || got["issues"] != "write" {
		t.Errorf("got %v", got)
	}

	if got, err := parsePermissions(nil); err != nil || got != nil {
		t.Errorf("got %v, %v; want nil map and no error", got, err)
	}

	for _, bad := range []string{"contents", "=read", "contents="} {
		if _, err := parsePermissions([]string{bad}); err == nil {
			t.Errorf("parsePermissions(%q): want error", bad)
		}
	}
}

func TestListenUnixIsPrivateAndReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "admin.sock")

	ln, err := listenUnix(path)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Filesystem permissions are the only guard on the admin surface.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("got socket mode %o, want 600", perm)
	}
	ln.Close()

	// A clean Close unlinks the socket, so the leftover case only arises when
	// the daemon dies without one. Simulate that, and check the next start
	// recovers instead of failing with "address already in use".
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("simulate crash leftover: %v", err)
	}
	again, err := listenUnix(path)
	if err != nil {
		t.Fatalf("listenUnix over a stale socket: %v", err)
	}
	again.Close()
}

// startAdmin serves the admin handler on a real Unix socket, which is how the
// CLI reaches it — no tailnet involved.
func startAdmin(t *testing.T) (*server.Server, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := policy.Open(filepath.Join(dir, "approvals.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := &server.Server{
		Store:  store,
		Engine: &policy.Engine{Store: store},
	}
	socket := filepath.Join(dir, "admin.sock")
	ln, err := listenUnix(socket)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	srv := &http.Server{Handler: s.AdminHandler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return s, socket
}

func TestAdminRoundTripOverSocket(t *testing.T) {
	s, socket := startAdmin(t)

	seeded, err := s.Store.AddPending(policy.Request{
		ID:          "req1",
		NodeID:      "node-1",
		NodeName:    "agent-1",
		Scope:       policy.Scope{Repos: []string{"one"}},
		RequestedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	client := adminClient(socket)

	resp, err := client.Get("http://admin/v1/pending")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	var pending []policy.Request
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if len(pending) != 1 || pending[0].ID != seeded.ID {
		t.Fatalf("got %+v, want the seeded request", pending)
	}

	if err := adminPost(socket, "/v1/approve", []byte(`{"id":"req1","ttl":"1h"}`)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(s.Store.ApprovalsFor("node-1", time.Now())) != 1 {
		t.Error("want one live approval")
	}
	if len(s.Store.Pending()) != 0 {
		t.Error("want the pending request cleared")
	}
}

func TestAdminReportsUnknownID(t *testing.T) {
	_, socket := startAdmin(t)

	err := adminPost(socket, "/v1/approve", []byte(`{"id":"nope"}`))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("got %v, want a not-found error", err)
	}
}

func TestAdminExplainsWhenDaemonIsAbsent(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "absent.sock")

	err := adminPost(socket, "/v1/approve", []byte(`{"id":"x"}`))
	if err == nil {
		t.Fatal("want an error when nothing is listening")
	}
	// The failure a user hits most often is "the daemon isn't running", so it
	// must say so rather than surfacing a bare dial error.
	if !strings.Contains(err.Error(), "is 'tsapp serve' running") {
		t.Errorf("got %q, want a hint about the daemon", err)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"bogus"}); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("got %v, want an unknown-command error", err)
	}
}

func TestRunRequiresACommand(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("want an error with no arguments")
	}
}

func TestServeRequiresAppCredentials(t *testing.T) {
	// Must fail before touching the tailnet.
	err := run([]string{"serve", "--app-id=", "--key="})
	if err == nil || !strings.Contains(err.Error(), "--app-id") {
		t.Fatalf("got %v, want a missing-credentials error", err)
	}
}

func TestDefaultDirIsNamespaced(t *testing.T) {
	if got := defaultDir("tsapp"); !strings.HasSuffix(got, "tsapp") {
		t.Errorf("got %q, want it to end in the app name", got)
	}
}

// testSigner builds a throwaway App signer so resolveInstallation can be
// exercised against a stub API.
func testSigner(t *testing.T) app.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	signer, err := app.ParsePEMSigner(encoded)
	if err != nil {
		t.Fatalf("ParsePEMSigner: %v", err)
	}
	return signer
}

func installationsServer(t *testing.T, body string) *app.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/app/installations") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return &app.Client{AppID: "1234567", Signer: testSigner(t), BaseURL: srv.URL, HTTP: srv.Client()}
}

func TestResolveInstallationDiscoversTheOnlyOne(t *testing.T) {
	client := installationsServer(t, `[{"id":89012345,"account":{"login":"asw101"}}]`)

	// The whole point: with one installation, --installation is unnecessary.
	got, account, err := resolveInstallation(context.Background(), client, 0)
	if err != nil {
		t.Fatalf("resolveInstallation: %v", err)
	}
	if got != 89012345 {
		t.Errorf("got %d, want 89012345", got)
	}
	// The account is what lets the policy refuse a request naming another owner.
	if account != "asw101" {
		t.Errorf("got account %q, want asw101", account)
	}
}

func TestResolveInstallationLooksUpAnExplicitID(t *testing.T) {
	// An explicit ID still needs one lookup, to learn the account the owner
	// guard checks against — but it must not enumerate every installation.
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		fmt.Fprint(w, `{"id":42,"account":{"login":"someorg"}}`)
	}))
	t.Cleanup(srv.Close)
	client := &app.Client{AppID: "1", Signer: testSigner(t), BaseURL: srv.URL, HTTP: srv.Client()}

	got, account, err := resolveInstallation(context.Background(), client, 42)
	if err != nil {
		t.Fatalf("resolveInstallation: %v", err)
	}
	if got != 42 || account != "someorg" {
		t.Errorf("got %d/%q, want 42/someorg", got, account)
	}
	if path != "/app/installations/42" {
		t.Errorf("got path %q, want the single-installation endpoint", path)
	}
}

func TestResolveInstallationListsChoicesWhenAmbiguous(t *testing.T) {
	client := installationsServer(t,
		`[{"id":1,"account":{"login":"asw101"}},{"id":2,"account":{"login":"someorg"}}]`)

	_, _, err := resolveInstallation(context.Background(), client, 0)
	if err == nil {
		t.Fatal("want an error when the App spans several installations")
	}
	// The error has to be actionable: it is the only place the IDs appear.
	for _, want := range []string{"--installation", "asw101", "someorg", "1", "2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestResolveInstallationExplainsWhenAppIsUninstalled(t *testing.T) {
	client := installationsServer(t, `[]`)

	_, _, err := resolveInstallation(context.Background(), client, 0)
	if err == nil || !strings.Contains(err.Error(), "no installations") {
		t.Fatalf("got %v, want a not-installed hint", err)
	}
}

func TestExpandTailnetHost(t *testing.T) {
	const self = "tsapp-client.tail1234.ts.net."

	tests := []struct {
		name   string
		server string
		want   string
	}{
		{
			// MagicDNS does not resolve bare short names, which is what the
			// default --server used to be.
			name:   "bare name gains the tailnet suffix",
			server: "http://tsapp:8080",
			want:   "http://tsapp.tail1234.ts.net:8080",
		},
		{
			name:   "bare name without a port",
			server: "https://tsapp",
			want:   "https://tsapp.tail1234.ts.net",
		},
		{
			name:   "already qualified is untouched",
			server: "http://tsapp.tail1234.ts.net:8080",
			want:   "http://tsapp.tail1234.ts.net:8080",
		},
		{
			name:   "ip address is untouched",
			server: "http://100.101.102.103:8080",
			want:   "http://100.101.102.103:8080",
		},
		{
			name:   "path is preserved",
			server: "http://tsapp:8080/base",
			want:   "http://tsapp.tail1234.ts.net:8080/base",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandTailnetHost(tc.server, self); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExpandTailnetHostLeavesThingsAloneWhenItCannotHelp(t *testing.T) {
	// A single-label self name yields no suffix; better to leave the address
	// alone than to build a nonsense one.
	if got := expandTailnetHost("http://tsapp:8080", "solo."); got != "http://tsapp:8080" {
		t.Errorf("got %q, want the address unchanged", got)
	}
	if got := expandTailnetHost("://bad", "a.b.ts.net."); got != "://bad" {
		t.Errorf("got %q, want the unparseable address unchanged", got)
	}
}

// flakyTransport fails the first n round trips, then delegates.
type flakyTransport struct {
	remaining int
	attempts  int
	next      http.RoundTripper
}

func (f *flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.attempts++
	if f.remaining > 0 {
		f.remaining--
		return nil, &net.DNSError{Err: "no such host", Name: r.URL.Hostname(), IsNotFound: true}
	}
	return f.next.RoundTrip(r)
}

func TestDoWhileSettlingRetriesTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	// The first run after a fresh join fails to resolve until the tailnet's
	// DNS lands; the request should ride that out rather than making the user
	// run the command twice.
	transport := &flakyTransport{remaining: 3, next: srv.Client().Transport}
	client := &http.Client{Transport: transport}

	resp, err := doWhileSettling(context.Background(), client, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, srv.URL, nil)
	})
	if err != nil {
		t.Fatalf("doWhileSettling: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got %d, want 200", resp.StatusCode)
	}
	if transport.attempts != 4 {
		t.Errorf("got %d attempts, want 4", transport.attempts)
	}
}

func TestDoWhileSettlingDoesNotRetryAnAnswer(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	// A 403 is the server answering. Retrying it would turn a fast denial into
	// a twenty second hang.
	resp, err := doWhileSettling(context.Background(), srv.Client(), func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, srv.URL, nil)
	})
	if err != nil {
		t.Fatalf("doWhileSettling: %v", err)
	}
	defer resp.Body.Close()
	if calls != 1 {
		t.Errorf("got %d calls, want 1", calls)
	}
}

func TestDoWhileSettlingHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := &http.Client{Transport: &flakyTransport{remaining: 1000}}
	if _, err := doWhileSettling(ctx, client, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, "http://example.invalid", nil)
	}); err == nil {
		t.Fatal("want an error once the context is cancelled")
	}
}

func TestVersionReportNamesTheBinary(t *testing.T) {
	got := versionReport()
	if !strings.HasPrefix(got, "tsapp ") {
		t.Errorf("got %q, want it to start with the program name", got)
	}
	// Built by `go test` from a checkout, so the toolchain stamps VCS info
	// even though -ldflags did not run.
	if !strings.Contains(got, "go1.") {
		t.Errorf("got %q, want the Go version", got)
	}
}

func TestVersionStringPrefersTheStampedValue(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	version = "tsapp/v9.9.9"
	if got := versionString(); got != "tsapp/v9.9.9" {
		t.Errorf("got %q, want the stamped value", got)
	}

	// Unstamped falls back to build info rather than claiming a version.
	version = ""
	if got := versionString(); got == "tsapp/v9.9.9" {
		t.Error("stale stamped value leaked through")
	}
}

func TestVersionIsReachableByEveryName(t *testing.T) {
	for _, name := range []string{"version", "--version", "-version"} {
		if err := run([]string{name}); err != nil {
			t.Errorf("run(%q): %v", name, err)
		}
	}
}

func TestShortRevision(t *testing.T) {
	if got := short("c2bf8779b9204e6235df60f4f6337f0d8d9b0fcf"); got != "c2bf8779b920" {
		t.Errorf("got %q, want 12 chars", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("got %q, want a short revision left alone", got)
	}
}

func TestParseWithIDAcceptsFlagsEitherSide(t *testing.T) {
	// "approve ID --ttl 720h" is the form the usage text documents, and the
	// flag package stops at the first non-flag argument, so it used to fail.
	for _, args := range [][]string{
		{"7c2a", "--ttl", "720h"},
		{"--ttl", "720h", "7c2a"},
		{"--ttl=720h", "7c2a"},
		{"7c2a", "--ttl=720h"},
	} {
		fs := flag.NewFlagSet("approve", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		ttl := fs.String("ttl", "", "")
		id, err := parseWithID(fs, args)
		if err != nil {
			t.Errorf("parseWithID(%v): %v", args, err)
			continue
		}
		if id != "7c2a" || *ttl != "720h" {
			t.Errorf("parseWithID(%v) = %q with ttl %q", args, id, *ttl)
		}
	}
}

func TestParseWithIDRejectsASecondPositional(t *testing.T) {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if _, err := parseWithID(fs, []string{"one", "two"}); err == nil {
		t.Error("want an error for a second positional argument")
	}
}

func TestParseWithIDAllowsNoID(t *testing.T) {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	id, err := parseWithID(fs, nil)
	if err != nil || id != "" {
		t.Errorf("got %q, %v; want empty and no error so the caller can report usage", id, err)
	}
}
