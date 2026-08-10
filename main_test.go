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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"errors"

	"github.com/asw101/tsapp/internal/app"
	"github.com/asw101/tsapp/internal/policy"
	"github.com/asw101/tsapp/internal/server"
)

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tsapp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

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
	path := filepath.Join(shortTempDir(t), "sub", "admin.sock")

	ln, err := listenUnix(path, "")
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
	again, err := listenUnix(path, "")
	if err != nil {
		t.Fatalf("listenUnix over a stale socket: %v", err)
	}
	again.Close()
}

// A named group is what lets an operator approve without root, so the widened
// mode and the group ownership are both part of the contract. The test uses a
// group this process already belongs to, since chown to an arbitrary group
// needs privileges the suite does not have.
func TestListenUnixWidensForAGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	gid := os.Getgid()

	ln, err := listenUnix(path, strconv.Itoa(gid))
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("got socket mode %o, want 660", perm)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no Stat_t on this platform")
	}
	if int(st.Gid) != gid {
		t.Errorf("got socket gid %d, want %d", st.Gid, gid)
	}
}

func TestListenUnixRejectsAnUnknownGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := listenUnix(path, "no-such-group-here")
	if err == nil {
		ln.Close()
		t.Fatal("listenUnix accepted a group that does not exist")
	}
	// Failing closed matters: a typo must not silently leave the socket at a
	// mode the operator did not ask for.
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("socket left behind after a failed group lookup")
	}
}

func TestLookupGIDAcceptsNamesAndNumbers(t *testing.T) {
	gid := os.Getgid()
	got, err := lookupGID(strconv.Itoa(gid))
	if err != nil {
		t.Fatalf("lookupGID(numeric): %v", err)
	}
	if got != gid {
		t.Errorf("got gid %d, want %d", got, gid)
	}

	g, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		t.Skipf("no name for gid %d: %v", gid, err)
	}
	got, err = lookupGID(g.Name)
	if err != nil {
		t.Fatalf("lookupGID(%q): %v", g.Name, err)
	}
	if got != gid {
		t.Errorf("got gid %d for %q, want %d", got, g.Name, gid)
	}
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
	ln, err := listenUnix(socket, "")
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

func TestDropIsDocumentedAsAClientCommand(t *testing.T) {
	if !strings.Contains(usage, "tsapp drop [flags]") {
		t.Error("want drop in the usage text")
	}
	// Drop belongs beside the commands a tailnet client can run, not beside
	// the admin ones that only reach the daemon over its socket.
	if strings.Index(usage, "tsapp drop") > strings.Index(usage, "tsapp pending") {
		t.Error("want drop listed with the client commands, above the admin group")
	}
}

func TestDescribeDrop(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp server.DropResponse
		want string
	}{
		{
			name: "nothing to drop",
			resp: server.DropResponse{NodeID: "node-1", NodeName: "agent.example.ts.net"},
			want: "agent.example.ts.net held nothing to drop",
		},
		{
			name: "one of each",
			resp: server.DropResponse{
				NodeID: "node-1", NodeName: "agent.example.ts.net",
				ApprovalsDropped: 1, PendingDropped: 1,
			},
			want: "agent.example.ts.net dropped 1 approval and 1 pending request",
		},
		{
			name: "several",
			resp: server.DropResponse{
				NodeID: "node-1", NodeName: "agent.example.ts.net",
				ApprovalsDropped: 2, PendingDropped: 0,
			},
			want: "agent.example.ts.net dropped 2 approvals and 0 pending requests",
		},
		{
			name: "no name to fall back on",
			resp: server.DropResponse{NodeID: "node-1", ApprovalsDropped: 1},
			want: "node-1 dropped 1 approval and 0 pending requests",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeDrop(tc.resp); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultDirIsNamespaced(t *testing.T) {
	if got := defaultDir("tsapp"); !strings.HasSuffix(got, "tsapp") {
		t.Errorf("got %q, want it to end in the app name", got)
	}
}

func TestResetRequiresConfirmation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "daemon")
	err := cmdReset([]string{"daemon", "--state-dir", dir})
	if err == nil || !strings.Contains(err.Error(), "--yes") || !strings.Contains(err.Error(), dir) {
		t.Fatalf("got %v, want the path and confirmation hint", err)
	}
}

func TestResetDeletesSelectedState(t *testing.T) {
	for _, target := range []string{"daemon", "client"} {
		t.Run(target, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), target)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("state"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := cmdReset([]string{target, "--state-dir", dir, "--yes"}); err != nil {
				t.Fatalf("cmdReset: %v", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("state directory still exists: %v", err)
			}
		})
	}
}

func TestResetAllDeletesBothStateDirectories(t *testing.T) {
	root := t.TempDir()
	daemonDir := filepath.Join(root, "daemon")
	clientDir := filepath.Join(root, "client")
	for _, dir := range []string{daemonDir, clientDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	err := cmdReset([]string{
		"all",
		"--daemon-state-dir", daemonDir,
		"--client-state-dir", clientDir,
		"--yes",
	})
	if err != nil {
		t.Fatalf("cmdReset: %v", err)
	}
	for _, dir := range []string{daemonDir, clientDir} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("state directory %s still exists: %v", dir, err)
		}
	}
}

// No target is the common case — "clean up whatever this host is holding" —
// so it must mean the same as an explicit "all" rather than an error.
func TestResetWithoutATargetClearsEverything(t *testing.T) {
	root := t.TempDir()
	daemonDir := filepath.Join(root, "daemon")
	clientDir := filepath.Join(root, "client")
	for _, dir := range []string{daemonDir, clientDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	err := cmdReset([]string{
		"--daemon-state-dir", daemonDir,
		"--client-state-dir", clientDir,
		"--yes",
	})
	if err != nil {
		t.Fatalf("cmdReset: %v", err)
	}
	for _, dir := range []string{daemonDir, clientDir} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("state directory %s still exists: %v", dir, err)
		}
	}
}

// Without --yes it must still refuse, and name both paths: a bare `tsapp reset`
// is the dry run people will lean on before committing to it.
func TestResetWithoutATargetStillNeedsConfirmation(t *testing.T) {
	root := t.TempDir()
	daemonDir := filepath.Join(root, "daemon")
	clientDir := filepath.Join(root, "client")

	err := cmdReset([]string{"--daemon-state-dir", daemonDir, "--client-state-dir", clientDir})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("got %v, want a confirmation hint", err)
	}
	for _, dir := range []string{daemonDir, clientDir} {
		if !strings.Contains(err.Error(), dir) {
			t.Errorf("error %q does not name %s", err, dir)
		}
	}
}

func TestResetRefusesWhileDaemonIsRunning(t *testing.T) {
	dir := shortTempDir(t)
	socket := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	err = cmdReset([]string{"daemon", "--state-dir", dir, "--yes"})
	if err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("got %v, want a running-daemon error", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("state was removed despite a running daemon: %v", err)
	}
}

func TestResetRejectsDangerousDirectories(t *testing.T) {
	for _, dir := range []string{string(filepath.Separator), defaultDir("")} {
		if _, err := safeResetDir(dir); err == nil {
			t.Errorf("safeResetDir(%q): want an error", dir)
		}
	}
}

func TestResetRejectsSymlinkToProtectedDirectory(t *testing.T) {
	config, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no user config directory: %v", err)
	}
	link := filepath.Join(t.TempDir(), "config")
	if err := os.Symlink(config, link); err != nil {
		t.Fatal(err)
	}
	if _, err := safeResetDir(link); err == nil {
		t.Errorf("safeResetDir(%q): want an error", link)
	}
}

func TestResetAllRejectsAmbiguousStateDir(t *testing.T) {
	err := cmdReset([]string{"all", "--state-dir", t.TempDir(), "--yes"})
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("got %v, want --state-dir to be rejected", err)
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

func TestTokenErrorCarriesTheRightExitCode(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		status   server.StatusResponse
		wantExit int
		wantText string
	}{
		{
			name:     "pending is retryable",
			code:     http.StatusAccepted,
			status:   server.StatusResponse{Status: "pending", RequestID: "7c2a"},
			wantExit: exitPending,
			wantText: "7c2a",
		},
		{
			name:     "denied is not",
			code:     http.StatusForbidden,
			status:   server.StatusResponse{Status: "denied", Reason: "scope exceeds the capability"},
			wantExit: exitDenied,
			wantText: "exceeds the capability",
		},
		{
			// An upstream failure is neither a policy decision nor something
			// approving would fix, so it stays a plain error.
			name:     "upstream failure is a plain error",
			code:     http.StatusBadGateway,
			status:   server.StatusResponse{Status: "error", Reason: "github api: 500"},
			wantExit: exitError,
			wantText: "github api",
		},
		{
			name:     "no reason falls back to the status line",
			code:     http.StatusInternalServerError,
			status:   server.StatusResponse{},
			wantExit: exitError,
			wantText: "500 Internal Server Error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tokenError(tc.code, "500 Internal Server Error", tc.status)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("got %q, want it to mention %q", err, tc.wantText)
			}

			got := exitError
			var coded *exitCodeError
			if errors.As(err, &coded) {
				got = coded.code
			}
			if got != tc.wantExit {
				t.Errorf("got exit %d, want %d", got, tc.wantExit)
			}
		})
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	// Collapsing any two of these would put a script back to parsing English.
	seen := map[int]bool{}
	for _, code := range []int{exitError, exitPending, exitDenied} {
		if seen[code] {
			t.Fatalf("exit code %d is used twice", code)
		}
		seen[code] = true
	}
	if exitError != 1 {
		t.Errorf("the generic failure should stay 1, got %d", exitError)
	}
}

// mintBody returns the JSON the minter actually sent to the API, so a test can
// tell an omitted repositories field from an empty or literal one.
func mintBody(t *testing.T, scope policy.Scope) map[string]any {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode token request: %v", err)
		}
		fmt.Fprint(w, `{"token":"ghs_example","expires_at":"2026-08-09T23:00:00Z"}`)
	}))
	t.Cleanup(srv.Close)

	minter := &githubMinter{
		client:         &app.Client{AppID: "1234567", Signer: testSigner(t), BaseURL: srv.URL, HTTP: srv.Client()},
		installationID: 89012345,
	}
	if _, err := minter.Mint(context.Background(), scope); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return body
}

func TestMintOmitsRepositoriesForTheWildcard(t *testing.T) {
	// "*" is a grant vocabulary word, not a repository. Sending it verbatim
	// would have GitHub look up a repo by that name and reject the mint.
	body := mintBody(t, policy.Scope{Repos: []string{policy.AllRepos}})

	if _, ok := body["repositories"]; ok {
		t.Errorf("repositories should be omitted for the wildcard, got %v", body["repositories"])
	}
}

func TestMintWidensWhenTheWildcardAppearsBesideNames(t *testing.T) {
	// The wildcard already covers the named repositories, so narrowing to them
	// would mint less than was approved.
	body := mintBody(t, policy.Scope{Repos: []string{"_cloud_native_ai", policy.AllRepos}})

	if _, ok := body["repositories"]; ok {
		t.Errorf("the wildcard should win, got repositories %v", body["repositories"])
	}
}

func TestMintNamesTheRepositoriesItWasGiven(t *testing.T) {
	body := mintBody(t, policy.Scope{Repos: []string{"justfiles", "_cloud_native_ai"}})

	got, _ := json.Marshal(body["repositories"])
	if string(got) != `["_cloud_native_ai","justfiles"]` {
		t.Errorf("got repositories %s, want the normalized pair", got)
	}
}

func TestWildcardRequestRoundTripsThroughAnApproval(t *testing.T) {
	// The path that was broken end to end: ask for "*", get approved, and have
	// the resulting grant cover the request it came from.
	req := policy.Scope{Repos: []string{policy.AllRepos}}
	stored := policy.Grant{Repos: req.Repos, Permissions: req.Permissions}

	if !policy.CoveredByAny([]policy.Grant{stored}, req) {
		t.Fatal("an approval minted from a wildcard request should cover it")
	}
	if _, ok := mintBody(t, req)["repositories"]; ok {
		t.Error("and it should mint against the whole installation")
	}
}
