package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
