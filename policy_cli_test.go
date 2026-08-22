package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asw101/mint/internal/tspolicy"
)

// policyStub is a Tailscale API that serves one policy file and records what
// was written to it.
type policyStub struct {
	current []byte
	written []byte
	writes  int
}

func newPolicyClient(t *testing.T, stub *policyStub) *tspolicy.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/acl"):
			w.Header().Set("ETag", `"v1"`)
			w.Write(stub.current)
		case strings.HasSuffix(r.URL.Path, "/acl/validate"):
			fmt.Fprint(w, "{}")
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/acl"):
			if r.Header.Get("If-Match") == "" {
				t.Error("a write arrived without If-Match")
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
			}
			stub.written = body
			stub.writes++
			w.Write(body)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return &tspolicy.Client{
		Cred:    &tspolicy.APIKey{Key: "tskey-api-test"},
		Tailnet: "-",
		BaseURL: server.URL,
		HTTP:    server.Client(),
	}
}

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const policyWithMint = `{
  "grants": [
    {"src": ["tag:agent"], "dst": ["tag:mint"], "app": {"asw101.dev/cap/mint": [{"repos": ["*"]}]}},
  ],
}
`

const policyWithTsapp = `{
  "grants": [
    {"src": ["tag:agent"], "dst": ["tag:tsapp"], "app": {"asw101.dev/cap/tsapp": [{"repos": ["*"]}]}},
  ],
}
`

const policyWithNeither = `{
  "grants": [
    {"src": ["tag:agent"], "dst": ["tag:mint"], "ip": ["*"]},
  ],
}
`

func TestPolicyApplyRefusesToRemoveMintsOwnCapability(t *testing.T) {
	// The failure mode this guards is the exact change the rename requires: a
	// policy that no longer names the capability locks out every client, and in
	// a large diff it reads as a tidy-up.
	stub := &policyStub{current: []byte(policyWithMint)}
	client := newPolicyClient(t, stub)

	err := policyApply(context.Background(), client, writePolicy(t, policyWithNeither), true, false)
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("got %v, want the override named", err)
	}
	if stub.writes != 0 {
		t.Error("nothing may be written when the guard fires")
	}
}

func TestPolicyApplyAcceptsTheLegacyCapability(t *testing.T) {
	// Mid-rename the policy legitimately grants the old name, the new one, or
	// both. Only "neither" is the dangerous state.
	stub := &policyStub{current: []byte(policyWithMint)}
	client := newPolicyClient(t, stub)

	if err := policyApply(context.Background(), client, writePolicy(t, policyWithTsapp), true, false); err != nil {
		t.Fatalf("policyApply: %v", err)
	}
	if stub.writes != 1 {
		t.Fatalf("wrote %d times, want 1", stub.writes)
	}
	if string(stub.written) != policyWithTsapp {
		t.Errorf("wrote %q, want the file as given", stub.written)
	}
}

func TestPolicyApplyForceOverridesTheGuard(t *testing.T) {
	stub := &policyStub{current: []byte(policyWithMint)}
	client := newPolicyClient(t, stub)

	if err := policyApply(context.Background(), client, writePolicy(t, policyWithNeither), true, true); err != nil {
		t.Fatalf("policyApply: %v", err)
	}
	if stub.writes != 1 {
		t.Fatalf("wrote %d times, want 1", stub.writes)
	}
}

func TestPolicyApplyNeedsYes(t *testing.T) {
	stub := &policyStub{current: []byte(policyWithMint)}
	client := newPolicyClient(t, stub)

	err := policyApply(context.Background(), client, writePolicy(t, policyWithTsapp), false, false)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("got %v, want a refusal naming --yes", err)
	}
	if stub.writes != 0 {
		t.Error("nothing may be written without confirmation")
	}
}

func TestPolicyApplyIsANoOpWhenNothingChanged(t *testing.T) {
	stub := &policyStub{current: []byte(policyWithMint)}
	client := newPolicyClient(t, stub)

	if err := policyApply(context.Background(), client, writePolicy(t, policyWithMint), true, false); err != nil {
		t.Fatalf("policyApply: %v", err)
	}
	if stub.writes != 0 {
		t.Error("an unchanged policy must not be rewritten")
	}
}

func TestPolicyDiffAgainstTheTailnet(t *testing.T) {
	stub := &policyStub{current: []byte(policyWithTsapp)}
	client := newPolicyClient(t, stub)

	if err := policyDiff(context.Background(), client, writePolicy(t, policyWithMint)); err != nil {
		t.Fatalf("policyDiff: %v", err)
	}
}

func TestDefaultSecretPathSeparatesReadFromWrite(t *testing.T) {
	// The two-client model only means anything if the routine commands cannot
	// reach the writing credential by default.
	read := defaultSecretPath("fetch")
	write := defaultSecretPath("apply")
	if read == write {
		t.Fatalf("fetch and apply both read %s", read)
	}
	for _, sub := range []string{"fetch", "diff", "validate"} {
		if got := defaultSecretPath(sub); got != read {
			t.Errorf("%s reads %s, want %s", sub, got, read)
		}
	}
	if !strings.HasSuffix(write, policyWriteSecretFile) {
		t.Errorf("apply reads %s", write)
	}
}

func TestServeRefusesAPolicyCredential(t *testing.T) {
	// Restraint expressed as capability rather than as a rule in a document:
	// the daemon does not decline to rewrite the policy, it refuses to run at
	// all while it could.
	for _, key := range tailscaleAPIEnv {
		t.Run(key, func(t *testing.T) {
			env := map[string]string{key: "tskey-api-something"}
			err := refuseIfPolicyCredentialPresent(func(k string) (string, bool) {
				v, ok := env[k]
				return v, ok
			})
			if err == nil {
				t.Fatalf("want a refusal when %s is set", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("got %v, want %s named", err, key)
			}
		})
	}
}

func TestServeAllowsAnEmptyPolicyCredential(t *testing.T) {
	// An empty variable is how a systemd EnvironmentFile clears one, and it
	// grants nothing, so it must not be treated as a credential.
	err := refuseIfPolicyCredentialPresent(func(k string) (string, bool) {
		if k == "TS_API_KEY" {
			return "", true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("got %v, want an empty variable to be harmless", err)
	}
}

func TestServeRejectsAPolicyCredentialEndToEnd(t *testing.T) {
	// The guard has to run before serve does anything else, or it is advice.
	t.Setenv("TS_OAUTH_CLIENT_SECRET", "tskey-client-x-y")
	err := cmdServe([]string{"--app-id", "1"})
	if err == nil || !strings.Contains(err.Error(), "TS_OAUTH_CLIENT_SECRET") {
		t.Fatalf("got %v, want serve to refuse to start", err)
	}
}

// F-005 in this workspace's friction log is `az login --password`: a secret in
// argv, readable from /proc/<pid>/cmdline by anything running as the same user.
// The documented Tailscale OAuth exchange has the same shape
// (`curl -d client_secret=...`). mint has no flag that takes a secret value, and
// this is what keeps somebody from adding one for convenience.
func TestPolicyHasNoSecretValueFlag(t *testing.T) {
	for _, arg := range []string{
		"--client-secret", "--secret", "--api-key", "--token", "--password",
	} {
		err := cmdPolicy([]string{"fetch", arg, "tskey-client-x-y"})
		if err == nil {
			t.Errorf("%s was accepted; secrets must come from a file or stdin", arg)
			continue
		}
		if !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Errorf("%s failed with %v, want it to be an unknown flag", arg, err)
		}
	}
}
