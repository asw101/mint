package policy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	n := 0
	return &Engine{
		Store: store,
		Now:   func() time.Time { return testTime },
		NewID: func() (string, error) { n++; return "id" + string(rune('0'+n)), nil },
	}
}

func caller(grants ...Grant) Identity {
	return Identity{NodeID: "node-1", NodeName: "agent-1", Grants: grants}
}

func TestEvaluateQueuesUnknownScope(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one", "two"}})

	got, err := e.Evaluate(id, Scope{Repos: []string{"one"}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending", got.Outcome, got.Reason)
	}
	if got.Request.ID == "" {
		t.Error("want a request id to approve against")
	}
	if len(e.Store.Pending()) != 1 {
		t.Errorf("got %d pending, want 1", len(e.Store.Pending()))
	}
}

func TestEvaluateAllowsAfterApproval(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one", "two"}})

	first, _ := e.Evaluate(id, Scope{Repos: []string{"one"}})
	if _, err := e.Store.Approve(first.Request.ID, 0, testTime, e.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	second, err := e.Evaluate(id, Scope{Repos: []string{"one"}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if second.Outcome != Allowed {
		t.Fatalf("got %v (%s), want allowed", second.Outcome, second.Reason)
	}
	if len(e.Store.Pending()) != 0 {
		t.Errorf("approval should have cleared the pending request")
	}
}

func TestApprovalCoversNarrowerLaterRequest(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one", "two", "three"}})

	broad, _ := e.Evaluate(id, Scope{
		Repos:       []string{"one", "two"},
		Permissions: map[string]string{"contents": "write"},
	})
	if _, err := e.Store.Approve(broad.Request.ID, 0, testTime, e.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// A narrower request must ride in on the broader approval.
	narrow, err := e.Evaluate(id, Scope{
		Repos:       []string{"one"},
		Permissions: map[string]string{"contents": "read"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if narrow.Outcome != Allowed {
		t.Fatalf("got %v (%s), want allowed", narrow.Outcome, narrow.Reason)
	}
}

func TestApprovalDoesNotCoverWiderLaterRequest(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one", "two"}})

	first, _ := e.Evaluate(id, Scope{Repos: []string{"one"}})
	if _, err := e.Store.Approve(first.Request.ID, 0, testTime, e.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	wider, _ := e.Evaluate(id, Scope{Repos: []string{"one", "two"}})
	if wider.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending — lateral movement must need a human", wider.Outcome, wider.Reason)
	}
}

func TestEvaluateDeniesOutsideACLCeiling(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one"}})

	got, err := e.Evaluate(id, Scope{Repos: []string{"secret"}})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied", got.Outcome)
	}
	// Queuing it would be useless: approving cannot exceed the ACL, so the
	// queue must not fill with unsatisfiable requests.
	if len(e.Store.Pending()) != 0 {
		t.Error("a scope outside the ACL ceiling must not be queued for approval")
	}
}

func TestEvaluateDeniesWithoutCapability(t *testing.T) {
	e := newTestEngine(t)
	got, _ := e.Evaluate(Identity{NodeID: "node-1"}, Scope{Repos: []string{"one"}})
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied", got.Outcome)
	}
}

func TestEvaluateDeniesUnidentifiedCaller(t *testing.T) {
	e := newTestEngine(t)
	got, _ := e.Evaluate(Identity{Grants: []Grant{{Repos: []string{AllRepos}}}}, Scope{Repos: []string{"one"}})
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied for a caller with no node identity", got.Outcome)
	}
}

func TestEvaluateRejectsMalformedScope(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{AllRepos}})

	for _, bad := range []string{"a/b/c", "/name", "owner/", " "} {
		got, _ := e.Evaluate(id, Scope{Repos: []string{bad}})
		if got.Outcome != Denied {
			t.Errorf("Evaluate(%q) = %v, want denied", bad, got.Outcome)
		}
	}
}

func TestOwnerQualifiedRepoIsAccepted(t *testing.T) {
	e := newTestEngine(t)
	e.Account = "asw101"
	id := caller(Grant{Repos: []string{"_components"}})

	// owner/name is how everyone writes a repository; it must mean the same as
	// the bare name the API and the grants use.
	got, _ := e.Evaluate(id, Scope{Repos: []string{"asw101/_components"}})
	if got.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending", got.Outcome, got.Reason)
	}
	if len(got.Scope.Repos) != 1 || got.Scope.Repos[0] != "_components" {
		t.Errorf("got %v, want the owner stripped", got.Scope.Repos)
	}
}

func TestBareAndQualifiedNamesShareAnApproval(t *testing.T) {
	e := newTestEngine(t)
	e.Account = "asw101"
	id := caller(Grant{Repos: []string{"_components"}})

	first, _ := e.Evaluate(id, Scope{Repos: []string{"_components"}})
	if _, err := e.Store.Approve(first.Request.ID, 0, testTime, e.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Spelling the owner out must not look like a different request.
	got, _ := e.Evaluate(id, Scope{Repos: []string{"asw101/_components"}})
	if got.Outcome != Allowed {
		t.Fatalf("got %v (%s), want allowed", got.Outcome, got.Reason)
	}
}

func TestForeignOwnerIsRefused(t *testing.T) {
	e := newTestEngine(t)
	e.Account = "asw101"
	id := caller(Grant{Repos: []string{AllRepos}})

	// Stripping the owner would turn someone else's repository into this
	// account's repository of the same name.
	got, _ := e.Evaluate(id, Scope{Repos: []string{"otherorg/_components"}})
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied", got.Outcome)
	}
	if !strings.Contains(got.Reason, "otherorg") || !strings.Contains(got.Reason, "asw101") {
		t.Errorf("reason %q should name both owners", got.Reason)
	}
}

func TestOwnerCheckIsSkippedWhenAccountIsUnknown(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{AllRepos}})

	// With no account configured there is nothing to compare against; the
	// request should still work rather than fail closed on a guess.
	got, _ := e.Evaluate(id, Scope{Repos: []string{"anyone/thing"}})
	if got.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending", got.Outcome, got.Reason)
	}
}

func TestExpiredApprovalStopsAllowing(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one"}})

	first, _ := e.Evaluate(id, Scope{Repos: []string{"one"}})
	if _, err := e.Store.Approve(first.Request.ID, time.Hour, testTime, e.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if got, _ := e.Evaluate(id, Scope{Repos: []string{"one"}}); got.Outcome != Allowed {
		t.Fatalf("got %v, want allowed while the approval is live", got.Outcome)
	}

	e.Now = func() time.Time { return testTime.Add(2 * time.Hour) }
	if got, _ := e.Evaluate(id, Scope{Repos: []string{"one"}}); got.Outcome != Pending {
		t.Fatalf("got %v, want pending once the approval expired", got.Outcome)
	}
}

func TestApprovalsAreScopedToOneNode(t *testing.T) {
	e := newTestEngine(t)
	grants := []Grant{{Repos: []string{"one"}}}

	first, _ := e.Evaluate(Identity{NodeID: "node-1", Grants: grants}, Scope{Repos: []string{"one"}})
	if _, err := e.Store.Approve(first.Request.ID, 0, testTime, e.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// A different node with the same ACL capability must not inherit it —
	// this is the per-instance control the ACL alone cannot express.
	other, _ := e.Evaluate(Identity{NodeID: "node-2", Grants: grants}, Scope{Repos: []string{"one"}})
	if other.Outcome != Pending {
		t.Fatalf("got %v, want pending for a different node", other.Outcome)
	}
}

func TestRepeatedRequestReusesPendingEntry(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one"}})

	first, _ := e.Evaluate(id, Scope{Repos: []string{"one"}})
	second, _ := e.Evaluate(id, Scope{Repos: []string{"one"}})

	if first.Request.ID != second.Request.ID {
		t.Errorf("got ids %q and %q; a retrying client must not flood the queue",
			first.Request.ID, second.Request.ID)
	}
	if len(e.Store.Pending()) != 1 {
		t.Errorf("got %d pending, want 1", len(e.Store.Pending()))
	}
}

func TestDenialNamesTheCallerAndCapability(t *testing.T) {
	e := newTestEngine(t)
	id := Identity{NodeID: "node-1", NodeName: "laptop.example.ts.net", User: "someone@github"}

	got, _ := e.Evaluate(id, Scope{Repos: []string{"one"}})
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied", got.Outcome)
	}
	// This is the first error a new deployment hits, so it has to say who was
	// refused and what to grant them.
	for _, want := range []string{"laptop.example.ts.net", "someone@github", CapabilityName, "grants syntax"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("reason %q missing %q", got.Reason, want)
		}
	}
}

func TestIdentityDescribe(t *testing.T) {
	tests := []struct {
		id   Identity
		want string
	}{
		{Identity{NodeName: "n", User: "u"}, "node n (user u)"},
		{Identity{NodeName: "n"}, "node n"},
		{Identity{User: "u"}, "user u"},
		{Identity{NodeID: "abc"}, "node abc"},
	}
	for _, tc := range tests {
		if got := tc.id.Describe(); got != tc.want {
			t.Errorf("Describe() = %q, want %q", got, tc.want)
		}
	}
}

func TestDescribePrefersTagsOverTheTaggedDevicesUser(t *testing.T) {
	// A tagged node reports its user as "tagged-devices", which is useless in a
	// grant. The tags are what src must match, so they win.
	id := Identity{
		NodeName: "tsapp-client.example.ts.net.",
		User:     "tagged-devices",
		Tags:     []string{"tag:agent"},
	}
	got := id.Describe()
	if !strings.Contains(got, "tag:agent") {
		t.Errorf("Describe() = %q, want it to name the tag", got)
	}
	if strings.Contains(got, "tagged-devices") {
		t.Errorf("Describe() = %q, should not offer tagged-devices as something to match", got)
	}
}

func TestOmittedPermissionsResolveFromTheGrant(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"_components"}, Permissions: map[string]string{"contents": "read"}})

	// Naming no permissions means "the most this policy allows", so the
	// request is narrowed to the grant rather than refused for exceeding it.
	got, _ := e.Evaluate(id, Scope{Repos: []string{"_components"}})
	if got.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending", got.Outcome, got.Reason)
	}
	if got.Scope.Permissions["contents"] != "read" {
		t.Errorf("got permissions %v, want contents=read filled in", got.Scope.Permissions)
	}
	// The stored request must be the resolved scope, or approving it would
	// bless something wider than was decided.
	if e.Store.Pending()[0].Scope.Permissions["contents"] != "read" {
		t.Errorf("pending request stored %v", e.Store.Pending()[0].Scope)
	}
}

func TestUnrestrictedGrantLeavesTheRequestUnrestricted(t *testing.T) {
	e := newTestEngine(t)
	// No permissions in the grant means defer to the App's own set.
	id := caller(Grant{Repos: []string{AllRepos}})

	got, _ := e.Evaluate(id, Scope{Repos: []string{"anything"}})
	if got.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending", got.Outcome, got.Reason)
	}
	if len(got.Scope.Permissions) != 0 {
		t.Errorf("got %v, want permissions left unset", got.Scope.Permissions)
	}
}

func TestExplicitPermissionsAreNotOverridden(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "write"}})

	got, _ := e.Evaluate(id, Scope{Repos: []string{"one"}, Permissions: map[string]string{"contents": "read"}})
	if got.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending", got.Outcome, got.Reason)
	}
	// Asking for less than the grant allows must stay less.
	if got.Scope.Permissions["contents"] != "read" {
		t.Errorf("got %v, want the explicit contents=read preserved", got.Scope.Permissions)
	}
}

func TestAmbiguousGrantsRequireExplicitPermissions(t *testing.T) {
	e := newTestEngine(t)
	id := caller(
		Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "read"}},
		Grant{Repos: []string{"one"}, Permissions: map[string]string{"contents": "write"}},
	)

	// Two grants cover the repository with different permissions; picking one
	// would be a guess about intent.
	got, _ := e.Evaluate(id, Scope{Repos: []string{"one"}})
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied", got.Outcome)
	}
	if !strings.Contains(got.Reason, "several tailnet grants") {
		t.Errorf("reason %q should explain the ambiguity", got.Reason)
	}
}

func TestResolutionPicksTheGrantCoveringTheRepos(t *testing.T) {
	e := newTestEngine(t)
	id := caller(
		Grant{Repos: []string{"public"}, Permissions: map[string]string{"contents": "read"}},
		Grant{Repos: []string{"private"}, Permissions: map[string]string{"contents": "write"}},
	)

	got, _ := e.Evaluate(id, Scope{Repos: []string{"private"}})
	if got.Outcome != Pending {
		t.Fatalf("got %v (%s), want pending", got.Outcome, got.Reason)
	}
	if got.Scope.Permissions["contents"] != "write" {
		t.Errorf("got %v, want the private grant's permissions", got.Scope.Permissions)
	}
}

func TestDeniedUnscopedRequestExplainsItself(t *testing.T) {
	e := newTestEngine(t)
	id := caller(Grant{Repos: []string{"_components"}})

	got, _ := e.Evaluate(id, Scope{})
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied", got.Outcome)
	}
	if !strings.Contains(got.Reason, "--repo") {
		t.Errorf("reason %q should say how to fix it", got.Reason)
	}
}
