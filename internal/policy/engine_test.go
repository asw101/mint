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

	got, _ := e.Evaluate(id, Scope{Repos: []string{"owner/name"}})
	if got.Outcome != Denied {
		t.Fatalf("got %v, want denied for owner/name form", got.Outcome)
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
