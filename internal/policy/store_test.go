package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "approvals.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, path
}

func seedPending(t *testing.T, s *Store, nodeID string, repos ...string) Request {
	t.Helper()
	r, err := s.AddPending(Request{
		ID:          "req-" + nodeID,
		NodeID:      nodeID,
		NodeName:    "agent-" + nodeID,
		Scope:       Scope{Repos: repos},
		RequestedAt: testTime,
	})
	if err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	return r
}

func TestStoreRoundTripsThroughDisk(t *testing.T) {
	s, path := newTestStore(t)
	req := seedPending(t, s, "node-1", "one")
	if _, err := s.Approve(req.ID, 0, testTime, func() (string, error) { return "app-1", nil }); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	live := reopened.ApprovalsFor("node-1", testTime)
	if len(live) != 1 || live[0].ID != "app-1" {
		t.Fatalf("got %+v, want the approval to survive a reload", live)
	}
	if len(reopened.Pending()) != 0 {
		t.Error("pending request should not survive approval")
	}
}

func TestStoreFileIsPrivate(t *testing.T) {
	s, path := newTestStore(t)
	seedPending(t, s, "node-1", "one")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The store decides who may mint; other local users must not be able to
	// read, let alone edit, it.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("got mode %o, want 600", perm)
	}
	if dir, err := os.Stat(filepath.Dir(path)); err == nil {
		if perm := dir.Mode().Perm(); perm != 0o700 {
			t.Errorf("got dir mode %o, want 700", perm)
		}
	}
}

func TestStoreWritesAtomically(t *testing.T) {
	s, path := newTestStore(t)
	seedPending(t, s, "node-1", "one")

	// The temporary file used for the rename must not be left behind, or a
	// reader could find a half-written sibling next to the real one.
	if _, err := os.Stat(path + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file left behind: %v", err)
	}
}

func TestApproveUnknownRequest(t *testing.T) {
	s, _ := newTestStore(t)
	_, err := s.Approve("nope", 0, testTime, NewID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestDenyRemovesPending(t *testing.T) {
	s, _ := newTestStore(t)
	req := seedPending(t, s, "node-1", "one")

	if err := s.Deny(req.ID); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if len(s.Pending()) != 0 {
		t.Error("want the request gone")
	}
	if !errors.Is(s.Deny(req.ID), ErrNotFound) {
		t.Error("want ErrNotFound denying it twice")
	}
}

func TestRevokeRemovesApproval(t *testing.T) {
	s, _ := newTestStore(t)
	req := seedPending(t, s, "node-1", "one")
	approval, err := s.Approve(req.ID, 0, testTime, func() (string, error) { return "app-1", nil })
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if err := s.Revoke(approval.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(s.ApprovalsFor("node-1", testTime)) != 0 {
		t.Error("want no live approvals after revoke")
	}
	if !errors.Is(s.Revoke(approval.ID), ErrNotFound) {
		t.Error("want ErrNotFound revoking it twice")
	}
}

func TestApprovalsForSkipsExpiredAndOtherNodes(t *testing.T) {
	s, _ := newTestStore(t)

	live := seedPending(t, s, "node-1", "one")
	if _, err := s.Approve(live.ID, time.Hour, testTime, func() (string, error) { return "live", nil }); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	other := seedPending(t, s, "node-2", "two")
	if _, err := s.Approve(other.ID, 0, testTime, func() (string, error) { return "other", nil }); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got := s.ApprovalsFor("node-1", testTime)
	if len(got) != 1 || got[0].ID != "live" {
		t.Fatalf("got %+v, want only node-1's approval", got)
	}
	if got := s.ApprovalsFor("node-1", testTime.Add(2*time.Hour)); len(got) != 0 {
		t.Errorf("got %+v, want none once expired", got)
	}
}

func TestPruneExpired(t *testing.T) {
	s, path := newTestStore(t)

	expiring := seedPending(t, s, "node-1", "one")
	if _, err := s.Approve(expiring.ID, time.Hour, testTime, func() (string, error) { return "expiring", nil }); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	forever := seedPending(t, s, "node-2", "two")
	if _, err := s.Approve(forever.ID, 0, testTime, func() (string, error) { return "forever", nil }); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	removed, err := s.PruneExpired(testTime.Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if removed != 1 {
		t.Errorf("got %d removed, want 1", removed)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if all := reopened.Approvals(); len(all) != 1 || all[0].ID != "forever" {
		t.Errorf("got %+v, want only the non-expiring approval", all)
	}
}

// seedNode gives a node one approval and one outstanding request, so a drop
// has both kinds of record to remove.
func seedNode(t *testing.T, s *Store, nodeID string) {
	t.Helper()
	approved, err := s.AddPending(Request{
		ID:          nodeID + "-approved",
		NodeID:      nodeID,
		NodeName:    "agent-" + nodeID,
		Scope:       Scope{Repos: []string{"one"}},
		RequestedAt: testTime,
	})
	if err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if _, err := s.Approve(approved.ID, 0, testTime, func() (string, error) { return nodeID + "-approval", nil }); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := s.AddPending(Request{
		ID:          nodeID + "-pending",
		NodeID:      nodeID,
		NodeName:    "agent-" + nodeID,
		Scope:       Scope{Repos: []string{"two"}},
		RequestedAt: testTime,
	}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
}

func TestDropNodeRemovesOnlyThatNode(t *testing.T) {
	for _, tc := range []struct {
		name              string
		drop              string
		approvals         int
		pending           int
		wantApprovalsLeft []string
		wantPendingLeft   []string
	}{
		{
			name:              "a node holding both kinds of record",
			drop:              "node-1",
			approvals:         1,
			pending:           1,
			wantApprovalsLeft: []string{"node-2-approval"},
			wantPendingLeft:   []string{"node-2-pending"},
		},
		{
			name:              "a node holding nothing",
			drop:              "node-3",
			approvals:         0,
			pending:           0,
			wantApprovalsLeft: []string{"node-1-approval", "node-2-approval"},
			wantPendingLeft:   []string{"node-1-pending", "node-2-pending"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newTestStore(t)
			seedNode(t, s, "node-1")
			seedNode(t, s, "node-2")

			approvals, pending, err := s.DropNode(tc.drop)
			if err != nil {
				t.Fatalf("DropNode: %v", err)
			}
			if approvals != tc.approvals || pending != tc.pending {
				t.Errorf("got %d approvals and %d pending dropped, want %d and %d",
					approvals, pending, tc.approvals, tc.pending)
			}

			// Reopening proves the removal reached disk, not just memory.
			reopened, err := Open(path)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			var gotApprovals []string
			for _, a := range reopened.Approvals() {
				gotApprovals = append(gotApprovals, a.ID)
			}
			var gotPending []string
			for _, r := range reopened.Pending() {
				gotPending = append(gotPending, r.ID)
			}
			if !equalIDs(gotApprovals, tc.wantApprovalsLeft) {
				t.Errorf("got approvals %v, want %v", gotApprovals, tc.wantApprovalsLeft)
			}
			if !equalIDs(gotPending, tc.wantPendingLeft) {
				t.Errorf("got pending %v, want %v", gotPending, tc.wantPendingLeft)
			}
		})
	}
}

func TestDropNodeIsIdempotent(t *testing.T) {
	s, _ := newTestStore(t)
	seedNode(t, s, "node-1")

	if _, _, err := s.DropNode("node-1"); err != nil {
		t.Fatalf("DropNode: %v", err)
	}
	// Dropping again is not an error: a node that holds nothing has already
	// achieved what it asked for.
	approvals, pending, err := s.DropNode("node-1")
	if err != nil {
		t.Fatalf("second DropNode: %v", err)
	}
	if approvals != 0 || pending != 0 {
		t.Errorf("got %d approvals and %d pending on the second drop, want none", approvals, pending)
	}
}

func equalIDs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestOpenMissingFileStartsEmpty(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.Approvals()) != 0 || len(s.Pending()) != 0 {
		t.Error("want an empty store")
	}
}

func TestOpenRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Failing loudly matters: silently starting empty would drop every
	// approval and quietly re-prompt for access already granted.
	if _, err := Open(path); err == nil {
		t.Fatal("want an error for a corrupt store")
	}
}

func TestNewIDIsRandomAndShort(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if len(id) != 8 {
			t.Fatalf("got %q, want 8 hex chars", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
