package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/asw101/mint/internal/app"
	"github.com/asw101/mint/internal/policy"
	"github.com/asw101/mint/internal/wormhole"
)

var testTime = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

// fakeIdentifier stands in for the tailnet, so authorization is testable
// without one.
type fakeIdentifier struct {
	resp *apitype.WhoIsResponse
	err  error
}

type fakePeerResolver struct {
	peers map[string]ResolvedPeer
	err   error
}

func (f fakePeerResolver) ResolvePeer(_ context.Context, name string) (ResolvedPeer, error) {
	if f.err != nil {
		return ResolvedPeer{}, f.err
	}
	peer, ok := f.peers[name]
	if !ok {
		return ResolvedPeer{}, ErrPeerNotFound
	}
	return peer, nil
}

func (f fakeIdentifier) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	return f.resp, f.err
}

type fakeMinter struct {
	got   policy.Scope
	token *app.Token
	err   error
}

func (f *fakeMinter) Mint(_ context.Context, scope policy.Scope) (*app.Token, error) {
	f.got = scope
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

// whoIs builds a WhoIsResponse whose CapMap carries the given grants. Each
// grant is a separate RawMessage, matching how the ACL lists them.
func whoIs(t *testing.T, nodeID string, grants ...policy.Grant) *apitype.WhoIsResponse {
	t.Helper()
	var raw []tailcfg.RawMessage
	for _, g := range grants {
		encoded, err := json.Marshal(g)
		if err != nil {
			t.Fatalf("marshal grant: %v", err)
		}
		raw = append(raw, tailcfg.RawMessage(encoded))
	}
	resp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID: tailcfg.StableNodeID(nodeID),
			Name:     nodeID + ".example.ts.net",
		},
		UserProfile: &tailcfg.UserProfile{LoginName: "someone@github"},
	}
	if len(raw) > 0 {
		resp.CapMap = tailcfg.PeerCapMap{CapName: raw}
	}
	return resp
}

func newTestServer(t *testing.T, who *apitype.WhoIsResponse, minter Minter) *Server {
	t.Helper()
	store, err := policy.Open(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	n := 0
	mailbox := wormhole.New()
	mailbox.SetClock(func() time.Time { return testTime })
	mailbox.SetIDGenerator(func() (string, error) { n++; return fmt.Sprintf("%032x", n), nil })
	s := &Server{
		Store: store,
		Engine: &policy.Engine{
			Store: store,
			Now:   func() time.Time { return testTime },
			NewID: func() (string, error) { n++; return fmt.Sprintf("req%d", n), nil },
		},
		Who:      fakeIdentifier{resp: who},
		Minter:   minter,
		Wormhole: mailbox,
		Peers: fakePeerResolver{peers: map[string]ResolvedPeer{
			"node-1": {NodeID: "node-1", NodeName: "node-1.example.ts.net", Tags: []string{"tag:agent"}},
			"node-2": {NodeID: "node-2", NodeName: "node-2.example.ts.net", Tags: []string{"tag:agent"}},
			"sender": {NodeID: "sender", NodeName: "sender.example.ts.net", Tags: []string{"tag:admin"}},
		}},
	}
	mailbox.SetEventSink(s.logWormholeEvent)
	return s
}

func postToken(t *testing.T, s *Server, body TokenRequest) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader(encoded))
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, req)
	return rec
}

func TestTokenPendingThenAllowedAfterApproval(t *testing.T) {
	minter := &fakeMinter{token: &app.Token{
		Token:       "ghs_example",
		ExpiresAt:   testTime.Add(time.Hour),
		Permissions: map[string]string{"contents": "read"},
	}}
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one", "two"}}), minter)

	rec := postToken(t, s, TokenRequest{Repos: []string{"one"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d, want 202 pending: %s", rec.Code, rec.Body)
	}
	var status StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status.Status != "pending" || status.RequestID == "" {
		t.Fatalf("got %+v, want a pending status with a request id", status)
	}

	if _, err := s.Store.Approve(status.RequestID, 0, testTime, policy.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	rec = postToken(t, s, TokenRequest{Repos: []string{"one"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 after approval: %s", rec.Code, rec.Body)
	}
	var token TokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &token); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if token.Token != "ghs_example" {
		t.Errorf("got token %q", token.Token)
	}
	if len(minter.got.Repos) != 1 || minter.got.Repos[0] != "one" {
		t.Errorf("minter received scope %+v, want repos [one]", minter.got)
	}
}

func TestTokenDeniedOutsideCapability(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})

	rec := postToken(t, s, TokenRequest{Repos: []string{"secret"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", rec.Code, rec.Body)
	}
	if len(s.Store.Pending()) != 0 {
		t.Error("a scope outside the capability must not be queued")
	}
}

func TestTokenDeniedWithoutCapability(t *testing.T) {
	// No capability in the CapMap at all: the tailnet policy grants nothing.
	s := newTestServer(t, whoIs(t, "node-1"), &fakeMinter{})

	rec := postToken(t, s, TokenRequest{Repos: []string{"one"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", rec.Code, rec.Body)
	}
}

func TestTokenDeniedWhenCallerUnknown(t *testing.T) {
	s := newTestServer(t, nil, &fakeMinter{})
	s.Who = fakeIdentifier{err: errors.New("no peer")}

	rec := postToken(t, s, TokenRequest{Repos: []string{"one"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

func TestTokenRejectsMalformedBody(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})

	req := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestTokenReportsMintFailure(t *testing.T) {
	minter := &fakeMinter{err: errors.New("github api: repository does not exist")}
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), minter)

	rec := postToken(t, s, TokenRequest{Repos: []string{"one"}})
	if _, err := s.Store.Approve("req1", 0, testTime, policy.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	rec = postToken(t, s, TokenRequest{Repos: []string{"one"}})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502: %s", rec.Code, rec.Body)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("does not exist")) {
		t.Errorf("want the upstream reason surfaced, got %s", rec.Body)
	}
}

func TestTokenNeverMintsWithoutApproval(t *testing.T) {
	minter := &fakeMinter{token: &app.Token{Token: "ghs_example"}}
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), minter)

	postToken(t, s, TokenRequest{Repos: []string{"one"}})
	if minter.got.Repos != nil {
		t.Fatal("minter was called for a request still awaiting approval")
	}
}

func TestWhoamiReportsIdentity(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})

	req := httptest.NewRequest(http.MethodGet, "/v1/whoami", nil)
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	var identity policy.Identity
	if err := json.Unmarshal(rec.Body.Bytes(), &identity); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if identity.NodeID != "node-1" || len(identity.Grants) != 1 {
		t.Errorf("got %+v", identity)
	}
}

func TestAdminApproveAndRevoke(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})
	postToken(t, s, TokenRequest{Repos: []string{"one"}})

	admin := s.AdminHandler()

	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/pending", nil))
	var pending []policy.Request
	if err := json.Unmarshal(rec.Body.Bytes(), &pending); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending, want 1", len(pending))
	}

	body := fmt.Sprintf(`{"id":%q,"ttl":"1h"}`, pending[0].ID)
	rec = httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/approve", bytes.NewReader([]byte(body))))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: got %d: %s", rec.Code, rec.Body)
	}
	var approval policy.Approval
	if err := json.Unmarshal(rec.Body.Bytes(), &approval); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if approval.ExpiresAt.IsZero() {
		t.Error("want the ttl applied")
	}

	rec = httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/revoke",
		bytes.NewReader([]byte(fmt.Sprintf(`{"id":%q}`, approval.ID)))))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d: %s", rec.Code, rec.Body)
	}
	if len(s.Store.ApprovalsFor("node-1", testTime)) != 0 {
		t.Error("want the approval gone")
	}
}

func TestAdminDenyDropsRequest(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})
	postToken(t, s, TokenRequest{Repos: []string{"one"}})

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/deny",
		bytes.NewReader([]byte(`{"id":"req1"}`))))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body)
	}
	if len(s.Store.Pending()) != 0 {
		t.Error("want the request dropped")
	}
}

func TestAdminSurfaceIsNotOnTheTailnetHandler(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{AllReposForTest}}), &fakeMinter{})

	// Approving must not be reachable by tailnet clients — only over the
	// local admin socket.
	for _, path := range []string{"/v1/approve", "/v1/revoke", "/v1/deny"} {
		rec := httptest.NewRecorder()
		s.TailnetHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path,
			bytes.NewReader([]byte(`{"id":"req1"}`))))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404 on the tailnet handler", path, rec.Code)
		}
	}
	for _, path := range []string{"/v1/pending", "/v1/approvals"} {
		rec := httptest.NewRecorder()
		s.TailnetHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404 on the tailnet handler", path, rec.Code)
		}
	}
}

const AllReposForTest = policy.AllRepos

// seedNode gives a node one approval and one outstanding request, so a drop
// has both kinds of record to remove.
func seedNode(t *testing.T, s *Server, nodeID string) {
	t.Helper()
	approved, err := s.Store.AddPending(policy.Request{
		ID:          nodeID + "-approved",
		NodeID:      nodeID,
		NodeName:    nodeID + ".example.ts.net",
		Scope:       policy.Scope{Repos: []string{"one"}},
		RequestedAt: testTime,
	})
	if err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	if _, err := s.Store.Approve(approved.ID, 0, testTime, func() (string, error) { return nodeID + "-approval", nil }); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := s.Store.AddPending(policy.Request{
		ID:          nodeID + "-pending",
		NodeID:      nodeID,
		NodeName:    nodeID + ".example.ts.net",
		Scope:       policy.Scope{Repos: []string{"two"}},
		RequestedAt: testTime,
	}); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
}

func postDrop(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/drop", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, req)
	return rec
}

func TestDropRemovesTheCallersRecordsAndNobodyElses(t *testing.T) {
	// Whatever the body says, the node dropped is the one the tailnet
	// identified. A client that could name a node would be able to strip
	// another node's access without holding any capability itself.
	for _, tc := range []struct{ name, body string }{
		{"no body", ""},
		{"empty object", `{}`},
		{"names another node", `{"node_id":"node-2"}`},
		{"names another node's records", `{"node_id":"node-2","id":"node-2-approval"}`},
		{"malformed body", `{not json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})
			seedNode(t, s, "node-1")
			seedNode(t, s, "node-2")
			addressed := []byte("addressed to node-1")
			sent := []byte("sent by node-1")
			if _, err := s.Wormhole.Put(
				wormhole.Peer{NodeID: "node-2", NodeName: "node-2.example.ts.net"},
				wormhole.Peer{NodeID: "node-1", NodeName: "node-1.example.ts.net"},
				"addressed", addressed, wormhole.DefaultTTL, false,
			); err != nil {
				t.Fatalf("seed addressed wormhole: %v", err)
			}
			if _, err := s.Wormhole.Put(
				wormhole.Peer{NodeID: "node-1", NodeName: "node-1.example.ts.net"},
				wormhole.Peer{NodeID: "node-2", NodeName: "node-2.example.ts.net"},
				"sent", sent, wormhole.DefaultTTL, false,
			); err != nil {
				t.Fatalf("seed sent wormhole: %v", err)
			}

			rec := postDrop(t, s, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("got %d, want 200: %s", rec.Code, rec.Body)
			}
			var dropped DropResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &dropped); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if dropped.NodeID != "node-1" {
				t.Errorf("dropped node %q, want the calling node node-1", dropped.NodeID)
			}
			if dropped.ApprovalsDropped != 1 || dropped.PendingDropped != 1 || dropped.WormholesDropped != 1 {
				t.Errorf("got %+v, want one approval, pending request, and addressed wormhole dropped", dropped)
			}
			if !allZeroForServerTest(addressed) {
				t.Error("drop did not zero the caller's addressed wormhole")
			}
			item, err := s.Wormhole.Consume("node-2", "node-1", "sent")
			if err != nil {
				t.Fatalf("drop removed an item the caller sent: %v", err)
			}
			zeroBytes(item.Value)

			if got := s.Store.ApprovalsFor("node-1", testTime); len(got) != 0 {
				t.Errorf("got %+v, want the caller's approvals gone", got)
			}

			if got := s.Store.ApprovalsFor("node-2", testTime); len(got) != 1 {
				t.Errorf("got %+v, want node-2's approval untouched", got)
			}
			var left []string
			for _, r := range s.Store.Pending() {
				left = append(left, r.ID)
			}
			if len(left) != 1 || left[0] != "node-2-pending" {
				t.Errorf("got pending %v, want only node-2's request", left)
			}
		})
	}
}

func allZeroForServerTest(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}

func TestDropIsIdempotent(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})
	seedNode(t, s, "node-1")

	postDrop(t, s, "")
	// Having nothing to give up is success, not a failure: a client that
	// dropped twice has what it asked for either way.
	rec := postDrop(t, s, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 on a second drop: %s", rec.Code, rec.Body)
	}
	var dropped DropResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &dropped); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dropped.ApprovalsDropped != 0 || dropped.PendingDropped != 0 {
		t.Errorf("got %+v, want nothing dropped the second time", dropped)
	}
}

func TestDropDeniedWhenCallerUnknown(t *testing.T) {
	s := newTestServer(t, nil, &fakeMinter{})
	seedNode(t, s, "node-1")
	s.Who = fakeIdentifier{err: errors.New("no peer")}

	rec := postDrop(t, s, `{"node_id":"node-1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	if len(s.Store.ApprovalsFor("node-1", testTime)) != 1 || len(s.Store.Pending()) != 1 {
		t.Error("an unidentified caller must not remove anything")
	}
}
func TestMintsTheResolvedScopeNotTheRawRequest(t *testing.T) {
	minter := &fakeMinter{token: &app.Token{Token: "ghs_example"}}
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{
		Repos:       []string{"one"},
		Permissions: map[string]string{"contents": "read"},
	}), minter)

	// The client names no permissions; the policy supplies contents=read.
	postToken(t, s, TokenRequest{Repos: []string{"one"}})
	if _, err := s.Store.Approve("req1", 0, testTime, policy.NewID); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	postToken(t, s, TokenRequest{Repos: []string{"one"}})

	// Minting the raw request would ask GitHub for the installation's whole
	// grant, quietly handing out more than the policy allows.
	if got := minter.got.Permissions["contents"]; got != "read" {
		t.Errorf("minted with permissions %v, want contents=read", minter.got.Permissions)
	}
}

func TestAdminStatusVerbsAreSpelledCorrectly(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", policy.Grant{Repos: []string{"one"}}), &fakeMinter{})
	admin := s.AdminHandler()

	postToken(t, s, TokenRequest{Repos: []string{"one"}})
	approval, err := s.Store.Approve("req1", 0, testTime, func() (string, error) { return "app1", nil })
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	for _, tc := range []struct{ path, id, want string }{
		{"/v1/revoke", approval.ID, "revoked"},
	} {
		rec := httptest.NewRecorder()
		admin.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path,
			bytes.NewReader([]byte(fmt.Sprintf(`{"id":%q}`, tc.id)))))
		var status StatusResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if status.Status != tc.want {
			t.Errorf("%s returned %q, want %q", tc.path, status.Status, tc.want)
		}
	}

	postToken(t, s, TokenRequest{Repos: []string{"one"}})
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/deny",
		bytes.NewReader([]byte(`{"id":"req2"}`))))
	var status StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if status.Status != "denied" {
		t.Errorf("deny returned %q, want \"denied\"", status.Status)
	}
}

// capRename covers the transitional window in which the tailnet policy and the
// binaries reading it disagree about the capability's name. Both spellings have
// to work, and grants under them have to add up rather than one shadowing the
// other, or renaming the capability locks clients out for as long as the two
// sides are out of step.
func TestCapabilityRename(t *testing.T) {
	encode := func(t *testing.T, grants ...policy.Grant) []tailcfg.RawMessage {
		t.Helper()
		var raw []tailcfg.RawMessage
		for _, g := range grants {
			encoded, err := json.Marshal(g)
			if err != nil {
				t.Fatalf("marshal grant: %v", err)
			}
			raw = append(raw, tailcfg.RawMessage(encoded))
		}
		return raw
	}
	base := func(t *testing.T, caps tailcfg.PeerCapMap) *apitype.WhoIsResponse {
		who := whoIs(t, "node-1")
		who.CapMap = caps
		return who
	}

	t.Run("legacy name alone still authorizes", func(t *testing.T) {
		who := base(t, tailcfg.PeerCapMap{
			LegacyCapNames[0]: encode(t, policy.Grant{Repos: []string{"one"}}),
		})
		s := newTestServer(t, who, &fakeMinter{})

		rec := postToken(t, s, TokenRequest{Repos: []string{"one"}})
		if rec.Code != http.StatusAccepted {
			t.Fatalf("got %d, want 202 pending under the old capability name: %s", rec.Code, rec.Body)
		}
	})

	t.Run("both names merge", func(t *testing.T) {
		who := base(t, tailcfg.PeerCapMap{
			CapName:           encode(t, policy.Grant{Repos: []string{"one"}}),
			LegacyCapNames[0]: encode(t, policy.Grant{Repos: []string{"two"}}),
		})
		s := newTestServer(t, who, &fakeMinter{})

		for _, repo := range []string{"one", "two"} {
			rec := postToken(t, s, TokenRequest{Repos: []string{repo}})
			if rec.Code != http.StatusAccepted {
				t.Errorf("repo %q: got %d, want 202 pending: %s", repo, rec.Code, rec.Body)
			}
		}
		rec := postToken(t, s, TokenRequest{Repos: []string{"three"}})
		if rec.Code != http.StatusForbidden {
			t.Errorf("got %d, want 403 for a repo neither name grants: %s", rec.Code, rec.Body)
		}
	})
}
