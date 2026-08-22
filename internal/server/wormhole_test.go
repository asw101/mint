package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/asw101/mint/internal/policy"
	"github.com/asw101/mint/internal/wormhole"
)

func wormholeGrantPut(tags ...string) policy.Grant {
	return policy.Grant{Wormhole: &policy.WormholeGrant{PutToTags: tags}}
}

func wormholeGrantGet() policy.Grant {
	return policy.Grant{Wormhole: &policy.WormholeGrant{Get: true}}
}

func setCaller(s *Server, whoID string, grants ...policy.Grant) {
	s.Who = fakeIdentifier{resp: whoIsNoTest(whoID, grants...)}
}

func whoIsNoTest(nodeID string, grants ...policy.Grant) *apitype.WhoIsResponse {
	var raw []tailcfg.RawMessage
	for _, grant := range grants {
		encoded, _ := json.Marshal(grant)
		raw = append(raw, tailcfg.RawMessage(encoded))
	}
	resp := &apitype.WhoIsResponse{
		Node: &tailcfg.Node{
			StableID: tailcfg.StableNodeID(nodeID),
			Name:     nodeID + ".example.ts.net",
		},
	}
	if len(raw) > 0 {
		resp.CapMap = tailcfg.PeerCapMap{CapName: raw}
	}
	return resp
}

func postWormhole(t *testing.T, s *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	switch body := body.(type) {
	case []byte:
		encoded = body
	default:
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, req)
	return rec
}

func putWormhole(t *testing.T, s *Server, sender, recipient, key string, value []byte, replace bool) WormholePutResponse {
	t.Helper()
	setCaller(s, sender, wormholeGrantPut("tag:agent"))
	rec := postWormhole(t, s, "/v1/wormhole/put", WormholePutRequest{
		To: recipient, Key: key, TTL: "10m", ValueBase64: value, Replace: replace,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("put got %d, want 201: %s", rec.Code, rec.Body)
	}
	var response WormholePutResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode put: %v", err)
	}
	return response
}

func TestWormholeRecipientIsAlwaysTheCaller(t *testing.T) {
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	putWormhole(t, s, "sender", "node-1", "key", []byte("only node one"), false)

	setCaller(s, "node-1", wormholeGrantGet())
	req := httptest.NewRequest(http.MethodPost,
		"/v1/wormhole/get?to=node-2&recipient_node_id=node-2",
		strings.NewReader(`{"from":"sender","key":"key"}`))
	req.Header.Set("X-Recipient-Node-ID", "node-2")
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("caller get got %d: %s", rec.Code, rec.Body)
	}

	// A body field for the recipient is outside the protocol and is rejected,
	// not interpreted. The query and header above were likewise unable to
	// redirect the successful consume away from the WhoIs caller.
	putWormhole(t, s, "sender", "node-1", "key-2", []byte("still node one"), false)
	setCaller(s, "node-1", wormholeGrantGet())
	rec = postWormhole(t, s, "/v1/wormhole/get",
		[]byte(`{"from":"sender","key":"key-2","to":"node-2","node_id":"node-2"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("get with recipient body fields got %d, want 400", rec.Code)
	}
	rec = postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender", Key: "key-2"})
	if rec.Code != http.StatusOK {
		t.Fatalf("rejected body consumed or redirected the item: %d: %s", rec.Code, rec.Body)
	}
}

func TestWormholeConsumeIsAtMostOnceAndSenderIsPartOfAddress(t *testing.T) {
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	resolver := s.Peers.(fakePeerResolver)
	resolver.peers["sender-2"] = ResolvedPeer{NodeID: "sender-2", NodeName: "sender-2.example.ts.net", Tags: []string{"tag:admin"}}
	s.Peers = resolver

	putWormhole(t, s, "sender", "node-1", "same-key", []byte("from one"), false)
	putWormhole(t, s, "sender-2", "node-1", "same-key", []byte("from two"), false)
	setCaller(s, "node-1", wormholeGrantGet())

	rec := postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender", Key: "same-key"})
	if rec.Code != http.StatusOK {
		t.Fatalf("first get got %d: %s", rec.Code, rec.Body)
	}
	var got WormholeGetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if string(got.ValueBase64) != "from one" {
		t.Errorf("got %q, want sender one's value", got.ValueBase64)
	}

	rec = postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender", Key: "same-key"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second get got %d, want absent", rec.Code)
	}
	rec = postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender-2", Key: "same-key"})
	if rec.Code != http.StatusOK {
		t.Fatalf("other sender's tuple was disturbed: %d: %s", rec.Code, rec.Body)
	}
}

func TestWormholeKeyOnlyActionsRejectAmbiguityWithoutRemovingItems(t *testing.T) {
	for _, action := range []string{"get", "discard"} {
		t.Run(action, func(t *testing.T) {
			s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
			resolver := s.Peers.(fakePeerResolver)
			resolver.peers["sender-2"] = ResolvedPeer{NodeID: "sender-2", NodeName: "sender-2.example.ts.net", Tags: []string{"tag:admin"}}
			s.Peers = resolver

			putWormhole(t, s, "sender", "node-1", "same-key", []byte("from one"), false)
			putWormhole(t, s, "sender-2", "node-1", "same-key", []byte("from two"), false)
			setCaller(s, "node-1", wormholeGrantGet())

			rec := postWormhole(t, s, "/v1/wormhole/"+action, WormholeGetRequest{Key: "same-key"})
			if rec.Code != http.StatusConflict {
				t.Fatalf("key-only %s got %d, want 409: %s", action, rec.Code, rec.Body)
			}
			for _, sender := range []string{"sender.example.ts.net", "sender-2.example.ts.net"} {
				if !strings.Contains(rec.Body.String(), sender) {
					t.Errorf("ambiguity response %q does not name %s", rec.Body, sender)
				}
			}

			for _, sender := range []string{"sender", "sender-2"} {
				rec = postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: sender, Key: "same-key"})
				if rec.Code != http.StatusOK {
					t.Fatalf("%s item was removed by ambiguous %s: %d: %s", sender, action, rec.Code, rec.Body)
				}
			}
		})
	}
}

func TestWormholeKeyOnlyGetAndDiscardResolveOneSender(t *testing.T) {
	for _, action := range []string{"get", "discard"} {
		t.Run(action, func(t *testing.T) {
			s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
			putWormhole(t, s, "sender", "node-1", "key", []byte("secret"), false)
			setCaller(s, "node-1", wormholeGrantGet())

			rec := postWormhole(t, s, "/v1/wormhole/"+action, WormholeGetRequest{Key: "key"})
			if rec.Code != http.StatusOK {
				t.Fatalf("key-only %s got %d: %s", action, rec.Code, rec.Body)
			}
		})
	}
}

func TestWormholeListIsRecipientScopedAndNeverRevealsValues(t *testing.T) {
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	nodeOneValue := []byte("unique-node-one-secret")
	nodeTwoValue := []byte("unique-node-two-secret")
	putWormhole(t, s, "sender", "node-1", "one/key", nodeOneValue, false)
	putWormhole(t, s, "sender", "node-2", "two/key", nodeTwoValue, false)

	setCaller(s, "node-1", wormholeGrantGet())
	req := httptest.NewRequest(http.MethodGet,
		"/v1/wormhole/list?recipient_node_id=node-2",
		strings.NewReader(`{"recipient_node_id":"node-2"}`))
	req.Header.Set("X-Recipient-Node-ID", "node-2")
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list got %d: %s", rec.Code, rec.Body)
	}
	var got WormholeListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Key != "one/key" ||
		got.Items[0].SenderNodeID != "sender" ||
		got.Items[0].SenderNodeName != "sender.example.ts.net" ||
		got.Items[0].SizeBytes != len(nodeOneValue) {
		t.Fatalf("list returned %+v, want only node-1 metadata", got.Items)
	}
	for _, value := range [][]byte{nodeOneValue, nodeTwoValue} {
		hash := sha256.Sum256(value)
		for _, forbidden := range []string{
			string(value),
			hex.EncodeToString(hash[:]),
		} {
			if strings.Contains(rec.Body.String(), forbidden) {
				t.Errorf("list response revealed payload material %q: %s", forbidden, rec.Body)
			}
		}
	}

	setCaller(s, "node-2", wormholeGrantGet())
	rec = httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/wormhole/list", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"two/key"`) {
		t.Fatalf("listing as node-1 disturbed node-2 item: %d: %s", rec.Code, rec.Body)
	}
}

func TestWormholeListRequiresGetCapabilityAndOmitsExpiredItems(t *testing.T) {
	now := testTime
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	s.Wormhole.SetClock(func() time.Time { return now })
	putWormhole(t, s, "sender", "node-1", "expired", []byte("secret"), false)

	setCaller(s, "node-1")
	rec := httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/wormhole/list", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("list without get capability got %d, want 403: %s", rec.Code, rec.Body)
	}

	now = now.Add(wormhole.DefaultTTL)
	setCaller(s, "node-1", wormholeGrantGet())
	rec = httptest.NewRecorder()
	s.TailnetHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/wormhole/list", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list expired got %d: %s", rec.Code, rec.Body)
	}
	var got WormholeListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 0 {
		t.Fatalf("list returned expired items: %+v", got.Items)
	}
}

func TestWormholeGetZeroesConsumedBufferAfterWritingResponse(t *testing.T) {
	s := newTestServer(t, whoIs(t, "node-1", wormholeGrantGet()), &fakeMinter{})
	value := []byte("secret")
	if _, err := s.Wormhole.Put(
		wormhole.Peer{NodeID: "sender", NodeName: "sender.example.ts.net"},
		wormhole.Peer{NodeID: "node-1", NodeName: "node-1.example.ts.net"},
		"key", value, wormhole.DefaultTTL, false,
	); err != nil {
		t.Fatal(err)
	}

	rec := postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender", Key: "key"})
	if rec.Code != http.StatusOK {
		t.Fatalf("get got %d: %s", rec.Code, rec.Body)
	}
	if !allZeroForServerTest(value) {
		t.Error("get did not zero the consumed value after writing the response")
	}
}

func TestWormholeOverwriteNeedsExplicitReplacementAndLogsDisplacedID(t *testing.T) {
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	var logs bytes.Buffer
	s.Logger = log.New(&logs, "", 0)

	first := putWormhole(t, s, "sender", "node-1", "key", []byte("old"), false)
	setCaller(s, "sender", wormholeGrantPut("tag:agent"))
	rec := postWormhole(t, s, "/v1/wormhole/put", WormholePutRequest{
		To: "node-1", Key: "key", TTL: "10m", ValueBase64: []byte("retry"),
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("plain overwrite got %d, want 409: %s", rec.Code, rec.Body)
	}

	replaced := putWormhole(t, s, "sender", "node-1", "key", []byte("regenerated"), true)
	if !replaced.Replaced {
		t.Fatal("replacement response did not report replaced=true")
	}
	if !strings.Contains(logs.String(), "replace") || !strings.Contains(logs.String(), "displaced="+first.ID) {
		t.Errorf("replacement log missing its event or displaced id:\n%s", logs.String())
	}
}

func TestWormholeExpiredConsumedAndNeverExistedAreIndistinguishable(t *testing.T) {
	var wantCode int
	var wantBody string
	for _, state := range []string{"never existed", "expired", "consumed"} {
		t.Run(state, func(t *testing.T) {
			now := testTime
			s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
			s.Wormhole.SetClock(func() time.Time { return now })
			if state != "never existed" {
				putWormhole(t, s, "sender", "node-1", "key", []byte("secret"), false)
			}
			switch state {
			case "expired":
				now = now.Add(wormhole.DefaultTTL)
			case "consumed":
				item, err := s.Wormhole.Consume("node-1", "sender", "key")
				if err != nil {
					t.Fatal(err)
				}
				zeroBytes(item.Value)
			}

			setCaller(s, "node-1", wormholeGrantGet())
			rec := postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender", Key: "key"})
			if wantBody == "" {
				wantCode, wantBody = rec.Code, rec.Body.String()
			}
			if rec.Code != wantCode || rec.Body.String() != wantBody {
				t.Errorf("got %d %q, want indistinguishable %d %q", rec.Code, rec.Body, wantCode, wantBody)
			}
		})
	}
}

func TestWormholeAuthorizationUsesCapabilityAndResolvedTargetTag(t *testing.T) {
	for _, tc := range []struct {
		name   string
		caller string
		grants []policy.Grant
		action string
		want   int
	}{
		{
			name:   "put allowed tag",
			caller: "sender", grants: []policy.Grant{wormholeGrantPut("tag:agent")},
			action: "put", want: http.StatusCreated,
		},
		{
			name:   "put denied tag",
			caller: "sender", grants: []policy.Grant{wormholeGrantPut("tag:other")},
			action: "put", want: http.StatusForbidden,
		},
		{
			name:   "put denied without wormhole grant",
			caller: "sender", grants: []policy.Grant{{Repos: []string{"*"}}},
			action: "put", want: http.StatusForbidden,
		},
		{
			name:   "get denied without get capability",
			caller: "node-1", grants: []policy.Grant{{Repos: []string{"*"}}},
			action: "get", want: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, whoIs(t, tc.caller, tc.grants...), &fakeMinter{})
			var rec *httptest.ResponseRecorder
			if tc.action == "put" {
				rec = postWormhole(t, s, "/v1/wormhole/put", WormholePutRequest{
					To: "node-1", Key: "key", TTL: "10m", ValueBase64: []byte("secret"),
				})
			} else {
				rec = postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender", Key: "key"})
			}
			if rec.Code != tc.want {
				t.Errorf("got %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

func TestWormholeNeverLogsPayloadBodyHashOrKey(t *testing.T) {
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	var logs bytes.Buffer
	s.Logger = log.New(&logs, "", 0)
	value := []byte("unique-secret-value-9fdfc4")
	secret := string(value)
	key := "sensitive/label-8a31"
	hash := sha256.Sum256(value)

	putWormhole(t, s, "sender", "node-1", key, value, false)
	setCaller(s, "node-1", wormholeGrantGet())
	rec := postWormhole(t, s, "/v1/wormhole/get", WormholeGetRequest{From: "sender", Key: key})
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d: %s", rec.Code, rec.Body)
	}

	logged := logs.String()
	for _, forbidden := range []string{
		secret,
		"dW5pcXVlLXNlY3JldC12YWx1ZS05ZmRmYzQ=",
		hex.EncodeToString(hash[:]),
		key,
		"value_base64",
	} {
		if strings.Contains(logged, forbidden) {
			t.Errorf("audit log leaked %q:\n%s", forbidden, logged)
		}
	}
	for _, required := range []string{"put", "consume", "sender", "node-1", "expires=", "result="} {
		if !strings.Contains(logged, required) {
			t.Errorf("audit log missing %q:\n%s", required, logged)
		}
	}
}

func TestWormholePutBoundsBodyBeforeBase64Decode(t *testing.T) {
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	oversized := append([]byte(`{"value_base64":"`), bytes.Repeat([]byte("A"), maxWormholePutBody)...)
	oversized = append(oversized, []byte(`"}`)...)
	rec := postWormhole(t, s, "/v1/wormhole/put", oversized)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413: %s", rec.Code, rec.Body)
	}
}

func TestWormholeDiscardDoesNotRevealValueAndNeedsNoGetCapability(t *testing.T) {
	s := newTestServer(t, whoIs(t, "sender", wormholeGrantPut("tag:agent")), &fakeMinter{})
	putWormhole(t, s, "sender", "node-1", "key", []byte("secret"), false)

	setCaller(s, "node-1")
	rec := postWormhole(t, s, "/v1/wormhole/discard", WormholeGetRequest{From: "sender", Key: "key"})
	if rec.Code != http.StatusOK {
		t.Fatalf("discard got %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "value") {
		t.Errorf("discard response revealed payload material: %s", rec.Body)
	}
}
