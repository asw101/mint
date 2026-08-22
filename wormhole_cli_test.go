package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"

	"github.com/asw101/mint/internal/server"
	"github.com/asw101/mint/internal/wormhole"
)

func TestWormholeUsageListsTheExactCLI(t *testing.T) {
	for _, line := range []string{
		"mint wormhole put --to NODE --key KEY [--ttl 10m] [--replace]",
		"mint wormhole get --key KEY [--from NODE]",
		"mint wormhole discard --key KEY [--from NODE]",
		"mint wormhole list [--json]",
	} {
		if !strings.Contains(usage, line) || !strings.Contains(wormholeUsage, line) {
			t.Errorf("usage is missing %q", line)
		}
	}
}

func TestWormholeListHumanOutput(t *testing.T) {
	now := time.Date(2026, 8, 10, 20, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		result server.WormholeListResponse
		want   []string
	}{
		{
			name: "empty",
			want: []string{"No wormhole items are addressed to this node."},
		},
		{
			name: "table",
			result: server.WormholeListResponse{Items: []server.WormholeListItem{{
				SenderNodeID:   "node-1",
				SenderNodeName: "sender.example.ts.net",
				Key:            "azure/provisioner",
				CreatedAt:      now,
				ExpiresAt:      now.Add(10 * time.Minute),
				SizeBytes:      123,
			}}},
			want: []string{
				"SENDER", "SENDER ID", "KEY", "CREATED", "EXPIRES", "BYTES",
				"sender.example.ts.net", "node-1", "azure/provisioner",
				now.Format(time.RFC3339), "123",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := reportWormholeList(&out, tc.result); err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output %q missing %q", out.String(), want)
				}
			}
		})
	}
}

func TestReadWormholeValuePreservesRawBytesAndBoundsInput(t *testing.T) {
	raw := []byte{0, 1, 2, '\n', 0xff}
	got, err := readWormholeValue(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("got %v, want raw bytes %v", got, raw)
	}
	zeroCLIBytes(got)

	tooLarge := bytes.NewReader(make([]byte, wormhole.MaxValueBytes+1))
	if _, err := readWormholeValue(tooLarge); err == nil {
		t.Fatal("accepted a value over 256 KiB")
	}
}

func TestWormholeRequestNeverRetriesTransportErrors(t *testing.T) {
	transport := &flakyTransport{remaining: 10}
	client := &http.Client{Transport: transport}
	_, err := doWormholeRequest(context.Background(), client, "http://mint", "/v1/wormhole/get", []byte(`{}`))
	if err == nil {
		t.Fatal("want a transport error")
	}
	if transport.attempts != 1 {
		t.Errorf("got %d attempts, want exactly one for at-most-once get", transport.attempts)
	}
}

func TestWormholeHTTPStatusMapsPolicyDenialToExitThree(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Body:       io.NopCloser(strings.NewReader(`{"status":"denied","reason":"not permitted"}`)),
	}
	err := wormholeHTTPError(resp)
	var coded *exitCodeError
	if !errors.As(err, &coded) || coded.code != exitDenied {
		t.Fatalf("got %v, want exit %d", err, exitDenied)
	}
}

func TestWormholeHTTPStatusLeavesSenderAmbiguityAtExitOne(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusConflict,
		Status:     "409 Conflict",
		Body: io.NopCloser(strings.NewReader(
			`{"status":"ambiguous","reason":"candidate senders: sender-1, sender-2"}`)),
	}
	err := wormholeHTTPError(resp)
	var coded *exitCodeError
	if errors.As(err, &coded) {
		t.Fatalf("got exit %d, want ordinary exit 1", coded.code)
	}
	for _, sender := range []string{"sender-1", "sender-2"} {
		if !strings.Contains(err.Error(), sender) {
			t.Errorf("error %q does not name %s", err, sender)
		}
	}
}

func TestReplacementNoticeExplainsTheHandoffSignal(t *testing.T) {
	var out bytes.Buffer
	reportWormholePut(&out, server.WormholePutResponse{Replaced: true})
	for _, want := range []string{"replaced", "unconsumed", "recipient", "stalled"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("notice %q missing %q", out.String(), want)
		}
	}
}

type fakeStatusClient struct {
	status *ipnstate.Status
	err    error
}

func (f fakeStatusClient) Status(context.Context) (*ipnstate.Status, error) {
	return f.status, f.err
}

func TestLocalPeerResolverReturnsStableIdentityAndTags(t *testing.T) {
	tagView := views.SliceOf([]string{"tag:agent"})
	resolver := localPeerResolver{client: fakeStatusClient{status: &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			ID:       tailcfg.StableNodeID("node-1"),
			HostName: "build-agent",
			DNSName:  "build-agent.example.ts.net.",
			Tags:     &tagView,
		},
	}}}

	for _, name := range []string{"build-agent", "BUILD-AGENT.EXAMPLE.TS.NET."} {
		got, err := resolver.ResolvePeer(context.Background(), name)
		if err != nil {
			t.Fatalf("ResolvePeer(%q): %v", name, err)
		}
		if got.NodeID != "node-1" || got.NodeName != "build-agent.example.ts.net." ||
			len(got.Tags) != 1 || got.Tags[0] != "tag:agent" {
			t.Errorf("ResolvePeer(%q) = %+v", name, got)
		}
	}
}

func TestPeerResolverRefusesAmbiguousShortNames(t *testing.T) {
	peers := []*ipnstate.PeerStatus{
		{ID: tailcfg.StableNodeID("one"), HostName: "agent", DNSName: "agent.one.ts.net."},
		{ID: tailcfg.StableNodeID("two"), HostName: "agent", DNSName: "agent.two.ts.net."},
	}
	if got := matchingPeers(peers, "agent", false); len(got) != 2 {
		t.Fatalf("got %d short-name matches, want ambiguity", len(got))
	}
	if got := matchingPeers(peers, "agent.one.ts.net", true); len(got) != 1 || got[0].ID != "one" {
		t.Errorf("fully qualified match = %+v", got)
	}
}

func TestWormholeDefaultAndMaximumTTL(t *testing.T) {
	if wormhole.DefaultTTL != 10*time.Minute || wormhole.MaxTTL != time.Hour {
		t.Errorf("got default/max %s/%s", wormhole.DefaultTTL, wormhole.MaxTTL)
	}
}

// settleProbeTransport fails the first n round trips with a transport error, the way
// MagicDNS does before the tsnet stack has settled, then delegates.
type settleProbeTransport struct {
	failures int
	attempts int
	paths    []string
	next     http.RoundTripper
}

func (f *settleProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.attempts++
	f.paths = append(f.paths, r.URL.Path)
	if f.attempts <= f.failures {
		return nil, fmt.Errorf("lookup %s: no such host", r.URL.Hostname())
	}
	return f.next.RoundTrip(r)
}

// A cold tsnet stack must not fail a wormhole command outright: the wait
// belongs before the request. Regression test for wormhole commands issuing a
// bare request while token/whoami/drop retried through doWhileSettling.
func TestSettleTailnetAbsorbsColdStartThenTheRequestGoesOutOnce(t *testing.T) {
	var wormholeCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/wormhole/get" {
			wormholeCalls++
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	ft := &settleProbeTransport{failures: 2, next: http.DefaultTransport}
	client := &http.Client{Transport: ft}

	if err := settleTailnet(context.Background(), client, srv.URL); err != nil {
		t.Fatalf("settleTailnet did not absorb the cold start: %v", err)
	}
	if ft.attempts != 3 {
		t.Errorf("got %d attempts, want 3 (two failures then success)", ft.attempts)
	}
	for _, p := range ft.paths {
		if p != "/v1/whoami" {
			t.Errorf("settle probed %s; it must only probe the idempotent whoami", p)
		}
	}

	// The at-most-once request is issued exactly once, never retried.
	resp, err := doWormholeRequest(context.Background(), client, srv.URL, "/v1/wormhole/get", []byte(`{}`))
	if err != nil {
		t.Fatalf("wormhole request after settle: %v", err)
	}
	resp.Body.Close()
	if wormholeCalls != 1 {
		t.Errorf("wormhole endpoint hit %d times, want exactly 1", wormholeCalls)
	}
}
