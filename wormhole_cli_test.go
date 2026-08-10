package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"

	"github.com/asw101/tsapp/internal/server"
	"github.com/asw101/tsapp/internal/wormhole"
)

func TestWormholeUsageListsTheExactCLI(t *testing.T) {
	for _, line := range []string{
		"tsapp wormhole put --to NODE --key KEY [--ttl 10m] [--replace]",
		"tsapp wormhole get --from NODE --key KEY",
		"tsapp wormhole discard --from NODE --key KEY",
	} {
		if !strings.Contains(usage, line) || !strings.Contains(wormholeUsage, line) {
			t.Errorf("usage is missing %q", line)
		}
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
	_, err := doWormholeRequest(context.Background(), client, "http://tsapp", "/v1/wormhole/get", []byte(`{}`))
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
