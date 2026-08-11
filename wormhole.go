package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"tailscale.com/ipn/ipnstate"

	"github.com/asw101/tsapp/internal/server"
	"github.com/asw101/tsapp/internal/wormhole"
)

const wormholeUsage = `Usage:
  tsapp wormhole put --to NODE --key KEY [--ttl 10m] [--replace]
  tsapp wormhole get --key KEY [--from NODE]
  tsapp wormhole discard --key KEY [--from NODE]
  tsapp wormhole list [--json]
`

func cmdWormhole(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, wormholeUsage)
		return errors.New("wormhole needs put, get, discard, or list")
	}
	switch args[0] {
	case "put":
		return cmdWormholePut(args[1:])
	case "get":
		return cmdWormholeGet(args[1:])
	case "discard":
		return cmdWormholeDiscard(args[1:])
	case "list":
		return cmdWormholeList(args[1:])
	default:
		return fmt.Errorf("unknown wormhole command %q", args[0])
	}
}

func cmdWormholePut(args []string) error {
	fs := flag.NewFlagSet("wormhole put", flag.ContinueOnError)
	var cf clientFlags
	cf.bind(fs)
	to := fs.String("to", "", "recipient tailnet node")
	key := fs.String("key", "", "mailbox key")
	ttl := fs.Duration("ttl", wormhole.DefaultTTL, "retention time")
	replace := fs.Bool("replace", false, "replace this sender's unconsumed item")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *to == "" || *key == "" {
		return errors.New("usage: tsapp wormhole put --to NODE --key KEY [--ttl 10m] [--replace]")
	}
	if err := wormhole.ValidateKey(*key); err != nil {
		return err
	}
	if err := wormhole.ValidateTTL(*ttl); err != nil {
		return err
	}

	value, err := readWormholeValue(os.Stdin)
	if err != nil {
		return err
	}
	defer zeroCLIBytes(value)
	body, err := json.Marshal(server.WormholePutRequest{
		To:          *to,
		Key:         *key,
		TTL:         ttl.String(),
		ValueBase64: value,
		Replace:     *replace,
	})
	if err != nil {
		return err
	}
	defer zeroCLIBytes(body)

	ctx, stop := signalContext()
	defer stop()
	srv, httpClient, err := cf.dial(ctx)
	if err != nil {
		return err
	}
	defer srv.Close()

	if err := settleTailnet(ctx, httpClient, cf.server); err != nil {
		return err
	}

	resp, err := doWormholeRequest(ctx, httpClient, cf.server, "/v1/wormhole/put", body)
	if err != nil {
		return fmt.Errorf("put outcome is ambiguous: the daemon may have stored the item; ask the recipient to get it once before reissuing under a new key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return wormholeHTTPError(resp)
	}
	var result server.WormholePutResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return err
	}
	reportWormholePut(os.Stderr, result)
	return nil
}

func reportWormholePut(w io.Writer, result server.WormholePutResponse) {
	if result.Replaced {
		fmt.Fprintln(w, "tsapp: replaced an unconsumed wormhole item; the recipient may be unavailable or the handoff may be stalled")
		return
	}
	fmt.Fprintf(w, "tsapp: stored wormhole item %s for %s until %s\n",
		result.ID, result.RecipientNodeName, result.ExpiresAt.Format(time.RFC3339))
}

func cmdWormholeGet(args []string) error {
	fs := flag.NewFlagSet("wormhole get", flag.ContinueOnError)
	var cf clientFlags
	cf.bind(fs)
	from := fs.String("from", "", "expected sender tailnet node")
	key := fs.String("key", "", "mailbox key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *key == "" {
		return errors.New("usage: tsapp wormhole get --key KEY [--from NODE]")
	}
	if err := wormhole.ValidateKey(*key); err != nil {
		return err
	}
	body, err := json.Marshal(server.WormholeGetRequest{From: *from, Key: *key})
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()
	srv, httpClient, err := cf.dial(ctx)
	if err != nil {
		return err
	}
	defer srv.Close()

	if err := settleTailnet(ctx, httpClient, cf.server); err != nil {
		return err
	}

	// Consume is at-most-once. A retry after a lost response could turn a
	// successful consume into a misleading absent result, which is why the
	// wait for the tailnet happens above, before anything is sent, rather than
	// as a retry around this request.
	resp, err := doWormholeRequest(ctx, httpClient, cf.server, "/v1/wormhole/get", body)
	if err != nil {
		return fmt.Errorf("get outcome is ambiguous: the item may already have been consumed; do not retry automatically: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wormholeHTTPError(resp)
	}
	var result server.WormholeGetResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWormholeResponseBytes)).Decode(&result); err != nil {
		return err
	}
	defer zeroCLIBytes(result.ValueBase64)
	_, err = os.Stdout.Write(result.ValueBase64)
	return err
}

func cmdWormholeDiscard(args []string) error {
	fs := flag.NewFlagSet("wormhole discard", flag.ContinueOnError)
	var cf clientFlags
	cf.bind(fs)
	from := fs.String("from", "", "expected sender tailnet node")
	key := fs.String("key", "", "mailbox key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *key == "" {
		return errors.New("usage: tsapp wormhole discard --key KEY [--from NODE]")
	}
	if err := wormhole.ValidateKey(*key); err != nil {
		return err
	}
	body, err := json.Marshal(server.WormholeGetRequest{From: *from, Key: *key})
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()
	srv, httpClient, err := cf.dial(ctx)
	if err != nil {
		return err
	}
	defer srv.Close()

	if err := settleTailnet(ctx, httpClient, cf.server); err != nil {
		return err
	}

	resp, err := doWormholeRequest(ctx, httpClient, cf.server, "/v1/wormhole/discard", body)
	if err != nil {
		return fmt.Errorf("discard outcome is ambiguous: the item may already have been discarded: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wormholeHTTPError(resp)
	}
	fmt.Fprintln(os.Stderr, "tsapp: discarded wormhole item")
	return nil
}

func cmdWormholeList(args []string) error {
	fs := flag.NewFlagSet("wormhole list", flag.ContinueOnError)
	var cf clientFlags
	cf.bind(fs)
	asJSON := fs.Bool("json", false, "print the full response")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tsapp wormhole list [--json]")
	}

	ctx, stop := signalContext()
	defer stop()
	srv, httpClient, err := cf.dial(ctx)
	if err != nil {
		return err
	}
	defer srv.Close()

	if err := settleTailnet(ctx, httpClient, cf.server); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(cf.server, "/")+"/v1/wormhole/list", nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("reach %s: %w", cf.server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return wormholeHTTPError(resp)
	}
	var result server.WormholeListResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(result)
	}
	return reportWormholeList(os.Stdout, result)
}

func reportWormholeList(w io.Writer, result server.WormholeListResponse) error {
	if len(result.Items) == 0 {
		_, err := fmt.Fprintln(w, "No wormhole items are addressed to this node.")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SENDER\tSENDER ID\tKEY\tCREATED\tEXPIRES\tBYTES"); err != nil {
		return err
	}
	for _, item := range result.Items {
		name := item.SenderNodeName
		if name == "" {
			name = item.SenderNodeID
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n",
			name, item.SenderNodeID, item.Key,
			item.CreatedAt.Format(time.RFC3339), item.ExpiresAt.Format(time.RFC3339), item.SizeBytes); err != nil {
			return err
		}
	}
	return tw.Flush()
}

const maxWormholeResponseBytes = (wormhole.MaxValueBytes*4+2)/3 + 4096

func readWormholeValue(r io.Reader) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(r, wormhole.MaxValueBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read value from stdin: %w", err)
	}
	if len(value) > wormhole.MaxValueBytes {
		zeroCLIBytes(value)
		return nil, fmt.Errorf("value exceeds %d bytes", wormhole.MaxValueBytes)
	}
	return value, nil
}

// settleTailnet waits for the tailnet to become usable, before any wormhole
// request is issued.
//
// Every invocation brings up its own tsnet stack, and MagicDNS does not resolve
// for the first moment after that. token, whoami, and drop absorb this by
// retrying the request itself; wormhole must not. A get is at-most-once, so
// repeating one that may already have been delivered could turn a successful
// consume into a misleading absent result, and a repeated put could collide
// with the item it just stored.
//
// Readiness is therefore a precondition rather than a retry around the real
// request. whoami is idempotent and carries no mailbox effect, so retrying it
// costs nothing; once it answers, the wormhole request goes out exactly once.
//
// A failure here is unambiguous — nothing was sent — so callers report it
// plainly instead of warning that the outcome is unknown.
func settleTailnet(ctx context.Context, client *http.Client, baseURL string) error {
	resp, err := doWhileSettling(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(baseURL, "/")+"/v1/whoami", nil)
	})
	if err != nil {
		return fmt.Errorf("reach %s: %w", baseURL, err)
	}
	// Only that an answer arrived matters, not what it said.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return nil
}

func doWormholeRequest(ctx context.Context, client *http.Client, baseURL, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(baseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

func wormholeHTTPError(resp *http.Response) error {
	var status server.StatusResponse
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&status)
	err := errors.New(reasonOr(status, "server returned "+resp.Status))
	switch resp.StatusCode {
	case http.StatusAccepted:
		return &exitCodeError{code: exitPending, err: err}
	case http.StatusForbidden:
		return &exitCodeError{code: exitDenied, err: err}
	default:
		return err
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

type statusClient interface {
	Status(context.Context) (*ipnstate.Status, error)
}

type localPeerResolver struct {
	client statusClient
}

func (r localPeerResolver) ResolvePeer(ctx context.Context, name string) (server.ResolvedPeer, error) {
	status, err := r.client.Status(ctx)
	if err != nil {
		return server.ResolvedPeer{}, err
	}
	query := normalizePeerName(name)
	if query == "" {
		return server.ResolvedPeer{}, fmt.Errorf("%q: %w", name, server.ErrPeerNotFound)
	}

	var peers []*ipnstate.PeerStatus
	if status.Self != nil {
		peers = append(peers, status.Self)
	}
	for _, peer := range status.Peer {
		peers = append(peers, peer)
	}
	matches := matchingPeers(peers, query, strings.Contains(query, "."))
	if len(matches) == 0 {
		return server.ResolvedPeer{}, fmt.Errorf("%q: %w", name, server.ErrPeerNotFound)
	}
	if len(matches) > 1 {
		return server.ResolvedPeer{}, fmt.Errorf("tailnet peer name %q is ambiguous", name)
	}
	peer := matches[0]
	nodeName := peer.DNSName
	if nodeName == "" {
		nodeName = peer.HostName
	}
	var tags []string
	if peer.Tags != nil {
		tags = peer.Tags.AsSlice()
	}
	return server.ResolvedPeer{
		NodeID:   string(peer.ID),
		NodeName: nodeName,
		Tags:     tags,
	}, nil
}

func matchingPeers(peers []*ipnstate.PeerStatus, query string, fullyQualified bool) []*ipnstate.PeerStatus {
	seen := map[string]bool{}
	var matches []*ipnstate.PeerStatus
	for _, peer := range peers {
		if peer == nil || peer.ID == "" {
			continue
		}
		dnsName := normalizePeerName(peer.DNSName)
		hostName := normalizePeerName(peer.HostName)
		match := dnsName == query || hostName == query
		if !fullyQualified {
			first, _, _ := strings.Cut(dnsName, ".")
			match = match || hostName == query || first == query
		}
		id := string(peer.ID)
		if match && !seen[id] {
			seen[id] = true
			matches = append(matches, peer)
		}
	}
	return matches
}

func normalizePeerName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func zeroCLIBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
