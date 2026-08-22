package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// This file is the whole of mint's compatibility with the name it had before:
// the project was called `tsapp` until 2026-08, and a rename that cannot be
// applied to every node at the same instant needs the old names to keep
// working while it is in flight.
//
// Everything here is deliberately in one place so that removing it is a single
// deletion once no `tsapp` node, environment or grant remains. Each hook says
// what has to be true before it can go.

// legacyPrefix is the old project name, and the stem of every legacy default:
// the state directories, the daemon's tailnet name, and the environment
// variables.
const legacyPrefix = "tsapp"

// defaultServer is where a client looks for the daemon when nothing says
// otherwise. legacyServer is where the daemon answered under the old name.
const (
	defaultServer = "http://mint:8080"
	legacyServer  = "http://tsapp:8080"
)

// defaultStateDir returns the state directory for name, preferring an existing
// directory left by the old name over a new empty one.
//
// This is what makes an in-place upgrade non-destructive. The tsnet node key
// lives in this directory, and so does the daemon's approvals.json: a mint
// binary that quietly ignored ~/.config/tsapp would join the tailnet as a brand
// new node needing a fresh console approval, and the daemon would come up
// having forgotten every approval a human had granted.
//
// Removable once every host has been migrated with `mint migrate-state`, or by
// hand.
func defaultStateDir(name string) string {
	current := defaultDir(name)
	if _, err := os.Stat(current); err == nil {
		return current
	}
	legacy := defaultDir(legacyName(name))
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return current
}

// legacyName maps a mint-side default to the tsapp-side one: "mint" to "tsapp",
// "mint-client" to "tsapp-client".
func legacyName(name string) string {
	return legacyPrefix + strings.TrimPrefix(name, "mint")
}

var legacyEnvWarned sync.Once

// envOrLegacy reads key, falls back to the tsapp-era name, then to fallback.
//
// Removable once no caller sets a TSAPP_ variable. The warning is what makes
// that knowable rather than guessed at.
func envOrLegacy(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	legacy := legacyPrefix2Env(key)
	if v := os.Getenv(legacy); v != "" {
		legacyEnvWarned.Do(func() {
			fmt.Fprintf(os.Stderr, "mint: %s is deprecated; use %s\n", legacy, key)
		})
		return v
	}
	return fallback
}

// legacyPrefix2Env turns MINT_STATE_DIR into TSAPP_STATE_DIR.
func legacyPrefix2Env(key string) string {
	return "TSAPP_" + strings.TrimPrefix(key, "MINT_")
}

// peerWait bounds how long resolveServer waits for the netmap.
//
// tsnet returns from Up as soon as the node is Running, which is before its
// view of the tailnet's other nodes has arrived: on a cold client the peer list
// is empty for a moment. That moment is longer than the question takes to
// answer, so waiting is the difference between this check working and this
// check silently doing nothing. It is bounded because the answer only matters
// during the rename, and a client must not hang on it.
const peerWait = 5 * time.Second

// resolveServer picks the daemon's address when the caller did not choose one.
//
// The migration order that keeps everyone reachable is clients first, daemon
// last: a mint client has to be able to talk to a daemon still calling itself
// `tsapp`. Rather than pay a failed request to discover that, ask the local
// tailnet who is actually there. `mint` wins whenever it exists, so this stops
// mattering the moment the daemon is renamed.
//
// Any failure here leaves server untouched: this is a convenience, and a broken
// probe must not be able to break a working client.
//
// Removable once the daemon has been renamed on every tailnet mint serves.
func resolveServer(ctx context.Context, srv *tsnet.Server, server string) string {
	if server != defaultServer {
		return server
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return server
	}

	deadline := time.Now().Add(peerWait)
	for {
		status, err := lc.Status(ctx)
		if err != nil {
			return server
		}
		if status != nil && len(status.Peer) > 0 {
			if !hasPeer(status.Peer, legacyPrefix) || hasPeer(status.Peer, "mint") {
				return server
			}
			fmt.Fprintf(os.Stderr, "mint: no mint node on this tailnet; using %s\n", legacyServer)
			return legacyServer
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return server
		}
		select {
		case <-ctx.Done():
			return server
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// hasPeer reports whether any peer's MagicDNS name starts with the given host
// label.
func hasPeer[K comparable](peers map[K]*ipnstate.PeerStatus, host string) bool {
	for _, peer := range peers {
		if peer != nil && hostOf(peer.DNSName) == host {
			return true
		}
	}
	return false
}

// hostOf takes the first label of a MagicDNS name: "tsapp.tail1234.ts.net."
// becomes "tsapp".
func hostOf(dnsName string) string {
	host, _, _ := strings.Cut(strings.TrimSuffix(dnsName, "."), ".")
	return host
}

// migrateStateDir moves a tsapp-era state directory to its mint name, so the
// compatibility above stops being load-bearing on that host. It is the
// `mint migrate-state` command; nothing calls it implicitly, because moving a
// running daemon's state out from under it is not something to do by surprise.
func migrateStateDir(name string) (from, to string, err error) {
	from = defaultDir(legacyName(name))
	to = defaultDir(name)
	if _, err := os.Stat(from); err != nil {
		return from, to, err
	}
	if _, err := os.Stat(to); err == nil {
		return from, to, fmt.Errorf("%s already exists; move or remove it first", to)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return from, to, err
	}
	if err := os.Rename(from, to); err != nil {
		return from, to, fmt.Errorf("move %s to %s: %w", from, to, err)
	}
	return from, to, nil
}

// cmdMigrateState is `mint migrate-state [daemon|client|all]`: it renames the
// tsapp-era state directories on this host to their mint names, so that
// defaultStateDir stops having anything to fall back to.
//
// It is a move, not a copy, and it keeps the tsnet node key: the node stays the
// same node, with the same console approval and the same tags. The daemon must
// be stopped first, for the same reason `mint reset` insists on it.
func cmdMigrateState(args []string) error {
	target := "all"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = args[0], args[1:]
		if target != "daemon" && target != "client" && target != "all" {
			return fmt.Errorf("unknown migrate-state target %q (want daemon, client, or all)", target)
		}
	}
	fs := flag.NewFlagSet("migrate-state "+target, flag.ContinueOnError)
	socket := fs.String("socket", "", "daemon admin socket used to check whether it is running")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	var names []string
	switch target {
	case "daemon":
		names = []string{"mint"}
	case "client":
		names = []string{"mint-client"}
	case "all":
		names = []string{"mint", "mint-client"}
	}

	if target == "daemon" || target == "all" {
		sock := *socket
		if sock == "" {
			sock = filepath.Join(defaultStateDir("mint"), "admin.sock")
		}
		if err := ensureDaemonStopped(sock); err != nil {
			return err
		}
	}

	var moved int
	for _, name := range names {
		from, to, err := migrateStateDir(name)
		if err != nil {
			// Nothing to migrate is the expected answer on a host that never
			// ran tsapp, or has already been migrated. Say so and carry on;
			// only a real failure to move should stop the command.
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "mint: %s: nothing to migrate\n", from)
				continue
			}
			return err
		}
		fmt.Printf("moved %s to %s\n", from, to)
		moved++
	}
	if moved == 0 {
		fmt.Fprintln(os.Stderr, "mint: no tsapp state found; nothing to do")
	}
	return nil
}
