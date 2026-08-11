// Command tsapp mints short-lived GitHub App tokens for tailnet clients,
// automatically when a human has already approved the scope and on request
// when they have not.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tailscale.com/tsnet"

	"github.com/asw101/tsapp/internal/app"
	"github.com/asw101/tsapp/internal/policy"
	"github.com/asw101/tsapp/internal/server"
	"github.com/asw101/tsapp/internal/wormhole"
)

const usage = `tsapp mints GitHub App tokens for tailnet clients.

Usage:
  tsapp serve [flags]              run the daemon
  tsapp token [flags]              ask the daemon for a token
  tsapp whoami [flags]             show what the daemon sees you as
  tsapp drop [flags]               give up everything this node holds
  tsapp wormhole put --to NODE --key KEY [--ttl 10m] [--replace]
  tsapp wormhole get --key KEY [--from NODE]
  tsapp wormhole discard --key KEY [--from NODE]
  tsapp wormhole list [--json]

  tsapp version                    print the version and how it was built

  tsapp pending                    list requests awaiting approval
  tsapp approvals                  list current approvals
  tsapp approve <id> [--ttl 30d]   approve a pending request
  tsapp deny <id>                  drop a pending request
  tsapp revoke <id>                revoke an approval
  tsapp reset --yes                delete all local state
  tsapp reset daemon --yes         narrow it to the daemon identity and approvals
  tsapp reset client --yes         narrow it to the client identity

serve flags:
  --hostname NAME     tailnet name to claim         (default tsapp)
  --state-dir PATH    tsnet state and approvals     (default OS config dir/tsapp)
  --socket PATH       admin socket                  (default <state-dir>/admin.sock)
  --socket-group G    group that may use the admin socket, name or gid
                      (env TSAPP_SOCKET_GROUP). Widens it from 0600 to 0660,
                      so members approve without root. The socket has no other
                      authentication — grant it as you would sudo
  --port N            tailnet listen port           (default 8080)
  --tls               serve HTTPS on :443 instead of HTTP; needs HTTPS
                      Certificates enabled for the tailnet. No cert to supply
  --app-id ID         GitHub App ID                 (env GH_APP_ID)
  --key PATH          App private key PEM           (env GH_APP_KEY_FILE)
  --installation ID   installation to mint from     (env GH_APP_INSTALLATION_ID)
                      optional; discovered when the App has exactly one
  --api URL           GitHub API base URL           (env GITHUB_API_URL)

token flags:
  --server URL        daemon address                (default http://tsapp:8080)
  --repo NAME         repository, repeatable and comma-separated. Required;
                      pass --repo '*' to ask for every repository the
                      installation can reach, which still needs approval
  --permission k=v    narrow a permission, repeatable
  --hostname NAME     tailnet name for this client  (default tsapp-client)
  --state-dir PATH    tsnet state for this client   (default OS config dir/tsapp-client)
  --json              print the full response

whoami and wormhole take the client flags that do not describe a scope —
--server, --hostname, and --state-dir — and drop and wormhole list take those
plus --json.

Drop needs no approval, because it only ever reduces what the caller can
reach: the daemon removes the calling node's approvals and its outstanding
requests and every wormhole item addressed to it immediately. Items it sent to
other nodes remain. The node it drops is always the caller, so one client cannot
drop another's access.

Clients join the tailnet on first run and print a login URL. Approve the node
in the Tailscale console, give it a tag, and grant it the tsapp capability;
after that it asks for scopes and this daemon decides.

Admin commands talk to the daemon over its Unix socket, so they work only from
the host it runs on. That is deliberate: approving is an operator action, not
something a tailnet client can reach.

Reset permanently deletes local tsnet identities and, for the daemon, every
approval. It does not remove the corresponding nodes from the Tailscale admin
console.

Exit codes from 'tsapp token' and 'tsapp wormhole', so a script need not read
the message:
  0  a token, on stdout
  2  pending approval — unused by wormhole v1
  3  denied by policy — retrying will not help
  1  anything else
`

// Exit codes a script can branch on. Pending and denied want different
// responses — retry versus stop — and telling them apart by parsing the
// message would be worse for everyone.
const (
	exitError   = 1 // anything else: transport, configuration, upstream
	exitPending = 2 // the scope needs a human to approve it
	exitDenied  = 3 // refused by policy; retrying will not help
)

// exitCodeError carries the status `tsapp` should exit with.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string { return e.err.Error() }
func (e *exitCodeError) Unwrap() error { return e.err }

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(os.Args[1:]); err != nil {
		code := exitError
		var coded *exitCodeError
		if errors.As(err, &coded) {
			code = coded.code
		}
		fmt.Fprintln(os.Stderr, "tsapp: "+err.Error())
		os.Exit(code)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "token":
		return cmdToken(args[1:])
	case "whoami":
		return cmdWhoami(args[1:])
	case "drop":
		return cmdDrop(args[1:])
	case "wormhole":
		return cmdWormhole(args[1:])
	case "pending":
		return cmdAdminList(args[1:], "/v1/pending")
	case "approvals":
		return cmdAdminList(args[1:], "/v1/approvals")
	case "approve":
		return cmdApprove(args[1:])
	case "deny":
		return cmdAdminByID(args[1:], "deny", "/v1/deny")
	case "revoke":
		return cmdAdminByID(args[1:], "revoke", "/v1/revoke")
	case "reset":
		return cmdReset(args[1:])
	case "version", "--version", "-version":
		fmt.Print(versionReport())
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try 'tsapp help')", args[0])
	}
}

// --- version ---

// version is stamped at build time with -ldflags "-X main.version=...".
// Unstamped builds fall back to the VCS information the toolchain records.
var version = ""

// versionReport describes the binary well enough to tell two of them apart:
// which release, which commit, and whether the tree was dirty when it was
// built. A binary that cannot say which one it is invites the wrong bug report.
func versionReport() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tsapp %s\n", versionString())

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b.String()
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if revision := settings["vcs.revision"]; revision != "" {
		state := "clean"
		if settings["vcs.modified"] == "true" {
			state = "dirty"
		}
		fmt.Fprintf(&b, "  commit  %s (%s)\n", short(revision), state)
	}
	if when := settings["vcs.time"]; when != "" {
		fmt.Fprintf(&b, "  built   %s\n", when)
	}
	fmt.Fprintf(&b, "  go      %s %s/%s\n", info.GoVersion, settings["GOOS"], settings["GOARCH"])
	return b.String()
}

func versionString() string {
	if version != "" {
		return version
	}
	// A binary installed with "go install" carries its module version here;
	// one built from a working tree usually reports "(devel)".
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "unknown"
}

func short(revision string) string {
	if len(revision) > 12 {
		return revision[:12]
	}
	return revision
}

// --- serve ---

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	hostname := fs.String("hostname", "tsapp", "tailnet name to claim")
	stateDir := fs.String("state-dir", defaultDir("tsapp"), "tsnet state and approvals")
	socket := fs.String("socket", "", "admin socket path")
	socketGroup := fs.String("socket-group", envOr("TSAPP_SOCKET_GROUP", ""),
		"group allowed to use the admin socket (name or gid); widens it to 0660")
	port := fs.Int("port", 8080, "tailnet listen port")
	useTLS := fs.Bool("tls", false, "serve HTTPS over the tailnet")
	appID := fs.String("app-id", os.Getenv("GH_APP_ID"), "GitHub App ID")
	keyPath := fs.String("key", envOr("GH_APP_KEY_FILE", ""), "App private key PEM")
	installation := fs.Int64("installation", envInt64("GH_APP_INSTALLATION_ID"),
		"installation ID; discovered automatically when the App has exactly one")
	apiURL := fs.String("api", envOr("GITHUB_API_URL", app.DefaultBaseURL), "GitHub API base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" {
		*socket = filepath.Join(*stateDir, "admin.sock")
	}
	if strings.TrimSpace(*appID) == "" || strings.TrimSpace(*keyPath) == "" {
		return errors.New("serve needs --app-id and --key (or GH_APP_ID and GH_APP_KEY_FILE)")
	}
	if err := disableCoreDumps(); err != nil {
		return err
	}

	signer, err := app.LoadPEMSigner(*keyPath)
	if err != nil {
		return err
	}

	gh := &app.Client{AppID: *appID, Signer: signer, BaseURL: *apiURL, UserAgent: "tsapp"}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	installationID, account, err := resolveInstallation(ctx, gh, *installation)
	if err != nil {
		return err
	}
	log.Printf("minting from installation %d (%s)", installationID, account)

	store, err := policy.Open(filepath.Join(*stateDir, "approvals.json"))
	if err != nil {
		return err
	}
	if pruned, err := store.PruneExpired(time.Now()); err != nil {
		return err
	} else if pruned > 0 {
		log.Printf("pruned %d expired approval(s)", pruned)
	}

	srv := &tsnet.Server{
		Hostname: *hostname,
		Dir:      filepath.Join(*stateDir, "tsnet"),
		// Logf (verbose backend) is discarded when unset; UserLogf keeps the
		// status lines a daemon operator wants.
	}
	defer srv.Close()

	status, err := srv.Up(ctx)
	if err != nil {
		return fmt.Errorf("join tailnet: %w", err)
	}
	log.Printf("tailnet node %s (%s)", status.Self.DNSName, status.Self.TailscaleIPs)

	localClient, err := srv.LocalClient()
	if err != nil {
		return err
	}

	handler := &server.Server{
		Engine:   &policy.Engine{Store: store, Account: account},
		Store:    store,
		Who:      localClient,
		Minter:   &githubMinter{client: gh, installationID: installationID},
		Logger:   log.Default(),
		Wormhole: wormhole.New(),
		Peers:    localPeerResolver{client: localClient},
	}
	handler.StartWormhole(ctx.Done())
	defer handler.CloseWormhole()

	var tailnetListener net.Listener
	addr := fmt.Sprintf(":%d", *port)
	if *useTLS {
		// The certificate comes from Tailscale, for this node's MagicDNS name.
		// There is no key or cert file to supply, and the first request after
		// startup can take thirty seconds or more while LetsEncrypt issues it.
		log.Print("serving HTTPS; the first request may block while the certificate is issued")
		tailnetListener, err = srv.ListenTLS("tcp", ":443")
		if err != nil {
			return fmt.Errorf("serve HTTPS on the tailnet: %w\n"+
				"  Tailscale issues the certificate for this node's MagicDNS name, so there is\n"+
				"  nothing to supply — but HTTPS Certificates must be enabled for the tailnet\n"+
				"  (admin console, DNS page). Or drop --tls: tailnet traffic is already\n"+
				"  WireGuard-encrypted, which is why plain HTTP is the default.", err)
		}
		addr = ":443"
	} else {
		// Plain HTTP is safe here: everything on the tailnet is already
		// WireGuard-encrypted, and this avoids the LetsEncrypt round trip.
		tailnetListener, err = srv.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen on tailnet: %w", err)
		}
	}
	defer tailnetListener.Close()

	adminListener, err := listenUnix(*socket, *socketGroup)
	if err != nil {
		return err
	}
	defer adminListener.Close()

	if *socketGroup != "" {
		log.Printf("tailnet %s%s, admin %s (group %s)", *hostname, addr, *socket, *socketGroup)
	} else {
		log.Printf("tailnet %s%s, admin %s", *hostname, addr, *socket)
	}

	errs := make(chan error, 2)
	go func() { errs <- http.Serve(tailnetListener, handler.TailnetHandler()) }()
	go func() { errs <- http.Serve(adminListener, handler.AdminHandler()) }()

	select {
	case <-ctx.Done():
		log.Print("shutting down")
		return nil
	case err := <-errs:
		return err
	}
}

func disableCoreDumps() error {
	limit := &syscall.Rlimit{}
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, limit); err != nil {
		return fmt.Errorf("read core dump limit: %w", err)
	}
	limit.Cur = 0
	limit.Max = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, limit); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	return nil
}

// listenUnix binds the admin socket, replacing a stale one left by a crash.
//
// An empty group keeps the socket 0600, reachable by the service user and root
// alone. Naming a group widens it to 0660 owned by that group, which is what
// lets an operator approve without sudo — and is a real widening, since the
// socket has no authentication beyond these bits. The directory must be
// traversable by the group too, or this achieves nothing.
func listenUnix(path, group string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("clear stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on admin socket: %w", err)
	}
	mode := os.FileMode(0o600)
	if group != "" {
		gid, err := lookupGID(group)
		if err != nil {
			ln.Close()
			return nil, err
		}
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			return nil, fmt.Errorf("give admin socket to group %q: %w", group, err)
		}
		mode = 0o660
	}
	// Filesystem permissions are the only thing guarding the admin surface.
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("restrict admin socket: %w", err)
	}
	return ln, nil
}

// lookupGID resolves a group name or a numeric gid. A numeric value is taken
// as-is so a unit can name a gid that has no entry on this host.
func lookupGID(group string) (int, error) {
	if gid, err := strconv.Atoi(group); err == nil {
		return gid, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, fmt.Errorf("resolve --socket-group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q has a non-numeric gid %q", group, g.Gid)
	}
	return gid, nil
}

type githubMinter struct {
	client         *app.Client
	installationID int64
}

func (m *githubMinter) Mint(ctx context.Context, scope policy.Scope) (*app.Token, error) {
	scope = scope.Normalize()

	repos := scope.Repos
	if scope.HasAllRepos() {
		// The API reads an omitted repositories field as the installation's
		// whole reach, which is exactly what the wildcard asks for. Sending
		// "*" through would be looked up as a repository name and rejected.
		repos = nil
	}
	return m.client.CreateToken(ctx, m.installationID, app.TokenRequest{
		Repositories: repos,
		Permissions:  scope.Permissions,
	})
}

// resolveInstallation returns the installation to mint from and the account it
// belongs to. The account is what lets the policy refuse a request naming some
// other owner.
func resolveInstallation(ctx context.Context, client *app.Client, explicit int64) (int64, string, error) {
	if explicit != 0 {
		installation, err := client.Installation(ctx, explicit)
		if err != nil {
			return 0, "", err
		}
		return installation.ID, installation.Account.Login, nil
	}
	installations, err := client.Installations(ctx)
	if err != nil {
		return 0, "", err
	}
	switch len(installations) {
	case 0:
		return 0, "", errors.New("app has no installations; install it on an account first")
	case 1:
		return installations[0].ID, installations[0].Account.Login, nil
	default:
		var b strings.Builder
		b.WriteString("app has multiple installations; pass --installation:\n")
		for _, in := range installations {
			fmt.Fprintf(&b, "  %d\t%s\n", in.ID, in.Account.Login)
		}
		return 0, "", errors.New(strings.TrimRight(b.String(), "\n"))
	}
}

// --- client ---

type clientFlags struct {
	server   string
	hostname string
	stateDir string
}

func (c *clientFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.server, "server", envOr("TSAPP_SERVER", "http://tsapp:8080"), "daemon address")
	fs.StringVar(&c.hostname, "hostname", envOr("TSAPP_HOSTNAME", "tsapp-client"), "tailnet name for this client")
	fs.StringVar(&c.stateDir, "state-dir", envOr("TSAPP_STATE_DIR", defaultDir("tsapp-client")), "tsnet state")
}

// dial joins the tailnet, printing the login URL on first run so the node can
// be approved in the console.
func (c *clientFlags) dial(ctx context.Context) (*tsnet.Server, *http.Client, error) {
	srv := &tsnet.Server{
		Hostname: c.hostname,
		Dir:      c.stateDir,
		// Logf is the verbose backend log and is discarded when unset. The
		// user-facing messages — including the first-run auth URL — go to
		// UserLogf, which otherwise defaults to log.Printf and is noisy.
		UserLogf: func(format string, args ...any) {
			line := strings.TrimSpace(fmt.Sprintf(format, args...))
			if strings.Contains(line, "://login.tailscale.com") || strings.Contains(line, "To authenticate") {
				fmt.Fprintln(os.Stderr, line)
			}
		},
	}
	status, err := srv.Up(ctx)
	if err != nil {
		srv.Close()
		return nil, nil, fmt.Errorf("join tailnet: %w", err)
	}
	if status != nil && status.Self != nil {
		c.server = expandTailnetHost(c.server, status.Self.DNSName)
	}
	return srv, srv.HTTPClient(), nil
}

// expandTailnetHost turns a bare hostname into a MagicDNS name, using the
// tailnet suffix from this node's own DNS name. Short names do resolve once
// the tailnet's DNS configuration is in place, so this is belt and braces
// rather than a fix — see settleTimeout for the failure it looks like.
func expandTailnetHost(server, selfDNSName string) string {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return server
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return server
	}
	_, suffix, found := strings.Cut(strings.TrimSuffix(selfDNSName, "."), ".")
	if !found || suffix == "" {
		return server
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(host+"."+suffix, port)
	} else {
		u.Host = host + "." + suffix
	}
	return u.String()
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	var cf clientFlags
	cf.bind(fs)
	var repos, permissions stringList
	fs.Var(&repos, "repo", "repository (repeatable, comma-separated)")
	fs.Var(&permissions, "permission", "narrow a permission as key=value (repeatable)")
	asJSON := fs.Bool("json", false, "print the full response")
	if err := fs.Parse(args); err != nil {
		return err
	}

	scope := policy.Scope{Repos: splitAll(repos)}
	perms, err := parsePermissions(permissions)
	if err != nil {
		return err
	}
	scope.Permissions = perms

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv, httpClient, err := cf.dial(ctx)
	if err != nil {
		return err
	}
	defer srv.Close()

	body, _ := json.Marshal(server.TokenRequest{Repos: scope.Repos, Permissions: scope.Permissions})
	resp, err := doWhileSettling(ctx, httpClient, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimSuffix(cf.server, "/")+"/v1/token", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("reach %s: %w", cf.server, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var token server.TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return err
		}
		if *asJSON {
			return printJSON(token)
		}
		fmt.Println(token.Token)
		return nil

	default:
		var status server.StatusResponse
		_ = json.NewDecoder(resp.Body).Decode(&status)
		return tokenError(resp.StatusCode, resp.Status, status)
	}
}

// tokenError turns a non-success response into an error carrying the exit code
// a caller should branch on.
func tokenError(code int, statusLine string, status server.StatusResponse) error {
	switch code {
	case http.StatusAccepted:
		return &exitCodeError{code: exitPending, err: fmt.Errorf(
			"pending approval (request %s) — run 'tsapp approve %s' on the daemon host",
			status.RequestID, status.RequestID)}

	case http.StatusForbidden:
		return &exitCodeError{code: exitDenied, err: errors.New(reasonOr(status, "denied"))}

	default:
		return errors.New(reasonOr(status, "server returned "+statusLine))
	}
}

func reasonOr(status server.StatusResponse, fallback string) string {
	if status.Reason == "" {
		return fallback
	}
	if status.Status == "" {
		return status.Reason
	}
	return status.Status + ": " + status.Reason
}

func cmdWhoami(args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	var cf clientFlags
	cf.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv, httpClient, err := cf.dial(ctx)
	if err != nil {
		return err
	}
	defer srv.Close()

	resp, err := doWhileSettling(ctx, httpClient, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(cf.server, "/")+"/v1/whoami", nil)
	})
	if err != nil {
		return fmt.Errorf("reach %s: %w", cf.server, err)
	}
	defer resp.Body.Close()
	return copyJSON(resp)
}

// cmdDrop asks the daemon to remove everything this node holds.
//
// It names no node: the daemon drops whoever the tailnet says is calling, so
// the only access this can remove is the caller's own.
func cmdDrop(args []string) error {
	fs := flag.NewFlagSet("drop", flag.ContinueOnError)
	var cf clientFlags
	cf.bind(fs)
	asJSON := fs.Bool("json", false, "print the full response")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv, httpClient, err := cf.dial(ctx)
	if err != nil {
		return err
	}
	defer srv.Close()

	resp, err := doWhileSettling(ctx, httpClient, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimSuffix(cf.server, "/")+"/v1/drop", nil)
	})
	if err != nil {
		return fmt.Errorf("reach %s: %w", cf.server, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var status server.StatusResponse
		_ = json.NewDecoder(resp.Body).Decode(&status)
		return errors.New(reasonOr(status, "server returned "+resp.Status))
	}
	var dropped server.DropResponse
	if err := json.NewDecoder(resp.Body).Decode(&dropped); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(dropped)
	}
	fmt.Println(describeDrop(dropped))
	return nil
}

// describeDrop reports what went away, including when nothing did: a node
// that already held nothing got what it asked for, so that is a sentence
// rather than an error.
func describeDrop(d server.DropResponse) string {
	who := d.NodeName
	if who == "" {
		who = d.NodeID
	}
	if d.ApprovalsDropped == 0 && d.PendingDropped == 0 && d.WormholesDropped == 0 {
		return who + " held nothing to drop"
	}
	return fmt.Sprintf("%s dropped %s, %s, and %s", who,
		count(d.ApprovalsDropped, "approval"),
		count(d.PendingDropped, "pending request"),
		count(d.WormholesDropped, "wormhole item"))
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// settleTimeout bounds how long a client waits for the tailnet to become
// usable before giving up.
//
// tsnet reports Running before the tailnet's DNS configuration has been
// applied, so the first request after a fresh join can fail to resolve a peer
// that is about to be reachable. It looks like a hard "no such host" and goes
// away if you simply run the command again, which is a poor way to learn about
// it. Retrying transient failures makes the first run behave like the second.
const settleTimeout = 20 * time.Second

// doWhileSettling retries request failures until the tailnet settles. Only
// transport errors are retried; an HTTP response, whatever its status, is the
// server having answered.
func doWhileSettling(ctx context.Context, client *http.Client, newRequest func() (*http.Request, error)) (*http.Response, error) {
	deadline := time.Now().Add(settleTimeout)
	var lastErr error
	for attempt := 0; ; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, lastErr
		}
		if attempt == 0 {
			fmt.Fprintln(os.Stderr, "tsapp: waiting for the tailnet to settle...")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// --- admin ---

func adminSocketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", envOr("TSAPP_SOCKET", filepath.Join(defaultDir("tsapp"), "admin.sock")),
		"daemon admin socket")
}

func adminClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

func cmdAdminList(args []string, path string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	socket := adminSocketFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := adminClient(*socket).Get("http://admin" + path)
	if err != nil {
		return adminDialError(*socket, err)
	}
	defer resp.Body.Close()
	return copyJSON(resp)
}

func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	socket := adminSocketFlag(fs)
	ttl := fs.String("ttl", "", "expire the approval after this long, e.g. 720h (default never)")
	id, err := parseWithID(fs, args)
	if err != nil {
		return err
	}
	if id == "" {
		return errors.New("usage: tsapp approve <request-id> [--ttl 720h]")
	}
	body, _ := json.Marshal(map[string]string{"id": id, "ttl": *ttl})
	return adminPost(*socket, "/v1/approve", body)
}

// parseWithID parses flags that may appear either side of the single
// positional argument.
//
// The flag package stops at the first non-flag argument, so "approve ID --ttl
// 720h" would otherwise treat --ttl as a second positional and fail — which is
// exactly the form the usage text documents. Parsing in rounds accepts both
// orders.
func parseWithID(fs *flag.FlagSet, args []string) (string, error) {
	var id string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return "", err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return id, nil
		}
		if id != "" {
			return "", fmt.Errorf("unexpected argument %q", rest[0])
		}
		id, rest = rest[0], rest[1:]
	}
}

func cmdAdminByID(args []string, name, path string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	socket := adminSocketFlag(fs)
	id, err := parseWithID(fs, args)
	if err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("usage: tsapp %s <id>", name)
	}
	body, _ := json.Marshal(map[string]string{"id": id})
	return adminPost(*socket, path, body)
}

func adminPost(socket, path string, body []byte) error {
	resp, err := adminClient(socket).Post("http://admin"+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return adminDialError(socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var status server.StatusResponse
		_ = json.NewDecoder(resp.Body).Decode(&status)
		if status.Reason != "" {
			return errors.New(status.Reason)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	return copyJSON(resp)
}

func adminDialError(socket string, err error) error {
	return fmt.Errorf("reach the daemon at %s (is 'tsapp serve' running on this host?): %w", socket, err)
}

// --- reset ---

func cmdReset(args []string) error {
	// "Clean up everything this host holds" is the case people actually want,
	// so it is the default: a bare `tsapp reset` covers daemon and client
	// alike, and a target narrows it when only one of them is in the way.
	target := "all"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = args[0], args[1:]
		if target != "daemon" && target != "client" && target != "all" {
			return fmt.Errorf("unknown reset target %q (want daemon, client, or all)", target)
		}
	}

	fs := flag.NewFlagSet("reset "+target, flag.ContinueOnError)
	var stateDir, daemonStateDir, clientStateDir, socket string
	switch target {
	case "daemon":
		fs.StringVar(&stateDir, "state-dir", envOr("TSAPP_STATE_DIR", defaultDir("tsapp")),
			"daemon state directory")
		fs.StringVar(&socket, "socket", "", "daemon admin socket used to check whether it is running")
	case "client":
		fs.StringVar(&stateDir, "state-dir", envOr("TSAPP_STATE_DIR", defaultDir("tsapp-client")),
			"client state directory")
	case "all":
		fs.StringVar(&daemonStateDir, "daemon-state-dir", defaultDir("tsapp"),
			"daemon state directory")
		fs.StringVar(&clientStateDir, "client-state-dir", defaultDir("tsapp-client"),
			"client state directory")
		fs.StringVar(&socket, "socket", "", "daemon admin socket used to check whether it is running")
	}
	yes := fs.Bool("yes", false, "confirm permanent deletion")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	var dirs []string
	switch target {
	case "daemon":
		daemonStateDir = stateDir
		dirs = []string{stateDir}
	case "client":
		dirs = []string{stateDir}
	case "all":
		dirs = []string{daemonStateDir, clientStateDir}
	}

	for i, dir := range dirs {
		safe, err := safeResetDir(dir)
		if err != nil {
			return err
		}
		dirs[i] = safe
	}
	if target == "daemon" || target == "all" {
		daemonStateDir = dirs[0]
	}
	if !*yes {
		return fmt.Errorf("reset %s would permanently remove %s; rerun with --yes",
			target, strings.Join(dirs, " and "))
	}

	if target == "daemon" || target == "all" {
		if socket == "" {
			socket = filepath.Join(daemonStateDir, "admin.sock")
		}
		if err := ensureDaemonStopped(socket); err != nil {
			return err
		}
	}

	seen := make(map[string]bool, len(dirs))
	for _, dir := range dirs {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("remove state directory %s: %w", dir, err)
		}
		fmt.Printf("removed %s\n", dir)
	}
	fmt.Fprintln(os.Stderr, "Remove the corresponding node or nodes from the Tailscale admin console.")
	return nil
}

func safeResetDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("refusing to reset an empty state directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve state directory %q: %w", dir, err)
	}
	abs = filepath.Clean(abs)
	root := filepath.Clean(string(filepath.Separator))
	if volume := filepath.VolumeName(abs); volume != "" {
		root = filepath.Clean(volume + string(filepath.Separator))
	}
	protected := []string{root}
	if home, err := os.UserHomeDir(); err == nil {
		protected = append(protected, filepath.Clean(home))
	}
	if config, err := os.UserConfigDir(); err == nil {
		protected = append(protected, filepath.Clean(config))
	}
	for _, path := range protected {
		if abs == path {
			return "", fmt.Errorf("refusing to reset protected directory %s", abs)
		}
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		resolved = filepath.Clean(resolved)
		for _, path := range protected {
			if resolved == path {
				return "", fmt.Errorf("refusing to reset %s because it resolves to protected directory %s", abs, resolved)
			}
		}
	}
	return abs, nil
}

func ensureDaemonStopped(socket string) error {
	conn, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
	if err == nil {
		conn.Close()
		return fmt.Errorf("daemon is still running at %s; stop it before resetting its state", socket)
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil
	}
	if _, statErr := os.Lstat(socket); errors.Is(statErr, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("cannot verify that the daemon is stopped at %s: %w", socket, err)
}

// --- helpers ---

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// splitAll expands comma-separated values so --repo a,b and --repo a --repo b
// mean the same thing.
func splitAll(values []string) []string {
	var out []string
	for _, v := range values {
		for _, field := range strings.Split(v, ",") {
			if field = strings.TrimSpace(field); field != "" {
				out = append(out, field)
			}
		}
	}
	return out
}

func parsePermissions(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for _, v := range splitAll(values) {
		key, value, found := strings.Cut(v, "=")
		if !found || key == "" || value == "" {
			return nil, fmt.Errorf("invalid permission %q (want key=value, e.g. contents=read)", v)
		}
		out[key] = value
	}
	return out, nil
}

func copyJSON(resp *http.Response) error {
	var v any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return err
	}
	return printJSON(v)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func defaultDir(name string) string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return name
	}
	return filepath.Join(dir, name)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt64(key string) int64 {
	v, err := strconv.ParseInt(os.Getenv(key), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
