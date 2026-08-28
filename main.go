// Command mint mints short-lived GitHub App tokens for tailnet clients,
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
	"io"
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
	"sync"
	"syscall"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"

	"github.com/asw101/mint/internal/app"
	"github.com/asw101/mint/internal/policy"
	"github.com/asw101/mint/internal/server"
	"github.com/asw101/mint/internal/wormhole"
)

const usage = `mint mints GitHub App tokens for tailnet clients.

Usage:
  mint serve [flags]              run the daemon
  mint token [flags]              ask the daemon for a token
  mint whoami [flags]             show what the daemon sees you as
  mint drop [flags]               give up everything this node holds
  mint wormhole put --to NODE --key KEY [--ttl 10m] [--replace]
  mint wormhole get --key KEY [--from NODE]
  mint wormhole discard --key KEY [--from NODE]
  mint wormhole list [--json]

  mint policy fetch|diff|validate|apply    manage the tailnet policy file

  mint version                    print the version and how it was built

  mint pending                    list requests awaiting approval
  mint approvals                  list current approvals
  mint approve <id> [--ttl 30d]   approve a pending request
  mint deny <id>                  drop a pending request
  mint revoke <id>                revoke an approval
  mint reset --yes                delete all local state
  mint reset daemon --yes         narrow it to the daemon identity and approvals
  mint reset client --yes         narrow it to the client identity

serve flags:
  --hostname NAME     tailnet name to claim         (default mint)
  --state-dir PATH    tsnet state and approvals     (default OS config dir/mint)
  --socket PATH       admin socket                  (default <state-dir>/admin.sock)
  --socket-group G    group that may use the admin socket, name or gid
                      (env MINT_SOCKET_GROUP). Widens it from 0600 to 0660,
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
  --server URL        daemon address                (default http://mint:8080)
  --repo NAME         repository, repeatable and comma-separated. Required;
                      pass --repo '*' to ask for every repository the
                      installation can reach, which still needs approval
  --permission k=v    narrow a permission, repeatable
  --hostname NAME     tailnet name for this client  (default mint-client)
  --state-dir PATH    tsnet state for this client   (default OS config dir/mint-client)
  --join-timeout D    how long to wait to join the tailnet
                      (default 30s, 0 waits forever, env MINT_JOIN_TIMEOUT).
                      A first run that prints a login URL waits 5m instead,
                      because that wait is a human's
  --json              print the full response

whoami and wormhole take the client flags that do not describe a scope —
--server, --hostname, --state-dir, and --join-timeout — and drop and wormhole
list take those plus --json.

Drop needs no approval, because it only ever reduces what the caller can
reach: the daemon removes the calling node's approvals and its outstanding
requests and every wormhole item addressed to it immediately. Items it sent to
other nodes remain. The node it drops is always the caller, so one client cannot
drop another's access.

Clients join the tailnet on first run and print a login URL. Approve the node
in the Tailscale console, give it a tag, and grant it the mint capability;
after that it asks for scopes and this daemon decides.

Admin commands talk to the daemon over its Unix socket, so they work only from
the host it runs on. That is deliberate: approving is an operator action, not
something a tailnet client can reach.

Reset permanently deletes local tsnet identities and, for the daemon, every
approval. It does not remove the corresponding nodes from the Tailscale admin
console.

Exit codes from 'mint token' and 'mint wormhole', so a script need not read
the message:
  0  a token, on stdout
  2  pending approval — unused by wormhole v1
  3  denied by policy — retrying will not help
  1  anything else, including a join that ran out of time: 2 and 3 are the
     daemon's answer, and a client that never reached it has none
`

// Exit codes a script can branch on. Pending and denied want different
// responses — retry versus stop — and telling them apart by parsing the
// message would be worse for everyone.
const (
	exitError   = 1 // anything else: transport, configuration, upstream
	exitPending = 2 // the scope needs a human to approve it
	exitDenied  = 3 // refused by policy; retrying will not help
)

// exitCodeError carries the status `mint` should exit with.
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
		fmt.Fprintln(os.Stderr, "mint: "+err.Error())
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
	case "policy":
		return cmdPolicy(args[1:])
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
		return fmt.Errorf("unknown command %q (try 'mint help')", args[0])
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
	fmt.Fprintf(&b, "mint %s\n", versionString())

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
	// Before anything else: the daemon must not be holding a credential that
	// can rewrite the tailnet policy that authorizes it. See
	// refuseIfPolicyCredentialPresent.
	if err := refuseIfPolicyCredentialPresent(os.LookupEnv); err != nil {
		return err
	}

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	hostname := fs.String("hostname", "mint", "tailnet name to claim")
	stateDir := fs.String("state-dir", defaultDir("mint"), "tsnet state and approvals")
	socket := fs.String("socket", "", "admin socket path")
	socketGroup := fs.String("socket-group", envOr("MINT_SOCKET_GROUP", ""),
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

	gh := &app.Client{AppID: *appID, Signer: signer, BaseURL: *apiURL, UserAgent: "mint"}

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

// defaultServer is where a client looks for the daemon when nothing says
// otherwise.
const defaultServer = "http://mint:8080"

type clientFlags struct {
	server   string
	hostname string
	stateDir string
	join     joinTimeoutFlag
}

func (c *clientFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.server, "server", envOr("MINT_SERVER", defaultServer), "daemon address")
	fs.StringVar(&c.hostname, "hostname", envOr("MINT_HOSTNAME", "mint-client"), "tailnet name for this client")
	fs.StringVar(&c.stateDir, "state-dir", envOr("MINT_STATE_DIR", defaultDir("mint-client")), "tsnet state")
	c.join.d, c.join.err = envJoinTimeout(os.Getenv("MINT_JOIN_TIMEOUT"))
	fs.Var(&c.join, "join-timeout", "how long to wait to join the tailnet, 0 for no bound (env MINT_JOIN_TIMEOUT)")
}

// dial joins the tailnet, printing the login URL on first run so the node can
// be approved in the console.
//
// The join is bounded. Every client command waits here before it can say
// anything at all, and a tailnet that never comes up used to mean a process
// that never exited: `git` sat for minutes on the credential helper, whose
// decline path reads an exit status a hung process never produces. The bound
// lives here rather than in the callers so that every one of them has it.
func (c *clientFlags) dial(ctx context.Context) (*tsnet.Server, *http.Client, error) {
	if c.join.err != nil {
		return nil, nil, c.join.err
	}
	budget := newJoinBudget(ctx, c.join.d, os.Stderr)
	// The bound is on the join, not on the session: the returned server and
	// client outlive it.
	defer budget.stop()

	srv := &tsnet.Server{
		Hostname: c.hostname,
		Dir:      c.stateDir,
		// Logf is the verbose backend log and is discarded when unset. The
		// user-facing messages — including the first-run auth URL — go to
		// UserLogf, which otherwise defaults to log.Printf and is noisy.
		UserLogf: func(format string, args ...any) {
			line := strings.TrimSpace(fmt.Sprintf(format, args...))
			if !isAuthPrompt(line) {
				return
			}
			fmt.Fprintln(os.Stderr, line)
			// A first run is not a stall. srv.Up is blocked on a human
			// opening that URL, and nobody finds a browser, logs in and
			// approves a node inside the unattended budget. Seeing the URL
			// is how we learn the wait belongs to a person, so the bound
			// becomes a person's, and we say so: a wait somebody knows the
			// length of is a wait, and a silent one is a hang.
			budget.extend(authTimeout)
		},
	}

	var status *ipnstate.Status
	err := joinUnder(budget, func(ctx context.Context) error {
		var err error
		status, err = srv.Up(ctx)
		return err
	})
	if err != nil {
		srv.Close()
		return nil, nil, err
	}
	if status != nil && status.Self != nil {
		c.server = expandTailnetHost(c.server, status.Self.DNSName)
	}
	return srv, srv.HTTPClient(), nil
}

// isAuthPrompt reports whether a tsnet user log line is the first-run login
// URL, which is both the one message worth showing and the sign that what
// we are waiting for is a person.
func isAuthPrompt(line string) bool {
	return strings.Contains(line, "://login.tailscale.com") || strings.Contains(line, "To authenticate")
}

// joinTimeout bounds a join nobody is watching.
//
// A healthy join takes seconds. Thirty of them is generous for one and short
// enough that a stalled credential helper fails while the person who ran it is
// still there to read why.
const joinTimeout = 30 * time.Second

// authTimeout bounds a join somebody is watching: the first run, where the
// node is waiting to be authorized in the console. That wait is legitimately
// minutes long, so it gets its own budget rather than making the unattended
// one long enough to cover it.
const authTimeout = 5 * time.Minute

// errJoinTimeout is the cause a joinBudget cancels with, so that running out
// of time is distinguishable from SIGINT, which cancels with context.Canceled.
var errJoinTimeout = errors.New("join timed out")

// joinBudget is the bound on joining the tailnet: a context derived from the
// caller's that cancels itself when the time is up, and can be given more time
// when it turns out a human is on the other end of the wait.
type joinBudget struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	warn   io.Writer

	mu       sync.Mutex
	timer    *time.Timer // nil when the budget is unbounded
	budget   time.Duration
	extended bool
}

// newJoinBudget derives a bounded context from parent. A budget of zero means
// no bound, which is what --join-timeout 0 asks for.
func newJoinBudget(parent context.Context, budget time.Duration, warn io.Writer) *joinBudget {
	ctx, cancel := context.WithCancelCause(parent)
	b := &joinBudget{ctx: ctx, cancel: cancel, warn: warn, budget: budget}
	if budget > 0 {
		b.timer = time.AfterFunc(budget, func() { b.cancel(errJoinTimeout) })
	}
	return b
}

// extend raises the bound to d and says so, reporting whether it did. It only
// ever lengthens: an unbounded budget stays unbounded, and announcing a bound
// that is not in force would be a lie.
func (b *joinBudget) extend(d time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.timer == nil || b.extended || d <= b.budget || b.ctx.Err() != nil {
		return false
	}
	b.timer.Reset(d)
	b.budget, b.extended = d, true
	fmt.Fprintf(b.warn, "mint: waiting up to %s for this node to be authorized\n", d)
	return true
}

// stop releases the budget. It is what keeps the bound on the join rather than
// on everything the caller does with the connection afterwards.
func (b *joinBudget) stop() {
	b.mu.Lock()
	if b.timer != nil {
		b.timer.Stop()
	}
	b.mu.Unlock()
	b.cancel(context.Canceled)
}

// explain names what actually went wrong. Running out of time is neither a
// signal nor a transport failure, and reporting it as "context canceled" is
// how a bound becomes as confusing as the hang it replaced.
func (b *joinBudget) explain(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(context.Cause(b.ctx), errJoinTimeout) {
		b.mu.Lock()
		budget := b.budget
		b.mu.Unlock()
		// exitError, said out loud rather than fallen into: exitPending and
		// exitDenied are the daemon's answer to a scope, and a client that
		// never reached the daemon did not get an answer to report.
		return &exitCodeError{code: exitError, err: fmt.Errorf(
			"join tailnet: gave up after %s: the tailnet did not become usable "+
				"(raise the bound with --join-timeout or MINT_JOIN_TIMEOUT, or set it to 0 to wait indefinitely)",
			budget)}
	}
	return fmt.Errorf("join tailnet: %w", err)
}

// joinUnder runs join under b's bound. The join is a parameter so the bound is
// exercisable without a tailnet: dial passes srv.Up, and a test passes a join
// that never returns.
func joinUnder(b *joinBudget, join func(context.Context) error) error {
	return b.explain(join(b.ctx))
}

// joinTimeoutFlag is --join-timeout. It is a flag.Value rather than a
// DurationVar because its default comes from the environment and that default
// has to be able to fail: a mistyped MINT_JOIN_TIMEOUT that quietly became 30s
// is a bound nobody asked for, imposed on the one person who asked for another.
type joinTimeoutFlag struct {
	d   time.Duration
	err error
}

func (f *joinTimeoutFlag) String() string {
	if f == nil {
		return joinTimeout.String()
	}
	return f.d.String()
}

func (f *joinTimeoutFlag) Set(value string) error {
	d, err := parseJoinTimeout(value)
	if err != nil {
		return err
	}
	// An explicit flag settles the question, including when the environment
	// holds nonsense the caller has just overridden.
	f.d, f.err = d, nil
	return nil
}

// parseJoinTimeout reads a join bound. Empty is the default; zero is no bound;
// anything unparseable is an error rather than a silent fallback, because the
// whole point of setting it is wanting a bound other than the default one.
func parseJoinTimeout(value string) (time.Duration, error) {
	if value == "" {
		return joinTimeout, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, errors.New("not a duration such as 30s or 5m")
	}
	if d < 0 {
		return 0, errors.New("must not be negative; 0 means no bound")
	}
	return d, nil
}

// envJoinTimeout is parseJoinTimeout for MINT_JOIN_TIMEOUT, naming the
// variable so the complaint points at what has to be fixed. The flag package
// names the flag itself.
func envJoinTimeout(value string) (time.Duration, error) {
	d, err := parseJoinTimeout(value)
	if err != nil {
		return 0, fmt.Errorf("MINT_JOIN_TIMEOUT=%q: %w", value, err)
	}
	return d, nil
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
			"pending approval (request %s) — run 'mint approve %s' on the daemon host",
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
			fmt.Fprintln(os.Stderr, "mint: waiting for the tailnet to settle...")
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
	return fs.String("socket", envOr("MINT_SOCKET", filepath.Join(defaultDir("mint"), "admin.sock")),
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
		return errors.New("usage: mint approve <request-id> [--ttl 720h]")
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
		return fmt.Errorf("usage: mint %s <id>", name)
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
	return fmt.Errorf("reach the daemon at %s (is 'mint serve' running on this host?): %w", socket, err)
}

// --- reset ---

func cmdReset(args []string) error {
	// "Clean up everything this host holds" is the case people actually want,
	// so it is the default: a bare `mint reset` covers daemon and client
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
		fs.StringVar(&stateDir, "state-dir", envOr("MINT_STATE_DIR", defaultDir("mint")),
			"daemon state directory")
		fs.StringVar(&socket, "socket", "", "daemon admin socket used to check whether it is running")
	case "client":
		fs.StringVar(&stateDir, "state-dir", envOr("MINT_STATE_DIR", defaultDir("mint-client")),
			"client state directory")
	case "all":
		fs.StringVar(&daemonStateDir, "daemon-state-dir", defaultDir("mint"),
			"daemon state directory")
		fs.StringVar(&clientStateDir, "client-state-dir", defaultDir("mint-client"),
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
