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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tailscale.com/tsnet"

	"github.com/asw101/tsapp/internal/app"
	"github.com/asw101/tsapp/internal/policy"
	"github.com/asw101/tsapp/internal/server"
)

const usage = `tsapp mints GitHub App tokens for tailnet clients.

Usage:
  tsapp serve [flags]              run the daemon
  tsapp token [flags]              ask the daemon for a token
  tsapp whoami [flags]             show what the daemon sees you as

  tsapp pending                    list requests awaiting approval
  tsapp approvals                  list current approvals
  tsapp approve <id> [--ttl 30d]   approve a pending request
  tsapp deny <id>                  drop a pending request
  tsapp revoke <id>                revoke an approval

serve flags:
  --hostname NAME     tailnet name to claim         (default tsapp)
  --state-dir PATH    tsnet state and approvals     (default ~/.config/tsapp)
  --socket PATH       admin socket                  (default <state-dir>/admin.sock)
  --port N            tailnet listen port           (default 8080)
  --tls               serve HTTPS instead of HTTP over the tailnet
  --app-id ID         GitHub App ID                 (env GH_APP_ID)
  --key PATH          App private key PEM           (env GH_APP_KEY_FILE)
  --installation ID   installation to mint from     (env GH_APP_INSTALLATION_ID)
                      optional; discovered when the App has exactly one
  --api URL           GitHub API base URL           (env GITHUB_API_URL)

token flags:
  --server URL        daemon address                (default http://tsapp:8080)
  --repo NAME         repository, repeatable and comma-separated
  --permission k=v    narrow a permission, repeatable
  --hostname NAME     tailnet name for this client  (default tsapp-client)
  --state-dir PATH    tsnet state for this client   (default ~/.config/tsapp-client)
  --json              print the full response

Clients join the tailnet on first run and print a login URL. Approve the node
in the Tailscale console, give it a tag, and grant it the tsapp capability;
after that it asks for scopes and this daemon decides.

Admin commands talk to the daemon over its Unix socket, so they work only from
the host it runs on. That is deliberate: approving is an operator action, not
something a tailnet client can reach.
`

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tsapp: "+err.Error())
		os.Exit(1)
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
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try 'tsapp help')", args[0])
	}
}

// --- serve ---

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	hostname := fs.String("hostname", "tsapp", "tailnet name to claim")
	stateDir := fs.String("state-dir", defaultDir("tsapp"), "tsnet state and approvals")
	socket := fs.String("socket", "", "admin socket path")
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

	signer, err := app.LoadPEMSigner(*keyPath)
	if err != nil {
		return err
	}
	gh := &app.Client{AppID: *appID, Signer: signer, BaseURL: *apiURL, UserAgent: "tsapp"}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	installationID, err := resolveInstallation(ctx, gh, *installation)
	if err != nil {
		return err
	}
	log.Printf("minting from installation %d", installationID)

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
		Engine: &policy.Engine{Store: store},
		Store:  store,
		Who:    localClient,
		Minter: &githubMinter{client: gh, installationID: installationID},
		Logger: log.Default(),
	}

	var tailnetListener net.Listener
	addr := fmt.Sprintf(":%d", *port)
	if *useTLS {
		tailnetListener, err = srv.ListenTLS("tcp", ":443")
		addr = ":443"
	} else {
		// Plain HTTP is safe here: everything on the tailnet is already
		// WireGuard-encrypted, and this avoids the LetsEncrypt round trip.
		tailnetListener, err = srv.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("listen on tailnet: %w", err)
	}
	defer tailnetListener.Close()

	adminListener, err := listenUnix(*socket)
	if err != nil {
		return err
	}
	defer adminListener.Close()

	log.Printf("tailnet %s%s, admin %s", *hostname, addr, *socket)

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

// listenUnix binds the admin socket, replacing a stale one left by a crash.
func listenUnix(path string) (net.Listener, error) {
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
	// Filesystem permissions are the only thing guarding the admin surface.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("restrict admin socket: %w", err)
	}
	return ln, nil
}

type githubMinter struct {
	client         *app.Client
	installationID int64
}

func (m *githubMinter) Mint(ctx context.Context, scope policy.Scope) (*app.Token, error) {
	return m.client.CreateToken(ctx, m.installationID, app.TokenRequest{
		Repositories: scope.Normalize().Repos,
		Permissions:  scope.Permissions,
	})
}

func resolveInstallation(ctx context.Context, client *app.Client, explicit int64) (int64, error) {
	if explicit != 0 {
		return explicit, nil
	}
	installations, err := client.Installations(ctx)
	if err != nil {
		return 0, err
	}
	switch len(installations) {
	case 0:
		return 0, errors.New("app has no installations; install it on an account first")
	case 1:
		return installations[0].ID, nil
	default:
		var b strings.Builder
		b.WriteString("app has multiple installations; pass --installation:\n")
		for _, in := range installations {
			fmt.Fprintf(&b, "  %d\t%s\n", in.ID, in.Account.Login)
		}
		return 0, errors.New(strings.TrimRight(b.String(), "\n"))
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
// tailnet suffix from this node's own DNS name. MagicDNS does not resolve bare
// short names, so "http://tsapp:8080" would otherwise fail with "no such host"
// even though the peer is right there.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(cf.server, "/")+"/v1/token", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
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

	case http.StatusAccepted:
		var status server.StatusResponse
		_ = json.NewDecoder(resp.Body).Decode(&status)
		return fmt.Errorf("pending approval (request %s) — run 'tsapp approve %s' on the daemon host",
			status.RequestID, status.RequestID)

	default:
		var status server.StatusResponse
		_ = json.NewDecoder(resp.Body).Decode(&status)
		if status.Reason != "" {
			return fmt.Errorf("%s: %s", status.Status, status.Reason)
		}
		return fmt.Errorf("server returned %s", resp.Status)
	}
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

	resp, err := httpClient.Get(strings.TrimSuffix(cf.server, "/") + "/v1/whoami")
	if err != nil {
		return fmt.Errorf("reach %s: %w", cf.server, err)
	}
	defer resp.Body.Close()
	return copyJSON(resp)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: tsapp approve <request-id> [--ttl 720h]")
	}
	body, _ := json.Marshal(map[string]string{"id": fs.Arg(0), "ttl": *ttl})
	return adminPost(*socket, "/v1/approve", body)
}

func cmdAdminByID(args []string, name, path string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	socket := adminSocketFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: tsapp %s <id>", name)
	}
	body, _ := json.Marshal(map[string]string{"id": fs.Arg(0)})
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
