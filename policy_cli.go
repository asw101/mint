package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/asw101/mint/internal/policy"
	"github.com/asw101/mint/internal/tspolicy"
)

const policyUsage = `mint policy manages the tailnet policy file that authorizes mint itself.

Usage:
  mint policy fetch [-o FILE]      print the tailnet's current policy file
  mint policy diff FILE            show what applying FILE would change
  mint policy validate FILE        ask Tailscale whether FILE would be accepted
  mint policy apply FILE [--yes]   replace the policy file with FILE

flags:
  --tailnet NAME       tailnet to act on (default -, this credential's own)
  --client-id ID       OAuth client id; read from the secret when it is a
                       tskey-client- value (env TS_OAUTH_CLIENT_ID)
  --secret-file PATH   file holding the OAuth client secret, mode 0600. "-"
                       reads stdin. Defaults to ~/_/tailscale-oauth for the
                       read commands and ~/_/tailscale-oauth-write for apply
  --api-key-file PATH  file holding a tskey-api- access token instead, for
                       bootstrapping before an OAuth client exists
  --api URL            Tailscale API base URL
  --force              apply a policy that grants no mint capability

Credentials, and why apply reads a different file
-------------------------------------------------
Use two OAuth clients, not one: policy_file:read for fetch, diff and validate,
and policy_file for apply. The read commands run constantly and cannot damage
anything; apply is deliberate and rare. Because the default secret file differs
per command, the routine paths do not merely decline to write the policy, they
hold a credential that cannot.

A tskey-api- access token carries its creator's full permissions and expires
after about ninety days. Use it to create the OAuth clients, then stop.

There is deliberately no flag that takes a secret as its value. A secret passed
as an argument is readable from /proc/<pid>/cmdline by anything running as the
same user, which is how a carefully delivered credential leaks on arrival.

The daemon never holds any of this. 'mint serve' refuses to start with a
Tailscale API credential in its environment: a broker that can rewrite the
grants authorizing it can grant itself anything the tailnet can express.
`

// policySecretFile and policyWriteSecretFile are the default locations, under
// the ~/_ directory this estate uses for delivered secrets.
const (
	policySecretFile      = "tailscale-oauth"
	policyWriteSecretFile = "tailscale-oauth-write"
)

func cmdPolicy(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, policyUsage)
		return errors.New("usage: mint policy <fetch|diff|validate|apply>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		fmt.Print(policyUsage)
		return nil
	case "fetch", "diff", "validate", "apply":
	default:
		return fmt.Errorf("unknown policy command %q (try 'mint policy help')", sub)
	}

	fs := flag.NewFlagSet("policy "+sub, flag.ContinueOnError)
	tailnet := fs.String("tailnet", envOr("TS_TAILNET", tspolicy.DefaultTailnet), "tailnet to act on")
	clientID := fs.String("client-id", os.Getenv("TS_OAUTH_CLIENT_ID"), "OAuth client id")
	secretFile := fs.String("secret-file", "", "file holding the OAuth client secret")
	apiKeyFile := fs.String("api-key-file", os.Getenv("TS_API_KEY_FILE"), "file holding a tskey-api- access token")
	apiURL := fs.String("api", envOr("TS_API_URL", tspolicy.DefaultBaseURL), "Tailscale API base URL")
	out := fs.String("o", "", "write the fetched policy here instead of stdout")
	yes := fs.Bool("yes", false, "apply without confirming")
	force := fs.Bool("force", false, "apply a policy that grants no mint capability")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	if *secretFile == "" {
		*secretFile = defaultSecretPath(sub)
	}
	cred, err := policyCredential(*clientID, *secretFile, *apiKeyFile)
	if err != nil {
		return err
	}
	client := &tspolicy.Client{Cred: cred, Tailnet: *tailnet, BaseURL: *apiURL}
	ctx := context.Background()

	switch sub {
	case "fetch":
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		return policyFetch(ctx, client, *out)
	case "diff":
		path, err := onePath(fs)
		if err != nil {
			return err
		}
		return policyDiff(ctx, client, path)
	case "validate":
		path, err := onePath(fs)
		if err != nil {
			return err
		}
		return policyValidate(ctx, client, path)
	case "apply":
		path, err := onePath(fs)
		if err != nil {
			return err
		}
		return policyApply(ctx, client, path, *yes, *force)
	}
	return nil
}

func onePath(fs *flag.FlagSet) (string, error) {
	switch fs.NArg() {
	case 0:
		return "", errors.New("name the policy file to read, or - for stdin")
	case 1:
		return fs.Arg(0), nil
	default:
		return "", fmt.Errorf("unexpected argument %q", fs.Arg(1))
	}
}

// defaultSecretPath is where each command looks for its credential. Apply
// reads a different file from everything else, which is the two-client model
// made concrete: the routine commands cannot reach the writing credential
// unless somebody deliberately points them at it.
func defaultSecretPath(sub string) string {
	name := policySecretFile
	if sub == "apply" {
		name = policyWriteSecretFile
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return name
	}
	return filepath.Join(home, "_", name)
}

func policyCredential(clientID, secretFile, apiKeyFile string) (tspolicy.Credential, error) {
	// An API key is the bootstrap, so it is only used when explicitly named.
	if apiKeyFile != "" {
		key, err := tspolicy.ReadSecretFile(apiKeyFile)
		if err != nil {
			return nil, err
		}
		return &tspolicy.APIKey{Key: key}, nil
	}
	secret, err := tspolicy.ReadSecretFile(secretFile)
	if err != nil {
		if tspolicy.IsNotExist(err) {
			return nil, fmt.Errorf("no credential at %s: create an OAuth client in the Tailscale console and write its secret there with mode 0600 (or pass --api-key-file to bootstrap)", secretFile)
		}
		return nil, err
	}
	// BaseURL is left empty on purpose, so the credential exchange always goes
	// to the real Tailscale API. --api and TS_API_URL redirect the policy calls
	// (useful against a stub) but must not be able to redirect where the client
	// secret is sent: an environment variable that can exfiltrate a credential
	// is a worse hole than the one the flag exists to fill.
	return &tspolicy.OAuthClient{ID: clientID, Secret: secret}, nil
}

func policyFetch(ctx context.Context, client *tspolicy.Client, out string) error {
	current, err := client.Fetch(ctx)
	if err != nil {
		return err
	}
	if out == "" {
		_, err := os.Stdout.Write(current.Body)
		return err
	}
	// The policy file is not a secret, but it describes the whole tailnet's
	// authorization, so it is not something to leave world-readable either.
	if err := os.WriteFile(out, current.Body, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "mint: wrote %s (version %s)\n", out, current.ETag)
	return nil
}

func policyDiff(ctx context.Context, client *tspolicy.Client, path string) error {
	proposed, err := readPolicyFile(path)
	if err != nil {
		return err
	}
	current, err := client.Fetch(ctx)
	if err != nil {
		return err
	}
	diff := tspolicy.Unified("tailnet", path, current.Body, proposed)
	if diff == "" {
		fmt.Fprintln(os.Stderr, "mint: no change")
		return nil
	}
	fmt.Print(diff)
	return nil
}

func policyValidate(ctx context.Context, client *tspolicy.Client, path string) error {
	proposed, err := readPolicyFile(path)
	if err != nil {
		return err
	}
	if err := client.Validate(ctx, proposed); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "mint: policy is valid")
	return nil
}

func policyApply(ctx context.Context, client *tspolicy.Client, path string, yes, force bool) error {
	proposed, err := readPolicyFile(path)
	if err != nil {
		return err
	}
	current, err := client.Fetch(ctx)
	if err != nil {
		return err
	}

	diff := tspolicy.Unified("tailnet", path, current.Body, proposed)
	if diff == "" {
		fmt.Fprintln(os.Stderr, "mint: no change; nothing to apply")
		return nil
	}

	// Removing mint's own capability is how a rename locks every client out,
	// and it is a change that reads as innocuous in a large diff. The old name
	// counts too: during the rename the policy legitimately grants one, the
	// other, or both.
	grantsMint := tspolicy.GrantsCapability(proposed, policy.CapabilityName)
	for _, name := range policy.LegacyCapabilityNames {
		grantsMint = grantsMint || tspolicy.GrantsCapability(proposed, name)
	}
	if !grantsMint && !force {
		return fmt.Errorf("this policy grants none of %s, so every mint client would be denied; rerun with --force if that is intended",
			strings.Join(append([]string{policy.CapabilityName}, policy.LegacyCapabilityNames...), ", "))
	}

	if err := client.Validate(ctx, proposed); err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, diff)
	if !yes {
		return errors.New("this would replace the tailnet policy file; rerun with --yes")
	}
	if err := client.Set(ctx, proposed, current.ETag); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "mint: applied")
	return nil
}

func readPolicyFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// --- the daemon holds none of this ---

// tailscaleAPIEnv are the variables that would hand a process a credential for
// the tailnet's own API.
var tailscaleAPIEnv = []string{
	"TS_API_KEY",
	"TS_API_KEY_FILE",
	"TS_OAUTH_CLIENT_SECRET",
	"TAILSCALE_API_KEY",
	"TAILSCALE_OAUTH_CLIENT_SECRET",
}

// refuseIfPolicyCredentialPresent stops `mint serve` from starting when its
// environment carries a credential for the Tailscale API.
//
// The tailnet policy file is what grants mint its authority. A daemon holding a
// credential that can rewrite it could grant itself anything the tailnet can
// express, which puts it above itself in the trust order. Managing the policy
// belongs to the operator commands in this same binary, run deliberately with
// their own credentials; the daemon's job is to be bound by the result.
//
// This is a capability check rather than a rule in a document, for the same
// reason the read and write commands read different files: a restraint that
// only exists as an instruction is one nobody can verify.
func refuseIfPolicyCredentialPresent(lookup func(string) (string, bool)) error {
	for _, key := range tailscaleAPIEnv {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return fmt.Errorf("%s is set: the daemon must not hold a credential that can rewrite the tailnet policy it is bound by. Unset it, and manage the policy with 'mint policy' as an operator", key)
		}
	}
	return nil
}
