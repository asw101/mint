# 🛟 mint 🌿

*it's a lifesaver.*

Mints short-lived GitHub App tokens for clients on your tailnet, and carries
short-lived consume-once bootstrap secrets between specific tailnet nodes.

The point is that **no credential is exchanged at the application layer.**
Clients present nothing; the daemon asks the tailnet who the caller is. Joining
the tailnet is the enrolment step, and you approve that once, in the Tailscale
console.

The case it is built for: a fresh sandbox, a container, a machine you will throw
away in an hour, getting scoped GitHub access with nothing to install but this
binary and nothing to paste in.

## What you bring

mint is not a service anybody runs for you. Two things are yours:

- **Your own GitHub App**, installed on the accounts and repositories you want
  reachable. mint holds its private key and mints installation tokens from it.
  It does not talk to any App but the one you give it.
- **Your own tailnet.** Tailscale's free tier is enough. The tailnet is the
  authentication: mint asks it who a caller is, and the tailnet's policy file
  says what that class of caller may ever be given.

There is no hosted version and no account to create. If you have both of those,
everything below is about half an hour.

## Install

Download a binary from [releases](https://github.com/asw101/mint/releases) and
put it on `PATH`:

```sh
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
base=https://github.com/asw101/mint/releases/latest/download

curl -fsSLO "$base/mint_${os}_${arch}"
curl -fsSLO "$base/SHA256SUMS"
grep " mint_${os}_${arch}$" SHA256SUMS | shasum -a 256 -c -
install -m 755 "mint_${os}_${arch}" /usr/local/bin/mint
```

Releases carry darwin and linux, amd64 and arm64, plus `SHA256SUMS` and the
systemd unit. Check the sum: this is a binary that will hold your App key.

Or build it: `go install github.com/asw101/mint@latest`.

The binary is the daemon, the client and the admin CLI. Which one it is depends
on the subcommand, so a client machine needs nothing else.

## First run, end to end

The sections below cover each piece; this is the order they go in. Steps 2 and
5 are the ones that catch people — **both** nodes need tagging.

**1.** On the host where the App private key lives, start the daemon.

```console
$ export GH_APP_ID=1234567                      # your App's id
$ export GH_APP_KEY_FILE=~/.config/mint/app.pem
$ mint serve --hostname=mint
minting from installation 89012345 (your-account)
To start this tsnet server ... go to: https://login.tailscale.com/a/...
```

**2.** Visit that URL. Then in the Tailscale console, approve the node and give
it **`tag:mint`**. The daemon logs its tailnet name once it is in:

```console
tailnet node mint.your-tailnet.ts.net. ([100.x.y.z ...])
tailnet mint:8080, admin ~/.config/mint/admin.sock
```

**3.** Add the two grants to your tailnet policy: see
[Full App permissions](#full-app-permissions).

**4.** On the client machine, ask for a token.

```console
$ mint token --repo widget
To start this tsnet server ... go to: https://login.tailscale.com/a/...
```

**5.** Visit that URL too, approve the node, and give it **`tag:agent`**.

**6.** Confirm the daemon sees the client as the grant expects.

```console
$ mint whoami
{
  "grants": [ ... ],
  "node_id": "nXXXXXXXXXXXX",
  "node_name": "mint-client.your-tailnet.ts.net.",
  "tags": ["tag:agent"],
  "user": "tagged-devices"
}
```

`grants` must not be `null`. If it is, the capability is not reaching this node:
see [no mint capability](./docs/acl.md#if-you-get-the-tailnet-policy-grants-no-mint-capability).

**7.** Ask for a token.

```console
$ mint token --repo widget
mint: pending approval (request 14bf7231) ...
```

**8.** Approve it, on the daemon host.

```console
$ mint approve 14bf7231 --ttl 720h
```

**9.** Ask again.

```console
$ mint token --repo widget
ghs_...
```

From then on that scope is silent for that node. A **wider** scope returns to
step 7; a **narrower** one rides in on the approval already granted.

Two messages that are expected rather than wrong:

- **`mint: waiting for the tailnet to settle...`** on a client's first run.
  The node reaches Running before its DNS is usable, so the request retries for
  a few seconds rather than failing.
- **The client is silent apart from its login URL.** Only the daemon logs
  freely.

## Three layers of policy

| Layer | Decides | Changed by |
| --- | --- | --- |
| GitHub App installation | which repos exist at all | you, in GitHub's UI |
| Tailnet ACL capability | the ceiling per client class | you, in the ACL |
| `mint` approvals | automatic vs needs-approval, **per node** | `mint approve` |

The ACL is a hard bound the daemon cannot exceed even if its own approval store
says otherwise. The store is what makes "already approved" mean *this client*
rather than *this kind of client* — tailnet tags are classes, and the store is
per-node.

## Running the daemon

The daemon holds the App private key, so run it where that key lives — not
inside an agent environment.

```sh
export GH_APP_ID=1234567
export GH_APP_KEY_FILE=~/.config/mint/app.pem

mint serve --hostname=mint
```

On first run it joins the tailnet and prints its node name. State — tsnet keys
and `approvals.json` — lives under `--state-dir` (default
`~/.config/mint`).

It joins as a user-owned node, so **tag it `tag:mint` before clients can reach
it** — see [Tag both nodes](#tag-both-nodes).

It listens in two places, and the split is deliberate:

| Surface | Reachable from | Authorized by |
| --- | --- | --- |
| `:8080` on the tailnet | any tailnet node | the caller's ACL capability |
| `admin.sock` | the daemon's own host | filesystem permissions |

Approving is an operator action, so it is not reachable from the tailnet at
all. Dropping access is the one mutation a client can make for itself, because
it only ever takes privilege away — see
[giving up access](./docs/operating.md#giving-up-access).

Plain HTTP is the default and is right here: tailnet traffic is already
WireGuard-encrypted, so TLS adds no confidentiality, only a round trip. `--tls`
serves HTTPS anyway if you want it; see
[docs/operating.md](./docs/operating.md#serving-https).

## Granting a client access

### Tag both nodes

Grants match on tags, and **both ends must be tagged** — `src` is the client,
`dst` is the daemon. The daemon is the one usually missed: it joined by you
visiting a login URL, so it is user-owned and untagged, and a `dst` of
`tag:mint` then matches nothing.

First declare who may own the tags, in the policy file:

```hujson
"tagOwners": {
  "tag:mint": ["autogroup:admin"],
  "tag:agent": ["autogroup:admin"],
},
```

Then, in the Tailscale console under **Machines**, for each node choose
**⋯ → Edit ACL tags**:

| Node | Tag |
| --- | --- |
| the daemon, `mint` | `tag:mint` |
| each client, `mint-client` | `tag:agent` |

`mint whoami` reports the tags the daemon actually sees, which is the quickest
way to confirm both ends before touching grants.

**Tagging changes what a node reports.** Before, `whoami` shows your login and
no `tags` field at all; after, it shows `"user": "tagged-devices"` and the tag.
That flip is how you know the console change took effect:

```jsonc
// before
{ "node_name": "mint-client...", "user": "you@example.com", "grants": null }
// after
{ "node_name": "mint-client...", "user": "tagged-devices",
  "tags": ["tag:agent"], "grants": [ ... ] }
```

Tagged nodes also have no key expiry, so the daemon will not silently drop off
the tailnet in a few months.

### Full App permissions

**Start broad and narrow later.** The App installation already decides which
repositories exist; making the ACL restate that list means editing tailnet
policy every time you add a repository to the App.

```hujson
"grants": [
  { "src": ["tag:agent"], "dst": ["tag:mint"], "ip": ["*"] },
  {
    "src": ["tag:agent"],
    "dst": ["tag:mint"],
    "app": {
      "aaronw.dev/cap/mint": [
        { "repos": ["*"] },
      ],
    },
  },
]
```

The capability deliberately **omits `permissions`**. That means a request
which does not pass `--permission` inherits the GitHub App installation's full
permission set. If the App has `contents:write`, for example,
`mint token --repo widget` requests a token with that permission.

This is not as permissive as it looks: **nothing is minted automatically**,
because each new scope still needs `mint approve` for that specific node. The
ACL says what a class of client *may ever* be given; the approval store says
what it has actually been given.

**Copy the capability name exactly: `aaronw.dev/cap/mint`.** Tailscale requires
custom capabilities to be `<domain>/<path>/<name>`, and mint reads this name and
no other, so it is the right value in your tailnet even though the domain is not
yours. Tailscale does not resolve the domain or check who owns it; it is a
namespace, chosen so that two unrelated applications cannot collide on `mint`.
A near miss here is the most common reason a grant that looks correct denies
everything.

**Two grants are needed, not one.** The first permits the connection; the
second confers the capability. Omit the first and the client cannot reach the
daemon at all, which presents as a connectivity failure rather than a policy
one.

Two other grant shapes exist: one bounding a client class to read-only even
when the App can write, and one for wormhole senders and recipients. Both are in
[docs/acl.md](./docs/acl.md), along with what to do when a grant that looks
correct denies everything.

## Using it from a client

```sh
mint token --repo widget
mint token --repo your-account/widget  # the same thing
```

Both spellings mean the same repository. The API scopes within the
installation's account, so the owner is dropped once it has been checked —
naming a *different* owner is refused rather than quietly reinterpreted.

`--repo` is required. Omitting it is refused rather than queued, because an
approval records the scope it was asked for, and an empty one covers nothing —
the client would be approved and still denied. To ask for the installation's
whole reach, say so:

```sh
mint token --repo '*'
```

That is highly privileged — every repository the App can see, with whatever
permissions the ACL leaves unrestricted — so it is deliberately explicit. It
still has to clear the tailnet ceiling (a grant carrying `"repos": ["*"]`) and
still waits for a human to approve it.

First run joins the tailnet and prints a login URL. Visit it, then in the
console approve the node and **give it `tag:agent`** — see
[Tag both nodes](#tag-both-nodes). Reusing `--state-dir` means later runs
reconnect as the same node without prompting.

`--server` defaults to `http://mint:8080`, so a daemon started with a
different `--hostname` needs it spelled out:

```sh
mint token --server http://mint-lab:8080 --repo widget
```

Then:

- **Scope already approved for this node** → a token, on stdout
- **Scope within the ACL but not yet approved** → `pending approval (request 7c2a)`
- **Scope outside the ACL** → denied, and *not* queued — approving could not
  satisfy it, so the queue never fills with unsatisfiable requests

### Exit codes

`mint token` and `mint wormhole` distinguish the outcomes a caller would
react to differently, so a script need not read the message:

| Exit | Meaning | What a caller should do |
| --- | --- | --- |
| `0` | the command succeeded | use the token, value, or metadata as requested |
| `2` | pending approval | retry once a human has approved |
| `3` | denied by policy | stop; retrying will not help |
| `1` | anything else | read the error; this includes absent or ambiguous wormhole items |

```sh
if token=$(mint token --repo widget 2>/dev/null); then
    use "$token"
else
    case $? in
        2) echo "waiting on approval" ;;
        3) echo "not permitted; check the tailnet policy" >&2; exit 1 ;;
        *) echo "mint unavailable" >&2; exit 1 ;;
    esac
fi
```

### Streams

**stdout carries what you asked for; stderr carries everything about getting
it.** The token, and any `--json` output, go to stdout alone — so
`$(mint token …)` captures exactly the token. Login URLs, the
`waiting for the tailnet to settle` notice, and every error go to stderr. The
daemon logs to stderr too, and never logs a token.

## Wormhole: ephemeral secret handoff

Wormhole is a memory-only mailbox for bootstrap values that should move
directly from a producer into one named tailnet node:

```text
mint wormhole put --to NODE --key KEY [--ttl 10m] [--replace]
mint wormhole get --key KEY [--from NODE]
mint wormhole discard --key KEY [--from NODE]
mint wormhole list [--json]
```

All four commands also accept `--server`, `--hostname`, and `--state-dir`.
`put` reads raw bytes from stdin; there is deliberately no `--value` flag that
would expose a secret in shell history or a process listing. `get` writes only
the raw value to stdout. `list` writes a compact metadata table, or its full
response with `--json`; it never returns values or hashes. Login notices,
acknowledgements, replacement warnings, and errors go to stderr.

An end-to-end service-principal handoff needs no copy and paste:

```sh
# Sender
az ad sp create-for-rbac \
  --name build-agent-provisioner \
  --role Owner \
  --scopes /subscriptions/.../resourceGroups/... \
  --output json |
mint wormhole put \
  --to build-agent \
  --key azure/provisioner \
  --ttl 10m

# Recipient
mint wormhole get \
  --key azure/provisioner |
./bootstrap-from-azure-sp-json
```

The resolution rules when a key has more than one sender, replacement,
lifetime, and what the memory-only design does and does not protect against are
in [docs/wormhole.md](./docs/wormhole.md).

## Managing the tailnet policy

Everything above asks you to edit the tailnet policy file by hand in the admin
console. `mint policy` does it from the command line instead, which matters
because the policy file **is** mint's authorization model: a broker that can
mint tokens but cannot manage the grants that authorize minting is half a tool.

```sh
mint policy fetch -o policy.hujson    # current policy, comments intact
$EDITOR policy.hujson
mint policy diff policy.hujson        # what applying it would change
mint policy apply policy.hujson --yes # replace it
```

`apply` validates against the tailnet, prints a diff, needs `--yes`, and sends
back the version it fetched so a change made in the console meanwhile fails the
write rather than being overwritten. **The daemon never holds the credential
that can do this**: `mint serve` refuses to start with a Tailscale API
credential in its environment. The two OAuth clients this wants, and why they
are two, are in [docs/policy.md](./docs/policy.md).

## Configuration

| Flag | Environment | Default |
| --- | --- | --- |
| `--app-id` | `GH_APP_ID` | — (required for `serve`) |
| `--key` | `GH_APP_KEY_FILE` | — (required for `serve`) |
| `--installation` | `GH_APP_INSTALLATION_ID` | optional; discovered when the App has one |
| `--api` | `GITHUB_API_URL` | `https://api.github.com` |
| `--server` | `MINT_SERVER` | `http://mint:8080` |
| `--state-dir` | `MINT_STATE_DIR` | OS user config directory plus `mint` or `mint-client` |
| `--socket` | `MINT_SOCKET` | `<state-dir>/admin.sock` |
| `--socket-group` | `MINT_SOCKET_GROUP` | — (socket stays `0600`) |
| `--tailnet` | `TS_TAILNET` | `-`, meaning this credential's own tailnet |
| `--secret-file` | — | `~/_/tailscale-oauth`, or `-write` for `policy apply` |
| `--api-key-file` | `TS_API_KEY_FILE` | — (OAuth is preferred) |

`mint` was called `tsapp` until August 2026, and still answers to it while the
rename lands: it reads an existing `~/.config/tsapp` state directory rather than
starting fresh, accepts `TSAPP_`-prefixed variables, and looks for a daemon named
`tsapp` when no `mint` node is on the tailnet. `mint migrate-state` ends that on
a host by renaming the directories, keeping the node identity and the daemon's
approvals. It lives in `compat.go`, and each piece records what has to be true
before it can be deleted.

The daemon also reads every capability name the project has used, merging grants
under all of them, so the policy file and the binaries reading it never have to
change in the same instant. `asw101.dev/cap/tsapp` is what live tailnets grant
today; `asw101.dev/cap/mint` was the name between the rename and the move to a
domain the author owns. `internal/policy/policy.go` is the list, and says when
each entry can go.

## Documentation

The README is the path you walk once. These are what you look up.

| | |
| --- | --- |
| [docs/acl.md](./docs/acl.md) | Every grant shape, and why a correct-looking one denies everything. |
| [docs/wormhole.md](./docs/wormhole.md) | Mailbox semantics: resolution, replacement, limits, threat boundary. |
| [docs/operating.md](./docs/operating.md) | Approving, giving up access, resetting state, running as a service. |
| [docs/policy.md](./docs/policy.md) | Managing the tailnet ACL with `mint policy`, and its two credentials. |
| [init/README.md](./init/README.md) | Installing the systemd unit on Linux, start to finish. |

## Agent skills

Two, both shipped with the project so they stay in step with it:

- [`skills/mint/SKILL.md`](./skills/mint/SKILL.md) tells an agent how to
  authenticate through the broker rather than reaching for a stored token:
  which command to run, how to read the exit code, and when to stop and ask a
  human.
- [`skills/mint-policy/SKILL.md`](./skills/mint-policy/SKILL.md) covers managing
  the tailnet policy file: the two credentials, the fetch-diff-apply loop, and
  the sequence for renaming a capability without locking anyone out.

Symlink them into your agent skills tree rather than copying:

```sh
ln -s ../../mint/skills/mint .agents/skills/mint
ln -s ../../mint/skills/mint-policy .agents/skills/mint-policy
```

Adjust the relative paths to wherever `mint/` sits.

## Development

```sh
just            # list recipes
just check      # gofmt check, vet, and tests
just build      # binary into bin/
just dist       # release binaries for every platform, with checksums
```

`just build` stamps the version from `git describe`, so a binary can say which
release it came from and whether the tree was dirty:

```console
$ mint version
mint v0.6.0
  commit  c2bf8779b920 (clean)
  built   2026-08-08T00:52:55Z
  go      go1.26.5 darwin/arm64
```

A plain `go build` still reports the commit and build time — the toolchain
records those — but cannot name the release.

The tailnet is mocked in tests: `WhoIs` sits behind an `Identifier` interface
and minting behind a `Minter`, so every authorization decision is testable
without joining anything. Keep it that way.

### Releases

Push a `vX.Y.Z` tag. [`.github/workflows/release.yml`](./.github/workflows/release.yml)
builds all four platforms, writes `SHA256SUMS`, attaches the systemd unit, and
publishes the release. It asserts the full asset list before publishing, because
the unit is not build output and a release missing it looks complete.

[`ci.yml`](./.github/workflows/ci.yml) runs gofmt, vet and the race detector on
every push, and cross-compiles every release target.

## Security notes

- **The daemon holds the App key.** It is the most privileged thing here; run
  it where the key belongs and nowhere else.
- **The approvals file is a security boundary.** Anything that can edit
  `approvals.json` can grant itself access, so it is written `0600` in a `0700`
  directory. Do not put it somewhere clients can reach.
- **The admin socket has no authentication** beyond filesystem permissions,
  which is why it is a Unix socket and not a tailnet endpoint.
- **Automatic grants are the ones nobody remembers**, so they are logged as
  carefully as approved ones. Ship the daemon's logs somewhere if the host is
  disposable.
- **This gates lateral movement, not misuse.** A client compromised after
  approval keeps the scope it already had until you revoke it — or until the
  node itself runs `mint drop`, which is auto-accepted precisely because it
  can only take privilege away.
- **The daemon never holds a policy-writing credential**, and refuses to start
  if it finds one. The tailnet policy is what grants mint its authority, so a
  daemon able to rewrite it sits above itself in the trust order.
- **No secret is ever passed as a command-line argument**, by mint or by
  anything the docs here ask you to run. `/proc/<pid>/cmdline` is readable by
  every process of the same user.
- **Tags are classes, not instances.** The ACL cannot say "this session"; the
  per-node approval store is what supplies that, and it only works because
  `WhoIs` reports a stable node ID.

## License

[MIT](./LICENSE).
