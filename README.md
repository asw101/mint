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

```sh
# 1. On the host where the App private key lives
export GH_APP_ID=1234567              # your App's id
export GH_APP_KEY_FILE=~/.config/mint/app.pem
mint serve --hostname=mint
#    minting from installation 89012345 (your-account)
#    To start this tsnet server ... go to: https://login.tailscale.com/a/...
```

**2.** Visit that URL. Then in the Tailscale console, approve the node and give
it **`tag:mint`**. The daemon logs its tailnet name once it is in:

```
tailnet node mint.your-tailnet.ts.net. ([100.x.y.z ...])
tailnet mint:8080, admin ~/.config/mint/admin.sock
```

**3.** Add the two grants to your tailnet policy — see
[Full App permissions](#full-app-permissions).

```sh
# 4. On the client machine
mint token --repo widget
#    To start this tsnet server ... go to: https://login.tailscale.com/a/...
```

**5.** Visit that URL too, approve the node, and give it **`tag:agent`**.

```sh
# 6. Confirm the daemon sees the client as the grant expects
mint whoami
#    "tags": ["tag:agent"], "grants": [ ... ]   <- grants must not be null

# 7. Ask for a token
mint token --repo widget
#    mint: pending approval (request 14bf7231) ...

# 8. Approve it, on the daemon host
mint approve 14bf7231 --ttl 720h

# 9. Ask again
mint token --repo widget
#    ghs_...
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
[Giving up access](#giving-up-access).

**Plain HTTP is the default and is fine here** — tailnet traffic is already
WireGuard-encrypted, so TLS adds no confidentiality, only a round trip.

`--tls` serves HTTPS on `:443` if you want it anyway. There is **no certificate
to supply**: Tailscale issues one for this node's MagicDNS name. It requires
**HTTPS Certificates** enabled for the tailnet (admin console, DNS page), and
the first request after startup can block for thirty seconds or more while
LetsEncrypt issues the certificate — that is not a hang.

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

### Explicit read-only permissions

Use this capability entry instead when a client class should be bounded to
read-only even though the App itself can write:

```hujson
"aaronw.dev/cap/mint": [
  {
    "repos": ["*"],
    "permissions": {"contents": "read"},
  },
],
```

A request that names no permissions resolves to the covering grant's, so
`mint token --repo widget` still works and yields a `contents:read`
token. A request for `contents:write` is denied before it can reach the
approval queue: the tailnet capability is a ceiling that approval cannot
raise.

The one case that cannot be resolved is two grants covering the same
repository with different permissions; name the permissions explicitly there.

The distinction is intentional:

| Capability entry | Omitted `--permission` means |
| --- | --- |
| `{ "repos": ["*"] }` | use the GitHub App installation's permissions |
| `{ "repos": ["*"], "permissions": {"contents": "read"} }` | request `contents:read` |

### Wormhole sender and recipient capabilities

Wormhole extends the same `aaronw.dev/cap/mint` payload. It does not add a
bearer token or a second authentication system:

```hujson
// A trusted sender may target agent-tagged nodes.
{
  "src": ["tag:admin"],
  "dst": ["tag:mint"],
  "app": {
    "aaronw.dev/cap/mint": [{
      "wormhole": {
        "putToTags": ["tag:agent"],
      },
    }],
  },
},

// An agent may list or consume items addressed to its stable node ID.
{
  "src": ["tag:agent"],
  "dst": ["tag:mint"],
  "app": {
    "aaronw.dev/cap/mint": [{
      "wormhole": {
        "get": true,
      },
    }],
  },
},
```

`putToTags` bounds which recipient classes a compromised sender can fill. A
CLI node name is only a lookup convenience: the daemon resolves it against the
tailnet, checks its current tags, and stores its stable node ID. `get` and
`list` derive the recipient exclusively from the caller's `WhoIs` result. They
accept no recipient field, and a request body, query parameter, or header cannot
select another node.

Wormhole delivery never enters the approval queue. Sending an already-created
secret is not the same decision as repeatedly minting a repository-scoped
credential: `put` and `get` must be explicitly present in the ACL capability,
while `discard` needs no grant because it can only reduce exposure.

### If you get "the tailnet policy grants no mint capability"

That error means everything up to authorization worked — the client joined,
reached the daemon, and `WhoIs` identified it. Only the capability is missing.
Run `mint whoami` to see exactly what the daemon sees, then check three
things:

1. **Does `src` match how the node actually presents?** `mint whoami` reports
   `tags` and `user`, and they are mutually exclusive in practice:

   | whoami shows | Match it with |
   | --- | --- |
   | `"user": "tagged-devices"` plus `tags` | the tag, e.g. `"src": ["tag:agent"]` |
   | a real login name, no tags | `"src": ["autogroup:member"]` or that login |

   **A tagged node is not in `autogroup:member`.** That autogroup covers user
   identities, so a grant using it will never match a tagged node no matter how
   permissive it looks. This is the most common way the capability comes back
   empty.

   For a user-owned node, this deliberately permissive grant confirms the path
   works before you tighten it:

   ```hujson
   "grants": [
     { "src": ["autogroup:member"], "dst": ["*"], "ip": ["*"] },
     {
       "src": ["autogroup:member"],
       "dst": ["*"],
       "app": {
         "aaronw.dev/cap/mint": [
           { "repos": ["*"] },
         ],
       },
     },
   ]
   ```

   That is deliberately permissive — use it to confirm the path works, then
   tighten to tags.

2. **Is the policy using the `grants` syntax?** App capabilities cannot be
   expressed in the legacy `acls` array. A tailnet that still uses `acls` needs
   a `grants` block adding alongside it.

3. **Is the capability name exact?** It must be `aaronw.dev/cap/mint`, and
   custom names must have the `<domain>/<path>/<name>` shape.

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

### Giving up access

A client can surrender everything it holds without an operator:

```sh
mint drop
#   agent.example.ts.net dropped 1 approval, 0 pending requests, and 1 wormhole item
mint drop --json
```

The daemon removes that node's approvals **and its outstanding requests** — a
pending request is latent privilege, and leaving it behind would let it be
approved after the node had given up its access. It needs no human because it
can only ever *reduce* what the caller reaches, unlike approving.

It also discards and zeroes every wormhole item addressed to the caller. It
does **not** retract items that caller previously sent to other nodes.

The node dropped is always the caller, taken from the tailnet `WhoIs` lookup.
There is no way to name another one: `drop` sends no node id, and the daemon
would ignore it if it did. Dropping again is a success, not an error — a node
that already holds nothing has what it asked for. Exit `0` on success, `1` if
the daemon could not be reached.

Later requests behave exactly as they did before the node was ever approved:
within the ACL they queue for approval, outside it they are denied.

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

The stored address remains the full tuple `(recipient stable node ID, sender
stable node ID, key)`. When `--from` is omitted, the daemon resolves the key
only if exactly one sender has an item for the caller. No match returns the same
absent response as before. Two or more senders return `409`, name every
candidate sender, and consume nothing; retry with an explicit `--from` only
after deciding which sender is expected. This fails loud rather than letting
another authorized sender substitute a value under a familiar key.

Pass `--from NODE` whenever the expected sender is known and certainty matters.
That precise form resolves the node name to its stable ID and consumes only the
full tuple. A successful `get` atomically removes the item before writing the
response. A second get is absent.

### Discovering addressed items

`mint wormhole list` shows every live item addressed to the calling node:
sender stable ID and name, key, creation and expiry times, and value size in
bytes. It never returns a value, any part of one, or a value hash. Empty is a
successful result and says plainly that no wormhole items are addressed to the
node.

The recipient always comes from the caller's tailnet `WhoIs` identity; body,
query, and header fields cannot select another node. Listing requires the same
`wormhole.get` capability as consuming. Expired items are pruned and omitted.

### Replacement is explicit

One live item may occupy a tuple. A plain retry while it is occupied returns
`409` and exit `1`; it never silently overwrites the value a recipient is
waiting for.

When the credential was deliberately regenerated, `put --replace` atomically
installs the new value and zeroes the old buffer under the same lock. It can
replace only the caller's own tuple, because the sender stable ID comes from
`WhoIs`. The response reports `"replaced": true`, the CLI warns on stderr that
an unconsumed value was displaced, and the audit log records a distinct
replacement event with the displaced opaque ID.

This is a deliberate refinement of the original reject-overwrite design.
Credential regeneration needs an expressible, bounded operation; forcing a new
key every time would make the key cease to identify the intended handoff.
Keeping replacement explicit preserves the protection against retry loops and
confused senders, while the warning makes a stalled or unavailable recipient
visible instead of treating replacement as an ordinary success. Replacing an
expired or consumed item is an ordinary put and reports `"replaced": false`.

### Limits, lifetime, and failure semantics

| Property | v1 |
| --- | --- |
| Key | 1–128 bytes, `[A-Za-z0-9._/-]` |
| Value | arbitrary bytes, at most 256 KiB decoded |
| TTL | 10 minutes by default, 1 hour maximum |
| Consumption | exactly once |
| Per recipient | 16 live items |
| Per sender | 32 live items |
| Global | 256 live items and 32 MiB |

Expired, consumed, and never-created items all return the same `404`/exit `1`
response. Listing can reveal that a live item uses a different sender or key,
but there is no peek endpoint and list metadata never includes value material.

| HTTP | CLI exit | Meaning |
| --- | ---: | --- |
| `200` / `201` | `0` | put, consume, discard, or list succeeded |
| `202` | `2` | reserved for future approval; unused in v1 |
| `403` | `3` | caller capability, recipient tag, or recipient policy denied |
| `400`, `404`, `409`, `413`, `429`, `5xx` | `1` | invalid, absent, ambiguous or occupied, too large, quota, or server failure |

A transport error during `get` is ambiguous: the daemon may have removed the
item before the response was lost. The CLI makes exactly one request, says that
the item may already have been consumed, and never retries automatically.
Reissue the source credential rather than trying to restore a consumed mailbox
item.

`discard` follows the same optional-`--from` resolution rules and removes the
caller's tuple without returning its value. Use it when a handoff is cancelled.

### Memory and threat boundary

Items live only in a mutex-protected map. They are never written to
`approvals.json`; restart intentionally loses them. Expired items are removed
both lazily and by a periodic sweep. Consume, discard, expiry, replacement,
shutdown, and `drop` overwrite the daemon-owned value buffer before releasing
it.

That is best-effort retention reduction, not a hard zeroization guarantee. Go,
JSON/base64 handling, kernel buffers, swap, core dumps, the sender, and the
receiving program may retain copies. Disable core dumps and avoid swap where
reasonable. Revoking the actual credential remains the issuer's job.

Tailnet WireGuard is the v1 transport confidentiality layer, matching mint's
existing plain-HTTP listener. The daemon sees plaintext. A compromised daemon
can read or alter live values and peer resolution; a compromised endpoint can
read values available to that node. Wormhole v1 does not claim end-to-end
encryption, durable delivery, restart recovery, leases, acknowledgements,
multi-consume, sender retraction, rotation, or cloud-specific parsing.

Audit logs contain event type, opaque item ID, sender and recipient stable IDs
and names, expiry, and result. They never contain a value, base64 payload,
request or response body, value hash, or key.

## Approving

Admin commands talk to the daemon over its Unix socket, so they run **on the
daemon's host** — not from a client. If the daemon uses a non-default
`--state-dir`, point them at its socket:

```sh
export MINT_SOCKET=/path/to/state/admin.sock
```

Otherwise you get `reach the daemon at ... (is 'mint serve' running on this
host?)`, which means the socket path, not necessarily the daemon.

From the daemon's host:

```sh
mint pending
mint approve 7c2a --ttl 720h
mint approvals
mint revoke <approval-id>
```

An approval covers **narrower later requests**: approving
`{one,two}: contents=write` silently covers a later `{one}: contents=read`. It
does not cover wider ones — asking for a repo you have not approved for that
node needs you again. That is the property worth having: **lateral movement
costs a human, routine work does not.**

`--ttl` is optional; without it the approval does not expire. Expired
approvals are pruned at startup.

### Approving without root

By default the socket is `0600`, so only the service user and root reach it,
and every admin command needs `sudo`. `--socket-group` widens it to `0660`
owned by a named group:

```sh
mint serve --socket-group=mint
#   tailnet mint:8080, admin /var/lib/mint/admin.sock (group mint)
```

The **directory** must be traversable by that group too, or the wider socket
changes nothing — the walk fails before the socket is consulted. Under systemd
that is `StateDirectoryMode=0750`; see [`init/README.md`](./init/README.md).

Be deliberate about who is in the group. **The socket has no authentication
beyond these bits**, so membership is the power to approve any scope the
tailnet policy allows — for practical purposes, sudo. Grant it to operators,
not to service accounts, and not to anything an agent runs as.

Naming a group that does not exist is a startup failure rather than a quiet
fallback to `0600`, so a typo cannot leave you thinking you have less access
than you do — or more.

## Resetting local state

Reset local tsnet identities and approvals before retiring or moving an
installation:

```sh
mint reset --yes           # all local state: daemon and client alike
```

A target narrows it when only one is in the way:

```sh
mint reset daemon --yes
mint reset client --yes
```

Without `--yes` it names what it would remove and stops, so a bare
`mint reset` is the dry run.

The daemon must be stopped first. A target-specific `--state-dir` handles a
custom daemon or client location; the untargeted form uses
`--daemon-state-dir` and `--client-state-dir`, because one path cannot describe
both. Pass `--socket` when the daemon used a custom admin socket so `reset` can
verify it is stopped.

**Under systemd the daemon's state is not where `reset` looks by default.** The
unit sets `--state-dir=/var/lib/mint`, while `reset` defaults to the config
directory of whoever runs it, so an unqualified reset quietly clears nothing
that matters:

```sh
sudo systemctl stop mint
sudo mint reset daemon --state-dir /var/lib/mint --yes
```

This is deliberately destructive: resetting the daemon removes its tsnet
identity and every pending request and approval; resetting the client removes
its tsnet identity. The command does **not** unregister those nodes from
Tailscale, so remove them separately in the Tailscale admin console.

## One installation per daemon

A GitHub App installation belongs to **one account**, and an installation token
cannot span accounts. `mint serve` resolves its installation once at startup
and mints from that, so one daemon serves one account.

Adding repositories to that account costs nothing: install the App on them and,
with `"repos": ["*"]`, they are immediately within the ceiling — each still
needs one `mint approve` per node. **No policy edit is required**, which is
why the ACL should not restate the repository list.

Reaching a repository under a *different* account needs the App installed
there too, which creates a second installation. Today that means a second
daemon. A request naming an owner this installation is not for is refused
rather than silently reinterpreted, so the failure is loud:

```
repository "otherorg/thing" names owner "otherorg", but this installation is for "your-account"
```

Supporting several accounts from one daemon would mean resolving the
installation per request from the owner, via
`GET /repos/{owner}/{repo}/installation`, instead of once at startup. Worth
doing when it is actually needed; it also makes the owner meaningful for
routing rather than only for checking.

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

`apply` sends back the version it fetched, so an edit made in the console
meanwhile fails the write rather than being silently overwritten. It validates
against the tailnet first, prints the diff, and refuses a policy that grants no
mint capability at all, which is the shape of an accidental lockout.

The `tailscale` CLI cannot do any of this: it has no ACL or policy subcommand,
and `syspolicy` diagnoses local MDM configuration rather than the tailnet. This
is an API job.

### Two credentials, not one

The credential that can rewrite the policy sits **above** mint in the trust
order. Something able to change the grants that authorize mint can grant itself
anything the tailnet can express, so it is kept out of the daemon entirely.

Create two OAuth clients in the Tailscale console, under Settings → OAuth
clients:

| Client | Scope | Used by | Secret file |
| --- | --- | --- | --- |
| Read | `policy_file:read` | `fetch`, `diff`, `validate` | `~/_/tailscale-oauth` |
| Write | `policy_file` | `apply` | `~/_/tailscale-oauth-write` |

Both 0600; mint refuses to read a secret file other users can. Because the
commands read different files by default, the ones you run constantly hold a
credential that *cannot* write the policy. That is a capability rather than a
promise.

**`mint serve` refuses to start** if it finds a Tailscale API credential in its
environment. The daemon is bound by the policy; it does not get to edit it.

**No mint flag takes a secret as its value.** Secrets come from files, or stdin
via `--secret-file -`. The exchange documented elsewhere as
`curl -d "client_secret=$SECRET"` publishes the secret to every process running
as the same user through `/proc/<pid>/cmdline`; mint does the OAuth exchange
in-process so it never reaches a command line.

A `tskey-api-…` access token works too, via `--api-key-file`. It carries its
creator's full permissions and expires after about ninety days, so use it to
create the two OAuth clients and then stop.

[`skills/mint-policy/SKILL.md`](./skills/mint-policy/SKILL.md) is the same thing
written for an agent, including how to rename a capability without locking the
tailnet out.

## Running as a service

[`init/mint.service`](./init/mint.service) runs the daemon under systemd as
an unprivileged user, with the App key supplied by `LoadCredential` rather than
left readable on disk. See [`init/README.md`](./init/README.md) for install,
first start, and the one hardening setting that will otherwise stop it booting.

Linux only — macOS uses launchd, and there is no plist here yet.

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

```
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
