# Operating the daemon

Approving scopes, giving access up, throwing state away, and running mint as a
service. Day-two work: none of it is needed to get a first token.

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

```console
$ mint serve --socket-group=mint
tailnet mint:8080, admin /var/lib/mint/admin.sock (group mint)
```

The **directory** must be traversable by that group too, or the wider socket
changes nothing — the walk fails before the socket is consulted. Under systemd
that is `StateDirectoryMode=0750`; see [`init/README.md`](../init/README.md).

Be deliberate about who is in the group. **The socket has no authentication
beyond these bits**, so membership is the power to approve any scope the
tailnet policy allows — for practical purposes, sudo. Grant it to operators,
not to service accounts, and not to anything an agent runs as.

Naming a group that does not exist is a startup failure rather than a quiet
fallback to `0600`, so a typo cannot leave you thinking you have less access
than you do — or more.

## Serving HTTPS

**Plain HTTP is the default and is fine here** — tailnet traffic is already
WireGuard-encrypted, so TLS adds no confidentiality, only a round trip.

`--tls` serves HTTPS on `:443` if you want it anyway. There is **no certificate
to supply**: Tailscale issues one for this node's MagicDNS name. It requires
**HTTPS Certificates** enabled for the tailnet (admin console, DNS page), and
the first request after startup can block for thirty seconds or more while
LetsEncrypt issues the certificate — that is not a hang.

## Giving up access

A client can surrender everything it holds without an operator:

```console
$ mint drop
agent.example.ts.net dropped 1 approval, 0 pending requests, and 1 wormhole item
```

`mint drop --json` prints the same as an object.

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

```console
repository "otherorg/thing" names owner "otherorg", but this installation is for "your-account"
```

Supporting several accounts from one daemon would mean resolving the
installation per request from the owner, via
`GET /repos/{owner}/{repo}/installation`, instead of once at startup. Worth
doing when it is actually needed; it also makes the owner meaningful for
routing rather than only for checking.

## Running as a service

[`init/mint.service`](../init/mint.service) runs the daemon under systemd as
an unprivileged user, with the App key supplied by `LoadCredential` rather than
left readable on disk. See [`init/README.md`](../init/README.md) for install,
first start, and the one hardening setting that will otherwise stop it booting.

Linux only — macOS uses launchd, and there is no plist here yet.
