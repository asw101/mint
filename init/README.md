# Running mint under systemd

`mint.service` runs the daemon as an unprivileged system user, with the App
private key supplied by systemd rather than left readable on disk.

This is for a **Linux** host. macOS uses launchd, and there is no plist here
yet.

## Install

```sh
# 1. The binary
sudo install -m 0755 bin/mint /usr/local/bin/mint

# 2. A service user with no home and no shell
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mint

# 3. Configuration, readable by the service and nobody else
sudo install -d -m 0750 -o root -g mint /etc/mint
sudo install -m 0640 -o root -g mint /path/to/app.pem /etc/mint/app.pem
printf 'GH_APP_ID=1234567\n' | sudo tee /etc/mint/env >/dev/null
sudo chmod 0640 /etc/mint/env && sudo chgrp mint /etc/mint/env

# 4. The unit
sudo install -m 0644 init/mint.service /etc/systemd/system/mint.service
sudo systemctl daemon-reload
sudo systemctl enable --now mint.service
```

## Authenticating the node

The node must be authenticated **once**. After that its identity is in
`/var/lib/mint/tsnet/tailscaled.state` and it reconnects on its own; the auth
key is not reused, and is ignored entirely unless `TSNET_FORCE_LOGIN=1`.

There are two ways, and for a service the first is better.

### With an auth key (recommended)

A **tagged, pre-approved** key removes every console step: the node comes up
already carrying its tag, so there is nothing to approve and nothing to tag by
hand — which also means the daemon is usable the moment systemd starts it,
rather than when someone next reads the journal.

In the Tailscale console, **Settings → Keys → Generate auth key**:

| Setting | Value |
| --- | --- |
| Reusable | no — one daemon, one key |
| Ephemeral | **no** — an ephemeral node is removed when it disconnects |
| Pre-approved | yes, if device approval is on for the tailnet |
| Tags | **`tag:mint`** |

Then add it to the environment file and restart:

```sh
printf 'TS_AUTHKEY=tskey-auth-...\n' | sudo tee -a /etc/mint/env >/dev/null
sudo systemctl restart mint
```

tsnet reads `TS_AUTHKEY` from the environment at first start. Once the node is
enrolled the value is dead weight — **remove it from the file afterwards**,
since an unused auth key in a config file is a credential you are not thinking
about. Keys expire on their own (90 days by default), but that is a backstop,
not a plan.

Ephemeral is worth being deliberate about: it is right for short-lived agent
clients that should disappear, and wrong for a daemon, which would vanish from
your tailnet on every restart and take its ACL tag with it.

### Interactively

Leave `TS_AUTHKEY` unset and the daemon waits, printing a URL. Watch for it:

```sh
sudo journalctl -u mint -f
```

```
minting from installation 89012345 (asw101)
tsnet running state path /var/lib/mint/tsnet/tailscaled.state
To start this tsnet server ... go to: https://login.tailscale.com/a/...
```

Visit it, then in the Tailscale console approve the node and give it
**`tag:mint`** by hand. The unit claims the hostname `mint` (from `%p`), so
clients need no `--server` override.

It logs its tailnet name once it is in:

```
tailnet node mint.your-tailnet.ts.net. ([100.x.y.z ...])
tailnet mint:8080, admin /var/lib/mint/admin.sock
```

**Check that name.** The unit asks for the hostname `mint`, but Tailscale
appends a suffix if something already holds it — a previous daemon, or a stale
node you have not removed — and you get `mint-1`. Clients default to
`http://mint:8080`, so they would then reach the *other* node:

```
tailnet node mint-1.your-tailnet.ts.net.   <- not what clients will dial
```

Remove the stale node from the console and restart to reclaim the name, or
point clients at the real one with `--server http://mint-1:8080`. The name is
fixed at registration, so restarting alone will not reclaim it.

`Restart=on-failure` means it keeps retrying, so an unauthenticated daemon is
not a failed one — it just sits there. Check `systemctl show mint -p NRestarts`
if you suspect a loop.

## Approving

The admin socket is at `/var/lib/mint/admin.sock`, mode `0600` inside a `0700`
directory, so it is reachable by **root or the `mint` user only**:

```sh
sudo MINT_SOCKET=/var/lib/mint/admin.sock mint pending
sudo MINT_SOCKET=/var/lib/mint/admin.sock mint approve 7c2a --ttl 720h
```

An ordinary user gets `permission denied` from the directory, before the socket
is even consulted. That is the intended boundary: approving is an operator
action.

**The socket does not exist until the node has authenticated.** `serve` joins
the tailnet before binding it, so until you visit the login URL every admin
command reports `is 'mint serve' running on this host?` even though it is.

### Dropping the MINT_SOCKET prefix

The unit runs with `--state-dir=/var/lib/mint`, so the socket lands there,
while the CLI looks in its own default state directory. Symlinking one to the
other means admin commands need no environment variable:

```sh
sudo install -d -m 0700 /root/.config/mint
sudo ln -sfn /var/lib/mint/admin.sock /root/.config/mint/admin.sock

sudo mint pending          # no MINT_SOCKET
```

This changes no permissions — root reached the socket already. Note the
symlink dangles while the daemon is down, and the "is `mint serve` running"
error then names the *symlink* path rather than the real one.

### Dropping the sudo as well

`--socket-group` widens the socket from `0600` to `0660` owned by a group, so
its members approve as themselves. Both halves are needed — a group-writable
socket inside a `0700` directory is still unreachable, because the directory
walk fails first:

```ini
# /etc/systemd/system/mint.service.d/10-admin-group.conf
[Service]
ExecStart=
ExecStart=/usr/local/bin/mint serve \
    --hostname=%p \
    --state-dir=%S/%p \
    --key=%d/app.pem \
    --socket-group=mint

StateDirectoryMode=0750
```

The empty `ExecStart=` is required: without it systemd runs a second command
alongside the unit's original rather than replacing it.

```sh
sudo systemctl daemon-reload && sudo systemctl restart mint
sudo usermod -aG mint <operator>
```

Then each operator symlinks the socket into their own default path:

```sh
mkdir -p ~/.config/mint
ln -sfn /var/lib/mint/admin.sock ~/.config/mint/admin.sock
mint pending               # no sudo, no MINT_SOCKET
```

Confirm the daemon agrees, and that the directory came along:

```sh
sudo journalctl -u mint -n 1     # ... admin /var/lib/mint/admin.sock (group mint)
ls -ld /var/lib/mint             # drwxr-x--- mint mint
ls -l /var/lib/mint/admin.sock   # srw-rw---- mint mint
```

**Group membership only applies to new login sessions.** The shell you ran
`usermod` from still has the old set, and `mint pending` there fails with
`permission denied` on the socket — log out and back in, or test with
`sudo -u <operator> -g mint mint pending`.

**Weigh this properly.** The admin socket has no authentication beyond
filesystem permissions, so the group is the power to approve any scope the
tailnet policy permits — the same reach as sudo on this host, minus the audit
trail sudo leaves. Put operators in it. Do not put service accounts, CI
runners, or anything an agent runs as in it: the whole design assumes approving
costs a human, and this group is exactly that cost.

## What systemd is doing for you

**`LoadCredential=app.pem:/etc/mint/app.pem`** — the key is mounted into a
per-service tmpfs and passed as `%d/app.pem`. It is never readable by the
`mint` user at rest, never copied into the state directory, and disappears
when the service stops.

**`StateDirectory=mint`** — `/var/lib/mint`, created `0700` and owned by the
service user. Holds the tsnet node key and `approvals.json`, both of which must
survive a restart. Removing it means re-authenticating the node and losing
every approval.

**Hardening** — no capabilities at all, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`,
`SystemCallFilter=@system-service`, and a restricted address-family set.

### The one that bites

`RestrictAddressFamilies` must include **`AF_NETLINK`**. `AF_INET AF_INET6
AF_UNIX` looks obviously sufficient for a network daemon, but tsnet enumerates
interfaces and routes over netlink, and without it startup fails with:

```
tsnet: route ip+net: netlinkrib: address family not supported by protocol
```

The App key loads *before* that point, so `minting from installation …`
appearing in the log does not mean the daemon is healthy.

`ProcSubset=pid` is deliberately **not** set, for a related reason: it hides
`/proc/net`, and tsnet reads `/proc/net/route` to enumerate interfaces. The
daemon still starts without it, but logs

```
interfaces: failed to read /proc/net/route: open /proc/net/route: no such file or directory
```

and works from a poorer picture of the host's networking. A warning rather than
a failure is the worse kind of hardening bug — it looks fine.

## Verifying the unit

```sh
systemd-analyze verify init/mint.service
systemd-analyze security mint.service     # once installed
```

`verify` will report the binary as missing until it is installed; that is
expected.

## Uninstall

```sh
sudo systemctl disable --now mint.service
sudo rm /etc/systemd/system/mint.service && sudo systemctl daemon-reload
sudo rm -rf /etc/mint /var/lib/mint   # removes the key, node identity, approvals
sudo userdel mint
sudo rm /usr/local/bin/mint
```

Remove the node from the Tailscale console too — deleting `/var/lib/mint`
orphans it rather than removing it.

## A user unit instead

For a workstation, running as yourself avoids the service user and the
`/etc/mint` dance:

```sh
mkdir -p ~/.config/systemd/user
sed -e 's|^User=.*||' -e 's|^Group=.*||' \
    -e 's|^LoadCredential=.*|Environment=GH_APP_KEY_FILE=%h/.config/mint/app.pem|' \
    -e 's|--key=%d/app.pem||' \
    -e 's|^ProtectHome=.*|ProtectHome=no|' \
    -e 's|^EnvironmentFile=.*|Environment=GH_APP_ID=1234567|' \
    -e 's|^\[Install\]|[Install]|' -e 's|^WantedBy=.*|WantedBy=default.target|' \
    init/mint.service > ~/.config/systemd/user/mint.service

systemctl --user daemon-reload
systemctl --user enable --now mint
loginctl enable-linger "$USER"     # so it runs when you are not logged in
```

State lands in `~/.config/mint` and the admin socket needs no `sudo`. You lose
`LoadCredential`, so the key sits readable by your own user — acceptable on a
single-user machine, not on a shared one.
