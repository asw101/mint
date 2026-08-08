# Running tsapp under systemd

`tsapp.service` runs the daemon as an unprivileged system user, with the App
private key supplied by systemd rather than left readable on disk.

This is for a **Linux** host. macOS uses launchd, and there is no plist here
yet.

## Install

```sh
# 1. The binary
sudo install -m 0755 bin/tsapp /usr/local/bin/tsapp

# 2. A service user with no home and no shell
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tsapp

# 3. Configuration, readable by the service and nobody else
sudo install -d -m 0750 -o root -g tsapp /etc/tsapp
sudo install -m 0640 -o root -g tsapp /path/to/app.pem /etc/tsapp/app.pem
printf 'GH_APP_ID=1234567\n' | sudo tee /etc/tsapp/env >/dev/null
sudo chmod 0640 /etc/tsapp/env && sudo chgrp tsapp /etc/tsapp/env

# 4. The unit
sudo install -m 0644 init/tsapp.service /etc/systemd/system/tsapp.service
sudo systemctl daemon-reload
sudo systemctl enable --now tsapp.service
```

## First start

The daemon joins the tailnet on start and waits to be authenticated. Watch for
the URL:

```sh
sudo journalctl -u tsapp -f
```

```
minting from installation 89012345 (asw101)
tsnet running state path /var/lib/tsapp/tsnet/tailscaled.state
To start this tsnet server ... go to: https://login.tailscale.com/a/...
```

Visit it, then in the Tailscale console approve the node and give it
**`tag:tsapp`**. The unit claims the hostname `tsapp` (from `%p`), so clients
need no `--server` override.

It logs its tailnet name once it is in:

```
tailnet node tsapp.your-tailnet.ts.net. ([100.x.y.z ...])
tailnet tsapp:8080, admin /var/lib/tsapp/admin.sock
```

`Restart=on-failure` means it keeps retrying, so an unauthenticated daemon is
not a failed one — it just sits there. Check `systemctl show tsapp -p NRestarts`
if you suspect a loop.

## Approving

The admin socket is at `/var/lib/tsapp/admin.sock`, mode `0600` inside a `0700`
directory, so it is reachable by **root or the `tsapp` user only**:

```sh
sudo TSAPP_SOCKET=/var/lib/tsapp/admin.sock tsapp pending
sudo TSAPP_SOCKET=/var/lib/tsapp/admin.sock tsapp approve 7c2a --ttl 720h
```

An ordinary user gets `permission denied` from the directory, before the socket
is even consulted. That is the intended boundary: approving is an operator
action.

**The socket does not exist until the node has authenticated.** `serve` joins
the tailnet before binding it, so until you visit the login URL every admin
command reports `is 'tsapp serve' running on this host?` even though it is.

## What systemd is doing for you

**`LoadCredential=app.pem:/etc/tsapp/app.pem`** — the key is mounted into a
per-service tmpfs and passed as `%d/app.pem`. It is never readable by the
`tsapp` user at rest, never copied into the state directory, and disappears
when the service stops.

**`StateDirectory=tsapp`** — `/var/lib/tsapp`, created `0700` and owned by the
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

## Verifying the unit

```sh
systemd-analyze verify init/tsapp.service
systemd-analyze security tsapp.service     # once installed
```

`verify` will report the binary as missing until it is installed; that is
expected.

## Uninstall

```sh
sudo systemctl disable --now tsapp.service
sudo rm /etc/systemd/system/tsapp.service && sudo systemctl daemon-reload
sudo rm -rf /etc/tsapp /var/lib/tsapp   # removes the key, node identity, approvals
sudo userdel tsapp
sudo rm /usr/local/bin/tsapp
```

Remove the node from the Tailscale console too — deleting `/var/lib/tsapp`
orphans it rather than removing it.

## A user unit instead

For a workstation, running as yourself avoids the service user and the
`/etc/tsapp` dance:

```sh
mkdir -p ~/.config/systemd/user
sed -e 's|^User=.*||' -e 's|^Group=.*||' \
    -e 's|^LoadCredential=.*|Environment=GH_APP_KEY_FILE=%h/.config/tsapp/app.pem|' \
    -e 's|--key=%d/app.pem||' \
    -e 's|^ProtectHome=.*|ProtectHome=no|' \
    -e 's|^EnvironmentFile=.*|Environment=GH_APP_ID=1234567|' \
    -e 's|^\[Install\]|[Install]|' -e 's|^WantedBy=.*|WantedBy=default.target|' \
    init/tsapp.service > ~/.config/systemd/user/tsapp.service

systemctl --user daemon-reload
systemctl --user enable --now tsapp
loginctl enable-linger "$USER"     # so it runs when you are not logged in
```

State lands in `~/.config/tsapp` and the admin socket needs no `sudo`. You lose
`LoadCredential`, so the key sits readable by your own user — acceptable on a
single-user machine, not on a shared one.
