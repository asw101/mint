---
name: mint-policy
description: Read, diff, validate and apply a tailnet's Tailscale policy file (ACL) through the API. Use when the user says /mint-policy, a grant or tag needs changing, a node is being denied and the ACL is suspected, or mint's own capability is being renamed or regranted.
user-invocable: true
allowed-tools: Bash
---

# /mint-policy — manage the tailnet policy file

The Tailscale policy file is the ACL: the HuJSON document that decides which
nodes may reach which, and which capabilities they carry. It is also what grants
`mint` its authority, so it sits **above** mint in the trust order rather than
inside it.

Read that sentence as an operating instruction, not a note. Everything below
keeps the credential that can rewrite the policy away from the daemon that is
bound by it.

## The `tailscale` CLI cannot do this

There is no ACL or policy subcommand. `tailscale syspolicy` diagnoses local MDM
configuration on this machine, which is a different thing entirely. The policy
file is reachable through the admin console, the API, the Terraform provider and
the GitOps action; of those, this is the API one. Do not go looking for a client
command.

## Credentials

Two OAuth clients, created in the Tailscale admin console under Settings → OAuth
clients:

| Client | Scope | Used by | Secret file |
| --- | --- | --- | --- |
| Read | `policy_file:read` | `fetch`, `diff`, `validate` | `~/_/tailscale-oauth` |
| Write | `policy_file` | `apply` | `~/_/tailscale-oauth-write` |

Both files must be mode 0600; mint refuses to read one that anybody else on the
box can. The commands read different files by default, so the routine paths hold
a credential that **cannot** change the ACL. That is a capability, not a
promise, and it is the stronger form.

An OAuth client never expires and keeps working even if the person who created
it loses tailnet access. That is the point for a box an agent operates, and also
the reason revoking one has to be somebody's deliberate job.

Writing a secret to its file, without it passing through argv:

```sh
install -m 600 /dev/null ~/_/tailscale-oauth
read -rs secret && printf '%s' "$secret" > ~/_/tailscale-oauth && unset secret
```

**Never** pass a secret as a command-line argument, to mint or to anything else.
`curl -d "client_secret=$SECRET"` puts it in `/proc/<pid>/cmdline`, where any
process running as the same user can read it. mint has no flag that takes a
secret value for exactly this reason: it reads files, or stdin via
`--secret-file -`.

### Bootstrapping, before an OAuth client exists

A `tskey-api-…` access token works and carries the full permissions of whoever
created it, expiring after about ninety days:

```sh
mint policy fetch --api-key-file ~/_/tailscale-api-key
```

Use it to create the two OAuth clients, then stop using it.

## The commands

```sh
mint policy fetch -o policy.hujson    # current policy, comments intact
mint policy diff policy.hujson        # what applying it would change
mint policy validate policy.hujson    # would Tailscale accept it
mint policy apply policy.hujson --yes # replace it
```

`fetch` asks for HuJSON, so comments and trailing commas survive the round trip.
A policy file is mostly comments explaining who may reach what; fetching it as
JSON would throw away the part written for humans.

`validate` is a real check against the tailnet, not a syntax check. It catches a
grant naming a tag that does not exist, which otherwise appears as a node
mysteriously losing access.

`apply` fetches first and sends the version it read back as `If-Match`, so a
change made in the admin console in the meantime fails the write rather than
being silently overwritten. It validates, prints the diff, and refuses without
`--yes`. It also refuses a policy that grants neither `asw101.dev/cap/mint` nor
`asw101.dev/cap/tsapp`, because that is the shape of an accidental lockout;
`--force` overrides it.

`--tailnet` defaults to `-`, meaning the credential's own tailnet, which is the
right answer whenever there is only one.

## The workflow

Always the same four steps. The diff is the part a human actually checks.

```sh
mint policy fetch -o /tmp/policy.hujson
$EDITOR /tmp/policy.hujson
mint policy diff /tmp/policy.hujson
mint policy apply /tmp/policy.hujson --yes
```

Keep the fetched copy until the change is verified. It is the rollback.

## Verify with a real request, not by reading the file

A policy that validates can still be wrong. After any change to a grant that
mint depends on:

```sh
mint whoami                        # does the daemon still recognise this node
mint token --repo <a real repo>    # does it still mint
```

A grant reads correctly far more often than it works.

## Renaming a capability without locking anyone out

mint honours `asw101.dev/cap/mint` and the older `asw101.dev/cap/tsapp` at the
same time and merges grants under both, so there is no instant at which the
policy and the binaries must agree. That is what makes the following safe:

1. **Add** the new capability alongside the old one, granting the same thing.
   Apply. Every client keeps working, under whichever name it knows.
2. Upgrade the daemon and the clients to a mint that knows both. Verify with a
   real `mint token` and a real `mint wormhole` round trip from another node.
3. **Remove** the old capability. Apply. Verify again.

Never combine steps 1 and 3 into a single edit that renames in place. The window
between the policy changing and every binary being upgraded is exactly where a
tailnet-wide lockout lives, and recovering from one needs console access from a
machine that is not locked out.

## What must never happen

- **The daemon must never hold a policy-writing credential.** `mint serve`
  refuses to start if it sees `TS_API_KEY`, `TS_OAUTH_CLIENT_SECRET` or their
  variants in its environment. A broker that can rewrite the grants authorizing
  it can grant itself anything the tailnet can express.
- **Do not put a secret on a command line.** See above; this is the single most
  common way a carefully delivered credential leaks.
- **Do not apply an edit you have not diffed.** The policy file is the one
  document where a plausible-looking change can remove a node's access silently.
