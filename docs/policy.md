# Managing the tailnet policy

The four commands and what `apply` guarantees are in the
[README](../README.md#managing-the-tailnet-policy). This is the credential model
behind them.

First, why this is an API job at all: the `tailscale` CLI cannot do any of it. It
has no ACL or policy subcommand, and `syspolicy` diagnoses local MDM
configuration rather than the tailnet. Installing a client buys nothing here.

## Two credentials, not one

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

[`skills/mint-policy/SKILL.md`](../skills/mint-policy/SKILL.md) is the same thing
written for an agent, including how to rename a capability without locking the
tailnet out.
