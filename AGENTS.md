# AGENTS.md

Guidance for AI coding agents working in `mint`.

## What this is

A daemon that mints GitHub App tokens for tailnet clients, plus the client and
admin CLI for it. See [`README.md`](./README.md) for usage and the design it
implements.

## Layout

| Path | What it is |
| --- | --- |
| `main.go` | CLI: `serve`, `token`, `whoami`, and the admin subcommands. |
| `internal/policy/policy.go` | Scope, Grant, and the subset check. |
| `internal/policy/store.go` | Approvals and pending requests, persisted atomically. |
| `internal/policy/engine.go` | The decision: allowed, pending, or denied. |
| `internal/server/server.go` | The tailnet and admin HTTP surfaces. |
| `internal/app/` | GitHub App JWT signing and token minting. |
| `internal/tspolicy/` | The Tailscale API client for the tailnet policy file. |
| `policy_cli.go` | `mint policy`: fetch, diff, validate, apply. Operator only. |
| `compat.go` | Everything that keeps the old `tsapp` name working. |
| `docs/` | Reference: grant shapes, wormhole semantics, day-two operation, `mint policy`, development. |

`internal/app` is **mint's own code**. It began as a copy of the same package in
`asw101/ghapp`, mint's predecessor, and mint is now the surviving consumer:
ghapp is deprecated, and Go could not have shared the package across module
boundaries under `internal/` in any case. Edit it here.

If something else ever needs it, mint promotes the package out of `internal/`
and the other repository depends on mint. Never the reverse: a dependency
pointing back at the retired predecessor gets the arrow backwards.

## Conventions

- **The tailnet is mocked in tests.** `WhoIs` sits behind
  `server.Identifier` and minting behind `server.Minter`. Every authorization
  decision must be testable without joining a tailnet — if a change makes that
  impossible, the change is wrong.
- **The ACL is a ceiling the store cannot raise.** `Engine.Evaluate` checks the
  capability first and the approval store second, and a scope outside the
  capability is denied rather than queued. Preserve that order: queuing
  unsatisfiable requests trains people to approve blindly.
- **Approving is never reachable from the tailnet.** Admin endpoints live on
  the Unix socket only. `TestAdminSurfaceIsNotOnTheTailnetHandler` guards this.
- **The daemon never holds a policy-writing credential.** The tailnet policy is
  what grants mint its authority, so a daemon able to rewrite it could grant
  itself anything the tailnet can express. `mint serve` refuses to start with a
  Tailscale API credential in its environment, and `mint policy apply` reads a
  different secret file from the read commands. Express this as capability, not
  as a rule someone has to remember.
- **No flag ever takes a secret as its value.** Secrets come from files or
  stdin. An argument is readable from `/proc/<pid>/cmdline` by anything running
  as the same user, which is how a carefully delivered credential leaks on
  arrival.
- **Never log or return a token except to the client that earned it.** Log the
  identity, the scope, and the expiry — not the secret.
- **Log automatic grants as carefully as approved ones.** The approved ones you
  remember; the automatic ones are the audit trail's whole point.
- **Match on stable IDs, not names.** Node names and repository names are
  mutable; `who.Node.StableID` is not.
- **Write state atomically.** `Store.save` writes to a temporary file and
  renames, so a reader never sees a partial file and a crash cannot lose
  existing approvals.
- **Standard library plus `tailscale.com`.** No other dependencies without a
  concrete reason.
- **Compatibility with the old name lives in `compat.go` and nowhere else.**
  mint was `tsapp` until 2026-08. Each hook there records what has to be true
  before it can be deleted; do not scatter new ones through the code.
- **The README is the path you walk once; `docs/` is what you look up.** Adding
  reference material to the README is how it got to 950 lines. The test is
  whether a first-time reader needs it to get a token: if not, it belongs in
  `docs/`. Nothing in the first-run walkthrough may depend on following a link.
- **Run `just check` before finishing** — gofmt, vet, and tests.
- **Commit as the human, never as the agent.** Every commit is attributed to
  the repository owner via the local Git identity. Do not override the author,
  and do not add `Co-Authored-By:` trailers or "generated with" footers.
