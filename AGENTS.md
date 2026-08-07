# AGENTS.md

Guidance for AI coding agents working in `tsapp`.

## What this is

A daemon that mints GitHub App tokens for tailnet clients, plus the client and
admin CLI for it. See [`README.md`](./README.md) for usage and
[`notes/tailnet-secret-broker.md`](../notes/tailnet-secret-broker.md) for the
architecture.

## Layout

| Path | What it is |
| --- | --- |
| `main.go` | CLI: `serve`, `token`, `whoami`, and the admin subcommands. |
| `internal/policy/policy.go` | Scope, Grant, and the subset check. |
| `internal/policy/store.go` | Approvals and pending requests, persisted atomically. |
| `internal/policy/engine.go` | The decision: allowed, pending, or denied. |
| `internal/server/server.go` | The tailnet and admin HTTP surfaces. |
| `internal/app/` | GitHub App JWT signing and token minting. |

`internal/app` is a **vendored copy** of a package maintained elsewhere in this
workspace, not an import. The two are allowed to diverge; do not add a module
dependency between them to share it.

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
- **Run `just check` before finishing** — gofmt, vet, and tests.
- **Commit as the human, never as the agent.** Every commit is attributed to
  the repository owner via the local Git identity. Do not override the author,
  and do not add `Co-Authored-By:` trailers or "generated with" footers.
