# Wormhole semantics

The commands, the stream rules and a worked handoff are in the
[README](../README.md#wormhole-ephemeral-secret-handoff). This is what the
mailbox guarantees, and what it does not.

## Resolving a key with more than one sender

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

## Discovering addressed items

`mint wormhole list` shows every live item addressed to the calling node:
sender stable ID and name, key, creation and expiry times, and value size in
bytes. It never returns a value, any part of one, or a value hash. Empty is a
successful result and says plainly that no wormhole items are addressed to the
node.

The recipient always comes from the caller's tailnet `WhoIs` identity; body,
query, and header fields cannot select another node. Listing requires the same
`wormhole.get` capability as consuming. Expired items are pruned and omitted.

## Replacement is explicit

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

## Limits, lifetime, and failure semantics

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

## Memory and threat boundary

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
