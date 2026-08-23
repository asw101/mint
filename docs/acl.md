# Tailnet policy grants

Every way to write mint's capability into a tailnet policy file, and what to do
when a grant that looks right denies everything. The minimum grant that gets you
working is in the [README](../README.md#full-app-permissions); this is the rest.

## Explicit read-only permissions

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

## Wormhole sender and recipient capabilities

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

## If you get "the tailnet policy grants no mint capability"

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
