---
name: tsapp
description: Get a short-lived, repository-scoped GitHub token from the tsapp broker on the tailnet, instead of using a stored PAT or the ambient gh login. Use when the user says /tsapp, when a task needs GitHub access to a specific repository, when gh or git fails with a permissions or authentication error, or when you are about to ask the user for a token.
user-invocable: true
allowed-tools: Bash
---

# /tsapp — authenticate to GitHub through the broker

`tsapp` mints a GitHub App token scoped to the repositories you name, valid for
one hour. You present no credential: the daemon identifies you by your tailnet
node and decides from policy.

Prefer this over a stored PAT or whatever `gh auth` happens to hold. The token
you get reaches only what a human has approved for this machine.

## Get a token

```sh
tsapp token --repo <name>
```

`--repo` takes a bare name or `owner/name`, is repeatable, and accepts a
comma-separated list. Ask for the **narrowest** set that does the job — a
narrower request is served silently from an existing approval, while a wider
one interrupts a human.

Use it without letting it reach a log or the transcript:

```sh
GH_TOKEN=$(tsapp token --repo widget) gh pr list --repo asw101/widget
```

For git over HTTPS:

```sh
GH_TOKEN=$(tsapp token --repo widget) \
  git -c credential.helper='!f() { echo "username=x-access-token"; echo "password=$GH_TOKEN"; }; f' \
  clone https://github.com/asw101/widget
```

## Read the exit code, not the message

| Exit | Meaning | Do this |
| --- | --- | --- |
| `0` | token on stdout | use it |
| `2` | pending approval | **stop and tell the user** the approve command; do not loop |
| `3` | denied by policy | **stop.** Retrying cannot help |
| `1` | transport, config, or upstream failure | report it; retry only if it looks transient |

```sh
if token=$(tsapp token --repo widget 2>/dev/null); then
    GH_TOKEN="$token" gh ...
else
    case $? in
        2) echo "needs approval" ;;
        3) echo "not permitted" ;;
        *) echo "broker unavailable" ;;
    esac
fi
```

On exit `2` the message names the request id. Surface it verbatim so the user
can act:

```
tsapp: pending approval (request 14bf7231) — run 'tsapp approve 14bf7231' on the daemon host
```

Then wait for them. **Approval is a human decision, and `tsapp approve` only
works on the daemon's host** — if you are not on it, you cannot approve, and
you should not try.

## Rules

- **Never print a token**, echo it, write it to a file, or put it in a commit,
  a log, or your reply. Pass it through an environment variable and let it go.
- **Mint per use.** Tokens last an hour. Do not cache one, and do not carry one
  between tasks.
- **Do not retry an exit `3`.** It is a policy decision. Report it and stop.
- **Do not widen the request to make an error go away.** Asking for more
  repositories than the task needs is how a narrow approval becomes a broad
  one.
- **Do not fall back to another credential** when `tsapp` refuses. A refusal is
  the answer, not an obstacle.

## Diagnosing

```sh
tsapp whoami
```

Reports what the daemon sees: node, tags, and the grants policy gives you. If
`grants` is `null`, the tailnet policy grants this node nothing — that is a
policy problem for the user to fix, not something to work around.

```sh
tsapp version                       # which build this is
tsapp token --server http://<host>:8080 --repo <name>
```

`--server` defaults to `http://tsapp:8080`; pass it when the daemon runs under
another hostname.

## Installing this skill

The skill lives with the project so it ships with it. Symlink it into the
agent skills tree rather than copying, so it tracks the project:

```sh
ln -s ../../tsapp/skills/tsapp .agents/skills/tsapp
```

Adjust the relative path to wherever `tsapp/` sits. Verify it resolves:

```sh
readlink -f .agents/skills/tsapp && cat .agents/skills/tsapp/SKILL.md | head -3
```
