// Package policy decides whether a client may be issued a token for the scope
// it asked for.
//
// Two things must both hold before a request is served automatically:
//
//  1. the scope is within the ceiling the tailnet ACL grants that client, and
//  2. the scope is within something a human has already approved for that
//     specific node.
//
// The ACL is a per-class bound and cannot be exceeded even if the approval
// store says otherwise; the store is per-node and is what makes "already
// approved" mean this client rather than this kind of client.
package policy

import (
	"fmt"
	"sort"
	"strings"
)

// AllRepos is the wildcard a grant may use to cover every repository the
// installation can reach.
const AllRepos = "*"

// CapabilityName is the tailnet ACL capability this service reads. It lives
// here rather than in the server package so denial messages can name it.
// Custom capabilities must be <domain>/<path>/<name>.
//
// The domain is a namespace, not an address: Tailscale does not resolve it and
// does not check that you own it. That is exactly why it should be a domain you
// do own, since nothing else will catch you borrowing somebody else's.
const CapabilityName = "aaronw.dev/cap/mint"

// permissionRank orders GitHub's permission levels so a request for "read"
// can be satisfied by a grant of "write".
var permissionRank = map[string]int{
	"none":  0,
	"read":  1,
	"write": 2,
	"admin": 3,
}

// Scope is what a client asked for: bare repository names (the API scopes
// within the installation's account) and the permissions it wants.
type Scope struct {
	Repos       []string          `json:"repos,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

// Grant is what some authority permits — either a capability from the tailnet
// ACL, or a stored approval. Repos may contain AllRepos.
type Grant struct {
	Repos       []string          `json:"repos,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
	Wormhole    *WormholeGrant    `json:"wormhole,omitempty"`
}

// WormholeGrant bounds mailbox delivery separately from repository scopes.
type WormholeGrant struct {
	PutToTags []string `json:"putToTags,omitempty"`
	Get       bool     `json:"get,omitempty"`
}

// AllowsWormholeGet reports whether any capability grant permits consumption.
func AllowsWormholeGet(grants []Grant) bool {
	for _, grant := range grants {
		if grant.Wormhole != nil && grant.Wormhole.Get {
			return true
		}
	}
	return false
}

// AllowsWormholePut reports whether any capability grant permits delivery to
// at least one of the recipient's current tags.
func AllowsWormholePut(grants []Grant, recipientTags []string) bool {
	for _, grant := range grants {
		if grant.Wormhole == nil {
			continue
		}
		for _, allowed := range grant.Wormhole.PutToTags {
			for _, actual := range recipientTags {
				if allowed == actual {
					return true
				}
			}
		}
	}
	return false
}

// IsZero reports whether the scope asks for nothing.
func (s Scope) IsZero() bool { return len(s.Repos) == 0 && len(s.Permissions) == 0 }

// HasAllRepos reports whether the scope names the AllRepos wildcard, which asks
// for every repository the installation can reach rather than a named set.
//
// A request may name it, unlike leaving the repositories empty: the wildcard is
// deliberate and still has to clear the ACL ceiling and an approval, whereas an
// omission is the same reach asked for by accident.
func (s Scope) HasAllRepos() bool {
	for _, r := range s.Repos {
		if strings.TrimSpace(r) == AllRepos {
			return true
		}
	}
	return false
}

// SplitRepo accepts either "owner/name" or a bare "name" and returns the two
// parts, with an empty owner when none was given.
func SplitRepo(s string) (owner, name string, err error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".git")
	if s == "" {
		return "", "", fmt.Errorf("empty repository name")
	}
	parts := strings.Split(s, "/")
	switch len(parts) {
	case 1:
		return "", parts[0], nil
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid repository %q", s)
		}
		return parts[0], parts[1], nil
	default:
		return "", "", fmt.Errorf("invalid repository %q (want owner/name or name)", s)
	}
}

// Normalize returns a copy with repositories reduced to bare names, sorted and
// de-duplicated, so equal scopes compare and store identically regardless of
// argument order or whether the owner was spelled out.
//
// The API scopes within the installation's account, so the owner carries no
// information by the time a token is minted. Owners are checked before this
// point, by Engine.Evaluate.
func (s Scope) Normalize() Scope {
	out := Scope{Permissions: map[string]string{}}
	seen := map[string]bool{}
	for _, r := range s.Repos {
		_, name, err := SplitRepo(r)
		if err != nil || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out.Repos = append(out.Repos, name)
	}
	sort.Strings(out.Repos)
	for k, v := range s.Permissions {
		out.Permissions[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(out.Permissions) == 0 {
		out.Permissions = nil
	}
	return out
}

// String renders a scope for logs and approval prompts.
func (s Scope) String() string {
	n := s.Normalize()
	repos := "(unscoped)"
	if len(n.Repos) > 0 {
		repos = strings.Join(n.Repos, ",")
	}
	if len(n.Permissions) == 0 {
		return repos
	}
	keys := make([]string, 0, len(n.Permissions))
	for k := range n.Permissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+n.Permissions[k])
	}
	return repos + " " + strings.Join(parts, ",")
}

// Covers reports whether g permits everything s asks for.
//
// An unscoped request — no repositories named — means every repository the
// installation can reach, so only a wildcard grant can cover it. A request
// naming no permissions inherits the installation's own grant, which likewise
// only a grant with no permission restriction can cover.
func (g Grant) Covers(s Scope) bool {
	if !g.coversRepos(s.Repos) {
		return false
	}
	return g.coversPermissions(s.Permissions)
}

func (g Grant) coversRepos(repos []string) bool {
	if g.hasWildcard() {
		return true
	}
	if len(repos) == 0 {
		// Unscoped: the installation's whole reach, which a finite grant
		// cannot bound.
		return false
	}
	allowed := make(map[string]bool, len(g.Repos))
	for _, r := range g.Repos {
		allowed[r] = true
	}
	for _, r := range repos {
		if !allowed[r] {
			return false
		}
	}
	return true
}

func (g Grant) coversPermissions(want map[string]string) bool {
	if len(g.Permissions) == 0 {
		// The grant does not restrict permissions, so it covers any request.
		return true
	}
	if len(want) == 0 {
		// The request inherits the installation's full permission set, which a
		// restricted grant cannot bound.
		return false
	}
	for key, level := range want {
		granted, ok := g.Permissions[key]
		if !ok {
			return false
		}
		if rank(level) > rank(granted) {
			return false
		}
	}
	return true
}

func (g Grant) hasWildcard() bool {
	for _, r := range g.Repos {
		if r == AllRepos {
			return true
		}
	}
	return false
}

// rank maps a permission level to its ordering. Unknown levels rank above
// every known one, so an unrecognised request is never silently satisfied by a
// weaker grant.
func rank(level string) int {
	if r, ok := permissionRank[strings.ToLower(strings.TrimSpace(level))]; ok {
		return r
	}
	return len(permissionRank) + 1
}

// CoveredByAny reports whether any single grant covers the scope. Grants are
// not combined: a request must fit inside one of them, because two grants that
// each cover half of a request were not written to permit the whole.
func CoveredByAny(grants []Grant, s Scope) bool {
	for _, g := range grants {
		if g.Covers(s) {
			return true
		}
	}
	return false
}

// Validate reports whether a scope is well formed.
func (s Scope) Validate() error {
	for _, r := range s.Repos {
		if _, _, err := SplitRepo(r); err != nil {
			return err
		}
	}
	for k, v := range s.Permissions {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("permission %q=%q must be key=value", k, v)
		}
		if _, ok := permissionRank[strings.ToLower(v)]; !ok {
			return fmt.Errorf("unknown permission level %q for %q", v, k)
		}
	}
	return nil
}
