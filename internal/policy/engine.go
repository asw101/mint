package policy

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"
)

// Identity is the caller, as reported by the tailnet.
type Identity struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name,omitempty"`
	User     string `json:"user,omitempty"`
	// Tags are the ACL tags the node carries. A tagged node reports its user
	// as "tagged-devices", so the tags are the only thing a grant's src can
	// usefully match.
	Tags []string `json:"tags,omitempty"`
	// Grants are the capabilities the tailnet ACL confers on this caller.
	// They are the ceiling: no stored approval can exceed them.
	Grants []Grant `json:"grants"`
}

// Describe names the caller the way a tailnet ACL would, so a denial can be
// turned straight into the grant that would fix it.
func (i Identity) Describe() string {
	if len(i.Tags) > 0 {
		return fmt.Sprintf("node %s (%s)", i.NodeName, strings.Join(i.Tags, ", "))
	}
	switch {
	case i.NodeName != "" && i.User != "":
		return fmt.Sprintf("node %s (user %s)", i.NodeName, i.User)
	case i.NodeName != "":
		return fmt.Sprintf("node %s", i.NodeName)
	case i.User != "":
		return fmt.Sprintf("user %s", i.User)
	default:
		return "node " + i.NodeID
	}
}

// Outcome is what the engine decided.
type Outcome int

const (
	// Denied means the scope is outside the ACL ceiling. Approving it would
	// not help; the ACL has to change.
	Denied Outcome = iota
	// Pending means the scope is permitted by the ACL but no human has
	// approved it for this node yet.
	Pending
	// Allowed means mint it.
	Allowed
)

func (o Outcome) String() string {
	switch o {
	case Allowed:
		return "allowed"
	case Pending:
		return "pending"
	default:
		return "denied"
	}
}

// Decision is the engine's answer, with the reason it reached it.
type Decision struct {
	Outcome Outcome
	Reason  string
	// Scope is the effective scope: what the caller asked for, with any
	// permissions it omitted filled in from the policy. Mint this, not the
	// original request.
	Scope Scope
	// Request is set when Outcome is Pending.
	Request Request
}

// Engine evaluates requests against the ACL ceiling and the approval store.
type Engine struct {
	Store *Store
	// Account is the login the installation belongs to. When set, a request
	// naming a different owner is refused rather than silently reinterpreted:
	// "otherorg/secrets" must not quietly become this account's "secrets".
	Account string
	// Now and NewID are injectable so decisions are reproducible in tests.
	Now   func() time.Time
	NewID func() (string, error)
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) newID() (string, error) {
	if e.NewID != nil {
		return e.NewID()
	}
	return NewID()
}

// Evaluate decides whether to mint for the scope this identity asked for.
//
// The order matters. A scope outside the ACL ceiling is denied outright rather
// than queued for approval, because no amount of approving would make it
// mintable — the operator would have to widen the tailnet policy first, and a
// queue full of unsatisfiable requests trains people to approve blindly.
func (e *Engine) Evaluate(id Identity, scope Scope) (Decision, error) {
	if err := scope.Validate(); err != nil {
		return Decision{Outcome: Denied, Reason: err.Error(), Scope: scope}, nil
	}
	if id.NodeID == "" {
		return Decision{Outcome: Denied, Reason: "caller has no node identity"}, nil
	}

	if err := e.checkOwners(scope); err != nil {
		return Decision{Outcome: Denied, Reason: err.Error(), Scope: scope}, nil
	}

	// Normalize reduces repositories to bare names, which is what the API and
	// the grants both use.
	scope = scope.Normalize()

	if len(id.Grants) == 0 {
		return Decision{
			Outcome: Denied,
			Reason: fmt.Sprintf(
				"the tailnet policy grants no tsapp capability to %s; add a grant whose src matches it, "+
					"with an app capability named %q (app capabilities require the grants syntax, not the legacy acls array)",
				id.Describe(), CapabilityName),
		}, nil
	}
	// A request that names no permissions means "the most this policy allows"
	// rather than "the installation's whole grant". Resolving from the
	// covering grant can only ever narrow the result, and it turns the most
	// common denial into a correctly scoped token.
	scope, err := resolvePermissions(id.Grants, scope)
	if err != nil {
		return Decision{Outcome: Denied, Reason: err.Error(), Scope: scope}, nil
	}

	if !CoveredByAny(id.Grants, scope) {
		return Decision{
			Outcome: Denied,
			Scope:   scope,
			Reason: fmt.Sprintf("scope %s exceeds the capability granted by the tailnet policy%s",
				scope, explainCeilingMiss(id.Grants, scope)),
		}, nil
	}

	now := e.now()
	approvals := e.Store.ApprovalsFor(id.NodeID, now)
	grants := make([]Grant, 0, len(approvals))
	for _, a := range approvals {
		grants = append(grants, a.Grant)
	}
	if CoveredByAny(grants, scope) {
		return Decision{
			Outcome: Allowed,
			Scope:   scope,
			Reason:  fmt.Sprintf("scope %s covered by an existing approval", scope),
		}, nil
	}

	reqID, err := e.newID()
	if err != nil {
		return Decision{}, err
	}
	req, err := e.Store.AddPending(Request{
		ID:          reqID,
		NodeID:      id.NodeID,
		NodeName:    id.NodeName,
		Scope:       scope,
		RequestedAt: now,
	})
	if err != nil {
		return Decision{}, err
	}
	return Decision{
		Outcome: Pending,
		Scope:   scope,
		Reason:  fmt.Sprintf("scope %s needs approval", scope),
		Request: req,
	}, nil
}

// explainCeilingMiss adds a hint for the two ways a request can exceed a grant
// that looks like it should cover it.
func explainCeilingMiss(grants []Grant, scope Scope) string {
	restrictsPermissions := false
	wildcard := false
	for _, g := range grants {
		if len(g.Permissions) > 0 {
			restrictsPermissions = true
		}
		if g.hasWildcard() {
			wildcard = true
		}
	}
	if len(scope.Repos) == 0 && !wildcard {
		return " (the request named no repositories, which means every repository the installation can reach;" +
			" name them with --repo, or grant \"repos\": [\"*\"])"
	}
	if len(scope.Permissions) == 0 && restrictsPermissions {
		// Reachable only when no grant covers the repositories, since a
		// covering grant would have supplied the permissions.
		return " (no grant covers those repositories, so the permissions could not be inferred either)"
	}
	return ""
}

// resolvePermissions fills in the permissions a request omitted, taking them
// from the grant that covers the repositories asked for.
//
// This is strictly narrowing: the result is derived from the ceiling, so it can
// never permit more than leaving the request unrestricted would have. Grants
// that do not restrict permissions leave the request unrestricted too, which
// defers to the App's own set.
func resolvePermissions(grants []Grant, scope Scope) (Scope, error) {
	if len(scope.Permissions) > 0 {
		return scope, nil
	}

	var covering []Grant
	for _, g := range grants {
		if g.coversRepos(scope.Repos) {
			covering = append(covering, g)
		}
	}
	if len(covering) == 0 {
		// Nothing covers the repositories; the ceiling check reports that,
		// with a better message than this function could give.
		return scope, nil
	}

	want := permissionKey(covering[0].Permissions)
	for _, g := range covering[1:] {
		if permissionKey(g.Permissions) != want {
			return scope, fmt.Errorf(
				"scope %s matches several tailnet grants with different permissions, "+
					"so the request must name the permissions it wants, e.g. --permission contents=read",
				scope)
		}
	}

	if len(covering[0].Permissions) == 0 {
		// The grant does not restrict permissions, so neither does the request.
		return scope, nil
	}
	resolved := scope
	resolved.Permissions = maps.Clone(covering[0].Permissions)
	return resolved, nil
}

// permissionKey renders a permission set canonically so two grants can be
// compared regardless of map ordering.
func permissionKey(permissions map[string]string) string {
	if len(permissions) == 0 {
		return ""
	}
	keys := make([]string, 0, len(permissions))
	for k := range permissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s;", k, permissions[k])
	}
	return b.String()
}

// checkOwners refuses a request naming an owner the installation is not for.
// Without this, normalizing "otherorg/secrets" to "secrets" would mint against
// this account's repository of that name.
func (e *Engine) checkOwners(scope Scope) error {
	if e.Account == "" {
		return nil
	}
	for _, r := range scope.Repos {
		owner, name, err := SplitRepo(r)
		if err != nil {
			return err
		}
		if owner != "" && !strings.EqualFold(owner, e.Account) {
			return fmt.Errorf("repository %q names owner %q, but this installation is for %q",
				r, owner, e.Account)
		}
		_ = name
	}
	return nil
}
