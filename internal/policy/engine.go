package policy

import (
	"fmt"
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
	// Request is set when Outcome is Pending.
	Request Request
}

// Engine evaluates requests against the ACL ceiling and the approval store.
type Engine struct {
	Store *Store
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
		return Decision{Outcome: Denied, Reason: err.Error()}, nil
	}
	if id.NodeID == "" {
		return Decision{Outcome: Denied, Reason: "caller has no node identity"}, nil
	}

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
	if !CoveredByAny(id.Grants, scope) {
		return Decision{
			Outcome: Denied,
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
	if len(scope.Permissions) == 0 && restrictsPermissions {
		return " (the request named no permissions, which means the installation's whole grant;" +
			" the policy restricts permissions, so name them, e.g. --permission contents=read)"
	}
	if len(scope.Repos) == 0 && !wildcard {
		return " (the request named no repositories, which means every repository the installation can reach;" +
			" name them with --repo, or grant \"repos\": [\"*\"])"
	}
	return ""
}
