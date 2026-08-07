package policy

import (
	"fmt"
	"time"
)

// Identity is the caller, as reported by the tailnet.
type Identity struct {
	NodeID   string
	NodeName string
	User     string
	// Grants are the capabilities the tailnet ACL confers on this caller.
	// They are the ceiling: no stored approval can exceed them.
	Grants []Grant
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
			Reason:  "no tsapp capability granted to this caller by the tailnet policy",
		}, nil
	}
	if !CoveredByAny(id.Grants, scope) {
		return Decision{
			Outcome: Denied,
			Reason:  fmt.Sprintf("scope %s exceeds the capability granted by the tailnet policy", scope),
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
