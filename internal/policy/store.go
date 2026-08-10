package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNotFound is returned when an approval or pending request ID is unknown.
var ErrNotFound = errors.New("not found")

// Approval is a grant a human has blessed for one specific node.
type Approval struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id"`
	NodeName   string    `json:"node_name,omitempty"`
	Grant      Grant     `json:"grant"`
	ApprovedAt time.Time `json:"approved_at"`
	// ExpiresAt zero means the approval does not expire.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Expired reports whether the approval has lapsed.
func (a Approval) Expired(now time.Time) bool {
	return !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt)
}

// Request is a scope a node asked for that no approval covered yet.
type Request struct {
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	NodeName    string    `json:"node_name,omitempty"`
	Scope       Scope     `json:"scope"`
	RequestedAt time.Time `json:"requested_at"`
}

type state struct {
	Approvals []Approval `json:"approvals"`
	Pending   []Request  `json:"pending"`
}

// Store persists approvals and pending requests to a JSON file.
//
// The file is the security boundary: it must not be writable by the clients
// whose access it governs, since anything that can edit it can grant itself
// whatever it likes.
type Store struct {
	path string

	mu    sync.Mutex
	state state
}

// Open loads the store at path, creating an empty one if absent.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("read approvals: %w", err)
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ApprovalsFor returns the live approvals for a node, skipping expired ones.
func (s *Store) ApprovalsFor(nodeID string, now time.Time) []Approval {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Approval
	for _, a := range s.state.Approvals {
		if a.NodeID == nodeID && !a.Expired(now) {
			out = append(out, a)
		}
	}
	return out
}

// Approvals returns every approval, expired ones included, for listing.
func (s *Store) Approvals() []Approval {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Approval(nil), s.state.Approvals...)
}

// Pending returns the outstanding requests.
func (s *Store) Pending() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.state.Pending...)
}

// AddPending records a request awaiting approval. An identical outstanding
// request from the same node is returned as-is rather than duplicated, so a
// client that retries in a loop does not flood the queue.
func (s *Store) AddPending(r Request) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := r.Scope.Normalize().String()
	for _, existing := range s.state.Pending {
		if existing.NodeID == r.NodeID && existing.Scope.Normalize().String() == want {
			return existing, nil
		}
	}
	r.Scope = r.Scope.Normalize()
	s.state.Pending = append(s.state.Pending, r)
	if err := s.save(); err != nil {
		return Request{}, err
	}
	return r, nil
}

// Approve turns a pending request into an approval. A zero ttl means the
// approval does not expire.
func (s *Store) Approve(requestID string, ttl time.Duration, now time.Time, newID func() (string, error)) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i, r := range s.state.Pending {
		if r.ID == requestID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Approval{}, fmt.Errorf("request %q: %w", requestID, ErrNotFound)
	}

	req := s.state.Pending[idx]
	id, err := newID()
	if err != nil {
		return Approval{}, err
	}
	approval := Approval{
		ID:         id,
		NodeID:     req.NodeID,
		NodeName:   req.NodeName,
		Grant:      Grant{Repos: req.Scope.Repos, Permissions: req.Scope.Permissions},
		ApprovedAt: now,
	}
	if ttl > 0 {
		approval.ExpiresAt = now.Add(ttl)
	}

	s.state.Pending = append(s.state.Pending[:idx], s.state.Pending[idx+1:]...)
	s.state.Approvals = append(s.state.Approvals, approval)
	if err := s.save(); err != nil {
		return Approval{}, err
	}
	return approval, nil
}

// Deny drops a pending request without approving it.
func (s *Store) Deny(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.state.Pending {
		if r.ID == requestID {
			s.state.Pending = append(s.state.Pending[:i], s.state.Pending[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("request %q: %w", requestID, ErrNotFound)
}

// Revoke removes an approval.
func (s *Store) Revoke(approvalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, a := range s.state.Approvals {
		if a.ID == approvalID {
			s.state.Approvals = append(s.state.Approvals[:i], s.state.Approvals[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("approval %q: %w", approvalID, ErrNotFound)
}

// DropNode removes everything a node holds — its approvals and its
// outstanding requests — and returns how many of each went away.
//
// Pending requests go too. They are latent privilege: leaving them behind
// would let a request the node made before giving up its access be approved
// afterwards, which is precisely what dropping is meant to prevent.
//
// A node that holds nothing is not an error. Surrendering privilege you do
// not have has already achieved what it asked for.
func (s *Store) DropNode(nodeID string) (approvals int, pending int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keptApprovals := s.state.Approvals[:0]
	for _, a := range s.state.Approvals {
		if a.NodeID == nodeID {
			approvals++
			continue
		}
		keptApprovals = append(keptApprovals, a)
	}
	keptPending := s.state.Pending[:0]
	for _, r := range s.state.Pending {
		if r.NodeID == nodeID {
			pending++
			continue
		}
		keptPending = append(keptPending, r)
	}
	if approvals == 0 && pending == 0 {
		return 0, 0, nil
	}
	s.state.Approvals = keptApprovals
	s.state.Pending = keptPending
	if err := s.save(); err != nil {
		return 0, 0, err
	}
	return approvals, pending, nil
}

// PruneExpired drops lapsed approvals and returns how many were removed.
func (s *Store) PruneExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.state.Approvals[:0]
	removed := 0
	for _, a := range s.state.Approvals {
		if a.Expired(now) {
			removed++
			continue
		}
		kept = append(kept, a)
	}
	if removed == 0 {
		return 0, nil
	}
	s.state.Approvals = kept
	return removed, s.save()
}

// save writes the state atomically, so a reader never sees a partial file and
// a crash mid-write cannot lose the existing approvals.
func (s *Store) save() error {
	if s.path == "" {
		return nil // in-memory, for tests
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode approvals: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	tmp := s.path + ".new"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write approvals: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace approvals: %w", err)
	}
	return nil
}

// NewID returns a short random identifier for requests and approvals.
func NewID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
