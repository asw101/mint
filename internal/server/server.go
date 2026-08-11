// Package server exposes token minting over the tailnet and an
// administrative surface over a local Unix socket.
//
// The split is deliberate. Token requests arrive from the tailnet and are
// authorized by the caller's tailnet identity; approving those requests is an
// operator action, so it is reachable only from the host the daemon runs on,
// gated by filesystem permissions rather than by anything a client can present.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/asw101/tsapp/internal/app"
	"github.com/asw101/tsapp/internal/policy"
	"github.com/asw101/tsapp/internal/wormhole"
)

// CapName is the tailnet ACL capability this service reads, typed for the
// tailscale API. The string lives in the policy package so denials can name it.
const CapName tailcfg.PeerCapability = policy.CapabilityName

// Identifier reports who a tailnet peer is. *local.Client satisfies it; tests
// supply a fake so the authorization logic needs no tailnet.
type Identifier interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// Minter turns an approved scope into a credential.
type Minter interface {
	Mint(ctx context.Context, scope policy.Scope) (*app.Token, error)
}

// TokenRequest is the client's ask.
type TokenRequest struct {
	Repos       []string          `json:"repos,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

// TokenResponse is returned when a token was minted.
type TokenResponse struct {
	Token       string            `json:"token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Repos       []string          `json:"repos,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
}

// StatusResponse is returned when no token was minted.
type StatusResponse struct {
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// DropResponse reports what a node surrendered.
type DropResponse struct {
	NodeID           string `json:"node_id"`
	NodeName         string `json:"node_name,omitempty"`
	ApprovalsDropped int    `json:"approvals_dropped"`
	PendingDropped   int    `json:"pending_dropped"`
	WormholesDropped int    `json:"wormholes_dropped"`
}

// Server serves both surfaces.
type Server struct {
	Engine *policy.Engine
	Store  *policy.Store
	Who    Identifier
	Minter Minter
	Logger *log.Logger

	Wormhole *wormhole.Store
	Peers    PeerResolver
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

// TailnetHandler serves requests arriving over the tailnet.
func (s *Server) TailnetHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/token", s.handleToken)
	mux.HandleFunc("POST /v1/drop", s.handleDrop)
	mux.HandleFunc("POST /v1/wormhole/put", s.handleWormholePut)
	mux.HandleFunc("POST /v1/wormhole/get", s.handleWormholeGet)
	mux.HandleFunc("POST /v1/wormhole/discard", s.handleWormholeDiscard)
	mux.HandleFunc("GET /v1/wormhole/list", s.handleWormholeList)
	mux.HandleFunc("GET /v1/whoami", s.handleWhoami)
	return mux
}

// AdminHandler serves the operator surface. It performs no authorization of
// its own — whoever can reach the socket is the operator.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/pending", s.handlePending)
	mux.HandleFunc("GET /v1/approvals", s.handleApprovals)
	mux.HandleFunc("POST /v1/approve", s.handleApprove)
	mux.HandleFunc("POST /v1/deny", s.handleDeny)
	mux.HandleFunc("POST /v1/revoke", s.handleRevoke)
	return mux
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	identity, err := s.identify(r)
	if err != nil {
		s.logf("token: unidentified caller %s: %v", r.RemoteAddr, err)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "caller could not be identified"})
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "denied", Reason: "malformed request body"})
		return
	}
	scope := policy.Scope{Repos: req.Repos, Permissions: req.Permissions}

	decision, err := s.Engine.Evaluate(identity, scope)
	if err != nil {
		s.logf("token: %s: evaluate: %v", identity.NodeName, err)
		writeJSON(w, http.StatusInternalServerError, StatusResponse{Status: "error", Reason: "policy evaluation failed"})
		return
	}

	switch decision.Outcome {
	case policy.Denied:
		s.logf("token: DENIED %s (%s) scope=%s: %s",
			identity.NodeName, identity.NodeID, scope, decision.Reason)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: decision.Reason})

	case policy.Pending:
		s.logf("token: PENDING %s (%s) scope=%s request=%s",
			identity.NodeName, identity.NodeID, scope, decision.Request.ID)
		writeJSON(w, http.StatusAccepted, StatusResponse{
			Status:    "pending",
			Reason:    decision.Reason,
			RequestID: decision.Request.ID,
		})

	case policy.Allowed:
		// Mint what the engine decided, which may have had permissions filled
		// in from the policy, not the raw request.
		token, err := s.Minter.Mint(r.Context(), decision.Scope)
		if err != nil {
			s.logf("token: %s: mint: %v", identity.NodeName, err)
			writeJSON(w, http.StatusBadGateway, StatusResponse{Status: "error", Reason: err.Error()})
			return
		}
		// Automatic grants are the ones nobody remembers approving, so they
		// are the ones the audit trail has to capture.
		s.logf("token: ALLOWED %s (%s) scope=%s expires=%s",
			identity.NodeName, identity.NodeID, decision.Scope, token.ExpiresAt.Format(time.RFC3339))
		writeJSON(w, http.StatusOK, TokenResponse{
			Token:       token.Token,
			ExpiresAt:   token.ExpiresAt,
			Repos:       decision.Scope.Repos,
			Permissions: token.Permissions,
		})
	}
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	identity, err := s.identify(r)
	if err != nil {
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "caller could not be identified"})
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

// handleDrop surrenders everything the calling node holds. No human approves
// it, because unlike every other mutation here it can only ever reduce what
// the caller can reach.
//
// The node dropped is always the one the tailnet identified, never one named
// in the request. Reading an id from the body, the query, or a header would
// turn giving up your own access into taking away somebody else's — and the
// caller would need no capability at all to do it.
func (s *Server) handleDrop(w http.ResponseWriter, r *http.Request) {
	identity, err := s.identify(r)
	if err != nil {
		s.logf("drop: unidentified caller %s: %v", r.RemoteAddr, err)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "caller could not be identified"})
		return
	}

	approvals, pending, err := s.Store.DropNode(identity.NodeID)
	if err != nil {
		s.logf("drop: %s: %v", identity.NodeName, err)
		writeJSON(w, http.StatusInternalServerError, StatusResponse{Status: "error", Reason: "could not drop the node's records"})
		return
	}
	wormholes := 0
	if s.Wormhole != nil {
		wormholes = s.Wormhole.DropRecipient(identity.NodeID)
	}
	// A node giving up its own access is as much a change in who may mint as
	// an approval is, so it belongs in the same audit trail.
	s.logf("drop: %s (%s) approvals=%d pending=%d wormholes=%d",
		identity.NodeName, identity.NodeID, approvals, pending, wormholes)
	writeJSON(w, http.StatusOK, DropResponse{
		NodeID:           identity.NodeID,
		NodeName:         identity.NodeName,
		ApprovalsDropped: approvals,
		PendingDropped:   pending,
		WormholesDropped: wormholes,
	})
}

// identify turns a peer address into a policy identity, reading the ACL
// capability that bounds what it may ever be granted.
func (s *Server) identify(r *http.Request) (policy.Identity, error) {
	who, err := s.Who.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return policy.Identity{}, err
	}
	if who == nil || who.Node == nil {
		return policy.Identity{}, fmt.Errorf("no node for %s", r.RemoteAddr)
	}

	// A missing capability is not an error: it means the tailnet policy grants
	// this caller nothing, which the engine reports as denied.
	grants, err := tailcfg.UnmarshalCapJSON[policy.Grant](who.CapMap, CapName)
	if err != nil {
		return policy.Identity{}, fmt.Errorf("parse capability %s: %w", CapName, err)
	}

	identity := policy.Identity{
		NodeID:   string(who.Node.StableID),
		NodeName: who.Node.Name,
		Grants:   grants,
	}
	if who.UserProfile != nil {
		identity.User = who.UserProfile.LoginName
	}
	// A tagged node reports its user as "tagged-devices", so the tags are what
	// a grant's src has to match. Surfacing them is the difference between a
	// guessable and an unguessable denial.
	identity.Tags = append(identity.Tags, who.Node.Tags...)
	return identity, nil
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Pending())
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Approvals())
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID  string `json:"id"`
		TTL string `json:"ttl,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: "malformed request body"})
		return
	}
	var ttl time.Duration
	if body.TTL != "" {
		parsed, err := time.ParseDuration(body.TTL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: err.Error()})
			return
		}
		ttl = parsed
	}

	approval, err := s.Store.Approve(body.ID, ttl, time.Now(), policy.NewID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, StatusResponse{Status: "error", Reason: err.Error()})
		return
	}
	s.logf("approve: %s for %s (%s) scope=%s",
		approval.ID, approval.NodeName, approval.NodeID,
		policy.Scope{Repos: approval.Grant.Repos, Permissions: approval.Grant.Permissions})
	writeJSON(w, http.StatusOK, approval)
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request) {
	s.mutateByID(w, r, "deny", "denied", s.Store.Deny)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	s.mutateByID(w, r, "revoke", "revoked", s.Store.Revoke)
}

// mutateByID takes the past tense explicitly; deriving it by appending "ed"
// produced "revokeed" and "denyed".
func (s *Server) mutateByID(w http.ResponseWriter, r *http.Request, action, done string, fn func(string) error) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: "malformed request body"})
		return
	}
	if err := fn(body.ID); err != nil {
		writeJSON(w, http.StatusNotFound, StatusResponse{Status: "error", Reason: err.Error()})
		return
	}
	s.logf("%s: %s", action, body.ID)
	writeJSON(w, http.StatusOK, StatusResponse{Status: done})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
