package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/asw101/tsapp/internal/policy"
	"github.com/asw101/tsapp/internal/wormhole"
)

const (
	maxWormholePutBody = (wormhole.MaxValueBytes*4+2)/3 + 4096
	maxWormholeBody    = 4096
	wormholeSweepEvery = time.Minute
)

// ErrPeerNotFound lets an injected resolver distinguish an absent name from a
// failure to read the tailnet state.
var ErrPeerNotFound = errors.New("tailnet peer not found")

// ResolvedPeer is the stable target selected from a CLI node name.
type ResolvedPeer struct {
	NodeID   string
	NodeName string
	Tags     []string
}

// PeerResolver resolves a CLI node name to one stable tailnet identity.
type PeerResolver interface {
	ResolvePeer(ctx context.Context, name string) (ResolvedPeer, error)
}

// WormholePutRequest carries bytes from one identified node to one resolved
// recipient. ValueBase64 is decoded by encoding/json without a string
// conversion in application code.
type WormholePutRequest struct {
	To          string `json:"to"`
	Key         string `json:"key"`
	TTL         string `json:"ttl,omitempty"`
	ValueBase64 []byte `json:"value_base64"`
	Replace     bool   `json:"replace,omitempty"`
}

// WormholePutResponse acknowledges metadata only, never the value.
type WormholePutResponse struct {
	ID                string    `json:"id"`
	Key               string    `json:"key"`
	SenderNodeID      string    `json:"sender_node_id"`
	RecipientNodeID   string    `json:"recipient_node_id"`
	RecipientNodeName string    `json:"recipient_node_name"`
	ExpiresAt         time.Time `json:"expires_at"`
	Replaced          bool      `json:"replaced"`
}

// WormholeGetRequest names an optional expected sender. The recipient has no
// request field: it is always the caller identified by WhoIs.
type WormholeGetRequest struct {
	From string `json:"from,omitempty"`
	Key  string `json:"key"`
}

// WormholeGetResponse returns the one consumed value.
type WormholeGetResponse struct {
	ID             string    `json:"id"`
	Key            string    `json:"key"`
	SenderNodeID   string    `json:"sender_node_id"`
	SenderNodeName string    `json:"sender_node_name"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	ValueBase64    []byte    `json:"value_base64"`
}

// WormholeDiscardResponse confirms removal without revealing the value.
type WormholeDiscardResponse struct {
	Status string `json:"status"`
}

// WormholeListItem describes one item without exposing its value.
type WormholeListItem struct {
	SenderNodeID   string    `json:"sender_node_id"`
	SenderNodeName string    `json:"sender_node_name"`
	Key            string    `json:"key"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	SizeBytes      int       `json:"size_bytes"`
}

// WormholeListResponse contains only items addressed to the caller.
type WormholeListResponse struct {
	Items []WormholeListItem `json:"items"`
}

// StartWormhole connects audit logging and starts the periodic expiry sweep.
func (s *Server) StartWormhole(done <-chan struct{}) {
	if s.Wormhole == nil {
		return
	}
	s.Wormhole.SetEventSink(s.logWormholeEvent)
	go s.Wormhole.RunSweeper(done, wormholeSweepEvery)
}

// CloseWormhole zeroes every item still held at shutdown.
func (s *Server) CloseWormhole() {
	if s.Wormhole != nil {
		s.Wormhole.Close()
	}
}

func (s *Server) handleWormholePut(w http.ResponseWriter, r *http.Request) {
	sender, err := s.identify(r)
	if err != nil {
		s.logf("wormhole: PUT caller=%s result=unidentified: %v", r.RemoteAddr, err)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "caller could not be identified"})
		return
	}

	var req WormholePutRequest
	if !decodeWormholeJSON(w, r, maxWormholePutBody, &req) {
		return
	}
	value := req.ValueBase64
	defer func() { zeroBytes(value) }()

	if req.To == "" {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: "to is required"})
		return
	}
	if err := wormhole.ValidateKey(req.Key); err != nil {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: err.Error()})
		return
	}
	if len(value) > wormhole.MaxValueBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, StatusResponse{
			Status: "error",
			Reason: fmt.Sprintf("decoded value exceeds %d bytes", wormhole.MaxValueBytes),
		})
		return
	}
	ttl := wormhole.DefaultTTL
	if req.TTL != "" {
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: "invalid ttl: " + err.Error()})
			return
		}
	}
	if err := wormhole.ValidateTTL(ttl); err != nil {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: err.Error()})
		return
	}

	recipient, err := s.resolvePeer(r, req.To)
	if err != nil {
		s.writePeerResolutionError(w, "PUT", sender, err)
		return
	}
	if !policy.AllowsWormholePut(sender.Grants, recipient.Tags) {
		s.logf("wormhole: PUT sender=%s (%s) recipient=%s (%s) result=denied",
			sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID)
		writeJSON(w, http.StatusForbidden, StatusResponse{
			Status: "denied",
			Reason: "tailnet policy does not allow delivery to the recipient's tags",
		})
		return
	}

	result, err := s.Wormhole.Put(
		wormhole.Peer{NodeID: sender.NodeID, NodeName: sender.NodeName},
		wormhole.Peer{NodeID: recipient.NodeID, NodeName: recipient.NodeName},
		req.Key, value, ttl, req.Replace,
	)
	if err != nil {
		switch {
		case errors.Is(err, wormhole.ErrOccupied):
			s.logf("wormhole: PUT sender=%s (%s) recipient=%s (%s) result=occupied",
				sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID)
			writeJSON(w, http.StatusConflict, StatusResponse{Status: "error", Reason: "wormhole item already exists; pass --replace to replace it explicitly"})
		case errors.Is(err, wormhole.ErrQuota):
			s.logf("wormhole: PUT sender=%s (%s) recipient=%s (%s) result=quota",
				sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID)
			writeJSON(w, http.StatusTooManyRequests, StatusResponse{Status: "error", Reason: err.Error()})
		default:
			s.logf("wormhole: PUT sender=%s (%s) recipient=%s (%s) result=error: %v",
				sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID, err)
			writeJSON(w, http.StatusInternalServerError, StatusResponse{Status: "error", Reason: "could not store wormhole item"})
		}
		return
	}
	// Ownership moved into the mailbox. It will be zeroed on replacement,
	// consume, discard, expiry, drop, or shutdown.
	value = nil
	writeJSON(w, http.StatusCreated, WormholePutResponse{
		ID:                result.Item.ID,
		Key:               result.Item.Key,
		SenderNodeID:      result.Item.Sender.NodeID,
		RecipientNodeID:   result.Item.Recipient.NodeID,
		RecipientNodeName: result.Item.Recipient.NodeName,
		ExpiresAt:         result.Item.ExpiresAt,
		Replaced:          result.Replaced,
	})
}

func (s *Server) handleWormholeGet(w http.ResponseWriter, r *http.Request) {
	recipient, err := s.identify(r)
	if err != nil {
		s.logf("wormhole: GET caller=%s result=unidentified: %v", r.RemoteAddr, err)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "caller could not be identified"})
		return
	}

	var req WormholeGetRequest
	if !decodeWormholeJSON(w, r, maxWormholeBody, &req) {
		return
	}
	if err := wormhole.ValidateKey(req.Key); err != nil {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: err.Error()})
		return
	}
	if !policy.AllowsWormholeGet(recipient.Grants) {
		s.logf("wormhole: GET recipient=%s (%s) result=denied", recipient.NodeName, recipient.NodeID)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "tailnet policy does not allow wormhole get"})
		return
	}

	var sender ResolvedPeer
	if req.From != "" {
		sender, err = s.resolvePeer(r, req.From)
		if err != nil {
			s.writePeerResolutionError(w, "GET", recipient, err)
			return
		}
	}
	item, err := s.Wormhole.Consume(recipient.NodeID, sender.NodeID, req.Key)
	if err != nil {
		switch {
		case errors.Is(err, wormhole.ErrNotFound):
			if sender.NodeID == "" {
				s.logf("wormhole: GET recipient=%s (%s) result=absent",
					recipient.NodeName, recipient.NodeID)
			} else {
				s.logf("wormhole: GET sender=%s (%s) recipient=%s (%s) result=absent",
					sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID)
			}
			writeJSON(w, http.StatusNotFound, StatusResponse{
				Status: "absent",
				Reason: "wormhole item is absent, expired, or already consumed",
			})
			return
		case errors.Is(err, wormhole.ErrAmbiguous):
			s.writeWormholeAmbiguous(w, "GET", recipient, err)
			return
		}
		s.logf("wormhole: GET sender=%s (%s) recipient=%s (%s) result=error: %v",
			sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID, err)
		writeJSON(w, http.StatusInternalServerError, StatusResponse{Status: "error", Reason: "could not consume wormhole item"})
		return
	}
	defer zeroBytes(item.Value)
	writeJSON(w, http.StatusOK, WormholeGetResponse{
		ID:             item.ID,
		Key:            item.Key,
		SenderNodeID:   item.Sender.NodeID,
		SenderNodeName: item.Sender.NodeName,
		CreatedAt:      item.CreatedAt,
		ExpiresAt:      item.ExpiresAt,
		ValueBase64:    item.Value,
	})
}

func (s *Server) handleWormholeDiscard(w http.ResponseWriter, r *http.Request) {
	recipient, err := s.identify(r)
	if err != nil {
		s.logf("wormhole: DISCARD caller=%s result=unidentified: %v", r.RemoteAddr, err)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "caller could not be identified"})
		return
	}

	var req WormholeGetRequest
	if !decodeWormholeJSON(w, r, maxWormholeBody, &req) {
		return
	}
	if err := wormhole.ValidateKey(req.Key); err != nil {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: err.Error()})
		return
	}

	var sender ResolvedPeer
	if req.From != "" {
		sender, err = s.resolvePeer(r, req.From)
		if err != nil {
			s.writePeerResolutionError(w, "DISCARD", recipient, err)
			return
		}
	}
	if err := s.Wormhole.Discard(recipient.NodeID, sender.NodeID, req.Key); err != nil {
		switch {
		case errors.Is(err, wormhole.ErrNotFound):
			if sender.NodeID == "" {
				s.logf("wormhole: DISCARD recipient=%s (%s) result=absent",
					recipient.NodeName, recipient.NodeID)
			} else {
				s.logf("wormhole: DISCARD sender=%s (%s) recipient=%s (%s) result=absent",
					sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID)
			}
			writeJSON(w, http.StatusNotFound, StatusResponse{
				Status: "absent",
				Reason: "wormhole item is absent, expired, or already consumed",
			})
			return
		case errors.Is(err, wormhole.ErrAmbiguous):
			s.writeWormholeAmbiguous(w, "DISCARD", recipient, err)
			return
		}
		s.logf("wormhole: DISCARD sender=%s (%s) recipient=%s (%s) result=error: %v",
			sender.NodeName, sender.NodeID, recipient.NodeName, recipient.NodeID, err)
		writeJSON(w, http.StatusInternalServerError, StatusResponse{Status: "error", Reason: "could not discard wormhole item"})
		return
	}
	writeJSON(w, http.StatusOK, WormholeDiscardResponse{Status: "discarded"})
}

// handleWormholeList reports metadata addressed to the caller identified by
// WhoIs. It never reads a recipient from the body, query, or headers.
func (s *Server) handleWormholeList(w http.ResponseWriter, r *http.Request) {
	recipient, err := s.identify(r)
	if err != nil {
		s.logf("wormhole: LIST caller=%s result=unidentified: %v", r.RemoteAddr, err)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "caller could not be identified"})
		return
	}
	if !policy.AllowsWormholeGet(recipient.Grants) {
		s.logf("wormhole: LIST recipient=%s (%s) result=denied", recipient.NodeName, recipient.NodeID)
		writeJSON(w, http.StatusForbidden, StatusResponse{Status: "denied", Reason: "tailnet policy does not allow wormhole get"})
		return
	}

	metadata := s.Wormhole.List(recipient.NodeID)
	items := make([]WormholeListItem, 0, len(metadata))
	for _, item := range metadata {
		items = append(items, WormholeListItem{
			SenderNodeID:   item.Sender.NodeID,
			SenderNodeName: item.Sender.NodeName,
			Key:            item.Key,
			CreatedAt:      item.CreatedAt,
			ExpiresAt:      item.ExpiresAt,
			SizeBytes:      item.SizeBytes,
		})
	}
	writeJSON(w, http.StatusOK, WormholeListResponse{Items: items})
}

func (s *Server) resolvePeer(r *http.Request, name string) (ResolvedPeer, error) {
	if s.Peers == nil {
		return ResolvedPeer{}, errors.New("peer resolver is not configured")
	}
	return s.Peers.ResolvePeer(r.Context(), name)
}

func (s *Server) writePeerResolutionError(w http.ResponseWriter, action string, caller policy.Identity, err error) {
	if errors.Is(err, ErrPeerNotFound) {
		s.logf("wormhole: %s caller=%s (%s) result=peer-not-found", action, caller.NodeName, caller.NodeID)
		writeJSON(w, http.StatusNotFound, StatusResponse{Status: "error", Reason: "tailnet peer not found"})
		return
	}
	s.logf("wormhole: %s caller=%s (%s) result=resolver-error: %v", action, caller.NodeName, caller.NodeID, err)
	writeJSON(w, http.StatusInternalServerError, StatusResponse{Status: "error", Reason: "could not resolve tailnet peer"})
}

func (s *Server) writeWormholeAmbiguous(w http.ResponseWriter, action string, recipient policy.Identity, err error) {
	var ambiguous *wormhole.AmbiguousError
	if !errors.As(err, &ambiguous) {
		writeJSON(w, http.StatusInternalServerError, StatusResponse{Status: "error", Reason: "could not resolve wormhole sender"})
		return
	}
	names := make([]string, 0, len(ambiguous.Senders))
	for _, sender := range ambiguous.Senders {
		name := sender.NodeName
		if name == "" {
			name = sender.NodeID
		}
		names = append(names, name)
	}
	s.logf("wormhole: %s recipient=%s (%s) candidate-senders=%s result=ambiguous",
		action, recipient.NodeName, recipient.NodeID, strings.Join(names, ","))
	writeJSON(w, http.StatusConflict, StatusResponse{
		Status: "ambiguous",
		Reason: "multiple senders have a wormhole item under this key: " +
			strings.Join(names, ", ") + "; retry with --from",
	})
}

func (s *Server) logWormholeEvent(event wormhole.Event) {
	if event.DisplacedID != "" {
		s.logf("wormhole: %s id=%s displaced=%s sender=%s (%s) recipient=%s (%s) expires=%s result=%s",
			event.Action, event.ItemID, event.DisplacedID,
			event.Sender.NodeName, event.Sender.NodeID,
			event.Recipient.NodeName, event.Recipient.NodeID,
			event.ExpiresAt.Format(time.RFC3339), event.Result)
		return
	}
	s.logf("wormhole: %s id=%s sender=%s (%s) recipient=%s (%s) expires=%s result=%s",
		event.Action, event.ItemID,
		event.Sender.NodeName, event.Sender.NodeID,
		event.Recipient.NodeName, event.Recipient.NodeID,
		event.ExpiresAt.Format(time.RFC3339), event.Result)
}

func decodeWormholeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, StatusResponse{Status: "error", Reason: "request body too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: "malformed request body"})
		}
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, StatusResponse{Status: "error", Reason: "malformed request body"})
		return false
	}
	return true
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
