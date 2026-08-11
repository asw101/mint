// Package wormhole holds short-lived, consume-once values in memory.
package wormhole

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

const (
	MaxKeyBytes   = 128
	MaxValueBytes = 256 << 10
	DefaultTTL    = 10 * time.Minute
	MaxTTL        = time.Hour
)

var (
	ErrNotFound  = errors.New("wormhole item not found")
	ErrAmbiguous = errors.New("wormhole item has multiple senders")
	ErrOccupied  = errors.New("wormhole tuple occupied")
	ErrQuota     = errors.New("wormhole quota exceeded")

	validKey = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// Limits bounds how much live secret material the daemon retains.
type Limits struct {
	PerRecipient int
	PerSender    int
	Global       int
	TotalBytes   int
}

// DefaultLimits are the v1 mailbox quotas.
var DefaultLimits = Limits{
	PerRecipient: 16,
	PerSender:    32,
	Global:       256,
	TotalBytes:   32 << 20,
}

// Peer is the stable identity and display name of one end of a handoff.
type Peer struct {
	NodeID   string
	NodeName string
}

type address struct {
	recipient string
	sender    string
	key       string
}

// Item is a live handoff. Value is owned by the Store until Consume returns it.
type Item struct {
	ID        string
	Key       string
	Sender    Peer
	Recipient Peer
	CreatedAt time.Time
	ExpiresAt time.Time
	Value     []byte
}

// ItemMetadata describes a live handoff without exposing its value.
type ItemMetadata struct {
	Key       string
	Sender    Peer
	CreatedAt time.Time
	ExpiresAt time.Time
	SizeBytes int
}

// AmbiguousError reports the senders that prevent key-only resolution.
type AmbiguousError struct {
	Senders []Peer
}

func (e *AmbiguousError) Error() string {
	return ErrAmbiguous.Error()
}

func (e *AmbiguousError) Unwrap() error {
	return ErrAmbiguous
}

// PutResult reports whether Put displaced an unconsumed item.
type PutResult struct {
	Item        Item
	Replaced    bool
	DisplacedID string
}

// Event contains only metadata safe for the audit log. Keys are deliberately
// absent because labels often become sensitive too.
type Event struct {
	Action      string
	ItemID      string
	DisplacedID string
	Sender      Peer
	Recipient   Peer
	ExpiresAt   time.Time
	Result      string
}

// Store is an intentionally memory-only mailbox.
type Store struct {
	mu         sync.Mutex
	items      map[address]*Item
	totalBytes int
	limits     Limits
	now        func() time.Time
	newID      func() (string, error)
	onEvent    func(Event)
}

// New returns an empty mailbox with the v1 limits.
func New() *Store {
	return &Store{
		items:  make(map[address]*Item),
		limits: DefaultLimits,
		now:    time.Now,
		newID:  NewID,
	}
}

// SetLimits replaces the quotas. It is intended for tests and must be called
// before the Store is used.
func (s *Store) SetLimits(limits Limits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits = limits
}

// SetClock replaces the clock. It is intended for tests and must be called
// before the Store is used.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// SetIDGenerator replaces the opaque ID generator. It is intended for tests
// and must be called before the Store is used.
func (s *Store) SetIDGenerator(newID func() (string, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.newID = newID
}

// SetEventSink receives audit-safe lifecycle events.
func (s *Store) SetEventSink(onEvent func(Event)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onEvent = onEvent
}

// ValidateKey reports whether key is safe and within the v1 bound.
func ValidateKey(key string) error {
	if len(key) == 0 || len(key) > MaxKeyBytes || !validKey.MatchString(key) {
		return fmt.Errorf("key must be 1-%d bytes of A-Z, a-z, 0-9, dot, underscore, slash, or hyphen", MaxKeyBytes)
	}
	return nil
}

// ValidateTTL reports whether ttl fits the v1 retention window.
func ValidateTTL(ttl time.Duration) error {
	if ttl <= 0 || ttl > MaxTTL {
		return fmt.Errorf("ttl must be greater than zero and no more than %s", MaxTTL)
	}
	return nil
}

// Put installs value at the tuple. The Store takes ownership of value only on
// success; callers must zero it themselves after an error.
func (s *Store) Put(sender, recipient Peer, key string, value []byte, ttl time.Duration, replace bool) (PutResult, error) {
	if err := ValidateKey(key); err != nil {
		return PutResult{}, err
	}
	if err := ValidateTTL(ttl); err != nil {
		return PutResult{}, err
	}
	if len(value) > MaxValueBytes {
		return PutResult{}, fmt.Errorf("value exceeds %d decoded bytes", MaxValueBytes)
	}
	if sender.NodeID == "" || recipient.NodeID == "" {
		return PutResult{}, errors.New("sender and recipient stable node IDs are required")
	}

	id, err := s.newOpaqueID()
	if err != nil {
		return PutResult{}, err
	}
	now := s.currentTime()
	item := Item{
		ID:        id,
		Key:       key,
		Sender:    sender,
		Recipient: recipient,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Value:     value,
	}
	addr := address{recipient: recipient.NodeID, sender: sender.NodeID, key: key}

	s.mu.Lock()
	events := s.pruneExpiredLocked(now)
	existing := s.items[addr]
	if existing != nil && !replace {
		sink := s.onEvent
		s.mu.Unlock()
		s.emit(sink, events)
		return PutResult{}, ErrOccupied
	}
	if err := s.checkQuotaLocked(existing, sender.NodeID, recipient.NodeID, len(value)); err != nil {
		sink := s.onEvent
		s.mu.Unlock()
		s.emit(sink, events)
		return PutResult{}, err
	}

	result := PutResult{Item: item}
	event := Event{
		Action:    "put",
		ItemID:    item.ID,
		Sender:    item.Sender,
		Recipient: item.Recipient,
		ExpiresAt: item.ExpiresAt,
		Result:    "stored",
	}
	if existing != nil {
		result.Replaced = true
		result.DisplacedID = existing.ID
		event.Action = "replace"
		event.DisplacedID = existing.ID
		event.Result = "replaced"
		s.totalBytes -= len(existing.Value)
		zero(existing.Value)
	}
	s.items[addr] = &item
	s.totalBytes += len(value)
	sink := s.onEvent
	s.mu.Unlock()

	s.emit(sink, append(events, event))
	return result, nil
}

// Consume atomically resolves, removes, and returns the matching item. An empty
// senderID resolves only when exactly one sender has the key. The caller owns
// Value and must zero it after writing or abandoning the response.
func (s *Store) Consume(recipientID, senderID, key string) (Item, error) {
	s.mu.Lock()
	now := s.currentTimeLocked()
	events := s.pruneExpiredLocked(now)
	addr, item, err := s.resolveLocked(recipientID, senderID, key)
	if err != nil {
		sink := s.onEvent
		s.mu.Unlock()
		s.emit(sink, events)
		return Item{}, err
	}
	delete(s.items, addr)
	s.totalBytes -= len(item.Value)
	event := eventFor("consume", item, "consumed")
	sink := s.onEvent
	s.mu.Unlock()

	s.emit(sink, append(events, event))
	return *item, nil
}

// Discard atomically resolves, removes, and zeroes the matching item without
// revealing it. An empty senderID resolves only when exactly one sender has the
// key.
func (s *Store) Discard(recipientID, senderID, key string) error {
	s.mu.Lock()
	now := s.currentTimeLocked()
	events := s.pruneExpiredLocked(now)
	addr, item, err := s.resolveLocked(recipientID, senderID, key)
	if err != nil {
		sink := s.onEvent
		s.mu.Unlock()
		s.emit(sink, events)
		return err
	}
	delete(s.items, addr)
	s.totalBytes -= len(item.Value)
	zero(item.Value)
	event := eventFor("discard", item, "discarded")
	sink := s.onEvent
	s.mu.Unlock()

	s.emit(sink, append(events, event))
	return nil
}

// List returns metadata for live items addressed to recipientID.
func (s *Store) List(recipientID string) []ItemMetadata {
	s.mu.Lock()
	now := s.currentTimeLocked()
	events := s.pruneExpiredLocked(now)
	items := make([]ItemMetadata, 0)
	for addr, item := range s.items {
		if addr.recipient != recipientID {
			continue
		}
		items = append(items, ItemMetadata{
			Key:       item.Key,
			Sender:    item.Sender,
			CreatedAt: item.CreatedAt,
			ExpiresAt: item.ExpiresAt,
			SizeBytes: len(item.Value),
		})
	}
	sink := s.onEvent
	s.mu.Unlock()

	s.emit(sink, events)
	sort.Slice(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		if items[i].Key != items[j].Key {
			return items[i].Key < items[j].Key
		}
		return items[i].Sender.NodeID < items[j].Sender.NodeID
	})
	return items
}

// DropRecipient removes and zeroes every item addressed to recipientID. Items
// the same node sent to somebody else are untouched.
func (s *Store) DropRecipient(recipientID string) int {
	now := s.currentTime()

	s.mu.Lock()
	events := s.pruneExpiredLocked(now)
	dropped := 0
	for addr, item := range s.items {
		if addr.recipient != recipientID {
			continue
		}
		delete(s.items, addr)
		s.totalBytes -= len(item.Value)
		zero(item.Value)
		events = append(events, eventFor("drop", item, "discarded"))
		dropped++
	}
	sink := s.onEvent
	s.mu.Unlock()

	s.emit(sink, events)
	return dropped
}

// Sweep removes and zeroes every expired item.
func (s *Store) Sweep() int {
	s.mu.Lock()
	events := s.pruneExpiredLocked(s.currentTimeLocked())
	sink := s.onEvent
	s.mu.Unlock()

	s.emit(sink, events)
	return len(events)
}

// RunSweeper removes expired items periodically until ctx is cancelled.
func (s *Store) RunSweeper(done <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			s.Sweep()
		}
	}
}

// Close removes and zeroes every live item.
func (s *Store) Close() int {
	s.mu.Lock()
	events := make([]Event, 0, len(s.items))
	for addr, item := range s.items {
		delete(s.items, addr)
		zero(item.Value)
		events = append(events, eventFor("shutdown", item, "discarded"))
	}
	s.totalBytes = 0
	sink := s.onEvent
	s.mu.Unlock()

	s.emit(sink, events)
	return len(events)
}

func (s *Store) currentTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentTimeLocked()
}

func (s *Store) currentTimeLocked() time.Time {
	return s.now()
}

func (s *Store) newOpaqueID() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.newID()
}

func (s *Store) checkQuotaLocked(existing *Item, senderID, recipientID string, valueBytes int) error {
	if existing != nil {
		if s.totalBytes-len(existing.Value)+valueBytes > s.limits.TotalBytes {
			return fmt.Errorf("%w: total bytes", ErrQuota)
		}
		return nil
	}
	if len(s.items) >= s.limits.Global {
		return fmt.Errorf("%w: global item limit", ErrQuota)
	}
	if s.totalBytes+valueBytes > s.limits.TotalBytes {
		return fmt.Errorf("%w: total bytes", ErrQuota)
	}
	var senderItems, recipientItems int
	for addr := range s.items {
		if addr.sender == senderID {
			senderItems++
		}
		if addr.recipient == recipientID {
			recipientItems++
		}
	}
	if senderItems >= s.limits.PerSender {
		return fmt.Errorf("%w: sender item limit", ErrQuota)
	}
	if recipientItems >= s.limits.PerRecipient {
		return fmt.Errorf("%w: recipient item limit", ErrQuota)
	}
	return nil
}

func (s *Store) resolveLocked(recipientID, senderID, key string) (address, *Item, error) {
	if senderID != "" {
		addr := address{recipient: recipientID, sender: senderID, key: key}
		item := s.items[addr]
		if item == nil {
			return address{}, nil, ErrNotFound
		}
		return addr, item, nil
	}

	var matchedAddress address
	var matchedItem *Item
	var senders []Peer
	for addr, item := range s.items {
		if addr.recipient != recipientID || addr.key != key {
			continue
		}
		matchedAddress = addr
		matchedItem = item
		senders = append(senders, item.Sender)
	}
	switch len(senders) {
	case 0:
		return address{}, nil, ErrNotFound
	case 1:
		return matchedAddress, matchedItem, nil
	default:
		sort.Slice(senders, func(i, j int) bool {
			if senders[i].NodeName != senders[j].NodeName {
				return senders[i].NodeName < senders[j].NodeName
			}
			return senders[i].NodeID < senders[j].NodeID
		})
		return address{}, nil, &AmbiguousError{Senders: senders}
	}
}

func (s *Store) pruneExpiredLocked(now time.Time) []Event {
	var events []Event
	for addr, item := range s.items {
		if now.Before(item.ExpiresAt) {
			continue
		}
		delete(s.items, addr)
		s.totalBytes -= len(item.Value)
		zero(item.Value)
		events = append(events, eventFor("expire", item, "expired"))
	}
	return events
}

func (s *Store) emit(sink func(Event), events []Event) {
	if sink == nil {
		return
	}
	for _, event := range events {
		sink(event)
	}
}

func eventFor(action string, item *Item, result string) Event {
	return Event{
		Action:    action,
		ItemID:    item.ID,
		Sender:    item.Sender,
		Recipient: item.Recipient,
		ExpiresAt: item.ExpiresAt,
		Result:    result,
	}
}

// NewID returns a 128-bit random identifier encoded for logs and responses.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate wormhole id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
