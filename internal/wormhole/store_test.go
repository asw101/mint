package wormhole

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

var testTime = time.Date(2026, 8, 10, 20, 0, 0, 0, time.UTC)

func testStore() *Store {
	s := New()
	s.SetClock(func() time.Time { return testTime })
	n := 0
	s.SetIDGenerator(func() (string, error) {
		n++
		return fmt.Sprintf("%032x", n), nil
	})
	return s
}

func peer(id string) Peer {
	return Peer{NodeID: id, NodeName: id + ".example.ts.net."}
}

func put(t *testing.T, s *Store, sender, recipient, key string, value []byte) PutResult {
	t.Helper()
	result, err := s.Put(peer(sender), peer(recipient), key, value, DefaultTTL, false)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return result
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestConsumeIsAtomicAndAtMostOnce(t *testing.T) {
	s := testStore()
	put(t, s, "sender", "recipient", "azure/provisioner", []byte("secret"))

	const readers = 32
	var wg sync.WaitGroup
	results := make(chan error, readers)
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			item, err := s.Consume("recipient", "sender", "azure/provisioner")
			if err == nil {
				zero(item.Value)
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var consumed, absent int
	for err := range results {
		switch {
		case err == nil:
			consumed++
		case errors.Is(err, ErrNotFound):
			absent++
		default:
			t.Fatalf("unexpected consume error: %v", err)
		}
	}
	if consumed != 1 || absent != readers-1 {
		t.Fatalf("got %d consumed and %d absent, want one consume", consumed, absent)
	}
}

func TestKeyOnlyConsumeRejectsAmbiguityWithoutConsumingEitherItem(t *testing.T) {
	s := testStore()
	put(t, s, "sender-2", "recipient", "same-key", []byte("from two"))
	put(t, s, "sender-1", "recipient", "same-key", []byte("from one"))

	_, err := s.Consume("recipient", "", "same-key")
	var ambiguous *AmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("Consume got %v, want AmbiguousError", err)
	}
	if len(ambiguous.Senders) != 2 ||
		ambiguous.Senders[0].NodeID != "sender-1" ||
		ambiguous.Senders[1].NodeID != "sender-2" {
		t.Fatalf("candidate senders = %+v, want sender-1 and sender-2", ambiguous.Senders)
	}
	for _, sender := range []string{"sender-1", "sender-2"} {
		item, err := s.Consume("recipient", sender, "same-key")
		if err != nil {
			t.Fatalf("Consume %s after ambiguity: %v", sender, err)
		}
		zero(item.Value)
	}
}

func TestKeyOnlyResolutionHandlesOneOrNoSender(t *testing.T) {
	for _, tc := range []struct {
		name    string
		discard bool
	}{
		{name: "consume"},
		{name: "discard", discard: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore()
			value := []byte("secret")
			put(t, s, "sender", "recipient", "key", value)

			if tc.discard {
				if err := s.Discard("recipient", "", "key"); err != nil {
					t.Fatalf("Discard: %v", err)
				}
				if !allZero(value) {
					t.Fatal("Discard did not zero the resolved value")
				}
				if err := s.Discard("recipient", "", "key"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("second Discard got %v, want ErrNotFound", err)
				}
				return
			}

			item, err := s.Consume("recipient", "", "key")
			if err != nil {
				t.Fatalf("Consume: %v", err)
			}
			if string(item.Value) != "secret" {
				t.Fatalf("Consume returned %q", item.Value)
			}
			zero(item.Value)
			if _, err := s.Consume("recipient", "", "key"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("second Consume got %v, want ErrNotFound", err)
			}
		})
	}
}

func TestListReturnsOnlyRecipientMetadataAndPrunesExpiredItems(t *testing.T) {
	now := testTime
	s := testStore()
	s.SetClock(func() time.Time { return now })
	put(t, s, "sender-2", "recipient", "later", []byte("12345"))
	put(t, s, "sender-1", "recipient", "first", []byte("123"))

	now = now.Add(DefaultTTL)
	live := []byte("1234")
	put(t, s, "sender-4", "recipient", "live", live)
	other := []byte("other")
	put(t, s, "sender-3", "other-recipient", "hidden", other)

	got := s.List("recipient")
	if len(got) != 1 {
		t.Fatalf("List returned %+v, want one live item", got)
	}
	if got[0].Sender.NodeID != "sender-4" || got[0].Key != "live" ||
		got[0].CreatedAt != now || got[0].ExpiresAt != now.Add(DefaultTTL) ||
		got[0].SizeBytes != len(live) {
		t.Errorf("List returned %+v", got[0])
	}
	if _, err := s.Consume("other-recipient", "sender-3", "hidden"); err != nil {
		t.Fatalf("List disturbed another recipient's item: %v", err)
	}
	zero(other)
}

func TestPutRefusesOverwriteUnlessReplacementIsExplicit(t *testing.T) {
	s := testStore()
	old := []byte("old credential")
	put(t, s, "sender", "recipient", "key", old)

	retry := []byte("retry")
	if _, err := s.Put(peer("sender"), peer("recipient"), "key", retry, DefaultTTL, false); !errors.Is(err, ErrOccupied) {
		t.Fatalf("plain overwrite got %v, want ErrOccupied", err)
	}
	if string(retry) != "retry" {
		t.Error("the store modified a rejected value it did not own")
	}
	zero(retry)
	item, err := s.Consume("recipient", "sender", "key")
	if err != nil {
		t.Fatalf("Consume original: %v", err)
	}
	if string(item.Value) != "old credential" {
		t.Fatalf("plain overwrite changed the value to %q", item.Value)
	}
	zero(item.Value)

	old = []byte("old credential")
	second := put(t, s, "sender", "recipient", "key", old)
	replacement := []byte("new credential")
	result, err := s.Put(peer("sender"), peer("recipient"), "key", replacement, DefaultTTL, true)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if !result.Replaced || result.DisplacedID != second.Item.ID {
		t.Errorf("got %+v, want replacement of %s", result, second.Item.ID)
	}
	if !allZero(old) {
		t.Error("replacement did not zero the displaced buffer before returning")
	}
	item, err = s.Consume("recipient", "sender", "key")
	if err != nil {
		t.Fatalf("Consume replacement: %v", err)
	}
	if string(item.Value) != "new credential" {
		t.Errorf("got replacement %q", item.Value)
	}
	zero(item.Value)
}

func TestReplacementNeverExposesAnEmptyTuple(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := testStore()
		old := []byte("old")
		put(t, s, "sender", "recipient", "key", old)

		start := make(chan struct{})
		consumed := make(chan error, 1)
		replaced := make(chan error, 1)
		go func() {
			<-start
			item, err := s.Consume("recipient", "sender", "key")
			if err == nil {
				zero(item.Value)
			}
			consumed <- err
		}()
		go func() {
			<-start
			value := []byte("new")
			_, err := s.Put(peer("sender"), peer("recipient"), "key", value, DefaultTTL, true)
			if err != nil {
				zero(value)
			}
			replaced <- err
		}()
		close(start)

		if err := <-consumed; err != nil {
			t.Fatalf("iteration %d observed an empty tuple during replacement: %v", i, err)
		}
		if err := <-replaced; err != nil {
			t.Fatalf("iteration %d replacement failed: %v", i, err)
		}
		s.Close()
	}
}

func TestReplacementIsBoundedBySender(t *testing.T) {
	s := testStore()
	other := []byte("other sender")
	put(t, s, "sender-2", "recipient", "key", other)
	put(t, s, "sender-1", "recipient", "key", []byte("sender one"))

	replacement := []byte("sender one regenerated")
	result, err := s.Put(peer("sender-1"), peer("recipient"), "key", replacement, DefaultTTL, true)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if !result.Replaced {
		t.Fatal("want sender-1 item replaced")
	}
	item, err := s.Consume("recipient", "sender-2", "key")
	if err != nil {
		t.Fatalf("Consume sender-2: %v", err)
	}
	if string(item.Value) != "other sender" {
		t.Errorf("sender-2 item changed to %q", item.Value)
	}
	zero(item.Value)
}

func TestExpiredOrConsumedItemIsNotAReplacement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(*testing.T, *Store)
	}{
		{
			name: "expired",
			remove: func(t *testing.T, s *Store) {
				testTime = testTime.Add(DefaultTTL)
				t.Cleanup(func() { testTime = testTime.Add(-DefaultTTL) })
			},
		},
		{
			name: "consumed",
			remove: func(t *testing.T, s *Store) {
				item, err := s.Consume("recipient", "sender", "key")
				if err != nil {
					t.Fatal(err)
				}
				zero(item.Value)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore()
			put(t, s, "sender", "recipient", "key", []byte("old"))
			tc.remove(t, s)
			result, err := s.Put(peer("sender"), peer("recipient"), "key", []byte("new"), DefaultTTL, true)
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if result.Replaced || result.DisplacedID != "" {
				t.Errorf("got %+v, want an ordinary put", result)
			}
		})
	}
}

func TestZeroesValuesOnEveryRemovalPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(*Store)
	}{
		{
			name: "consume",
			remove: func(s *Store) {
				item, _ := s.Consume("recipient", "sender", "key")
				zero(item.Value)
			},
		},
		{name: "discard", remove: func(s *Store) { _ = s.Discard("recipient", "sender", "key") }},
		{
			name: "expiry",
			remove: func(s *Store) {
				testTime = testTime.Add(DefaultTTL)
				s.Sweep()
				testTime = testTime.Add(-DefaultTTL)
			},
		},
		{name: "shutdown", remove: func(s *Store) { s.Close() }},
		{name: "drop", remove: func(s *Store) { s.DropRecipient("recipient") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore()
			value := []byte("secret material")
			put(t, s, "sender", "recipient", "key", value)
			tc.remove(s)
			if !allZero(value) {
				t.Errorf("%s left the owned value buffer intact", tc.name)
			}
		})
	}
}

func TestDropRemovesOnlyItemsAddressedToNode(t *testing.T) {
	s := testStore()
	addressed := []byte("for node")
	sent := []byte("from node")
	put(t, s, "sender", "node", "addressed", addressed)
	put(t, s, "node", "recipient", "sent", sent)

	if got := s.DropRecipient("node"); got != 1 {
		t.Fatalf("dropped %d, want one addressed item", got)
	}
	if !allZero(addressed) {
		t.Error("addressed item was not zeroed")
	}
	item, err := s.Consume("recipient", "node", "sent")
	if err != nil {
		t.Fatalf("sent item was removed: %v", err)
	}
	if string(item.Value) != "from node" {
		t.Errorf("got %q", item.Value)
	}
	zero(item.Value)
}

func TestEnforcesKeysValuesTTLsAndQuotas(t *testing.T) {
	for _, key := range []string{"", "bad key", "bad:key", string(make([]byte, MaxKeyBytes+1))} {
		if err := ValidateKey(key); err == nil {
			t.Errorf("ValidateKey(%q): want error", key)
		}
	}
	for _, key := range []string{"a", "azure/provisioner", "a_b-c.d"} {
		if err := ValidateKey(key); err != nil {
			t.Errorf("ValidateKey(%q): %v", key, err)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second, MaxTTL + time.Nanosecond} {
		if err := ValidateTTL(ttl); err == nil {
			t.Errorf("ValidateTTL(%s): want error", ttl)
		}
	}

	s := testStore()
	tooLarge := make([]byte, MaxValueBytes+1)
	if _, err := s.Put(peer("s"), peer("r"), "key", tooLarge, DefaultTTL, false); err == nil {
		t.Fatal("accepted an oversized decoded value")
	}

	tests := []struct {
		name   string
		limits Limits
		puts   []struct{ sender, recipient, key, value string }
	}{
		{
			name:   "recipient",
			limits: Limits{PerRecipient: 1, PerSender: 10, Global: 10, TotalBytes: 100},
			puts: []struct{ sender, recipient, key, value string }{
				{"s1", "r", "one", "a"}, {"s2", "r", "two", "b"},
			},
		},
		{
			name:   "sender",
			limits: Limits{PerRecipient: 10, PerSender: 1, Global: 10, TotalBytes: 100},
			puts: []struct{ sender, recipient, key, value string }{
				{"s", "r1", "one", "a"}, {"s", "r2", "two", "b"},
			},
		},
		{
			name:   "global",
			limits: Limits{PerRecipient: 10, PerSender: 10, Global: 1, TotalBytes: 100},
			puts: []struct{ sender, recipient, key, value string }{
				{"s1", "r1", "one", "a"}, {"s2", "r2", "two", "b"},
			},
		},
		{
			name:   "bytes",
			limits: Limits{PerRecipient: 10, PerSender: 10, Global: 10, TotalBytes: 1},
			puts: []struct{ sender, recipient, key, value string }{
				{"s1", "r1", "one", "a"}, {"s2", "r2", "two", "b"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore()
			s.SetLimits(tc.limits)
			for i, p := range tc.puts {
				value := []byte(p.value)
				_, err := s.Put(peer(p.sender), peer(p.recipient), p.key, value, DefaultTTL, false)
				if i == 0 && err != nil {
					t.Fatalf("first Put: %v", err)
				}
				if i == 1 && !errors.Is(err, ErrQuota) {
					t.Fatalf("second Put got %v, want ErrQuota", err)
				}
				if err != nil {
					zero(value)
				}
			}
		})
	}
}

func TestNewIDHasAtLeast128RandomBits(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 32 {
		t.Errorf("got %d hex characters, want 32", len(id))
	}
}
