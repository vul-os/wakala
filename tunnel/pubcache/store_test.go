package pubcache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// store_test.go — the bounded-store contract: hit, miss, LRU eviction, TTL
// expiry, oversize refusal. These are the properties that keep an internet-facing
// cache's memory cost a number the OPERATOR chose.

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestStoreHitAndMiss(t *testing.T) {
	s := newStore(1<<20, 1<<16, time.Hour, nil)
	if _, _, ok := s.get("chunk:a"); ok {
		t.Fatal("empty store reported a hit")
	}
	s.put("chunk:a", []byte("bytes"))
	body, _, ok := s.get("chunk:a")
	if !ok || string(body) != "bytes" {
		t.Fatalf("expected hit with stored bytes, got %q ok=%v", body, ok)
	}
	st := s.stats()
	if st.Hits != 1 || st.Misses != 1 || st.Objects != 1 || st.Bytes != 5 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

// TestStoreEvictsLeastRecentlyUsed: the byte cap is hard, and the victim is the
// least recently USED entry, not the least recently stored.
func TestStoreEvictsLeastRecentlyUsed(t *testing.T) {
	// Cap of 30 bytes fits exactly three 10-byte objects.
	s := newStore(30, 30, time.Hour, nil)
	ten := func(c byte) []byte { return []byte(fmt.Sprintf("%c123456789", c)) }
	s.put("chunk:a", ten('a'))
	s.put("chunk:b", ten('b'))
	s.put("chunk:c", ten('c'))
	// Touch a so b becomes the LRU victim.
	if _, _, ok := s.get("chunk:a"); !ok {
		t.Fatal("a should still be cached")
	}
	s.put("chunk:d", ten('d'))

	if _, _, ok := s.get("chunk:b"); ok {
		t.Fatal("b should have been evicted as least-recently-used")
	}
	for _, k := range []string{"chunk:a", "chunk:c", "chunk:d"} {
		if _, _, ok := s.get(k); !ok {
			t.Fatalf("%s should still be cached", k)
		}
	}
	if st := s.stats(); st.Evictions != 1 || st.Bytes > 30 {
		t.Fatalf("cap breached or wrong eviction count: %+v", st)
	}
}

func TestStoreTTLExpiry(t *testing.T) {
	clk := newFakeClock()
	s := newStore(1<<20, 1<<16, 10*time.Minute, clk.now)
	s.put("chunk:a", []byte("x"))

	clk.advance(9 * time.Minute)
	if _, _, ok := s.get("chunk:a"); !ok {
		t.Fatal("entry expired early")
	}
	clk.advance(2 * time.Minute)
	if _, _, ok := s.get("chunk:a"); ok {
		t.Fatal("entry served past its TTL")
	}
	st := s.stats()
	if st.Expired != 1 || st.Objects != 0 || st.Bytes != 0 {
		t.Fatalf("expired entry not reclaimed: %+v", st)
	}
}

// TestStoreRefusesOversizeObject: a huge object is not allowed to evict the
// whole cache on its way through.
func TestStoreRefusesOversizeObject(t *testing.T) {
	s := newStore(1000, 100, time.Hour, nil)
	s.put("chunk:small", []byte("ok"))
	s.put("chunk:big", make([]byte, 101))
	if _, _, ok := s.get("chunk:big"); ok {
		t.Fatal("oversize object was stored")
	}
	if _, _, ok := s.get("chunk:small"); !ok {
		t.Fatal("oversize put disturbed an existing entry")
	}
	if st := s.stats(); st.Rejected != 1 {
		t.Fatalf("oversize rejection not counted: %+v", st)
	}
}

// TestStoreRePutRefreshesRatherThanDuplicates: a content-addressed re-store can
// only ever be the same bytes, so it must refresh recency, not double-count.
func TestStoreRePutRefreshesRatherThanDuplicates(t *testing.T) {
	clk := newFakeClock()
	s := newStore(1<<20, 1<<16, 10*time.Minute, clk.now)
	s.put("chunk:a", []byte("hello"))
	clk.advance(9 * time.Minute)
	s.put("chunk:a", []byte("hello"))
	clk.advance(5 * time.Minute) // past the original TTL, inside the refreshed one
	if _, _, ok := s.get("chunk:a"); !ok {
		t.Fatal("re-stored entry did not have its TTL refreshed")
	}
	if st := s.stats(); st.Objects != 1 || st.Bytes != 5 {
		t.Fatalf("re-store duplicated the entry: %+v", st)
	}
}

func TestStorePurge(t *testing.T) {
	s := newStore(1<<20, 1<<16, time.Hour, nil)
	s.put("chunk:a", []byte("x"))
	s.purge()
	if st := s.stats(); st.Objects != 0 || st.Bytes != 0 {
		t.Fatalf("purge left state behind: %+v", st)
	}
}

func TestStoreConcurrentAccess(t *testing.T) {
	s := newStore(4096, 512, time.Hour, nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k := fmt.Sprintf("chunk:%d", (i*j)%64)
				s.put(k, []byte(k))
				s.get(k)
			}
		}(i)
	}
	wg.Wait()
	if st := s.stats(); st.Bytes > 4096 {
		t.Fatalf("byte cap breached under concurrency: %+v", st)
	}
}
