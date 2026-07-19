package pubcache

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// store.go — the bounded object store behind the cache.
//
// It is a plain size-capped LRU with a per-object TTL, and it is deliberately
// dumb: it holds only VERIFIED, IMMUTABLE, content-addressed bytes (verify.go
// runs before every put), so it needs no invalidation protocol, no coherence
// story, and no notion of "stale but correct". An entry can only ever be
// evicted or expired — never wrong.
//
// Two independent bounds, both hard:
//   - MaxBytes, enforced by LRU eviction, so the role's memory cost is a number
//     the operator chose rather than a function of what the internet asks for;
//   - TTL, so an object the swarm has moved on from does not occupy the cap
//     forever, and so a cache restarted with a different upstream set converges.
//
// A content address is a name, not a promise (§ 5.5.1): eviction here is not a
// deletion of anything, it is this node ceasing to be one of the holders. That
// is exactly the § 22.6.2 posture — availability is the emergent sum of
// independent holder choices, and dropping an object is always a holder's right.
//
// PINNING (durability by explicit retention) is a deliberate non-feature for
// now: pinned objects would need a persistent store and a real storage budget,
// and this node holds only soft state. A pin-capable holder is a compatible,
// separate implementation of the same role — the wire protocol is identical.

// entry is one cached object.
type entry struct {
	key      string
	body     []byte
	storedAt time.Time
}

// stats is a snapshot of cache counters, exported through the service for
// operator visibility (an operator running a not-blind role should be able to
// see exactly how much of it is running).
type stats struct {
	Hits, Misses, Stores, Evictions, Expired, Rejected uint64
	Objects                                            int
	Bytes                                              int64
}

// store is a concurrency-safe LRU with TTL.
type store struct {
	maxBytes    int64
	maxObjBytes int64
	ttl         time.Duration
	now         func() time.Time

	mu    sync.Mutex
	ll    *list.List // front = most recently used
	items map[string]*list.Element
	bytes int64

	hits, misses, stores, evictions, expired, rejected atomic.Uint64
}

func newStore(maxBytes, maxObjBytes int64, ttl time.Duration, now func() time.Time) *store {
	if now == nil {
		now = time.Now
	}
	return &store{
		maxBytes:    maxBytes,
		maxObjBytes: maxObjBytes,
		ttl:         ttl,
		now:         now,
		ll:          list.New(),
		items:       make(map[string]*list.Element),
	}
}

// cacheKey namespaces an address by the endpoint it was served from. The kinds
// use different addressing rules, so an address verified as one kind is not
// automatically valid as another; keeping them in separate namespaces means a
// verification result is never reused across rules.
func cacheKey(kind Kind, a Addr) string { return kind.String() + ":" + a.String() }

// get returns a live entry's bytes and its store time. An expired entry is
// dropped on the way past — lazy expiry keeps the read path lock-cheap and
// avoids a sweeper goroutine for a store whose entries are already bounded.
func (s *store) get(key string) ([]byte, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.items[key]
	if !ok {
		s.misses.Add(1)
		return nil, time.Time{}, false
	}
	e := el.Value.(*entry)
	if s.ttl > 0 && s.now().Sub(e.storedAt) >= s.ttl {
		s.removeLocked(el)
		s.expired.Add(1)
		s.misses.Add(1)
		return nil, time.Time{}, false
	}
	s.ll.MoveToFront(el)
	s.hits.Add(1)
	return e.body, e.storedAt, true
}

// put stores VERIFIED bytes. The caller MUST have run Verify first; this is the
// only way into the store, and it is unexported precisely so that invariant
// stays checkable by reading one file (service.go).
//
// An object larger than the per-object cap is not stored — it is still served to
// the requester by the caller, it just does not get to evict the rest of the
// cache on its way through.
func (s *store) put(key string, body []byte) {
	if s.maxObjBytes > 0 && int64(len(body)) > s.maxObjBytes {
		s.rejected.Add(1)
		return
	}
	if s.maxBytes > 0 && int64(len(body)) > s.maxBytes {
		s.rejected.Add(1)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.items[key]; ok {
		// Re-storing a content-addressed object can only ever store the same
		// bytes, so refresh recency and TTL rather than churn the entry.
		e := el.Value.(*entry)
		e.storedAt = s.now()
		s.ll.MoveToFront(el)
		return
	}
	e := &entry{key: key, body: body, storedAt: s.now()}
	s.items[key] = s.ll.PushFront(e)
	s.bytes += int64(len(body))
	s.stores.Add(1)
	s.evictLocked()
}

// evictLocked drops least-recently-used entries until the byte cap holds.
func (s *store) evictLocked() {
	for s.maxBytes > 0 && s.bytes > s.maxBytes {
		back := s.ll.Back()
		if back == nil {
			return
		}
		s.removeLocked(back)
		s.evictions.Add(1)
	}
}

func (s *store) removeLocked(el *list.Element) {
	e := el.Value.(*entry)
	s.ll.Remove(el)
	delete(s.items, e.key)
	s.bytes -= int64(len(e.body))
}

func (s *store) stats() stats {
	s.mu.Lock()
	objects, bytes := len(s.items), s.bytes
	s.mu.Unlock()
	return stats{
		Hits:      s.hits.Load(),
		Misses:    s.misses.Load(),
		Stores:    s.stores.Load(),
		Evictions: s.evictions.Load(),
		Expired:   s.expired.Load(),
		Rejected:  s.rejected.Load(),
		Objects:   objects,
		Bytes:     bytes,
	}
}

// purge empties the store (used on shutdown so a stopped role holds nothing).
func (s *store) purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ll.Init()
	s.items = make(map[string]*list.Element)
	s.bytes = 0
}
