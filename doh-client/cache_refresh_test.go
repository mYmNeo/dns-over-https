package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// These tests defend the expiry-triggered refresh contract: an expired entry is
// never served, its upstream query is reissued in the background, and every
// concurrent lookup for one key shares a single upstream query.

// refreshAnswer builds a one-answer response for name. The refresh tests use it
// both as the entry that expires and as the upstream answer, so the refreshed
// data is distinguishable from the original by its address.
func refreshAnswer(name, ip string, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Question = []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	})
	return msg
}

// answerIPv4 returns the address of the first A record in msg, or "" when the
// message carries none.
func answerIPv4(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// expireAll backdates every stored entry so it looks expired. Expiry is forced
// by rewriting storedAt rather than by sleeping, which keeps the tests
// deterministic; callers must not run it while a refresh is in flight.
func expireAll(cache *queryCache) {
	cache.mu.Lock()
	for _, entry := range cache.entries {
		entry.storedAt = time.Now().Add(-2 * entry.ttl)
	}
	cache.mu.Unlock()
}

// waitForCacheHit waits for the detached refresh to publish its answer. A hit
// for the key is the only evidence that put() ran: runFetch stores the answer
// after the fetcher returns, so collecting the fetcher's result is not enough.
func waitForCacheHit(t *testing.T, cache *queryCache, name, ecs string) *dns.Msg {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, msg, ok := cache.get(name, dns.TypeA, dns.ClassINET, 7, true, dns.DefaultMsgSize, ecs); ok {
			return msg
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %q to be refreshed into the cache", name)
		}
		time.Sleep(time.Millisecond)
	}
}

// settleRefresh blocks until the background refresh of key is over, by joining
// it: fetch returns only once the shared call has published its outcome, so a
// returned fetch proves the refresh has stored its answer or discarded its
// error. Joining an already-finished refresh runs a fresh one instead, which is
// equally settled by the time it returns.
func settleRefresh(t *testing.T, cache *queryCache, key cacheKey, req cacheRequest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = cache.fetch(ctx, key, req)
	if ctx.Err() != nil {
		t.Fatal("background refresh did not finish within the deadline")
	}
}

func TestExpiredEntryIsRefreshedNotServed(t *testing.T) {
	// Invariant: a lookup that finds an expired entry reports a miss — the stale
	// answer never reaches the client — while the entry is re-resolved upstream
	// with the very parameters it was stored with, so the next lookup is a hit.
	cache := newQueryCache()
	name := "refresh.example."
	ecsA := ecsCacheKey(net.ParseIP("203.0.113.10"), 24)
	if ecsA == "" {
		t.Fatal("ecsCacheKey returned empty for a global IPv4 address")
	}
	req := cacheRequest{ECS: ecsA, UDPSize: 1232, DO: true, CD: true}
	cache.put(refreshAnswer(name, "198.51.100.1", 300), req)
	expireAll(cache)

	// observation carries what the refresh asked upstream. It travels over the
	// channel so the fetcher's writes are ordered before the test's reads.
	type observation struct {
		key cacheKey
		req cacheRequest
	}
	var calls atomic.Int64
	called := make(chan observation, 512)
	cache.setFetcher(context.Background(), 5*time.Second, func(ctx context.Context, key cacheKey, r cacheRequest) (*dns.Msg, error) {
		calls.Add(1)
		called <- observation{key: key, req: r}
		return refreshAnswer(name, "198.51.100.7", 300), nil
	})

	buf, msg, ok := cache.get(name, dns.TypeA, dns.ClassINET, 0x1234, true, dns.DefaultMsgSize, ecsA)
	if ok || buf != nil || msg != nil {
		t.Fatalf("expired entry was served: ok=%v bytes=%d msg=%v", ok, len(buf), msg != nil)
	}

	var seen observation
	select {
	case seen = <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("expired entry did not trigger a background refresh")
	}

	refreshed := waitForCacheHit(t, cache, name, ecsA)
	if got := answerIPv4(refreshed); got != "198.51.100.7" {
		t.Errorf("refreshed answer = %q, want 198.51.100.7", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("fetcher calls = %d, want 1", n)
	}
	wantKey := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET, ECS: ecsA}
	if seen.key != wantKey {
		t.Errorf("refreshed key = %+v, want %+v", seen.key, wantKey)
	}
	if seen.req != req {
		t.Errorf("refreshed request = %+v, want %+v (refresh must reuse the client's parameters)", seen.req, req)
	}
}

func TestCompletedRefreshReleasesItsKey(t *testing.T) {
	// Invariant: a completed refresh retires its in-flight call, so the next
	// lookup for that key starts a new upstream query. A call left registered
	// would let later callers join a closed call and collect its old answer
	// without querying anything, pinning the entry to a stale answer for the
	// life of the process. fetch returns only after the call is retired, so
	// these two calls are strictly ordered and the count is exact.
	cache := newQueryCache()
	key := cacheKey{Name: "repeat.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	req := cacheRequest{UDPSize: 1232}

	var calls atomic.Int64
	cache.setFetcher(context.Background(), 5*time.Second, func(ctx context.Context, _ cacheKey, _ cacheRequest) (*dns.Msg, error) {
		// A distinct address per call, so a reused answer is visible.
		return refreshAnswer(key.Name, fmt.Sprintf("198.51.100.%d", calls.Add(1)+1), 300), nil
	})

	first, err := cache.fetch(context.Background(), key, req)
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if got := answerIPv4(first); got != "198.51.100.2" {
		t.Fatalf("first fetch answered %q, want 198.51.100.2", got)
	}

	second, err := cache.fetch(context.Background(), key, req)
	if err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	if got := answerIPv4(second); got != "198.51.100.3" {
		t.Errorf("second fetch answered %q, want 198.51.100.3 (it reused the finished call)", got)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("fetcher calls = %d, want 2 (a finished refresh must not be joined)", n)
	}
}

func TestConcurrentFetchesCoalesce(t *testing.T) {
	// Invariant: a lookup that arrives while a refresh is in flight joins that
	// one upstream query instead of starting its own, so a stampede of callers
	// for one key costs a single fetch and shares its answer.
	cache := newQueryCache()
	key := cacheKey{Name: "coalesce.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	release := make(chan struct{})
	// Buffered so an implementation that calls the fetcher more than once
	// cannot wedge it and turn a failed assertion into a hung test.
	entered := make(chan struct{}, 512)
	var calls atomic.Int64
	cache.setFetcher(context.Background(), 5*time.Second, func(ctx context.Context, _ cacheKey, _ cacheRequest) (*dns.Msg, error) {
		calls.Add(1)
		entered <- struct{}{}
		// Hold the query open until the joiners have been accounted for, so the
		// coalescing assertion cannot depend on scheduling luck.
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return refreshAnswer(key.Name, "203.0.113.99", 300), nil
	})

	type result struct {
		msg *dns.Msg
		err error
	}
	leader := make(chan result, 1)
	go func() {
		msg, err := cache.fetch(context.Background(), key, cacheRequest{})
		leader <- result{msg: msg, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fetcher was never invoked")
	}

	// The shared query is registered and blocked upstream, so a joiner that
	// arrives now must find it rather than start a second query. The joiners
	// use an already-cancelled context so each of them returns as soon as it
	// has looked up the in-flight call — that is their barrier: once they have
	// all returned, none can still be on its way into fetch(). A query of their
	// own would call the fetcher again.
	const joiners = 31
	var wg sync.WaitGroup
	for i := 0; i < joiners; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		wg.Add(1)
		go func(ctx context.Context) {
			defer wg.Done()
			cache.fetch(ctx, key, cacheRequest{})
		}(ctx)
	}
	joinersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(joinersDone)
	}()
	select {
	case <-joinersDone:
	case <-time.After(5 * time.Second):
		// Unblock everyone still waiting, then fail: a joiner that would not
		// return on its own cancelled context is the bug under test.
		close(release)
		t.Fatal("joiners stayed blocked instead of returning on their own context")
	}
	close(release)

	select {
	case got := <-leader:
		if got.err != nil {
			t.Fatalf("leader fetch failed: %v", got.err)
		}
		if got.msg == nil {
			t.Fatal("leader fetch returned a nil message")
		}
		if ip := answerIPv4(got.msg); ip != "203.0.113.99" {
			t.Errorf("leader answer = %q, want 203.0.113.99", ip)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader fetch never returned after the upstream query completed")
	}

	// Every joiner has returned and the shared query has finished, so no further
	// fetch can still be on its way: the count below is final.
	if n := calls.Load(); n != 1 {
		t.Errorf("fetcher calls = %d, want 1 (joiners must share the in-flight query)", n)
	}

	// The answer is published only after it is stored, so the refresh must be a
	// cache hit by the time fetch returned.
	if _, msg, ok := cache.get(key.Name, dns.TypeA, dns.ClassINET, 5, true, dns.DefaultMsgSize, ""); !ok || msg == nil {
		t.Fatalf("refreshed answer was not cached: hit=%v msg=%v", ok, msg != nil)
	}
}

func TestDistinctKeysAreNotCoalesced(t *testing.T) {
	// Invariant: coalescing is per key. Two different keys in flight at the same
	// time must each reach the upstream, or one query would answer for another.
	cache := newQueryCache()
	keys := []cacheKey{
		{Name: "distinct-a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "distinct-b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	// Each key must be answered by its own query, so the fetcher echoes the key
	// it was asked about. A shared in-flight slot would hand one caller the
	// other's answer as well as skipping a query.
	release := make(chan struct{})
	arrived := make(chan struct{}, 512)
	var calls atomic.Int64
	cache.setFetcher(context.Background(), 5*time.Second, func(ctx context.Context, key cacheKey, _ cacheRequest) (*dns.Msg, error) {
		calls.Add(1)
		arrived <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return refreshAnswer(key.Name, "203.0.113.7", 300), nil
	})

	msgs := make([]*dns.Msg, len(keys))
	errs := make([]error, len(keys))
	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Add(1)
		go func(i int, key cacheKey) {
			defer wg.Done()
			msgs[i], errs[i] = cache.fetch(context.Background(), key, cacheRequest{})
		}(i, key)
	}

	// Both fetches must be reached while neither is allowed to finish, which is
	// only possible if the two calls were in flight at the same time.
	for i := range keys {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d keys reached the fetcher", i, len(keys))
		}
	}
	close(release)
	wg.Wait()

	for i := range keys {
		if errs[i] != nil {
			t.Errorf("fetch %d returned error: %v", i, errs[i])
		}
		if msgs[i] == nil {
			t.Errorf("fetch %d returned a nil message", i)
			continue
		}
		if len(msgs[i].Question) != 1 || msgs[i].Question[0].Name != keys[i].Name {
			t.Errorf("fetch %d answered for %+v, want %q", i, msgs[i].Question, keys[i].Name)
		}
	}
	if n := calls.Load(); n != int64(len(keys)) {
		t.Errorf("fetcher calls = %d, want %d (distinct keys must not share a call)", n, len(keys))
	}
}

func TestFetchWithoutFetcherErrors(t *testing.T) {
	// Invariant: with no fetcher installed a fetch fails loudly instead of
	// panicking or blocking forever — the caller's own query machinery covers it.
	cache := newQueryCache()
	key := cacheKey{Name: "nofetcher.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	type result struct {
		msg *dns.Msg
		err error
	}
	done := make(chan result, 1)
	go func() {
		msg, err := cache.fetch(context.Background(), key, cacheRequest{})
		done <- result{msg: msg, err: err}
	}()

	select {
	case got := <-done:
		if got.err == nil {
			t.Fatal("fetch returned nil error with no fetcher installed")
		}
		if got.msg != nil {
			t.Errorf("fetch returned a message alongside its error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetch hung with no fetcher installed")
	}
}

func TestNoFetcherLeavesRefreshIdle(t *testing.T) {
	// Invariant: without a fetcher the refresh machinery stays completely idle.
	// Unit tests that only exercise get()/cleanup() go through the same expired
	// path and must not re-resolve anything: the miss is final, cleanup() is a
	// pure sweep, and neither panics nor resurrects the stale answer.
	cache := newQueryCache()
	name := "norefresh.example."
	cache.put(refreshAnswer(name, "198.51.100.1", 300), cacheRequest{})
	expireAll(cache)

	key := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cache.scheduleRefresh(key, cacheRequest{})
	cache.cleanup()

	if _, msg, ok := cache.get(name, dns.TypeA, dns.ClassINET, 1, true, dns.DefaultMsgSize, ""); ok {
		t.Fatalf("expired entry was served with no fetcher installed: msg=%v", msg != nil)
	}
	cache.cleanup()

	// A second lookup must still miss: had the sweep or the expired path
	// re-stored anything, it would surface here as a servable entry.
	if _, msg, ok := cache.get(name, dns.TypeA, dns.ClassINET, 2, true, dns.DefaultMsgSize, ""); ok {
		t.Fatalf("an entry reappeared without a fetcher: msg=%v", msg != nil)
	}
}

func TestFetchFailureCachesNothing(t *testing.T) {
	// Invariant: a failed upstream query yields only an error. It must not be
	// cached as a response for a key that had no entry.
	cache := newQueryCache()
	key := cacheKey{Name: "fail.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	cache.setFetcher(context.Background(), 5*time.Second, func(ctx context.Context, _ cacheKey, _ cacheRequest) (*dns.Msg, error) {
		return nil, errors.New("upstream unavailable")
	})

	msg, err := cache.fetch(context.Background(), key, cacheRequest{})
	if err == nil {
		t.Fatal("fetch returned nil error for a failing fetcher")
	}
	if msg != nil {
		t.Error("fetch returned a message alongside its error")
	}
	if _, msg, ok := cache.get(key.Name, dns.TypeA, dns.ClassINET, 1, true, dns.DefaultMsgSize, ""); ok {
		t.Fatalf("a failed refresh was served as a cache hit: msg=%v", msg != nil)
	}
}

func TestExpiredEntryRefreshFailureStaysMiss(t *testing.T) {
	// Invariant: when the refresh of an expired entry fails, the stale answer
	// stays gone. Nothing is resurrected and no error is cached, so the next
	// lookup is still a miss and the caller resolves it itself.
	cache := newQueryCache()
	name := "stale.example."
	cache.put(refreshAnswer(name, "198.51.100.1", 300), cacheRequest{})
	expireAll(cache)

	failed := make(chan struct{}, 512)
	cache.setFetcher(context.Background(), 5*time.Second, func(ctx context.Context, _ cacheKey, _ cacheRequest) (*dns.Msg, error) {
		failed <- struct{}{}
		return nil, errors.New("upstream unavailable")
	})

	if _, _, ok := cache.get(name, dns.TypeA, dns.ClassINET, 1, true, dns.DefaultMsgSize, ""); ok {
		t.Fatal("expired entry was served")
	}
	select {
	case <-failed:
	case <-time.After(5 * time.Second):
		t.Fatal("expired entry did not trigger a refresh")
	}

	// Join the refresh so the assertions below run after its error path has
	// discarded the result, not while it is still in flight.
	key := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	settleRefresh(t, cache, key, cacheRequest{})

	if _, msg, ok := cache.get(name, dns.TypeA, dns.ClassINET, 2, true, dns.DefaultMsgSize, ""); ok {
		t.Fatalf("a failed refresh left a servable entry behind: msg=%v", msg != nil)
	}
}

func TestPutRetainsRequestIdentity(t *testing.T) {
	// Invariant: an entry keeps the client's query parameters, because an expired
	// entry can only be refreshed identically if the UDP size and the DO/CD bits
	// survive the round trip.
	cache := newQueryCache()
	name := "identity.example."
	ecsA := ecsCacheKey(net.ParseIP("203.0.113.10"), 24)
	if ecsA == "" {
		t.Fatal("ecsCacheKey returned empty for a global IPv4 address")
	}
	req := cacheRequest{ECS: ecsA, UDPSize: 1232, DO: true, CD: true}

	cache.put(refreshAnswer(name, "198.51.100.1", 300), req)

	key := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET, ECS: ecsA}
	cache.mu.RLock()
	entry, found := cache.entries[key]
	var got cacheRequest
	if found {
		got = entry.req
	}
	cache.mu.RUnlock()

	if !found {
		t.Fatal("entry was not stored under the request's ECS dimension")
	}
	if got != req {
		t.Errorf("retained request = %+v, want %+v", got, req)
	}
	if _, _, ok := cache.get(name, dns.TypeA, dns.ClassINET, 1, true, dns.DefaultMsgSize, ecsA); !ok {
		t.Fatal("expected a hit for the stored ECS dimension")
	}
}

func TestCacheConcurrentRefreshMix(t *testing.T) {
	// Invariant: get, put, fetch and cleanup may run concurrently against one
	// cache. Run under -race, this is what proves the locking is sound; the mix
	// overlaps keys and keeps the cache at its eviction bound so stores,
	// refreshes and sweeps contend on the same entries.
	cache := newQueryCache()
	cache.maxEntries = 3
	var calls atomic.Int64
	cache.setFetcher(context.Background(), 5*time.Second, func(ctx context.Context, key cacheKey, _ cacheRequest) (*dns.Msg, error) {
		calls.Add(1)
		return refreshAnswer(key.Name, "203.0.113.5", 300), nil
	})

	names := []string{"race0.example.", "race1.example.", "race2.example.", "race3.example."}
	ecs := ecsCacheKey(net.ParseIP("203.0.113.10"), 24)
	const workers = 8
	const iterations = 40

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := names[(w+i)%len(names)]
				switch w % 4 {
				case 0:
					cache.get(name, dns.TypeA, dns.ClassINET, uint16(i), true, dns.DefaultMsgSize, ecs)
				case 1:
					cache.put(refreshAnswer(name, "203.0.113.5", 300), cacheRequest{ECS: ecs})
				case 2:
					key := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET, ECS: ecs}
					cache.fetch(context.Background(), key, cacheRequest{ECS: ecs})
				case 3:
					cache.cleanup()
				}
			}
		}(w)
	}
	wg.Wait()

	// A refresh must actually run somewhere in the mix: without fetch() the
	// locking around the in-flight map would go untested.
	if calls.Load() == 0 {
		t.Error("no refresh ran: the mix did not exercise fetch")
	}

	// Raise the bound so a straggling refresh cannot evict the probe entry,
	// then prove the cache is still usable after all that contention.
	cache.mu.Lock()
	cache.maxEntries = defaultMaxCacheEntries
	cache.mu.Unlock()

	cache.put(refreshAnswer("post-race.example.", "203.0.113.1", 300), cacheRequest{ECS: ecs})
	if _, msg, ok := cache.get("post-race.example.", dns.TypeA, dns.ClassINET, 9, true, dns.DefaultMsgSize, ecs); !ok || msg == nil {
		t.Fatalf("cache unusable after concurrent get/put/fetch/cleanup: hit=%v msg=%v", ok, msg != nil)
	}
}
