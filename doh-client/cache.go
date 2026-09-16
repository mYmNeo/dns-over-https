/*
   DNS-over-HTTPS
   Copyright (C) 2017-2018 Star Brilliant <m13253@hotmail.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	Name   string // FQDN lowercased (DNS is case-insensitive)
	Qtype  uint16
	Qclass uint16
	ECS    string // client subnet key, e.g. "203.0.113.0/24"; empty when no ECS
}

// cacheRequest captures the client query parameters needed to reissue an
// upstream lookup for a cached entry.
type cacheRequest struct {
	ECS     string // ecsCacheKey value; empty when no ECS
	UDPSize uint16 // EDNS UDP buffer size of the client query
	DO      bool   // DNSSEC OK bit of the client query
	CD      bool   // CheckingDisabled bit of the client query
}

// cacheFetcher re-resolves a cache key against the upstream. Implementations
// must not write to a DNS client.
type cacheFetcher func(ctx context.Context, key cacheKey, req cacheRequest) (*dns.Msg, error)

// fetchCall coordinates concurrent refreshes of a single cache key.
type fetchCall struct {
	done chan struct{}
	msg  *dns.Msg
	err  error
}

type cacheEntry struct {
	msg      *dns.Msg      // Deep copy of the response (read-only once stored)
	packed   []byte        // Pre-packed wire bytes (msg.Id as stored)
	storedAt time.Time     // When cached
	ttl      time.Duration // Minimum TTL across all Answer RRs
	req      cacheRequest  // retained so an expired entry can be refreshed identically
}

const defaultMaxCacheEntries = 10000

type queryCache struct {
	mu         sync.RWMutex
	entries    map[cacheKey]*cacheEntry
	maxEntries int

	// Background refresh state. inflight coalesces concurrent refreshes of the
	// same key; sem caps how many refreshes may run at once so a burst of
	// expired lookups cannot pile up unbounded upstream queries.
	inflight map[cacheKey]*fetchCall
	fetcher  cacheFetcher
	sem      chan struct{}
	ctx      context.Context
	timeout  time.Duration
}

func newQueryCache() *queryCache {
	return &queryCache{
		entries:    make(map[cacheKey]*cacheEntry),
		maxEntries: defaultMaxCacheEntries,
		inflight:   make(map[cacheKey]*fetchCall),
		sem:        make(chan struct{}, 32),
		ctx:        context.Background(),
	}
}

// ecsCacheKey builds the cache dimension for EDNS Client Subnet.
// An empty string means "no ECS" (shared across clients when no_ecs is set
// or when neither the query nor RemoteAddr yields a global client IP).
func ecsCacheKey(addr net.IP, mask uint8) string {
	if mask == 0 || addr == nil || addr.IsUnspecified() {
		return ""
	}
	return fmt.Sprintf("%s/%d", addr.String(), mask)
}

// get looks up a cached DNS response. It checks expiry, adjusts TTLs downward
// by elapsed time, sets the correct request ID, and returns packed wire bytes.
// The cloned message is also returned so callers can inspect answer IPs
// without a second lookup.
// An expired entry is never served: it is dropped and its upstream query is
// reissued in the background, coalesced per key with any concurrent refresh.
func (qc *queryCache) get(name string, qtype, qclass uint16, requestID uint16, isTCP bool, udpSize uint16, ecs string) ([]byte, *dns.Msg, bool) {
	key := cacheKey{
		Name:   name,
		Qtype:  qtype,
		Qclass: qclass,
		ECS:    ecs,
	}

	qc.mu.RLock()
	entry, found := qc.entries[key]
	qc.mu.RUnlock()

	if !found {
		return nil, nil, false
	}

	elapsed := time.Since(entry.storedAt)
	if elapsed >= entry.ttl {
		// Expired entries are never served. Drop the entry, then refresh it in
		// the background so the next lookup for this key is a hit; scheduleRefresh
		// is called with no lock held and never blocks.
		qc.mu.Lock()
		// Re-check under write lock (another goroutine may have already removed it)
		if e, ok := qc.entries[key]; ok && e.storedAt.Equal(entry.storedAt) {
			delete(qc.entries, key)
		}
		qc.mu.Unlock()
		// Refreshes are coalesced per key, so a stampede of expired lookups for
		// this key costs one upstream query rather than one each.
		qc.scheduleRefresh(key, entry.req)
		return nil, nil, false
	}

	// Fast path: if no time has elapsed and we have pre-packed bytes,
	// patch the 2-byte transaction ID in-place and return without
	// deep-cloning or re-packing. recordResponse only reads Answer
	// IPs transiently (never mutates or retains the pointer), so
	// returning entry.msg directly is safe.
	elapsedSec := uint32(elapsed / time.Second)
	if elapsedSec == 0 && entry.packed != nil {
		if isTCP || len(entry.packed) <= int(udpSize) {
			buf := make([]byte, len(entry.packed))
			copy(buf, entry.packed)
			buf[0] = byte(requestID >> 8)
			buf[1] = byte(requestID)
			return buf, entry.msg, true
		}
	}

	// Slow path: TTLs have changed or pre-packed bytes unavailable.
	// Deep-clone to mutate TTLs and ID without racing.
	clone := entry.msg.Copy()
	clone.Id = requestID

	adjustTTLs(clone.Answer, elapsedSec)
	adjustTTLs(clone.Ns, elapsedSec)
	adjustTTLs(clone.Extra, elapsedSec)

	// Truncate for UDP if needed
	if !isTCP {
		clone.Truncate(int(udpSize))
	}

	buf, err := clone.Pack()
	if err != nil {
		log.Printf("cache: failed to pack cached response: %v\n", err)
		return nil, nil, false
	}

	return buf, clone, true
}

// put stores a DNS response in the cache. Only caches successful responses
// (Rcode == 0) with at least one answer and a positive minimum TTL.
// req is kept on the entry so an expired entry can be refreshed with the same
// upstream parameters it was fetched with; a zero cacheRequest means no ECS.
func (qc *queryCache) put(msg *dns.Msg, req cacheRequest) {
	if msg.Rcode != dns.RcodeSuccess {
		return
	}
	if len(msg.Answer) == 0 {
		return
	}

	// Compute minimum TTL across Answer RRs
	var minTTL uint32
	for i, rr := range msg.Answer {
		ttl := rr.Header().Ttl
		if i == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL == 0 {
		return
	}

	if len(msg.Question) == 0 {
		return
	}

	question := msg.Question[0]
	key := cacheKey{
		Name:   toLowerASCII(question.Name),
		Qtype:  question.Qtype,
		Qclass: question.Qclass,
		ECS:    req.ECS,
	}

	entry := &cacheEntry{
		msg:      msg.Copy(),
		storedAt: time.Now(),
		ttl:      time.Duration(minTTL) * time.Second,
		req:      req,
	}

	// Pre-pack for zero-alloc fast-path on cache hit with elapsedSec == 0
	if packed, err := entry.msg.Pack(); err == nil {
		entry.packed = packed
	}

	qc.mu.Lock()
	// Evict a random entry if the cache is full and this key is new
	if len(qc.entries) >= qc.maxEntries {
		if _, exists := qc.entries[key]; !exists {
			for k := range qc.entries {
				delete(qc.entries, k)
				break
			}
		}
	}
	qc.entries[key] = entry
	qc.mu.Unlock()
}

// setFetcher installs the upstream resolver used by background refreshes. ctx
// outlives individual queries — it is the client's run context — and timeout
// bounds a single refresh. Until it is called, refreshes are disabled.
func (qc *queryCache) setFetcher(ctx context.Context, timeout time.Duration, f cacheFetcher) {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	qc.fetcher = f
	qc.ctx = ctx
	qc.timeout = timeout
}

// fetch resolves key against the upstream, coalescing every concurrent caller
// for that key into a single query. The leader runs the query in a detached
// goroutine so the answer is still stored even when the client that triggered
// it has already gone away; every caller, the leader included, waits for the
// shared result or gives up with its own context.
func (qc *queryCache) fetch(ctx context.Context, key cacheKey, req cacheRequest) (*dns.Msg, error) {
	call, leader := qc.beginFetch(key)
	if leader {
		go qc.runFetch(key, req, call)
	}

	select {
	case <-call.done:
		return call.msg, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// scheduleRefresh reissues the upstream query of an expired entry in the
// background. It must never block — get() calls it on the miss path — and is a
// no-op when no fetcher is installed or the refresh budget is exhausted; in
// that case the caller's own fetch covers the key.
func (qc *queryCache) scheduleRefresh(key cacheKey, req cacheRequest) {
	qc.mu.RLock()
	fetcher := qc.fetcher
	ctx := qc.ctx
	timeout := qc.timeout
	qc.mu.RUnlock()

	if fetcher == nil {
		return
	}

	select {
	case qc.sem <- struct{}{}:
	default:
		return
	}

	go func() {
		defer func() { <-qc.sem }()
		// Derive from the stored long-lived context, never the caller's: the
		// query that triggered this refresh may have returned long ago.
		refreshCtx := ctx
		if refreshCtx == nil {
			refreshCtx = context.Background()
		}
		if timeout > 0 {
			var cancel context.CancelFunc
			refreshCtx, cancel = context.WithTimeout(refreshCtx, timeout)
			defer cancel()
		}
		_, _ = qc.fetch(refreshCtx, key, req)
	}()
}

// beginFetch returns the in-flight call for key, creating and registering it
// when absent. The boolean reports whether the caller is the leader and must
// therefore run the query.
func (qc *queryCache) beginFetch(key cacheKey) (*fetchCall, bool) {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if call, ok := qc.inflight[key]; ok {
		return call, false
	}
	call := &fetchCall{done: make(chan struct{})}
	qc.inflight[key] = call
	return call, true
}

// runFetch performs the upstream query of one in-flight call and publishes its
// result. It runs in its own goroutine so a refresh completes independently of
// the client that triggered it.
func (qc *queryCache) runFetch(key cacheKey, req cacheRequest, call *fetchCall) {
	// Read the resolver configuration under the lock: setFetcher publishes it
	// from another goroutine.
	qc.mu.RLock()
	parent := qc.ctx
	timeout := qc.timeout
	fetcher := qc.fetcher
	qc.mu.RUnlock()

	if parent == nil {
		parent = context.Background()
	}
	fetchCtx := parent
	if timeout > 0 {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(parent, timeout)
		defer cancel()
	}

	var (
		msg *dns.Msg
		err error
	)
	if fetcher == nil {
		err = errors.New("cache: no fetcher installed")
	} else {
		msg, err = fetcher(fetchCtx, key, req)
	}
	if err == nil && msg != nil {
		// Re-store under the same key, replacing the entry that just expired.
		qc.put(msg, req)
	}

	// Waiters are released by close(call.done), so publish in exactly this
	// order: results first, then drop the in-flight registration so no later
	// caller joins a finished call, then close.
	call.msg = msg
	call.err = err
	qc.mu.Lock()
	delete(qc.inflight, key)
	qc.mu.Unlock()
	close(call.done)
}

// startCleanup runs a background goroutine that periodically removes expired
// cache entries. It stops when the provided context is cancelled.
func (qc *queryCache) startCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				qc.cleanup()
			}
		}
	}()
}

// cleanup evicts expired entries. It deliberately does not refresh anything:
// the lookup that misses is what triggers a refresh, and an entry that was
// re-stored in the meantime has a newer storedAt, which the re-check below
// protects from the sweep.
func (qc *queryCache) cleanup() {
	now := time.Now()

	// Collect expired keys under read lock to minimize write lock hold time
	var expired []cacheKey
	qc.mu.RLock()
	for key, entry := range qc.entries {
		if now.Sub(entry.storedAt) >= entry.ttl {
			expired = append(expired, key)
		}
	}
	qc.mu.RUnlock()

	if len(expired) == 0 {
		return
	}

	// Delete expired entries under write lock
	qc.mu.Lock()
	for _, key := range expired {
		// Re-check under write lock in case entry was refreshed
		if entry, ok := qc.entries[key]; ok && now.Sub(entry.storedAt) >= entry.ttl {
			delete(qc.entries, key)
		}
	}
	qc.mu.Unlock()
}

// adjustTTLs decrements the TTL of each RR by elapsedSec, clamping at zero.
func adjustTTLs(rrs []dns.RR, elapsedSec uint32) {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		if h.Ttl > elapsedSec {
			h.Ttl -= elapsedSec
		} else {
			h.Ttl = 0
		}
	}
}
