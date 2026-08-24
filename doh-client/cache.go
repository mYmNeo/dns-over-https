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

type cacheEntry struct {
	msg      *dns.Msg      // Deep copy of the response (read-only once stored)
	packed   []byte        // Pre-packed wire bytes (msg.Id as stored)
	storedAt time.Time     // When cached
	ttl      time.Duration // Minimum TTL across all Answer RRs
}

const defaultMaxCacheEntries = 10000

type queryCache struct {
	mu         sync.RWMutex
	entries    map[cacheKey]*cacheEntry
	maxEntries int
}

func newQueryCache() *queryCache {
	return &queryCache{
		entries:    make(map[cacheKey]*cacheEntry),
		maxEntries: defaultMaxCacheEntries,
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
		// Entry expired — remove it
		qc.mu.Lock()
		// Re-check under write lock (another goroutine may have already removed it)
		if e, ok := qc.entries[key]; ok && e.storedAt.Equal(entry.storedAt) {
			delete(qc.entries, key)
		}
		qc.mu.Unlock()
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
func (qc *queryCache) put(msg *dns.Msg, ecs string) {
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
		ECS:    ecs,
	}

	entry := &cacheEntry{
		msg:      msg.Copy(),
		storedAt: time.Now(),
		ttl:      time.Duration(minTTL) * time.Second,
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
