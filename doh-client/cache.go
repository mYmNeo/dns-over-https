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
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	Name   string // FQDN lowercased (DNS is case-insensitive)
	Qtype  uint16
	Qclass uint16
}

type cacheEntry struct {
	msg      *dns.Msg      // Deep copy of the response
	storedAt time.Time     // When cached
	ttl      time.Duration // Minimum TTL across all Answer RRs
}

type queryCache struct {
	mu      sync.RWMutex
	entries map[cacheKey]*cacheEntry
}

func newQueryCache() *queryCache {
	return &queryCache{
		entries: make(map[cacheKey]*cacheEntry),
	}
}

// get looks up a cached DNS response. It checks expiry, adjusts TTLs downward
// by elapsed time, sets the correct request ID, and returns packed wire bytes.
func (qc *queryCache) get(name string, qtype, qclass uint16, requestID uint16, isTCP bool, udpSize uint16) ([]byte, bool) {
	key := cacheKey{
		Name:   strings.ToLower(name),
		Qtype:  qtype,
		Qclass: qclass,
	}

	qc.mu.RLock()
	entry, found := qc.entries[key]
	qc.mu.RUnlock()

	if !found {
		return nil, false
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
		return nil, false
	}

	// Clone the message so we don't mutate the cached copy
	clone := entry.msg.Copy()
	clone.Id = requestID

	// Adjust TTLs downward by elapsed time
	elapsedSec := uint32(elapsed.Seconds())
	for _, rr := range clone.Answer {
		h := rr.Header()
		if h.Ttl > elapsedSec {
			h.Ttl -= elapsedSec
		} else {
			h.Ttl = 0
		}
	}
	for _, rr := range clone.Ns {
		h := rr.Header()
		if h.Ttl > elapsedSec {
			h.Ttl -= elapsedSec
		} else {
			h.Ttl = 0
		}
	}
	for _, rr := range clone.Extra {
		h := rr.Header()
		if h.Ttl > elapsedSec {
			h.Ttl -= elapsedSec
		} else {
			h.Ttl = 0
		}
	}

	// Truncate for UDP if needed
	if !isTCP {
		clone.Truncate(int(udpSize))
	}

	buf, err := clone.Pack()
	if err != nil {
		log.Printf("cache: failed to pack cached response: %v\n", err)
		return nil, false
	}

	return buf, true
}

// put stores a DNS response in the cache. Only caches successful responses
// (Rcode == 0) with at least one answer and a positive minimum TTL.
func (qc *queryCache) put(msg *dns.Msg) {
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

	question := msg.Question[0]
	key := cacheKey{
		Name:   strings.ToLower(question.Name),
		Qtype:  question.Qtype,
		Qclass: question.Qclass,
	}

	entry := &cacheEntry{
		msg:      msg.Copy(),
		storedAt: time.Now(),
		ttl:      time.Duration(minTTL) * time.Second,
	}

	qc.mu.Lock()
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
	qc.mu.Lock()
	defer qc.mu.Unlock()
	for key, entry := range qc.entries {
		if now.Sub(entry.storedAt) >= entry.ttl {
			delete(qc.entries, key)
		}
	}
}
