package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// buildTestResponse creates a DNS response with one A record.
func buildTestResponse() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.MsgHdr.Rcode = dns.RcodeSuccess
	msg.MsgHdr.Id = 0xAAAA // original cached ID
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(93, 184, 216, 34),
	}
	msg.Answer = append(msg.Answer, rr)
	return msg
}

func TestCacheGetFastPath(t *testing.T) {
	cache := newQueryCache()
	msg := buildTestResponse()
	cache.put(msg, "")

	requestID := uint16(0xBBBB)
	buf, gotMsg, ok := cache.get("example.com.", dns.TypeA, dns.ClassINET, requestID, true, dns.DefaultMsgSize, "")
	if !ok {
		t.Fatal("cache get returned false (expected cache hit)")
	}

	// Fast path returns entry.msg directly — should be non-nil
	if gotMsg == nil {
		t.Fatal("gotMsg is nil — fast path should return entry.msg directly")
	}

	// Verify the wire bytes have the patched request ID in bytes [0:2]
	if len(buf) < 2 {
		t.Fatal("buffer too short for DNS header")
	}
	gotID := uint16(buf[0])<<8 | uint16(buf[1])
	if gotID != requestID {
		t.Errorf("patched ID = 0x%04X, want 0x%04X", gotID, requestID)
	}
}

func TestCacheGetSlowPath(t *testing.T) {
	cache := newQueryCache()
	msg := buildTestResponse()
	cache.put(msg, "")

	// Force the storedAt to 2 seconds ago so elapsedSec > 0
	cache.mu.Lock()
	for _, entry := range cache.entries {
		entry.storedAt = time.Now().Add(-2 * time.Second)
		entry.packed = nil // also test the fallback when packed is unavailable
	}
	cache.mu.Unlock()

	requestID := uint16(0xCCCC)
	buf, gotMsg, ok := cache.get("example.com.", dns.TypeA, dns.ClassINET, requestID, true, dns.DefaultMsgSize, "")
	if !ok {
		t.Fatal("cache get returned false (expected cache hit)")
	}
	if gotMsg == nil {
		t.Fatal("gotMsg is nil on slow path")
	}

	// Verify wire bytes have correct ID
	gotID := uint16(buf[0])<<8 | uint16(buf[1])
	if gotID != requestID {
		t.Errorf("patched ID = 0x%04X, want 0x%04X", gotID, requestID)
	}

	// TTLs should be adjusted (300 - 2 = 298)
	if len(gotMsg.Answer) == 0 {
		t.Fatal("no answer RRs in returned message")
	}
	ttl := gotMsg.Answer[0].Header().Ttl
	if ttl != 298 {
		t.Errorf("TTL = %d, want 298 (adjusted from 300 by 2)", ttl)
	}
}

func BenchmarkCacheGetSameSecond(b *testing.B) {
	cache := newQueryCache()
	msg := buildTestResponse()
	cache.put(msg, "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := uint16(i & 0xFFFF)
		buf, gotMsg, ok := cache.get("example.com.", dns.TypeA, dns.ClassINET, id, true, dns.DefaultMsgSize, "")
		if !ok || buf == nil || gotMsg == nil {
			b.Fatal("unexpected cache miss")
		}
	}
}

func BenchmarkCacheGetElapsed(b *testing.B) {
	cache := newQueryCache()
	msg := buildTestResponse()
	cache.put(msg, "")

	// Set storedAt to 2 seconds ago and clear packed to force slow path
	cache.mu.Lock()
	for _, entry := range cache.entries {
		entry.storedAt = time.Now().Add(-2 * time.Second)
		entry.packed = nil
	}
	cache.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := uint16(i & 0xFFFF)
		buf, gotMsg, ok := cache.get("example.com.", dns.TypeA, dns.ClassINET, id, true, dns.DefaultMsgSize, "")
		if !ok || buf == nil || gotMsg == nil {
			b.Fatal("unexpected cache miss")
		}
	}
}
