package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// benchRequestMsg builds a realistic DNS message for benchmarking the client
// Pack + base64-encode hot path. It mirrors the server's benchResponseMsg so
// the two packages' benchmarks use a comparable workload.
func benchRequestMsg() *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.com.", dns.TypeA)
	msg.SetEdns0(4096, false)
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("93.184.216.34"),
	}
	msg.Answer = append(msg.Answer, rr)
	return msg
}

// --- Correctness: prove pooled paths produce identical output ---

// TestClientPackBufferEquivalence proves that PackBuffer into a pooled buffer
// yields byte-identical output to Pack.
func TestClientPackBufferEquivalence(t *testing.T) {
	t.Parallel()

	msg := benchRequestMsg()

	expected, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	bufp := dnsBufferPool.Get().(*[]byte)
	buf := (*bufp)[:cap(*bufp)]
	got, err := msg.PackBuffer(buf)
	if err != nil {
		t.Fatal(err)
	}
	dnsBufferPool.Put(bufp)

	if !bytes.Equal(got, expected) {
		t.Errorf("PackBuffer mismatch: got %d bytes, want %d bytes", len(got), len(expected))
	}
}

// TestClientPooledEncodeEquivalence proves that base64 encoding into a pooled
// buffer yields byte-identical output to EncodeToString.
func TestClientPooledEncodeEquivalence(t *testing.T) {
	t.Parallel()

	msg := benchRequestMsg()
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	expected := base64.RawURLEncoding.EncodeToString(packed)

	encBufp := dnsBufferPool.Get().(*[]byte)
	encLen := base64.RawURLEncoding.EncodedLen(len(packed))
	if cap(*encBufp) < encLen {
		*encBufp = make([]byte, encLen)
	}
	encBuf := (*encBufp)[:encLen]
	base64.RawURLEncoding.Encode(encBuf, packed)
	got := string(encBuf)
	dnsBufferPool.Put(encBufp)

	if got != expected {
		t.Errorf("pooled encode mismatch: got %q, want %q", got, expected)
	}
}

// --- base64 encode: before (EncodeToString) vs after (pooled) ---

// BenchmarkClientBase64EncodeString measures the current allocation pattern:
// base64.RawURLEncoding.EncodeToString allocates a fresh []byte every call.
func BenchmarkClientBase64EncodeString(b *testing.B) {
	msg := benchRequestMsg()
	packed, err := msg.Pack()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = base64.RawURLEncoding.EncodeToString(packed)
	}
}

// BenchmarkClientBase64EncodePooled measures the pooled pattern: encode into a
// buffer fetched from sync.Pool, avoiding the per-call output allocation. The
// only remaining allocation is the unavoidable string conversion for the URL.
func BenchmarkClientBase64EncodePooled(b *testing.B) {
	msg := benchRequestMsg()
	packed, err := msg.Pack()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		encBufp := dnsBufferPool.Get().(*[]byte)
		encLen := base64.RawURLEncoding.EncodedLen(len(packed))
		if cap(*encBufp) < encLen {
			*encBufp = make([]byte, encLen)
		}
		encBuf := (*encBufp)[:encLen]
		base64.RawURLEncoding.Encode(encBuf, packed)
		_ = string(encBuf)
		dnsBufferPool.Put(encBufp)
	}
}

// --- DNS message packing: before (Pack) vs after (PackBuffer + pool) ---

// BenchmarkClientMsgPack measures the current pattern: Msg.Pack() allocates and
// grows a new buffer each call.
func BenchmarkClientMsgPack(b *testing.B) {
	msg := benchRequestMsg()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := msg.Pack()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClientMsgPackBufferPooled measures the pooled pattern: pack into a
// buffer from sync.Pool via Msg.PackBuffer, avoiding per-call allocation.
func BenchmarkClientMsgPackBufferPooled(b *testing.B) {
	msg := benchRequestMsg()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		bufp := dnsBufferPool.Get().(*[]byte)
		buf := (*bufp)[:cap(*bufp)]
		_, err := msg.PackBuffer(buf)
		if err != nil {
			b.Fatal(err)
		}
		dnsBufferPool.Put(bufp)
	}
}

// BenchmarkClientRequestPackEncode measures the full request-build sequence
// (pack the query, then base64-encode it for the GET URL) before and after the
// pooling transformation, demonstrating the combined allocation reduction.
func BenchmarkClientRequestPackEncode(b *testing.B) {
	msg := benchRequestMsg()

	// Before: Pack + EncodeToString (the unoptimized client path).
	b.Run("Before", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			packed, err := msg.Pack()
			if err != nil {
				b.Fatal(err)
			}
			_ = base64.RawURLEncoding.EncodeToString(packed)
		}
	})

	// After: PackBuffer + pooled Encode (the optimized client path).
	b.Run("After", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			bufp := dnsBufferPool.Get().(*[]byte)
			packed, err := msg.PackBuffer((*bufp)[:cap(*bufp)])
			if err != nil {
				b.Fatal(err)
			}
			encBufp := dnsBufferPool.Get().(*[]byte)
			encLen := base64.RawURLEncoding.EncodedLen(len(packed))
			if cap(*encBufp) < encLen {
				*encBufp = make([]byte, encLen)
			}
			encBuf := (*encBufp)[:encLen]
			base64.RawURLEncoding.Encode(encBuf, packed)
			_ = string(encBuf)
			dnsBufferPool.Put(encBufp)
			dnsBufferPool.Put(bufp)
		}
	})
}
