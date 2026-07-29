package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// benchQueryB64 is a realistic RFC 8484 DoH GET query:
// base64url-encoded DNS query for www.example.com A record, no padding.
const benchQueryB64 = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

// benchResponseMsg builds a realistic DNS response for benchmarking Pack.
func benchResponseMsg() *dns.Msg {
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

func TestPooledDecodeEquivalence(t *testing.T) {
	t.Parallel()

	expected, err := base64.RawURLEncoding.DecodeString(benchQueryB64)
	if err != nil {
		t.Fatal(err)
	}

	src := []byte(benchQueryB64)
	decodedLen := base64.RawURLEncoding.DecodedLen(len(src))
	bufp := dnsBufferPool.Get().(*[]byte)
	if cap(*bufp) < decodedLen {
		*bufp = make([]byte, decodedLen)
	}
	decoded := (*bufp)[:decodedLen]
	n, err := base64.RawURLEncoding.Decode(decoded, src)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded[:n]
	dnsBufferPool.Put(bufp)

	if !bytes.Equal(got, expected) {
		t.Errorf("pooled decode mismatch: got %d bytes, want %d bytes", len(got), len(expected))
	}
}

func TestPackBufferEquivalence(t *testing.T) {
	t.Parallel()

	msg := benchResponseMsg()

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

// --- base64 decode: before (DecodeString) vs after (pooled) ---

// BenchmarkBase64DecodeString measures the current allocation pattern:
// base64.RawURLEncoding.DecodeString allocates a fresh []byte every call.
func BenchmarkBase64DecodeString(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, err := base64.RawURLEncoding.DecodeString(benchQueryB64)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBase64DecodePooled measures the pooled pattern: decode into a
// buffer fetched from sync.Pool, avoiding the per-call output allocation.
func BenchmarkBase64DecodePooled(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		src := []byte(benchQueryB64)
		decodedLen := base64.RawURLEncoding.DecodedLen(len(src))
		bufp := dnsBufferPool.Get().(*[]byte)
		if cap(*bufp) < decodedLen {
			*bufp = make([]byte, decodedLen)
		}
		decoded := (*bufp)[:decodedLen]
		n, err := base64.RawURLEncoding.Decode(decoded, src)
		if err != nil {
			b.Fatal(err)
		}
		_ = decoded[:n]
		dnsBufferPool.Put(bufp)
	}
}

// --- DNS message packing: before (Pack) vs after (PackBuffer + pool) ---

// BenchmarkMsgPack measures the current pattern: Msg.Pack() allocates and
// grows a new buffer each call.
func BenchmarkMsgPack(b *testing.B) {
	msg := benchResponseMsg()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := msg.Pack()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMsgPackBufferPooled measures the pooled pattern: pack into a
// buffer from sync.Pool via Msg.PackBuffer, avoiding per-call allocation.
func BenchmarkMsgPackBufferPooled(b *testing.B) {
	msg := benchResponseMsg()
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
