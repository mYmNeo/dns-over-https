package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestAdjustTTLsSkipsOPT(t *testing.T) {
	// Create an OPT record with DO bit set
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetDo() // sets the DNSSEC OK bit in the TTL field

	// Create an A record with a real TTL
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("1.2.3.4").To4(),
	}

	// Verify the OPT DO bit is set before call
	if opt.Do() != true {
		t.Fatal("expected DO bit set before adjustTTLs")
	}

	// Save original TTL value to verify it's unchanged
	origOPT := opt.Hdr.Ttl

	// Append OPT to Extra alongside the A record on purpose
	extra := []dns.RR{a, opt}
	adjustTTLs(extra, 100) // decrement TTLs by 100 seconds

	// The A record's TTL should be decremented
	if a.Hdr.Ttl != 200 {
		t.Errorf("A TTL = %d, want 200", a.Hdr.Ttl)
	}

	// The OPT record's Ttl (which holds DO+extended RCODE) should NOT be touched
	if opt.Hdr.Ttl != origOPT {
		t.Errorf("OPT Ttl changed from %d to %d", origOPT, opt.Hdr.Ttl)
	}
	if opt.Do() != true {
		t.Errorf("OPT DO bit was cleared by adjustTTLs")
	}
}

func TestAdjustTTLsClampAtZero(t *testing.T) {
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    50,
		},
		A: net.ParseIP("1.2.3.4").To4(),
	}

	extra := []dns.RR{a}
	adjustTTLs(extra, 100) // ELAPSED > TTL
	if a.Hdr.Ttl != 0 {
		t.Errorf("A TTL = %d, want 0 (clamped)", a.Hdr.Ttl)
	}
}

func TestPutWithEmptyQuestion(t *testing.T) {
	// Regression test: put() must not panic on a response with Rcode==0,
	// answers, but no questions.
	cache := newQueryCache()
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("1.2.3.4").To4(),
	})
	// Deliberately leave msg.Question empty

	// This should not panic
	cache.put(msg, "")

	// Verify cache is still empty (nothing was stored)
	_, _, ok := cache.get("example.com.", dns.TypeA, dns.ClassINET, 0, true, 512, "")
	if ok {
		t.Error("cache should be empty after put with no questions")
	}
}

func TestPutSuccessStoresAndReturns(t *testing.T) {
	cache := newQueryCache()
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Question = []dns.Question{{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("1.2.3.4").To4(),
	})
	msg.SetRcode(msg, dns.RcodeSuccess)

	cache.put(msg, "")

	_, _, ok := cache.get("example.com.", dns.TypeA, dns.ClassINET, 0, true, 512, "")
	if !ok {
		t.Error("expected cache hit after put")
	}
}


func buildLargeAResponse(n int) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Authoritative = true
	msg.Rcode = dns.RcodeSuccess
	msg.Question = []dns.Question{{Name: "large.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	for i := 0; i < n; i++ {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   "large.example.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).To4(),
		})
	}
	return msg
}

func TestTruncateForTransportPreservesOriginal(t *testing.T) {
	full := buildLargeAResponse(80)
	origAnswers := len(full.Answer)
	packed, err := full.Pack()
	if err != nil {
		t.Fatalf("pack full: %v", err)
	}
	if len(packed) <= 512 {
		t.Fatalf("fixture too small (%d bytes); need >512 to exercise Truncate", len(packed))
	}

	wire := truncateForTransport(full, false, 512)
	if len(full.Answer) != origAnswers {
		t.Fatalf("original Answer mutated: got %d want %d", len(full.Answer), origAnswers)
	}
	if len(wire.Answer) >= origAnswers {
		t.Fatalf("wire reply was not truncated: answers=%d", len(wire.Answer))
	}
	if !wire.Truncated {
		t.Fatal("expected Truncated bit on wire reply")
	}
}

func TestCachePreservesAnswersForLargerClientAfterSmallPut(t *testing.T) {
	full := buildLargeAResponse(80)
	packed, err := full.Pack()
	if err != nil {
		t.Fatalf("pack full: %v", err)
	}
	if len(packed) <= 512 {
		t.Fatalf("fixture too small (%d bytes)", len(packed))
	}

	// Correct path used by parseResponse*: put the untruncated message.
	cache := newQueryCache()
	cache.put(full, "")

	_, msgTCP, ok := cache.get("large.example.", dns.TypeA, dns.ClassINET, 1, true, 512, "")
	if !ok {
		t.Fatal("expected TCP cache hit")
	}
	if len(msgTCP.Answer) != len(full.Answer) {
		t.Fatalf("TCP hit lost answers: got %d want %d", len(msgTCP.Answer), len(full.Answer))
	}

	bufUDP, _, ok := cache.get("large.example.", dns.TypeA, dns.ClassINET, 2, false, 512, "")
	if !ok {
		t.Fatal("expected UDP cache hit")
	}
	if len(bufUDP) > 512 {
		t.Fatalf("UDP wire exceeds udpSize: %d", len(bufUDP))
	}

	// Document the old bug: putting an already-truncated msg permanently drops RRs.
	buggyCache := newQueryCache()
	buggy := truncateForTransport(full, false, 512)
	buggyCache.put(buggy, "")
	_, buggyTCP, ok := buggyCache.get("large.example.", dns.TypeA, dns.ClassINET, 3, true, 4096, "")
	if !ok {
		// Truncated responses may lack answers enough / ttl — either miss or short answers.
		return
	}
	if len(buggyTCP.Answer) >= len(full.Answer) {
		t.Fatal("expected truncated put to lose answers; fixture inconclusive")
	}
}

func TestCacheECSIsolation(t *testing.T) {
	cache := newQueryCache()
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Question = []dns.Question{{Name: "geo.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "geo.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("1.2.3.4").To4(),
	})

	ecsA := ecsCacheKey(net.ParseIP("203.0.113.10"), 24)
	ecsB := ecsCacheKey(net.ParseIP("198.51.100.20"), 24)
	if ecsA == "" || ecsB == "" || ecsA == ecsB {
		t.Fatalf("bad ecs keys: %q %q", ecsA, ecsB)
	}

	cache.put(msg, ecsA)

	if _, _, ok := cache.get("geo.example.", dns.TypeA, dns.ClassINET, 1, true, 512, ecsA); !ok {
		t.Fatal("expected hit for ecsA")
	}
	if _, _, ok := cache.get("geo.example.", dns.TypeA, dns.ClassINET, 2, true, 512, ecsB); ok {
		t.Fatal("ecsB must not hit ecsA entry")
	}
	if _, _, ok := cache.get("geo.example.", dns.TypeA, dns.ClassINET, 3, true, 512, ""); ok {
		t.Fatal("empty ECS must not hit ecsA entry")
	}
}

func TestEcsCacheKeyUnspecified(t *testing.T) {
	if got := ecsCacheKey(net.IPv4(0, 0, 0, 0), 0); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := ecsCacheKey(nil, 24); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
