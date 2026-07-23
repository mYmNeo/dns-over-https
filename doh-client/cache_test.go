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
