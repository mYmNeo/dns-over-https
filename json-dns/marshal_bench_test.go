package jsondns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// benchMarshalMsg builds a realistic dns.Msg for benchmarking Marshal.
// This mirrors the workload of a typical upstream response in the Google DNS
// wire path (doh-server/google.go generateResponseGoogle).
func benchMarshalMsg() *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.RecursionAvailable = true
	msg.SetQuestion("www.example.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "www.example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("93.184.216.34"),
		},
	}
	msg.Extra = []dns.RR{
		NewOPTRecord(4096, true),
	}
	return msg
}

// marshalSink prevents the compiler from optimizing away benchmark results.
var marshalSink *Response

// BenchmarkMarshal measures the allocation cost of jsondns.Marshal,
// which is called by the doh-server Google JSON response path on every request.
func BenchmarkMarshal(b *testing.B) {
	msg := benchMarshalMsg()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		// Marshal allocates a new Response with Question/Answer/Extra RR slices.
		marshalSink = Marshal(msg)
	}
}
