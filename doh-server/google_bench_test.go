package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"

	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

// benchGoogleResponse builds a realistic dns.Msg for benchmarking
// generateResponseGoogle. Mirrors the workload of a typical upstream response.
func benchGoogleResponse() *dns.Msg {
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
		jsondns.NewOPTRecord(4096, true),
	}
	return msg
}

// googleSink prevents compiler optimizations from eliding benchmark results.
var googleSink string

// BenchmarkGenerateResponseGoogle measures the allocation cost of the full
// Google-DNS JSON response path — jsondns.Marshal + json.Marshal + HTTP write.
// generateResponseGoogle does not use its *Server receiver, so a nil Server is
// safe. The httptest.ResponseRecorder and *http.Request are fresh per iteration
// to avoid state accumulation across calls.
func BenchmarkGenerateResponseGoogle(b *testing.B) {
	msg := benchGoogleResponse()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		w := httptest.NewRecorder()
		// generateResponseGoogle does not read r in this path; it only needs
		// a non-nil *http.Request to satisfy the signature.
		r := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
		req := &DNSRequest{
			response:   msg,
			isTailored: true,
		}
		(*Server)(nil).generateResponseGoogle(ctx, w, r, req)
	}
}
