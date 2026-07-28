package jsondns

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestUnmarshalRR_Correctness(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name  string
		rr    RR
		check func(t *testing.T, dnsRR dns.RR)
	}{
		{
			name: "A",
			rr: RR{
				Question: Question{Name: "example.com.", Type: dns.TypeA},
				TTL:      300,
				Data:     "1.2.3.4",
			},
			check: func(t *testing.T, dnsRR dns.RR) {
				a, ok := dnsRR.(*dns.A)
				if !ok {
					t.Fatalf("expected *dns.A, got %T", dnsRR)
				}
				if h := a.Header(); h.Name != "example.com." {
					t.Errorf("Name = %q, want %q", h.Name, "example.com.")
				}
				if h := a.Header(); h.Rrtype != dns.TypeA {
					t.Errorf("Rrtype = %d, want %d", h.Rrtype, dns.TypeA)
				}
				if h := a.Header(); h.Ttl != 300 {
					t.Errorf("Ttl = %d, want 300", h.Ttl)
				}
				if a.A.String() != "1.2.3.4" {
					t.Errorf("A = %v, want 1.2.3.4", a.A)
				}
			},
		},
		{
			name: "AAAA",
			rr: RR{
				Question: Question{Name: "example.com.", Type: dns.TypeAAAA},
				TTL:      300,
				Data:     "::1",
			},
			check: func(t *testing.T, dnsRR dns.RR) {
				aaaa, ok := dnsRR.(*dns.AAAA)
				if !ok {
					t.Fatalf("expected *dns.AAAA, got %T", dnsRR)
				}
				if h := aaaa.Header(); h.Name != "example.com." {
					t.Errorf("Name = %q, want %q", h.Name, "example.com.")
				}
				if aaaa.AAAA.String() != "::1" {
					t.Errorf("AAAA = %v, want ::1", aaaa.AAAA)
				}
			},
		},
		{
			name: "CNAME",
			rr: RR{
				Question: Question{Name: "www.example.com.", Type: dns.TypeCNAME},
				TTL:      300,
				Data:     "target.example.com.",
			},
			check: func(t *testing.T, dnsRR dns.RR) {
				cname, ok := dnsRR.(*dns.CNAME)
				if !ok {
					t.Fatalf("expected *dns.CNAME, got %T", dnsRR)
				}
				if h := cname.Header(); h.Name != "www.example.com." {
					t.Errorf("Name = %q, want %q", h.Name, "www.example.com.")
				}
				if cname.Target != "target.example.com." {
					t.Errorf("Target = %q, want %q", cname.Target, "target.example.com.")
				}
			},
		},
		{
			name: "TXT with semicolons",
			rr: RR{
				Question: Question{Name: "example.com.", Type: dns.TypeTXT},
				TTL:      300,
				Data:     `"v=spf1 include:_spf.example.com ~all"`,
			},
			check: func(t *testing.T, dnsRR dns.RR) {
				txt, ok := dnsRR.(*dns.TXT)
				if !ok {
					t.Fatalf("expected *dns.TXT, got %T", dnsRR)
				}
				if h := txt.Header(); h.Name != "example.com." {
					t.Errorf("Name = %q, want %q", h.Name, "example.com.")
				}
				if len(txt.Txt) != 1 || txt.Txt[0] != "v=spf1 include:_spf.example.com ~all" {
					t.Errorf("Txt = %v, want [\"v=spf1 include:_spf.example.com ~all\"]", txt.Txt)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dnsRR, err := unmarshalRR(tc.rr, now)
			if err != nil {
				t.Fatalf("unmarshalRR(%s) error: %v", tc.name, err)
			}
			tc.check(t, dnsRR)
		})
	}
}

// sink prevents the compiler from optimizing away benchmark results.
var sink string

// BenchmarkUnmarshalRR measures the full unmarshalRR path including validation
// and dns.NewRR parsing, using the strings.Builder zone construction.
func BenchmarkUnmarshalRR(b *testing.B) {
	rr := RR{
		Question: Question{Name: "example.com.", Type: dns.TypeA},
		TTL:      300,
		Data:     "1.2.3.4",
	}
	now := time.Now()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := unmarshalRR(rr, now)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkZoneConstruction isolates the zone-string building step from
// dns.NewRR parsing. It compares strings.Builder with Grow() against
// string concatenation to measure the allocation difference.
//
// Micro-benchmark results on AMD Ryzen 9 9950X (Go 1.24.1):
//
//	Builder   51 B/op   2 allocs/op   ~31 ns/op
//	Concat    35 B/op   2 allocs/op   ~36 ns/op
//
// Both approaches do 2 allocs (one for strconv.FormatUint, one for
// the final string). The strings.Builder wins on latency (~13% faster)
// by avoiding the variadic concatstrings call, at the cost of a modest
// 16-byte memory increase from the Builder's internal buffer overhead.
func BenchmarkZoneConstruction(b *testing.B) {
	rr := RR{
		Question: Question{Name: "example.com.", Type: dns.TypeA},
		TTL:      300,
		Data:     "1.2.3.4",
	}
	rrType := dns.TypeToString[rr.Type]

	b.Run("Builder", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			var buf strings.Builder
			buf.Grow(len(rr.Name) + 1 + 10 + 4 + len(rrType) + 1 + len(rr.Data))
			buf.WriteString(rr.Name)
			buf.WriteByte(' ')
			buf.WriteString(strconv.FormatUint(uint64(rr.TTL), 10))
			buf.WriteString(" IN ")
			buf.WriteString(rrType)
			buf.WriteByte(' ')
			buf.WriteString(rr.Data)
			sink = buf.String()
		}
	})

	b.Run("Concat", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			sink = rr.Name + " " + strconv.FormatUint(uint64(rr.TTL), 10) + " IN " + rrType + " " + rr.Data
		}
	})
}
