package jsondns

import (
	"testing"
	"time"
)

// TestUnmarshalRR_DMARC_TXT verifies that TXT records containing semicolons
// (e.g., DMARC, DKIM, SPF records) are not rejected by unmarshalRR.
func TestUnmarshalRR_DMARC_TXT(t *testing.T) {
	t.Parallel()

	// DMARC TXT record with semicolons in the data
	rr := RR{
		Question: Question{
			Name: "_dmarc.example.com.",
			Type: 16, // dns.TypeTXT
		},
		TTL:  3600,
		Data: `"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"`,
	}

	now := time.Now().UTC()
	dnsRR, err := unmarshalRR(rr, now)
	if err != nil {
		t.Fatalf("unmarshalRR rejected valid DMARC TXT: %v", err)
	}
	if dnsRR.Header().Rrtype != 16 {
		t.Errorf("expected TXT type 16, got %d", dnsRR.Header().Rrtype)
	}
	if dnsRR.Header().Name != "_dmarc.example.com." {
		t.Errorf("expected _dmarc.example.com., got %s", dnsRR.Header().Name)
	}
}

// TestUnmarshalRR_DKIM_TXT verifies DKIM TXT records with semicolons work.
func TestUnmarshalRR_DKIM_TXT(t *testing.T) {
	t.Parallel()

	// DKIM TXT record
	rr := RR{
		Question: Question{
			Name: "default._domainkey.example.com.",
			Type: 16,
		},
		TTL:  3600,
		Data: `"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQENWa" "6QrBAsdFfA"`,
	}

	now := time.Now().UTC()
	dnsRR, err := unmarshalRR(rr, now)
	if err != nil {
		t.Fatalf("unmarshalRR rejected valid DKIM TXT: %v", err)
	}
	if dnsRR.Header().Rrtype != 16 {
		t.Errorf("expected TXT type 16, got %d", dnsRR.Header().Rrtype)
	}
}

// TestUnmarshalRR_SPF_TXT verifies SPF TXT records work.
func TestUnmarshalRR_SPF_TXT(t *testing.T) {
	t.Parallel()

	rr := RR{
		Question: Question{
			Name: "example.com.",
			Type: 16,
		},
		TTL:  3600,
		Data: `"v=spf1 include:_spf.example.com ~all"`,
	}

	now := time.Now().UTC()
	dnsRR, err := unmarshalRR(rr, now)
	if err != nil {
		t.Fatalf("unmarshalRR rejected valid SPF TXT: %v", err)
	}
	if dnsRR.Header().Rrtype != 16 {
		t.Errorf("expected TXT type 16, got %d", dnsRR.Header().Rrtype)
	}
}

// TestUnmarshalRR_NewlineRejected verifies actual newlines in data are still rejected.
func TestUnmarshalRR_NewlineRejected(t *testing.T) {
	t.Parallel()

	rr := RR{
		Question: Question{
			Name: "example.com.",
			Type: 1, // dns.TypeA
		},
		TTL:  3600,
		Data: "192.168.1.1\n",
	}

	now := time.Now().UTC()
	_, err := unmarshalRR(rr, now)
	if err == nil {
		t.Errorf("expected error for data containing newline, got nil")
	}
}
