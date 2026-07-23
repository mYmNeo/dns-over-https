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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseCIDR(t *testing.T) {
	t.Parallel()
	for _, ednsClientSubnet := range []string{
		"2001:db8::/0",
		"2001:db8::/56",
		"2001:db8::",

		"127.0.0.1/0",
		"127.0.0.1/24",
		"127.0.0.1",

		"::ffff:7f00:1/0",
		"::ffff:7f00:1/120",
		"::ffff:7f00:1",
	} {
		_, ip, ipNet, err := parseSubnet(ednsClientSubnet)
		if err != nil {
			t.Errorf("ecs:%s ip:[%v]  ipNet:[%v]  err:[%v]", ednsClientSubnet, ip, ipNet, err)
		}
	}
}

func TestParseInvalidCIDR(t *testing.T) {
	t.Parallel()

	for _, ip := range []string{
		"test",
		"test/0",
		"test/24",
		"test/34",
		"test/56",
		"test/129",
		"2001:db8::/129",
		"127.0.0.1/33",
	} {
		_, _, _, err := parseSubnet(ip)
		if err == nil {
			t.Errorf("expected error for %q", ip)
		}
	}
}

func TestEdns0SubnetParseCIDR(t *testing.T) {
	t.Parallel()
	// init dns Msg
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.SetQuestion(dns.Fqdn("example.com"), 1)

	// init edns0Subnet
	edns0Subnet := new(dns.EDNS0_SUBNET)
	edns0Subnet.Code = dns.EDNS0SUBNET
	edns0Subnet.SourceScope = 0

	// init opt
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(dns.DefaultMsgSize)

	opt.Option = append(opt.Option, edns0Subnet)
	msg.Extra = append(msg.Extra, opt)

	for _, subnet := range []string{"::ffff:7f00:1/120", "127.0.0.1/24"} {
		var err error
		edns0Subnet.Family, edns0Subnet.Address, edns0Subnet.SourceNetmask, err = parseSubnet(subnet)
		if err != nil {
			t.Error(err)
			continue
		}
		t.Log(msg.Pack())
	}

	// ------127.0.0.1/24-----
	// [143 29 1 0 0 1 0 0 0 0 0 1 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0
	// opt start   0 41 16 0 0 0 0 0 0 11
	// subnet start 0 8 0 7 0 1 24 0
	// client subnet start 127 0 0]

	// -----::ffff:7f00:1/120----
	// [111 113 1 0 0 1 0 0 0 0 0 1 7 101 120 97 109 112 108 101 3 99 111 109 0 0 1 0 1 0
	// opt start  0 41 16 0 0 0 0 0 0 23
	// subnet start  0 8 0 19 0 2 120 0
	// client subnet start 0 0 0 0 0 0 0 0 0 0 255 255 127 0 0]
}

func TestParseIETFRejectsOversizedBase64(t *testing.T) {
	t.Parallel()

	// Build a "dns" form value longer than 65536 characters
	big := make([]byte, 70000)
	for i := range big {
		big[i] = 'A'
	}
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+string(big), http.NoBody)

	// We need a Server to call parseRequestIETF
	// Test only the length guard: if len > 65536, errcode should be 400 before any decode happens
	// Use a minimal server config
	srv := &Server{
		conf: &config{
			Path: "/dns-query",
		},
	}

	// The function needs Context, ResponseWriter, *http.Request
	// We can test indirectly through handlerFunc, which calls parseRequestIETF
	w := httptest.NewRecorder()
	srv.handlerFunc(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized dns param, got %d", resp.StatusCode)
	}
}

func TestParseIETFValidDNSQuery(t *testing.T) {
	t.Parallel()

	// A valid base64-encoded minimal DNS query
	// This is a minimal query for example.com A record
	dnsParam := "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+dnsParam, http.NoBody)

	srv := &Server{
		conf: &config{
			Path:     "/dns-query",
			Timeout:  5,
			Tries:    1,
			Upstream: []string{"udp:127.0.0.1:5353"},
		},
		udpClient: &dns.Client{
			Net:     "udp",
			UDPSize: dns.DefaultMsgSize,
			Timeout: 5 * time.Second,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: 5 * time.Second,
		},
	}

	w := httptest.NewRecorder()
	srv.handlerFunc(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	// Without a real upstream, the query will fail, but it should be a 503 (upstream failure)
	// not a 400 (parse failure) — confirming the base64 was decoded successfully
	if resp.StatusCode == http.StatusBadRequest {
		t.Errorf("valid DNS query should not return 400: got status %d", resp.StatusCode)
	}
}
