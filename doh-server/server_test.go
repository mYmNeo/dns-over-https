package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

func TestFindClientIP(t *testing.T) {
	t.Parallel()

	t.Run("IPv4", func(t *testing.T) {
		t.Parallel()
		srv := &Server{conf: &config{ECSAllowNonGlobalIP: false}}
		req := httptest.NewRequest(http.MethodGet, "/dns-query", http.NoBody)
		req.RemoteAddr = "8.8.8.8:12345"

		ip := srv.findClientIP(req)
		if ip == nil {
			t.Fatal("expected non-nil IP for global IPv4")
		}
		if !ip.Equal(net.IP{8, 8, 8, 8}) {
			t.Fatalf("expected 8.8.8.8, got %s", ip)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		t.Parallel()
		srv := &Server{conf: &config{ECSAllowNonGlobalIP: false}}
		req := httptest.NewRequest(http.MethodGet, "/dns-query", http.NoBody)
		req.RemoteAddr = "[2001:4860:4860::8888]:12345"

		ip := srv.findClientIP(req)
		if ip == nil {
			t.Fatal("expected non-nil IP for global IPv6")
		}
		expected := net.ParseIP("2001:4860:4860::8888")
		if !ip.Equal(expected) {
			t.Fatalf("expected %s, got %s", expected, ip)
		}
	})

	t.Run("PrivateIP", func(t *testing.T) {
		t.Parallel()
		srv := &Server{conf: &config{ECSAllowNonGlobalIP: false}}
		req := httptest.NewRequest(http.MethodGet, "/dns-query", http.NoBody)
		req.RemoteAddr = "10.0.0.1:12345"

		ip := srv.findClientIP(req)
		if ip != nil {
			t.Fatalf("expected nil for non-global IP with ECSAllowNonGlobalIP=false, got %s", ip)
		}
	})

	t.Run("XForwardedFor", func(t *testing.T) {
		t.Parallel()
		srv := &Server{conf: &config{ECSAllowNonGlobalIP: false}}
		req := httptest.NewRequest(http.MethodGet, "/dns-query", http.NoBody)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "8.8.8.8, 192.168.1.1")

		ip := srv.findClientIP(req)
		if ip == nil {
			t.Fatal("expected non-nil IP from X-Forwarded-For")
		}
		if !ip.Equal(net.IP{8, 8, 8, 8}) {
			t.Fatalf("expected 8.8.8.8, got %s", ip)
		}
	})

	t.Run("XRealIP", func(t *testing.T) {
		t.Parallel()
		srv := &Server{conf: &config{ECSAllowNonGlobalIP: false}}
		req := httptest.NewRequest(http.MethodGet, "/dns-query", http.NoBody)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Real-IP", "8.8.8.8")

		ip := srv.findClientIP(req)
		if ip == nil {
			t.Fatal("expected non-nil IP from X-Real-IP")
		}
		if !ip.Equal(net.IP{8, 8, 8, 8}) {
			t.Fatalf("expected 8.8.8.8, got %s", ip)
		}
	})
}

// findClientIPOld is the previous implementation using net.ResolveTCPAddr.
// It is kept for benchmarking comparison only — the new implementation
// uses net.SplitHostPort + net.ParseIP, which avoids unnecessary DNS
// resolution and is faster.
func findClientIPOld(r *http.Request, srv *Server) net.IP {
	noEcs := r.FormValue("no_ecs")
	if noEcs == "true" {
		return nil
	}
	remoteAddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		return nil
	}
	ip := remoteAddr.IP
	if srv.conf.ECSAllowNonGlobalIP || jsondns.IsGlobalIP(ip) {
		return ip
	}
	return nil
}

func BenchmarkFindClientIP(b *testing.B) {
	srv := &Server{conf: &config{ECSAllowNonGlobalIP: false}}

	b.Run("Old", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			req := httptest.NewRequest(http.MethodGet, "/dns-query", http.NoBody)
			req.RemoteAddr = "8.8.8.8:12345"
			_ = findClientIPOld(req, srv)
		}
	})

	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			req := httptest.NewRequest(http.MethodGet, "/dns-query", http.NoBody)
			req.RemoteAddr = "8.8.8.8:12345"
			_ = srv.findClientIP(req)
		}
	})
}
