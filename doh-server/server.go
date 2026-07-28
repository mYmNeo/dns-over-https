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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/handlers"
	"github.com/miekg/dns"

	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

type Server struct {
	conf         *config
	udpClient    *dns.Client
	tcpClient    *dns.Client
	tcpClientTLS *dns.Client
	servemux     *http.ServeMux
	cachedCert   *tls.Certificate
	servers      []*http.Server
	mu           sync.Mutex
	pprofServer  *http.Server
}

// SetPprofServer sets the pprof HTTP server to be started and shut down alongside the main servers.
func (s *Server) SetPprofServer(srv *http.Server) {
	s.pprofServer = srv
}

type DNSRequest struct {
	request         *dns.Msg
	response        *dns.Msg
	currentUpstream string
	errtext         string
	errcode         int
	transactionID   uint16
	isTailored      bool
}

func NewServer(conf *config) (*Server, error) {
	timeout := time.Duration(conf.Timeout) * time.Second
	s := &Server{
		conf: conf,
		udpClient: &dns.Client{
			Net:     "udp",
			UDPSize: dns.DefaultMsgSize,
			Timeout: timeout,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		},
		tcpClientTLS: &dns.Client{
			Net:     "tcp-tls",
			Timeout: timeout,
		},
		servemux: http.NewServeMux(),
	}
	if conf.LocalAddr != "" {
		udpLocalAddr, err := net.ResolveUDPAddr("udp", conf.LocalAddr)
		if err != nil {
			return nil, err
		}
		tcpLocalAddr, err := net.ResolveTCPAddr("tcp", conf.LocalAddr)
		if err != nil {
			return nil, err
		}
		s.udpClient.Dialer = &net.Dialer{
			Timeout:   timeout,
			LocalAddr: udpLocalAddr,
		}
		s.tcpClient.Dialer = &net.Dialer{
			Timeout:   timeout,
			LocalAddr: tcpLocalAddr,
		}
		s.tcpClientTLS.Dialer = &net.Dialer{
			Timeout:   timeout,
			LocalAddr: tcpLocalAddr,
		}
	}
	s.servemux.HandleFunc(conf.Path, s.handlerFunc)
	return s, nil
}

func (s *Server) Start() error {
	servemux := http.Handler(s.servemux)
	if s.conf.Verbose {
		servemux = handlers.CombinedLoggingHandler(os.Stdout, servemux)
	}

	var clientCAPool *x509.CertPool
	if s.conf.TLSClientAuth {
		if s.conf.TLSClientAuthCA != "" {
			clientCA, err := os.ReadFile(s.conf.TLSClientAuthCA)
			if err != nil {
				log.Fatalf("Reading certificate for client authentication has failed: %v", err)
			}
			clientCAPool = x509.NewCertPool()
			clientCAPool.AppendCertsFromPEM(clientCA)
			log.Println("Certificate loaded for client TLS authentication")
		} else {
			log.Fatalln("TLS client authentication requires both tls_client_auth and tls_client_auth_ca, exiting.")
		}
	}

	// Pre-load TLS certificate to avoid disk I/O on every TLS handshake
	if s.conf.Cert != "" && s.conf.Key != "" {
		cert, err := tls.LoadX509KeyPair(s.conf.Cert, s.conf.Key)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		s.cachedCert = &cert
	}

	numServers := len(s.conf.Listen)
	if s.pprofServer != nil {
		numServers++
	}
	results := make(chan error, numServers)
	s.servers = make([]*http.Server, 0, numServers)
	for _, addr := range s.conf.Listen {
		srv := &http.Server{
			Addr:              addr,
			Handler:           servemux,
			ReadTimeout:       30 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if s.conf.Cert != "" || s.conf.Key != "" {
			tlsConfig := &tls.Config{
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return s.cachedCert, nil
				},
			}
			if clientCAPool != nil {
				tlsConfig.ClientCAs = clientCAPool
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
			srv.TLSConfig = tlsConfig
		}
		s.servers = append(s.servers, srv)
	}
	if s.pprofServer != nil {
		s.servers = append(s.servers, s.pprofServer)
	}

	for i, srv := range s.servers {
		go func(srv *http.Server, idx int) {
			var err error
			if srv.TLSConfig != nil {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil {
				log.Println(err)
			}
			results <- err
		}(srv, i)
	}
	// wait for all handlers
	for i := 0; i < cap(results); i++ {
		err := <-results
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}
	close(results)
	return nil
}

// Shutdown gracefully stops all HTTP servers.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range s.servers {
		_ = srv.Shutdown(ctx)
	}
}

func (s *Server) handlerFunc(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, POST")
	w.Header().Set("Access-Control-Allow-Origin", "")
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.Header().Set("Server", USER_AGENT)
	w.Header().Set("X-Powered-By", USER_AGENT)

	if r.Method == "OPTIONS" {
		w.Header().Set("Content-Length", "0")
		return
	}

	if r.Form == nil {
		r.ParseForm()
	}

	for _, header := range s.conf.DebugHTTPHeaders {
		if value := r.Header.Get(header); value != "" {
			log.Printf("%s: %s\n", header, value)
		}
	}

	contentType := r.Header.Get("Content-Type")
	if ct := r.FormValue("ct"); ct != "" {
		contentType = ct
	}
	if contentType == "" {
		// Guess request Content-Type based on other parameters
		if r.FormValue("name") != "" {
			contentType = "application/dns-json"
		} else if r.FormValue("dns") != "" {
			contentType = "application/dns-message"
		}
	}
	var responseType string
	if accept := r.Header.Get("Accept"); accept != "" {
		responseType = parseAcceptType(accept)
	}
	if responseType == "" {
		// Guess response Content-Type based on request Content-Type
		if contentType == "application/dns-json" {
			responseType = "application/json"
		} else if contentType == "application/dns-message" {
			responseType = "application/dns-message"
		} else if contentType == "application/dns-udpwireformat" {
			responseType = "application/dns-message"
		}
	}

	var req *DNSRequest
	if contentType == "application/dns-json" {
		req = s.parseRequestGoogle(ctx, w, r)
	} else if contentType == "application/dns-message" {
		req = s.parseRequestIETF(ctx, w, r)
	} else if contentType == "application/dns-udpwireformat" {
		req = s.parseRequestIETF(ctx, w, r)
	} else {
		jsondns.FormatError(w, fmt.Sprintf("Invalid argument value: \"ct\" = %q", contentType), 415)
		return
	}
	if req.errcode == 444 {
		return
	}
	if req.errcode != 0 {
		jsondns.FormatError(w, req.errtext, req.errcode)
		return
	}

	req = s.patchRootRD(req)

	err := s.doDNSQuery(ctx, req)
	if err != nil {
		jsondns.FormatError(w, fmt.Sprintf("DNS query failure (%s)", err.Error()), 503)
		return
	}

	if responseType == "application/json" {
		s.generateResponseGoogle(ctx, w, r, req)
	} else if responseType == "application/dns-message" {
		s.generateResponseIETF(ctx, w, r, req)
	} else {
		panic("Unknown response Content-Type")
	}
}

func (s *Server) findClientIP(r *http.Request) net.IP {
	noEcs := r.FormValue("no_ecs")
	if strings.EqualFold(noEcs, "true") {
		return nil
	}

	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		// Scan comma-separated IPs without allocating a []string slice.
		for xForwardedFor != "" {
			var addr string
			if idx := strings.IndexByte(xForwardedFor, ','); idx >= 0 {
				addr = xForwardedFor[:idx]
				xForwardedFor = xForwardedFor[idx+1:]
			} else {
				addr = xForwardedFor
				xForwardedFor = ""
			}
			ip := net.ParseIP(strings.TrimSpace(addr))
			if jsondns.IsGlobalIP(ip) {
				return ip
			}
		}
	}
	XRealIP := r.Header.Get("X-Real-IP")
	if XRealIP != "" {
		addr := strings.TrimSpace(XRealIP)
		ip := net.ParseIP(addr)
		if s.conf.ECSAllowNonGlobalIP || jsondns.IsGlobalIP(ip) {
			return ip
		}
	}

	hostStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(hostStr)
	if ip == nil {
		return nil
	}
	if s.conf.ECSAllowNonGlobalIP || jsondns.IsGlobalIP(ip) {
		return ip
	}
	return nil
}

// Workaround a bug causing Unbound to refuse returning anything about the root.
func (s *Server) patchRootRD(req *DNSRequest) *DNSRequest {
	for _, question := range req.request.Question {
		if question.Name == "." {
			req.request.RecursionDesired = true
		}
	}
	return req
}

// parseAcceptType scans the Accept header value for known DNS response types
// without allocating intermediate slices.
func parseAcceptType(accept string) string {
	for {
		// Find next comma-separated segment
		idx := strings.IndexByte(accept, ',')
		var candidate string
		if idx < 0 {
			candidate = accept
		} else {
			candidate = accept[:idx]
		}
		// Strip quality parameters
		if semi := strings.IndexByte(candidate, ';'); semi >= 0 {
			candidate = candidate[:semi]
		}
		candidate = strings.TrimSpace(candidate)
		switch candidate {
		case "application/json":
			return "application/json"
		case "application/dns-udpwireformat", "application/dns-message":
			return "application/dns-message"
		}
		if idx < 0 {
			break
		}
		accept = accept[idx+1:]
	}
	return ""
}

// Return the position index for the question of qtype from a DNS msg, otherwise return -1.
func (s *Server) indexQuestionType(msg *dns.Msg, qtype uint16) int {
	for i, question := range msg.Question {
		if question.Qtype == qtype {
			return i
		}
	}
	return -1
}

func (s *Server) doDNSQuery(ctx context.Context, req *DNSRequest) (err error) {
	numServers := len(s.conf.Upstream)
	for i := uint(0); i < s.conf.Tries; i++ {
		req.currentUpstream = s.conf.Upstream[rand.IntN(numServers)]

		upstream, t := addressAndType(req.currentUpstream)

		switch t {
		default:
			log.Printf("invalid DNS type %q in upstream %q", t, upstream)
			return &configError{"invalid DNS type"}
		// Use DNS-over-TLS (DoT) if configured to do so
		case "tcp-tls":
			req.response, _, err = s.tcpClientTLS.ExchangeContext(ctx, req.request, upstream)
		case "tcp", "udp":
			// Use TCP if always configured to or if the Query type dictates it (AXFR)
			if t == "tcp" || (s.indexQuestionType(req.request, dns.TypeAXFR) > -1) {
				req.response, _, err = s.tcpClient.ExchangeContext(ctx, req.request, upstream)
			} else {
				req.response, _, err = s.udpClient.ExchangeContext(ctx, req.request, upstream)
				if err == nil && req.response != nil && req.response.Truncated {
					log.Println("UDP response truncated, retrying with TCP")
					req.response, _, err = s.tcpClient.ExchangeContext(ctx, req.request, upstream)
				}

				// Retry with TCP if this was an IXFR request, and we only received an SOA
				if err == nil && req.response != nil && (s.indexQuestionType(req.request, dns.TypeIXFR) > -1) &&
					(len(req.response.Answer) == 1) &&
					(req.response.Answer[0].Header().Rrtype == dns.TypeSOA) {
					req.response, _, err = s.tcpClient.ExchangeContext(ctx, req.request, upstream)
				}
			}
		}

		if err == nil {
			return nil
		}
		log.Printf("DNS error from upstream %s: %s\n", req.currentUpstream, err.Error())
	}
	return err
}
