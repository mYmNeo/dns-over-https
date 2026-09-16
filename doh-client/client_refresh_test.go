package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/m13253/dns-over-https/v2/doh-client/config"
	"github.com/m13253/dns-over-https/v2/doh-client/selector"
	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

// These tests defend the upstream half of the refresh contract: refreshCache is
// the cache's real resolver and must issue the DoH request a client-driven miss
// would issue, over both supported protocols, and hand the parsed answer back.
// The cache-level tests inject a fake fetcher, so query construction, the ECS
// replay and the protocol switch are only exercised here.

// refreshTestAnswer is the address both upstreams answer with, so the value the
// cache stores is distinguishable from anything the request carries.
const refreshTestAnswer = "198.51.100.7"

// refreshTestClient builds a Client wired for one real DoH round trip against
// upstreamURL. NewClient is not used because the config upstream lists are
// unexported; the selector is populated directly instead. An empty upstreamURL
// yields a selector with no upstreams.
func refreshTestClient(t *testing.T, upstreamType selector.UpstreamType, upstreamURL string) *Client {
	t.Helper()
	c := &Client{conf: &config.Config{}, cache: newQueryCache()}
	c.httpClientMux = new(sync.RWMutex)
	// Interface is unset, so getInterfaceIPs returns nil and the transport
	// dials the test server directly: no bootstrap resolver, no privileges.
	if err := c.newHTTPClient(); err != nil {
		t.Fatal(err)
	}
	s := selector.NewRandomSelector()
	if upstreamURL != "" {
		if err := s.Add(upstreamURL, upstreamType); err != nil {
			t.Fatal(err)
		}
	}
	c.selector = s
	return c
}

// refreshTestContext bounds one refresh round trip so a stalled dial fails the
// test instead of hanging it.
func refreshTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// refreshFirstIPv4 returns the address of the first A record in msg, or "" when
// the message carries none.
func refreshFirstIPv4(msg *dns.Msg) string {
	if msg == nil {
		return ""
	}
	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// refreshProductionKeyECS builds the ECS dimension of a key the way the
// client-driven miss path builds it: through GetEDNSClientInfo, which also masks
// the address, followed by ecsCacheKey. A refresh must replay that string
// unchanged, so deriving the key here makes exact equality a meaningful
// assertion rather than a formality — a refresh that re-derived ECS from the
// client address would widen a precise /32 key to the /24 that address implies.
func refreshProductionKeyECS(ip string, precise bool) string {
	_, mask, addr := jsondns.GetEDNSClientInfo(net.ParseIP(ip), precise)
	return ecsCacheKey(addr, mask)
}

// The Google JSON reply is built from named types rather than a literal so the
// body is marshalled, never hand-escaped. jsondns.RR is deliberately not used:
// it always marshals an unprepared Expires field, which the parser rejects.
type refreshJSONQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type refreshJSONAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type refreshJSONReply struct {
	Status   uint32                `json:"Status"`
	Question []refreshJSONQuestion `json:"Question"`
	Answer   []refreshJSONAnswer   `json:"Answer"`
}

// googleRefreshRequest is what the Google-protocol handler observed. The handler
// runs on its own goroutine, so the value reaches the test over a channel rather
// than through shared memory.
type googleRefreshRequest struct {
	method      string
	contentType string
	name        string
	qtype       string
	cd          string
	ecs         string
}

// startGoogleRefreshServer serves one DoH JSON answer for name and reports the
// query it received. A request that is not a DNS-JSON GET is refused, so a
// protocol switch regression fails the refresh itself.
func startGoogleRefreshServer(t *testing.T, name string) (*httptest.Server, <-chan googleRefreshRequest) {
	t.Helper()
	seen := make(chan googleRefreshRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		seen <- googleRefreshRequest{
			method:      r.Method,
			contentType: query.Get("ct"),
			name:        query.Get("name"),
			qtype:       query.Get("type"),
			cd:          query.Get("cd"),
			ecs:         query.Get("edns_client_subnet"),
		}
		if r.Method != http.MethodGet || query.Get("ct") != "application/dns-json" {
			http.Error(w, "not a Google DNS-JSON GET", http.StatusBadRequest)
			return
		}
		body, err := json.Marshal(refreshJSONReply{
			Status:   dns.RcodeSuccess,
			Question: []refreshJSONQuestion{{Name: name, Type: dns.TypeA}},
			Answer:   []refreshJSONAnswer{{Name: name, Type: dns.TypeA, TTL: 300, Data: refreshTestAnswer}},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// ietfRefreshRequest is what the RFC 8484 handler decoded. query is nil and
// decodeError set when the payload was not a DNS message at all.
type ietfRefreshRequest struct {
	method      string
	query       *dns.Msg
	decodeError string
}

// startIETFRefreshServer serves one wire-format answer for name and reports the
// request it decoded, accepting both transports RFC 8484 allows.
func startIETFRefreshServer(t *testing.T, name string) (*httptest.Server, <-chan ietfRefreshRequest) {
	t.Helper()
	seen := make(chan ietfRefreshRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		var payload []byte
		var err error
		switch {
		case r.Method == http.MethodGet:
			payload, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		case r.Method == http.MethodPost:
			payload, err = io.ReadAll(r.Body)
		default:
			err = fmt.Errorf("unexpected method %s", r.Method)
		}
		if err != nil {
			seen <- ietfRefreshRequest{method: method, decodeError: err.Error()}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(payload); err != nil {
			seen <- ietfRefreshRequest{method: method, decodeError: err.Error()}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seen <- ietfRefreshRequest{method: method, query: query}

		reply := new(dns.Msg)
		reply.SetReply(query)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(refreshTestAnswer).To4(),
		}}
		packed, err := reply.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func TestRefreshCacheGoogleProtocol(t *testing.T) {
	// Invariant: a refresh reissues the query of the entry it belongs to over the
	// Google JSON protocol. The upstream sees the key's own name, type and ECS
	// dimension plus the CD bit the entry was stored with, and the parsed answer
	// is returned to the cache rather than written to a client.
	for _, tc := range []struct {
		desc    string
		precise bool
	}{
		{"coarse subnet", false},
		{"precise subnet", true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			name := "google-refresh.example."
			key := cacheKey{
				Name:   name,
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
				ECS:    refreshProductionKeyECS("203.0.113.10", tc.precise),
			}
			req := cacheRequest{ECS: key.ECS, UDPSize: dns.DefaultMsgSize, CD: true}

			srv, seen := startGoogleRefreshServer(t, name)
			c := refreshTestClient(t, selector.Google, srv.URL)

			msg, err := c.refreshCache(refreshTestContext(t), key, req)
			if err != nil {
				t.Fatalf("refreshCache: %v", err)
			}
			if got := refreshFirstIPv4(msg); got != refreshTestAnswer {
				t.Errorf("refreshed answer = %q, want %q", got, refreshTestAnswer)
			}

			got := <-seen
			if got.method != http.MethodGet {
				t.Errorf("upstream method = %q, want GET", got.method)
			}
			if got.contentType != "application/dns-json" {
				t.Errorf("upstream ct = %q, want application/dns-json", got.contentType)
			}
			if got.name != key.Name {
				t.Errorf("upstream name = %q, want %q", got.name, key.Name)
			}
			if got.qtype != "A" {
				t.Errorf("upstream type = %q, want A", got.qtype)
			}
			if got.cd != "1" {
				t.Errorf("upstream cd = %q, want 1", got.cd)
			}
			// The upstream must replay the entry's own ECS dimension, not one
			// re-derived from the client address: for the precise key that
			// distinction is /32 versus the /24 a re-derivation would send.
			if got.ecs != key.ECS {
				t.Errorf("upstream edns_client_subnet = %q, want the entry's own ECS %q", got.ecs, key.ECS)
			}
		})
	}
}

func TestRefreshCacheIETFProtocol(t *testing.T) {
	// Invariant: the same refresh over RFC 8484 carries the key's question and
	// the key's ECS dimension as an EDNS0_SUBNET option on the wire, and the
	// unpacked upstream reply is returned to the cache.
	name := "ietf-refresh.example."
	key := cacheKey{
		Name:   name,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
		// A precise key: replaying it must send /32, so a refresh that
		// re-derived ECS from the client address would widen it to /24.
		ECS: refreshProductionKeyECS("203.0.113.10", true),
	}
	req := cacheRequest{ECS: key.ECS, UDPSize: dns.DefaultMsgSize}

	srv, seen := startIETFRefreshServer(t, name)
	c := refreshTestClient(t, selector.IETF, srv.URL)

	msg, err := c.refreshCache(refreshTestContext(t), key, req)
	if err != nil {
		t.Fatalf("refreshCache: %v", err)
	}
	if got := refreshFirstIPv4(msg); got != refreshTestAnswer {
		t.Errorf("refreshed answer = %q, want %q", got, refreshTestAnswer)
	}

	got := <-seen
	if got.decodeError != "" {
		t.Fatalf("upstream could not decode the DoH query: %s", got.decodeError)
	}
	if got.method != http.MethodGet {
		t.Errorf("upstream method = %q, want GET", got.method)
	}
	if len(got.query.Question) != 1 {
		t.Fatalf("upstream request carried %d questions, want 1", len(got.query.Question))
	}
	question := got.query.Question[0]
	if question.Name != key.Name || question.Qtype != key.Qtype || question.Qclass != key.Qclass {
		t.Errorf("upstream question = %v/%d/%d, want %s/%d/%d",
			question.Name, question.Qtype, question.Qclass, key.Name, key.Qtype, key.Qclass)
	}

	_, ipnet, err := net.ParseCIDR(key.ECS)
	if err != nil {
		t.Fatalf("test key %q is not a CIDR: %v", key.ECS, err)
	}
	wantMask, _ := ipnet.Mask.Size()
	opt := got.query.IsEdns0()
	if opt == nil {
		t.Fatal("upstream request carried no EDNS0 record: the ECS dimension was dropped")
	}
	var subnet *dns.EDNS0_SUBNET
	for _, option := range opt.Option {
		if s, ok := option.(*dns.EDNS0_SUBNET); ok {
			subnet = s
			break
		}
	}
	if subnet == nil {
		t.Fatal("upstream request carried no EDNS0_SUBNET option: the ECS dimension was dropped")
	}
	// The address and the netmask both come from key.ECS. The mask is the
	// load-bearing half: the replay must not re-derive the /24 that a client
	// address implies for this /32 key.
	if subnet.Family != 1 {
		t.Errorf("upstream ECS family = %d, want 1 (IPv4)", subnet.Family)
	}
	if subnet.SourceNetmask != uint8(wantMask) {
		t.Errorf("upstream ECS netmask = %d, want %d (from %q)", subnet.SourceNetmask, wantMask, key.ECS)
	}
	// String comparison, not net.IP.Equal: the wire decode yields a 16-byte
	// v4-mapped address while the key holds a 4-byte one, and String() is the
	// canonical form of both.
	if got := subnet.Address.String(); got != ipnet.IP.String() {
		t.Errorf("upstream ECS address = %s, want %s (from %q)", got, ipnet.IP, key.ECS)
	}
}

func TestRefreshCacheBlockedDomainRefuses(t *testing.T) {
	// Invariant: the blocklist guard runs before any upstream contact, so a
	// refresh of a blocked domain fails and the upstream never sees the query.
	name := "blocked-refresh.example."
	dir := t.TempDir()
	blockPath := filepath.Join(dir, "blocklist.txt")
	writeListFile(t, blockPath, strings.TrimSuffix(name, ".")+"\n")
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "upstream must not be reached", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c := refreshTestClient(t, selector.Google, srv.URL)
	c.conf.Other.BlockList = []string{blockPath}
	if err := c.replaceBlockList(); err != nil {
		t.Fatal(err)
	}
	if blocked, _, _ := c.checkLists(name); !blocked {
		t.Fatalf("test setup: %q is not blocked", name)
	}

	key := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg, err := c.refreshCache(refreshTestContext(t), key, cacheRequest{})
	if err == nil {
		t.Fatal("refreshCache resolved a blocked domain")
	}
	if msg != nil {
		t.Errorf("blocked refresh returned a message: %v", msg)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("upstream called %d times for a blocked domain, want 0", got)
	}
}

func TestRefreshCacheNoUpstream(t *testing.T) {
	// Invariant: with no upstream to choose from a refresh reports the failure
	// to the cache instead of dereferencing a nil upstream.
	c := refreshTestClient(t, selector.Google, "")
	if upstream := c.selector.Get(); upstream != nil {
		t.Fatalf("test setup: selector has an upstream: %v", upstream)
	}

	key := cacheKey{Name: "no-upstream.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if msg, err := c.refreshCache(refreshTestContext(t), key, cacheRequest{}); err == nil {
		t.Fatalf("refreshCache resolved without an upstream: %v", msg)
	}
}
