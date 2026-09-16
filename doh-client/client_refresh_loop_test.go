package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/m13253/dns-over-https/v2/doh-client/selector"
)

// This file defends the feature end to end, through the real DNS handler rather
// than through the cache API: a query resolves and caches, its entry expires, and
// the next query is answered from freshly re-resolved data. The cache-level tests
// cover coalescing in isolation and client_refresh_test.go covers the upstream
// request; only this test proves the two halves are wired together, which is the
// path a resolver actually depends on.

// loopResponseWriter captures what the handler sends to a client. handlerFunc
// writes the success path with Write and the failure path with WriteMsg, so both
// are recorded. It is used from the goroutine that calls handlerFunc, and the
// test reads it afterwards, so a mutex keeps the two accesses ordered.
type loopResponseWriter struct {
	mu   sync.Mutex
	wire []byte
	msgs []*dns.Msg
}

func (w *loopResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

// RemoteAddr reports a non-global address so findClientIP yields no ECS and the
// loop exercises the no-ECS key, the same shape as a local stub resolver client.
func (w *loopResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}
}

func (w *loopResponseWriter) WriteMsg(m *dns.Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, m)
	return nil
}

func (w *loopResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.wire = append(w.wire, p...)
	return len(p), nil
}

func (w *loopResponseWriter) Close() error        { return nil }
func (w *loopResponseWriter) TsigStatus() error   { return nil }
func (w *loopResponseWriter) TsigTimersOnly(bool) {}
func (w *loopResponseWriter) Hijack()             {}

// reply unpacks whatever the handler wrote and returns the first A record's
// address, or "" when the handler sent nothing or no answer.
func (w *loopResponseWriter) reply(t *testing.T) string {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, m := range w.msgs {
		if addr := refreshFirstIPv4(m); addr != "" {
			return addr
		}
	}
	if len(w.wire) == 0 {
		return ""
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(w.wire); err != nil {
		t.Fatalf("handler wrote an unparseable reply: %v", err)
	}
	return refreshFirstIPv4(msg)
}

// startMutableRefreshServer answers the first query with first and every later
// query with refreshed, counting the calls. The distinct answers are what make
// "was the client served stale data?" observable.
func startMutableRefreshServer(t *testing.T, name, first, refreshed string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := first
		if calls.Add(1) > 1 {
			addr = refreshed
		}
		if r.Method != http.MethodGet || r.URL.Query().Get("ct") != "application/dns-json" {
			http.Error(w, "not a Google DNS-JSON GET", http.StatusBadRequest)
			return
		}
		body, err := json.Marshal(refreshJSONReply{
			Status:   dns.RcodeSuccess,
			Question: []refreshJSONQuestion{{Name: name, Type: dns.TypeA}},
			Answer:   []refreshJSONAnswer{{Name: name, Type: dns.TypeA, TTL: 300, Data: addr}},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// expireCacheKey backdates the stored entry for key so the next lookup treats it
// as expired. Expiry is forced rather than waited for, which keeps the test fast
// and deterministic.
func expireCacheKey(t *testing.T, cache *queryCache, key cacheKey) {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, ok := cache.entries[key]
	if !ok {
		t.Fatalf("test setup: no cache entry for %+v", key)
	}
	entry.storedAt = time.Now().Add(-2 * entry.ttl)
}

func TestHandlerRefetchesAndReplacesExpiredEntry(t *testing.T) {
	// Invariant: an expired entry is not served. The next client query is
	// answered with freshly resolved data, that data replaces the expired entry,
	// and the query after it is served from the cache without touching upstream.
	const (
		name      = "loop.example."
		firstAddr = "198.51.100.1"
		newAddr   = "198.51.100.2"
	)
	srv, calls := startMutableRefreshServer(t, name, firstAddr, newAddr)

	c := refreshTestClient(t, selector.Google, srv.URL)
	// Timeout is zero in a bare Config, which would expire the handler's own
	// context immediately and turn every fetch into a failure.
	c.conf.Other.Timeout = 10
	c.cache.setFetcher(t.Context(), 10*time.Second, c.refreshCache)

	query := new(dns.Msg)
	query.SetQuestion(name, dns.TypeA)

	// 1. A cold query resolves upstream and caches the answer.
	w := &loopResponseWriter{}
	c.handlerFunc(w, query, false)
	if got := w.reply(t); got != firstAddr {
		t.Fatalf("cold query answered %q, want %q", got, firstAddr)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cold query made %d upstream calls, want 1", got)
	}

	// 2. Expire the entry, then query again through the handler.
	key := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	expireCacheKey(t, c.cache, key)

	w2 := &loopResponseWriter{}
	c.handlerFunc(w2, query, false)
	if got := w2.reply(t); got != newAddr {
		t.Errorf("query after expiry answered %q, want %q: the expired answer was served instead of being refreshed", got, newAddr)
	}
	afterRefresh := calls.Load()

	// 3. The refreshed data must now be what the cache serves. A cache hit makes
	// no upstream call, so the count must not move.
	w3 := &loopResponseWriter{}
	c.handlerFunc(w3, query, false)
	if got := w3.reply(t); got != newAddr {
		t.Errorf("query after refresh answered %q, want %q", got, newAddr)
	}
	if got := calls.Load(); got != afterRefresh {
		t.Errorf("upstream called %d more times after the entry was refreshed, want 0: the refreshed answer was not cached", got-afterRefresh)
	}
}

func TestExpiredLookupRefreshesThroughRealUpstream(t *testing.T) {
	// Invariant: the refresh is driven by the cache itself, not by the handler's
	// miss path. A lookup that finds an expired entry — with no handler involved
	// — must produce a real upstream query through the client's own resolver and
	// leave the cache holding the new answer.
	const (
		name      = "selfheal.example."
		firstAddr = "198.51.100.11"
		newAddr   = "198.51.100.22"
	)
	// Every upstream answer is the new address: the refresh is the first query
	// this server ever sees, so a "first vs later" switch would hand it the
	// seeded value back and make the assertion meaningless.
	srv, calls := startMutableRefreshServer(t, name, newAddr, newAddr)

	c := refreshTestClient(t, selector.Google, srv.URL)
	c.conf.Other.Timeout = 10
	c.cache.setFetcher(t.Context(), 10*time.Second, c.refreshCache)

	// Seed the cache the way a first client query would.
	seed := new(dns.Msg)
	seed.SetQuestion(name, dns.TypeA)
	seed.Response = true
	seed.Rcode = dns.RcodeSuccess
	seed.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(firstAddr).To4(),
	}}
	c.cache.put(seed, cacheRequest{})

	key := cacheKey{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	expireCacheKey(t, c.cache, key)

	// The lookup alone must report a miss and start the refresh. Nothing else
	// runs, so any upstream call is the cache triggering it.
	if _, _, ok := c.cache.get(name, dns.TypeA, dns.ClassINET, 1, true, dns.DefaultMsgSize, ""); ok {
		t.Fatal("expired entry was served by get")
	}

	refreshed := waitForCacheHit(t, c.cache, name, "")
	if got := refreshFirstIPv4(refreshed); got != newAddr {
		t.Errorf("cache now holds %q, want %q: the expired lookup did not refresh through the real upstream", got, newAddr)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("expiring one key caused %d upstream queries, want 1", got)
	}
}
