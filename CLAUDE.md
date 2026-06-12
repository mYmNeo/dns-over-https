# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**DNS-over-HTTPS (DoH)** — A production-grade Go implementation providing both client and server binaries for DNS resolution over HTTPS, supporting:
- **Google DNS-over-HTTPS protocol** (JSON-based API, `application/dns-json`)
- **IETF RFC 8484** (binary wire format, `application/dns-message`)
- **EDNS0-Client-Subnet (ECS)** for GeoDNS/CDN support
- **GFW filtering** (Great Firewall of China detection and bypass)
- **Weighted load balancing** (random, nginx-style, LVS-style selectors)
- **Health checking** with upstream status reporting

**Module Path:** `github.com/m13253/dns-over-https/v2`  
**Go Version:** 1.24.1  
**Current Version:** 2.3.10

---

## Quick Build & Test

```bash
make                                  # Build both doh-client and doh-server
make doh-client/doh-client            # Build only client
make doh-server/doh-server            # Build only server
make clean                            # Remove built binaries
make install                          # Install to /usr/local/bin + /etc/dns-over-https
make uninstall                        # Remove installed files

# Testing
go test ./...                         # Run all tests
go test ./json-dns/...                # Tests: EDNS/globalip/helpers
go test ./doh-server/...              # Tests: parse_test.go (CIDR/subnet parsing)
golangci-lint run ./...               # Lint (see .golangci.yml)
```

**Build flags:** Makefile uses `-ldflags "-s -w"` (strip debug info) and `-pgo=auto` (profile-guided optimization, Go 1.24+).

### Go Version Note
`.github/workflows/go.yml` uses Go 1.25.1; `go.mod` specifies 1.24.1. The `-pgo=auto` build flag (Makefile) requires Go 1.24+.

---

## Architecture Overview

### Two-Binary, One-Library Design

```
┌─────────────────────────────────────────────────────────┐
│ doh-client/ — Local recursive DNS proxy                 │
├─────────────────────────────────────────────────────────┤
│ Listens on UDP/TCP (default 127.0.0.1:53)              │
│ • Forwards queries to upstream DoH servers              │
│ • Query result caching (10k entries max, LRU-ish)       │
│ • GFW blocking + ipset filtering (Linux)                │
│ • Upstream selector with health checking                │
│ • IPv4/IPv6 support, EDNS0-Client-Subnet               │
└─────────────────────────────────────────────────────────┘

                       ┌──────────────────────┐
                       │ json-dns/ — Shared   │
                       │ protocol library     │
                       │ (marshal/unmarshal   │
                       │  wire format)        │
                       └──────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ doh-server/ — HTTPS endpoint for DNS queries            │
├─────────────────────────────────────────────────────────┤
│ Listens on TCP/HTTPS (default 127.0.0.1:8053)          │
│ • Accepts DoH requests (Google JSON or IETF wire)       │
│ • Proxies to traditional upstream resolvers             │
│ • Retry logic (configurable tries, random upstream)     │
│ • TLS client certificate auth support                   │
│ • Content-type negotiation + CORS headers               │
└─────────────────────────────────────────────────────────┘
```

---

## Key Files & Modules

### `doh-client/`

| File | Purpose |
|------|---------|
| `main.go` | Entry point, CLI flags, signal handling, PID file management |
| `client.go` | Core `Client` struct; DNS handler dispatch; GFW/iptables setup |
| `cache.go` | Query result caching (TTL-aware, background cleanup) |
| `config/config.go` | TOML config parsing; upstream selector modes |
| `selector/` | Upstream selection strategies & health checking |
| `google.go`, `ietf.go` | Request/response handling per protocol format |
| `version.go` | VERSION = "2.3.10", USER_AGENT constant |
| `helpers.go` | `sendErrorReply()` — sends DNS error reply with given rcode, logs error |
| `helpers.go` | Utility functions for DNS operations |

**Key Dependencies:**
- `github.com/miekg/dns` — DNS protocol, message parsing, UDP/TCP clients/servers
- `github.com/OneYX/v2ray-core/tools/gfwlist` — GFW list parsing (locally vendored)
- `github.com/coreos/go-iptables` — iptables rule management (Linux-only)
- `github.com/vishvananda/netlink` — Network interface queries (Linux-only)
- `golang.org/x/net/http2` — HTTP/2 transport
- `golang.org/x/net/idna` — Internationalized domain name support

### `doh-server/`

| File | Purpose |
|------|---------|
| `main.go` | Entry point, CLI flags, signal handling, PID file |
| `server.go` | Core `Server` struct; HTTP handler; retry logic for upstream DNS |
| `config.go` | TOML config parsing for server settings |
| `google.go`, `ietf.go` | Request parsing & response generation per protocol |
| `response.go` | Response struct marshaling (internal) |
| `parse_test.go` | Tests for EDNS0-Client-Subnet CIDR parsing |
| `version.go` | VERSION = "2.3.10", USER_AGENT |

**Key Dependencies:**
- `github.com/gorilla/handlers` — HTTP logging middleware
- `github.com/miekg/dns` — DNS protocol

### `json-dns/`

| File | Purpose |
|------|---------|
| `response.go` | JSON wire format structs: `Response`, `Question`, `RR` |
| `marshal.go` | Convert `miekg/dns.Msg` → JSON format |
| `unmarshal.go` | Convert JSON/wire format → `miekg/dns.Msg` |
| `globalip.go` | IP classification (global vs. private/loopback); RFC6890 subnet tree |
| `error.go` | HTTP error response formatting |
| `edns.go` | EDNS0 extension parsing (EDNS0-Client-Subnet, EDNS0-COOKIE) |
| `helpers.go`, `edns_test.go`, `globalip_test.go`, `helpers_test.go` | Utilities & tests |

---

## GFW Filtering & Upstream Selection

### GFW List Handling (`doh-client/client.go`)

- **GFW list sources:** Configurable via `gfwlist_url` (fetch from URL) or `gfwlist` (local files) in TOML
- **Block list:** Separate `blocklist` for domain-based blocking (refused with `RcodeRefused`)
- **GFW detection:** For blocked domains, queries are routed through DoH upstreams; unblocked (passthrough) domains bypass DoH and use bootstrap servers
- **IP filtering:** When a query is detected as GFW-blocked, response IPs are added to an ipset (`gfw_iplist`) via `ipset restore` command
- **Thread-safety:** GFW list updates use `sync.RWMutex` (`c.gfwLock`)

**Key Functions:**
- `PrepareGFWListIPSet()` — Creates ipset, sets up iptables PREROUTING/POSTROUTING rules (Linux-only)
- `AddGFWFilterIP()` — Batch-adds response IPs to ipset via `exec.Command("ipset restore")`
- `isGFWBlocked(domain)` — Checks if domain is in GFW list
- `isBlocked(domain)` — Checks if domain is in block list

### Upstream Selection (`doh-client/selector/`)

**Interface:** `Selector` with three implementations:

1. **RandomSelector** — Simple random selection, no health checking
   - Init function seeds rand with `time.Now().UnixNano()`
   - No upstream state tracking
   
2. **NginxWRRSelector** — Nginx-style weighted round-robin
   - Maintains effective weights (incremented/decremented by health checks)
   - Smooth weight adjustment to prevent oscillation
   
3. **LVSWRRSelector** — LVS-style weighted round-robin
   - More aggressive weight penalties on timeout (-10 vs -5)
   - Used in high-performance load-balancing scenarios

**Health Checking:**
- Runs concurrently in background; triggered by `StartEvaluate(ctx)` in client
- Tests each upstream with a dummy query (`www.example.com` type A)
- Google protocol: expects status=0 in JSON → +5 weight, HTTP error → -3, JSON decode error → -2
- IETF protocol: expects HTTP 200 → +5, else → -3
- Timeout penalty: -5 (Nginx) or -10 (LVS); clamped to [1, original_weight]

---

## Caching Implementation (`doh-client/cache.go`)

**Cache Design:**
- In-memory map-based cache with TTL awareness
- **Max size:** 10,000 entries (hardcoded); entries rejected if full
- **TTL tracking:** Uses minimum TTL from all Answer RRs; clamps at 0
- **Key:** Tuple of (lowercase FQDN, query type, query class)

**Operations:**
- `get()` — Checks expiry, adjusts TTLs downward by elapsed time, clones message, truncates for UDP, repacks wire format
- `put()` — Only caches successful responses (Rcode==0) with ≥1 answer and minTTL > 0
- `startCleanup()` — Background goroutine runs every 60 seconds to remove expired entries
- **Thread-safety:** Uses `sync.RWMutex` for all cache operations

**Expiry Logic:**
- Entry expires when `now - storedAt >= ttl`
- Clean-up collects expired keys under read lock, then deletes under write lock (avoiding lock contention)

---

## Error Handling & Timeouts

### Client-Side (`doh-client/`)

- **HTTP Client Timeout:** Configurable via `timeout` setting (default 10 seconds)
- **HTTP Connection Lifecycle:** 
  - NewClient recreates HTTP client every 5 minutes if active (avoids stale connections)
  - TLS handshake timeout = `timeout` seconds
  - Idle connection timeout = 90 seconds; MaxIdleConns = 100; MaxIdleConnsPerHost = 10
- **Retry Logic:** None built-in; fails over via selector if upstream is unavailable
- **Error Classification:**
  - Timeout errors reported to selector via `ReportUpstreamStatus(..., selector.Timeout)`
  - 5xx responses reported via `ReportUpstreamStatus(..., selector.Error)`
  - 2xx responses reported via `ReportUpstreamStatus(..., selector.OK)`
- **Query Timeout:** Each DNS query wrapped in `context.WithTimeout(timeout seconds)`

### Server-Side (`doh-server/server.go`)

- **Upstream Retry Loop:** Tries up to `tries` times (default 3) with random upstream selection
- **Transport Fallback:** 
  - UDP first; if truncated or IXFR+SOA, retries with TCP
  - TCP-TLS if configured (`tcp-tls` prefix on upstream)
- **Timeout:** Applies per upstream query via `ExchangeContext()`
- **Error Propagation:** Returns 503 Service Unavailable if all retries exhaust

---

## Configuration File Format

Both client and server use TOML. Config paths:
- **Linux:** `/etc/dns-over-https/`
- **macOS:** `/usr/local/etc/dns-over-https/`

### Client Config (`doh-client/doh-client.conf`)

```toml
listen = ["127.0.0.1:53", "[::1]:53"]

[upstream]
upstream_selector = "random"  # or "weighted_round_robin" or "lvs_weighted_round_robin"
[[upstream.upstream_ietf]]
    url = "https://cloudflare-dns.com/dns-query"
    weight = 50

[others]
bootstrap = ["8.8.8.8:53"]           # Used to resolve upstream URLs
passthrough = ["captive.apple.com"]  # Bypass DoH for these domains
gfwlist = ["gfwlist.txt"]            # Local GFW lists (files)
gfwlist_url = [...]                  # Remote GFW lists (URLs)
blocklist = ["blocklist.txt"]        # Block (refuse) these domains
timeout = 30
no_cookies = true                    # Disable HTTP Cookies
no_ecs = false                       # Enable EDNS0-Client-Subnet
no_ipv6 = false
verbose = false
insecure_tls_skip_verify = false
cert = "tls-certs/client-cert.pem"
key = "tls-certs/client-key.pem"
tls_client_auth = true
tls_client_auth_ca = "ca-cert.pem"
local_ifname = "eth0"                # For GFW iptables rules
proxy_port = 8080                    # For GFW traffic redirection
iptables_path = "/sbin/iptables"     # Linux-only
```

### Server Config (`doh-server/doh-server.conf`)

```toml
listen = ["127.0.0.1:8053", "[::1]:8053"]
local_addr = ""                      # Bind outgoing queries to specific local address
cert = "server-cert.pem"
key = "server-key.pem"
path = "/dns-query"                  # HTTP path for DoH requests
upstream = ["udp:1.1.1.1:53", "tcp:8.8.8.8:53", "tcp-tls:dns.google:853"]
timeout = 10
tries = 3                            # Retry count
verbose = false
log_guessed_client_ip = false
ecs_allow_non_global_ip = false      # Allow RFC1918 addresses in ECS
ecs_use_precise_ip = false           # Limit ECS mask to /24 or /128
tls_client_auth = true
tls_client_auth_ca = "ca-cert.pem"
```

---

## Protocol Support

### Request/Response Negotiation

- **Client sends:** `Accept` header (can specify `application/dns-json` or `application/dns-message`)
- **Server responds:** According to Accept preference, falling back to request Content-Type
- **Default:** If ambiguous, follows request protocol

### Google DNS-over-HTTPS Protocol

**Request:** `GET /resolve?name=example.com&type=A&do=1`  
**Response:** JSON with Status=0, Answer array with TTL

**Implementation:**
- Client: `google.go` handles request generation and response parsing
- Server: Parses query params, generates JSON response with TTL as absolute expiry time

### IETF RFC 8484 Protocol

**Request:** Base64url-encoded DNS wire format in `dns` query param or POST body  
**Response:** `application/dns-message` with DNS wire format

**Implementation:**
- Client: `ietf.go` handles wire format encoding/decoding
- Server: Parses binary, generates binary response

---

## Platform-Specific Code

### Linux-Only Features (via build tags or runtime checks)

1. **GFW Filtering & iptables:** `PrepareGFWListIPSet()`, `PrepareDNSRules()`, `AddGFWFilterIP()`
   - Uses `github.com/coreos/go-iptables`
   - Executes `ipset`, `iptables` CLI commands
   
2. **Network Interface Access:** `GetIPFromInterface()`, `GetRouteTable()`
   - Uses `github.com/vishvananda/netlink`
   - Reads `/proc/net/route`

3. **PID File Management:** Available only on Linux, BSD family (FreeBSD, OpenBSD, NetBSD, DragonFly)
   - Used by both `doh-client` and `doh-server`
   - Checked via `runtime.GOOS` switch

### macOS-Specific

1. **darwin-wrapper/** — Wrapper for system integration (systemd not available)
2. **launchd/** — launchd plist files for service registration
3. **Makefile:** Builds `darwin-wrapper` on macOS only

### Default Listen Addresses

- **Linux:** Configurable per-platform via Makefile
- **macOS:** Different default paths (e.g., `/usr/local/etc/` vs `/etc/`)

---

## Global State & Initialization

### Init Functions

1. **`json-dns/globalip.go:init()`** — Populates `defaultFilter` (iptree) with RFC6890 reserved IP ranges
   - Used by `IsGlobalIP()` to classify IPs as global or private/reserved
   - Called once at package init time

2. **`doh-client/selector/randomSelector.go:init()`** — Seeds PRNG with `time.Now().UnixNano()`
   - Used by RandomSelector's simple random selection

### Singleton Patterns

- **Client:** Single global `Client` instance per process (created in `main()`)
- **Selector:** Single `Selector` implementation (chosen at init based on config)
- **Cache:** Single `queryCache` instance per Client
- **GFW List:** Single `gfwlist.GFWList` instance per Client (protected by `sync.RWMutex`)
- **HTTP Client:** Single per Client, recreated every 5 minutes

---

## Signal Handling & Graceful Shutdown

### Client (`doh-client/main.go`)

```go
signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
go func() {
    for sig := range c {
        log.Printf("Received signal: %v", sig)
        client.cleanRules()        // Clean up iptables rules
        os.Exit(0)
    }
}()
```

- Calls `cleanRules()` on SIGINT/SIGTERM to remove iptables rules before exit
- Currently blocks indefinitely; no graceful connection draining

### Server (`doh-server/main.go`)

- **No explicit signal handling** — Relies on OS to terminate HTTP server
- Could be improved with graceful shutdown (e.g., `http.Server.Shutdown()` on SIGTERM)

---

## Logging

**Approach:** All output to `stderr` via standard `log` package or `fmt.Printf()`

- `log.Println()`, `log.Printf()` — Default logging
- `fmt.Printf()` — Query logging in client (formatted as Apache combined log style)
- Controlled via `verbose` config flag (enabled via `-verbose` CLI flag or config)
- No structured logging; no log levels (info/debug/warn/error); no log rotation

**Sample Log Lines:**
- Client: `127.0.0.1 - - [02/Jan/2006:15:04:05 -0700] "example.com IN A"`
- Server: Combined logging if verbose (via `handlers.CombinedLoggingHandler`)

---

## Deployment & Docker

### Docker Images

**Client Dockerfile** (`Dockerfile.client`):
```dockerfile
FROM golang:alpine AS build-env
# Build doh-client binary
FROM alpine:latest
# Multi-stage: copy binary + config, expose 53/udp 53/tcp 5380
```

**Server Dockerfile** (`Dockerfile.server`):
```dockerfile
FROM golang:alpine AS build-env
# Build doh-server binary
FROM alpine:latest
# Multi-stage: copy binary + config, expose 8053
```

**Deployment Methods:**
- Standalone binaries with systemd (Linux)
- NetworkManager integration (Linux)
- launchd (macOS)
- Docker containers (multi-arch: linux/amd64, linux/arm/v6, linux/arm/v7, linux/arm64/v8)
- Docker Compose + Traefik + Unbound (example in README)

### CI/CD

- **`.github/workflows/go.yml`** — Builds on push/PR; uploads artifacts
- **`.github/workflows/docker.yml`** — Pushes multi-arch images to Docker Hub on master push

---

## Testing

### Test Files

1. **`json-dns/edns_test.go`** — EDNS0-Client-Subnet parsing, CIDR validation
2. **`json-dns/globalip_test.go`** — Global IP classification
3. **`json-dns/helpers_test.go`** — Utility function tests
4. **`doh-server/parse_test.go`** — CIDR/subnet parsing edge cases (IPv4, IPv6, mapped IPv4-in-IPv6)

### Running Tests

```bash
go test ./...                    # All tests
go test -v ./json-dns/...       # Verbose
go test -run TestName ./pkg/    # Single test
go test -parallel 1 ./...       # Sequential (useful for debugging)
```

**No e2e or integration tests** — Only unit tests for parsing logic. Manual testing required for end-to-end DNS queries.

---

## Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `github.com/miekg/dns` | v1.1.68 | DNS protocol, message parsing |
| `github.com/BurntSushi/toml` | v1.5.0 | TOML config parsing |
| `github.com/coreos/go-iptables` | v0.8.0 | iptables rules (Linux-only) |
| `github.com/vishvananda/netlink` | v1.3.1 | Network interface access (Linux-only) |
| `github.com/gorilla/handlers` | v1.5.2 | HTTP logging middleware |
| `github.com/infobloxopen/go-trees` | (PR date) | IP tree for RFC6890 classification |
| `github.com/OneYX/v2ray-core` | (local) | GFW list parsing (vendored) |
| `golang.org/x/net` | v0.44.0 | HTTP/2, IDNA, DNS extensions |
| `golang.org/x/sys` | v0.36.0 | Platform-specific syscalls |

### No Vendoring

Uses `go.mod` and `go.sum` directly. One exception: `github.com/OneYX/v2ray-core` is locally vendored in `staging/` via `replace` directive in go.mod.

---

## Linting & Code Style

**Tool:** `golangci-lint` (see `.golangci.yml`)

**Key Rules:**
- Import order enforced by `gci` with three sections: standard library → third-party → `github.com/m13253/dns-over-https/v2` prefix. Any import ordering violation will fail lint.
- Nearly all linters enabled; disabled: `importas`, `depguard`, `lll`, `exhaustruct`, `perfsprint`, `gochecknoinits`, `wsl`, `exportloopref`
- `gofumpt` extra rules enabled (stricter gofmt)
- `revive`: all rules except `line-length-limit`
- `govet`: `enable-all: true`

```bash
golangci-lint run ./...  # Lint all packages
```

---

## Common Workflows

### Add a New Upstream Selector

1. Create `doh-client/selector/mySelector.go`
2. Implement `Selector` interface: `Get()`, `StartEvaluate()`, `ReportUpstreamStatus()`
3. Update `doh-client/client.go` to instantiate your selector based on config
4. Add config option in `doh-client/config/config.go` (const and parsing)
5. Test: `go test ./doh-client/selector/...`

### Modify GFW Filtering

1. Edit GFW list sources in config: `gfwlist_url` or `gfwlist`
2. See `client.go`: `isGFWBlocked()`, `isBlocked()`, `AddGFWFilterIP()`
3. GFW list format: Requires `github.com/OneYX/v2ray-core` parsing logic

### Add a New DoH Protocol Variant

1. Duplicate `doh-client/ietf.go` or `google.go`
2. Update `Upstream` in selector to add new type
3. Update client handler to dispatch to new protocol handler
4. Implement request generation and response parsing

---

## Troubleshooting Notes

1. **GFW Filtering Not Working:** Verify `local_ifname`, `proxy_port`, iptables permissions, ipset availability
2. **Health Checks Always Fail:** Check upstream URL reachability, firewall rules
3. **Cache Not Hit:** Verify TTL > 0; check cache size isn't full (10k entries)
4. **Upstream Timeout:** Increase `timeout` setting; check network connectivity; verify DNS upstream is responding
5. **TLS Client Auth Fails:** Ensure certificate paths are correct and readable; verify CA cert contains issuer chain

