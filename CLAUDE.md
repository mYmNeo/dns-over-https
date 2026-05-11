# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DNS-over-HTTPS (DoH) — a Go implementation providing both client and server binaries for DNS resolution over HTTPS, supporting Google DNS-over-HTTPS protocol and IETF RFC 8484.

## Build Commands

```bash
make                    # Build both doh-client and doh-server binaries
make doh-client/doh-client  # Build only the client
make doh-server/doh-server  # Build only the server
make clean              # Remove built binaries
```

## Testing

```bash
go test ./...                          # Run all tests
go test ./json-dns/...                 # Run tests in the json-dns package
go test ./doh-server/...               # Run tests in the doh-server package
go test -run TestFunctionName ./pkg/   # Run a single test
```

## Linting

Uses golangci-lint with nearly all linters enabled (see `.golangci.yml`):

```bash
golangci-lint run ./...
```

Import ordering (enforced by gci): standard library, then third-party, then `github.com/m13253/dns-over-https/v2` prefix.

## Architecture

The project has two independent binaries sharing a common library:

### `doh-client/` — Local DNS proxy
- Listens on local UDP/TCP DNS ports (default 127.0.0.1:53)
- Forwards queries to upstream DoH servers over HTTPS
- Key components:
  - `client.go` — Core Client struct, HTTP client management, DNS handler dispatch, GFW/iptables filtering
  - `config/config.go` — TOML config parsing with upstream selector modes (random, weighted_round_robin, lvs_weighted_round_robin)
  - `selector/` — Upstream server selection strategies with health checking (`Selector` interface in `selector.go`)
  - `google.go` / `ietf.go` — Request/response handling for each protocol format
  - `cache.go` — Query result caching

### `doh-server/` — HTTP(S) endpoint for DNS queries
- Accepts DoH requests and proxies to traditional upstream DNS resolvers (UDP/TCP/TCP-TLS)
- Key components:
  - `server.go` — HTTP server setup, request routing, content-type negotiation, upstream DNS query with retry
  - `config.go` — TOML config parsing for server
  - `google.go` / `ietf.go` — Parse/generate for each protocol format

### `json-dns/` — Shared library
- `response.go` — JSON wire format structs (Response, Question, RR)
- `marshal.go` / `unmarshal.go` — Conversion between `miekg/dns` messages and JSON format
- `globalip.go` — IP classification for EDNS0-Client-Subnet
- `error.go` — HTTP error response formatting

## Key Dependencies

- `github.com/miekg/dns` — DNS protocol library (message parsing, UDP/TCP clients/servers)
- `github.com/BurntSushi/toml` — Configuration file parsing
- `github.com/gorilla/handlers` — HTTP logging middleware (server)
- `golang.org/x/net/http2` — HTTP/2 transport (client)
- `github.com/coreos/go-iptables` — iptables rule management (client, Linux-only)
- `github.com/vishvananda/netlink` — Network interface info (client, Linux-only)

## Configuration

Both binaries use TOML config files:
- `doh-client/doh-client.conf` — Client configuration
- `doh-server/doh-server.conf` — Server configuration

Config path on Linux: `/etc/dns-over-https/`; on macOS: `/usr/local/etc/dns-over-https/`

## Protocol Support

The server content-type negotiates between:
- `application/dns-json` (Google-style JSON API)
- `application/dns-message` (IETF RFC 8484 binary wire format)

Both are supported for request and response on client and server sides.
