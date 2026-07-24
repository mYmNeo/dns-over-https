.PHONY: all clean install package uninstall

PREFIX = /usr/local
VERSION = 2.3.10
ifeq ($(GOROOT),)
GOBUILD = go build -ldflags "-s -w" -pgo=auto
else
GOBUILD = $(GOROOT)/bin/go build -ldflags "-s -w" -pgo=auto
endif

ifeq ($(shell uname),Darwin)
CONFDIR = /usr/local/etc/dns-over-https
else
CONFDIR = /etc/dns-over-https
endif

all: doh-client/doh-client doh-server/doh-server doh-ip-lookup/doh-ip-lookup
	if [ "`uname`" = "Darwin" ]; then \
		$(MAKE) -C darwin-wrapper; \
	fi

clean:
	rm -f doh-client/doh-client doh-server/doh-server doh-ip-lookup/doh-ip-lookup
	if [ "`uname`" = "Darwin" ]; then \
		$(MAKE) -C darwin-wrapper clean; \
	fi

install:
	[ -e doh-client/doh-client ] || $(MAKE) doh-client/doh-client
	[ -e doh-server/doh-server ] || $(MAKE) doh-server/doh-server
	[ -e doh-ip-lookup/doh-ip-lookup ] || $(MAKE) doh-ip-lookup/doh-ip-lookup
	mkdir -p "$(DESTDIR)$(PREFIX)/bin/"
	install -m0755 doh-client/doh-client "$(DESTDIR)$(PREFIX)/bin/doh-client"
	install -m0755 doh-server/doh-server "$(DESTDIR)$(PREFIX)/bin/doh-server"
	install -m0755 doh-ip-lookup/doh-ip-lookup "$(DESTDIR)$(PREFIX)/bin/doh-ip-lookup"
	mkdir -p "$(DESTDIR)$(CONFDIR)/"
	install -m0644 doh-client/doh-client.conf "$(DESTDIR)$(CONFDIR)/doh-client.conf.example"
	install -m0644 doh-server/doh-server.conf "$(DESTDIR)$(CONFDIR)/doh-server.conf.example"
	[ -e "$(DESTDIR)$(CONFDIR)/doh-client.conf" ] || install -m0644 doh-client/doh-client.conf "$(DESTDIR)$(CONFDIR)/doh-client.conf"
	[ -e "$(DESTDIR)$(CONFDIR)/doh-server.conf" ] || install -m0644 doh-server/doh-server.conf "$(DESTDIR)$(CONFDIR)/doh-server.conf"
	if [ "`uname`" = "Linux" ]; then \
		$(MAKE) -C systemd install "DESTDIR=$(DESTDIR)"; \
		$(MAKE) -C NetworkManager install "DESTDIR=$(DESTDIR)"; \
	elif [ "`uname`" = "Darwin" ]; then \
		$(MAKE) -C darwin-wrapper install "DESTDIR=$(DESTDIR)" "PREFIX=$(PREFIX)"; \
		$(MAKE) -C launchd install "DESTDIR=$(DESTDIR)"; \
	fi

package: all
	mkdir -p .package-tmp
	cp doh-client/doh-client doh-server/doh-server doh-ip-lookup/doh-ip-lookup .package-tmp/
	tar -czf dns-over-https-$(VERSION)-$$(uname -s | tr A-Z a-z)-$$(go env GOARCH).tar.gz \
		-C .package-tmp doh-client doh-server doh-ip-lookup
	rm -rf .package-tmp

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/doh-client" "$(DESTDIR)$(PREFIX)/bin/doh-server" "$(DESTDIR)$(PREFIX)/bin/doh-ip-lookup" "$(DESTDIR)$(CONFDIR)/doh-client.conf.example" "$(DESTDIR)$(CONFDIR)/doh-server.conf.example"
	if [ "`uname`" = "Linux" ]; then \
		$(MAKE) -C systemd uninstall "DESTDIR=$(DESTDIR)"; \
		$(MAKE) -C NetworkManager uninstall "DESTDIR=$(DESTDIR)"; \
	elif [ "`uname`" = "Darwin" ]; then \
		$(MAKE) -C launchd uninstall "DESTDIR=$(DESTDIR)"; \
	fi

doh-client/doh-client: doh-client/client.go doh-client/cache.go doh-client/config/config.go doh-client/google.go doh-client/ietf.go doh-client/main.go doh-client/version.go doh-client/shmmap/layout.go doh-client/shmmap/shmmap_linux.go doh-client/shmmap/shmmap_stub.go json-dns/error.go json-dns/globalip.go json-dns/marshal.go json-dns/response.go json-dns/unmarshal.go
	cd doh-client && $(GOBUILD)

doh-ip-lookup/doh-ip-lookup: doh-ip-lookup/main.go doh-client/shmmap/layout.go doh-client/shmmap/shmmap_linux.go doh-client/shmmap/shmmap_stub.go
	$(GOBUILD) -o doh-ip-lookup/doh-ip-lookup ./doh-ip-lookup

doh-server/doh-server: doh-server/config.go doh-server/google.go doh-server/ietf.go doh-server/main.go doh-server/server.go doh-server/version.go json-dns/error.go json-dns/globalip.go json-dns/marshal.go json-dns/response.go json-dns/unmarshal.go
	cd doh-server && $(GOBUILD)
