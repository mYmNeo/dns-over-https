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
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OneYX/v2ray-core/tools/gfwlist"
	"github.com/coreos/go-iptables/iptables"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/http2"
	"golang.org/x/net/idna"

	"github.com/m13253/dns-over-https/v2/doh-client/config"
	"github.com/m13253/dns-over-https/v2/doh-client/selector"
	"github.com/m13253/dns-over-https/v2/doh-client/shmmap"
	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

type Client struct {
	httpClientLastCreate time.Time
	cookieJar            http.CookieJar
	selector             selector.Selector
	httpClientMux        *sync.RWMutex
	tcpClient            *dns.Client
	bootstrapResolver    *net.Resolver
	udpClient            *dns.Client
	conf                 *config.Config
	httpTransport        *http.Transport
	httpClient           *http.Client
	udpServers           []*dns.Server
	tcpServers           []*dns.Server
	passthrough          []string
	gfwLock              sync.RWMutex
	gfwList              *gfwlist.GFWList
	blockList            *gfwlist.GFWList
	bootstrap            []string
	routerRules          RouterRules
	cache                *queryCache
	shmStore             *shmmap.Store
	ipsetCh              chan string
}

type DNSRequest struct {
	err               error
	response          *http.Response
	reply             *dns.Msg
	currentUpstream   string
	ednsClientAddress net.IP
	udpSize           uint16
	ednsClientNetmask uint8
}

const (
	GFW_IPLIST = "gfw_iplist"
)

func NewClient(conf *config.Config) (c *Client, err error) {
	c = &Client{
		conf:    conf,
		cache:   newQueryCache(),
		ipsetCh: make(chan string, 256),
	}

	udpHandler := dns.HandlerFunc(c.udpHandlerFunc)
	tcpHandler := dns.HandlerFunc(c.tcpHandlerFunc)
	c.udpClient = &dns.Client{
		Net:     "udp",
		UDPSize: dns.DefaultMsgSize,
		Timeout: time.Duration(conf.Other.Timeout) * time.Second,
	}
	c.tcpClient = &dns.Client{
		Net:     "tcp",
		Timeout: time.Duration(conf.Other.Timeout) * time.Second,
	}

	if c.conf.Other.Interface != "" {
		localV4, localV6, err := c.getInterfaceIPs()
		if err != nil {
			return nil, fmt.Errorf("failed to get interface IPs for %s: %v", c.conf.Other.Interface, err)
		}
		var localAddr net.IP
		if localV4 != nil {
			localAddr = localV4
		} else {
			localAddr = localV6
		}

		c.udpClient.Dialer = &net.Dialer{
			Timeout:   time.Duration(conf.Other.Timeout) * time.Second,
			LocalAddr: &net.UDPAddr{IP: localAddr},
		}
		c.tcpClient.Dialer = &net.Dialer{
			Timeout:   time.Duration(conf.Other.Timeout) * time.Second,
			LocalAddr: &net.TCPAddr{IP: localAddr},
		}
	}

	for _, addr := range conf.Listen {
		c.udpServers = append(c.udpServers, &dns.Server{
			Addr:    addr,
			Net:     "udp",
			Handler: udpHandler,
			UDPSize: dns.DefaultMsgSize,
		})
		c.tcpServers = append(c.tcpServers, &dns.Server{
			Addr:    addr,
			Net:     "tcp",
			Handler: tcpHandler,
		})
	}
	c.bootstrapResolver = net.DefaultResolver
	if len(conf.Other.Bootstrap) != 0 {
		c.bootstrap = make([]string, len(conf.Other.Bootstrap))
		for i, bootstrap := range conf.Other.Bootstrap {
			bootstrapAddr, err := net.ResolveUDPAddr("udp", bootstrap)
			if err != nil {
				bootstrapAddr, err = net.ResolveUDPAddr("udp", "["+bootstrap+"]:53")
			}
			if err != nil {
				return nil, err
			}
			c.bootstrap[i] = bootstrapAddr.String()
		}
		c.bootstrapResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var d net.Dialer
				if c.conf.Other.Interface != "" {
					localV4, localV6, err := c.getInterfaceIPs()
					if err != nil {
						log.Printf("Bootstrap dial warning: %v", err)
					} else {
						numServers := len(c.bootstrap)
						bootstrap := c.bootstrap[rand.Intn(numServers)]
						host, _, _ := net.SplitHostPort(bootstrap)
						ip := net.ParseIP(host)
						if ip != nil {
							if ip.To4() != nil {
								if localV4 != nil {
									if strings.HasPrefix(network, "udp") {
										d.LocalAddr = &net.UDPAddr{IP: localV4}
									} else {
										d.LocalAddr = &net.TCPAddr{IP: localV4}
									}
								}
							} else {
								if localV6 != nil {
									if strings.HasPrefix(network, "udp") {
										d.LocalAddr = &net.UDPAddr{IP: localV6}
									} else {
										d.LocalAddr = &net.TCPAddr{IP: localV6}
									}
								}
							}
						}
						conn, err := d.DialContext(ctx, network, bootstrap)
						return conn, err
					}
				}
				numServers := len(c.bootstrap)
				bootstrap := c.bootstrap[rand.IntN(numServers)]
				conn, err := d.DialContext(ctx, network, bootstrap)
				return conn, err
			},
		}
		if len(conf.Other.Passthrough) != 0 {
			c.passthrough = make([]string, len(conf.Other.Passthrough))
			for i, passthrough := range conf.Other.Passthrough {
				if punycode, err := idna.ToASCII(passthrough); err != nil {
					passthrough = punycode
				}
				c.passthrough[i] = "." + strings.ToLower(strings.Trim(passthrough, ".")) + "."
			}
		}
	}
	// Most CDNs require Cookie support to prevent DDoS attack.
	// Disabling Cookie does not effectively prevent tracking,
	// so I will leave it on to make anti-DDoS services happy.
	if !c.conf.Other.NoCookies {
		c.cookieJar, err = cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
	} else {
		c.cookieJar = nil
	}

	c.httpClientMux = new(sync.RWMutex)
	err = c.newHTTPClient()
	if err != nil {
		return nil, err
	}

	switch c.conf.Upstream.UpstreamSelector {
	case config.NginxWRR:
		if c.conf.Other.Verbose {
			log.Println(config.NginxWRR, "mode start")
		}

		s := selector.NewNginxWRRSelector(time.Duration(c.conf.Other.Timeout) * time.Second)
		for _, u := range c.conf.Upstream.UpstreamGoogle {
			if err := s.Add(u.URL, selector.Google, u.Weight); err != nil {
				return nil, err
			}
		}

		for _, u := range c.conf.Upstream.UpstreamIETF {
			if err := s.Add(u.URL, selector.IETF, u.Weight); err != nil {
				return nil, err
			}
		}

		c.selector = s

	case config.LVSWRR:
		if c.conf.Other.Verbose {
			log.Println(config.LVSWRR, "mode start")
		}

		s := selector.NewLVSWRRSelector(time.Duration(c.conf.Other.Timeout) * time.Second)
		for _, u := range c.conf.Upstream.UpstreamGoogle {
			if err := s.Add(u.URL, selector.Google, u.Weight); err != nil {
				return nil, err
			}
		}

		for _, u := range c.conf.Upstream.UpstreamIETF {
			if err := s.Add(u.URL, selector.IETF, u.Weight); err != nil {
				return nil, err
			}
		}

		c.selector = s

	default:
		if c.conf.Other.Verbose {
			log.Println(config.Random, "mode start")
		}

		// if selector is invalid or random, use random selector, or should we stop program and let user knows he is wrong?
		s := selector.NewRandomSelector()
		for _, u := range c.conf.Upstream.UpstreamGoogle {
			if err := s.Add(u.URL, selector.Google); err != nil {
				return nil, err
			}
		}

		for _, u := range c.conf.Upstream.UpstreamIETF {
			if err := s.Add(u.URL, selector.IETF); err != nil {
				return nil, err
			}
		}

		c.selector = s
	}

	if c.conf.Other.Verbose {
		if reporter, ok := c.selector.(selector.DebugReporter); ok {
			reporter.ReportWeights(context.Background())
		}
	}

	if c.conf.Other.LocalInterfaceName != "" {
		if err := c.PrepareDNSRules(); err != nil {
			log.Printf("Warning: failed to prepare DNS rules: %v\n", err)
		}
		if c.conf.Other.GFWListURL != nil || c.conf.Other.GFWList != nil {
			if err := c.PrepareGFWListIPSet(); err != nil {
				log.Printf("Warning: failed to prepare GFW ipset: %v\n", err)
			}
		}
	}

	if c.conf.Other.GFWListURL != nil || c.conf.Other.GFWList != nil {
		gfwList, err := gfwlist.NewGFWList(c.conf.Other.GFWListURL, c.conf.Other.GFWList)
		if err != nil {
			return nil, fmt.Errorf("failed to create gfwlist: %s", err)
		}
		c.gfwList = gfwList
	}

	if c.conf.Other.BlockList != nil {
		blockList, err := gfwlist.NewGFWList(nil, c.conf.Other.BlockList)
		if err != nil {
			return nil, fmt.Errorf("failed to create blocklist: %s", err)
		}
		c.blockList = blockList
	}

	if conf.Other.DNSShmEnabled && runtime.GOOS == "linux" {
		store, err := shmmap.Open(conf.Other.DNSShmName, conf.Other.DNSShmSize)
		if err != nil {
			log.Printf("Warning: failed to open DNS shared memory map: %v\n", err)
		} else {
			c.shmStore = store
			if conf.Other.Verbose {
				log.Printf("DNS shared memory map enabled: %s\n", conf.Other.DNSShmName)
			}
		}
	}

	return c, nil
}

func (c *Client) newHTTPClient() error {
	c.httpClientMux.Lock()
	defer c.httpClientMux.Unlock()
	if !c.httpClientLastCreate.IsZero() && time.Since(c.httpClientLastCreate) < 5*time.Minute {
		return nil
	}
	if c.httpTransport != nil {
		c.httpTransport.CloseIdleConnections()
	}

	localV4, localV6, err := c.getInterfaceIPs()
	if err != nil {
		log.Printf("Interface binding error: %v", err)
		return err
	}

	baseDialer := &net.Dialer{
		Timeout:   time.Duration(c.conf.Other.Timeout) * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  c.bootstrapResolver,
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: c.conf.Other.TLSInsecureSkipVerify}
	if c.conf.Other.TLSClientAuth {
		cert, err := tls.LoadX509KeyPair(c.conf.Other.Cert, c.conf.Other.Key)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %s", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		clientCA, err := os.ReadFile(c.conf.Other.TLSClientAuthCA)
		if err != nil {
			log.Fatalf("Reading certificate for client authentication has failed: %v", err)
		}
		clientCAPool := x509.NewCertPool()
		clientCAPool.AppendCertsFromPEM(clientCA)
		tlsConfig.RootCAs = clientCAPool
	}

	c.httpTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if c.conf.Other.Interface == "" {
				return baseDialer.DialContext(ctx, network, addr)
			}

			if network == "tcp4" && localV4 != nil {
				d := *baseDialer
				d.LocalAddr = &net.TCPAddr{IP: localV4}
				return d.DialContext(ctx, network, addr)
			}
			if network == "tcp6" && localV6 != nil {
				d := *baseDialer
				d.LocalAddr = &net.TCPAddr{IP: localV6}
				return d.DialContext(ctx, network, addr)
			}

			// Manual Dual-Stack: Resolve host and try compatible families sequentially
			host, port, _ := net.SplitHostPort(addr)
			ips, err := c.bootstrapResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}

			var lastErr error
			for _, ip := range ips {
				d := *baseDialer
				targetAddr := net.JoinHostPort(ip.String(), port)

				if ip.IP.To4() != nil {
					if localV4 == nil {
						continue
					}
					d.LocalAddr = &net.TCPAddr{IP: localV4}
				} else {
					if localV6 == nil {
						continue
					}
					d.LocalAddr = &net.TCPAddr{IP: localV6}
				}

				conn, err := d.DialContext(ctx, "tcp", targetAddr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}

			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("connection to %s failed: no matching local/remote IP families on interface %s", addr, c.conf.Other.Interface)
		},
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   time.Duration(c.conf.Other.Timeout) * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	if c.conf.Other.NoIPv6 {
		originalDial := c.httpTransport.DialContext
		c.httpTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if strings.HasPrefix(network, "tcp") {
				network = "tcp4"
			}
			return originalDial(ctx, network, address)
		}
	}

	err = http2.ConfigureTransport(c.httpTransport)
	if err != nil {
		return err
	}
	c.httpClient = &http.Client{
		Transport: c.httpTransport,
		Jar:       c.cookieJar,
	}
	c.httpClientLastCreate = time.Now()
	return nil
}

func (c *Client) Start() error {
	results := make(chan error, len(c.udpServers)+len(c.tcpServers))
	for _, srv := range append(c.udpServers, c.tcpServers...) {
		go func(srv *dns.Server) {
			err := srv.ListenAndServe()
			if err != nil {
				log.Println(err)
			}
			results <- err
		}(srv)
	}

	// start evaluation loop
	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // caller can use this to stop health-check goroutines
	c.selector.StartEvaluate(ctx)
	c.cache.startCleanup(ctx)
	if c.shmStore != nil {
		c.shmStore.StartCleanup(ctx)
	}
	if c.ipsetCh != nil {
		c.startIPSetFlusher()
	}

	for i := 0; i < cap(results); i++ {
		err := <-results
		if err != nil {
			return err
		}
	}
	close(results)

	return nil
}

func (c *Client) handlerFunc(w dns.ResponseWriter, r *dns.Msg, isTCP bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.conf.Other.Timeout)*time.Second)
	defer cancel()

	if r.Response {
		log.Println("Received a response packet")
		return
	}

	if len(r.Question) != 1 {
		log.Println("Number of questions is not 1")
		reply := jsondns.PrepareReply(r)
		reply.Rcode = dns.RcodeFormatError
		w.WriteMsg(reply)
		return
	}
	question := &r.Question[0]
	questionName := strings.ToLower(question.Name)
	questionClass := jsondns.ClassToString(question.Qclass)
	questionType := jsondns.TypeToString(question.Qtype)
	if c.conf.Other.Verbose {
		fmt.Printf("%s - - [%s] \"%s %s %s\"\n", w.RemoteAddr(), time.Now().Format("02/Jan/2006:15:04:05 -0700"), questionName, questionClass, questionType)
	}
	isBlocked, gfwBlocked := c.checkLists(questionName)
	if isBlocked {
		log.Println("Blocked:", questionName)
		reply := jsondns.PrepareReply(r)
		reply.Rcode = dns.RcodeRefused
		w.WriteMsg(reply)
		return
	}

	// Check cache
	udpSize := uint16(dns.DefaultMsgSize)
	if opt := r.IsEdns0(); opt != nil {
		udpSize = opt.UDPSize()
	}
	if buf, msg, ok := c.cache.get(questionName, question.Qtype, question.Qclass, r.Id, isTCP, udpSize); ok {
		if c.conf.Other.Verbose {
			log.Printf("cache hit: %s %s %s\n", questionName, questionClass, questionType)
		}
		c.recordResponse(msg)
		w.Write(buf)
		return
	}

	useBootstrap := c.isPassthrough(questionName)
	if c.gfwList != nil && !gfwBlocked {
		useBootstrap = true
	}
	if useBootstrap {
		if c.exchangeViaBootstrap(w, r, isTCP, questionName, questionClass, questionType) {
			return
		}
	}

	upstream := c.selector.Get()
	requestType := upstream.RequestType

	if c.conf.Other.Verbose {
		log.Println("choose upstream:", upstream)
	}

	var req *DNSRequest
	switch requestType {
	case "application/dns-json":
		req = c.generateRequestGoogle(ctx, w, r, isTCP, upstream)

	case "application/dns-message":
		req = c.generateRequestIETF(ctx, w, r, isTCP, upstream)

	default:
		panic("Unknown request Content-Type")
	}

	if req.err != nil {
		if urlErr, ok := req.err.(*url.Error); ok {
			// should we only check timeout?
			if urlErr.Timeout() {
				c.selector.ReportUpstreamStatus(upstream, selector.Timeout)
			}
		}

		return
	}

	// if req.err == nil, req.response != nil
	defer req.response.Body.Close()

	for _, header := range c.conf.Other.DebugHTTPHeaders {
		if value := req.response.Header.Get(header); value != "" {
			log.Printf("%s: %s\n", header, value)
		}
	}

	candidateType := req.response.Header.Get("Content-Type")
	if idx := strings.IndexByte(candidateType, ';'); idx >= 0 {
		candidateType = candidateType[:idx]
	}

	var fullReply *dns.Msg
	switch candidateType {
	case "application/json":
		fullReply = c.parseResponseGoogle(ctx, w, r, isTCP, req)

	case "application/dns-message", "application/dns-udpwireformat":
		fullReply = c.parseResponseIETF(ctx, w, r, isTCP, req)

	default:
		switch requestType {
		case "application/dns-json":
			fullReply = c.parseResponseGoogle(ctx, w, r, isTCP, req)

		case "application/dns-message":
			fullReply = c.parseResponseIETF(ctx, w, r, isTCP, req)

		default:
			panic("Unknown response Content-Type")
		}
	}

	if gfwBlocked && fullReply != nil {
		log.Println("GFW blocked:", questionName)
		c.AddGFWFilterIP(fullReply.Answer)
	}

	if fullReply != nil {
		c.cache.put(fullReply)
		c.recordResponse(fullReply)
	}

	// https://developers.cloudflare.com/1.1.1.1/dns-over-https/request-structure/ says
	// returns code will be 200 / 400 / 413 / 415 / 504, some server will return 503, so
	// I think if status code is 5xx, upstream must have some problems
	/*if req.response.StatusCode/100 == 5 {
		c.selector.ReportUpstreamStatus(upstream, selector.Medium)
	}*/

	switch req.response.StatusCode / 100 {
	case 5:
		c.selector.ReportUpstreamStatus(upstream, selector.Error)

	case 2:
		c.selector.ReportUpstreamStatus(upstream, selector.OK)
	}
}

func (c *Client) udpHandlerFunc(w dns.ResponseWriter, r *dns.Msg) {
	c.handlerFunc(w, r, false)
}

func (c *Client) tcpHandlerFunc(w dns.ResponseWriter, r *dns.Msg) {
	c.handlerFunc(w, r, true)
}

func (c *Client) recordResponse(msg *dns.Msg) {
	if c.shmStore == nil || msg == nil {
		return
	}
	c.shmStore.Put(msg)
}

func (c *Client) findClientIP(w dns.ResponseWriter, r *dns.Msg) (ednsClientAddress net.IP, ednsClientNetmask uint8) {
	ednsClientNetmask = 255
	if c.conf.Other.NoECS {
		return net.IPv4(0, 0, 0, 0), 0
	}
	if opt := r.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if option.Option() == dns.EDNS0SUBNET {
				edns0Subnet := option.(*dns.EDNS0_SUBNET)
				ednsClientAddress = edns0Subnet.Address
				ednsClientNetmask = edns0Subnet.SourceNetmask
				return
			}
		}
	}
	switch addr := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		if ip := addr.IP; jsondns.IsGlobalIP(ip) {
			_, ednsClientNetmask, ednsClientAddress = jsondns.GetEDNSClientInfo(ip, false)
		}
	case *net.TCPAddr:
		if ip := addr.IP; jsondns.IsGlobalIP(ip) {
			_, ednsClientNetmask, ednsClientAddress = jsondns.GetEDNSClientInfo(ip, false)
		}
	}
	return
}

// getInterfaceIPs returns the first valid IPv4 and IPv6 addresses found on the interface
func (c *Client) getInterfaceIPs() (v4, v6 net.IP, err error) {
	if c.conf.Other.Interface == "" {
		return nil, nil, nil
	}
	ifi, err := net.InterfaceByName(c.conf.Other.Interface)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, err
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if v4 == nil {
				v4 = ip4
			}
		} else {
			if v6 == nil && !c.conf.Other.NoIPv6 {
				v6 = ip
			}
		}
	}
	if v4 == nil && v6 == nil {
		return nil, nil, fmt.Errorf("no valid IP addresses found on interface %s", c.conf.Other.Interface)
	}
	return v4, v6, nil
}

func (c *Client) checkLists(domain string) (isBlocked, isGFWBlocked bool) {
	c.gfwLock.RLock()
	defer c.gfwLock.RUnlock()
	domain = strings.TrimSuffix(domain, ".")
	isBlocked = c.blockList != nil && c.blockList.IsBlockedByGFW(domain)
	isGFWBlocked = c.gfwList != nil && c.gfwList.IsBlockedByGFW(domain)
	return
}

func (c *Client) isPassthrough(domain string) bool {
	if len(c.passthrough) == 0 {
		return false
	}
	domain = strings.ToLower(domain)
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	for _, pt := range c.passthrough {
		if strings.HasSuffix(domain, pt) {
			return true
		}
	}
	return false
}

func (c *Client) exchangeViaBootstrap(w dns.ResponseWriter, r *dns.Msg, isTCP bool, questionName, questionClass, questionType string) bool {
	if len(c.bootstrap) == 0 {
		return false
	}
	upstream := c.bootstrap[rand.IntN(len(c.bootstrap))]
	log.Printf("Request \"%s %s %s\" is passed through %s.\n", questionName, questionClass, questionType, upstream)
	var reply *dns.Msg
	var err error
	if !isTCP {
		reply, _, err = c.udpClient.Exchange(r, upstream)
	} else {
		reply, _, err = c.tcpClient.Exchange(r, upstream)
	}
	if err == nil {
		c.recordResponse(reply)
		w.WriteMsg(reply)
		return true
	}
	log.Println(err)
	reply = jsondns.PrepareReply(r)
	reply.Rcode = dns.RcodeServerFailure
	w.WriteMsg(reply)
	return true
}

func (c *Client) AddGFWFilterIP(answers []dns.RR) {
	// Collect all IPv4 addresses from answer records
	for _, ans := range answers {
		if rr, ok := ans.(*dns.A); ok {
			select {
			case c.ipsetCh <- rr.A.String():
			default:
				// channel full, drop — flusher will catch up
			}
		}
	}
}

func (c *Client) startIPSetFlusher() {
	go func() {
		var ips []string
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case ip := <-c.ipsetCh:
				ips = append(ips, ip)
				// Drain any additional queued IPs without blocking
				for len(ips) < 128 {
					select {
					case ip := <-c.ipsetCh:
						ips = append(ips, ip)
					default:
						goto flush
					}
				}
			flush:
				c.flushIPSet(ips)
				ips = ips[:0]
			case <-ticker.C:
				if len(ips) > 0 {
					c.flushIPSet(ips)
					ips = ips[:0]
				}
			}
		}
	}()
}

func (c *Client) flushIPSet(ips []string) {
	cmd := exec.Command("ipset", "restore")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Println("Failed to create ipset restore stdin pipe", "error", err)
		return
	}
	for _, ip := range ips {
		fmt.Fprintf(stdin, "add %s %s -exist\n", GFW_IPLIST, ip)
	}
	stdin.Close()
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("Failed to add IPs to ipset via restore", "output", string(out), "error", err)
	}
}

type RouterRules struct {
	ipt *iptables.IPTables
	// dns
	dnsRule []string
	// prerouting
	preRoutingRule []string
	// postrouting
	postRoutingRule []string
}

func (c *Client) PrepareDNSRules() error {
	ipt, err := iptables.New(iptables.Path(c.conf.Other.IPTablesPath), iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}

	localCIDR, err := GetRouteTable(c.conf.Other.LocalInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get local CIDR: %s", err)
	}

	localIP, err := GetIPFromInterface(c.conf.Other.LocalInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get local IP: %s", err)
	}

	_, port, err := net.SplitHostPort(c.conf.Listen[0])
	if err != nil {
		return fmt.Errorf("failed to split host port: %s", err)
	}

	dnsRule := []string{
		"-s", localCIDR,
		"-p", "udp",
		"--dport", "53",
		"-j", "DNAT",
		"--to-destination", net.JoinHostPort(localIP, port),
	}
	err = ipt.AppendUnique("nat", "PREROUTING", dnsRule...)
	if err != nil {
		return fmt.Errorf("failed to create dns iptables: %s", err)
	}
	c.routerRules.dnsRule = dnsRule
	if c.routerRules.ipt == nil {
		c.routerRules.ipt = ipt
	}

	return nil
}

func (c *Client) PrepareGFWListIPSet() error {
	out, err := exec.Command("ipset", "create", GFW_IPLIST, "hash:ip", "-exist").CombinedOutput()
	if err != nil {
		log.Println("Create ipset", "ipset", GFW_IPLIST, "output", string(out))
		return err
	}

	localCIDR, err := GetRouteTable(c.conf.Other.LocalInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get local CIDR: %s", err)
	}

	localIP, err := GetIPFromInterface(c.conf.Other.LocalInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get local IP: %s", err)
	}

	gfwlistRule := []string{
		"-s", localCIDR,
		"-p", "tcp",
		"-m", "set",
		"--match-set", GFW_IPLIST,
		"dst",
		"-j", "DNAT",
		"--to-destination", net.JoinHostPort(localIP, strconv.Itoa(c.conf.Other.ProxyPort)),
	}

	ipt, err := iptables.New(iptables.Path(c.conf.Other.IPTablesPath), iptables.IPFamily(iptables.ProtocolIPv4))
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}
	if c.routerRules.ipt == nil {
		c.routerRules.ipt = ipt
	}

	err = ipt.AppendUnique("nat", "PREROUTING", gfwlistRule...)
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}
	c.routerRules.preRoutingRule = gfwlistRule

	postRoutingRule := []string{
		"-s", localCIDR,
		"-j", "MASQUERADE",
	}
	err = ipt.AppendUnique("nat", "POSTROUTING", postRoutingRule...)
	if err != nil {
		return fmt.Errorf("failed to create gfwlist iptables: %s", err)
	}
	c.routerRules.postRoutingRule = postRoutingRule

	return nil
}

func GetIPFromInterface(iferName string) (string, error) {
	nlHandle, err := netlink.NewHandle()
	if err != nil {
		return "", fmt.Errorf("failed to create netlink handle: %s", err)
	}
	defer nlHandle.Close()

	link, err := nlHandle.LinkByName(iferName)
	if err != nil {
		return "", fmt.Errorf("failed to get link by name: %s", err)
	}

	addrs, err := nlHandle.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to get address list: %s", err)
	}

	for _, addr := range addrs {
		if !addr.IP.IsLoopback() {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				return ipv4.String(), nil
			}
		}
	}

	return "", fmt.Errorf("interface not found: %s", iferName)
}

func GetRouteTable(ifName string) (string, error) {
	if ifName == "" {
		return "", fmt.Errorf("interface name is empty")
	}
	// Get system routing rules
	routeFile, err := os.Open("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("failed to open route file: %v", err)
	}
	defer routeFile.Close()

	scanner := bufio.NewScanner(routeFile)
	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		iface := fields[0]
		destHex := fields[1]
		maskHex := fields[7]

		if iface != ifName {
			continue
		}

		dest, err := hex.DecodeString(destHex)
		if err != nil || len(dest) < 4 {
			continue
		}
		mask, err := hex.DecodeString(maskHex)
		if err != nil || len(mask) < 4 {
			continue
		}
		cidr := net.IPNet{
			IP:   net.IPv4(dest[3], dest[2], dest[1], dest[0]),
			Mask: net.IPv4Mask(mask[3], mask[2], mask[1], mask[0]),
		}

		return cidr.String(), nil
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read route file: %v", err)
	}

	return "", fmt.Errorf("no route found for interface %q", ifName)
}

func (c *Client) cleanRules() {
	log.Println("Cleaning router rules")
	if c.routerRules.ipt != nil {
		if len(c.routerRules.dnsRule) > 0 {
			c.routerRules.ipt.DeleteIfExists("nat", "PREROUTING", c.routerRules.dnsRule...)
		}

		if len(c.routerRules.preRoutingRule) > 0 {
			c.routerRules.ipt.DeleteIfExists("nat", "PREROUTING", c.routerRules.preRoutingRule...)
		}

		if len(c.routerRules.postRoutingRule) > 0 {
			c.routerRules.ipt.DeleteIfExists("nat", "POSTROUTING", c.routerRules.postRoutingRule...)
		}
	}

	exec.Command("ipset", "flush", GFW_IPLIST).CombinedOutput()
	exec.Command("ipset", "destroy", GFW_IPLIST).CombinedOutput()
}
