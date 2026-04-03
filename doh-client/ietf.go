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
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/m13253/dns-over-https/v2/doh-client/selector"
	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

func (c *Client) generateRequestIETF(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, isTCP bool, upstream *selector.Upstream) *DNSRequest {
	opt := r.IsEdns0()
	udpSize := uint16(512)
	if opt == nil {
		opt = jsondns.NewOPTRecord(dns.DefaultMsgSize, false)
		r.Extra = append([]dns.RR{opt}, r.Extra...)
	} else {
		udpSize = opt.UDPSize()
	}
	var edns0Subnet *dns.EDNS0_SUBNET
	for _, option := range opt.Option {
		if option.Option() == dns.EDNS0SUBNET {
			edns0Subnet = option.(*dns.EDNS0_SUBNET)
			break
		}
	}
	ednsClientAddress, ednsClientNetmask := net.IP(nil), uint8(255)
	if edns0Subnet == nil {
		ednsClientAddress, ednsClientNetmask = c.findClientIP(w, r)
		if ednsClientAddress != nil {
			ednsClientFamily, netmask, addr := jsondns.GetEDNSClientInfo(ednsClientAddress, false)
			ednsClientAddress = addr
			ednsClientNetmask = netmask
			edns0Subnet = jsondns.NewEDNS0Subnet(ednsClientFamily, ednsClientNetmask, ednsClientAddress)
			opt.Option = append(opt.Option, edns0Subnet)
		}
	} else {
		ednsClientAddress, ednsClientNetmask = edns0Subnet.Address, edns0Subnet.SourceNetmask
	}

	requestID := r.Id
	r.Id = 0
	requestBinary, err := r.Pack()
	if err != nil {
		return sendErrorReply(w, r, dns.RcodeFormatError, err)
	}
	r.Id = requestID
	requestBase64 := base64.RawURLEncoding.EncodeToString(requestBinary)

	requestURL := upstream.URL + "?ct=application/dns-message&dns=" + requestBase64

	var req *http.Request
	if len(requestURL) < 2048 {
		req, err = http.NewRequest(http.MethodGet, requestURL, http.NoBody)
		if err != nil {
			return sendErrorReply(w, r, dns.RcodeServerFailure, err)
		}
	} else {
		req, err = http.NewRequest(http.MethodPost, upstream.URL, bytes.NewReader(requestBinary))
		if err != nil {
			return sendErrorReply(w, r, dns.RcodeServerFailure, err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
	}
	req.Header.Set("Accept", "application/dns-message, application/dns-udpwireformat, application/json")
	if !c.conf.Other.NoUserAgent {
		req.Header.Set("User-Agent", USER_AGENT)
	} else {
		req.Header.Set("User-Agent", "")
	}
	req = req.WithContext(ctx)
	c.httpClientMux.RLock()
	resp, err := c.httpClient.Do(req)
	c.httpClientMux.RUnlock()

	// if http Client.Do returns non-nil error, it always *url.Error
	/*if err == context.DeadlineExceeded {
		// Do not respond, silently fail to prevent caching of SERVFAIL
		log.Println(err)
		return &DNSRequest{
			err: err,
		}
	}*/

	if err != nil {
		return sendErrorReply(w, r, dns.RcodeServerFailure, err)
	}

	return &DNSRequest{
		response:          resp,
		reply:             jsondns.PrepareReply(r),
		udpSize:           udpSize,
		ednsClientAddress: ednsClientAddress,
		ednsClientNetmask: ednsClientNetmask,
		currentUpstream:   upstream.URL,
	}
}

func (c *Client) parseResponseIETF(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, isTCP bool, req *DNSRequest) *dns.Msg {
	defer req.response.Body.Close()

	if req.response.StatusCode != http.StatusOK {
		log.Printf("HTTP error from upstream %s: %s\n", req.currentUpstream, req.response.Status)
		req.reply.Rcode = dns.RcodeServerFailure
		contentType := req.response.Header.Get("Content-Type")
		if contentType != "application/dns-message" && !strings.HasPrefix(contentType, "application/dns-message;") {
			w.WriteMsg(req.reply)
			return nil
		}
	}

	body, err := io.ReadAll(req.response.Body)
	if err != nil {
		log.Printf("read error from upstream %s: %v\n", req.currentUpstream, err)
		req.reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(req.reply)
		return nil
	}
	headerNow := req.response.Header.Get("Date")
	now := time.Now().UTC()
	if headerNow != "" {
		if nowDate, err := time.Parse(http.TimeFormat, headerNow); err == nil {
			now = nowDate
		} else {
			log.Printf("Date header parse error from upstream %s: %v\n", req.currentUpstream, err)
		}
	}
	headerLastModified := req.response.Header.Get("Last-Modified")
	lastModified := now
	if headerLastModified != "" {
		if lastModifiedDate, err := time.Parse(http.TimeFormat, headerLastModified); err == nil {
			lastModified = lastModifiedDate
		} else {
			log.Printf("Last-Modified header parse error from upstream %s: %v\n", req.currentUpstream, err)
		}
	}
	timeDelta := now.Sub(lastModified)
	if timeDelta < 0 {
		timeDelta = 0
	}

	fullReply := new(dns.Msg)
	err = fullReply.Unpack(body)
	if err != nil {
		log.Printf("unpacking error from upstream %s: %v\n", req.currentUpstream, err)
		req.reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(req.reply)
		return nil
	}

	fullReply.Id = r.Id
	for _, rr := range fullReply.Answer {
		_ = fixRecordTTL(rr, timeDelta)
	}
	for _, rr := range fullReply.Ns {
		_ = fixRecordTTL(rr, timeDelta)
	}
	for _, rr := range fullReply.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		_ = fixRecordTTL(rr, timeDelta)
	}

	if isTCP {
		fullReply.Truncate(dns.MaxMsgSize)
	} else {
		fullReply.Truncate(int(req.udpSize))
	}
	buf, err := fullReply.Pack()
	if err != nil {
		log.Printf("packing error with upstream %s: %v\n", req.currentUpstream, err)
		req.reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(req.reply)
		return nil
	}
	_, err = w.Write(buf)
	if err != nil {
		log.Printf("failed to write to client: %v\n", err)
	}
	return fullReply
}

func fixRecordTTL(rr dns.RR, delta time.Duration) dns.RR {
	rrHeader := rr.Header()
	oldTTL := time.Duration(rrHeader.Ttl) * time.Second
	newTTL := oldTTL - delta
	if newTTL > 0 {
		rrHeader.Ttl = uint32(newTTL / time.Second)
	} else {
		rrHeader.Ttl = 0
	}
	return rr
}
