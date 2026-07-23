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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

func (s *Server) parseRequestIETF(ctx context.Context, w http.ResponseWriter, r *http.Request) *DNSRequest {
	requestBase64 := r.FormValue("dns")
	if len(requestBase64) > 65536 {
		return &DNSRequest{
			errcode: 400,
			errtext: fmt.Sprintf("Invalid argument value: \"dns\" too long"),
		}
	}
	requestBinary, err := base64.RawURLEncoding.DecodeString(requestBase64)
	if err != nil {
		return &DNSRequest{
			errcode: 400,
			errtext: fmt.Sprintf("Invalid argument value: \"dns\" = %q", requestBase64),
		}
	}
	if len(requestBinary) == 0 && (r.Header.Get("Content-Type") == "application/dns-message" || r.Header.Get("Content-Type") == "application/dns-udpwireformat") {
		const maxBodySize = 65536
		requestBinary, err = io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err != nil {
			return &DNSRequest{
				errcode: 400,
				errtext: fmt.Sprintf("Failed to read request body (%s)", err.Error()),
			}
		}
	}
	if len(requestBinary) == 0 {
		return &DNSRequest{
			errcode: 400,
			errtext: "Invalid argument value: \"dns\"",
		}
	}

	if s.patchDNSCryptProxyReqID(w, r, requestBinary) {
		return &DNSRequest{
			errcode: 444,
		}
	}

	msg := new(dns.Msg)
	err = msg.Unpack(requestBinary)
	if err != nil {
		return &DNSRequest{
			errcode: 400,
			errtext: fmt.Sprintf("DNS packet parse failure (%s)", err.Error()),
		}
	}

	if s.conf.Verbose && len(msg.Question) > 0 {
		question := &msg.Question[0]
		questionName := question.Name
		questionClass := jsondns.ClassToString(question.Qclass)
		questionType := jsondns.TypeToString(question.Qtype)
		var clientip net.IP = nil
		if s.conf.LogGuessedIP {
			clientip = s.findClientIP(r)
		}
		if clientip != nil {
			fmt.Printf("%s - - [%s] \"%s %s %s\"\n", clientip, time.Now().Format("02/Jan/2006:15:04:05 -0700"), questionName, questionClass, questionType)
		} else {
			fmt.Printf("%s - - [%s] \"%s %s %s\"\n", r.RemoteAddr, time.Now().Format("02/Jan/2006:15:04:05 -0700"), questionName, questionClass, questionType)
		}
	}

	transactionID := msg.Id
	msg.Id = dns.Id()
	opt := msg.IsEdns0()
	if opt == nil {
		opt = jsondns.NewOPTRecord(dns.DefaultMsgSize, false)
		msg.Extra = append(msg.Extra, opt)
	}
	var edns0Subnet *dns.EDNS0_SUBNET
	for _, option := range opt.Option {
		if option.Option() == dns.EDNS0SUBNET {
			edns0Subnet = option.(*dns.EDNS0_SUBNET)
			break
		}
	}
	isTailored := edns0Subnet == nil

	if edns0Subnet == nil {
		ednsClientAddress := s.findClientIP(r)
		if ednsClientAddress != nil {
			ednsClientFamily, ednsClientNetmask, ednsClientAddress := jsondns.GetEDNSClientInfo(ednsClientAddress, s.conf.ECSUsePreciseIP)
			edns0Subnet = jsondns.NewEDNS0Subnet(ednsClientFamily, ednsClientNetmask, ednsClientAddress)
			opt.Option = append(opt.Option, edns0Subnet)
		}
	}

	return &DNSRequest{
		request:       msg,
		transactionID: transactionID,
		isTailored:    isTailored,
	}
}

func (s *Server) generateResponseIETF(ctx context.Context, w http.ResponseWriter, r *http.Request, req *DNSRequest) {
	respMeta := jsondns.ComputeResponseMeta(req.response)
	req.response.Id = req.transactionID
	respBytes, err := req.response.Pack()
	if err != nil {
		log.Printf("DNS packet construct failure with upstream %s: %v\n", req.currentUpstream, err)
		jsondns.FormatError(w, fmt.Sprintf("DNS packet construct failure (%s)", err.Error()), 500)
		return
	}

	setDNSResponseHeaders(w, "application/dns-message", respMeta, req.isTailored)

	if respMeta.Status == dns.RcodeServerFailure {
		log.Printf("received server failure from upstream %s: %v\n", req.currentUpstream, req.response)
		w.WriteHeader(503)
	}
	_, err = w.Write(respBytes)
	if err != nil {
		log.Printf("failed to write to client: %v\n", err)
	}
}

// Workaround a bug causing DNSCrypt-Proxy to expect a response with TransactionID = 0xcafe.
func (s *Server) patchDNSCryptProxyReqID(w http.ResponseWriter, r *http.Request, requestBinary []byte) bool {
	if strings.Contains(r.UserAgent(), "dnscrypt-proxy") && bytes.Equal(requestBinary, []byte("\xca\xfe\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x02\x00\x01\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00")) {
		if s.conf.Verbose {
			log.Println("DNSCrypt-Proxy detected. Patching response.")
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Vary", "Accept, User-Agent")
		now := time.Now().UTC().Format(http.TimeFormat)
		w.Header().Set("Date", now)
		w.Write([]byte("\xca\xfe\x81\x05\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\xa8\xa7\r\nWorkaround a bug causing DNSCrypt-Proxy to expect a response with TransactionID = 0xcafe\r\nRefer to https://github.com/jedisct1/dnscrypt-proxy/issues/526 for details."))
		return true
	}
	return false
}
