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
	"log"
	"net"

	"github.com/miekg/dns"

	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

// sendErrorReply logs the error (if non-nil), sends a DNS error reply with the given rcode,
// and returns a DNSRequest with the error set.
func sendErrorReply(w dns.ResponseWriter, r *dns.Msg, rcode int, err error) *DNSRequest {
	if err != nil {
		log.Println(err)
	}
	reply := jsondns.PrepareReply(r)
	reply.Rcode = rcode
	w.WriteMsg(reply)
	return &DNSRequest{
		err: err,
	}
}


// truncateForTransport returns a copy of msg truncated for the client transport.
// The input message is left intact so callers can cache/record the full answer.
func truncateForTransport(msg *dns.Msg, isTCP bool, udpSize uint16) *dns.Msg {
	out := msg.Copy()
	if isTCP {
		out.Truncate(dns.MaxMsgSize)
	} else {
		out.Truncate(int(udpSize))
	}
	return out
}

// voidResponseWriter is a dns.ResponseWriter that discards everything written
// to it. The cache refresh path reuses generateRequest*/parseResponse* so that a
// refreshed answer is obtained by exactly the same protocol logic as a
// client-driven query; those helpers write their reply through the
// ResponseWriter, and a refresh must not write to any real client.
type voidResponseWriter struct{}

func (voidResponseWriter) LocalAddr() net.Addr  { return nil }
func (voidResponseWriter) RemoteAddr() net.Addr { return nil }

func (voidResponseWriter) WriteMsg(*dns.Msg) error { return nil }

func (voidResponseWriter) Write(p []byte) (int, error) { return len(p), nil }

func (voidResponseWriter) Close() error { return nil }

func (voidResponseWriter) TsigStatus() error { return nil }

func (voidResponseWriter) TsigTimersOnly(bool) {}

func (voidResponseWriter) Hijack() {}
