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

package jsondns

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func Marshal(msg *dns.Msg) *Response {
	now := time.Now().UTC()

	resp := new(Response)
	resp.Status = uint32(msg.Rcode)
	resp.TC = msg.Truncated
	resp.RD = msg.RecursionDesired
	resp.RA = msg.RecursionAvailable
	resp.AD = msg.AuthenticatedData
	resp.CD = msg.CheckingDisabled

	resp.Question = make([]Question, 0, len(msg.Question))
	for _, question := range msg.Question {
		jsonQuestion := Question{
			Name: question.Name,
			Type: question.Qtype,
		}
		resp.Question = append(resp.Question, jsonQuestion)
	}

	resp.Answer = make([]RR, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		jsonAnswer := marshalRR(rr, now)
		if !resp.HaveTTL || jsonAnswer.TTL < resp.LeastTTL {
			resp.HaveTTL = true
			resp.LeastTTL = jsonAnswer.TTL
			resp.EarliestExpires = jsonAnswer.Expires
		}
		resp.Answer = append(resp.Answer, jsonAnswer)
	}

	resp.Authority = make([]RR, 0, len(msg.Ns))
	for _, rr := range msg.Ns {
		jsonAuthority := marshalRR(rr, now)
		if !resp.HaveTTL || jsonAuthority.TTL < resp.LeastTTL {
			resp.HaveTTL = true
			resp.LeastTTL = jsonAuthority.TTL
			resp.EarliestExpires = jsonAuthority.Expires
		}
		resp.Authority = append(resp.Authority, jsonAuthority)
	}

	resp.Additional = make([]RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		jsonAdditional := marshalRR(rr, now)
		header := rr.Header()
		if header.Rrtype == dns.TypeOPT {
			opt := rr.(*dns.OPT)
			resp.Status = ((opt.Hdr.Ttl & 0xff000000) >> 20) | (resp.Status & 0xff)
			for _, option := range opt.Option {
				if option.Option() == dns.EDNS0SUBNET {
					edns0 := option.(*dns.EDNS0_SUBNET)
					clientAddress := edns0.Address
					if clientAddress == nil {
						clientAddress = net.IP{0, 0, 0, 0}
					} else if ipv4 := clientAddress.To4(); ipv4 != nil {
						clientAddress = ipv4
					}
					resp.EdnsClientSubnet = clientAddress.String() + "/" + strconv.FormatUint(uint64(edns0.SourceScope), 10)
				}
			}
			continue
		}
		if !resp.HaveTTL || jsonAdditional.TTL < resp.LeastTTL {
			resp.HaveTTL = true
			resp.LeastTTL = jsonAdditional.TTL
			resp.EarliestExpires = jsonAdditional.Expires
		}
		resp.Additional = append(resp.Additional, jsonAdditional)
	}

	return resp
}

// ComputeResponseMeta computes only the metadata fields (Status, HaveTTL,
// LeastTTL, EarliestExpires) from a dns.Msg without performing full string
// conversion of RR data. This is much cheaper than Marshal when only the
// metadata is needed (e.g., for setting HTTP cache headers on binary responses).
func ComputeResponseMeta(msg *dns.Msg) *Response {
	now := time.Now().UTC()

	resp := &Response{
		Status: uint32(msg.Rcode),
	}

	// Scan all sections for minimum TTL
	scanTTL := func(rrs []dns.RR) {
		for _, rr := range rrs {
			header := rr.Header()
			if header.Rrtype == dns.TypeOPT {
				opt := rr.(*dns.OPT)
				resp.Status = ((opt.Hdr.Ttl & 0xff000000) >> 20) | (resp.Status & 0xff)
				continue
			}
			ttl := header.Ttl
			expires := now.Add(time.Duration(ttl) * time.Second)
			if !resp.HaveTTL || ttl < resp.LeastTTL {
				resp.HaveTTL = true
				resp.LeastTTL = ttl
				resp.EarliestExpires = expires
			}
		}
	}

	scanTTL(msg.Answer)
	scanTTL(msg.Ns)
	scanTTL(msg.Extra)

	return resp
}

func marshalRR(rr dns.RR, now time.Time) RR {
	jsonRR := RR{}
	rrHeader := rr.Header()
	jsonRR.Name = rrHeader.Name
	jsonRR.Type = rrHeader.Rrtype
	jsonRR.TTL = rrHeader.Ttl
	jsonRR.Expires = now.Add(time.Duration(jsonRR.TTL) * time.Second)
	jsonRR.ExpiresStr = jsonRR.Expires.Format(time.RFC1123)

	// Extract data field after the last tab in the RR string representation.
	// Format: "name\tTTL\tCLASS\tTYPE\tDATA" — DATA is the last field;
	// miekg/dns escapes tabs in RDATA, so the last tab is the TYPE→DATA separator.
	s := rr.String()
	_, data, found := strings.CutLast(s, "\t")
	if found {
		jsonRR.Data = data
	}
	return jsonRR
}
