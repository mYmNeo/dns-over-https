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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"

	jsondns "github.com/m13253/dns-over-https/v2/json-dns"
)

func (s *Server) parseRequestGoogle(ctx context.Context, w http.ResponseWriter, r *http.Request) *DNSRequest {
	name := r.FormValue("name")
	if name == "" {
		return &DNSRequest{
			errcode: 400,
			errtext: "Invalid argument value: \"name\"",
		}
	}
	if punycode, err := idna.ToASCII(name); err == nil {
		name = punycode
	} else {
		return &DNSRequest{
			errcode: 400,
			errtext: fmt.Sprintf("Invalid argument value: \"name\" = %q (%s)", name, err.Error()),
		}
	}

	rrTypeStr := r.FormValue("type")
	rrType := uint16(1)
	if rrTypeStr == "" {
	} else if v, err := strconv.ParseUint(rrTypeStr, 10, 16); err == nil {
		rrType = uint16(v)
	} else if v, ok := dns.StringToType[strings.ToUpper(rrTypeStr)]; ok {
		rrType = v
	} else {
		return &DNSRequest{
			errcode: 400,
			errtext: fmt.Sprintf("Invalid argument value: \"type\" = %q", rrTypeStr),
		}
	}

	cdStr := r.FormValue("cd")
	cd := false
	if cdStr == "1" || strings.EqualFold(cdStr, "true") {
		cd = true
	} else if cdStr == "0" || strings.EqualFold(cdStr, "false") || cdStr == "" {
	} else {
		return &DNSRequest{
			errcode: 400,
			errtext: fmt.Sprintf("Invalid argument value: \"cd\" = %q", cdStr),
		}
	}

	ednsClientSubnet := r.FormValue("edns_client_subnet")
	ednsClientFamily := uint16(0)
	ednsClientAddress := net.IP(nil)
	ednsClientNetmask := uint8(255)
	if ednsClientSubnet != "" {
		if ednsClientSubnet == "0/0" {
			ednsClientSubnet = "0.0.0.0/0"
		}

		var err error
		ednsClientFamily, ednsClientAddress, ednsClientNetmask, err = parseSubnet(ednsClientSubnet)
		if err != nil {
			return &DNSRequest{
				errcode: 400,
				errtext: err.Error(),
			}
		}
	} else {
		ednsClientAddress = s.findClientIP(r)
		if ednsClientAddress == nil {
			ednsClientNetmask = 0
		} else {
			ednsClientFamily, ednsClientNetmask, ednsClientAddress = jsondns.GetEDNSClientInfo(ednsClientAddress, false)
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), rrType)
	msg.CheckingDisabled = cd
	opt := jsondns.NewOPTRecord(dns.DefaultMsgSize, true)
	if ednsClientAddress != nil {
		edns0Subnet := jsondns.NewEDNS0Subnet(ednsClientFamily, ednsClientNetmask, ednsClientAddress)
		opt.Option = append(opt.Option, edns0Subnet)
	}
	msg.Extra = append(msg.Extra, opt)

	return &DNSRequest{
		request:    msg,
		isTailored: ednsClientSubnet == "",
	}
}

func parseSubnet(ednsClientSubnet string) (ednsClientFamily uint16, ednsClientAddress net.IP, ednsClientNetmask uint8, err error) {
	slash := strings.IndexByte(ednsClientSubnet, '/')
	if slash < 0 {
		ednsClientAddress = net.ParseIP(ednsClientSubnet)
		if ednsClientAddress == nil {
			err = fmt.Errorf("Invalid argument value: \"edns_client_subnet\" = %q", ednsClientSubnet)
			return
		}
		if ipv4 := ednsClientAddress.To4(); ipv4 != nil {
			ednsClientFamily = 1
			ednsClientAddress = ipv4
			ednsClientNetmask = 24
		} else {
			ednsClientFamily = 2
			ednsClientNetmask = 56
		}
	} else {
		ednsClientAddress = net.ParseIP(ednsClientSubnet[:slash])
		if ednsClientAddress == nil {
			err = fmt.Errorf("Invalid argument value: \"edns_client_subnet\" = %q", ednsClientSubnet)
			return
		}
		netmask, err1 := strconv.ParseUint(ednsClientSubnet[slash+1:], 10, 8)
		if err1 != nil {
			err = fmt.Errorf("Invalid argument value: \"edns_client_subnet\" = %q", ednsClientSubnet)
			return
		}
		ednsClientNetmask = uint8(netmask)
		if ipv4 := ednsClientAddress.To4(); ipv4 != nil {
			// Pure IPv4 address: reject netmask > 32.
			// IPv4-mapped IPv6 (e.g. ::ffff:x.x.x.x) with netmask > 32: keep as IPv6.
			if ednsClientNetmask > 32 && !strings.Contains(ednsClientSubnet[:slash], ":") {
				err = fmt.Errorf("Invalid argument value: \"edns_client_subnet\" = %q", ednsClientSubnet)
				return
			}
			if ednsClientNetmask <= 32 {
				ednsClientFamily = 1
				ednsClientAddress = ipv4
			} else if ednsClientNetmask > 128 {
				err = fmt.Errorf("Invalid argument value: \"edns_client_subnet\" = %q", ednsClientSubnet)
				return
			} else {
				ednsClientFamily = 2
			}
		} else if ednsClientNetmask > 128 {
			err = fmt.Errorf("Invalid argument value: \"edns_client_subnet\" = %q", ednsClientSubnet)
			return
		} else {
			ednsClientFamily = 2
		}
	}

	return
}

func (s *Server) generateResponseGoogle(ctx context.Context, w http.ResponseWriter, r *http.Request, req *DNSRequest) {
	respJSON := jsondns.Marshal(req.response)
	respStr, err := json.Marshal(respJSON)
	if err != nil {
		log.Println(err)
		jsondns.FormatError(w, fmt.Sprintf("DNS packet parse failure (%s)", err.Error()), 500)
		return
	}

	setDNSResponseHeaders(w, "application/json; charset=UTF-8", respJSON, req.isTailored)
	if respJSON.Status == dns.RcodeServerFailure {
		w.WriteHeader(503)
	}
	w.Write(respStr)
}
