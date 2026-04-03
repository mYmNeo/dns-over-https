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

	"github.com/miekg/dns"
)

// GetEDNSClientInfo determines the EDNS client subnet family, netmask, and address
// based on the provided IP. If precise is true, it uses /32 for IPv4 and /128 for IPv6;
// otherwise it uses /24 for IPv4 and /56 for IPv6 (and masks accordingly).
// Returns family=0 if ip is nil.
func GetEDNSClientInfo(ip net.IP, precise bool) (family uint16, netmask uint8, addr net.IP) {
	if ip == nil {
		return 0, 0, nil
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		family = 1
		addr = ipv4
		if precise {
			netmask = 32
		} else {
			netmask = 24
			addr = addr.Mask(net.CIDRMask(24, 32))
		}
	} else {
		family = 2
		addr = ip
		if precise {
			netmask = 128
		} else {
			netmask = 56
			addr = addr.Mask(net.CIDRMask(56, 128))
		}
	}
	return
}

// NewEDNS0Subnet creates a new EDNS0_SUBNET option with the given parameters.
func NewEDNS0Subnet(family uint16, netmask uint8, addr net.IP) *dns.EDNS0_SUBNET {
	edns0Subnet := new(dns.EDNS0_SUBNET)
	edns0Subnet.Code = dns.EDNS0SUBNET
	edns0Subnet.Family = family
	edns0Subnet.SourceNetmask = netmask
	edns0Subnet.SourceScope = 0
	edns0Subnet.Address = addr
	return edns0Subnet
}

// NewOPTRecord creates a new OPT pseudo-RR with the given UDP buffer size and DO flag.
func NewOPTRecord(udpSize uint16, setDO bool) *dns.OPT {
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(udpSize)
	opt.SetDo(setDO)
	return opt
}
