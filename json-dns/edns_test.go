package jsondns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestGetEDNSClientInfoIPv4(t *testing.T) {
	t.Parallel()
	ip := net.ParseIP("192.168.1.100")

	family, netmask, addr := GetEDNSClientInfo(ip, false)
	if family != 1 {
		t.Errorf("expected family 1, got %d", family)
	}
	if netmask != 24 {
		t.Errorf("expected netmask 24, got %d", netmask)
	}
	expected := ip.To4().Mask(net.CIDRMask(24, 32))
	if !addr.Equal(expected) {
		t.Errorf("expected masked address %s, got %s", expected, addr)
	}
}

func TestGetEDNSClientInfoIPv4Precise(t *testing.T) {
	t.Parallel()
	ip := net.ParseIP("192.168.1.100")

	family, netmask, addr := GetEDNSClientInfo(ip, true)
	if family != 1 {
		t.Errorf("expected family 1, got %d", family)
	}
	if netmask != 32 {
		t.Errorf("expected netmask 32, got %d", netmask)
	}
	if !addr.Equal(ip.To4()) {
		t.Errorf("expected address %s, got %s", ip, addr)
	}
}

func TestGetEDNSClientInfoIPv6(t *testing.T) {
	t.Parallel()
	ip := net.ParseIP("2001:db8::1")

	family, netmask, addr := GetEDNSClientInfo(ip, false)
	if family != 2 {
		t.Errorf("expected family 2, got %d", family)
	}
	if netmask != 56 {
		t.Errorf("expected netmask 56, got %d", netmask)
	}
	expected := ip.Mask(net.CIDRMask(56, 128))
	if !addr.Equal(expected) {
		t.Errorf("expected masked address %s, got %s", expected, addr)
	}
}

func TestGetEDNSClientInfoIPv6Precise(t *testing.T) {
	t.Parallel()
	ip := net.ParseIP("2001:db8::1")

	family, netmask, addr := GetEDNSClientInfo(ip, true)
	if family != 2 {
		t.Errorf("expected family 2, got %d", family)
	}
	if netmask != 128 {
		t.Errorf("expected netmask 128, got %d", netmask)
	}
	if !addr.Equal(ip) {
		t.Errorf("expected address %s, got %s", ip, addr)
	}
}

func TestGetEDNSClientInfoNil(t *testing.T) {
	t.Parallel()
	family, netmask, addr := GetEDNSClientInfo(nil, false)
	if family != 0 || netmask != 0 || addr != nil {
		t.Errorf("expected zero values for nil IP, got family=%d netmask=%d addr=%v", family, netmask, addr)
	}
}

func TestNewEDNS0Subnet(t *testing.T) {
	t.Parallel()
	ip := net.ParseIP("192.168.1.0").To4()
	subnet := NewEDNS0Subnet(1, 24, ip)
	if subnet.Code != dns.EDNS0SUBNET {
		t.Errorf("expected EDNS0SUBNET code, got %d", subnet.Code)
	}
	if subnet.Family != 1 {
		t.Errorf("expected family 1, got %d", subnet.Family)
	}
	if subnet.SourceNetmask != 24 {
		t.Errorf("expected source netmask 24, got %d", subnet.SourceNetmask)
	}
	if subnet.SourceScope != 0 {
		t.Errorf("expected source scope 0, got %d", subnet.SourceScope)
	}
	if !subnet.Address.Equal(ip) {
		t.Errorf("expected address %s, got %s", ip, subnet.Address)
	}
}

func TestNewOPTRecord(t *testing.T) {
	t.Parallel()
	opt := NewOPTRecord(4096, true)
	if opt.Hdr.Name != "." {
		t.Errorf("expected Name \".\", got %q", opt.Hdr.Name)
	}
	if opt.Hdr.Rrtype != dns.TypeOPT {
		t.Errorf("expected TypeOPT, got %d", opt.Hdr.Rrtype)
	}
	if opt.UDPSize() != 4096 {
		t.Errorf("expected UDPSize 4096, got %d", opt.UDPSize())
	}
	if !opt.Do() {
		t.Error("expected DO=true")
	}

	opt2 := NewOPTRecord(512, false)
	if opt2.Do() {
		t.Error("expected DO=false")
	}
	if opt2.UDPSize() != 512 {
		t.Errorf("expected UDPSize 512, got %d", opt2.UDPSize())
	}
}
