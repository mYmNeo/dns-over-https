package main

import (
	"fmt"
	"net"
	"strings"
)

// validatePprofAddr requires empty (disabled) or a loopback host:port.
func validatePprofAddr(addr string) error {
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("pprof_addr %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("pprof_addr %q: missing port", addr)
	}
	if host == "" {
		return fmt.Errorf("pprof_addr %q: must bind to loopback (got all interfaces)", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("pprof_addr %q: host must be loopback IP or localhost", addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("pprof_addr %q: must bind to loopback", addr)
	}
	return nil
}
