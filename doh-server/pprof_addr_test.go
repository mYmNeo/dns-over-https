package main

import "testing"

func TestValidatePprofAddr(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:6060", "[::1]:6060", "localhost:6060", ""} {
		if err := validatePprofAddr(addr); err != nil {
			t.Fatalf("%q: unexpected err %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:6060", ":6060", "[::]:6060", "192.168.1.1:6060", "example.com:6060", "127.0.0.1"} {
		if err := validatePprofAddr(addr); err == nil {
			t.Fatalf("%q: expected error", addr)
		}
	}
}
