package main

import "testing"

func TestIsPassthroughMatchesFQDNQuestions(t *testing.T) {
	// Entries are stored the way NewClient normalizes them: no surrounding dots.
	c := &Client{passthrough: []string{"captive.apple.com", "example.com"}}

	tests := []struct {
		domain string
		want   bool
	}{
		{"captive.apple.com.", true},
		{"foo.captive.apple.com.", true},
		{"Captive.Apple.COM.", true},
		{"evilcaptive.apple.com.", false},
		{"example.com.", true},
		{"www.example.com.", true},
		{"badexample.com.", false},
		{"apple.com.", false},
	}
	for _, tt := range tests {
		if got := c.isPassthrough(tt.domain); got != tt.want {
			t.Errorf("isPassthrough(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}
