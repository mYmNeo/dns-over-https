package main

import (
	"strings"
	"testing"
)

func TestToLowerASCII(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already lowercase",
			input: "www.example.com",
			want:  "www.example.com",
		},
		{
			name:  "mixed case",
			input: "Www.Example.COM",
			want:  "www.example.com",
		},
		{
			name:  "all uppercase",
			input: "WWW.EXAMPLE.COM",
			want:  "www.example.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "FQDN with trailing dot",
			input: "Www.Example.com.",
			want:  "www.example.com.",
		},
		{
			name:  "ASCII only, no letters",
			input: "123.456.789.0",
			want:  "123.456.789.0",
		},
		{
			name:  "single uppercase char",
			input: "A",
			want:  "a",
		},
		{
			name:  "single lowercase char",
			input: "a",
			want:  "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toLowerASCII(tt.input)
			if got != tt.want {
				t.Errorf("toLowerASCII(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Regression: ensure our fast path is at least as correct as strings.ToLower on ASCII.
func TestToLowerASCII_MatchesStringsToLower(t *testing.T) {
	cases := []string{
		"",
		"a",
		"z",
		"example.com",
		"EXAMPLE.COM",
		"eXaMpLe.CoM",
		"mixed.CASE.domain.",
		"123.abc.456",
	}

	for _, s := range cases {
		got := toLowerASCII(s)
		want := strings.ToLower(s)
		if got != want {
			t.Errorf("toLowerASCII(%q) = %q, strings.ToLower = %q", s, got, want)
		}
	}
}

func BenchmarkToLowerASCII_AlreadyLower(b *testing.B) {
	s := "www.example.com"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = toLowerASCII(s)
	}
}

func BenchmarkToLowerASCII_MixedCase(b *testing.B) {
	s := "Www.Example.COM"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = toLowerASCII(s)
	}
}

func BenchmarkToLowerASCII_AllUppercase(b *testing.B) {
	s := "WWW.EXAMPLE.COM"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = toLowerASCII(s)
	}
}

func BenchmarkStringsToLower_AlreadyLower(b *testing.B) {
	s := "www.example.com"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = strings.ToLower(s)
	}
}

func BenchmarkStringsToLower_MixedCase(b *testing.B) {
	s := "Www.Example.COM"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = strings.ToLower(s)
	}
}
