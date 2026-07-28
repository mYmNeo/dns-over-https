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
	"testing"
)

func TestParseAcceptType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		accept string
		want   string
	}{
		{
			name:   "single application/dns-message",
			accept: "application/dns-message",
			want:   "application/dns-message",
		},
		{
			name:   "single application/json",
			accept: "application/json",
			want:   "application/json",
		},
		{
			name:   "application/dns-udpwireformat maps to dns-message",
			accept: "application/dns-udpwireformat",
			want:   "application/dns-message",
		},
		{
			name:   "multiple types prefers first match",
			accept: "application/dns-message, application/json",
			want:   "application/dns-message",
		},
		{
			name:   "multiple types with json first",
			accept: "application/json, application/dns-message",
			want:   "application/json",
		},
		{
			name:   "multiple types skips unknown until match",
			accept: "text/html, application/json, application/dns-message",
			want:   "application/json",
		},
		{
			name:   "with quality parameter",
			accept: "application/dns-message;q=1",
			want:   "application/dns-message",
		},
		{
			name:   "multiple with quality params and whitespace",
			accept: "text/html;q=0.9, application/dns-message;q=0.8, application/json;q=0.7",
			want:   "application/dns-message",
		},
		{
			name:   "empty string returns empty",
			accept: "",
			want:   "",
		},
		{
			name:   "unknown type returns empty",
			accept: "text/html",
			want:   "",
		},
		{
			name:   "only unknown types returns empty",
			accept: "text/html, text/plain, image/png",
			want:   "",
		},
		{
			name:   "dns-udpwireformat among many",
			accept: "text/html, application/dns-udpwireformat, application/json",
			want:   "application/dns-message",
		},
		{
			name:   "whitespace around values",
			accept: "  application/json  ",
			want:   "application/json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAcceptType(tt.accept)
			if got != tt.want {
				t.Errorf("parseAcceptType(%q) = %q, want %q", tt.accept, got, tt.want)
			}
		})
	}
}

func BenchmarkParseAcceptType(b *testing.B) {
	const input = "application/dns-message, application/json"
	b.ReportAllocs()
	for b.Loop() {
		parseAcceptType(input)
	}
}
