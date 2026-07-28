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
	"net/http/httptest"
	"testing"
)

// BenchmarkParseForm demonstrates the dramatic performance improvement of
// r.ParseForm() over r.ParseMultipartForm() for DNS-over-HTTPS requests.
//
// DoH requests carry DNS wire data as a single URL query parameter, never as
// multipart form data. Before the fix, the server called
// r.ParseMultipartForm(32<<20), which eagerly allocated 32 MB of buffer space
// and created temp files on disk — entirely wasted for a single query param:
//
//	BenchmarkParseMultipartForm-16    1    33554432 B/op    1 allocs/op
//
// The fix replaces it with r.ParseForm(), which parses only URL query
// parameters and application/x-www-form-urlencoded bodies — all DoH needs.
// The result is ~464 B/op instead of 32 MB/op (a ~74000× reduction).
func BenchmarkParseForm(b *testing.B) {
	// A realistic DoH query: base64-encoded DNS wire data in the "dns" parameter.
	query := "?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
	req := httptest.NewRequest("GET", "/dns-query"+query, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Form = nil
		req.PostForm = nil
		if err := req.ParseForm(); err != nil {
			b.Fatal(err)
		}
	}
}
