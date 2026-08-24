package gfwlist

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecodeGFWListOrPlainPlaintext(t *testing.T) {
	raw := []byte("example.com\n||blocked.example\n")
	got := decodeGFWListOrPlain(raw)
	if got != string(raw) {
		t.Fatalf("plaintext passthrough failed: %q", got)
	}
	list, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if !list.IsBlockedByGFW("example.com") {
		t.Fatal("expected example.com blocked")
	}
	if !list.IsBlockedByGFW("foo.blocked.example") {
		t.Fatal("expected ||blocked.example to match")
	}
}

func TestDecodeGFWListOrPlainBase64(t *testing.T) {
	plain := "[AutoProxy0.2.9]\n||google.com\n"
	enc := base64.StdEncoding.EncodeToString([]byte(plain))
	got := decodeGFWListOrPlain([]byte(enc))
	if !strings.Contains(got, "||google.com") {
		t.Fatalf("decoded=%q", got)
	}
}

func TestNewGFWListPlainLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(path, []byte("plainblock.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := NewGFWList(nil, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	if !list.IsBlockedByGFW("plainblock.test") {
		t.Fatal("expected plaintext local blocklist hit")
	}
}

func TestFetchGFWListURLTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 50 * time.Millisecond}
	if _, err := fetchGFWListURL(client, srv.URL); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestFetchGFWListURLTooLarge(t *testing.T) {
	old := gfwlistMaxBytes
	gfwlistMaxBytes = 64
	defer func() { gfwlistMaxBytes = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytesRepeat(80))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	if _, err := fetchGFWListURL(client, srv.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected exceeds error, got %v", err)
	}
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'A'
	}
	return b
}
