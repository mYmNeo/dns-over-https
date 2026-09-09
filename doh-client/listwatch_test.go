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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/m13253/dns-over-https/v2/doh-client/config"
)

func writeListFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitListMatch(t *testing.T, c *Client, domain string, wantBlocked, wantGFW bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		isBlocked, isGFW, _ := c.checkLists(domain)
		if isBlocked == wantBlocked && isGFW == wantGFW {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	isBlocked, isGFW, gfwEnabled := c.checkLists(domain)
	t.Fatalf("domain %s: blocked=%v gfw=%v gfwEnabled=%v, want blocked=%v gfw=%v",
		domain, isBlocked, isGFW, gfwEnabled, wantBlocked, wantGFW)
}

func TestReplaceBlockList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "block.txt")
	writeListFile(t, path, "old.example\n")

	c := &Client{conf: &config.Config{}}
	c.conf.Other.BlockList = []string{path}
	if err := c.replaceBlockList(); err != nil {
		t.Fatal(err)
	}

	isBlocked, _, _ := c.checkLists("old.example")
	if !isBlocked {
		t.Fatal("expected old.example blocked")
	}

	writeListFile(t, path, "new.example\n")
	if err := c.replaceBlockList(); err != nil {
		t.Fatal(err)
	}
	isBlocked, _, _ = c.checkLists("old.example")
	if isBlocked {
		t.Fatal("expected old.example unblocked after reload")
	}
	isBlocked, _, _ = c.checkLists("new.example")
	if !isBlocked {
		t.Fatal("expected new.example blocked after reload")
	}
}

func TestReplaceKeepsPreviousOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "block.txt")
	writeListFile(t, path, "keep.example\n")

	c := &Client{conf: &config.Config{}}
	c.conf.Other.BlockList = []string{path}
	if err := c.replaceBlockList(); err != nil {
		t.Fatal(err)
	}

	c.conf.Other.BlockList = []string{filepath.Join(dir, "missing.txt")}
	if err := c.replaceBlockList(); err == nil {
		t.Fatal("expected error for missing blocklist")
	}
	isBlocked, _, _ := c.checkLists("keep.example")
	if !isBlocked {
		t.Fatal("expected previous blocklist to remain after failed reload")
	}
}

func TestStartListWatcherNoFiles(t *testing.T) {
	c := &Client{conf: &config.Config{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.startListWatcher(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestListWatcherReloadsOnWriteAndRename(t *testing.T) {
	dir := t.TempDir()
	gfwPath := filepath.Join(dir, "gfw.txt")
	blockPath := filepath.Join(dir, "block.txt")
	writeListFile(t, gfwPath, "gfw-old.example\n")
	writeListFile(t, blockPath, "block-old.example\n")

	c := &Client{conf: &config.Config{}}
	c.conf.Other.GFWList = []string{gfwPath}
	c.conf.Other.BlockList = []string{blockPath}
	if err := c.replaceGFWList(); err != nil {
		t.Fatal(err)
	}
	if err := c.replaceBlockList(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.startListWatcher(ctx); err != nil {
		t.Fatal(err)
	}

	writeListFile(t, gfwPath, "gfw-new.example\n")
	writeListFile(t, blockPath, "block-new.example\n")
	waitListMatch(t, c, "gfw-new.example", false, true)
	waitListMatch(t, c, "block-new.example", true, false)
	waitListMatch(t, c, "gfw-old.example", false, false)
	waitListMatch(t, c, "block-old.example", false, false)

	tmp := blockPath + ".tmp"
	writeListFile(t, tmp, "block-renamed.example\n")
	if err := os.Rename(tmp, blockPath); err != nil {
		t.Fatal(err)
	}
	waitListMatch(t, c, "block-renamed.example", true, false)
	waitListMatch(t, c, "block-new.example", false, false)
}
