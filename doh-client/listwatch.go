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
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/OneYX/v2ray-core/tools/gfwlist"
	"github.com/fsnotify/fsnotify"
)

const listReloadDebounce = 250 * time.Millisecond

const (
	listKindGFW uint8 = 1 << iota
	listKindBlock
)

func listWatchPaths(gfwFiles, blockFiles []string) map[string]uint8 {
	paths := make(map[string]uint8)
	add := func(files []string, kind uint8) {
		for _, p := range files {
			if p == "" {
				continue
			}
			paths[absListPath(p)] |= kind
		}
	}
	add(gfwFiles, listKindGFW)
	add(blockFiles, listKindBlock)
	return paths
}

func absListPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

func (c *Client) replaceGFWList() error {
	list, err := gfwlist.NewGFWList(c.conf.Other.GFWListURL, c.conf.Other.GFWList)
	if err != nil {
		return err
	}
	c.gfwLock.Lock()
	c.gfwList = list
	c.gfwLock.Unlock()
	return nil
}

func (c *Client) replaceBlockList() error {
	list, err := gfwlist.NewGFWList(nil, c.conf.Other.BlockList)
	if err != nil {
		return err
	}
	c.gfwLock.Lock()
	c.blockList = list
	c.gfwLock.Unlock()
	return nil
}

func (c *Client) startListWatcher(ctx context.Context) error {
	paths := listWatchPaths(c.conf.Other.GFWList, c.conf.Other.BlockList)
	if len(paths) == 0 {
		return nil
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	dirs := make(map[string]struct{})
	for p := range paths {
		dirs[filepath.Dir(p)] = struct{}{}
	}
	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return fmt.Errorf("watch %s: %w", dir, err)
		}
	}
	go c.watchListEvents(ctx, watcher, paths)
	return nil
}

func (c *Client) watchListEvents(ctx context.Context, watcher *fsnotify.Watcher, paths map[string]uint8) {
	defer func() { _ = watcher.Close() }()

	var (
		timer   *time.Timer
		timerCh <-chan time.Time
		pending uint8
	)
	schedule := func() {
		if timer == nil {
			timer = time.NewTimer(listReloadDebounce)
			timerCh = timer.C
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(listReloadDebounce)
	}

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				_ = timer.Stop()
			}
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			kind, match := paths[absListPath(ev.Name)]
			if !match {
				continue
			}
			if ev.Has(fsnotify.Write) || ev.Has(fsnotify.Create) || ev.Has(fsnotify.Remove) || ev.Has(fsnotify.Rename) {
				pending |= kind
				schedule()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			if err != nil {
				log.Printf("gfwlist/blocklist watcher: %v", err)
			}
		case <-timerCh:
			timer = nil
			timerCh = nil
			c.reloadPendingLists(pending)
			pending = 0
		}
	}
}

func (c *Client) reloadPendingLists(pending uint8) {
	if pending&listKindGFW != 0 {
		if err := c.replaceGFWList(); err != nil {
			log.Printf("failed to reload gfwlist: %v", err)
		} else {
			log.Println("reloaded gfwlist")
		}
	}
	if pending&listKindBlock != 0 {
		if err := c.replaceBlockList(); err != nil {
			log.Printf("failed to reload blocklist: %v", err)
		} else {
			log.Println("reloaded blocklist")
		}
	}
}
