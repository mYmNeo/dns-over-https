package gfwlist

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var GFWListURL = "https://gitlab.com/gfwlist/gfwlist/raw/master/gfwlist.txt"

type hostWildcardRule struct {
	pattern string
}

func (r *hostWildcardRule) match(domain string) bool {
	return strings.Contains(domain, r.pattern)
}

type urlWildcardRule struct {
	pattern     string
	prefixMatch bool
}

func (r *urlWildcardRule) match(domain string) bool {
	if r.prefixMatch {
		return strings.HasPrefix(domain, r.pattern)
	}
	return strings.Contains(domain, r.pattern)
}

type regexRule struct {
	re *regexp.Regexp
}

func (r *regexRule) match(domain string) bool {
	return r.re.MatchString(domain)
}

type whiteListRule struct {
	r gfwListRule
}

func (r *whiteListRule) match(domain string) bool {
	return r.r.match(domain)
}

type gfwListRule interface {
	match(domain string) bool
}

type GFWList struct {
	ruleMap        map[string]gfwListRule
	ruleList       []gfwListRule
	blockedCache   map[string]bool
	blockedCacheMu sync.RWMutex
}

func (gfw *GFWList) FastMatchDomain(domain string) (bool, bool) {
	if gfw.ruleMap == nil || len(domain) == 0 {
		return false, false
	}

	rootDomain := domain
	if strings.Contains(domain, ":") {
		domain, _, _ = net.SplitHostPort(domain)
		rootDomain = domain
	}

	rule, exist := gfw.ruleMap[domain]
	if !exist {
		ss := strings.Split(domain, ".")
		if len(ss) > 2 {
			rootDomain = ss[len(ss)-2] + "." + ss[len(ss)-1]
			if len(ss[len(ss)-2]) < 4 && len(ss) >= 3 {
				rootDomain = ss[len(ss)-3] + "." + rootDomain
			}
		}
		if rootDomain != domain {
			rule, exist = gfw.ruleMap[rootDomain]
		}
	}
	if exist {
		matched := rule.match(domain)
		if _, ok := rule.(*whiteListRule); ok {
			return !matched, true
		}
		return matched, true
	}
	return false, false
}

func (gfw *GFWList) IsBlockedByGFW(domain string) bool {
	// Check the bounded memoization cache first
	gfw.blockedCacheMu.RLock()
	if blocked, ok := gfw.blockedCache[domain]; ok {
		gfw.blockedCacheMu.RUnlock()
		return blocked
	}
	gfw.blockedCacheMu.RUnlock()

	fastMatchResult, exist := gfw.FastMatchDomain(domain)
	if exist {
		gfw.cacheBlocked(domain, fastMatchResult)
		return fastMatchResult
	}

	for _, rule := range gfw.ruleList {
		if rule.match(domain) {
			if _, ok := rule.(*whiteListRule); ok {
				gfw.cacheBlocked(domain, false)
				return false
			}
			gfw.cacheBlocked(domain, true)
			return true
		}
	}
	gfw.cacheBlocked(domain, false)
	return false
}

const maxBlockedCache = 100_000

func (gfw *GFWList) cacheBlocked(domain string, blocked bool) {
	gfw.blockedCacheMu.Lock()
	if gfw.blockedCache == nil {
		gfw.blockedCache = make(map[string]bool)
	} else if len(gfw.blockedCache) >= maxBlockedCache {
		// Clear the cache when it grows too large
		gfw.blockedCache = make(map[string]bool)
	}
	gfw.blockedCache[domain] = blocked
	gfw.blockedCacheMu.Unlock()
}

func Parse(rules string) (*GFWList, error) {
	reader := bufio.NewReader(strings.NewReader(rules))
	gfw := new(GFWList)
	gfw.ruleMap = make(map[string]gfwListRule)
	// i := 0
	for {
		line, _, err := reader.ReadLine()
		if nil != err {
			break
		}
		str := strings.TrimSpace(string(line))
		// comment
		if strings.HasPrefix(str, "!") || len(str) == 0 || strings.HasPrefix(str, "[") {
			continue
		}
		var rule gfwListRule
		isWhileListRule := false
		fastMatch := false
		if strings.HasPrefix(str, "@@") {
			str = str[2:]
			isWhileListRule = true
		}
		if strings.HasPrefix(str, "/") && strings.HasSuffix(str, "/") {
			str = str[1 : len(str)-1]
			re, err := regexp.Compile(str)
			if err != nil {
				slog.Error("Invalid regex pattern, skipping", "pattern", str, "error", err)
				continue
			}
			rule = &regexRule{re}
		} else {
			if strings.HasPrefix(str, "||") {
				fastMatch = true
				str = str[2:]
				rule = &hostWildcardRule{str}
			} else if strings.HasPrefix(str, "|") {
				rule = &urlWildcardRule{str[1:], true}
			} else {
				if !strings.Contains(str, "/") {
					fastMatch = true
					str = strings.TrimPrefix(str, ".")
					rule = &hostWildcardRule{str}
				} else {
					rule = &urlWildcardRule{str, false}
				}
			}
		}
		if isWhileListRule {
			rule = &whiteListRule{rule}
		}
		if fastMatch {
			gfw.ruleMap[str] = rule
		} else {
			gfw.ruleList = append(gfw.ruleList, rule)
		}
	}
	return gfw, nil
}

const gfwlistHTTPTimeout = 30 * time.Second

var gfwlistMaxBytes int64 = 16 << 20 // 16 MiB per source; overridable in tests


func NewGFWList(urls []string, localFiles []string) (*GFWList, error) {
	var parts []string

	client := &http.Client{Timeout: gfwlistHTTPTimeout}
	for _, rawURL := range urls {
		text, err := fetchGFWListURL(client, rawURL)
		if err != nil {
			return nil, err
		}
		parts = append(parts, text)
	}

	for _, localFile := range localFiles {
		raw, err := os.ReadFile(localFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read gfwlist local file %s: %w", localFile, err)
		}
		parts = append(parts, decodeGFWListOrPlain(raw))
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("no gfwlist sources provided")
	}
	return Parse(strings.Join(parts, "\n"))
}

func fetchGFWListURL(client *http.Client, rawURL string) (string, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to get gfwlist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get gfwlist: %v", resp.Status)
	}

	limited := io.LimitReader(resp.Body, int64(gfwlistMaxBytes)+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("failed to read gfwlist body: %w", err)
	}
	if int64(len(raw)) > gfwlistMaxBytes {
		return "", fmt.Errorf("gfwlist response exceeds %d bytes", gfwlistMaxBytes)
	}

	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(raw)))
	if err != nil {
		return "", fmt.Errorf("failed to decode gfwlist: %w", err)
	}
	return string(decoded), nil
}

// decodeGFWListOrPlain accepts canonical base64 AutoProxy lists or plaintext
// rule/domain lines (used by local blocklist files).
func decodeGFWListOrPlain(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err == nil && looksLikeGFWList(decoded) {
		return string(decoded)
	}
	// Also accept base64 with newlines via streaming decoder.
	decoded, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(trimmed)))
	if err == nil && looksLikeGFWList(decoded) {
		return string(decoded)
	}
	return string(raw)
}

func looksLikeGFWList(b []byte) bool {
	s := string(b)
	if strings.Contains(s, "[AutoProxy") {
		return true
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, ".") || strings.HasPrefix(line, "/") {
			return true
		}
	}
	return false
}
