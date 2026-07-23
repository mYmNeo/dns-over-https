package selector

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
)

// healthCheckUpstreams runs health checks on all upstreams concurrently using the provided HTTP client.
// timeoutPenalty is the weight penalty for connection failures (e.g., -5 for LVS, -10 for Nginx).
func healthCheckUpstreams(upstreams []*Upstream, client *http.Client, timeoutPenalty int32, checkGoogle func(*http.Response, *Upstream), checkIETF func(*http.Response, *Upstream)) {
	wg := sync.WaitGroup{}

	sem := make(chan struct{}, 10)
	for i := range upstreams {
		wg.Add(1)

		go func(i int) {
			sem <- struct{}{}
			defer wg.Done()
			defer func() { <-sem }()

			upstreamURL := upstreams[i].URL
			var acceptType string

			switch upstreams[i].Type {
			case Google:
				upstreamURL += "?name=www.example.com&type=A"
				acceptType = "application/dns-json"

			case IETF:
				// www.example.com
				upstreamURL += "?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
				acceptType = "application/dns-message"
			}

			req, err := http.NewRequest(http.MethodGet, upstreamURL, http.NoBody)
			if err != nil {
				log.Printf("upstream: %s type: %s check failed: %v", upstreamURL, typeMap[upstreams[i].Type], err)
				return
			}

			req.Header.Set("accept", acceptType)

			resp, err := client.Do(req)
			if err != nil {
				adjustWeight(upstreams[i], timeoutPenalty)
				return
			}

			switch upstreams[i].Type {
			case Google:
				checkGoogle(resp, upstreams[i])

			case IETF:
				checkIETF(resp, upstreams[i])
			}
		}(i)
	}

	wg.Wait()
}

// adjustWeight atomically adjusts the effective weight, clamping to [1, maxWeight].
func adjustWeight(upstream *Upstream, delta int32) {
	for {
		old := atomic.LoadInt32(&upstream.effectiveWeight)
		newWeight := old + delta
		if newWeight < 1 {
			newWeight = 1
		} else if newWeight > upstream.weight {
			newWeight = upstream.weight
		}
		if atomic.CompareAndSwapInt32(&upstream.effectiveWeight, old, newWeight) {
			return
		}
	}
}

// checkGoogleResponse validates a Google DNS-over-HTTPS health check response.
func checkGoogleResponse(resp *http.Response, upstream *Upstream) {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		adjustWeight(upstream, -3)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Status *float64 `json:"Status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		adjustWeight(upstream, -2)
		return
	}
	if result.Status != nil && *result.Status == 0 {
		adjustWeight(upstream, 5)
		return
	}

	adjustWeight(upstream, -2)
}

// checkIETFResponse validates an IETF DNS-over-HTTPS health check response.
func checkIETFResponse(resp *http.Response, upstream *Upstream) {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		adjustWeight(upstream, -3)
		return
	}

	adjustWeight(upstream, 5)
}
