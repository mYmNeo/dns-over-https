package selector

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type LVSWRRSelector struct {
	upstreams     []*Upstream // upstreamsInfo
	client        http.Client // http client to check the upstream
	mu            sync.Mutex  // protects Get() for correct round-robin
	lastChoose    int32
	currentWeight int32
	cachedGCD     int32
	cachedMax     int32
}

func NewLVSWRRSelector(timeout time.Duration) *LVSWRRSelector {
	return &LVSWRRSelector{
		client:     http.Client{Timeout: timeout},
		lastChoose: -1,
	}
}

func (ls *LVSWRRSelector) Add(url string, upstreamType UpstreamType, weight int32) (err error) {
	if weight < 1 {
		return errors.New("weight must be >= 1")
	}

	upstream, err := NewUpstream(upstreamType, url, weight)
	if err != nil {
		return err
	}
	ls.upstreams = append(ls.upstreams, upstream)
	ls.updateCachedWeights()
	return nil
}

func (ls *LVSWRRSelector) StartEvaluate(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			healthCheckUpstreams(ls.upstreams, &ls.client, -10, checkGoogleResponse, checkIETFResponse)
			ls.updateCachedWeights()

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (ls *LVSWRRSelector) Get() *Upstream {
	if len(ls.upstreams) == 0 {
		return nil
	}
	if len(ls.upstreams) == 1 {
		return ls.upstreams[0]
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()

	// Snapshot effective weights and cached values under lock
	cachedGCD := ls.cachedGCD
	cachedMax := ls.cachedMax
	currentWeight := ls.currentWeight

	// Guard: if cachedMax is 0, recompute to avoid panic
	if cachedMax == 0 {
		ls.updateCachedWeightsLocked()
		cachedGCD = ls.cachedGCD
		cachedMax = ls.cachedMax
	}

	for round := int32(0); round < int32(len(ls.upstreams))*2; round++ {
		ls.lastChoose = (ls.lastChoose + 1) % int32(len(ls.upstreams))

		if ls.lastChoose == 0 {
			currentWeight -= cachedGCD
			if currentWeight <= 0 {
				currentWeight = cachedMax
			}
		}

		if atomic.LoadInt32(&ls.upstreams[ls.lastChoose].effectiveWeight) >= currentWeight {
			ls.currentWeight = currentWeight
			return ls.upstreams[ls.lastChoose]
		}
	}

	// Fallback: return the upstream with maximum effective weight
	var best *Upstream
	var bestW int32
	for _, u := range ls.upstreams {
		w := atomic.LoadInt32(&u.effectiveWeight)
		if w > bestW {
			bestW = w
			best = u
		}
	}
	return best
}

// updateCachedWeights recomputes and caches the GCD and max weight values under lock.
func (ls *LVSWRRSelector) updateCachedWeights() {
	ls.mu.Lock()
	ls.updateCachedWeightsLocked()
	ls.mu.Unlock()
}

// updateCachedWeightsLocked recomputes cached GCD and max. Caller MUST hold ls.mu.
func (ls *LVSWRRSelector) updateCachedWeightsLocked() {
	if len(ls.upstreams) < 2 {
		if len(ls.upstreams) == 1 {
			w := atomic.LoadInt32(&ls.upstreams[0].effectiveWeight)
			ls.cachedGCD = w
			ls.cachedMax = w
		}
		return
	}

	gcdVal := gcd(atomic.LoadInt32(&ls.upstreams[0].effectiveWeight), atomic.LoadInt32(&ls.upstreams[1].effectiveWeight))
	for i := 2; i < len(ls.upstreams); i++ {
		gcdVal = gcd(gcdVal, atomic.LoadInt32(&ls.upstreams[i].effectiveWeight))
	}

	var maxVal int32
	for _, upstream := range ls.upstreams {
		w := atomic.LoadInt32(&upstream.effectiveWeight)
		if w > maxVal {
			maxVal = w
		}
	}

	ls.cachedGCD = gcdVal
	ls.cachedMax = maxVal
}

func gcd(x, y int32) int32 {
	if x < 0 {
		x = -x
	}
	if y < 0 {
		y = -y
	}
	if x == 0 || y == 0 {
		return x | y
	}
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

func (ls *LVSWRRSelector) ReportUpstreamStatus(upstream *Upstream, upstreamStatus upstreamStatus) {
	switch upstreamStatus {
	case Timeout:
		adjustWeight(upstream, -10)
	case Error:
		adjustWeight(upstream, -2)
	case OK:
		adjustWeight(upstream, 1)
	}
	ls.updateCachedWeights()
}

func (ls *LVSWRRSelector) ReportWeights(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, u := range ls.upstreams {
					log.Printf("%s, effect weight: %d", u, atomic.LoadInt32(&u.effectiveWeight))
				}
			}
		}
	}()
}
