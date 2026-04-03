package selector

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type LVSWRRSelector struct {
	upstreams     []*Upstream // upstreamsInfo
	client        http.Client // http client to check the upstream
	lastChoose    int32
	currentWeight int32
}

func NewLVSWRRSelector(timeout time.Duration) *LVSWRRSelector {
	return &LVSWRRSelector{
		client:     http.Client{Timeout: timeout},
		lastChoose: -1,
	}
}

func (ls *LVSWRRSelector) Add(url string, upstreamType UpstreamType, weight int32) (err error) {
	if weight < 1 {
		return errors.New("weight is 1")
	}

	upstream, err := NewUpstream(upstreamType, url, weight)
	if err != nil {
		return err
	}
	ls.upstreams = append(ls.upstreams, upstream)
	return nil
}

func (ls *LVSWRRSelector) StartEvaluate(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			healthCheckUpstreams(ls.upstreams, &ls.client, -5, checkGoogleResponse, checkIETFResponse)

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (ls *LVSWRRSelector) Get() *Upstream {
	if len(ls.upstreams) == 1 {
		return ls.upstreams[0]
	}

	for {
		lastChoose := (atomic.LoadInt32(&ls.lastChoose) + 1) % int32(len(ls.upstreams))
		atomic.StoreInt32(&ls.lastChoose, lastChoose)

		if lastChoose == 0 {
			currentWeight := atomic.AddInt32(&ls.currentWeight, -ls.gcdWeight())

			if currentWeight <= 0 {
				currentWeight = atomic.AddInt32(&ls.currentWeight, ls.maxWeight())

				if currentWeight == 0 {
					panic("current weight is 0")
				}
			}
		}

		currentWeight := atomic.LoadInt32(&ls.currentWeight)
		if atomic.LoadInt32(&ls.upstreams[lastChoose].effectiveWeight) >= currentWeight {
			return ls.upstreams[lastChoose]
		}
	}
}

func (ls *LVSWRRSelector) gcdWeight() (res int32) {
	res = gcd(atomic.LoadInt32(&ls.upstreams[0].effectiveWeight), atomic.LoadInt32(&ls.upstreams[0].effectiveWeight))

	for i := 1; i < len(ls.upstreams); i++ {
		res = gcd(res, atomic.LoadInt32(&ls.upstreams[i].effectiveWeight))
	}

	return
}

func (ls *LVSWRRSelector) maxWeight() (res int32) {
	for _, upstream := range ls.upstreams {
		w := atomic.LoadInt32(&upstream.effectiveWeight)
		if w > res {
			res = w
		}
	}

	return
}

func gcd(x, y int32) int32 {
	for {
		if x < y {
			x, y = y, x
		}

		tmp := x % y
		if tmp == 0 {
			return y
		}

		x = tmp
	}
}

func (ls *LVSWRRSelector) ReportUpstreamStatus(upstream *Upstream, upstreamStatus upstreamStatus) {
	switch upstreamStatus {
	case Timeout:
		adjustWeight(upstream, -5)
	case Error:
		adjustWeight(upstream, -2)
	case OK:
		adjustWeight(upstream, 1)
	}
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
