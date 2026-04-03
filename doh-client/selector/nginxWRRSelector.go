package selector

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type NginxWRRSelector struct {
	upstreams []*Upstream // upstreamsInfo
	client    http.Client // http client to check the upstream
}

func NewNginxWRRSelector(timeout time.Duration) *NginxWRRSelector {
	return &NginxWRRSelector{
		client: http.Client{Timeout: timeout},
	}
}

func (ws *NginxWRRSelector) Add(url string, upstreamType UpstreamType, weight int32) (err error) {
	upstream, err := NewUpstream(upstreamType, url, weight)
	if err != nil {
		return err
	}
	ws.upstreams = append(ws.upstreams, upstream)
	return nil
}

func (ws *NginxWRRSelector) StartEvaluate(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			healthCheckUpstreams(ws.upstreams, &ws.client, -10, checkGoogleResponse, checkIETFResponse)

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// nginx wrr like.
func (ws *NginxWRRSelector) Get() *Upstream {
	var (
		total             int32
		bestUpstreamIndex = -1
		bestWeight        int32
	)

	for i := range ws.upstreams {
		effectiveWeight := atomic.LoadInt32(&ws.upstreams[i].effectiveWeight)
		currentWeight := atomic.AddInt32(&ws.upstreams[i].currentWeight, effectiveWeight)
		total += effectiveWeight

		if bestUpstreamIndex == -1 || currentWeight > bestWeight {
			bestUpstreamIndex = i
			bestWeight = currentWeight
		}
	}

	atomic.AddInt32(&ws.upstreams[bestUpstreamIndex].currentWeight, -total)

	return ws.upstreams[bestUpstreamIndex]
}

func (ws *NginxWRRSelector) ReportUpstreamStatus(upstream *Upstream, upstreamStatus upstreamStatus) {
	switch upstreamStatus {
	case Timeout:
		adjustWeight(upstream, -5)
	case Error:
		adjustWeight(upstream, -3)
	case OK:
		adjustWeight(upstream, 1)
	}
}

func (ws *NginxWRRSelector) ReportWeights(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, u := range ws.upstreams {
					log.Printf("%s, effect weight: %d", u, atomic.LoadInt32(&u.effectiveWeight))
				}
			}
		}
	}()
}
