package selector

import (
	"context"
	"math/rand/v2"
)

type RandomSelector struct {
	upstreams []*Upstream
}

func NewRandomSelector() *RandomSelector {
	return new(RandomSelector)
}

func (rs *RandomSelector) Add(url string, upstreamType UpstreamType) (err error) {
	upstream, err := NewUpstream(upstreamType, url, 0)
	if err != nil {
		return err
	}
	rs.upstreams = append(rs.upstreams, upstream)
	return nil
}

func (rs *RandomSelector) Get() *Upstream {
	if len(rs.upstreams) == 0 {
		return nil
	}
	return rs.upstreams[rand.IntN(len(rs.upstreams))]
}

func (rs *RandomSelector) StartEvaluate(ctx context.Context) {}

func (rs *RandomSelector) ReportUpstreamStatus(upstream *Upstream, upstreamStatus upstreamStatus) {}
