package selector

import (
	"context"
	"math/rand"
	"time"
)

func init() {
	rand.NewSource(time.Now().UnixNano())
}

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
	return rs.upstreams[rand.Intn(len(rs.upstreams))]
}

func (rs *RandomSelector) StartEvaluate(ctx context.Context) {}

func (rs *RandomSelector) ReportUpstreamStatus(upstream *Upstream, upstreamStatus upstreamStatus) {}
