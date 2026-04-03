package selector

import (
	"errors"
	"fmt"
)

type UpstreamType int

const (
	Google UpstreamType = iota
	IETF
)

var typeMap = map[UpstreamType]string{
	Google: "Google",
	IETF:   "IETF",
}

// requestTypeMap maps upstream types to their Accept/Content-Type header values.
var requestTypeMap = map[UpstreamType]string{
	Google: "application/dns-json",
	IETF:   "application/dns-message",
}

type Upstream struct {
	Type            UpstreamType
	URL             string
	RequestType     string
	weight          int32
	effectiveWeight int32
	currentWeight   int32
}

func (u Upstream) String() string {
	return fmt.Sprintf("upstream type: %s, upstream url: %s", typeMap[u.Type], u.URL)
}

// NewUpstream creates a new Upstream with the given type, URL, and weight.
// Weight is used for weighted round-robin selectors; pass 0 for random selector.
func NewUpstream(upstreamType UpstreamType, url string, weight int32) (*Upstream, error) {
	requestType, ok := requestTypeMap[upstreamType]
	if !ok {
		return nil, errors.New("unknown upstream type")
	}
	return &Upstream{
		Type:            upstreamType,
		URL:             url,
		RequestType:     requestType,
		weight:          weight,
		effectiveWeight: weight,
	}, nil
}
