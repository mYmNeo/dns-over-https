package selector

import "context"

type Selector interface {
	// Get returns a upstream
	Get() *Upstream

	// StartEvaluate starts the upstream evaluation loop.
	// The loop stops when the provided context is cancelled.
	StartEvaluate(ctx context.Context)

	// ReportUpstreamStatus report upstream status
	ReportUpstreamStatus(upstream *Upstream, upstreamStatus upstreamStatus)
}

type DebugReporter interface {
	// ReportWeights starts a goroutine to report all upstream weights, recommend interval is 15s
	ReportWeights(ctx context.Context)
}
