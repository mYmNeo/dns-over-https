package selector

import "testing"

func TestNginxWRREmptyGet(t *testing.T) {
	s := NewNginxWRRSelector(5000)
	up := s.Get()
	if up != nil {
		t.Errorf("expected nil from empty NginxWRRSelector, got %v", up)
	}
}

func TestRandomSelectorEmptyGet(t *testing.T) {
	s := NewRandomSelector()
	up := s.Get()
	if up != nil {
		t.Errorf("expected nil from empty RandomSelector, got %v", up)
	}
}

func TestAdjustWeightConcurrent(t *testing.T) {
	upstream, err := NewUpstream(Google, "https://dns.google/dns-query", 10)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate concurrent weight adjustments
	done := make(chan struct{})
	const workers = 10
	const iterations = 100
	for range workers {
		go func() {
			for range iterations {
				adjustWeight(upstream, -5)
				adjustWeight(upstream, 3)
			}
			done <- struct{}{}
		}()
	}
	for range workers {
		<-done
	}

	// After net -2 per iteration ( -5 + 3 ) * 100 * 10 = -2000 total
	// But clamped to [1, 10], so final should be stable in that range
	if upstream.effectiveWeight < 1 || upstream.effectiveWeight > 10 {
		t.Errorf("effectiveWeight %d outside expected [1,10]", upstream.effectiveWeight)
	}
}

func TestReportUpstreamStatusTimeoutPenalties(t *testing.T) {
	// Per CLAUDE.md:165,173 — LVS uses -10, Nginx uses -5 for Timeout.
	// Runtime ReportUpstreamStatus(Timeout) must match the healthcheck timeoutPenalty.
	tests := []struct {
		name       string
		url        string
		upType     UpstreamType
		weight     int32
		wantWeight int32 // effectiveWeight after one Timeout report
	}{
		{"LVS_Timeout", "https://lvs.example.com/dns-query", IETF, 10, 1},
		{"Nginx_Timeout", "https://nginx.example.com/dns-query", IETF, 10, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, err := NewUpstream(tt.upType, tt.url, tt.weight)
			if err != nil {
				t.Fatal(err)
			}

			// Simulate LVS-style Timeout penalty
			if tt.name == "LVS_Timeout" {
				ls := NewLVSWRRSelector(5000)
				ls.upstreams = append(ls.upstreams, upstream)
				ls.ReportUpstreamStatus(upstream, Timeout)
			} else {
				ws := NewNginxWRRSelector(5000)
				ws.upstreams = append(ws.upstreams, upstream)
				ws.ReportUpstreamStatus(upstream, Timeout)
			}

			if upstream.effectiveWeight != tt.wantWeight {
				t.Errorf("effectiveWeight = %d, want %d", upstream.effectiveWeight, tt.wantWeight)
			}
		})
	}
}

func TestHealthCheckPenaltyMatchesCLAUDE(t *testing.T) {
	// Verify that the timeoutPenalty passed to healthCheckUpstreams by each
	// selector matches CLAUDE.md: LVS = -10, Nginx = -5.
	// We can't call StartEvaluate() without a real server, but we verify
	// the constants indirectly through ReportUpstreamStatus + call site review.
	// This test asserts the contract: LVS Timeout delta = -10, Nginx Timeout delta = -5.

	lvsUpstream, err := NewUpstream(IETF, "https://lvs.example.com/dns-query", 10)
	if err != nil {
		t.Fatal(err)
	}
	nginxUpstream, err := NewUpstream(IETF, "https://nginx.example.com/dns-query", 10)
	if err != nil {
		t.Fatal(err)
	}

	// LVS: Timeout = -10
	ls := NewLVSWRRSelector(5000)
	ls.upstreams = append(ls.upstreams, lvsUpstream)
	ls.ReportUpstreamStatus(lvsUpstream, Timeout)
	if lvsUpstream.effectiveWeight != 1 {
		t.Errorf("LVS Timeout: effectiveWeight = %d, want 1 (10 - 10, clamped to 1)", lvsUpstream.effectiveWeight)
	}

	// Nginx: Timeout = -5
	ws := NewNginxWRRSelector(5000)
	ws.upstreams = append(ws.upstreams, nginxUpstream)
	ws.ReportUpstreamStatus(nginxUpstream, Timeout)
	if nginxUpstream.effectiveWeight != 5 {
		t.Errorf("Nginx Timeout: effectiveWeight = %d, want 5 (10 - 5)", nginxUpstream.effectiveWeight)
	}

	// LVS: Error = -2 (unchanged, but document it)
	lvs2, _ := NewUpstream(IETF, "https://lvs2.example.com/dns-query", 10)
	ls.upstreams = append(ls.upstreams, lvs2)
	ls.ReportUpstreamStatus(lvs2, Error)
	if lvs2.effectiveWeight != 8 {
		t.Errorf("LVS Error: effectiveWeight = %d, want 8 (10 - 2)", lvs2.effectiveWeight)
	}

	// Nginx: Error = -3 (unchanged, but document it)
	nginx2, _ := NewUpstream(IETF, "https://nginx2.example.com/dns-query", 10)
	ws.upstreams = append(ws.upstreams, nginx2)
	ws.ReportUpstreamStatus(nginx2, Error)
	if nginx2.effectiveWeight != 7 {
		t.Errorf("Nginx Error: effectiveWeight = %d, want 7 (10 - 3)", nginx2.effectiveWeight)
	}
}
