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
