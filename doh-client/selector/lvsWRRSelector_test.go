package selector

import "testing"

func TestGCD(t *testing.T) {
	tests := []struct {
		x, y, want int32
	}{
		{0, 5, 5},
		{5, 0, 5},
		{-5, 10, 5},
		{10, -5, 5},
		{-10, -5, 5},
		{0, 0, 0},
		{12, 8, 4},
		{8, 12, 4},
		{1, 1, 1},
	}
	for _, tt := range tests {
		got := gcd(tt.x, tt.y)
		if got != tt.want {
			t.Errorf("gcd(%d,%d) = %d, want %d", tt.x, tt.y, got, tt.want)
		}
	}
}
