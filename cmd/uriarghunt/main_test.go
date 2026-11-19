package main

import (
	"testing"

	"uriarghunt/internal/report"
)

func TestParseTier(t *testing.T) {
	for n := 0; n <= 3; n++ {
		got, err := parseTier(n)
		if err != nil {
			t.Fatalf("parseTier(%d) error: %v", n, err)
		}
		if got != report.Tier(n) {
			t.Errorf("parseTier(%d) = %v, want %v", n, got, report.Tier(n))
		}
	}

	for _, bad := range []int{-1, 4, 99} {
		if _, err := parseTier(bad); err == nil {
			t.Errorf("parseTier(%d) expected error", bad)
		}
	}
}
