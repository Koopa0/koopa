// Copyright 2026 Koopa. All rights reserved.

package search

import "testing"

func TestParseLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "empty defaults to 20", raw: "", want: 20},
		{name: "non-numeric defaults to 20", raw: "abc", want: 20},
		{name: "zero defaults to 20", raw: "0", want: 20},
		{name: "negative defaults to 20", raw: "-5", want: 20},
		{name: "one is kept", raw: "1", want: 1},
		{name: "in range is kept", raw: "10", want: 10},
		{name: "max is kept", raw: "50", want: 50},
		{name: "above max clamps to max", raw: "51", want: 50},
		{name: "far above max clamps to max", raw: "1000", want: 50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseLimit(tt.raw); got != tt.want {
				t.Errorf("parseLimit(%q) = %d, want %d", tt.raw, got, tt.want)
			}
		})
	}
}

func TestLimitPerSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		total int
		n     int
		want  int
	}{
		{name: "even split", total: 20, n: 4, want: 5},
		{name: "floors to whole", total: 10, n: 3, want: 3},
		{name: "at least one when the split rounds to zero", total: 3, n: 4, want: 1},
		{name: "one each at the cap", total: 50, n: 50, want: 1},
		{name: "zero sources", total: 20, n: 0, want: 0},
		{name: "negative sources", total: 20, n: -1, want: 0},
		{name: "zero total", total: 0, n: 4, want: 0},
		{name: "negative total", total: -5, n: 4, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := limitPerSource(tt.total, tt.n); got != tt.want {
				t.Errorf("limitPerSource(%d, %d) = %d, want %d", tt.total, tt.n, got, tt.want)
			}
		})
	}
}
