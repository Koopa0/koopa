package mcp

import (
	"testing"
)

func TestClampDurationMinutes(t *testing.T) {
	t.Parallel()

	flex := func(n int) *FlexInt {
		v := FlexInt(n)
		return &v
	}
	i32 := func(n int32) *int32 { return &n }

	tests := []struct {
		name string
		in   *FlexInt
		want *int32
	}{
		{name: "nil input", in: nil, want: nil},
		{name: "zero", in: flex(0), want: nil},
		{name: "negative one — was silently becoming 1 minute before fix", in: flex(-1), want: nil},
		{name: "large negative", in: flex(-9999), want: nil},
		{name: "lower bound", in: flex(1), want: i32(1)},
		{name: "typical session length", in: flex(45), want: i32(45)},
		{name: "upper bound", in: flex(1440), want: i32(1440)},
		{name: "above cap clamps to 1440", in: flex(1441), want: i32(1440)},
		{name: "absurd value clamps to 1440", in: flex(99999), want: i32(1440)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := clampDurationMinutes(tt.in)
			switch {
			case tt.want == nil && got == nil:
				// match
			case tt.want == nil && got != nil:
				t.Fatalf("clampDurationMinutes(%v) = %d, want nil", tt.in, *got)
			case tt.want != nil && got == nil:
				t.Fatalf("clampDurationMinutes(%v) = nil, want %d", tt.in, *tt.want)
			case *tt.want != *got:
				t.Errorf("clampDurationMinutes(%v) = %d, want %d", tt.in, *got, *tt.want)
			}
		})
	}
}

// TestResolveDueWithinHours pins the absent-vs-explicit-zero contract for the
// retrieval-view window. The bug class commit b2e08cc fixed: a plain int
// caller field collapses unset and zero into the same value, so an explicit
// "due right now" request silently became "default window". The *FlexInt
// indirection — and the resolver below — is the structural guarantee that
// keeps the two distinct.
func TestResolveDueWithinHours(t *testing.T) {
	t.Parallel()

	flex := func(n int) *FlexInt {
		v := FlexInt(n)
		return &v
	}

	tests := []struct {
		name string
		in   *FlexInt
		want int
	}{
		{name: "nil input defaults to 24h", in: nil, want: 24},
		{name: "explicit zero preserved as strict due-now", in: flex(0), want: 0},
		{name: "lower positive", in: flex(1), want: 1},
		{name: "typical morning window", in: flex(24), want: 24},
		{name: "week-ahead upper bound", in: flex(168), want: 168},
		{name: "above cap clamps to 168", in: flex(169), want: 168},
		{name: "absurd positive clamps to 168", in: flex(99999), want: 168},
		{name: "negative one clamps to 0", in: flex(-1), want: 0},
		{name: "absurd negative clamps to 0", in: flex(-9999), want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolveDueWithinHours(tt.in)
			if got != tt.want {
				t.Errorf("resolveDueWithinHours(%v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
