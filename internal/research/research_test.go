// Copyright 2026 Koopa. All rights reserved.

package research

import "testing"

func TestTrustStatusValid(t *testing.T) {
	tests := []struct {
		name string
		in   TrustStatus
		want bool
	}{
		{name: "low_trust", in: TrustLow, want: true},
		{name: "trusted", in: TrustTrusted, want: true},
		{name: "empty", in: "", want: false},
		{name: "bogus", in: "verified", want: false},
		{name: "note maturity leaks in", in: "evergreen", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.Valid(); got != tt.want {
				t.Errorf("TrustStatus(%q).Valid() = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestStatusValid(t *testing.T) {
	tests := []struct {
		name string
		in   Status
		want bool
	}{
		{name: "open", in: StatusOpen, want: true},
		{name: "fulfilled", in: StatusFulfilled, want: true},
		{name: "empty", in: "", want: false},
		{name: "bogus", in: "closed", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.Valid(); got != tt.want {
				t.Errorf("Status(%q).Valid() = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
