// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/Koopa0/koopa/internal/learning"
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

// TestLearningDashboardOutput_MarshalJSON_PerView pins the wire shape of
// LearningDashboardOutput.MarshalJSON. The custom marshaller is the
// contract — struct tags on the type are deliberately misleading
// (commented in learning.go) — so this test addresses the marshaller
// directly. Invariants per view:
//
//   - `view` and `total` are always present.
//   - Exactly ONE view-specific slice key is present, and it matches the
//     view name (overview→sessions, mastery→mastery, etc.).
//   - All other view-specific keys are ABSENT (not present-with-null).
//   - `domain_warning` appears only when DomainWarning != "".
//   - The view-specific slice encodes as `[]` (not `null`) when empty,
//     via the package-internal ensureSlice helper.
//
// Invalid-view cases (View="" or View="bogus") are intentionally NOT
// tested here. learning.go:846-909 defaults View="" to "overview" and
// rejects unknown views with an error BEFORE returning a
// LearningDashboardOutput, so MarshalJSON is unreachable in those
// states from any production code path.
func TestLearningDashboardOutput_MarshalJSON_PerView(t *testing.T) {
	t.Parallel()

	// viewKeys is the canonical view → view-specific-key mapping.
	// Other views' keys must be ABSENT from the marshaled output for
	// the current view, not present-with-null. The closed set here is
	// the contract: a new view requires updating MarshalJSON AND this
	// test together.
	viewKeys := map[string]string{
		"overview":   "sessions",
		"mastery":    "mastery",
		"weaknesses": "weaknesses",
		"retrieval":  "retrieval",
		"timeline":   "timeline",
		"variations": "variations",
	}
	allViewKeys := make([]string, 0, len(viewKeys))
	for _, k := range viewKeys {
		allViewKeys = append(allViewKeys, k)
	}

	// Two populated rows so `total` carries a non-zero value and the
	// array-length assertion is meaningful. Concrete element shapes
	// belong to internal/learning; we only assert the wrapper here.
	populatedSessions := []learning.Session{{}, {}}
	populatedMastery := []MasteryRow{{}, {}}

	tests := []struct {
		name         string
		out          LearningDashboardOutput
		wantSliceKey string // which view-specific key must be present
		wantSliceLen int    // expected length of that slice
		wantHasWarn  bool   // domain_warning must appear
	}{
		{
			name:         "overview empty — sessions=[] only, total=0",
			out:          LearningDashboardOutput{View: "overview", Total: 0, Sessions: nil},
			wantSliceKey: "sessions",
			wantSliceLen: 0,
		},
		{
			name:         "overview populated — sessions has rows, total reflects",
			out:          LearningDashboardOutput{View: "overview", Total: 2, Sessions: populatedSessions},
			wantSliceKey: "sessions",
			wantSliceLen: 2,
		},
		{
			name:         "mastery empty — mastery=[] only",
			out:          LearningDashboardOutput{View: "mastery", Total: 0, Mastery: nil},
			wantSliceKey: "mastery",
			wantSliceLen: 0,
		},
		{
			name:         "mastery populated — mastery has rows",
			out:          LearningDashboardOutput{View: "mastery", Total: 2, Mastery: populatedMastery},
			wantSliceKey: "mastery",
			wantSliceLen: 2,
		},
		{
			name:         "weaknesses empty",
			out:          LearningDashboardOutput{View: "weaknesses", Total: 0},
			wantSliceKey: "weaknesses",
			wantSliceLen: 0,
		},
		{
			name:         "retrieval empty",
			out:          LearningDashboardOutput{View: "retrieval", Total: 0},
			wantSliceKey: "retrieval",
			wantSliceLen: 0,
		},
		{
			name:         "timeline empty",
			out:          LearningDashboardOutput{View: "timeline", Total: 0},
			wantSliceKey: "timeline",
			wantSliceLen: 0,
		},
		{
			name:         "variations empty",
			out:          LearningDashboardOutput{View: "variations", Total: 0},
			wantSliceKey: "variations",
			wantSliceLen: 0,
		},
		{
			name:         "domain_warning appears only when set (mastery view)",
			out:          LearningDashboardOutput{View: "mastery", Total: 0, DomainWarning: `domain "bogus" not found`},
			wantSliceKey: "mastery",
			wantSliceLen: 0,
			wantHasWarn:  true,
		},
		{
			name:         "domain_warning absent when empty (overview view)",
			out:          LearningDashboardOutput{View: "overview", Total: 0, DomainWarning: ""},
			wantSliceKey: "sessions",
			wantSliceLen: 0,
			wantHasWarn:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			// view + total always present
			for _, required := range []string{"view", "total"} {
				if _, ok := parsed[required]; !ok {
					t.Errorf("LearningDashboardOutput[%q] view=%q missing required key %q", tt.name, tt.out.View, required)
				}
			}

			// exactly the right view-specific key is present
			if _, ok := parsed[tt.wantSliceKey]; !ok {
				t.Errorf("LearningDashboardOutput view=%q missing view-specific key %q", tt.out.View, tt.wantSliceKey)
			}

			// other view keys MUST be absent (not null, not [])
			for _, k := range allViewKeys {
				if k == tt.wantSliceKey {
					continue
				}
				if _, present := parsed[k]; present {
					t.Errorf("LearningDashboardOutput view=%q leaked off-view key %q (MarshalJSON should strip it)", tt.out.View, k)
				}
			}

			// the view-specific slice MUST be a JSON array (never null)
			raw, ok := parsed[tt.wantSliceKey]
			if ok {
				if string(raw) == "null" {
					t.Errorf("LearningDashboardOutput view=%q [%q] = null, want JSON array (ensureSlice contract)", tt.out.View, tt.wantSliceKey)
				}
				var arr []json.RawMessage
				if err := json.Unmarshal(raw, &arr); err != nil {
					t.Errorf("LearningDashboardOutput view=%q [%q] is not an array: %v (raw=%s)", tt.out.View, tt.wantSliceKey, err, raw)
				} else if len(arr) != tt.wantSliceLen {
					t.Errorf("LearningDashboardOutput view=%q [%q] len = %d, want %d", tt.out.View, tt.wantSliceKey, len(arr), tt.wantSliceLen)
				}
			}

			// domain_warning conditional
			_, hasWarn := parsed["domain_warning"]
			if hasWarn != tt.wantHasWarn {
				t.Errorf("LearningDashboardOutput view=%q has domain_warning = %v, want %v", tt.out.View, hasWarn, tt.wantHasWarn)
			}

			// also sanity-check: no unexpected top-level keys.
			// Allowed: view, total, the active view's key, and (optionally) domain_warning.
			allowed := []string{"view", "total", tt.wantSliceKey}
			if tt.wantHasWarn {
				allowed = append(allowed, "domain_warning")
			}
			for k := range parsed {
				if !slices.Contains(allowed, k) {
					t.Errorf("LearningDashboardOutput view=%q has unexpected top-level key %q", tt.out.View, k)
				}
			}
		})
	}
}
