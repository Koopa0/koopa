package mcp

import (
	"strings"
	"testing"
)

// TestEmptyReasonFromProbe locks the recommend_next_target diagnostic
// contract: the empty_reason string must name the dominant cause from
// the probe report, not list every possible cause. HQ Round 2 audit
// flagged the previous "list four causes" message as honest but
// operationally useless — coaches re-ran their own diagnostic to
// figure out which case applied.
//
// Each case asserts on a substring marker that pinpoints the cause
// branch, and (when the relaxed-filter prefix should appear) checks
// for the prefix too. Substring matching is loose on purpose so prose
// edits do not require test churn — the markers are the load-bearing
// promises.
func TestEmptyReasonFromProbe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		report      probeReport
		relaxed     bool
		wantMarker  string
		wantRelaxed bool
	}{
		{
			name: "all weaknesses unanchored — points at no_anchor_attempts",
			report: probeReport{
				weaknessesProbed: 3,
				noAnchorAttempts: 3,
			},
			wantMarker: "no recorded attempts",
		},
		{
			name: "all anchored but no variations — points at no_variations",
			report: probeReport{
				weaknessesProbed: 2,
				noVariations:     2,
			},
			wantMarker: "no learning_target_relations",
		},
		{
			name: "all variations rejected — names rejection causes",
			report: probeReport{
				weaknessesProbed:      4,
				allVariationsRejected: 4,
			},
			wantMarker: "rejected by acceptVariation",
		},
		{
			name: "mixed: noAnchorAttempts dominant",
			report: probeReport{
				weaknessesProbed:      5,
				noAnchorAttempts:      3,
				noVariations:          1,
				allVariationsRejected: 1,
			},
			wantMarker: "no recorded attempts (no anchors)",
		},
		{
			name: "mixed: noVariations dominant",
			report: probeReport{
				weaknessesProbed:      5,
				noAnchorAttempts:      1,
				noVariations:          3,
				allVariationsRejected: 1,
			},
			wantMarker: "no recorded relations",
		},
		{
			name: "mixed: allRejected dominant",
			report: probeReport{
				weaknessesProbed:      4,
				noAnchorAttempts:      1,
				noVariations:          1,
				allVariationsRejected: 2,
			},
			wantMarker: "all rejected by acceptVariation",
		},
		{
			name: "relaxed filter — prefix appended",
			report: probeReport{
				weaknessesProbed: 1,
				noAnchorAttempts: 1,
			},
			relaxed:     true,
			wantMarker:  "no recorded attempts",
			wantRelaxed: true,
		},
		{
			name:       "zero weaknesses — defensive sentinel",
			report:     probeReport{},
			wantMarker: "no weakness concepts to probe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := emptyReasonFromProbe(tt.report, tt.relaxed)
			if !strings.Contains(got, tt.wantMarker) {
				t.Errorf("emptyReasonFromProbe(...) = %q, want substring %q", got, tt.wantMarker)
			}
			hasRelaxed := strings.Contains(got, "relaxed interleaving filter")
			if hasRelaxed != tt.wantRelaxed {
				t.Errorf("emptyReasonFromProbe(...) relaxed prefix = %v, want %v\nfull message: %s", hasRelaxed, tt.wantRelaxed, got)
			}
		})
	}
}
