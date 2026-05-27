package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
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

// TestRecommendNextTargetOutput_OmitemptyContract pins the per-field
// presence contract for RecommendNextTargetOutput. The `omitempty` tags
// on `recent_patterns` and `empty_reason` are deliberate: clients
// distinguish "we ran the recommender and it had nothing to say" from
// "we ran the recommender and the result included observability signal
// X". Removing either `omitempty` would silently break that distinction
// — this test fails if anyone does.
//
// `candidates` has NO `omitempty` and MUST always be emitted, so a
// client iterating `response.candidates` never hits an undefined.
func TestRecommendNextTargetOutput_OmitemptyContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		out              RecommendNextTargetOutput
		wantCandidates   bool // must always be true — candidates has no omitempty
		wantPatterns     bool // recent_patterns key present?
		wantEmptyReason  bool // empty_reason key present?
		wantCandidateLen int
	}{
		{
			name:             "fully empty — only candidates key emitted",
			out:              RecommendNextTargetOutput{Candidates: []Candidate{}},
			wantCandidates:   true,
			wantPatterns:     false,
			wantEmptyReason:  false,
			wantCandidateLen: 0,
		},
		{
			name: "candidates only — recommender returned suggestions; no diagnostic needed",
			out: RecommendNextTargetOutput{
				Candidates: []Candidate{
					{TargetID: uuid.New(), Title: "Sliding window mid", SourceConcept: "two-pointer", SourceSeverity: "moderate", Reason: "weakness anchor"},
					{TargetID: uuid.New(), Title: "Sliding window hard", SourceConcept: "two-pointer", SourceSeverity: "moderate", Reason: "harder variant"},
				},
			},
			wantCandidates:   true,
			wantPatterns:     false,
			wantEmptyReason:  false,
			wantCandidateLen: 2,
		},
		{
			name: "empty_reason set — diagnostic surfaces when zero candidates",
			out: RecommendNextTargetOutput{
				Candidates:  []Candidate{},
				EmptyReason: "no concepts need practice in the 30-day window",
			},
			wantCandidates:   true,
			wantPatterns:     false,
			wantEmptyReason:  true,
			wantCandidateLen: 0,
		},
		{
			name: "recent_patterns populated — interleaving filter observability",
			out: RecommendNextTargetOutput{
				Candidates:     []Candidate{},
				RecentPatterns: []string{"two-pointer", "sliding-window"},
				EmptyReason:    "all candidates rejected by interleaving filter; retry with relaxed filter",
			},
			wantCandidates:   true,
			wantPatterns:     true,
			wantEmptyReason:  true,
			wantCandidateLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			_, hasCandidates := parsed["candidates"]
			if hasCandidates != tt.wantCandidates {
				t.Errorf("RecommendNextTargetOutput has candidates key = %v, want %v (candidates must have NO omitempty)", hasCandidates, tt.wantCandidates)
			}
			_, hasPatterns := parsed["recent_patterns"]
			if hasPatterns != tt.wantPatterns {
				t.Errorf("RecommendNextTargetOutput has recent_patterns key = %v, want %v (must honor omitempty)", hasPatterns, tt.wantPatterns)
			}
			_, hasReason := parsed["empty_reason"]
			if hasReason != tt.wantEmptyReason {
				t.Errorf("RecommendNextTargetOutput has empty_reason key = %v, want %v (must honor omitempty)", hasReason, tt.wantEmptyReason)
			}

			// candidates length cross-check when present
			rawCands, hasCands := parsed["candidates"]
			if !hasCands {
				return
			}
			if string(rawCands) == "null" {
				t.Errorf("RecommendNextTargetOutput[candidates] = null, want JSON array")
				return
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(rawCands, &arr); err != nil {
				t.Errorf("RecommendNextTargetOutput[candidates] is not an array: %v (raw=%s)", err, rawCands)
				return
			}
			if len(arr) != tt.wantCandidateLen {
				t.Errorf("RecommendNextTargetOutput[candidates] len = %d, want %d", len(arr), tt.wantCandidateLen)
			}
		})
	}
}
