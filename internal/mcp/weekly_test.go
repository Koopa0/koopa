package mcp

import (
	"encoding/json"
	"testing"

	"github.com/Koopa0/koopa/internal/weekly"
)

// TestWeeklySummaryOutput_WireShape pins the top-level wire shape of
// WeeklySummaryOutput. Two keys are required on every response:
//
//   - `review` (weekly.Review) — owned by internal/weekly; THIS test does
//     NOT pin its internal fields. The weekly package owns that contract.
//   - `mastery` ([]MasteryRow) — owned by this package; MUST encode as
//     `[]` not `null` when empty so a consuming agent or frontend can
//     iterate it unconditionally.
//
// `mastery` has no `omitempty` tag in WeeklySummaryOutput, so a nil
// slice would marshal as `null` — this test catches that drift.
func TestWeeklySummaryOutput_WireShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		out         WeeklySummaryOutput
		wantMastery int
	}{
		{
			name: "empty mastery — encodes as [] not null",
			out: WeeklySummaryOutput{
				Review:  weekly.Review{},
				Mastery: []MasteryRow{},
			},
			wantMastery: 0,
		},
		{
			name: "populated mastery — preserves cardinality",
			out: WeeklySummaryOutput{
				Review:  weekly.Review{},
				Mastery: []MasteryRow{{}, {}, {}},
			},
			wantMastery: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			for _, key := range []string{"review", "mastery"} {
				if _, ok := parsed[key]; !ok {
					t.Errorf("WeeklySummaryOutput missing key %q", key)
				}
			}

			rawMastery, ok := parsed["mastery"]
			if !ok {
				return
			}
			if string(rawMastery) == "null" {
				t.Errorf("WeeklySummaryOutput[mastery] = null, want JSON array")
				return
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(rawMastery, &arr); err != nil {
				t.Errorf("WeeklySummaryOutput[mastery] is not an array: %v (raw=%s)", err, rawMastery)
				return
			}
			if len(arr) != tt.wantMastery {
				t.Errorf("WeeklySummaryOutput[mastery] len = %d, want %d", len(arr), tt.wantMastery)
			}
		})
	}
}
