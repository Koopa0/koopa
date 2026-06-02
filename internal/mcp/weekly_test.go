// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"encoding/json"
	"testing"

	"github.com/Koopa0/koopa/internal/activity"
	"github.com/Koopa0/koopa/internal/learning"
	"github.com/Koopa0/koopa/internal/weekly"
)

// TestWeeklySummaryOutput_WireShape pins the top-level wire shape of
// WeeklySummaryOutput. Three keys are required on every response:
//
//   - `review` (weekly.Review) — owned by internal/weekly; THIS test does
//     NOT pin its internal fields. The weekly package owns that contract.
//   - `mastery` ([]MasteryRow) — owned by this package; MUST encode as
//     `[]` not `null` when empty so a consuming agent or frontend can
//     iterate it unconditionally.
//   - `self_audit` (SelfAudit) — owned by this package since CF-08 P0;
//     MUST always be present (value type, not pointer) and its two
//     slice fields MUST encode as `[]` not `null` when empty for the
//     same iterate-unconditionally reason.
//
// None of these fields carry `omitempty`, so nil slices would marshal
// as `null` — this test catches that drift.
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
				SelfAudit: SelfAudit{
					SameConceptRepeatedWithinWeek: []learning.RepeatedConcept{},
					SkipReasonPrefixHistogram:     []activity.SkipReasonPrefix{},
				},
			},
			wantMastery: 0,
		},
		{
			name: "populated mastery — preserves cardinality",
			out: WeeklySummaryOutput{
				Review:  weekly.Review{},
				Mastery: []MasteryRow{{}, {}, {}},
				SelfAudit: SelfAudit{
					SameConceptRepeatedWithinWeek: []learning.RepeatedConcept{},
					SkipReasonPrefixHistogram:     []activity.SkipReasonPrefix{},
				},
			},
			wantMastery: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			for _, key := range []string{"review", "mastery", "self_audit"} {
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

			// Pin the two slice fields inside self_audit so a future
			// refactor that drops `omitempty`-equivalent behaviour or
			// switches to nil slices fails loudly.
			rawSelfAudit, ok := parsed["self_audit"]
			if !ok {
				return
			}
			var saMap map[string]json.RawMessage
			if err := json.Unmarshal(rawSelfAudit, &saMap); err != nil {
				t.Errorf("WeeklySummaryOutput[self_audit] is not an object: %v (raw=%s)", err, rawSelfAudit)
				return
			}
			for _, sliceKey := range []string{"same_concept_repeated_within_week", "skip_reason_prefix_histogram"} {
				raw, ok := saMap[sliceKey]
				if !ok {
					t.Errorf("self_audit missing slice key %q", sliceKey)
					continue
				}
				if string(raw) == "null" {
					t.Errorf("self_audit[%s] = null, want JSON array", sliceKey)
				}
			}
		})
	}
}
