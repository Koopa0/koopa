package learning

import (
	"encoding/json"
	"testing"
)

// Track 1B — Today fan-out wire contract.
//
// GET /api/admin/learning/summary is one of the six Today fan-out sources.
// LearningService.summary() → TodayService consumes the due_reviews field.
// learningSummaryResponse is unexported, so this is a white-box test pinning
// the wire field names without a database — a rename of due_reviews breaks the
// Today review badge silently.

func TestLearningSummaryWireContract(t *testing.T) {
	resp := learningSummaryResponse{
		StreakDays: 4,
		DueReviews: 3,
		Domains:    []DomainMastery{},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, want := range []string{"streak_days", "due_reviews", "domains"} {
		if _, ok := m[want]; !ok {
			t.Errorf("learningSummaryResponse missing wire field %q (TodayService consumes due_reviews)", want)
		}
	}
}
