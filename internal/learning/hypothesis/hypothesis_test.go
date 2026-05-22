package hypothesis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Track 1B-correction — Today fan-out wire contract (unverified hypotheses).
//
// GET /api/admin/learning/hypotheses?state=unverified is one of the six Today
// fan-out sources. HypothesisService.list → TodayService hypothesisRow()
// consumes id/claim/created_at/created_by (and the list is filtered by state).
// This is a WIRE-SHAPE test (struct marshaling), NOT a full route/handler
// contract: it pins the field names hypothesis.Record emits without exercising
// the mounted handler or a database. A rename here breaks the Today "Awaiting
// judgment" hypothesis rows silently.
func TestHypothesisRecordWireContract(t *testing.T) {
	r := Record{
		ID:           uuid.New(),
		CreatedBy:    "learning-studio",
		Claim:        "DFS termination is my weak spot",
		State:        State("unverified"),
		ObservedDate: time.Date(2026, 5, 18, 4, 0, 0, 0, time.UTC),
		CreatedAt:    time.Date(2026, 5, 18, 4, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// id/claim/created_at/created_by are consumed by TodayService; state is the
	// list filter param the frontend relies on.
	for _, want := range []string{"id", "claim", "state", "created_at", "created_by"} {
		if _, ok := m[want]; !ok {
			t.Errorf("hypothesis.Record missing wire field %q (Today hypothesis row / state filter consumes it)", want)
		}
	}
}
