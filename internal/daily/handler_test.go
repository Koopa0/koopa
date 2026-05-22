package daily

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Track 1B — Today fan-out wire contract.
//
// GET /api/admin/commitment/daily-plan is one of the six Today fan-out
// sources. DailyPlanService.today() → TodayService.plan() consumes the
// top-level fields date/items/total/done/overdue_count. These marshaling
// tests pin those wire field names (and the null-vs-empty rule) without a
// database — a rename here breaks the Today plan region silently.

func TestPlanResponseWireContract(t *testing.T) {
	resp := PlanResponse{
		Date:         "2026-05-21",
		Items:        []PlanItem{{ID: "p1", TodoID: "t1", Title: "Fix auth middleware", SelectedBy: "hq"}},
		Total:        2,
		Done:         1,
		OverdueCount: 1,
	}
	keys := wireKeys(t, resp)
	for _, want := range []string{"date", "items", "total", "done", "overdue_count"} {
		if _, ok := keys[want]; !ok {
			t.Errorf("PlanResponse missing wire field %q (TodayService.plan consumes it)", want)
		}
	}

	itemKeys := firstItemKeys(t, keys["items"])
	for _, want := range []string{"id", "todo_id", "title", "state", "selected_by"} {
		if _, ok := itemKeys[want]; !ok {
			t.Errorf("PlanItem missing wire field %q", want)
		}
	}
}

// TestPlanResponseEmptyItemsIsArrayNotNull pins null-vs-empty: the handler
// initializes Items to a non-nil slice (make([]PlanItem, 0)), so an empty plan
// serializes "items":[] per the json-api rule, never "items":null.
func TestPlanResponseEmptyItemsIsArrayNotNull(t *testing.T) {
	b, err := json.Marshal(PlanResponse{Date: "2026-05-21", Items: []PlanItem{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(b, []byte(`"items":[]`)) {
		t.Errorf("empty PlanResponse must serialize \"items\":[], got %s", b)
	}
}

func wireKeys(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func firstItemKeys(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("unmarshal items: %v", err)
	}
	if len(arr) == 0 {
		t.Fatal("items array empty")
	}
	return arr[0]
}
