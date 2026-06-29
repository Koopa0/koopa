// Copyright 2026 Koopa. All rights reserved.

package daily

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// TestItem_IsCompletedOn pins the completion predicate shared by the Today
// aggregate (today.loadPlan) and brief(reflection): a planned todo counts as
// completed when it reached done OR when it is a recurring todo whose occurrence
// was completed on the plan date. The recurrence arm is the one that a pure
// todo_state check misses — a routine done today never sets state=done.
func TestItem_IsCompletedOn(t *testing.T) {
	t.Parallel()
	date := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	otherDay := time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC)
	weekdayMask := int16(127)
	interval := int32(1)

	// Cross-timezone civil-date case: the plan date is Asia/Taipei midnight
	// (2026-06-30 00:00+08 == 2026-06-29 16:00 UTC) while last_completed_on is a
	// DATE read as midnight UTC. sameCivilDate compares .Date() components in
	// each location, so a 2026-06-30 stamp matches the Taipei plan date even
	// though the underlying instants differ — and a 2026-06-29 stamp does not.
	taipei, err := time.LoadLocation("Asia/Taipei")
	if err != nil {
		t.Fatalf("loading Asia/Taipei: %v", err)
	}
	taipeiDate := time.Date(2026, 6, 30, 0, 0, 0, 0, taipei)

	tests := []struct {
		name string
		item Item
		want bool
	}{
		{name: "terminal done", item: Item{TodoState: "done"}, want: true},
		{name: "plain todo not done", item: Item{TodoState: "todo"}, want: false},
		{name: "someday not done", item: Item{TodoState: "someday"}, want: false},
		{
			name: "weekday recurring completed today",
			item: Item{TodoState: "in_progress", TodoRecurWeekdays: &weekdayMask, TodoLastCompletedOn: &date},
			want: true,
		},
		{
			name: "interval recurring completed today",
			item: Item{TodoState: "todo", TodoRecurInterval: &interval, TodoLastCompletedOn: &date},
			want: true,
		},
		{
			name: "recurring completed a different day",
			item: Item{TodoState: "todo", TodoRecurWeekdays: &weekdayMask, TodoLastCompletedOn: &otherDay},
			want: false,
		},
		{
			name: "recurring never completed",
			item: Item{TodoState: "todo", TodoRecurWeekdays: &weekdayMask},
			want: false,
		},
		{
			name: "non-recurring with a stray stamp is not 'completed today'",
			item: Item{TodoState: "todo", TodoLastCompletedOn: &date},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.item.IsCompletedOn(date); got != tt.want {
				t.Errorf("IsCompletedOn(%s) = %v, want %v", date.Format(time.DateOnly), got, tt.want)
			}
		})
	}

	// Cross-timezone: a Taipei-midnight plan date vs a UTC-stored stamp.
	matchTaipei := Item{TodoState: "todo", TodoRecurWeekdays: &weekdayMask, TodoLastCompletedOn: &date}        // stamp 2026-06-30 UTC
	missTaipei := Item{TodoState: "todo", TodoRecurWeekdays: &weekdayMask, TodoLastCompletedOn: &otherDay}      // stamp 2026-06-29 UTC
	if !matchTaipei.IsCompletedOn(taipeiDate) {
		t.Errorf("IsCompletedOn(Taipei %s) with a 2026-06-30 UTC stamp = false, want true (same civil date)", taipeiDate.Format(time.DateOnly))
	}
	if missTaipei.IsCompletedOn(taipeiDate) {
		t.Errorf("IsCompletedOn(Taipei %s) with a 2026-06-29 UTC stamp = true, want false (different civil date)", taipeiDate.Format(time.DateOnly))
	}
}

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
		Items:        []PlanItem{{ID: "p1", TodoID: "t1", Title: "Fix auth middleware", SelectedBy: "claude"}},
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
