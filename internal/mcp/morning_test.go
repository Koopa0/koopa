// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/todo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// TestPlanDayOutput_ItemsRemovedNeverNull guards the json-api invariant
// for the items_removed field on plan_day's output: even when no plan
// existed for the date, the slice must marshal to [] not null. plan_day
// is idempotent and re-callable; client code that iterates items_removed
// to surface "what got displaced" cannot tolerate a nil here.
func TestPlanDayOutput_ItemsRemovedNeverNull(t *testing.T) {
	t.Parallel()

	out := PlanDayOutput{
		Date:         time.Now().Format(time.DateOnly),
		ItemsCreated: 0,
		Items:        []daily.Item{},
		ItemsRemoved: []daily.RemovedItem{},
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal(out) error = %v, want nil", err)
	}
	got := string(b)
	if strings.Contains(got, `"items_removed":null`) {
		t.Errorf("PlanDayOutput JSON has items_removed=null, want []: %s", got)
	}
	if strings.Contains(got, `"items":null`) {
		t.Errorf("PlanDayOutput JSON has items=null, want []: %s", got)
	}
}

// TestBriefOutput_MorningSlicesMarshalAsEmptyArray locks in the json-api
// invariant that every morning list field on BriefOutput must serialise to []
// (never null) regardless of which sections were requested. The handler
// initialises every morning slice field up front; this test guards that
// initialisation against drift.
func TestBriefOutput_MorningSlicesMarshalAsEmptyArray(t *testing.T) {
	t.Parallel()

	out := BriefOutput{
		Mode:            briefModeMorning,
		Date:            time.Now().Format(time.DateOnly),
		OverdueTodos:    []todo.PendingDetail{},
		TodayTodos:      []todo.PendingDetail{},
		ActiveTodos:     []todo.PendingDetail{},
		RecurringTodos:  []todo.Item{},
		CommittedTodos:  []daily.Item{},
		UpcomingTodos:   []todo.PendingDetail{},
		ActiveGoals:     []goal.ActiveGoalSummary{},
		RSSHighlights:   []RSSHighlight{},
		ContentPipeline: []ContentSummary{},
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal(out) error = %v, want nil", err)
	}

	listFields := []string{
		"overdue_todos",
		"today_todos",
		"active_todos",
		"recurring_todos",
		"committed_todos",
		"upcoming_todos",
		"active_goals",
		"rss_highlights",
		"content_pipeline",
	}
	got := string(b)
	for _, field := range listFields {
		if strings.Contains(got, `"`+field+`":null`) {
			t.Errorf("BriefOutput morning JSON for %q field is null, want []", field)
		}
	}
}

// TestResolveDefaultSections pins the per-agent allowlist contract: a caller
// not listed in defaultSectionsByAgent falls through to "all sections"
// semantics (nil return). The map is currently empty (learning-studio, its
// only former entry, has been retired), so every caller falls through.
// Explicit sections are handled by brief, not this function — this only locks
// the map.
func TestResolveDefaultSections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		caller string
		want   []string
	}{
		{name: "unlisted caller falls through to all", caller: "claude", want: nil},
		{name: "empty caller falls through to all", caller: "", want: nil},
		{name: "retired learning-studio falls through to all", caller: "learning-studio", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveDefaultSections(tt.caller)
			if len(got) != len(tt.want) {
				t.Fatalf("resolveDefaultSections(%q) len = %d, want %d (got=%v)", tt.caller, len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				if got[i] != w {
					t.Errorf("resolveDefaultSections(%q)[%d] = %q, want %q", tt.caller, i, got[i], w)
				}
			}
		})
	}
}

// TestBriefOutput_MorningWireShape pins the wire-level key set that brief
// emits in morning mode. The companion test above
// (TestBriefOutput_MorningSlicesMarshalAsEmptyArray) only proves that list
// fields don't become null on the zero value; this test additionally asserts
// (a) the exact key set (mode + date + every morning list field),
// (b) each list-bearing field carries the expected JSON name when populated,
// and (c) populating one section doesn't bleed into other sections' fields.
//
// Concrete element values are deliberately NOT pinned — only key presence and
// slice cardinality. Element shapes belong to their owning packages.
func TestBriefOutput_MorningWireShape(t *testing.T) {
	t.Parallel()

	// expectedTopLevelKeys is the canonical set of keys brief must always emit
	// in morning mode (mode + date + every morning list field). Adding to this
	// list is a wire-shape change and should fail this test until the constant
	// is updated in the same PR.
	expectedTopLevelKeys := []string{
		"mode",
		"date",
		"overdue_todos",
		"today_todos",
		"active_todos",
		"recurring_todos",
		"committed_todos",
		"upcoming_todos",
		"active_goals",
		"rss_highlights",
		"content_pipeline",
		"proposals_pending",
	}

	type fieldExpectation struct {
		key string
		// len asserts the marshaled JSON value is an array of exactly this length.
		len int
	}

	tests := []struct {
		name   string
		out    BriefOutput
		expect []fieldExpectation
	}{
		{
			name: "zero — every list field is [] not null",
			out: BriefOutput{
				Mode:            briefModeMorning,
				Date:            "2026-05-27",
				OverdueTodos:    []todo.PendingDetail{},
				TodayTodos:      []todo.PendingDetail{},
				ActiveTodos:     []todo.PendingDetail{},
				RecurringTodos:  []todo.Item{},
				CommittedTodos:  []daily.Item{},
				UpcomingTodos:   []todo.PendingDetail{},
				ActiveGoals:     []goal.ActiveGoalSummary{},
				RSSHighlights:   []RSSHighlight{},
				ContentPipeline: []ContentSummary{},
			},
			expect: []fieldExpectation{
				{"overdue_todos", 0},
				{"today_todos", 0},
				{"recurring_todos", 0},
				{"committed_todos", 0},
				{"upcoming_todos", 0},
				{"active_goals", 0},
				{"rss_highlights", 0},
				{"content_pipeline", 0},
			},
		},
		{
			name: "todos section populated — only todo-bearing keys carry data, others stay []",
			out: BriefOutput{
				Mode: briefModeMorning,
				Date: "2026-05-27",
				OverdueTodos: []todo.PendingDetail{
					{ID: uuid.New(), Title: "ship audit memo"},
				},
				TodayTodos:      []todo.PendingDetail{{ID: uuid.New(), Title: "review draft"}},
				RecurringTodos:  []todo.Item{},
				CommittedTodos:  []daily.Item{},
				UpcomingTodos:   []todo.PendingDetail{},
				ActiveGoals:     []goal.ActiveGoalSummary{},
				RSSHighlights:   []RSSHighlight{},
				ContentPipeline: []ContentSummary{},
			},
			expect: []fieldExpectation{
				{"overdue_todos", 1},
				{"today_todos", 1},
				{"committed_todos", 0},
				{"upcoming_todos", 0},
				{"active_goals", 0},
			},
		},
		{
			name: "rss section populated — RSSHighlights uses local DTO shape",
			out: BriefOutput{
				Mode:           briefModeMorning,
				Date:           "2026-05-27",
				OverdueTodos:   []todo.PendingDetail{},
				TodayTodos:     []todo.PendingDetail{},
				RecurringTodos: []todo.Item{},
				CommittedTodos: []daily.Item{},
				UpcomingTodos:  []todo.PendingDetail{},
				ActiveGoals:    []goal.ActiveGoalSummary{},
				RSSHighlights: []RSSHighlight{
					{Title: "Go 1.27 preview", URL: "https://example/g127", FeedName: "Go Blog", CreatedAt: "2026-05-26T10:00:00Z"},
				},
				ContentPipeline: []ContentSummary{},
			},
			expect: []fieldExpectation{
				{"rss_highlights", 1},
				{"overdue_todos", 0},
				{"content_pipeline", 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)

			// (a) canonical key set must match — catches field renames + missing fields
			gotKeys := slices.Sorted(maps.Keys(parsed))
			wantKeys := slices.Sorted(slices.Values(expectedTopLevelKeys))
			if diff := cmp.Diff(wantKeys, gotKeys); diff != "" {
				t.Errorf("BriefOutput morning top-level key set mismatch (-want +got):\n%s", diff)
			}

			// (b)+(c) per-field cardinality on the cases that pinned it
			for _, exp := range tt.expect {
				raw, ok := parsed[exp.key]
				if !ok {
					t.Errorf("BriefOutput missing key %q", exp.key)
					continue
				}
				if string(raw) == "null" {
					t.Errorf("BriefOutput[%q] = null, want JSON array of len %d", exp.key, exp.len)
					continue
				}
				var arr []json.RawMessage
				if err := json.Unmarshal(raw, &arr); err != nil {
					t.Errorf("BriefOutput[%q] is not a JSON array: %v (raw=%s)", exp.key, err, raw)
					continue
				}
				if len(arr) != exp.len {
					t.Errorf("BriefOutput[%q] len = %d, want %d", exp.key, len(arr), exp.len)
				}
			}
		})
	}
}

// TestBriefOutput_ReflectionWireShape pins the wire-level key set that brief
// emits in reflection mode: mode + date + plan-vs-actual completion fields,
// and crucially NO agent_notes-derived fields (the former today_notes /
// today_plan are dropped). It also asserts the inactive morning fields do not
// leak into the reflection envelope.
func TestBriefOutput_ReflectionWireShape(t *testing.T) {
	t.Parallel()

	expectedTopLevelKeys := []string{
		"mode",
		"date",
		"planned_items",
		"completed_count",
		"deferred_count",
		"planned_count",
		"completion_rate",
	}

	out := BriefOutput{
		Mode:           briefModeReflection,
		Date:           "2026-05-27",
		PlannedItems:   []daily.Item{},
		CompletedCount: 2,
		DeferredCount:  1,
		PlannedCount:   0,
		CompletionRate: 0.5,
	}

	parsed := marshalToKeyMap(t, out)
	gotKeys := slices.Sorted(maps.Keys(parsed))
	wantKeys := slices.Sorted(slices.Values(expectedTopLevelKeys))
	if diff := cmp.Diff(wantKeys, gotKeys); diff != "" {
		t.Errorf("BriefOutput reflection top-level key set mismatch (-want +got):\n%s", diff)
	}

	// Dropped agent_notes-derived fields must never resurface.
	for _, forbidden := range []string{"today_notes", "today_plan", "plan_history"} {
		if _, ok := parsed[forbidden]; ok {
			t.Errorf("BriefOutput reflection emitted forbidden agent_notes field %q", forbidden)
		}
	}

	// planned_items must be [] not null.
	if raw, ok := parsed["planned_items"]; ok {
		if string(raw) == "null" {
			t.Error("BriefOutput[planned_items] = null, want []")
		}
	}
}

// TestBriefOutput_ProposalsPendingWire pins proposals_pending as a scalar on
// the morning wire: it always serialises (present at 0, never omitted) so the
// push consumer can gate its nudge on N > 0, it carries the value set on the
// output through MarshalJSON's morning branch, and it never leaks into the
// reflection envelope (it is a morning-only field).
func TestBriefOutput_ProposalsPendingWire(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		out  BriefOutput
		want string // exact JSON number expected for proposals_pending
	}{
		{
			name: "morning zero — present as 0, not omitted",
			out:  BriefOutput{Mode: briefModeMorning, Date: "2026-05-27"},
			want: "0",
		},
		{
			name: "morning positive — carries the summed count through MarshalJSON",
			out:  BriefOutput{Mode: briefModeMorning, Date: "2026-05-27", ProposalsPending: 7},
			want: "7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parsed := marshalToKeyMap(t, tt.out)
			raw, ok := parsed["proposals_pending"]
			if !ok {
				t.Fatalf("morning BriefOutput missing proposals_pending key")
			}
			if string(raw) != tt.want {
				t.Errorf("proposals_pending = %s, want %s", raw, tt.want)
			}
		})
	}

	// Reflection mode must not emit proposals_pending — it is morning-only.
	reflection := BriefOutput{Mode: briefModeReflection, Date: "2026-05-27", ProposalsPending: 5}
	if _, ok := marshalToKeyMap(t, reflection)["proposals_pending"]; ok {
		t.Error("reflection BriefOutput emitted proposals_pending, want absent (morning-only field)")
	}
}
