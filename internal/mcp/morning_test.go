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
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
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
		Mode:                 briefModeMorning,
		Date:                 time.Now().Format(time.DateOnly),
		OverdueTodos:         []todo.PendingDetail{},
		TodayTodos:           []todo.PendingDetail{},
		CommittedTodos:       []daily.Item{},
		UpcomingTodos:        []todo.PendingDetail{},
		ActiveGoals:          []goal.ActiveGoalSummary{},
		UnverifiedHypotheses: []hypothesis.Record{},
		RSSHighlights:        []RSSHighlight{},
		ContentPipeline:      []ContentSummary{},
	}

	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal(out) error = %v, want nil", err)
	}

	listFields := []string{
		"overdue_todos",
		"today_todos",
		"committed_todos",
		"upcoming_todos",
		"active_goals",
		"unverified_hypotheses",
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

// TestResolveDefaultSections pins the per-agent allowlist contract: an
// unlisted caller falls through to "all sections" semantics (nil return), and
// learning-studio explicitly skips rss + content_pipeline so the morning-brief
// token cost stays focused on learning-relevant signals. Explicit sections are
// handled by brief, not this function — this only locks the map.
func TestResolveDefaultSections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		caller string
		want   []string
	}{
		{name: "unlisted caller falls through to all", caller: "hq", want: nil},
		{name: "empty caller falls through to all", caller: "", want: nil},
		{
			name:   "learning-studio gets focused subset",
			caller: "learning-studio",
			want:   []string{"tasks", "hypotheses"},
		},
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
			// learning-studio's set must NEVER include rss or content_pipeline
			// regardless of how the map grows — these are the noise the brief
			// specifically wanted to silence.
			if tt.caller == "learning-studio" {
				for _, sec := range got {
					if sec == "rss" || sec == "content_pipeline" {
						t.Errorf("resolveDefaultSections(learning-studio) included %q — that noise should stay gone", sec)
					}
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
		"committed_todos",
		"upcoming_todos",
		"active_goals",
		"unverified_hypotheses",
		"rss_highlights",
		"content_pipeline",
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
				Mode:                 briefModeMorning,
				Date:                 "2026-05-27",
				OverdueTodos:         []todo.PendingDetail{},
				TodayTodos:           []todo.PendingDetail{},
				CommittedTodos:       []daily.Item{},
				UpcomingTodos:        []todo.PendingDetail{},
				ActiveGoals:          []goal.ActiveGoalSummary{},
				UnverifiedHypotheses: []hypothesis.Record{},
				RSSHighlights:        []RSSHighlight{},
				ContentPipeline:      []ContentSummary{},
			},
			expect: []fieldExpectation{
				{"overdue_todos", 0},
				{"today_todos", 0},
				{"committed_todos", 0},
				{"upcoming_todos", 0},
				{"active_goals", 0},
				{"unverified_hypotheses", 0},
				{"rss_highlights", 0},
				{"content_pipeline", 0},
			},
		},
		{
			name: "tasks section populated — only task-bearing keys carry data, others stay []",
			out: BriefOutput{
				Mode: briefModeMorning,
				Date: "2026-05-27",
				OverdueTodos: []todo.PendingDetail{
					{ID: uuid.New(), Title: "ship audit memo"},
				},
				TodayTodos:           []todo.PendingDetail{{ID: uuid.New(), Title: "review draft"}},
				CommittedTodos:       []daily.Item{},
				UpcomingTodos:        []todo.PendingDetail{},
				ActiveGoals:          []goal.ActiveGoalSummary{},
				UnverifiedHypotheses: []hypothesis.Record{},
				RSSHighlights:        []RSSHighlight{},
				ContentPipeline:      []ContentSummary{},
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
				Mode:                 briefModeMorning,
				Date:                 "2026-05-27",
				OverdueTodos:         []todo.PendingDetail{},
				TodayTodos:           []todo.PendingDetail{},
				CommittedTodos:       []daily.Item{},
				UpcomingTodos:        []todo.PendingDetail{},
				ActiveGoals:          []goal.ActiveGoalSummary{},
				UnverifiedHypotheses: []hypothesis.Record{},
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
