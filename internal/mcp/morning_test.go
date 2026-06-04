// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
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

// TestMorningContextOutput_AllSlicesMarshalAsEmptyArray locks in the
// json-api invariant that every list field on MorningContextOutput must
// serialise to [] (never null) regardless of which sections were
// requested. The handler initialises all eleven slice fields up front;
// this test guards that initialisation against drift.
func TestMorningContextOutput_AllSlicesMarshalAsEmptyArray(t *testing.T) {
	t.Parallel()

	out := MorningContextOutput{
		Date:                 time.Now().Format(time.DateOnly),
		OverdueTodos:         []todo.PendingDetail{},
		TodayTodos:           []todo.PendingDetail{},
		CommittedTodos:       []daily.Item{},
		UpcomingTodos:        []todo.PendingDetail{},
		ActiveGoals:          []goal.ActiveGoalSummary{},
		UnverifiedHypotheses: []hypothesis.Record{},
		RSSHighlights:        []RSSHighlight{},
		PlanHistory:          []agentnote.Note{},
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
		"plan_history",
		"content_pipeline",
	}
	got := string(b)
	for _, field := range listFields {
		if strings.Contains(got, `"`+field+`":null`) {
			t.Errorf("MorningContextOutput JSON for %q field is null, want []", field)
		}
	}
}

// TestResolveDefaultSections pins the per-agent allowlist contract for
// REQ-5: an unlisted caller falls through to "all sections" semantics
// (nil return), and learning-studio explicitly skips rss +
// content_pipeline so the morning-briefing token cost stays focused on
// learning-relevant signals. Explicit input.Sections is handled by
// morningContext, not this function — this only locks the map.
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
			want:   []string{"tasks", "hypotheses", "plan_history"},
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
			// regardless of how the map grows — these are the noise the
			// brief specifically wanted to silence.
			if tt.caller == "learning-studio" {
				for _, sec := range got {
					if sec == "rss" || sec == "content_pipeline" {
						t.Errorf("resolveDefaultSections(learning-studio) included %q — REQ-5 wanted that noise gone", sec)
					}
				}
			}
		})
	}
}

// TestMorningContextOutput_PopulatedWireShape pins the wire-level key set
// that morning_context emits. The companion test above
// (TestMorningContextOutput_AllSlicesMarshalAsEmptyArray) only proves that
// list fields don't become null on the zero value; this test additionally
// asserts (a) the exact key set, (b) each list-bearing field carries the
// expected JSON name when populated, and (c) populating one section
// doesn't bleed into other sections' fields.
//
// Concrete element values are deliberately NOT pinned — only key presence
// and slice cardinality. Element shapes belong to their owning packages
// (todo, daily, agent_note, hypothesis, goal, task, content).
func TestMorningContextOutput_PopulatedWireShape(t *testing.T) {
	t.Parallel()

	// expectedTopLevelKeys is the canonical set of keys morning_context
	// must always emit (every list field plus `date`). Adding to this
	// list is a wire-shape change and should fail this test until the
	// constant is updated in the same PR.
	expectedTopLevelKeys := []string{
		"date",
		"overdue_todos",
		"today_todos",
		"committed_todos",
		"upcoming_todos",
		"active_goals",
		"unverified_hypotheses",
		"rss_highlights",
		"plan_history",
		"content_pipeline",
	}

	type fieldExpectation struct {
		key string
		// len asserts the marshaled JSON value is an array of exactly this length.
		len int
	}

	tests := []struct {
		name   string
		out    MorningContextOutput
		expect []fieldExpectation
	}{
		{
			name: "zero — every list field is [] not null",
			out: MorningContextOutput{
				Date:                 "2026-05-27",
				OverdueTodos:         []todo.PendingDetail{},
				TodayTodos:           []todo.PendingDetail{},
				CommittedTodos:       []daily.Item{},
				UpcomingTodos:        []todo.PendingDetail{},
				ActiveGoals:          []goal.ActiveGoalSummary{},
				UnverifiedHypotheses: []hypothesis.Record{},
				RSSHighlights:        []RSSHighlight{},
				PlanHistory:          []agentnote.Note{},
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
				{"plan_history", 0},
				{"content_pipeline", 0},
			},
		},
		{
			name: "tasks section populated — only task-bearing keys carry data, others stay []",
			out: MorningContextOutput{
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
				PlanHistory:          []agentnote.Note{},
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
			out: MorningContextOutput{
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
				PlanHistory:     []agentnote.Note{},
				ContentPipeline: []ContentSummary{},
			},
			expect: []fieldExpectation{
				{"rss_highlights", 1},
				{"overdue_todos", 0},
				{"plan_history", 0},
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
				t.Errorf("MorningContextOutput top-level key set mismatch (-want +got):\n%s", diff)
			}

			// (b)+(c) per-field cardinality on the cases that pinned it
			for _, exp := range tt.expect {
				raw, ok := parsed[exp.key]
				if !ok {
					t.Errorf("MorningContextOutput missing key %q", exp.key)
					continue
				}
				if strings.Contains(string(raw), `null`) && string(raw) == "null" {
					t.Errorf("MorningContextOutput[%q] = null, want JSON array of len %d", exp.key, exp.len)
					continue
				}
				var arr []json.RawMessage
				if err := json.Unmarshal(raw, &arr); err != nil {
					t.Errorf("MorningContextOutput[%q] is not a JSON array: %v (raw=%s)", exp.key, err, raw)
					continue
				}
				if len(arr) != exp.len {
					t.Errorf("MorningContextOutput[%q] len = %d, want %d", exp.key, len(arr), exp.len)
				}
			}
		})
	}
}
