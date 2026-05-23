package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentnote "github.com/Koopa0/koopa/internal/agent/note"
	"github.com/Koopa0/koopa/internal/agent/task"
	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/goal"
	"github.com/Koopa0/koopa/internal/learning/hypothesis"
	"github.com/Koopa0/koopa/internal/todo"
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
		OverdueTasks:         []todo.PendingDetail{},
		TodayTasks:           []todo.PendingDetail{},
		CommittedTasks:       []daily.Item{},
		UpcomingTasks:        []todo.PendingDetail{},
		ActiveGoals:          []goal.ActiveGoalSummary{},
		PendingTasksReceived: []task.Task{},
		PendingTasksIssued:   []task.Task{},
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
		"overdue_tasks",
		"today_tasks",
		"committed_tasks",
		"upcoming_tasks",
		"active_goals",
		"pending_tasks_received",
		"pending_tasks_issued",
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
			want:   []string{"tasks", "pending_tasks", "hypotheses", "plan_history"},
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
