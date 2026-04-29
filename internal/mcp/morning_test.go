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
