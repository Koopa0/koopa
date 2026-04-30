package mcp

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/daily"
	"github.com/Koopa0/koopa/internal/todo"
)

// TestDisplacedFrom locks the items_removed semantic: a todo that
// appears in both the old plan and the new items list is NOT
// displaced, even though its plan_item row got a fresh id during the
// delete-then-insert dance. Only todos absent from the new list
// surface in items_removed.
//
// This is the behavior the morning-briefing override flow relies on
// — without it, items_removed reports row-identity churn instead of
// real evictions, and the override-confirmation use case breaks.
func TestDisplacedFrom(t *testing.T) {
	t.Parallel()

	todoA := uuid.New()
	todoB := uuid.New()
	todoC := uuid.New()

	rmA := daily.RemovedItem{ID: uuid.New(), TodoID: todoA, TodoTitle: "todo A"}
	rmB := daily.RemovedItem{ID: uuid.New(), TodoID: todoB, TodoTitle: "todo B"}
	rmC := daily.RemovedItem{ID: uuid.New(), TodoID: todoC, TodoTitle: "todo C"}

	tests := []struct {
		name    string
		removed []daily.RemovedItem
		kept    []PlanDayItem
		want    []daily.RemovedItem
	}{
		{
			name:    "empty removed returns empty",
			removed: nil,
			kept:    []PlanDayItem{{TaskID: todoA.String()}},
			want:    nil,
		},
		{
			name:    "every removed todo carried over — none displaced",
			removed: []daily.RemovedItem{rmA, rmB},
			kept:    []PlanDayItem{{TaskID: todoA.String()}, {TaskID: todoB.String()}},
			want:    []daily.RemovedItem{},
		},
		{
			name:    "one carried over, one dropped — only the dropped is displaced",
			removed: []daily.RemovedItem{rmA, rmB},
			kept:    []PlanDayItem{{TaskID: todoA.String()}},
			want:    []daily.RemovedItem{rmB},
		},
		{
			name:    "no overlap — every removed is displaced",
			removed: []daily.RemovedItem{rmA, rmB},
			kept:    []PlanDayItem{{TaskID: todoC.String()}},
			want:    []daily.RemovedItem{rmA, rmB},
		},
		{
			name:    "kept includes invalid task_id — invalid id is ignored, valid ones still match",
			removed: []daily.RemovedItem{rmA, rmB},
			kept:    []PlanDayItem{{TaskID: "not-a-uuid"}, {TaskID: todoA.String()}},
			want:    []daily.RemovedItem{rmB},
		},
		{
			name:    "no kept items — every removed is displaced",
			removed: []daily.RemovedItem{rmA, rmB, rmC},
			kept:    nil,
			want:    []daily.RemovedItem{rmA, rmB, rmC},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := displacedFrom(tt.removed, tt.kept)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("displacedFrom() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    todo.State
		action  string
		wantErr bool
	}{
		// inbox: can clarify or defer
		{name: "inbox clarify", from: todo.StateInbox, action: "clarify", wantErr: false},
		{name: "inbox defer", from: todo.StateInbox, action: "defer", wantErr: false},
		{name: "inbox start", from: todo.StateInbox, action: "start", wantErr: true},
		{name: "inbox complete", from: todo.StateInbox, action: "complete", wantErr: true},

		// todo: can start, complete, or defer
		{name: "todo start", from: todo.StateTodo, action: "start", wantErr: false},
		{name: "todo complete", from: todo.StateTodo, action: "complete", wantErr: false},
		{name: "todo defer", from: todo.StateTodo, action: "defer", wantErr: false},
		{name: "todo clarify", from: todo.StateTodo, action: "clarify", wantErr: true},

		// in_progress: can complete or defer
		{name: "in_progress complete", from: todo.StateInProgress, action: "complete", wantErr: false},
		{name: "in_progress defer", from: todo.StateInProgress, action: "defer", wantErr: false},
		{name: "in_progress start", from: todo.StateInProgress, action: "start", wantErr: true},
		{name: "in_progress clarify", from: todo.StateInProgress, action: "clarify", wantErr: true},

		// someday: can clarify or start
		{name: "someday clarify", from: todo.StateSomeday, action: "clarify", wantErr: false},
		{name: "someday start", from: todo.StateSomeday, action: "start", wantErr: false},
		{name: "someday complete", from: todo.StateSomeday, action: "complete", wantErr: true},
		{name: "someday defer", from: todo.StateSomeday, action: "defer", wantErr: true},

		// done: no transitions
		{name: "done clarify", from: todo.StateDone, action: "clarify", wantErr: true},
		{name: "done start", from: todo.StateDone, action: "start", wantErr: true},
		{name: "done complete", from: todo.StateDone, action: "complete", wantErr: true},
		{name: "done defer", from: todo.StateDone, action: "defer", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTransition(tt.from, tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTransition(%q, %q) error = %v, wantErr = %v", tt.from, tt.action, err, tt.wantErr)
			}
		})
	}
}
