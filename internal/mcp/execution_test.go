package mcp

import (
	"testing"

	"github.com/Koopa0/koopa0.dev/internal/task"
)

func TestValidateTransition(t *testing.T) {
	tests := []struct {
		from    task.Status
		action  string
		wantErr bool
	}{
		// inbox: can clarify or defer
		{task.StatusInbox, "clarify", false},
		{task.StatusInbox, "defer", false},
		{task.StatusInbox, "start", true},
		{task.StatusInbox, "complete", true},

		// todo: can start, complete, or defer
		{task.StatusTodo, "start", false},
		{task.StatusTodo, "complete", false},
		{task.StatusTodo, "defer", false},
		{task.StatusTodo, "clarify", true},

		// in-progress: can complete or defer
		{task.StatusInProgress, "complete", false},
		{task.StatusInProgress, "defer", false},
		{task.StatusInProgress, "start", true},
		{task.StatusInProgress, "clarify", true},

		// someday: can clarify or start
		{task.StatusSomeday, "clarify", false},
		{task.StatusSomeday, "start", false},
		{task.StatusSomeday, "complete", true},
		{task.StatusSomeday, "defer", true},

		// done: no transitions
		{task.StatusDone, "clarify", true},
		{task.StatusDone, "start", true},
		{task.StatusDone, "complete", true},
		{task.StatusDone, "defer", true},
	}

	for _, tt := range tests {
		name := string(tt.from) + " → " + tt.action
		t.Run(name, func(t *testing.T) {
			err := validateTransition(tt.from, tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTransition(%q, %q) error = %v, wantErr = %v", tt.from, tt.action, err, tt.wantErr)
			}
		})
	}
}
