package mcp

import (
	"testing"

	"github.com/Koopa0/koopa/internal/todo"
)

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
