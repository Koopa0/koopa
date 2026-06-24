// Copyright 2026 Koopa. All rights reserved.

// tasks.go holds list_tasks, the read half of the proposal-readback loop.
// An agent pushes a raw todo into the inbox with capture_inbox (created_by =
// itself); the owner triages it in admin; list_tasks lets that same agent
// read back the disposition of the todos it created — closing the loop so an
// agent can learn the owner's taste from accept / pending / reject outcomes.
//
// # Caller-scoping
//
// The list is scoped to the resolved caller identity: it returns ONLY the
// todos whose created_by equals the caller, never the owner's personal todos
// or another agent's. There is no created_by input parameter — the scope is
// structural, derived from callerIdentity, so it cannot be widened to read a
// different creator. read-only.

package mcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/Koopa0/koopa/internal/todo"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListTasksInput is the input for the list_tasks tool. It carries only the
// caller self-identification — there are no filters. The readback is
// caller-scoped to the resolved identity, never a free-form filter over
// another agent's todos.
type ListTasksInput struct {
	As string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent whose created todos to read back. The list is scoped to this resolved identity; it is never a free-form filter over other agents' or the owner's todos."`
}

// TaskListItem is one row of list_tasks: a todo the calling agent created,
// with its current state so the agent can read the disposition. created_by
// echoes the resolved caller identity to make the caller-scoped contract
// explicit on the wire.
type TaskListItem struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	State     string `json:"state"`
	CreatedBy string `json:"created_by"`
}

// ListTasksOutput is the output of the list_tasks tool.
type ListTasksOutput struct {
	Tasks []TaskListItem `json:"tasks"`
}

func (s *Server) listTasks(ctx context.Context, _ *mcp.CallToolRequest, _ ListTasksInput) (*mcp.CallToolResult, ListTasksOutput, error) {
	caller := s.callerIdentity(ctx)
	rows, err := s.todos.TodosByCreator(ctx, caller)
	if err != nil {
		return nil, ListTasksOutput{}, fmt.Errorf("listing tasks created by %q: %w", caller, err)
	}

	tasks := make([]TaskListItem, len(rows))
	for i := range rows {
		tasks[i] = TaskListItem{
			ID:        rows[i].ID.String(),
			Title:     rows[i].Title,
			State:     string(rows[i].State),
			CreatedBy: caller,
		}
	}
	return nil, ListTasksOutput{Tasks: tasks}, nil
}

// resolveTaskStates is the closed set of terminal states resolve_task accepts.
// Only an agent's own created todos can be moved here; the values mirror the
// todo_state enum's terminal members (done plus the two agent self-close
// states added for this loop).
var resolveTaskStates = map[string]todo.State{
	"done":      todo.StateDone,
	"archived":  todo.StateArchived,
	"dismissed": todo.StateDismissed,
}

// ResolveTaskInput is the input for resolve_task: the id of a todo the caller
// created and the terminal state to move it to. Like list_tasks there is no
// created_by parameter — the write is scoped to the resolved caller identity,
// so an agent can only resolve its own todos, never the owner's or another
// agent's.
type ResolveTaskInput struct {
	ID    string `json:"id" jsonschema:"required" jsonschema_description:"UUID of a todo YOU created (created_by = your resolved identity). Resolving a todo created by anyone else returns not-found and changes nothing."`
	State string `json:"state" jsonschema:"required" jsonschema_description:"Terminal state to set: 'done' (completed), 'archived' (filed away), or 'dismissed' (won't do)."`
	As    string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call. The resolve is scoped to this resolved identity; it can only close todos you created."`
}

// ResolveTaskOutput echoes the resolved id + state and an ok flag, closing the
// write half of the capture/readback loop.
type ResolveTaskOutput struct {
	ID    string `json:"id"`
	State string `json:"state"`
	OK    bool   `json:"ok"`
}

func (s *Server) resolveTask(ctx context.Context, _ *mcp.CallToolRequest, in ResolveTaskInput) (*mcp.CallToolResult, ResolveTaskOutput, error) {
	state, ok := resolveTaskStates[in.State]
	if !ok {
		return nil, ResolveTaskOutput{}, fmt.Errorf("invalid state %q: must be one of done, archived, dismissed", in.State)
	}

	id, err := uuid.Parse(in.ID)
	if err != nil {
		return nil, ResolveTaskOutput{}, fmt.Errorf("invalid id %q: %w", in.ID, err)
	}

	caller := s.callerIdentity(ctx)

	// A recurring todo's "done" completes today's occurrence and keeps the todo
	// recurring — not a terminal close. archived/dismissed fall through and DO
	// end the recurrence.
	if state == todo.StateDone {
		if handled, out, err := s.resolveRecurringDone(ctx, id, caller); handled || err != nil {
			return nil, out, err
		}
	}

	res, err := s.todos.ResolveByCreator(ctx, id, caller, state)
	if err != nil {
		if errors.Is(err, todo.ErrNotFound) {
			return nil, ResolveTaskOutput{}, fmt.Errorf("no todo %s created by %q: it does not exist or you did not create it", id, caller)
		}
		return nil, ResolveTaskOutput{}, fmt.Errorf("resolving task %s to %s: %w", id, state, err)
	}

	return nil, ResolveTaskOutput{ID: res.ID.String(), State: string(res.State), OK: true}, nil
}

// resolveRecurringDone completes today's occurrence of a recurring, caller-owned
// todo. handled=false means the todo is not recurring (or does not exist), and
// the caller should fall through to the normal terminal resolve. ItemByID is the
// recurrence probe; CompleteOccurrence enforces the caller-scope, so a recurring
// todo owned by another agent reports not-found.
func (s *Server) resolveRecurringDone(ctx context.Context, id uuid.UUID, caller string) (bool, ResolveTaskOutput, error) {
	item, err := s.todos.ItemByID(ctx, id)
	if err != nil || !item.IsRecurring() {
		return false, ResolveTaskOutput{}, nil
	}
	if err := s.todos.CompleteOccurrence(ctx, id, caller, s.today()); err != nil {
		if errors.Is(err, todo.ErrNotFound) {
			return true, ResolveTaskOutput{}, fmt.Errorf("no todo %s created by %q: it does not exist or you did not create it", id, caller)
		}
		return true, ResolveTaskOutput{}, fmt.Errorf("completing recurring occurrence %s: %w", id, err)
	}
	return true, ResolveTaskOutput{ID: id.String(), State: string(todo.StateDone), OK: true}, nil
}
