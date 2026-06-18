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
	"fmt"

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
	if err := s.requireRegisteredCaller(ctx, "list_tasks"); err != nil {
		return nil, ListTasksOutput{}, err
	}

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
