// Copyright 2026 Koopa. All rights reserved.

// todos.go holds list_todos, the read half of the proposal-readback loop.
// An agent pushes a raw todo into the inbox with capture_inbox (created_by =
// itself); the owner triages it in admin; list_todos lets that same agent
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
	"time"

	"github.com/Koopa0/koopa/internal/todo"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListTodosInput is the input for the list_todos tool. It carries only the
// caller self-identification — there are no filters. The readback is
// caller-scoped to the resolved identity, never a free-form filter over
// another agent's todos.
type ListTodosInput struct {
	As string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent whose created todos to read back. The list is scoped to this resolved identity; it is never a free-form filter over other agents' or the owner's todos."`
}

// TodoListItem is one row of list_todos: a todo the calling agent created,
// with its current state so the agent can read the disposition. created_by
// echoes the resolved caller identity to make the caller-scoped contract
// explicit on the wire.
type TodoListItem struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	State     string `json:"state"`
	CreatedBy string `json:"created_by"`
}

// ListTodosOutput is the output of the list_todos tool.
type ListTodosOutput struct {
	Todos []TodoListItem `json:"todos"`
}

func (s *Server) listTodos(ctx context.Context, _ *mcp.CallToolRequest, _ ListTodosInput) (*mcp.CallToolResult, ListTodosOutput, error) {
	caller := s.callerIdentity(ctx)
	rows, err := s.todos.TodosByCreator(ctx, caller)
	if err != nil {
		return nil, ListTodosOutput{}, fmt.Errorf("listing todos created by %q: %w", caller, err)
	}

	todos := make([]TodoListItem, len(rows))
	for i := range rows {
		todos[i] = TodoListItem{
			ID:        rows[i].ID.String(),
			Title:     rows[i].Title,
			State:     string(rows[i].State),
			CreatedBy: caller,
		}
	}
	return nil, ListTodosOutput{Todos: todos}, nil
}

// resolveTodoStates is the closed set of terminal states resolve_todo accepts.
// Only an agent's own created todos can be moved here; the values mirror the
// todo_state enum's terminal members (done plus the two agent self-close
// states added for this loop).
var resolveTodoStates = map[string]todo.State{
	"done":      todo.StateDone,
	"archived":  todo.StateArchived,
	"dismissed": todo.StateDismissed,
}

// ResolveTodoInput is the input for resolve_todo: the id of a todo the caller
// created and the terminal state to move it to. Like list_todos there is no
// created_by parameter — the write is scoped to the resolved caller identity,
// so an agent can only resolve its own todos, never the owner's or another
// agent's.
type ResolveTodoInput struct {
	ID    string `json:"id" jsonschema:"required" jsonschema_description:"UUID of a todo YOU created (created_by = your resolved identity). Resolving a todo created by anyone else returns not-found and changes nothing."`
	State string `json:"state" jsonschema:"required" jsonschema_description:"Terminal state to set: 'done' (completed), 'archived' (filed away), or 'dismissed' (won't do)."`
	As    string `json:"as,omitempty" jsonschema_description:"Self-identification — the agent making the call. The resolve is scoped to this resolved identity; it can only close todos you created."`
}

// ResolveTodoOutput echoes the resolved id + state and an ok flag, closing the
// write half of the capture/readback loop.
type ResolveTodoOutput struct {
	ID    string `json:"id"`
	State string `json:"state"`
	OK    bool   `json:"ok"`
}

func (s *Server) resolveTodo(ctx context.Context, _ *mcp.CallToolRequest, in ResolveTodoInput) (*mcp.CallToolResult, ResolveTodoOutput, error) {
	state, ok := resolveTodoStates[in.State]
	if !ok {
		return nil, ResolveTodoOutput{}, fmt.Errorf("invalid state %q: must be one of done, archived, dismissed", in.State)
	}

	id, err := uuid.Parse(in.ID)
	if err != nil {
		return nil, ResolveTodoOutput{}, fmt.Errorf("invalid id %q: %w", in.ID, err)
	}

	caller := s.callerIdentity(ctx)

	// The resolve runs inside withActorTx so the 'completed'/'state_changed'
	// audit event is attributed to the caller (not the trigger's fallback).
	var out ResolveTodoOutput
	err = s.withActorTx(ctx, func(tx pgx.Tx) error {
		store := s.todos.WithTx(tx)

		// A recurring todo's "done" completes today's occurrence and keeps it
		// recurring — not a terminal close; archived/dismissed fall through.
		if state == todo.StateDone {
			done, o, err := completeRecurringOccurrence(ctx, store, id, caller, s.today())
			if err != nil {
				return err
			}
			if done {
				out = o
				return nil
			}
		}

		res, err := store.ResolveByCreator(ctx, id, caller, state)
		if err != nil {
			if errors.Is(err, todo.ErrNotFound) {
				return errNoSuchTodo(id, caller)
			}
			return fmt.Errorf("resolving todo %s to %s: %w", id, state, err)
		}
		out = ResolveTodoOutput{ID: res.ID.String(), State: string(res.State), OK: true}
		return nil
	})
	if err != nil {
		return nil, ResolveTodoOutput{}, err
	}
	return nil, out, nil
}

// completeRecurringOccurrence completes today's occurrence of a recurring,
// caller-owned todo. done=false means the todo is not recurring (or not found),
// so the caller should fall through to a terminal resolve. CompleteOccurrence
// enforces caller-scope, so a recurring todo owned by another agent is not-found.
func completeRecurringOccurrence(ctx context.Context, store *todo.Store, id uuid.UUID, caller string, today time.Time) (bool, ResolveTodoOutput, error) {
	item, err := store.ItemByID(ctx, id)
	if err != nil || !item.IsRecurring() {
		return false, ResolveTodoOutput{}, nil
	}
	if err := store.CompleteOccurrence(ctx, id, caller, today); err != nil {
		if errors.Is(err, todo.ErrNotFound) {
			return true, ResolveTodoOutput{}, errNoSuchTodo(id, caller)
		}
		return true, ResolveTodoOutput{}, fmt.Errorf("completing recurring occurrence %s: %w", id, err)
	}
	return true, ResolveTodoOutput{ID: id.String(), State: string(todo.StateDone), OK: true}, nil
}

// errNoSuchTodo is the caller-scoped not-found message shared by resolve_todo's
// terminal and recurring paths — a todo the caller did not create reads identical
// to one that does not exist.
func errNoSuchTodo(id uuid.UUID, caller string) error {
	return fmt.Errorf("no todo %s created by %q: it does not exist or you did not create it", id, caller)
}
