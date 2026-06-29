// Copyright 2026 Koopa. All rights reserved.

// Package todo provides personal GTD work-item tracking.
//
// "todo" is the system's sole work-item entity. Koopa is the only router and
// there is no agent-to-agent task coordination, so no separate "task" entity
// exists — the MCP surface (list_todos / resolve_todo / capture_inbox) and the
// admin UI both speak "todo".
package todo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

func escapeILIKE(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// Store handles database operations for todo items.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// CreateParams holds the parameters for creating a new todo item.
type CreateParams struct {
	Title       string
	Description string
	ProjectID   *uuid.UUID
	Due         *time.Time
	Energy      *string
	Priority    *string
	CreatedBy   string
}

// mapWriteError classifies a PostgreSQL todo-write failure into a store
// sentinel. A foreign-key violation (23503) on the client-supplied project_id
// becomes ErrInvalidInput (a bad input → 400). The created_by FK (server-set
// actor) is deliberately NOT mapped: an unregistered actor is a server/config
// condition, not bad client input, so it falls through to a wrapped 500. Any
// other error is wrapped with the supplied context.
func mapWriteError(err error, operation string) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
		pgErr.Code == pgerrcode.ForeignKeyViolation &&
		pgErr.ConstraintName == "todos_project_id_fkey" {
		return ErrInvalidInput
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// Create inserts a new todo item in inbox state.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Item, error) {
	r, err := s.q.CreateTodoItem(ctx, db.CreateTodoItemParams{
		Title:       p.Title,
		State:       db.TodoStateInbox,
		Due:         p.Due,
		ProjectID:   p.ProjectID,
		Energy:      p.Energy,
		Priority:    p.Priority,
		Description: p.Description,
		CreatedBy:   p.CreatedBy,
	})
	if err != nil {
		return nil, mapWriteError(err, "creating todo item")
	}
	t := rowToItem(&r)
	return &t, nil
}

// Items returns all todo items.
func (s *Store) Items(ctx context.Context) ([]Item, error) {
	rows, err := s.q.TodoItems(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing todo items: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
}

// ItemByID returns a single todo item by its ID.
func (s *Store) ItemByID(ctx context.Context, id uuid.UUID) (*Item, error) {
	r, err := s.q.TodoItemByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying todo item %s: %w", id, err)
	}
	t := rowToItem(&r)
	return &t, nil
}

// TodosByCreator returns the todos created by createdBy, newest first. It
// backs the list_todos MCP readback loop: an agent reads the disposition
// (state) of the todos it created. createdBy is the resolved caller
// identity — caller-scoped, never a client-supplied filter — so the result
// is exactly the caller's own todos. Backed by idx_todos_created_by.
func (s *Store) TodosByCreator(ctx context.Context, createdBy string) ([]CreatorItem, error) {
	rows, err := s.q.TodosByCreator(ctx, createdBy)
	if err != nil {
		return nil, fmt.Errorf("listing todos created by %q: %w", createdBy, err)
	}
	items := make([]CreatorItem, len(rows))
	for i := range rows {
		items[i] = CreatorItem{
			ID:    rows[i].ID,
			Title: rows[i].Title,
			State: State(rows[i].State),
		}
	}
	return items, nil
}

// ResolveByCreator moves a todo the caller created to a terminal state
// (done / archived / dismissed) for the resolve_todo readback loop. createdBy
// is the resolved caller identity — caller-scoped, never a client-supplied
// filter — so a todo owned by a different creator (or a non-existent id)
// matches 0 rows and returns ErrNotFound, never a cross-creator mutation.
// completed_at is reconciled in SQL to satisfy chk_todo_completed_at_consistency
// (now() for done, cleared otherwise). Backed by idx_todos_created_by.
func (s *Store) ResolveByCreator(ctx context.Context, id uuid.UUID, createdBy string, state State) (*Resolution, error) {
	row, err := s.q.ResolveTodoByCreator(ctx, db.ResolveTodoByCreatorParams{
		ID:        id,
		CreatedBy: createdBy,
		State:     db.TodoState(state),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resolving todo %s created by %q to %s: %w", id, createdBy, state, err)
	}
	return &Resolution{ID: row.ID, State: State(row.State)}, nil
}

// UpdateState updates a todo item's state.
func (s *Store) UpdateState(ctx context.Context, id uuid.UUID, state State) (*Item, error) {
	r, err := s.q.UpdateTodoItemState(ctx, db.UpdateTodoItemStateParams{
		ID:    id,
		State: db.TodoState(state),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating todo item %s state to %s: %w", id, state, err)
	}
	t := rowToItem(&r)
	return &t, nil
}

// UpdateParams holds optional fields for updating a todo item.
type UpdateParams struct {
	ID          uuid.UUID
	Title       *string
	Due         *time.Time
	Energy      *string
	Priority    *string
	ProjectID   *uuid.UUID
	Description *string
}

// Update updates arbitrary todo item fields.
func (s *Store) Update(ctx context.Context, p *UpdateParams) (*Item, error) {
	params := db.UpdateTodoItemParams{ID: p.ID}
	params.NewTitle = p.Title
	params.Due = p.Due
	params.Energy = p.Energy
	params.Priority = p.Priority
	params.NewProjectID = p.ProjectID
	params.NewDescription = p.Description
	r, err := s.q.UpdateTodoItem(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, mapWriteError(err, fmt.Sprintf("updating todo item %s", p.ID))
	}
	t := rowToItem(&r)
	return &t, nil
}

// ClarifyParams holds fields for promoting inbox → todo.
type ClarifyParams struct {
	Priority *string
	Energy   *string
	Due      *time.Time
}

// Clarify promotes an inbox todo item to todo state with optional fields.
func (s *Store) Clarify(ctx context.Context, id uuid.UUID, p *ClarifyParams) (*Item, error) {
	row, err := s.q.ClarifyTodoItem(ctx, db.ClarifyTodoItemParams{
		ID:       id,
		Priority: p.Priority,
		Energy:   p.Energy,
		Due:      p.Due,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("clarifying todo item %s: %w", id, err)
	}
	t := rowToItem(&row)
	return &t, nil
}

// Activate promotes a someday todo item back to todo state. Returns
// ErrNotFound when the row does not exist or is not in someday state
// (the SQL guard mirrors Clarify's inbox guard).
func (s *Store) Activate(ctx context.Context, id uuid.UUID) (*Item, error) {
	row, err := s.q.ActivateTodoItem(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("activating todo item %s: %w", id, err)
	}
	t := rowToItem(&row)
	return &t, nil
}

// Start sets a todo item's state to in_progress.
func (s *Store) Start(ctx context.Context, id uuid.UUID) error {
	_, err := s.UpdateState(ctx, id, StateInProgress)
	return err
}

// Complete sets a todo item's state to done and returns the updated item.
func (s *Store) Complete(ctx context.Context, id uuid.UUID) (*Item, error) {
	return s.UpdateState(ctx, id, StateDone)
}

// Defer sets a todo item's state to someday.
func (s *Store) Defer(ctx context.Context, id uuid.UUID) error {
	_, err := s.UpdateState(ctx, id, StateSomeday)
	return err
}

// Delete hard-deletes an inbox todo item. Returns ErrNotFound if not found or not in inbox.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.DeleteTodoItem(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting todo item %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func rowToItem(r *db.Todo) Item {
	return Item{
		ID:              r.ID,
		Title:           r.Title,
		State:           State(r.State),
		Due:             r.Due,
		ProjectID:       r.ProjectID,
		CompletedAt:     r.CompletedAt,
		Energy:          r.Energy,
		Priority:        r.Priority,
		RecurInterval:   r.RecurInterval,
		RecurUnit:       r.RecurUnit,
		RecurWeekdays:   r.RecurWeekdays,
		LastCompletedOn: r.LastCompletedOn,
		Description:     r.Description,
		CreatedBy:       r.CreatedBy,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

// ErrNotFound indicates the todo item does not exist.
var ErrNotFound = errors.New("todo: not found")

// ErrInvalidInput signals a client-supplied value the database rejected:
// a project_id foreign key pointing at a non-existent project.
var ErrInvalidInput = errors.New("todo: invalid input")

// State represents a todo item's GTD lifecycle state. Mirrors the todo_state
// SQL enum. Uses underscores (in_progress) to match Go naming conventions.
//
// archived and dismissed are terminal self-close states an agent sets via the
// resolve_todo MCP readback loop on a todo it created — distinct from done
// (completed) in intent: archived = filed away, dismissed = won't do. Like
// every non-done state they carry no completed_at (chk_todo_completed_at_consistency).
type State string

const (
	StateInbox      State = "inbox"
	StateTodo       State = "todo"
	StateInProgress State = "in_progress"
	StateDone       State = "done"
	StateSomeday    State = "someday"
	StateArchived   State = "archived"
	StateDismissed  State = "dismissed"
)

// Item represents a personal GTD work item.
//
// Unqualified "Item" reads cleanly at the call site (todo.Item) and avoids
// the pkg.PkgSomething stutter that naming.md forbids.
type Item struct {
	ID              uuid.UUID  `json:"id"`
	Title           string     `json:"title"`
	State           State      `json:"state"`
	Due             *time.Time `json:"due,omitempty"`
	ProjectID       *uuid.UUID `json:"project_id,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	Energy          *string    `json:"energy,omitempty"`
	Priority        *string    `json:"priority,omitempty"`
	RecurInterval   *int32     `json:"recur_interval,omitempty"`
	RecurUnit       *string    `json:"recur_unit,omitempty"`
	RecurWeekdays   *int16     `json:"recur_weekdays,omitempty"`
	LastCompletedOn *time.Time `json:"last_completed_on,omitempty"`
	Description     string     `json:"description,omitempty"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// IsRecurring reports whether the item has a recurrence schedule — either
// weekday-mode (recur_weekdays) or interval-mode (recur_interval). The
// RecurringItemsDueToday read query computes due-today from the same two modes
// in SQL; this in-memory predicate is the Go-side equivalent for callers
// holding an Item.
func (t *Item) IsRecurring() bool {
	return t.RecurWeekdays != nil || (t.RecurInterval != nil && *t.RecurInterval > 0)
}

// CreatorItem is a slim todo projection for the list_todos readback loop —
// just enough for an agent to learn the disposition (state) of a todo it
// created. The heavyweight fields (due / energy / project / recurrence) the
// readback does not need are omitted; created_by is implied by the query
// filter and supplied by the caller, so it is not re-selected here.
type CreatorItem struct {
	ID    uuid.UUID
	Title string
	State State
}

// Resolution is the slim result of ResolveByCreator — the resolved todo's id
// and the terminal state now stored, enough for the resolve_todo readback ack.
type Resolution struct {
	ID    uuid.UUID
	State State
}

// PendingDetail is a pending todo with project context.
//
// CreatedBy and Description are populated by BacklogItems only (the admin
// list view projects them onto the wire); the morning-context date views
// leave them empty and omit them from JSON.
type PendingDetail struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	State         State      `json:"state"`
	Due           *time.Time `json:"due,omitempty"`
	ProjectTitle  string     `json:"project_title"`
	ProjectSlug   string     `json:"project_slug"`
	Energy        *string    `json:"energy,omitempty"`
	Priority      *string    `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     *string    `json:"recur_unit,omitempty"`
	// RecurWeekdays is the weekday-mode recurrence mask. Carried so the backlog
	// wire lets the GTD page recognise weekday-mode routines as recurring — a
	// todo is recurring when EITHER RecurInterval or RecurWeekdays is set, and
	// without this the page treated only interval-mode as recurring (weekday
	// routines then leaked into Pending with no recurrence badge).
	RecurWeekdays *int16    `json:"recur_weekdays,omitempty"`
	Description   string    `json:"description,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// SearchDetail is a search hit with project context.
type SearchDetail struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	State         State      `json:"state"`
	Due           *time.Time `json:"due,omitempty"`
	ProjectTitle  string     `json:"project_title"`
	ProjectSlug   string     `json:"project_slug"`
	Energy        *string    `json:"energy,omitempty"`
	Priority      *string    `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     *string    `json:"recur_unit,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Description   string     `json:"description,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// CompletedDetail is a recently completed todo with project context.
type CompletedDetail struct {
	ID           uuid.UUID  `json:"id"`
	Title        string     `json:"title"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	ProjectTitle string     `json:"project_title"`
}

// CreatedDetail is a recently created todo with project context.
type CreatedDetail struct {
	ID           uuid.UUID `json:"id"`
	Title        string    `json:"title"`
	CreatedAt    time.Time `json:"created_at"`
	ProjectTitle string    `json:"project_title"`
}
