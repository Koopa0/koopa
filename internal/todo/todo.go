// Package todo provides personal GTD work-item tracking.
//
// Named todo (not task) to free the bare word "task" for the inter-agent
// coordination entity — the tasks table in schema and the
// internal/agent/task package. Vocabulary discipline: task =
// agent-to-agent work unit, todo = personal GTD item. This matches the
// schema-level split between the todos and tasks tables.
package todo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
	q                    *db.Queries
	recurringDoneHandler RecurringDoneHandler
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
//
// recurringDoneHandler is propagated so the tx-bound store retains its
// async-completion side channel for recurring todo lifecycle events.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{
		q:                    s.q.WithTx(tx),
		recurringDoneHandler: s.recurringDoneHandler,
	}
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
		return nil, fmt.Errorf("creating todo item: %w", err)
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

// PendingItemsByTitle finds pending todo items matching a title (case-insensitive).
func (s *Store) PendingItemsByTitle(ctx context.Context, title string) ([]Item, error) {
	escaped := escapeILIKE(title)
	rows, err := s.q.PendingTodoItemsByTitle(ctx, &escaped)
	if err != nil {
		return nil, fmt.Errorf("searching pending todo items by title %q: %w", title, err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
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
	State       *State
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
	if p.State != nil {
		params.State = db.NullTodoState{
			TodoState: db.TodoState(*p.State),
			Valid:     true,
		}
	}
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
		return nil, fmt.Errorf("updating todo item %s: %w", p.ID, err)
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

// Start sets a todo item's state to in_progress.
func (s *Store) Start(ctx context.Context, id uuid.UUID) error {
	_, err := s.UpdateState(ctx, id, StateInProgress)
	return err
}

// Complete sets a todo item's state to done.
func (s *Store) Complete(ctx context.Context, id uuid.UUID, _ *time.Time) error {
	_, err := s.UpdateState(ctx, id, StateDone)
	return err
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
		ID:            r.ID,
		Title:         r.Title,
		State:         State(r.State),
		Due:           r.Due,
		ProjectID:     r.ProjectID,
		CompletedAt:   r.CompletedAt,
		Energy:        r.Energy,
		Priority:      r.Priority,
		RecurInterval: r.RecurInterval,
		RecurUnit:     r.RecurUnit,
		Description:   r.Description,
		CreatedBy:     r.CreatedBy,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

// ErrNotFound indicates the todo item does not exist.
var ErrNotFound = errors.New("todo: not found")

// State represents a todo item's GTD lifecycle state. Mirrors the todo_state
// SQL enum. Uses underscores (in_progress) to match Go naming conventions.
type State string

const (
	StateInbox      State = "inbox"
	StateTodo       State = "todo"
	StateInProgress State = "in_progress"
	StateDone       State = "done"
	StateSomeday    State = "someday"
)

// Item represents a personal GTD work item.
//
// Unqualified "Item" reads cleanly at the call site (todo.Item) and avoids
// the pkg.PkgSomething stutter that naming.md forbids.
type Item struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	State         State      `json:"state"`
	Due           *time.Time `json:"due,omitempty"`
	ProjectID     *uuid.UUID `json:"project_id,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	Energy        *string    `json:"energy,omitempty"`
	Priority      *string    `json:"priority,omitempty"`
	RecurInterval *int32     `json:"recur_interval,omitempty"`
	RecurUnit     *string    `json:"recur_unit,omitempty"`
	Description   string     `json:"description,omitempty"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// RecurringDoneHandler is called when a recurring todo item is completed.
type RecurringDoneHandler func(ctx context.Context, t *Item) error

// IsRecurring reports whether the item has a recurrence schedule.
func (t *Item) IsRecurring() bool {
	return t.RecurInterval != nil && *t.RecurInterval > 0
}

// NextDue calculates the next due date based on recurrence settings.
// Returns nil if the item is not recurring or has no due date.
// For months, clamps to the last day of the target month to prevent drift
// (e.g., Jan 31 + 1 month = Feb 28, not Mar 3).
func (t *Item) NextDue() *time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	next := advanceDate(*t.Due, int(*t.RecurInterval), derefStr(t.RecurUnit))
	return &next
}

// NextCycleDateOnOrAfter returns the first recurrence date on or after cutoff.
func (t *Item) NextCycleDateOnOrAfter(cutoff time.Time) *time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	base := *t.Due
	interval := int(*t.RecurInterval)
	unit := derefStr(t.RecurUnit)
	cutoffDate := truncateToDate(cutoff)
	baseDate := truncateToDate(base)

	if !baseDate.Before(cutoffDate) {
		return &baseDate
	}

	switch unit {
	case "days":
		days := daysBetween(baseDate, cutoffDate)
		cycles := (days + interval - 1) / interval
		next := baseDate.AddDate(0, 0, cycles*interval)
		return &next
	case "weeks":
		days := daysBetween(baseDate, cutoffDate)
		stepDays := interval * 7
		cycles := (days + stepDays - 1) / stepDays
		next := baseDate.AddDate(0, 0, cycles*stepDays)
		return &next
	default:
		cur := baseDate
		for cur.Before(cutoffDate) {
			cur = advanceDate(cur, interval, unit)
		}
		return &cur
	}
}

// MissedOccurrences returns all occurrence dates between the current due and cutoff (exclusive).
func (t *Item) MissedOccurrences(cutoff time.Time) []time.Time {
	if !t.IsRecurring() || t.Due == nil {
		return nil
	}
	cutoffDate := truncateToDate(cutoff)
	cur := truncateToDate(*t.Due)
	var missed []time.Time
	for cur.Before(cutoffDate) {
		missed = append(missed, cur)
		cur = advanceDate(cur, int(*t.RecurInterval), derefStr(t.RecurUnit))
	}
	return missed
}

func advanceDate(base time.Time, interval int, unit string) time.Time {
	switch unit {
	case "days":
		return base.AddDate(0, 0, interval)
	case "weeks":
		return base.AddDate(0, 0, interval*7)
	case "months":
		return addMonthsClamped(base, interval)
	case "years":
		return addMonthsClamped(base, interval*12)
	default:
		return base.AddDate(0, 0, interval)
	}
}

func addMonthsClamped(base time.Time, months int) time.Time {
	y, m, d := base.Date()
	targetMonth := time.Month(int(m) + months)
	lastDay := time.Date(y, targetMonth+1, 0, 0, 0, 0, 0, base.Location()).Day()
	if d > lastDay {
		d = lastDay
	}
	return time.Date(y, targetMonth, d, 0, 0, 0, 0, base.Location())
}

func truncateToDate(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func daysBetween(a, b time.Time) int {
	return int(b.Sub(a).Hours() / 24)
}

func derefStr(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}

// Pending is a lightweight projection used by morning_context.
type Pending struct {
	Title string
	Due   string
}

// ProjectCompletion holds a per-project completion count.
type ProjectCompletion struct {
	ProjectTitle string
	Completed    int64
}

// PendingDetail is a pending todo with project context.
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
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
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
