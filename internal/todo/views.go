// views.go owns the filtered-list read queries consumed by the MCP
// morning_context / reflection_context aggregators and the daily-plan
// UI: overdue, due-today, due-range, pending-with-project, inbox, stale
// someday, backlog, and per-project groupings. Pure reads, no writes.

package todo

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/db"
)

// OverdueItems returns todo items past due that are not done.
func (s *Store) OverdueItems(ctx context.Context, today time.Time) ([]PendingDetail, error) {
	rows, err := s.q.OverdueTodoItems(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing overdue todo items: %w", err)
	}
	items := make([]PendingDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = PendingDetail{
			ID: r.ID, Title: r.Title, State: State(r.State), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return items, nil
}

// ItemsDueOn returns todo items due on a specific date.
func (s *Store) ItemsDueOn(ctx context.Context, date time.Time) ([]PendingDetail, error) {
	rows, err := s.q.TodoItemsDueOn(ctx, &date)
	if err != nil {
		return nil, fmt.Errorf("listing todo items due on %s: %w", date.Format(time.DateOnly), err)
	}
	items := make([]PendingDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = PendingDetail{
			ID: r.ID, Title: r.Title, State: State(r.State), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return items, nil
}

// ItemsDueInRange returns todo items due in a date range.
func (s *Store) ItemsDueInRange(ctx context.Context, start, end time.Time) ([]PendingDetail, error) {
	rows, err := s.q.TodoItemsDueInRange(ctx, db.TodoItemsDueInRangeParams{
		StartDate: &start,
		EndDate:   &end,
	})
	if err != nil {
		return nil, fmt.Errorf("listing todo items due in range: %w", err)
	}
	items := make([]PendingDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = PendingDetail{
			ID: r.ID, Title: r.Title, State: State(r.State), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return items, nil
}

// PendingItems returns todo items that are not done (lightweight).
func (s *Store) PendingItems(ctx context.Context) ([]Pending, error) {
	rows, err := s.q.PendingTodoItems(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pending todo items: %w", err)
	}
	items := make([]Pending, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		var due string
		if r.Due != nil {
			due = r.Due.Format(time.DateOnly)
		}
		items = append(items, Pending{Title: r.Title, Due: due})
	}
	return items, nil
}

// PendingItemsWithProject returns pending todo items with project context.
func (s *Store) PendingItemsWithProject(ctx context.Context, projectSlug *string, maxResults int32) ([]PendingDetail, error) {
	rows, err := s.q.PendingTodoItemsWithProject(ctx, db.PendingTodoItemsWithProjectParams{
		ProjectSlug: projectSlug,
		MaxResults:  maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pending todo items with project: %w", err)
	}
	items := make([]PendingDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = PendingDetail{
			ID:            r.ID,
			Title:         r.Title,
			State:         State(r.State),
			Due:           r.Due,
			ProjectTitle:  r.ProjectTitle,
			ProjectSlug:   r.ProjectSlug,
			Energy:        r.Energy,
			Priority:      r.Priority,
			RecurInterval: r.RecurInterval,
			RecurUnit:     r.RecurUnit,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
		}
	}
	return items, nil
}

// InboxCount returns the number of todo items in the inbox state.
func (s *Store) InboxCount(ctx context.Context) (int, error) {
	n, err := s.q.TodoInboxCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("counting inbox todo items: %w", err)
	}
	return int(n), nil
}

// StaleSomedayCount returns the number of someday todo items not updated in staleDays.
func (s *Store) StaleSomedayCount(ctx context.Context, staleDays int) (int, error) {
	before := time.Now().AddDate(0, 0, -staleDays)
	n, err := s.q.StaleSomedayTodoCount(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("counting stale someday todo items: %w", err)
	}
	return int(n), nil
}

// InboxItems returns all todo items in the inbox state, newest first.
func (s *Store) InboxItems(ctx context.Context) ([]Item, error) {
	rows, err := s.q.InboxTodoItems(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing inbox todo items: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
}

// BacklogItems returns a filtered list for the admin backlog view.
func (s *Store) BacklogItems(ctx context.Context, state, projectID, energy, priority, search string, limit int) ([]PendingDetail, error) {
	var projID *uuid.UUID
	if projectID != "" {
		id, err := uuid.Parse(projectID)
		if err == nil {
			projID = &id
		}
	}
	var energyPtr, priorityPtr, searchPtr *string
	if energy != "" {
		energyPtr = &energy
	}
	if priority != "" {
		priorityPtr = &priority
	}
	if search != "" {
		escaped := escapeILIKE(search)
		searchPtr = &escaped
	}

	rows, err := s.q.BacklogTodoItems(ctx, db.BacklogTodoItemsParams{
		State:      db.TodoState(state),
		ProjectID:  projID,
		Energy:     energyPtr,
		Priority:   priorityPtr,
		Search:     searchPtr,
		MaxResults: int32(limit), // #nosec G115 -- bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("listing backlog todo items: %w", err)
	}
	items := make([]PendingDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = PendingDetail{
			ID: r.ID, Title: r.Title, State: State(r.State), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return items, nil
}

// GroupedItems holds todo items grouped by state for admin project detail.
// Shape matches the frontend TodosByState contract — the four active states
// that render in the inspector. Items in states not listed here (inbox,
// archived) are silently dropped because they do not belong in a project's
// task breakdown: inbox is pre-project triage, archived is historical.
type GroupedItems struct {
	InProgress []Brief `json:"in_progress"`
	Todo       []Brief `json:"todo"`
	Done       []Brief `json:"done"`
	Someday    []Brief `json:"someday"`
}

// Brief is a lightweight todo item for grouped views.
type Brief struct {
	ID       uuid.UUID  `json:"id"`
	Title    string     `json:"title"`
	State    State      `json:"state"`
	Due      *time.Time `json:"due,omitempty"`
	Energy   *string    `json:"energy,omitempty"`
	Priority *string    `json:"priority,omitempty"`
}

// ItemsByProjectGrouped returns todo items for a project grouped by state.
func (s *Store) ItemsByProjectGrouped(ctx context.Context, projectID uuid.UUID) (*GroupedItems, error) {
	rows, err := s.q.TodoItemsByProjectGrouped(ctx, &projectID)
	if err != nil {
		return nil, fmt.Errorf("listing todo items for project %s: %w", projectID, err)
	}
	result := &GroupedItems{
		InProgress: []Brief{},
		Todo:       []Brief{},
		Done:       []Brief{},
		Someday:    []Brief{},
	}
	for i := range rows {
		r := &rows[i]
		b := Brief{
			ID:       r.ID,
			Title:    r.Title,
			State:    State(r.State),
			Due:      r.Due,
			Energy:   r.Energy,
			Priority: r.Priority,
		}
		switch State(r.State) {
		case StateInProgress:
			result.InProgress = append(result.InProgress, b)
		case StateTodo:
			result.Todo = append(result.Todo, b)
		case StateDone:
			result.Done = append(result.Done, b)
		case StateSomeday:
			result.Someday = append(result.Someday, b)
		case StateInbox:
			// Inbox items are pre-project triage and never belong to a
			// project's task breakdown. Intentionally dropped — see the
			// doc comment on GroupedItems.
		}
	}
	return result, nil
}
