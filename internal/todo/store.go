package todo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
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

// SetRecurringDoneHandler registers the callback for recurring todo completion.
func (s *Store) SetRecurringDoneHandler(h RecurringDoneHandler) {
	s.recurringDoneHandler = h
}

// CreateParams holds the parameters for creating a new todo item.
type CreateParams struct {
	Title       string
	Description string
	ProjectID   *uuid.UUID
	Due         *time.Time
	Energy      *string
	Priority    *string
	Assignee    string
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
		Assignee:    p.Assignee,
		CreatedBy:   p.CreatedBy,
	})
	if err != nil {
		return nil, fmt.Errorf("creating todo item: %w", err)
	}
	t := rowToItem(&r)
	return &t, nil
}

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
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
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
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
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
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return items, nil
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

// PendingItemsWithProject returns pending todo items with project context.
func (s *Store) PendingItemsWithProject(ctx context.Context, projectSlug, assignee *string, maxResults int32) ([]PendingDetail, error) {
	rows, err := s.q.PendingTodoItemsWithProject(ctx, db.PendingTodoItemsWithProjectParams{
		ProjectSlug: projectSlug,
		Assignee:    assignee,
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
			Assignee:      r.Assignee,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
		}
	}
	return items, nil
}

// SearchItems searches todo items with optional filters.
func (s *Store) SearchItems(ctx context.Context, query, projectSlug, stateFilter, assignee *string, completedAfter, completedBefore *time.Time, maxResults int32) ([]SearchDetail, error) {
	var escapedQuery *string
	if query != nil {
		v := escapeILIKE(*query)
		escapedQuery = &v
	}
	rows, err := s.q.SearchTodoItems(ctx, db.SearchTodoItemsParams{
		Query:           escapedQuery,
		ProjectSlug:     projectSlug,
		StateFilter:     stateFilter,
		Assignee:        assignee,
		CompletedAfter:  completedAfter,
		CompletedBefore: completedBefore,
		MaxResults:      maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("searching todo items: %w", err)
	}
	items := make([]SearchDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = SearchDetail{
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
			Assignee:      r.Assignee,
			CompletedAt:   r.CompletedAt,
			Description:   r.Description,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
		}
	}
	return items, nil
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
	Assignee    *string
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
	params.Assignee = p.Assignee
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

// CompletedItemsDetailSince returns todo items completed since the given time.
func (s *Store) CompletedItemsDetailSince(ctx context.Context, since time.Time) ([]CompletedDetail, error) {
	rows, err := s.q.CompletedTodoDetailSince(ctx, &since)
	if err != nil {
		return nil, fmt.Errorf("listing completed todo items since %s: %w", since.Format(time.DateOnly), err)
	}
	result := make([]CompletedDetail, len(rows))
	for i, r := range rows {
		result[i] = CompletedDetail{
			ID:           r.ID,
			Title:        r.Title,
			CompletedAt:  r.CompletedAt,
			ProjectTitle: r.ProjectTitle,
		}
	}
	return result, nil
}

// ItemsCreatedSince returns todo items created since the given time.
func (s *Store) ItemsCreatedSince(ctx context.Context, since time.Time) ([]CreatedDetail, error) {
	rows, err := s.q.TodoItemsCreatedSince(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("listing todo items created since %s: %w", since.Format(time.DateOnly), err)
	}
	result := make([]CreatedDetail, len(rows))
	for i, r := range rows {
		result[i] = CreatedDetail{
			ID:           r.ID,
			Title:        r.Title,
			CreatedAt:    r.CreatedAt,
			ProjectTitle: r.ProjectTitle,
		}
	}
	return result, nil
}

// OverdueRecurringItems returns recurring todo items with due < today.
func (s *Store) OverdueRecurringItems(ctx context.Context, today time.Time) ([]Item, error) {
	rows, err := s.q.OverdueRecurringTodoItems(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing overdue recurring todo items: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
}

// RecurringItemsDueToday returns recurring todo items due today.
func (s *Store) RecurringItemsDueToday(ctx context.Context, today time.Time) ([]Item, error) {
	rows, err := s.q.RecurringTodoItemsDueToday(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing recurring todo items due today: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		items[i] = rowToItem(&rows[i])
	}
	return items, nil
}

// UpdateDue updates only the due date.
func (s *Store) UpdateDue(ctx context.Context, id uuid.UUID, due time.Time) error {
	n, err := s.q.UpdateTodoItemDue(ctx, db.UpdateTodoItemDueParams{ID: id, Due: &due})
	if err != nil {
		return fmt.Errorf("updating todo item %s due: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ResetRecurring advances a recurring todo item's due date and resets state to todo.
func (s *Store) ResetRecurring(ctx context.Context, id uuid.UUID, nextDue time.Time) (*Item, error) {
	r, err := s.q.ResetRecurringTodoItem(ctx, db.ResetRecurringTodoItemParams{ID: id, Due: &nextDue})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resetting recurring todo item %s: %w", id, err)
	}
	t := rowToItem(&r)
	return &t, nil
}

// LogSkip inserts a skip record.
func (s *Store) LogSkip(ctx context.Context, itemID uuid.UUID, originalDue, skippedDate time.Time, reason string) error {
	return s.q.CreateTodoSkipRecord(ctx, db.CreateTodoSkipRecordParams{
		TodoID:      itemID,
		OriginalDue: originalDue,
		SkippedDate: skippedDate,
		Reason:      reason,
	})
}

// RecurringItemByProject finds a recurring pending todo item under a project due today or overdue.
func (s *Store) RecurringItemByProject(ctx context.Context, projectID uuid.UUID, today time.Time) (*Item, error) {
	r, err := s.q.RecurringTodoItemByProject(ctx, db.RecurringTodoItemByProjectParams{
		ProjectID: &projectID,
		Today:     &today,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying recurring todo item for project %s: %w", projectID, err)
	}
	t := rowToItem(&r)
	return &t, nil
}

func rowToItem(r *db.Todo) Item {
	return Item{
		ID:               r.ID,
		Title:            r.Title,
		State:            State(r.State),
		Due:              r.Due,
		ProjectID:        r.ProjectID,
		ExternalProvider: r.ExternalProvider,
		ExternalRef:      r.ExternalRef,
		CompletedAt:      r.CompletedAt,
		Energy:           r.Energy,
		Priority:         r.Priority,
		RecurInterval:    r.RecurInterval,
		RecurUnit:        r.RecurUnit,
		Description:      r.Description,
		Assignee:         r.Assignee,
		CreatedBy:        r.CreatedBy,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
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
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return items, nil
}

// GroupedItems holds todo items grouped by state for admin project detail.
type GroupedItems struct {
	InProgress []Brief `json:"in_progress"`
	Todo       []Brief `json:"todo"`
	Done       []Brief `json:"done"`
	Other      []Brief `json:"other"`
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
		Other:      []Brief{},
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
		default:
			result.Other = append(result.Other, b)
		}
	}
	return result, nil
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
