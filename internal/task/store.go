package task

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

// Store handles database operations for tasks.
type Store struct {
	q                    *db.Queries
	recurringDoneHandler RecurringDoneHandler
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// SetRecurringDoneHandler registers the callback for recurring task completion.
func (s *Store) SetRecurringDoneHandler(h RecurringDoneHandler) {
	s.recurringDoneHandler = h
}

// CreateParams holds the parameters for creating a new task.
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

// Create inserts a new task with status=inbox.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Task, error) {
	r, err := s.q.CreateTask(ctx, db.CreateTaskParams{
		Title:       p.Title,
		Status:      db.TaskStatusInbox,
		Due:         p.Due,
		ProjectID:   p.ProjectID,
		Energy:      p.Energy,
		Priority:    p.Priority,
		Description: p.Description,
		Assignee:    p.Assignee,
		CreatedBy:   p.CreatedBy,
	})
	if err != nil {
		return nil, fmt.Errorf("creating task: %w", err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// OverdueTasks returns tasks past due that are not done.
func (s *Store) OverdueTasks(ctx context.Context, today time.Time) ([]PendingTaskDetail, error) {
	rows, err := s.q.OverdueTasks(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing overdue tasks: %w", err)
	}
	tasks := make([]PendingTaskDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		tasks[i] = PendingTaskDetail{
			ID: r.ID, Title: r.Title, Status: Status(r.Status), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return tasks, nil
}

// TasksDueOn returns tasks due on a specific date.
func (s *Store) TasksDueOn(ctx context.Context, date time.Time) ([]PendingTaskDetail, error) {
	rows, err := s.q.TasksDueOn(ctx, &date)
	if err != nil {
		return nil, fmt.Errorf("listing tasks due on %s: %w", date.Format(time.DateOnly), err)
	}
	tasks := make([]PendingTaskDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		tasks[i] = PendingTaskDetail{
			ID: r.ID, Title: r.Title, Status: Status(r.Status), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return tasks, nil
}

// TasksDueInRange returns tasks due in a date range (exclusive start, inclusive end).
func (s *Store) TasksDueInRange(ctx context.Context, start, end time.Time) ([]PendingTaskDetail, error) {
	rows, err := s.q.TasksDueInRange(ctx, db.TasksDueInRangeParams{
		StartDate: &start,
		EndDate:   &end,
	})
	if err != nil {
		return nil, fmt.Errorf("listing tasks due in range: %w", err)
	}
	tasks := make([]PendingTaskDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		tasks[i] = PendingTaskDetail{
			ID: r.ID, Title: r.Title, Status: Status(r.Status), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return tasks, nil
}

// Tasks returns all tasks.
func (s *Store) Tasks(ctx context.Context) ([]Task, error) {
	rows, err := s.q.Tasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tasks: %w", err)
	}
	tasks := make([]Task, len(rows))
	for i := range rows {
		tasks[i] = rowToTask(&rows[i])
	}
	return tasks, nil
}

// PendingTasks returns tasks that are not done (lightweight).
func (s *Store) PendingTasks(ctx context.Context) ([]PendingTask, error) {
	rows, err := s.q.PendingTasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pending tasks: %w", err)
	}
	tasks := make([]PendingTask, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		var due string
		if r.Due != nil {
			due = r.Due.Format(time.DateOnly)
		}
		tasks = append(tasks, PendingTask{Title: r.Title, Due: due})
	}
	return tasks, nil
}

// TaskByID returns a single task by its ID.
func (s *Store) TaskByID(ctx context.Context, id uuid.UUID) (*Task, error) {
	r, err := s.q.TaskByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying task %s: %w", id, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// PendingTasksByTitle finds pending tasks matching a title (case-insensitive).
func (s *Store) PendingTasksByTitle(ctx context.Context, title string) ([]Task, error) {
	escaped := escapeILIKE(title)
	rows, err := s.q.PendingTasksByTitle(ctx, &escaped)
	if err != nil {
		return nil, fmt.Errorf("searching pending tasks by title %q: %w", title, err)
	}
	tasks := make([]Task, len(rows))
	for i := range rows {
		tasks[i] = rowToTask(&rows[i])
	}
	return tasks, nil
}

// UpdateStatus updates a task's status.
func (s *Store) UpdateStatus(ctx context.Context, id uuid.UUID, status Status) (*Task, error) {
	r, err := s.q.UpdateTaskStatus(ctx, db.UpdateTaskStatusParams{
		ID:     id,
		Status: db.TaskStatus(status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating task %s status to %s: %w", id, status, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// PendingTasksWithProject returns pending tasks with project context.
func (s *Store) PendingTasksWithProject(ctx context.Context, projectSlug, assignee *string, maxResults int32) ([]PendingTaskDetail, error) {
	rows, err := s.q.PendingTasksWithProject(ctx, db.PendingTasksWithProjectParams{
		ProjectSlug: projectSlug,
		Assignee:    assignee,
		MaxResults:  maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pending tasks with project: %w", err)
	}
	tasks := make([]PendingTaskDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		tasks[i] = PendingTaskDetail{
			ID:            r.ID,
			Title:         r.Title,
			Status:        Status(r.Status),
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
	return tasks, nil
}

// SearchTasks searches tasks with optional filters.
func (s *Store) SearchTasks(ctx context.Context, query, projectSlug, statusFilter, assignee *string, completedAfter, completedBefore *time.Time, maxResults int32) ([]SearchTaskDetail, error) {
	var escapedQuery *string
	if query != nil {
		v := escapeILIKE(*query)
		escapedQuery = &v
	}
	rows, err := s.q.SearchTasks(ctx, db.SearchTasksParams{
		Query:           escapedQuery,
		ProjectSlug:     projectSlug,
		StatusFilter:    statusFilter,
		Assignee:        assignee,
		CompletedAfter:  completedAfter,
		CompletedBefore: completedBefore,
		MaxResults:      maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("searching tasks: %w", err)
	}
	tasks := make([]SearchTaskDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		tasks[i] = SearchTaskDetail{
			ID:            r.ID,
			Title:         r.Title,
			Status:        Status(r.Status),
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
	return tasks, nil
}

// UpdateParams holds optional fields for updating a task.
type UpdateParams struct {
	ID          uuid.UUID
	Title       *string
	Status      *Status
	Due         *time.Time
	Energy      *string
	Priority    *string
	ProjectID   *uuid.UUID
	Description *string
	Assignee    *string
}

// Update updates arbitrary task fields.
func (s *Store) Update(ctx context.Context, p *UpdateParams) (*Task, error) {
	params := db.UpdateTaskParams{ID: p.ID}
	params.NewTitle = p.Title
	if p.Status != nil {
		params.Status = db.NullTaskStatus{
			TaskStatus: db.TaskStatus(*p.Status),
			Valid:      true,
		}
	}
	params.Due = p.Due
	params.Energy = p.Energy
	params.Priority = p.Priority
	params.NewProjectID = p.ProjectID
	params.NewDescription = p.Description
	params.Assignee = p.Assignee
	r, err := s.q.UpdateTask(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating task %s: %w", p.ID, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// CompletedTasksDetailSince returns tasks completed since the given time.
func (s *Store) CompletedTasksDetailSince(ctx context.Context, since time.Time) ([]CompletedTaskDetail, error) {
	rows, err := s.q.CompletedTasksDetailSince(ctx, &since)
	if err != nil {
		return nil, fmt.Errorf("listing completed tasks since %s: %w", since.Format(time.DateOnly), err)
	}
	result := make([]CompletedTaskDetail, len(rows))
	for i, r := range rows {
		result[i] = CompletedTaskDetail{
			ID:           r.ID,
			Title:        r.Title,
			CompletedAt:  r.CompletedAt,
			ProjectTitle: r.ProjectTitle,
		}
	}
	return result, nil
}

// TasksCreatedSince returns tasks created since the given time.
func (s *Store) TasksCreatedSince(ctx context.Context, since time.Time) ([]CreatedTaskDetail, error) {
	rows, err := s.q.TasksCreatedSince(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("listing tasks created since %s: %w", since.Format(time.DateOnly), err)
	}
	result := make([]CreatedTaskDetail, len(rows))
	for i, r := range rows {
		result[i] = CreatedTaskDetail{
			ID:           r.ID,
			Title:        r.Title,
			CreatedAt:    r.CreatedAt,
			ProjectTitle: r.ProjectTitle,
		}
	}
	return result, nil
}

// OverdueRecurringTasks returns recurring tasks with due < today.
func (s *Store) OverdueRecurringTasks(ctx context.Context, today time.Time) ([]Task, error) {
	rows, err := s.q.OverdueRecurringTasks(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing overdue recurring tasks: %w", err)
	}
	tasks := make([]Task, len(rows))
	for i := range rows {
		tasks[i] = rowToTask(&rows[i])
	}
	return tasks, nil
}

// RecurringTasksDueToday returns recurring tasks due today.
func (s *Store) RecurringTasksDueToday(ctx context.Context, today time.Time) ([]Task, error) {
	rows, err := s.q.RecurringTasksDueToday(ctx, &today)
	if err != nil {
		return nil, fmt.Errorf("listing recurring tasks due today: %w", err)
	}
	tasks := make([]Task, len(rows))
	for i := range rows {
		tasks[i] = rowToTask(&rows[i])
	}
	return tasks, nil
}

// UpdateDue updates only the due date.
func (s *Store) UpdateDue(ctx context.Context, id uuid.UUID, due time.Time) error {
	n, err := s.q.UpdateTaskDue(ctx, db.UpdateTaskDueParams{ID: id, Due: &due})
	if err != nil {
		return fmt.Errorf("updating task %s due: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ResetRecurring advances a recurring task's due date and resets status to todo.
func (s *Store) ResetRecurring(ctx context.Context, id uuid.UUID, nextDue time.Time) (*Task, error) {
	r, err := s.q.ResetRecurringTask(ctx, db.ResetRecurringTaskParams{ID: id, Due: &nextDue})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resetting recurring task %s: %w", id, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// LogSkip inserts a skip record.
func (s *Store) LogSkip(ctx context.Context, taskID uuid.UUID, originalDue, skippedDate time.Time, reason string) error {
	return s.q.CreateSkipRecord(ctx, db.CreateSkipRecordParams{
		TaskID:      taskID,
		OriginalDue: originalDue,
		SkippedDate: skippedDate,
		Reason:      reason,
	})
}

// RecurringTaskByProject finds a recurring pending task under a project due today or overdue.
func (s *Store) RecurringTaskByProject(ctx context.Context, projectID uuid.UUID, today time.Time) (*Task, error) {
	r, err := s.q.RecurringTaskByProject(ctx, db.RecurringTaskByProjectParams{
		ProjectID: &projectID,
		Today:     &today,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying recurring task for project %s: %w", projectID, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

func rowToTask(r *db.Task) Task {
	return Task{
		ID:            r.ID,
		Title:         r.Title,
		Status:        Status(r.Status),
		Due:           r.Due,
		ProjectID:     r.ProjectID,
		NotionPageID:  r.NotionPageID,
		CompletedAt:   r.CompletedAt,
		Energy:        r.Energy,
		Priority:      r.Priority,
		RecurInterval: r.RecurInterval,
		RecurUnit:     r.RecurUnit,
		Description:   r.Description,
		Assignee:      r.Assignee,
		CreatedBy:     r.CreatedBy,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

// InboxCount returns the number of tasks with status=inbox.
func (s *Store) InboxCount(ctx context.Context) (int, error) {
	n, err := s.q.InboxCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("counting inbox tasks: %w", err)
	}
	return int(n), nil
}

// StaleSomedayCount returns the number of someday tasks not updated in staleDays.
func (s *Store) StaleSomedayCount(ctx context.Context, staleDays int) (int, error) {
	before := time.Now().AddDate(0, 0, -staleDays)
	n, err := s.q.StaleSomedayCount(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("counting stale someday tasks: %w", err)
	}
	return int(n), nil
}

// InboxTasks returns all tasks with status=inbox, newest first.
func (s *Store) InboxTasks(ctx context.Context) ([]Task, error) {
	rows, err := s.q.InboxTasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing inbox tasks: %w", err)
	}
	tasks := make([]Task, len(rows))
	for i := range rows {
		tasks[i] = rowToTask(&rows[i])
	}
	return tasks, nil
}

// ClarifyParams holds fields for promoting inbox → todo.
type ClarifyParams struct {
	Priority *string
	Energy   *string
	Due      *time.Time
}

// Clarify promotes an inbox task to todo with optional fields.
func (s *Store) Clarify(ctx context.Context, id uuid.UUID, p *ClarifyParams) (*Task, error) {
	row, err := s.q.ClarifyTask(ctx, db.ClarifyTaskParams{
		ID:       id,
		Priority: p.Priority,
		Energy:   p.Energy,
		Due:      p.Due,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("clarifying task %s: %w", id, err)
	}
	t := rowToTask(&row)
	return &t, nil
}

// Start sets a task's status to in-progress.
func (s *Store) Start(ctx context.Context, id uuid.UUID) error {
	_, err := s.UpdateStatus(ctx, id, StatusInProgress)
	return err
}

// Complete sets a task's status to done with the given completion time.
func (s *Store) Complete(ctx context.Context, id uuid.UUID, completedAt *time.Time) error {
	_, err := s.UpdateStatus(ctx, id, StatusDone)
	return err
}

// DeferTask sets a task's status to someday.
func (s *Store) DeferTask(ctx context.Context, id uuid.UUID) error {
	_, err := s.UpdateStatus(ctx, id, StatusSomeday)
	return err
}

// BacklogTasks returns a filtered list of tasks for the admin backlog view.
func (s *Store) BacklogTasks(ctx context.Context, status, projectID, energy, priority, search string, limit int) ([]PendingTaskDetail, error) {
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

	rows, err := s.q.BacklogTasks(ctx, db.BacklogTasksParams{
		Status:     db.TaskStatus(status),
		ProjectID:  projID,
		Energy:     energyPtr,
		Priority:   priorityPtr,
		Search:     searchPtr,
		MaxResults: int32(limit), // #nosec G115 -- bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("listing backlog tasks: %w", err)
	}
	tasks := make([]PendingTaskDetail, len(rows))
	for i := range rows {
		r := &rows[i]
		tasks[i] = PendingTaskDetail{
			ID: r.ID, Title: r.Title, Status: Status(r.Status), Due: r.Due,
			ProjectTitle: r.ProjectTitle, ProjectSlug: r.ProjectSlug,
			Energy: r.Energy, Priority: r.Priority,
			RecurInterval: r.RecurInterval, RecurUnit: r.RecurUnit,
			Assignee: r.Assignee, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		}
	}
	return tasks, nil
}

// GroupedTasks holds tasks grouped by status for admin project detail.
type GroupedTasks struct {
	InProgress []TaskBrief `json:"in_progress"`
	Todo       []TaskBrief `json:"todo"`
	Done       []TaskBrief `json:"done"`
	Other      []TaskBrief `json:"other"`
}

// TaskBrief is a lightweight task for grouped views.
type TaskBrief struct {
	ID       uuid.UUID  `json:"id"`
	Title    string     `json:"title"`
	Status   Status     `json:"status"`
	Due      *time.Time `json:"due,omitempty"`
	Energy   *string    `json:"energy,omitempty"`
	Priority *string    `json:"priority,omitempty"`
}

// TasksByProjectGrouped returns tasks for a project grouped by status.
func (s *Store) TasksByProjectGrouped(ctx context.Context, projectID uuid.UUID) (*GroupedTasks, error) {
	rows, err := s.q.TasksByProjectGrouped(ctx, &projectID)
	if err != nil {
		return nil, fmt.Errorf("listing tasks for project %s: %w", projectID, err)
	}
	result := &GroupedTasks{
		InProgress: []TaskBrief{},
		Todo:       []TaskBrief{},
		Done:       []TaskBrief{},
		Other:      []TaskBrief{},
	}
	for i := range rows {
		r := &rows[i]
		tb := TaskBrief{
			ID:       r.ID,
			Title:    r.Title,
			Status:   Status(r.Status),
			Due:      r.Due,
			Energy:   r.Energy,
			Priority: r.Priority,
		}
		switch Status(r.Status) {
		case StatusInProgress:
			result.InProgress = append(result.InProgress, tb)
		case StatusTodo:
			result.Todo = append(result.Todo, tb)
		case StatusDone:
			result.Done = append(result.Done, tb)
		default:
			result.Other = append(result.Other, tb)
		}
	}
	return result, nil
}

// Delete hard-deletes a task. Used only for inbox discard.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	return s.q.DeleteTask(ctx, id)
}
