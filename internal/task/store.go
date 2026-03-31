package task

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for tasks.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Tasks returns all tasks ordered by status and due date.
func (s *Store) Tasks(ctx context.Context) ([]Task, error) {
	rows, err := s.q.Tasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tasks: %w", err)
	}
	tasks := make([]Task, len(rows))
	for i := range rows {
		r := rows[i]
		tasks[i] = rowToTask(&r)
	}
	return tasks, nil
}

// PendingTasks returns tasks that are not done, satisfying flow.TaskQuerier.
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
		tasks = append(tasks, PendingTask{
			Title: r.Title,
			Due:   due,
		})
	}
	return tasks, nil
}

// UpsertByNotionPageID upserts a task by its Notion page ID.
func (s *Store) UpsertByNotionPageID(ctx context.Context, p *UpsertByNotionParams) (*Task, error) {
	r, err := s.q.UpsertTaskByNotionPageID(ctx, db.UpsertTaskByNotionPageIDParams{
		Title:         p.Title,
		Status:        db.TaskStatus(p.Status),
		Due:           p.Due,
		ProjectID:     p.ProjectID,
		NotionPageID:  &p.NotionPageID,
		Energy:        p.Energy,
		Priority:      p.Priority,
		RecurInterval: p.RecurInterval,
		RecurUnit:     p.RecurUnit,
		MyDay:         p.MyDay,
		Description:   p.Description,
		Assignee:      p.Assignee,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting task by notion page %s: %w", p.NotionPageID, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// NotionPageIDs returns all notion page IDs for tasks synced from Notion.
func (s *Store) NotionPageIDs(ctx context.Context) ([]string, error) {
	ptrs, err := s.q.NotionTaskPageIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing task notion page ids: %w", err)
	}
	ids := make([]string, 0, len(ptrs))
	for _, p := range ptrs {
		if p != nil {
			ids = append(ids, *p)
		}
	}
	return ids, nil
}

// ArchiveByNotionPageID marks a single task as done by its Notion page ID.
func (s *Store) ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error) {
	n, err := s.q.ArchiveTaskByNotionPageID(ctx, &notionPageID)
	if err != nil {
		return 0, fmt.Errorf("archiving task by notion page %s: %w", notionPageID, err)
	}
	return n, nil
}

// ArchiveOrphanNotion marks tasks as done if their notion_page_id
// is not in the given list of active IDs. Returns the number of archived tasks.
// Returns 0 immediately if activeIDs is empty to avoid archiving all records.
func (s *Store) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
	if len(activeIDs) == 0 {
		return 0, nil
	}
	n, err := s.q.ArchiveOrphanNotionTasks(ctx, activeIDs)
	if err != nil {
		return 0, fmt.Errorf("archiving orphan notion tasks: %w", err)
	}
	return n, nil
}

// CompletedSince counts tasks completed since the given time.
func (s *Store) CompletedSince(ctx context.Context, since time.Time) (int64, error) {
	n, err := s.q.CompletedTasksSince(ctx, &since)
	if err != nil {
		return 0, fmt.Errorf("counting completed tasks: %w", err)
	}
	return n, nil
}

// CompletedByProjectSince returns per-project completion counts since the given time.
func (s *Store) CompletedByProjectSince(ctx context.Context, since time.Time) ([]ProjectCompletion, error) {
	rows, err := s.q.CompletedTasksByProjectSince(ctx, &since)
	if err != nil {
		return nil, fmt.Errorf("counting completed tasks by project: %w", err)
	}
	result := make([]ProjectCompletion, len(rows))
	for i := range rows {
		result[i] = ProjectCompletion{
			ProjectTitle: rows[i].ProjectTitle,
			Completed:    rows[i].Completed,
		}
	}
	return result, nil
}

// PendingTasksWithProject returns pending tasks with project context for MCP tools.
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
			MyDay:         r.MyDay,
			Assignee:      r.Assignee,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
		}
	}
	return tasks, nil
}

// SearchTasks searches tasks by title/description with optional filters.
func (s *Store) SearchTasks(ctx context.Context, query, projectSlug, statusFilter, assignee *string, completedAfter, completedBefore *time.Time, maxResults int32) ([]SearchTaskDetail, error) {
	rows, err := s.q.SearchTasks(ctx, db.SearchTasksParams{
		Query:           query,
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
			MyDay:         r.MyDay,
			Assignee:      r.Assignee,
			CompletedAt:   r.CompletedAt,
			Description:   r.Description,
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
		}
	}
	return tasks, nil
}

// MyDayTasks returns current My Day pending tasks with project context.
func (s *Store) MyDayTasks(ctx context.Context) ([]MyDaySnapshot, error) {
	rows, err := s.q.MyDayTasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing my day tasks: %w", err)
	}
	tasks := make([]MyDaySnapshot, len(rows))
	for i := range rows {
		r := &rows[i]
		tasks[i] = MyDaySnapshot{
			ID:           r.ID,
			Title:        r.Title,
			ProjectTitle: r.ProjectTitle,
			Energy:       r.Energy,
			Priority:     r.Priority,
			Assignee:     r.Assignee,
		}
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

// TaskByNotionPageID returns a task by its Notion page ID.
func (s *Store) TaskByNotionPageID(ctx context.Context, notionPageID string) (*Task, error) {
	r, err := s.q.TaskByNotionPageID(ctx, &notionPageID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying task by notion page %s: %w", notionPageID, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// PendingTasksByTitle finds pending tasks matching a title (case-insensitive contains).
func (s *Store) PendingTasksByTitle(ctx context.Context, title string) ([]Task, error) {
	rows, err := s.q.PendingTasksByTitle(ctx, &title)
	if err != nil {
		return nil, fmt.Errorf("searching pending tasks by title %q: %w", title, err)
	}
	tasks := make([]Task, len(rows))
	for i := range rows {
		tasks[i] = rowToTask(&rows[i])
	}
	return tasks, nil
}

// UpdateStatus updates a task's status and returns the updated task.
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

// UpdateMyDay sets or clears My Day for a task.
func (s *Store) UpdateMyDay(ctx context.Context, id uuid.UUID, myDay bool) error {
	n, err := s.q.UpdateTaskMyDay(ctx, db.UpdateTaskMyDayParams{
		ID:    id,
		MyDay: myDay,
	})
	if err != nil {
		return fmt.Errorf("updating task %s my_day: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("task %s not found or already done", id)
	}
	return nil
}

// ClearAllMyDay clears My Day for all pending tasks.
func (s *Store) ClearAllMyDay(ctx context.Context) (int64, error) {
	n, err := s.q.ClearAllMyDay(ctx)
	if err != nil {
		return 0, fmt.Errorf("clearing all my day: %w", err)
	}
	return n, nil
}

// MyDayTasksWithNotionPageID returns tasks marked as My Day that have a Notion page ID.
func (s *Store) MyDayTasksWithNotionPageID(ctx context.Context) ([]MyDayNotionTask, error) {
	rows, err := s.q.MyDayTasksWithNotionPageID(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying my day tasks with notion page id: %w", err)
	}
	result := make([]MyDayNotionTask, 0, len(rows))
	for _, r := range rows {
		if r.NotionPageID == nil {
			continue
		}
		result = append(result, MyDayNotionTask{
			ID:           r.ID,
			NotionPageID: *r.NotionPageID,
		})
	}
	return result, nil
}

// DailySummaryHintForDate computes task counts for a single day (committed vs pulled).
func (s *Store) DailySummaryHintForDate(ctx context.Context, dayStart, dayEnd time.Time) (*DailySummaryHint, error) {
	row, err := s.q.DailySummaryHint(ctx, db.DailySummaryHintParams{
		DayStart: &dayStart,
		DayEnd:   &dayEnd,
	})
	if err != nil {
		return nil, fmt.Errorf("querying daily summary hint: %w", err)
	}

	titles, titleErr := s.q.CompletedTitlesSince(ctx, &dayStart)
	if titleErr != nil {
		return nil, fmt.Errorf("querying completed titles: %w", titleErr)
	}
	completedTitles := make([]string, len(titles))
	copy(completedTitles, titles)

	return &DailySummaryHint{
		MyDayTasksTotal:     int(row.MyDayTotal),
		MyDayTasksCompleted: int(row.MyDayCompleted),
		NonMyDayCompleted:   int(row.NonMyDayCompleted),
		TotalCompleted:      int(row.TotalCompleted),
		CompletedTitles:     completedTitles,
	}, nil
}

// CompletedTasksDetailSince returns tasks completed since the given time with project context.
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

// TasksCreatedSince returns tasks created since the given time with project context.
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

// RecurringTaskByProject finds a recurring pending task under a
// project that is due today, overdue, or in My Day. Returns (nil, nil) when no
// matching task exists — callers use this for best-effort auto-complete.
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

// UpdateParams holds optional fields for updating a task.
type UpdateParams struct {
	ID          uuid.UUID
	Title       *string
	Status      *Status
	Due         *time.Time
	Energy      *string
	Priority    *string
	MyDay       *bool
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
	params.MyDay = p.MyDay
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

// OverdueRecurringTasks returns all recurring tasks with due < today.
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

// RecurringTasksDueToday returns recurring tasks with due <= today (for My Day auto-populate).
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

// UpdateDue updates only the due date for a task.
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

// ResetRecurring advances a recurring task's due date, resets status to todo, and clears my_day.
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

// MyDayIncompleteTaskIDs returns tasks in My Day that are not done (for daily reset logging).
func (s *Store) MyDayIncompleteTaskIDs(ctx context.Context) ([]db.MyDayIncompleteTaskIDsRow, error) {
	return s.q.MyDayIncompleteTaskIDs(ctx)
}

// LogSkip inserts a skip record. Idempotent via ON CONFLICT DO NOTHING.
func (s *Store) LogSkip(ctx context.Context, taskID uuid.UUID, originalDue, skippedDate time.Time, reason string) error {
	return s.q.CreateSkipRecord(ctx, db.CreateSkipRecordParams{
		TaskID:      taskID,
		OriginalDue: originalDue,
		SkippedDate: skippedDate,
		Reason:      reason,
	})
}

// SkipRecord represents a single skip event.
type SkipRecord struct {
	ID          uuid.UUID `json:"id"`
	TaskID      uuid.UUID `json:"task_id"`
	OriginalDue time.Time `json:"original_due"`
	SkippedDate time.Time `json:"skipped_date"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
}

// SkipHistoryByTask returns skip records for a task since a given date.
func (s *Store) SkipHistoryByTask(ctx context.Context, taskID uuid.UUID, since time.Time) ([]SkipRecord, error) {
	rows, err := s.q.SkipHistoryByTask(ctx, db.SkipHistoryByTaskParams{
		TaskID: taskID,
		Since:  since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying skip history for task %s: %w", taskID, err)
	}
	records := make([]SkipRecord, len(rows))
	for i, r := range rows {
		records[i] = SkipRecord{
			ID:          r.ID,
			TaskID:      r.TaskID,
			OriginalDue: r.OriginalDue,
			SkippedDate: r.SkippedDate,
			Reason:      r.Reason,
			CreatedAt:   r.CreatedAt,
		}
	}
	return records, nil
}

// SkipCountByTask returns the number of skips for a task since a given date.
func (s *Store) SkipCountByTask(ctx context.Context, taskID uuid.UUID, since time.Time) (int, error) {
	n, err := s.q.SkipCountByTask(ctx, db.SkipCountByTaskParams{
		TaskID: taskID,
		Since:  since,
	})
	if err != nil {
		return 0, fmt.Errorf("counting skips for task %s: %w", taskID, err)
	}
	return int(n), nil
}

// SkipRecordWithTitle includes task title for project-level queries.
type SkipRecordWithTitle struct {
	SkipRecord
	TaskTitle string `json:"task_title"`
}

// SkipHistoryByProject returns skip records for all tasks under a project.
func (s *Store) SkipHistoryByProject(ctx context.Context, projectID uuid.UUID, since time.Time) ([]SkipRecordWithTitle, error) {
	rows, err := s.q.SkipHistoryByProject(ctx, db.SkipHistoryByProjectParams{
		ProjectID: &projectID,
		Since:     since,
	})
	if err != nil {
		return nil, fmt.Errorf("querying skip history for project %s: %w", projectID, err)
	}
	records := make([]SkipRecordWithTitle, len(rows))
	for i, r := range rows {
		records[i] = SkipRecordWithTitle{
			SkipRecord: SkipRecord{
				ID:          r.ID,
				TaskID:      r.TaskID,
				OriginalDue: r.OriginalDue,
				SkippedDate: r.SkippedDate,
				Reason:      r.Reason,
				CreatedAt:   r.CreatedAt,
			},
			TaskTitle: r.TaskTitle,
		}
	}
	return records, nil
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
		MyDay:         r.MyDay,
		Description:   r.Description,
		Assignee:      r.Assignee,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}
