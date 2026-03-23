package task

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/koopa0/blog-backend/internal/db"
	"github.com/koopa0/blog-backend/internal/flow"
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
func (s *Store) PendingTasks(ctx context.Context) ([]flow.PendingTask, error) {
	rows, err := s.q.PendingTasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pending tasks: %w", err)
	}
	tasks := make([]flow.PendingTask, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		var due string
		if r.Due != nil {
			due = r.Due.Format(time.DateOnly)
		}
		tasks = append(tasks, flow.PendingTask{
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
func (s *Store) CompletedByProjectSince(ctx context.Context, since time.Time) ([]flow.ProjectCompletion, error) {
	rows, err := s.q.CompletedTasksByProjectSince(ctx, &since)
	if err != nil {
		return nil, fmt.Errorf("counting completed tasks by project: %w", err)
	}
	result := make([]flow.ProjectCompletion, len(rows))
	for i := range rows {
		result[i] = flow.ProjectCompletion{
			ProjectTitle: rows[i].ProjectTitle,
			Completed:    rows[i].Completed,
		}
	}
	return result, nil
}

// PendingTasksWithProject returns pending tasks with project context for MCP tools.
func (s *Store) PendingTasksWithProject(ctx context.Context, projectSlug *string, maxResults int32) ([]PendingTaskDetail, error) {
	rows, err := s.q.PendingTasksWithProject(ctx, db.PendingTasksWithProjectParams{
		ProjectSlug: projectSlug,
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
			CreatedAt:     r.CreatedAt,
			UpdatedAt:     r.UpdatedAt,
		}
	}
	return tasks, nil
}

// TaskByID returns a single task by its ID.
func (s *Store) TaskByID(ctx context.Context, id uuid.UUID) (*Task, error) {
	r, err := s.q.TaskByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("querying task %s: %w", id, err)
	}
	t := rowToTask(&r)
	return &t, nil
}

// TaskByNotionPageID returns a task by its Notion page ID.
func (s *Store) TaskByNotionPageID(ctx context.Context, notionPageID string) (*Task, error) {
	r, err := s.q.TaskByNotionPageID(ctx, &notionPageID)
	if err != nil {
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

// UpdateParams holds optional fields for updating a task.
type UpdateParams struct {
	ID          uuid.UUID
	Status      *Status
	Due         *time.Time
	Energy      *string
	Priority    *string
	MyDay       *bool
	ProjectID   *uuid.UUID
	Description *string
}

// Update updates arbitrary task fields.
func (s *Store) Update(ctx context.Context, p *UpdateParams) (*Task, error) {
	params := db.UpdateTaskParams{ID: p.ID}
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
	r, err := s.q.UpdateTask(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("updating task %s: %w", p.ID, err)
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
		MyDay:         r.MyDay,
		Description:   r.Description,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}
