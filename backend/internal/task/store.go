package task

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/db"
	"github.com/koopa0/blog-backend/internal/flow"
)

// Store handles database operations for tasks.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{q: db.New(pool)}
}

// Tasks returns all tasks ordered by status and due date.
func (s *Store) Tasks(ctx context.Context) ([]Task, error) {
	rows, err := s.q.Tasks(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tasks: %w", err)
	}
	tasks := make([]Task, len(rows))
	for i, r := range rows {
		tasks[i] = rowToTask(r)
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
	for _, r := range rows {
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
func (s *Store) UpsertByNotionPageID(ctx context.Context, p UpsertByNotionParams) (*Task, error) {
	r, err := s.q.UpsertTaskByNotionPageID(ctx, db.UpsertTaskByNotionPageIDParams{
		Title:        p.Title,
		Status:       db.TaskStatus(p.Status),
		Due:          p.Due,
		ProjectID:    p.ProjectID,
		NotionPageID: &p.NotionPageID,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting task by notion page %s: %w", p.NotionPageID, err)
	}
	t := rowToTask(r)
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

// ArchiveOrphanNotion marks tasks as done if their notion_page_id
// is not in the given list of active IDs. Returns the number of archived tasks.
func (s *Store) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
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
	for i, r := range rows {
		result[i] = flow.ProjectCompletion{
			ProjectTitle: r.ProjectTitle,
			Completed:    r.Completed,
		}
	}
	return result, nil
}

func rowToTask(r db.Task) Task {
	return Task{
		ID:           r.ID,
		Title:        r.Title,
		Status:       Status(r.Status),
		Due:          r.Due,
		ProjectID:    r.ProjectID,
		NotionPageID: r.NotionPageID,
		CompletedAt:  r.CompletedAt,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}
