package goal

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store handles database operations for goals.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{q: db.New(pool)}
}

// Goals returns all goals ordered by status and deadline.
func (s *Store) Goals(ctx context.Context) ([]Goal, error) {
	rows, err := s.q.Goals(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing goals: %w", err)
	}
	goals := make([]Goal, len(rows))
	for i, r := range rows {
		goals[i] = rowToGoal(r)
	}
	return goals, nil
}

// UpsertByNotionPageID upserts a goal by its Notion page ID.
func (s *Store) UpsertByNotionPageID(ctx context.Context, p UpsertByNotionParams) (*Goal, error) {
	r, err := s.q.UpsertGoalByNotionPageID(ctx, db.UpsertGoalByNotionPageIDParams{
		Title:        p.Title,
		Description:  p.Description,
		Status:       db.GoalStatus(p.Status),
		Area:         p.Area,
		Quarter:      p.Quarter,
		Deadline:     p.Deadline,
		NotionPageID: &p.NotionPageID,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting goal by notion page %s: %w", p.NotionPageID, err)
	}
	g := rowToGoal(r)
	return &g, nil
}

// GoalByNotionPageID returns a goal by its Notion page ID.
func (s *Store) GoalByNotionPageID(ctx context.Context, notionPageID string) (*Goal, error) {
	r, err := s.q.GoalByNotionPageID(ctx, &notionPageID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying goal by notion page %s: %w", notionPageID, err)
	}
	g := rowToGoal(r)
	return &g, nil
}

// NotionPageIDs returns all notion page IDs for goals synced from Notion.
func (s *Store) NotionPageIDs(ctx context.Context) ([]string, error) {
	ptrs, err := s.q.NotionGoalPageIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing goal notion page ids: %w", err)
	}
	ids := make([]string, 0, len(ptrs))
	for _, p := range ptrs {
		if p != nil {
			ids = append(ids, *p)
		}
	}
	return ids, nil
}

// ArchiveOrphanNotion marks goals as abandoned if their notion_page_id
// is not in the given list of active IDs. Returns the number of archived goals.
func (s *Store) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
	n, err := s.q.ArchiveOrphanNotionGoals(ctx, activeIDs)
	if err != nil {
		return 0, fmt.Errorf("archiving orphan notion goals: %w", err)
	}
	return n, nil
}

func rowToGoal(r db.Goal) Goal {
	return Goal{
		ID:           r.ID,
		Title:        r.Title,
		Description:  r.Description,
		Status:       Status(r.Status),
		Area:         r.Area,
		Quarter:      r.Quarter,
		Deadline:     r.Deadline,
		NotionPageID: r.NotionPageID,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}
