package goal

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for goals.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Goals returns all goals ordered by status and deadline.
func (s *Store) Goals(ctx context.Context) ([]Goal, error) {
	rows, err := s.q.Goals(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing goals: %w", err)
	}
	goals := make([]Goal, len(rows))
	for i := range rows {
		r := rows[i]
		goals[i] = rowToGoal(&r)
	}
	return goals, nil
}

// UpsertByNotionPageID upserts a goal by its Notion page ID.
func (s *Store) UpsertByNotionPageID(ctx context.Context, p *UpsertByNotionParams) (*Goal, error) {
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
	g := rowToGoal(&r)
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

// ArchiveByNotionPageID marks a single goal as abandoned by its Notion page ID.
func (s *Store) ArchiveByNotionPageID(ctx context.Context, notionPageID string) (int64, error) {
	n, err := s.q.ArchiveGoalByNotionPageID(ctx, &notionPageID)
	if err != nil {
		return 0, fmt.Errorf("archiving goal by notion page %s: %w", notionPageID, err)
	}
	return n, nil
}

// ArchiveOrphanNotion marks goals as abandoned if their notion_page_id
// is not in the given list of active IDs. Returns the number of archived goals.
// Returns 0 immediately if activeIDs is empty to avoid archiving all records.
func (s *Store) ArchiveOrphanNotion(ctx context.Context, activeIDs []string) (int64, error) {
	if len(activeIDs) == 0 {
		return 0, nil
	}
	n, err := s.q.ArchiveOrphanNotionGoals(ctx, activeIDs)
	if err != nil {
		return 0, fmt.Errorf("archiving orphan notion goals: %w", err)
	}
	return n, nil
}

// IDByNotionPageID resolves a Notion page ID to a goal UUID.
func (s *Store) IDByNotionPageID(ctx context.Context, notionPageID string) (uuid.UUID, error) {
	id, err := s.q.GoalIDByNotionPageID(ctx, &notionPageID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, fmt.Errorf("resolving goal by notion page %s: %w", notionPageID, err)
	}
	return id, nil
}

// GoalByTitle returns a goal by case-insensitive title match.
func (s *Store) GoalByTitle(ctx context.Context, title string) (*Goal, error) {
	r, err := s.q.GoalByTitle(ctx, title)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying goal by title %q: %w", title, err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

// UpdateStatus updates a goal's status.
func (s *Store) UpdateStatus(ctx context.Context, id uuid.UUID, status Status) (*Goal, error) {
	r, err := s.q.UpdateGoalStatus(ctx, db.UpdateGoalStatusParams{
		ID:     id,
		Status: db.GoalStatus(status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating goal %s status: %w", id, err)
	}
	g := rowToGoal(&r)
	return &g, nil
}

func rowToGoal(r *db.Goal) Goal {
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
