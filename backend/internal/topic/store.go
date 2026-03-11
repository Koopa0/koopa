package topic

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store handles database operations for topics.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{q: db.New(pool)}
}

// AllTopicSlugs returns all topic slugs and names, lightweight for AI tag classification.
func (s *Store) AllTopicSlugs(ctx context.Context) ([]TopicSlug, error) {
	rows, err := s.q.AllTopicSlugs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing topic slugs: %w", err)
	}
	slugs := make([]TopicSlug, len(rows))
	for i, r := range rows {
		slugs[i] = TopicSlug{Slug: r.Slug, Name: r.Name}
	}
	return slugs, nil
}

// Topics returns all topics with published content counts.
func (s *Store) Topics(ctx context.Context) ([]Topic, error) {
	rows, err := s.q.Topics(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing topics: %w", err)
	}
	topics := make([]Topic, len(rows))
	for i, r := range rows {
		topics[i] = Topic{
			ID:           r.ID,
			Slug:         r.Slug,
			Name:         r.Name,
			Description:  r.Description,
			Icon:         r.Icon,
			ContentCount: int(r.ContentCount),
			SortOrder:    int(r.SortOrder),
			CreatedAt:    r.CreatedAt,
			UpdatedAt:    r.UpdatedAt,
		}
	}
	return topics, nil
}

// TopicBySlug returns a single topic by slug.
func (s *Store) TopicBySlug(ctx context.Context, slug string) (*Topic, error) {
	r, err := s.q.TopicBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying topic %s: %w", slug, err)
	}
	return &Topic{
		ID:           r.ID,
		Slug:         r.Slug,
		Name:         r.Name,
		Description:  r.Description,
		Icon:         r.Icon,
		ContentCount: int(r.ContentCount),
		SortOrder:    int(r.SortOrder),
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}, nil
}

// CreateTopic inserts a new topic.
func (s *Store) CreateTopic(ctx context.Context, p CreateParams) (*Topic, error) {
	r, err := s.q.CreateTopic(ctx, db.CreateTopicParams{
		Slug:        p.Slug,
		Name:        p.Name,
		Description: p.Description,
		Icon:        p.Icon,
		SortOrder:   int32(p.SortOrder), // #nosec G115 -- sort order is a small UI ordering value, not user-controlled
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating topic: %w", err)
	}
	return &Topic{
		ID:          r.ID,
		Slug:        r.Slug,
		Name:        r.Name,
		Description: r.Description,
		Icon:        r.Icon,
		SortOrder:   int(r.SortOrder),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

// UpdateTopic updates a topic.
func (s *Store) UpdateTopic(ctx context.Context, id uuid.UUID, p UpdateParams) (*Topic, error) {
	var sortOrder *int32
	if p.SortOrder != nil {
		v := int32(*p.SortOrder) // #nosec G115 -- sort order is a small UI ordering value, not user-controlled
		sortOrder = &v
	}
	r, err := s.q.UpdateTopic(ctx, db.UpdateTopicParams{
		ID:          id,
		Slug:        p.Slug,
		Name:        p.Name,
		Description: p.Description,
		Icon:        p.Icon,
		SortOrder:   sortOrder,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating topic %s: %w", id, err)
	}
	return &Topic{
		ID:          r.ID,
		Slug:        r.Slug,
		Name:        r.Name,
		Description: r.Description,
		Icon:        r.Icon,
		SortOrder:   int(r.SortOrder),
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

// DeleteTopic deletes a topic by ID.
func (s *Store) DeleteTopic(ctx context.Context, id uuid.UUID) error {
	err := s.q.DeleteTopic(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting topic %s: %w", id, err)
	}
	return nil
}
