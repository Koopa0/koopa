// Copyright 2026 Koopa. All rights reserved.

package topic

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for topics.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by callers
// composing multi-store transactions — typically via api.ActorMiddleware
// (HTTP) or mcp.Server.withActorTx (MCP). The tx carries koopa.actor
// so audit triggers attribute mutations correctly.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Topics returns all topics with published content counts.
func (s *Store) Topics(ctx context.Context) ([]Topic, error) {
	rows, err := s.q.Topics(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing topics: %w", err)
	}
	topics := make([]Topic, len(rows))
	for i := range rows {
		r := rows[i]
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
func (s *Store) CreateTopic(ctx context.Context, p *CreateParams) (*Topic, error) {
	r, err := s.q.CreateTopic(ctx, db.CreateTopicParams{
		Slug:        p.Slug,
		Name:        p.Name,
		Description: p.Description,
		Icon:        p.Icon,
		SortOrder:   int32(p.SortOrder), // #nosec G115 -- sort order is a small UI ordering value, not user-controlled
	})
	if err != nil {
		return nil, mapWriteError(err, "creating topic")
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
func (s *Store) UpdateTopic(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Topic, error) {
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
		return nil, mapWriteError(err, fmt.Sprintf("updating topic %s", id))
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

// mapWriteError classifies a PostgreSQL topic-write failure into a feature
// sentinel. A unique violation (23505) on the slug becomes ErrConflict; a
// check-constraint violation (23514 — chk_topic_slug_format,
// chk_topic_name_not_blank) becomes ErrInvalidInput; any other error is
// wrapped with the supplied context.
func mapWriteError(err error, operation string) error {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return fmt.Errorf("%s: %w", operation, err)
	}
	switch pgErr.Code {
	case pgerrcode.UniqueViolation:
		return ErrConflict
	case pgerrcode.CheckViolation:
		return ErrInvalidInput
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}
