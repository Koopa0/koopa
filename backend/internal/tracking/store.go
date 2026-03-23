package tracking

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store handles database operations for tracking topics.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// TrackingTopics returns all tracking topics.
func (s *Store) TrackingTopics(ctx context.Context) ([]Topic, error) {
	rows, err := s.q.TrackingTopics(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tracking topics: %w", err)
	}
	topics := make([]Topic, len(rows))
	for i := range rows {
		r := rows[i]
		topics[i] = dbToTrackingTopic(&r)
	}
	return topics, nil
}

// TrackingTopicByID returns a single tracking topic by ID.
func (s *Store) TrackingTopicByID(ctx context.Context, id uuid.UUID) (*Topic, error) {
	r, err := s.q.TrackingTopicByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying tracking topic %s: %w", id, err)
	}
	t := dbToTrackingTopic(&r)
	return &t, nil
}

// CreateTrackingTopic inserts a new tracking topic.
func (s *Store) CreateTrackingTopic(ctx context.Context, p *CreateParams) (*Topic, error) {
	if p.Keywords == nil {
		p.Keywords = []string{}
	}
	if p.Sources == nil {
		p.Sources = []string{}
	}
	if p.Schedule == "" {
		p.Schedule = "0 */6 * * *"
	}
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	r, err := s.q.CreateTrackingTopic(ctx, db.CreateTrackingTopicParams{
		Name:     p.Name,
		Keywords: p.Keywords,
		Sources:  p.Sources,
		Enabled:  enabled,
		Schedule: p.Schedule,
	})
	if err != nil {
		return nil, fmt.Errorf("creating tracking topic: %w", err)
	}
	t := dbToTrackingTopic(&r)
	return &t, nil
}

// UpdateTrackingTopic updates a tracking topic.
func (s *Store) UpdateTrackingTopic(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Topic, error) {
	r, err := s.q.UpdateTrackingTopic(ctx, db.UpdateTrackingTopicParams{
		ID:       id,
		Name:     p.Name,
		Keywords: p.Keywords,
		Sources:  p.Sources,
		Enabled:  p.Enabled,
		Schedule: p.Schedule,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating tracking topic %s: %w", id, err)
	}
	t := dbToTrackingTopic(&r)
	return &t, nil
}

// DeleteTrackingTopic deletes a tracking topic by ID.
func (s *Store) DeleteTrackingTopic(ctx context.Context, id uuid.UUID) error {
	err := s.q.DeleteTrackingTopic(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting tracking topic %s: %w", id, err)
	}
	return nil
}

// Keywords returns a deduplicated, lowercased list of all keywords
// from enabled tracking topics. Satisfies collector.KeywordLoader.
func (s *Store) Keywords(ctx context.Context) ([]string, error) {
	topics, err := s.TrackingTopics(ctx)
	if err != nil {
		return nil, err
	}
	var all []string
	for i := range topics {
		if !topics[i].Enabled {
			continue
		}
		all = append(all, topics[i].Keywords...)
	}
	// Deduplicate and lowercase in caller (collector.NormalizeKeywords).
	return all, nil
}

// dbToTrackingTopic converts a db.TrackingTopic to Topic.
func dbToTrackingTopic(r *db.TrackingTopic) Topic {
	return Topic{
		ID:        r.ID,
		Name:      r.Name,
		Keywords:  r.Keywords,
		Sources:   r.Sources,
		Enabled:   r.Enabled,
		Schedule:  r.Schedule,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}
