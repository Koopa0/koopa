package insight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for insights.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Create inserts a new insight.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Insight, error) {
	row, err := s.q.CreateInsight(ctx, db.CreateInsightParams{
		Source:                p.Source,
		Content:               p.Content,
		Hypothesis:            p.Hypothesis,
		InvalidationCondition: p.InvalidationCondition,
		Metadata:              p.Metadata,
		ObservedDate:          p.ObservedDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating insight: %w", err)
	}
	return rowToInsight(&row), nil
}

// ByID returns a single insight by ID.
func (s *Store) ByID(ctx context.Context, id int64) (*Insight, error) {
	row, err := s.q.InsightByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying insight %d: %w", id, err)
	}
	return rowToInsight(&row), nil
}

// UpdateStatus changes an insight's status.
func (s *Store) UpdateStatus(ctx context.Context, id int64, status Status) (*Insight, error) {
	row, err := s.q.UpdateInsightStatus(ctx, db.UpdateInsightStatusParams{
		ID:     id,
		Status: string(status),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating insight %d status: %w", id, err)
	}
	return rowToInsight(&row), nil
}

// UpdateMetadata replaces an insight's metadata (used for add_evidence).
func (s *Store) UpdateMetadata(ctx context.Context, id int64, metadata json.RawMessage) (*Insight, error) {
	row, err := s.q.UpdateInsightMetadata(ctx, db.UpdateInsightMetadataParams{
		ID:       id,
		Metadata: metadata,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating insight %d metadata: %w", id, err)
	}
	return rowToInsight(&row), nil
}

// Unverified returns unverified insights.
func (s *Store) Unverified(ctx context.Context, limit int32) ([]Insight, error) {
	rows, err := s.q.UnverifiedInsights(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("querying unverified insights: %w", err)
	}
	result := make([]Insight, len(rows))
	for i := range rows {
		result[i] = *rowToInsight(&rows[i])
	}
	return result, nil
}

// ByStatus returns insights filtered by optional status, newest first.
func (s *Store) ByStatus(ctx context.Context, status *string, limit int32) ([]Insight, error) {
	rows, err := s.q.InsightsByStatus(ctx, db.InsightsByStatusParams{
		Status:     status,
		MaxResults: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("querying insights: %w", err)
	}
	result := make([]Insight, len(rows))
	for i := range rows {
		result[i] = *rowToInsight(&rows[i])
	}
	return result, nil
}

func rowToInsight(r *db.Insight) *Insight {
	ins := &Insight{
		ID:                    r.ID,
		Source:                r.Source,
		Content:               r.Content,
		Status:                Status(r.Status),
		Hypothesis:            r.Hypothesis,
		InvalidationCondition: r.InvalidationCondition,
		ObservedDate:          r.ObservedDate,
		CreatedAt:             r.CreatedAt,
	}
	if r.Metadata != nil {
		_ = json.Unmarshal(r.Metadata, &ins.Metadata)
	}
	return ins
}
