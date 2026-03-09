package collected

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koopa0/blog-backend/internal/db"
)

// nullCollectedStatus converts a *string to db.NullCollectedStatus.
func nullCollectedStatus(s *string) db.NullCollectedStatus {
	if s == nil {
		return db.NullCollectedStatus{}
	}
	return db.NullCollectedStatus{CollectedStatus: db.CollectedStatus(*s), Valid: true}
}

// Store handles database operations for collected data.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{q: db.New(pool)}
}

// CollectedData returns a paginated list of collected data.
func (s *Store) CollectedData(ctx context.Context, f Filter) ([]CollectedData, int, error) {
	status := nullCollectedStatus(f.Status)

	rows, err := s.q.CollectedData(ctx, db.CollectedDataParams{
		Limit:  int32(f.PerPage),                //nolint:gosec // pagination values are bounded by API layer
		Offset: int32((f.Page - 1) * f.PerPage), //nolint:gosec // pagination values are bounded by API layer
		Status: status,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing collected data: %w", err)
	}

	count, err := s.q.CollectedDataCount(ctx, status)
	if err != nil {
		return nil, 0, fmt.Errorf("counting collected data: %w", err)
	}

	data := make([]CollectedData, len(rows))
	for i, r := range rows {
		data[i] = datumToCollectedData(r)
	}

	return data, int(count), nil
}

// CollectedDataByID returns a single collected data item by ID.
func (s *Store) CollectedDataByID(ctx context.Context, id uuid.UUID) (*CollectedData, error) {
	r, err := s.q.CollectedDataByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying collected data %s: %w", id, err)
	}
	d := datumToCollectedData(r)
	return &d, nil
}

// Curate marks collected data as curated and links to content.
func (s *Store) Curate(ctx context.Context, id, contentID uuid.UUID) error {
	_, err := s.q.CurateCollected(ctx, db.CurateCollectedParams{
		ID:               id,
		CuratedContentID: &contentID,
	})
	if err != nil {
		return fmt.Errorf("curating collected data %s: %w", id, err)
	}
	return nil
}

// Ignore marks collected data as ignored.
func (s *Store) Ignore(ctx context.Context, id uuid.UUID) error {
	err := s.q.IgnoreCollected(ctx, id)
	if err != nil {
		return fmt.Errorf("ignoring collected data %s: %w", id, err)
	}
	return nil
}

// datumToCollectedData converts a db.CollectedDatum to CollectedData.
func datumToCollectedData(r db.CollectedDatum) CollectedData {
	return CollectedData{
		ID:               r.ID,
		SourceURL:        r.SourceUrl,
		SourceName:       r.SourceName,
		Title:            r.Title,
		OriginalContent:  r.OriginalContent,
		AISummary:        r.AiSummary,
		RelevanceScore:   r.RelevanceScore,
		Topics:           r.Topics,
		Status:           Status(r.Status),
		CuratedContentID: r.CuratedContentID,
		CollectedAt:      r.CollectedAt,
	}
}
