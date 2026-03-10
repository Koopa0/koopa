package collected

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// CreateCollectedData inserts a new collected data item.
func (s *Store) CreateCollectedData(ctx context.Context, p CreateParams) (*CollectedData, error) {
	r, err := s.q.CreateCollectedData(ctx, db.CreateCollectedDataParams{
		SourceUrl:       p.SourceURL,
		SourceName:      p.SourceName,
		Title:           p.Title,
		OriginalContent: p.OriginalContent,
		Topics:          p.Topics,
		UrlHash:         p.URLHash,
		FeedID:          p.FeedID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating collected data: %w", err)
	}
	d := datumToCollectedData(r)
	return &d, nil
}

// CollectedDataByURLHash returns a single collected data item by URL hash.
func (s *Store) CollectedDataByURLHash(ctx context.Context, urlHash string) (*CollectedData, error) {
	r, err := s.q.CollectedDataByURLHash(ctx, urlHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying collected data by url hash %s: %w", urlHash, err)
	}
	d := datumToCollectedData(r)
	return &d, nil
}

// UpdateScoring updates the AI scoring fields for a collected data item.
func (s *Store) UpdateScoring(ctx context.Context, id uuid.UUID, p ScoringParams) error {
	if err := s.q.UpdateCollectedScoring(ctx, db.UpdateCollectedScoringParams{
		ID:            id,
		AiScore:       &p.Score,
		AiScoreReason: &p.Reason,
		AiSummaryZh:   &p.SummaryZH,
		AiTitleZh:     &p.TitleZH,
		Status:        db.CollectedStatus(p.Status),
	}); err != nil {
		return fmt.Errorf("updating collected scoring %s: %w", id, err)
	}
	return nil
}

// UpdateFeedback updates the user feedback for a collected data item.
func (s *Store) UpdateFeedback(ctx context.Context, id uuid.UUID, feedback Feedback) error {
	fb := string(feedback)
	if err := s.q.UpdateCollectedFeedback(ctx, db.UpdateCollectedFeedbackParams{
		ID:           id,
		UserFeedback: &fb,
	}); err != nil {
		return fmt.Errorf("updating collected feedback %s: %w", id, err)
	}
	return nil
}

// HighScoreCollectedData returns collected data with AI score >= minScore in a time range.
func (s *Store) HighScoreCollectedData(ctx context.Context, start, end time.Time, minScore int16) ([]CollectedData, error) {
	rows, err := s.q.HighScoreCollectedData(ctx, db.HighScoreCollectedDataParams{
		AiScore:       &minScore,
		CollectedAt:   start,
		CollectedAt_2: end,
	})
	if err != nil {
		return nil, fmt.Errorf("listing high score collected data: %w", err)
	}
	data := make([]CollectedData, len(rows))
	for i, r := range rows {
		data[i] = datumToCollectedData(r)
	}
	return data, nil
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
		URLHash:          r.UrlHash,
		AIScore:          r.AiScore,
		AIScoreReason:    r.AiScoreReason,
		AISummaryZH:      r.AiSummaryZh,
		AITitleZH:        r.AiTitleZh,
		UserFeedback:     r.UserFeedback,
		FeedbackAt:       r.FeedbackAt,
		FeedID:           r.FeedID,
	}
}
