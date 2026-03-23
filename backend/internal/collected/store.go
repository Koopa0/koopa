package collected

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Items returns a paginated list of collected items.
func (s *Store) Items(ctx context.Context, f Filter) ([]Item, int, error) {
	status := nullCollectedStatus(f.Status)
	limit := int32(f.PerPage)                 // #nosec G115 -- pagination values are bounded by API layer
	offset := int32((f.Page - 1) * f.PerPage) // #nosec G115 -- pagination values are bounded by API layer

	var (
		rows []db.CollectedDatum
		err  error
	)
	if f.Sort == "relevance" {
		rows, err = s.q.CollectedDataByRelevance(ctx, db.CollectedDataByRelevanceParams{
			Limit:  limit,
			Offset: offset,
			Status: status,
		})
	} else {
		rows, err = s.q.CollectedData(ctx, db.CollectedDataParams{
			Limit:  limit,
			Offset: offset,
			Status: status,
		})
	}
	if err != nil {
		return nil, 0, fmt.Errorf("listing collected data: %w", err)
	}

	count, err := s.q.CollectedDataCount(ctx, status)
	if err != nil {
		return nil, 0, fmt.Errorf("counting collected data: %w", err)
	}

	data := make([]Item, len(rows))
	for i := range rows {
		r := rows[i]
		data[i] = datumToItem(&r)
	}

	return data, int(count), nil
}

// Item returns a single collected item by ID.
func (s *Store) Item(ctx context.Context, id uuid.UUID) (*Item, error) {
	r, err := s.q.CollectedDataByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying collected data %s: %w", id, err)
	}
	d := datumToItem(&r)
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

// CreateItem inserts a new collected item.
func (s *Store) CreateItem(ctx context.Context, p *CreateParams) (*Item, error) {
	r, err := s.q.CreateCollectedData(ctx, db.CreateCollectedDataParams{
		SourceUrl:       p.SourceURL,
		SourceName:      p.SourceName,
		Title:           p.Title,
		OriginalContent: p.OriginalContent,
		Topics:          p.Topics,
		UrlHash:         p.URLHash,
		FeedID:          p.FeedID,
		RelevanceScore:  p.RelevanceScore,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating collected data: %w", err)
	}
	d := datumToItem(&r)
	return &d, nil
}

// ItemByURLHash returns a single collected item by URL hash.
func (s *Store) ItemByURLHash(ctx context.Context, urlHash string) (*Item, error) {
	r, err := s.q.CollectedDataByURLHash(ctx, urlHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying collected data by url hash %s: %w", urlHash, err)
	}
	d := datumToItem(&r)
	return &d, nil
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

// RecentCollectedData returns recently collected items in a time range, ordered by collected_at DESC.
func (s *Store) RecentCollectedData(ctx context.Context, start, end time.Time, limit int32) ([]Item, error) {
	rows, err := s.q.RecentCollectedData(ctx, db.RecentCollectedDataParams{
		CollectedAt:   start,
		CollectedAt_2: end,
		Limit:         limit,
	})
	if err != nil {
		return nil, fmt.Errorf("listing recent collected data: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		data[i] = datumToItem(&rows[i])
	}
	return data, nil
}

// LatestCollectedData returns the latest collected items, optionally filtered by a since timestamp.
// When since is nil, returns the latest maxResults items regardless of time.
func (s *Store) LatestCollectedData(ctx context.Context, since *time.Time, maxResults int32) ([]Item, error) {
	rows, err := s.q.LatestCollectedData(ctx, db.LatestCollectedDataParams{
		Since:      since,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing latest collected data: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		data[i] = datumToItem(&rows[i])
	}
	return data, nil
}

// TopRelevantCollected returns unread collected items with relevance > 0.5 since the given time.
func (s *Store) TopRelevantCollected(ctx context.Context, since time.Time, maxResults int32) ([]Item, error) {
	rows, err := s.q.TopRelevantCollected(ctx, db.TopRelevantCollectedParams{
		Since:      since,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing top relevant collected data: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		data[i] = datumToItem(&rows[i])
	}
	return data, nil
}

// DeleteOldIgnored deletes ignored collected data with collected_at before cutoff.
// Returns the number of rows deleted.
func (s *Store) DeleteOldIgnored(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := s.q.DeleteOldIgnored(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("deleting old ignored collected data: %w", err)
	}
	return n, nil
}

// datumToItem converts a db.CollectedDatum to Item.
func datumToItem(r *db.CollectedDatum) Item {
	return Item{
		ID:               r.ID,
		SourceURL:        r.SourceUrl,
		SourceName:       r.SourceName,
		Title:            r.Title,
		OriginalContent:  r.OriginalContent,
		RelevanceScore:   r.RelevanceScore,
		Topics:           r.Topics,
		Status:           Status(r.Status),
		CuratedContentID: r.CuratedContentID,
		CollectedAt:      r.CollectedAt,
		URLHash:          r.UrlHash,
		UserFeedback:     r.UserFeedback,
		FeedbackAt:       r.FeedbackAt,
		FeedID:           r.FeedID,
	}
}
