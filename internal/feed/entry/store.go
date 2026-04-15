package entry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// nullCollectedStatus converts a *string to db.NullFeedEntryStatus.
func nullCollectedStatus(s *string) db.NullFeedEntryStatus {
	if s == nil {
		return db.NullFeedEntryStatus{}
	}
	return db.NullFeedEntryStatus{FeedEntryStatus: db.FeedEntryStatus(*s), Valid: true}
}

// Store handles database operations for collected data.
type Store struct {
	q    *db.Queries
	dbtx db.DBTX
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx), dbtx: dbtx}
}

// Items returns a paginated list of collected items.
func (s *Store) Items(ctx context.Context, f Filter) ([]Item, int, error) {
	status := nullCollectedStatus(f.Status)
	limit := int32(f.PerPage)                 // #nosec G115 -- pagination values are bounded by API layer
	offset := int32((f.Page - 1) * f.PerPage) // #nosec G115 -- pagination values are bounded by API layer

	if f.Sort == "relevance" {
		rows, err := s.q.CollectedDataByRelevance(ctx, db.CollectedDataByRelevanceParams{
			Limit:  limit,
			Offset: offset,
			Status: status,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("listing collected data: %w", err)
		}
		count, err := s.q.CollectedDataCount(ctx, status)
		if err != nil {
			return nil, 0, fmt.Errorf("counting collected data: %w", err)
		}
		data := make([]Item, len(rows))
		for i := range rows {
			r := &rows[i]
			data[i] = rowToItem(collectedRow{
				ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
				RelevanceScore: r.RelevanceScore, Status: r.Status,
				CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
				UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
				PublishedAt: r.PublishedAt, FeedName: r.FeedName,
			})
		}
		return data, int(count), nil
	}

	rows, err := s.q.CollectedData(ctx, db.CollectedDataParams{
		Limit:  limit,
		Offset: offset,
		Status: status,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing collected data: %w", err)
	}
	count, err := s.q.CollectedDataCount(ctx, status)
	if err != nil {
		return nil, 0, fmt.Errorf("counting collected data: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			RelevanceScore: r.RelevanceScore, Status: r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
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
	d := rowToItem(collectedRow{
		ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
		RelevanceScore: r.RelevanceScore, Status: r.Status,
		CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
		UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
		PublishedAt: r.PublishedAt, FeedName: r.FeedName,
	})
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
		Title:           p.Title,
		OriginalContent: p.OriginalContent,
		UrlHash:         p.URLHash,
		FeedID:          p.FeedID,
		RelevanceScore:  p.RelevanceScore,
		PublishedAt:     p.PublishedAt,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
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
	d := rowToItem(collectedRow{
		ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
		RelevanceScore: r.RelevanceScore, Status: r.Status,
		CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
		UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
		PublishedAt: r.PublishedAt, FeedName: r.FeedName,
	})
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
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			RelevanceScore: r.RelevanceScore, Status: r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
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
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			RelevanceScore: r.RelevanceScore, Status: r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
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
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			RelevanceScore: r.RelevanceScore, Status: r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
	}
	return data, nil
}

// LatestByRecency returns collected items ordered by recency, optionally filtered by time.
func (s *Store) LatestByRecency(ctx context.Context, since *time.Time, maxResults int32) ([]Item, error) {
	rows, err := s.q.LatestCollectedByRecency(ctx, db.LatestCollectedByRecencyParams{
		Since:      since,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing collected data by recency: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			RelevanceScore: r.RelevanceScore, Status: r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
	}
	return data, nil
}

// HighPriorityRecent returns unread items from high-priority feeds since the given time.
func (s *Store) HighPriorityRecent(ctx context.Context, since time.Time, maxResults int32) ([]Item, error) {
	rows, err := s.q.HighPriorityRecentCollected(ctx, db.HighPriorityRecentCollectedParams{
		Since:      since,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing high priority collected data: %w", err)
	}
	data := make([]Item, len(rows))
	for i := range rows {
		r := &rows[i]
		data[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			RelevanceScore: r.RelevanceScore, Status: r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
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

// TopItems returns the top N highest-scoring unread items from the last 7 days.
func (s *Store) TopItems(ctx context.Context, limit int) ([]Item, error) {
	since := time.Now().AddDate(0, 0, -7)
	rows, err := s.q.TopRelevantCollected(ctx, db.TopRelevantCollectedParams{
		Since:      since,
		MaxResults: int32(limit), // #nosec G115 -- limit bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("listing top collected items: %w", err)
	}
	items := make([]Item, len(rows))
	for i := range rows {
		r := &rows[i]
		items[i] = rowToItem(collectedRow{
			ID: r.ID, SourceUrl: r.SourceUrl, Title: r.Title, OriginalContent: r.OriginalContent,
			RelevanceScore: r.RelevanceScore, Status: r.Status,
			CuratedContentID: r.CuratedContentID, CollectedAt: r.CollectedAt, UrlHash: r.UrlHash,
			UserFeedback: r.UserFeedback, FeedbackAt: r.FeedbackAt, FeedID: r.FeedID,
			PublishedAt: r.PublishedAt, FeedName: r.FeedName,
		})
	}
	return items, nil
}

// collectedRow is the common field set shared by all sqlc-generated collected data
// row types. Each query returns a different Row type (CollectedDataRow, LatestCollectedDataRow, etc.)
// but they all share the same fields including FeedName from the LEFT JOIN.
type collectedRow struct {
	ID               uuid.UUID
	SourceUrl        string //nolint:staticcheck,revive // matches sqlc-generated field name
	Title            string
	OriginalContent  string
	RelevanceScore   float64
	Status           db.FeedEntryStatus
	CuratedContentID *uuid.UUID
	CollectedAt      time.Time
	UrlHash          string //nolint:staticcheck,revive // matches sqlc-generated field name
	UserFeedback     *string
	FeedbackAt       *time.Time
	FeedID           *uuid.UUID
	PublishedAt      *time.Time
	FeedName         string
}

func rowToItem(r collectedRow) Item { //nolint:gocritic // hugeParam: struct passed by value matches codebase pattern
	return Item{
		ID:               r.ID,
		SourceURL:        r.SourceUrl,
		FeedName:         r.FeedName,
		Title:            r.Title,
		OriginalContent:  &r.OriginalContent,
		RelevanceScore:   r.RelevanceScore,
		Status:           Status(r.Status),
		CuratedContentID: r.CuratedContentID,
		CollectedAt:      r.CollectedAt,
		PublishedAt:      r.PublishedAt,
		URLHash:          r.UrlHash,
		UserFeedback:     r.UserFeedback,
		FeedbackAt:       r.FeedbackAt,
		FeedID:           r.FeedID,
	}
}

// datumToItem converts a db.FeedEntry to Item (used for CreateCollectedData which returns FeedEntry).
func datumToItem(r *db.FeedEntry) Item {
	return Item{
		ID:               r.ID,
		SourceURL:        r.SourceUrl,
		Title:            r.Title,
		OriginalContent:  &r.OriginalContent,
		RelevanceScore:   r.RelevanceScore,
		Status:           Status(r.Status),
		CuratedContentID: r.CuratedContentID,
		CollectedAt:      r.CollectedAt,
		PublishedAt:      r.PublishedAt,
		URLHash:          r.UrlHash,
		UserFeedback:     r.UserFeedback,
		FeedbackAt:       r.FeedbackAt,
		FeedID:           r.FeedID,
	}
}

// CollectionStats returns per-feed and global collection statistics for
// the window [now-days, now). The optional feedID restricts both queries
// to a single feed. Both queries are sqlc-generated.
func (s *Store) CollectionStats(ctx context.Context, feedID *uuid.UUID, days int) (*Stats, error) {
	cutoff := time.Now().AddDate(0, 0, -days)

	rows, err := s.q.CollectionStatsByFeed(ctx, db.CollectionStatsByFeedParams{
		Cutoff: cutoff,
		FeedID: feedID,
	})
	if err != nil {
		return nil, fmt.Errorf("querying per-feed stats: %w", err)
	}
	feeds := make([]FeedStat, len(rows))
	for i := range rows {
		var lastCollected *time.Time
		if !rows[i].LastCollectedAt.IsZero() {
			t := rows[i].LastCollectedAt
			lastCollected = &t
		}
		feeds[i] = FeedStat{
			FeedID:          rows[i].ID,
			FeedName:        rows[i].Name,
			TotalItems:      int(rows[i].TotalItems),
			AvgScore:        rows[i].AvgScore,
			LastCollectedAt: lastCollected,
		}
	}

	g, err := s.q.CollectionStatsGlobal(ctx, db.CollectionStatsGlobalParams{
		Cutoff: cutoff,
		FeedID: feedID,
	})
	if err != nil {
		return nil, fmt.Errorf("querying global stats: %w", err)
	}

	return &Stats{
		Feeds: feeds,
		Global: GlobalStat{
			TotalItems:   int(g.TotalItems),
			TotalFeeds:   int(g.TotalFeeds),
			AvgScore:     g.AvgScore,
			UnreadCount:  int(g.UnreadCount),
			CuratedCount: int(g.CuratedCount),
		},
	}, nil
}
