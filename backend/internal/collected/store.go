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
		data[i] = datumToItem(&rows[i])
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
		items[i] = datumToItem(&rows[i])
	}
	return items, nil
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

// CollectionStats returns per-feed and global collection statistics.
// Raw SQL is required: this aggregation joins collected_data and feeds tables
// with GROUP BY, which cannot be expressed efficiently via sqlc-generated queries.
// Parameters use pgx placeholders ($1, $2), no string interpolation.
func (s *Store) CollectionStats(ctx context.Context, feedID *uuid.UUID, days int) (*Stats, error) {
	cutoff := time.Now().AddDate(0, 0, -days)

	// Per-feed stats
	feedQuery := `
		SELECT f.id, f.name,
		       COUNT(cd.id)::int AS total_items,
		       COALESCE(AVG(cd.relevance_score), 0) AS avg_score,
		       MAX(cd.collected_at) AS last_collected_at
		FROM feeds f
		LEFT JOIN collected_data cd ON cd.feed_id = f.id AND cd.collected_at >= $1
	`
	args := []any{cutoff}
	if feedID != nil {
		feedQuery += " WHERE f.id = $2"
		args = append(args, *feedID)
	}
	feedQuery += " GROUP BY f.id, f.name ORDER BY total_items DESC"

	rows, err := s.dbtx.Query(ctx, feedQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("querying per-feed stats: %w", err)
	}
	defer rows.Close()

	var feeds []FeedStat
	for rows.Next() {
		var fs FeedStat
		if err := rows.Scan(&fs.FeedID, &fs.FeedName, &fs.TotalItems, &fs.AvgScore, &fs.LastCollectedAt); err != nil {
			return nil, fmt.Errorf("scanning feed stat: %w", err)
		}
		feeds = append(feeds, fs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating feed stats: %w", err)
	}

	// Global stats
	globalQuery := `
		SELECT COUNT(*)::int AS total_items,
		       COUNT(DISTINCT feed_id)::int AS total_feeds,
		       COALESCE(AVG(relevance_score), 0) AS avg_score,
		       COUNT(*) FILTER (WHERE status = 'unread')::int AS unread_count,
		       COUNT(*) FILTER (WHERE status = 'curated')::int AS curated_count
		FROM collected_data
		WHERE collected_at >= $1
	`
	globalArgs := []any{cutoff}
	if feedID != nil {
		globalQuery += " AND feed_id = $2"
		globalArgs = append(globalArgs, *feedID)
	}

	var g GlobalStat
	row := s.dbtx.QueryRow(ctx, globalQuery, globalArgs...)
	if err := row.Scan(&g.TotalItems, &g.TotalFeeds, &g.AvgScore, &g.UnreadCount, &g.CuratedCount); err != nil {
		return nil, fmt.Errorf("querying global stats: %w", err)
	}

	return &Stats{Feeds: feeds, Global: g}, nil
}
