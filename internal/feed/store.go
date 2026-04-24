// store.go holds Store methods for the feeds table and the
// feed_topics junction.
//
// Transactional contract: any mutation that writes both the feed row
// and the junction (Create, Update with TopicIDs) requires a
// tx-bound Store — the two writes must not split across connections.
// A non-tx Store surfaces ErrNotTransactional on those paths rather
// than silently half-writing. Admin HTTP callers get the tx through
// api.ActorMiddleware; background callers must open their own.

package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for feeds.
type Store struct {
	dbtx   db.DBTX
	q      *db.Queries
	logger *slog.Logger
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX, logger *slog.Logger) *Store {
	return &Store{dbtx: dbtx, q: db.New(dbtx), logger: logger}
}

// WithTx returns a Store that uses tx for all queries. Matches the
// project-wide convention where every feature store exposes WithTx
// so callers can compose multi-store transactions at the handler or
// job layer. Required prereq for actor middleware (which must SET
// LOCAL koopa.actor on the same connection as the mutation) and for
// atomic feed+feed_topics junction writes.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{
		dbtx:   tx,
		q:      s.q.WithTx(tx),
		logger: s.logger,
	}
}

// Feeds returns all feeds, optionally filtered by schedule.
func (s *Store) Feeds(ctx context.Context, schedule *string) ([]Feed, error) {
	rows, err := s.q.Feeds(ctx, schedule)
	if err != nil {
		return nil, fmt.Errorf("listing feeds: %w", err)
	}
	feeds := make([]Feed, len(rows))
	for i := range rows {
		r := &rows[i]
		feeds[i] = Feed{
			ID:                  r.ID,
			URL:                 r.Url,
			Name:                r.Name,
			Schedule:            r.Schedule,
			Topics:              r.Topics,
			Enabled:             r.Enabled,
			Priority:            r.Priority,
			Etag:                derefStr(r.Etag),
			LastModified:        derefStr(r.LastModified),
			LastFetchedAt:       r.LastFetchedAt,
			ConsecutiveFailures: int(r.ConsecutiveFailures),
			LastError:           derefStr(r.LastError),
			DisabledReason:      derefStr(r.DisabledReason),
			Filter:              ParseFilterConfig(r.FilterConfig),
			CreatedAt:           r.CreatedAt,
			UpdatedAt:           r.UpdatedAt,
		}
	}
	return feeds, nil
}

// Feed returns a single feed by ID.
func (s *Store) Feed(ctx context.Context, id uuid.UUID) (*Feed, error) {
	r, err := s.q.FeedByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying feed %s: %w", id, err)
	}
	f := Feed{
		ID:                  r.ID,
		URL:                 r.Url,
		Name:                r.Name,
		Schedule:            r.Schedule,
		Topics:              r.Topics,
		Enabled:             r.Enabled,
		Priority:            r.Priority,
		Etag:                derefStr(r.Etag),
		LastModified:        derefStr(r.LastModified),
		LastFetchedAt:       r.LastFetchedAt,
		ConsecutiveFailures: int(r.ConsecutiveFailures),
		LastError:           derefStr(r.LastError),
		DisabledReason:      derefStr(r.DisabledReason),
		Filter:              ParseFilterConfig(r.FilterConfig),
		CreatedAt:           r.CreatedAt,
		UpdatedAt:           r.UpdatedAt,
	}
	return &f, nil
}

// EnabledFeeds returns all enabled feeds regardless of schedule.
func (s *Store) EnabledFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.q.EnabledFeeds(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing enabled feeds: %w", err)
	}
	feeds := make([]Feed, len(rows))
	for i := range rows {
		r := rows[i]
		feeds[i] = dbToFeed(&r)
	}
	return feeds, nil
}

// EnabledFeedsBySchedule returns all enabled feeds for the given schedule.
func (s *Store) EnabledFeedsBySchedule(ctx context.Context, schedule string) ([]Feed, error) {
	rows, err := s.q.EnabledFeedsBySchedule(ctx, schedule)
	if err != nil {
		return nil, fmt.Errorf("listing enabled feeds for schedule %s: %w", schedule, err)
	}
	feeds := make([]Feed, len(rows))
	for i := range rows {
		r := rows[i]
		feeds[i] = dbToFeed(&r)
	}
	return feeds, nil
}

// CreateFeed inserts a new feed and, when p.TopicIDs is non-empty, writes
// the feed_topics junction rows atomically with the feed insert.
//
// Atomicity contract: feed_topics writes must run on the same transaction
// as the feed insert so a FK violation on topic_id rolls back the feed
// row. The caller achieves this by first calling s.WithTx(tx) — every
// admin-mounted route does this via api.TxFromContext + ActorMiddleware,
// so production traffic is always transactional. If TopicIDs is non-empty
// and the store was not bound to a transaction, CreateFeed returns
// ErrNotTransactional before touching the database; this surfaces wiring
// bugs as 500s instead of silent partial writes.
func (s *Store) CreateFeed(ctx context.Context, p *CreateParams) (*Feed, error) {
	if len(p.TopicIDs) > 0 {
		if _, ok := s.dbtx.(pgx.Tx); !ok {
			return nil, ErrNotTransactional
		}
	}
	filterJSON, err := json.Marshal(p.Filter)
	if err != nil {
		return nil, fmt.Errorf("marshaling filter config: %w", err)
	}
	r, err := s.q.CreateFeed(ctx, db.CreateFeedParams{
		Url:          p.URL,
		Name:         p.Name,
		Schedule:     p.Schedule,
		FilterConfig: filterJSON,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating feed: %w", err)
	}

	if len(p.TopicIDs) > 0 {
		if err := s.q.InsertFeedTopics(ctx, db.InsertFeedTopicsParams{
			FeedID:   r.ID,
			TopicIds: p.TopicIDs,
		}); err != nil {
			return nil, mapFeedTopicsInsertError(err)
		}
	}

	f := dbToFeed(&r)
	return &f, nil
}

// UpdateFeed updates a feed and, when p.TopicIDs is non-nil, replaces the
// feed_topics junction atomically with the feed update. See CreateFeed
// for the atomicity contract — the same requirement applies here. If the
// caller passes a non-nil TopicIDs on a non-transactional store, UpdateFeed
// returns ErrNotTransactional before touching the database so wiring bugs
// surface as 500s instead of partial DELETE-without-INSERT states.
//
// TopicIDs semantics:
//   - nil        — junction untouched
//   - empty ([]) — DELETE only, leaving the feed with zero topics
//   - populated  — DELETE then INSERT of the new set
func (s *Store) UpdateFeed(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Feed, error) {
	if p.TopicIDs != nil {
		if _, ok := s.dbtx.(pgx.Tx); !ok {
			return nil, ErrNotTransactional
		}
	}
	var filterJSON json.RawMessage
	if p.Filter != nil {
		var err error
		filterJSON, err = json.Marshal(p.Filter)
		if err != nil {
			return nil, fmt.Errorf("marshaling filter config: %w", err)
		}
	}
	r, err := s.q.UpdateFeed(ctx, db.UpdateFeedParams{
		ID:           id,
		Url:          p.URL,
		Name:         p.Name,
		Schedule:     p.Schedule,
		Enabled:      p.Enabled,
		FilterConfig: filterJSON,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("updating feed %s: %w", id, err)
	}

	if err := s.replaceFeedTopics(ctx, r.ID, p.TopicIDs); err != nil {
		return nil, err
	}

	f := dbToFeed(&r)
	return &f, nil
}

// replaceFeedTopics implements the nil-vs-empty-vs-populated contract
// documented on UpdateParams.TopicIDs: nil is a no-op, empty clears the
// junction, populated clears then inserts. Split out of UpdateFeed so the
// caller stays a simple linear happy-path.
func (s *Store) replaceFeedTopics(ctx context.Context, feedID uuid.UUID, topicIDs []uuid.UUID) error {
	if topicIDs == nil {
		return nil
	}
	if err := s.q.DeleteFeedTopics(ctx, feedID); err != nil {
		return fmt.Errorf("clearing feed topics for %s: %w", feedID, err)
	}
	if len(topicIDs) == 0 {
		return nil
	}
	if err := s.q.InsertFeedTopics(ctx, db.InsertFeedTopicsParams{
		FeedID:   feedID,
		TopicIds: topicIDs,
	}); err != nil {
		return mapFeedTopicsInsertError(err)
	}
	return nil
}

// mapFeedTopicsInsertError translates a PostgreSQL error from a
// feed_topics insert into a feature sentinel. A 23503
// (foreign_key_violation) on topic_id means the caller passed an id
// that doesn't reference an existing topic; return ErrTopicNotFound so
// the handler can surface a 400 without leaking the FK constraint name.
// Any other error wraps the original with context.
func mapFeedTopicsInsertError(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.ForeignKeyViolation {
		return ErrTopicNotFound
	}
	return fmt.Errorf("inserting feed topics: %w", err)
}

// DeleteFeed deletes a feed by ID.
func (s *Store) DeleteFeed(ctx context.Context, id uuid.UUID) error {
	err := s.q.DeleteFeed(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting feed %s: %w", id, err)
	}
	return nil
}

// IncrementFailure increments the failure counter and auto-disables when threshold is reached.
func (s *Store) IncrementFailure(ctx context.Context, id uuid.UUID, errMsg string) error {
	failures, err := s.q.IncrementFeedFailure(ctx, db.IncrementFeedFailureParams{
		ID:        id,
		LastError: &errMsg,
	})
	if err != nil {
		return fmt.Errorf("incrementing feed failure %s: %w", id, err)
	}

	if failures < MaxConsecutiveFailures {
		return nil
	}

	reason := fmt.Sprintf("auto-disabled: %d consecutive failures", MaxConsecutiveFailures)
	s.logger.Warn("auto-disabling feed", "feed_id", id, "failures", failures)
	if err := s.q.AutoDisableFeed(ctx, db.AutoDisableFeedParams{
		ID:             id,
		DisabledReason: &reason,
	}); err != nil {
		return fmt.Errorf("auto-disabling feed %s: %w", id, err)
	}

	return nil
}

// ResetFailure resets the failure counter and updates etag/last-modified.
func (s *Store) ResetFailure(ctx context.Context, id uuid.UUID, etag, lastModified string) error {
	if err := s.q.ResetFeedFailure(ctx, db.ResetFeedFailureParams{
		ID:           id,
		Etag:         &etag,
		LastModified: &lastModified,
	}); err != nil {
		return fmt.Errorf("resetting feed failure %s: %w", id, err)
	}
	return nil
}

// dbToFeed converts a db.Feed to Feed.
func dbToFeed(r *db.Feed) Feed {
	return Feed{
		ID:                  r.ID,
		URL:                 r.Url,
		Name:                r.Name,
		Schedule:            r.Schedule,
		Enabled:             r.Enabled,
		Priority:            r.Priority,
		Etag:                derefStr(r.Etag),
		LastModified:        derefStr(r.LastModified),
		LastFetchedAt:       r.LastFetchedAt,
		ConsecutiveFailures: int(r.ConsecutiveFailures),
		LastError:           derefStr(r.LastError),
		DisabledReason:      derefStr(r.DisabledReason),
		Filter:              ParseFilterConfig(r.FilterConfig),
		CreatedAt:           r.CreatedAt,
		UpdatedAt:           r.UpdatedAt,
	}
}

// derefStr safely dereferences a *string, returning "" for nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
