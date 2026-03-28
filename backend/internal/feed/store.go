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

	"github.com/koopa0/blog-backend/internal/db"
)

// AlertSender sends alert notifications when feeds are auto-disabled.
type AlertSender interface {
	Send(ctx context.Context, text string) error
}

// Store handles database operations for feeds.
type Store struct {
	q      *db.Queries
	alerts AlertSender
	logger *slog.Logger
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX, logger *slog.Logger) *Store {
	return &Store{q: db.New(dbtx), logger: logger}
}

// SetAlerts sets the alert sender for auto-disable notifications.
func (s *Store) SetAlerts(alerts AlertSender) {
	s.alerts = alerts
}

// Feeds returns all feeds, optionally filtered by schedule.
func (s *Store) Feeds(ctx context.Context, schedule *string) ([]Feed, error) {
	rows, err := s.q.Feeds(ctx, schedule)
	if err != nil {
		return nil, fmt.Errorf("listing feeds: %w", err)
	}
	feeds := make([]Feed, len(rows))
	for i := range rows {
		r := rows[i]
		feeds[i] = dbToFeed(&r)
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
	f := dbToFeed(&r)
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

// CreateFeed inserts a new feed.
func (s *Store) CreateFeed(ctx context.Context, p *CreateParams) (*Feed, error) {
	topics := p.Topics
	if topics == nil {
		topics = []string{}
	}
	filterJSON, err := json.Marshal(p.Filter)
	if err != nil {
		return nil, fmt.Errorf("marshaling filter config: %w", err)
	}
	r, err := s.q.CreateFeed(ctx, db.CreateFeedParams{
		Url:          p.URL,
		Name:         p.Name,
		Schedule:     p.Schedule,
		Topics:       topics,
		FilterConfig: filterJSON,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("creating feed: %w", err)
	}
	f := dbToFeed(&r)
	return &f, nil
}

// UpdateFeed updates a feed.
func (s *Store) UpdateFeed(ctx context.Context, id uuid.UUID, p *UpdateParams) (*Feed, error) {
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
		Topics:       p.Topics,
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
	f := dbToFeed(&r)
	return &f, nil
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
		LastError: errMsg,
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
		DisabledReason: reason,
	}); err != nil {
		return fmt.Errorf("auto-disabling feed %s: %w", id, err)
	}

	if s.alerts != nil {
		msg := fmt.Sprintf("[ALERT] Feed auto-disabled\nFeed ID: %s\nFailures: %d\nLast error: %s",
			id, failures, errMsg)
		if sendErr := s.alerts.Send(ctx, msg); sendErr != nil {
			s.logger.Error("sending feed disable alert", "feed_id", id, "error", sendErr)
		}
	}

	return nil
}

// ResetFailure resets the failure counter and updates etag/last-modified.
func (s *Store) ResetFailure(ctx context.Context, id uuid.UUID, etag, lastModified string) error {
	if err := s.q.ResetFeedFailure(ctx, db.ResetFeedFailureParams{
		ID:           id,
		Etag:         etag,
		LastModified: lastModified,
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
		Topics:              r.Topics,
		Enabled:             r.Enabled,
		Priority:            r.Priority,
		Etag:                r.Etag,
		LastModified:        r.LastModified,
		LastFetchedAt:       r.LastFetchedAt,
		ConsecutiveFailures: int(r.ConsecutiveFailures),
		LastError:           r.LastError,
		DisabledReason:      r.DisabledReason,
		Filter:              ParseFilterConfig(r.FilterConfig),
		CreatedAt:           r.CreatedAt,
		UpdatedAt:           r.UpdatedAt,
	}
}
