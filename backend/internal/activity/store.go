package activity

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store manages activity events in the database.
type Store struct {
	q *db.Queries
}

// NewStore returns an activity Store backed by the given connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a new Store that uses the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// CreateEvent inserts an activity event and returns its ID.
// Returns the existing event ID on dedup hit (via ON CONFLICT DO UPDATE no-op).
// This is idempotent: re-inserting the same event returns the same ID.
func (s *Store) CreateEvent(ctx context.Context, p RecordParams) (int64, error) {
	id, err := s.q.CreateEvent(ctx, db.CreateEventParams{
		SourceID:  p.SourceID,
		Timestamp: p.Timestamp,
		EventType: p.EventType,
		Source:    p.Source,
		Project:   p.Project,
		Repo:      p.Repo,
		Ref:       p.Ref,
		Title:     p.Title,
		Body:      p.Body,
		Metadata:  p.Metadata,
	})
	if err != nil {
		return 0, fmt.Errorf("creating activity event: %w", err)
	}
	return id, nil
}

// EventsByTimeRange returns all activity events within [start, end).
func (s *Store) EventsByTimeRange(ctx context.Context, start, end time.Time) ([]Event, error) {
	rows, err := s.q.EventsByTimeRange(ctx, db.EventsByTimeRangeParams{
		StartTime: start,
		EndTime:   end,
	})
	if err != nil {
		return nil, fmt.Errorf("querying events by time range: %w", err)
	}
	events := make([]Event, len(rows))
	for i, r := range rows {
		events[i] = Event{
			ID:        r.ID,
			SourceID:  r.SourceID,
			Timestamp: r.Timestamp,
			EventType: r.EventType,
			Source:    r.Source,
			Project:   r.Project,
			Repo:      r.Repo,
			Ref:       r.Ref,
			Title:     r.Title,
			Body:      r.Body,
			Metadata:  r.Metadata,
			CreatedAt: r.CreatedAt,
		}
	}
	return events, nil
}

// EventsByFilters returns activity events within [start, end) with optional source and project filters.
func (s *Store) EventsByFilters(ctx context.Context, start, end time.Time, source, project *string, limit int) ([]Event, error) {
	rows, err := s.q.EventsByFilters(ctx, db.EventsByFiltersParams{
		StartTime:     start,
		EndTime:       end,
		FilterSource:  source,
		FilterProject: project,
		MaxResults:    int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying events by filters: %w", err)
	}
	events := make([]Event, len(rows))
	for i, r := range rows {
		events[i] = Event{
			ID:        r.ID,
			SourceID:  r.SourceID,
			Timestamp: r.Timestamp,
			EventType: r.EventType,
			Source:    r.Source,
			Project:   r.Project,
			Repo:      r.Repo,
			Ref:       r.Ref,
			Title:     r.Title,
			Body:      r.Body,
			Metadata:  r.Metadata,
			CreatedAt: r.CreatedAt,
		}
	}
	return events, nil
}

// EventsByProject returns recent activity events for a specific project name.
func (s *Store) EventsByProject(ctx context.Context, projectName string, limit int) ([]Event, error) {
	rows, err := s.q.EventsByProject(ctx, db.EventsByProjectParams{
		ProjectName: &projectName,
		MaxResults:  int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying events by project %s: %w", projectName, err)
	}
	events := make([]Event, len(rows))
	for i, r := range rows {
		events[i] = Event{
			ID:        r.ID,
			SourceID:  r.SourceID,
			Timestamp: r.Timestamp,
			EventType: r.EventType,
			Source:    r.Source,
			Project:   r.Project,
			Repo:      r.Repo,
			Ref:       r.Ref,
			Title:     r.Title,
			Body:      r.Body,
			Metadata:  r.Metadata,
			CreatedAt: r.CreatedAt,
		}
	}
	return events, nil
}

// SyncEventTags links an activity event to canonical tags.
// Duplicate associations are silently ignored via ON CONFLICT DO NOTHING.
// Best-effort: inserts as many as possible, returns the first non-conflict error.
func (s *Store) SyncEventTags(ctx context.Context, eventID int64, tagIDs []uuid.UUID) error {
	var firstErr error
	for _, tagID := range tagIDs {
		if err := s.q.InsertEventTag(ctx, db.InsertEventTagParams{
			EventID: eventID,
			TagID:   tagID,
		}); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("inserting event tag (event %d, tag %s): %w", eventID, tagID, err)
		}
	}
	return firstErr
}
