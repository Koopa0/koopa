package activity

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
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
func (s *Store) CreateEvent(ctx context.Context, p *RecordParams) (int64, error) {
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
	for i := range rows {
		r := &rows[i]
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
	for i := range rows {
		r := &rows[i]
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
	for i := range rows {
		r := &rows[i]
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

// ProjectCompletion is a per-project task completion count.
type ProjectCompletion struct {
	ProjectTitle string
	Completed    int64
}

// CompletionsByProjectSince counts task completions per project from activity events.
// Unlike task-table queries, this captures recurring task completions
// (which reset to "To Do" and disappear from snapshot queries).
func (s *Store) CompletionsByProjectSince(ctx context.Context, since time.Time) ([]ProjectCompletion, error) {
	rows, err := s.q.CompletionEventsByProjectSince(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("querying completion events: %w", err)
	}
	result := make([]ProjectCompletion, len(rows))
	for i := range rows {
		result[i] = ProjectCompletion{
			ProjectTitle: rows[i].ProjectTitle,
			Completed:    rows[i].Completed,
		}
	}
	return result, nil
}

// DeleteOldEvents deletes activity events with a timestamp before cutoff.
// Returns the number of rows deleted.
func (s *Store) DeleteOldEvents(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := s.q.DeleteOldEvents(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("deleting old events: %w", err)
	}
	return n, nil
}

// SyncEventTags links an activity event to canonical tags via a single bulk insert.
// Duplicate associations are silently ignored via ON CONFLICT DO NOTHING.
func (s *Store) SyncEventTags(ctx context.Context, eventID int64, tagIDs []uuid.UUID) error {
	if len(tagIDs) == 0 {
		return nil
	}
	if err := s.q.InsertEventTags(ctx, db.InsertEventTagsParams{
		EventID: eventID,
		TagIds:  tagIDs,
	}); err != nil {
		return fmt.Errorf("inserting event tags for event %d: %w", eventID, err)
	}
	return nil
}
