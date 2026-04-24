package activity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa/internal/db"
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

// EventsByTimeRange returns activity_events within [start, end).
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
			ID:         r.ID,
			EntityID:   nilIfEmpty(r.EntityID),
			Timestamp:  r.Timestamp,
			ChangeKind: r.ChangeKind,
			EntityType: r.EntityType,
			Actor:      r.Actor,
			Project:    r.Project,
			Title:      r.Title,
			Metadata:   json.RawMessage(r.Metadata),
			CreatedAt:  r.CreatedAt,
		}
	}
	return events, nil
}

// EventsByFilters returns activity events within [start, end) with optional
// entity_type, project, and actor filters. entityType matches
// activity_events.entity_type. actors is a multi-value allowlist (nil/empty →
// all actors) matching activity_events.actor.
func (s *Store) EventsByFilters(ctx context.Context, start, end time.Time, entityType, project *string, actors []string, limit int) ([]Event, error) {
	// sqlc maps NULL text[] → empty slice in Go; pass nil explicitly so the
	// query's IS NULL branch fires instead of matching against an empty array.
	var filterActors []string
	if len(actors) > 0 {
		filterActors = actors
	}
	rows, err := s.q.EventsByFilters(ctx, db.EventsByFiltersParams{
		StartTime:        start,
		EndTime:          end,
		FilterEntityType: entityType,
		FilterProject:    project,
		FilterActors:     filterActors,
		MaxResults:       int32(limit), // #nosec G115 -- limit is bounded by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying events by filters: %w", err)
	}
	events := make([]Event, len(rows))
	for i := range rows {
		r := &rows[i]
		events[i] = Event{
			ID:         r.ID,
			EntityID:   nilIfEmpty(r.EntityID),
			Timestamp:  r.Timestamp,
			ChangeKind: r.ChangeKind,
			EntityType: r.EntityType,
			Actor:      r.Actor,
			Project:    r.Project,
			Title:      r.Title,
			Metadata:   json.RawMessage(r.Metadata),
			CreatedAt:  r.CreatedAt,
		}
	}
	return events, nil
}

// nilIfEmpty converts an empty-string NOT NULL column value into the nil
// *string that wire clients expect. Non-empty values are returned as a
// pointer to a copy so callers can retain the value independently of the
// row iteration.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
