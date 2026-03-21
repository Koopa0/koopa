package flowrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store handles database operations for flow runs.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// CreateRun inserts a new flow run with status pending.
func (s *Store) CreateRun(ctx context.Context, flowName string, input json.RawMessage, contentID *uuid.UUID) (*Run, error) {
	r, err := s.q.CreateFlowRun(ctx, db.CreateFlowRunParams{
		FlowName:  flowName,
		ContentID: contentID,
		Input:     input,
	})
	if err != nil {
		return nil, fmt.Errorf("creating flow run: %w", err)
	}
	return dbToRun(r), nil
}

// PendingRunExists returns true if a pending or running flow run exists
// for the given flow name and content ID.
func (s *Store) PendingRunExists(ctx context.Context, flowName string, contentID *uuid.UUID) (bool, error) {
	exists, err := s.q.PendingRunExists(ctx, db.PendingRunExistsParams{
		FlowName:  flowName,
		ContentID: contentID,
	})
	if err != nil {
		return false, fmt.Errorf("checking pending run for %s: %w", flowName, err)
	}
	return exists, nil
}

// LatestCompletedRun returns the most recently completed flow run for
// a given flow name and content ID.
func (s *Store) LatestCompletedRun(ctx context.Context, flowName string, contentID uuid.UUID) (*Run, error) {
	r, err := s.q.LatestCompletedRunByContentAndFlow(ctx, db.LatestCompletedRunByContentAndFlowParams{
		FlowName:  flowName,
		ContentID: &contentID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying latest completed run: %w", err)
	}
	return dbToRun(r), nil
}

// Run returns a single flow run by ID.
func (s *Store) Run(ctx context.Context, id uuid.UUID) (*Run, error) {
	r, err := s.q.FlowRunByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying flow run %s: %w", id, err)
	}
	return dbToRun(r), nil
}

// Runs returns a paginated list of flow runs.
func (s *Store) Runs(ctx context.Context, f Filter) ([]Run, int, error) {
	var status db.NullFlowStatus
	if f.Status != nil {
		status = db.NullFlowStatus{FlowStatus: db.FlowStatus(*f.Status), Valid: true}
	}

	rows, err := s.q.FlowRuns(ctx, db.FlowRunsParams{
		Limit:  int32(f.PerPage),                // #nosec G115 -- pagination values are bounded by API layer
		Offset: int32((f.Page - 1) * f.PerPage), // #nosec G115 -- pagination values are bounded by API layer
		Status: status,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("listing flow runs: %w", err)
	}

	count, err := s.q.FlowRunsCount(ctx, status)
	if err != nil {
		return nil, 0, fmt.Errorf("counting flow runs: %w", err)
	}

	runs := make([]Run, len(rows))
	for i, r := range rows {
		runs[i] = *dbToRun(r)
	}
	return runs, int(count), nil
}

// UpdateRunning marks a flow run as running and increments the attempt counter.
func (s *Store) UpdateRunning(ctx context.Context, id uuid.UUID) error {
	err := s.q.UpdateFlowRunRunning(ctx, id)
	if err != nil {
		return fmt.Errorf("updating flow run %s to running: %w", id, err)
	}
	return nil
}

// UpdateCompleted marks a flow run as completed with output.
func (s *Store) UpdateCompleted(ctx context.Context, id uuid.UUID, output json.RawMessage) error {
	err := s.q.UpdateFlowRunCompleted(ctx, db.UpdateFlowRunCompletedParams{
		ID:     id,
		Output: output,
	})
	if err != nil {
		return fmt.Errorf("updating flow run %s to completed: %w", id, err)
	}
	return nil
}

// UpdateFailed marks a flow run as failed with an error message.
func (s *Store) UpdateFailed(ctx context.Context, id uuid.UUID, errMsg string) error {
	err := s.q.UpdateFlowRunFailed(ctx, db.UpdateFlowRunFailedParams{
		ID:    id,
		Error: &errMsg,
	})
	if err != nil {
		return fmt.Errorf("updating flow run %s to failed: %w", id, err)
	}
	return nil
}

// RetryableRuns atomically resets failed and stuck-pending runs to pending status
// and returns them. Uses UPDATE...RETURNING to prevent duplicate pickup by concurrent cron ticks.
func (s *Store) RetryableRuns(ctx context.Context) ([]Run, error) {
	rows, err := s.q.RetryableFlowRuns(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching retryable flow runs: %w", err)
	}
	runs := make([]Run, len(rows))
	for i, r := range rows {
		runs[i] = *dbToRun(r)
	}
	return runs, nil
}

// DeleteOldCompletedRuns deletes completed/failed flow runs with created_at before cutoff.
// Returns the number of rows deleted.
func (s *Store) DeleteOldCompletedRuns(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := s.q.DeleteOldCompletedRuns(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("deleting old completed flow runs: %w", err)
	}
	return n, nil
}

// FlowFailureStat holds per-flow failure counts.
type FlowFailureStat struct {
	FlowName string
	Total    int64
	Failed   int64
}

// FailureStats returns per-flow failure counts since the given time.
func (s *Store) FailureStats(ctx context.Context, since time.Time) ([]FlowFailureStat, error) {
	rows, err := s.q.FlowFailureStats(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("querying flow failure stats: %w", err)
	}
	stats := make([]FlowFailureStat, len(rows))
	for i, r := range rows {
		stats[i] = FlowFailureStat{
			FlowName: r.FlowName,
			Total:    r.Total,
			Failed:   r.Failed,
		}
	}
	return stats, nil
}

func dbToRun(r db.FlowRun) *Run {
	return &Run{
		ID:          r.ID,
		FlowName:    r.FlowName,
		ContentID:   r.ContentID,
		Input:       json.RawMessage(r.Input),
		Output:      r.Output,
		Status:      Status(r.Status),
		Error:       r.Error,
		Attempt:     int(r.Attempt),
		MaxAttempts: int(r.MaxAttempts),
		StartedAt:   r.StartedAt,
		EndedAt:     r.EndedAt,
		CreatedAt:   r.CreatedAt,
	}
}
