package hypothesis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for hypotheses.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// Create inserts a new hypothesis.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Record, error) {
	r, err := s.q.CreateHypothesis(ctx, db.CreateHypothesisParams{
		Author:                p.Author,
		Content:               p.Content,
		Claim:                 p.Claim,
		InvalidationCondition: p.InvalidationCondition,
		Metadata:              p.Metadata,
		ObservedDate:          p.ObservedDate,
	})
	if err != nil {
		return nil, fmt.Errorf("creating hypothesis: %w", err)
	}
	return rowToRecord(&r)
}

// RecordByID returns a single hypothesis by ID.
func (s *Store) RecordByID(ctx context.Context, id int64) (*Record, error) {
	r, err := s.q.HypothesisByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying hypothesis %d: %w", id, err)
	}
	return rowToRecord(&r)
}

// UpdateState updates a hypothesis's lifecycle state.
func (s *Store) UpdateState(ctx context.Context, id int64, state State) (*Record, error) {
	r, err := s.q.UpdateHypothesisState(ctx, db.UpdateHypothesisStateParams{
		ID:    id,
		State: db.HypothesisState(state),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating hypothesis %d state: %w", id, err)
	}
	return rowToRecord(&r)
}

// UpdateMetadata overwrites a hypothesis's metadata blob.
func (s *Store) UpdateMetadata(ctx context.Context, id int64, metadata json.RawMessage) (*Record, error) {
	r, err := s.q.UpdateHypothesisMetadata(ctx, db.UpdateHypothesisMetadataParams{
		ID:       id,
		Metadata: metadata,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating hypothesis %d metadata: %w", id, err)
	}
	return rowToRecord(&r)
}

// Unverified returns up to maxResults unverified hypotheses.
func (s *Store) Unverified(ctx context.Context, maxResults int32) ([]Record, error) {
	rows, err := s.q.UnverifiedHypotheses(ctx, maxResults)
	if err != nil {
		return nil, fmt.Errorf("listing unverified hypotheses: %w", err)
	}
	return rowsToRecords(rows)
}

// ByState returns hypotheses filtered by state (nil = all states).
func (s *Store) ByState(ctx context.Context, state *State, maxResults int32) ([]Record, error) {
	stateArg := db.NullHypothesisState{}
	if state != nil {
		stateArg.HypothesisState = db.HypothesisState(*state)
		stateArg.Valid = true
	}
	rows, err := s.q.HypothesesByState(ctx, db.HypothesesByStateParams{
		State:      stateArg,
		MaxResults: maxResults,
	})
	if err != nil {
		return nil, fmt.Errorf("listing hypotheses by state: %w", err)
	}
	return rowsToRecords(rows)
}

func rowsToRecords(rows []db.Hypothesis) ([]Record, error) {
	out := make([]Record, 0, len(rows))
	for i := range rows {
		r, err := rowToRecord(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, nil
}

func rowToRecord(r *db.Hypothesis) (*Record, error) {
	var meta map[string]any
	if len(r.Metadata) > 0 {
		if err := json.Unmarshal(r.Metadata, &meta); err != nil {
			return nil, fmt.Errorf("unmarshaling hypothesis %d metadata: %w", r.ID, err)
		}
	}
	return &Record{
		ID:                    r.ID,
		Author:                r.Author,
		Content:               r.Content,
		State:                 State(r.State),
		Claim:                 r.Claim,
		InvalidationCondition: r.InvalidationCondition,
		Metadata:              meta,
		ObservedDate:          r.ObservedDate,
		CreatedAt:             r.CreatedAt,
	}, nil
}
