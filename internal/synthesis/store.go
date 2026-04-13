package synthesis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles database operations for the syntheses table.
//
// Create is the write path. Only secondary consolidation processes
// should call it — there is no compile-time enforcement of that,
// but an integration test asserts live handlers leave the table
// untouched, and the package documentation makes the contract clear.
//
// RecentByKind and LatestBySubjectKey are the read paths, used by
// retrospective query tools. Neither falls through to live compute
// on a miss — they return empty results or ErrNotFound.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store that uses tx for all queries. Matches the
// project-wide convention. Used by consolidation to wrap a run's
// reads and writes in a single transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Create inserts a new synthesis row. Returns the inserted row on
// success, or ErrNotFound when ON CONFLICT DO NOTHING skipped the
// insert (same evidence set already recorded). The "not found"
// semantic for a conflict is deliberate — the caller can branch
// with errors.Is(err, ErrNotFound) to distinguish "new snapshot
// written" from "already up-to-date".
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Synthesis, error) {
	bodyBytes := []byte(p.Body)
	evidenceBytes, err := json.Marshal(p.Evidence)
	if err != nil {
		return nil, fmt.Errorf("marshaling evidence: %w", err)
	}

	row, err := s.q.CreateSynthesis(ctx, db.CreateSynthesisParams{
		SubjectType:  string(p.SubjectType),
		SubjectID:    p.SubjectID,
		SubjectKey:   p.SubjectKey,
		Kind:         string(p.Kind),
		Body:         bodyBytes,
		Evidence:     evidenceBytes,
		EvidenceHash: p.EvidenceHash,
		ComputedBy:   p.ComputedBy,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ON CONFLICT DO NOTHING + RETURNING yields zero rows
			// on conflict. Map to ErrNotFound so the caller can
			// treat it as "already recorded".
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("creating synthesis: %w", err)
	}
	return rowToSynthesis(&row)
}

// RecentByKind returns the most recent syntheses for (subjectType,
// kind), ordered newest first. An optional subjectKey pins the
// result to a single subject (e.g. all snapshots for week 2026-W15).
// Empty result is a valid answer — it means nothing has been
// consolidated yet. This is NOT a cache miss; the reader does not
// fall through to live compute.
func (s *Store) RecentByKind(
	ctx context.Context,
	subjectType SubjectType,
	kind Kind,
	subjectKey *string,
	limit int,
) ([]Synthesis, error) {
	rows, err := s.q.RecentByKind(ctx, db.RecentByKindParams{
		Limit:       int32(limit), // #nosec G115 -- caller bounds limit in handler
		SubjectType: string(subjectType),
		Kind:        string(kind),
		SubjectKey:  subjectKey,
	})
	if err != nil {
		return nil, fmt.Errorf("listing syntheses: %w", err)
	}

	out := make([]Synthesis, len(rows))
	for i := range rows {
		s, convErr := rowToSynthesis(&rows[i])
		if convErr != nil {
			return nil, convErr
		}
		out[i] = *s
	}
	return out, nil
}

// LatestBySubjectKey returns the single most recent synthesis for a
// specific (subjectType, subjectKey, kind). Returns ErrNotFound when
// no row exists — again, not a cache miss, just absence of a
// historical record.
func (s *Store) LatestBySubjectKey(
	ctx context.Context,
	subjectType SubjectType,
	subjectKey string,
	kind Kind,
) (*Synthesis, error) {
	row, err := s.q.LatestBySubjectKey(ctx, db.LatestBySubjectKeyParams{
		SubjectType: string(subjectType),
		SubjectKey:  &subjectKey,
		Kind:        string(kind),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying latest synthesis for %s: %w", subjectKey, err)
	}
	return rowToSynthesis(&row)
}

// CountByKind returns the total number of syntheses for a
// (subjectType, kind). Used by integration tests to assert
// invariants like "live handlers leave syntheses empty".
func (s *Store) CountByKind(
	ctx context.Context,
	subjectType SubjectType,
	kind Kind,
) (int, error) {
	n, err := s.q.CountByKind(ctx, db.CountByKindParams{
		SubjectType: string(subjectType),
		Kind:        string(kind),
	})
	if err != nil {
		return 0, fmt.Errorf("counting syntheses: %w", err)
	}
	return int(n), nil
}

// rowToSynthesis converts a generated db.Synthesis into the domain
// type. Evidence is unmarshaled here because the JSONB column is
// stored as [][]byte from sqlc, but the domain model carries a typed
// []EvidenceRef for consumer convenience.
func rowToSynthesis(r *db.Synthesis) (*Synthesis, error) {
	var evidence []EvidenceRef
	if len(r.Evidence) > 0 {
		if err := json.Unmarshal(r.Evidence, &evidence); err != nil {
			return nil, fmt.Errorf("unmarshaling evidence for synthesis %s: %w", r.ID, err)
		}
	}
	if evidence == nil {
		evidence = []EvidenceRef{}
	}
	return &Synthesis{
		ID:           r.ID,
		SubjectType:  SubjectType(r.SubjectType),
		SubjectID:    r.SubjectID,
		SubjectKey:   r.SubjectKey,
		Kind:         Kind(r.Kind),
		Body:         json.RawMessage(r.Body),
		Evidence:     evidence,
		EvidenceHash: r.EvidenceHash,
		ComputedAt:   r.ComputedAt,
		ComputedBy:   r.ComputedBy,
	}, nil
}
