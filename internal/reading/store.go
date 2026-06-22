// Copyright 2026 Koopa. All rights reserved.

package reading

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Koopa0/koopa/internal/db"
)

// Store handles database operations for readings and their reflections.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// WithTx returns a Store bound to tx for all queries. Used by the admin
// handlers via api.ActorMiddleware's per-request tx. No audit triggers
// fire on the reading tables, but mutations still run inside the request
// tx so multi-statement handlers stay atomic.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx)}
}

// Reading returns a single reading by ID.
func (s *Store) Reading(ctx context.Context, id uuid.UUID) (*Reading, error) {
	r, err := s.q.ReadingByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying reading %s: %w", id, err)
	}
	row := readingRow(r)
	return buildReading(&row), nil
}

// Readings lists the shelf, optionally filtered to one status, ordered by
// most recently updated. Status-group ordering is the frontend's concern.
func (s *Store) Readings(ctx context.Context, status *Status) ([]Reading, error) {
	var statusArg *string
	if status != nil {
		if !status.Valid() {
			return nil, fmt.Errorf("%w: status %q", ErrInvalidInput, *status)
		}
		statusArg = new(string(*status))
	}
	rows, err := s.q.Readings(ctx, statusArg)
	if err != nil {
		return nil, fmt.Errorf("listing readings: %w", err)
	}
	out := make([]Reading, len(rows))
	for i := range rows {
		row := readingRow(rows[i])
		out[i] = *buildReading(&row)
	}
	return out, nil
}

// Create inserts a new reading. Status defaults to StatusWantToRead when
// empty; an unrecognized status returns ErrInvalidInput.
func (s *Store) Create(ctx context.Context, p *CreateParams) (*Reading, error) {
	status := p.Status
	if status == "" {
		status = StatusWantToRead
	}
	if !status.Valid() {
		return nil, fmt.Errorf("%w: status %q", ErrInvalidInput, p.Status)
	}
	r, err := s.q.CreateReading(ctx, db.CreateReadingParams{
		Title:     p.Title,
		Author:    p.Author,
		Status:    string(status),
		StartedOn: p.StartedOn,
	})
	if err != nil {
		return nil, fmt.Errorf("inserting reading: %w", err)
	}
	row := readingRow(r)
	return buildReading(&row), nil
}

// Update modifies editable fields; nil params stay unchanged. A status
// update to StatusFinished with no explicit FinishedOn auto-stamps
// finished_on to today unless a finish date already exists (resolution
// order documented on the UpdateReading query).
func (s *Store) Update(ctx context.Context, id uuid.UUID, p UpdateParams) (*Reading, error) {
	var statusArg *string
	if p.Status != nil {
		if !p.Status.Valid() {
			return nil, fmt.Errorf("%w: status %q", ErrInvalidInput, *p.Status)
		}
		statusArg = new(string(*p.Status))
	}
	r, err := s.q.UpdateReading(ctx, db.UpdateReadingParams{
		ID:         id,
		Title:      p.Title,
		Author:     p.Author,
		Status:     statusArg,
		StartedOn:  p.StartedOn,
		FinishedOn: p.FinishedOn,
		IsPublic:   p.IsPublic,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating reading %s: %w", id, err)
	}
	row := readingRow(r)
	return buildReading(&row), nil
}

// Delete removes a reading by ID. ON DELETE CASCADE removes the book's
// entire diary with it. Returns ErrNotFound when no row matched.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	n, err := s.q.DeleteReading(ctx, id)
	if err != nil {
		return fmt.Errorf("deleting reading %s: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Reflections returns the diary thread for one reading: entry_date
// ascending, created_at as the same-day tiebreak.
func (s *Store) Reflections(ctx context.Context, readingID uuid.UUID) ([]Reflection, error) {
	rows, err := s.q.ReflectionsForReading(ctx, readingID)
	if err != nil {
		return nil, fmt.Errorf("listing reflections for reading %s: %w", readingID, err)
	}
	out := make([]Reflection, len(rows))
	for i := range rows {
		row := reflectionRow(rows[i])
		out[i] = buildReflection(&row)
	}
	return out, nil
}

// CreateReflection inserts a diary entry under a reading. A nil entryDate
// defaults to today (the database's CURRENT_DATE). A missing parent
// reading surfaces as ErrNotFound (FK violation).
func (s *Store) CreateReflection(ctx context.Context, readingID uuid.UUID, entryDate *time.Time, body string) (*Reflection, error) {
	r, err := s.q.CreateReflection(ctx, db.CreateReflectionParams{
		ReadingID: readingID,
		EntryDate: entryDate,
		Body:      body,
	})
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.ForeignKeyViolation {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("inserting reflection under reading %s: %w", readingID, err)
	}
	row := reflectionRow(r)
	out := buildReflection(&row)
	return &out, nil
}

// UpdateReflection modifies a diary entry, bound to its parent reading in
// the WHERE clause — a {readingID, id} mismatch is ErrNotFound, never a
// cross-book write.
func (s *Store) UpdateReflection(ctx context.Context, readingID, id uuid.UUID, p UpdateReflectionParams) (*Reflection, error) {
	r, err := s.q.UpdateReflection(ctx, db.UpdateReflectionParams{
		ID:        id,
		ReadingID: readingID,
		Body:      p.Body,
		EntryDate: p.EntryDate,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("updating reflection %s under reading %s: %w", id, readingID, err)
	}
	row := reflectionRow(r)
	out := buildReflection(&row)
	return &out, nil
}

// DeleteReflection removes a diary entry with the same membership binding
// as UpdateReflection. Returns ErrNotFound when no row matched.
func (s *Store) DeleteReflection(ctx context.Context, readingID, id uuid.UUID) error {
	n, err := s.q.DeleteReflection(ctx, db.DeleteReflectionParams{
		ID:        id,
		ReadingID: readingID,
	})
	if err != nil {
		return fmt.Errorf("deleting reflection %s under reading %s: %w", id, readingID, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// readingRow is the field subset buildReading needs. Adding the embedding +
// search_vector columns to the readings table gave each explicit-column query
// its own sqlc *Row type (the table struct db.Reading now carries the two extra
// columns the shelf queries do not select), so the build helper takes this
// shared shape rather than any single generated type. Every shelf-row query
// converts its row to a readingRow at the call site.
type readingRow struct {
	ID         uuid.UUID
	Title      string
	Author     string
	Status     string
	StartedOn  *time.Time
	FinishedOn *time.Time
	IsPublic   bool
	GoalID     *uuid.UUID
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// buildReading converts the shared row shape into the domain type.
func buildReading(r *readingRow) *Reading {
	return &Reading{
		ID:         r.ID,
		Title:      r.Title,
		Author:     r.Author,
		Status:     Status(r.Status),
		StartedOn:  r.StartedOn,
		FinishedOn: r.FinishedOn,
		IsPublic:   r.IsPublic,
		GoalID:     r.GoalID,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
}

// reflectionRow mirrors the Reflection domain type field-for-field — same
// reasoning as readingRow (the reading_reflections table gained embedding +
// search_vector, so each diary query gets its own *Row type). Because the
// fields match exactly, buildReflection is a direct struct conversion.
type reflectionRow struct {
	ID        uuid.UUID
	ReadingID uuid.UUID
	EntryDate time.Time
	Body      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// buildReflection converts the shared row shape into the domain type.
func buildReflection(r *reflectionRow) Reflection {
	return Reflection(*r)
}
