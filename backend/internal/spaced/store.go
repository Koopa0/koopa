package spaced

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/koopa0/blog-backend/internal/db"
)

// Store manages spaced repetition intervals in the database.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given connection.
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx)}
}

// DueIntervals returns notes due for review, ordered by most overdue first.
func (s *Store) DueIntervals(ctx context.Context, limit int) ([]DueInterval, error) {
	rows, err := s.q.DueIntervals(ctx, int32(limit)) // #nosec G115 -- limit bounded by handler
	if err != nil {
		return nil, fmt.Errorf("listing due intervals: %w", err)
	}
	result := make([]DueInterval, len(rows))
	for i, r := range rows {
		result[i] = toDueInterval(r)
	}
	return result, nil
}

// Interval returns the spaced repetition state for a single note.
func (s *Store) Interval(ctx context.Context, noteID int64) (*Interval, error) {
	row, err := s.q.IntervalByNoteID(ctx, noteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying interval for note %d: %w", noteID, err)
	}
	iv := toInterval(row)
	return &iv, nil
}

// UpsertInterval creates or updates a spaced repetition interval.
func (s *Store) UpsertInterval(ctx context.Context, p UpsertParams) (*Interval, error) {
	row, err := s.q.UpsertInterval(ctx, db.UpsertIntervalParams{
		NoteID:         p.NoteID,
		EasinessFactor: p.EasinessFactor,
		IntervalDays:   int32(p.IntervalDays), // #nosec G115 -- SM-2 values are small
		Repetitions:    int32(p.Repetitions),  // #nosec G115 -- SM-2 values are small
		LastQuality:    toInt32Ptr(p.LastQuality),
		DueAt:          p.DueAt,
		ReviewedAt:     p.ReviewedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting interval for note %d: %w", p.NoteID, err)
	}
	iv := toInterval(row)
	return &iv, nil
}

// InsertInterval enrolls a note for spaced repetition. Returns ErrConflict
// if the note is already enrolled (atomic, no race condition).
func (s *Store) InsertInterval(ctx context.Context, p InsertParams) (*Interval, error) {
	row, err := s.q.InsertInterval(ctx, db.InsertIntervalParams{
		NoteID:         p.NoteID,
		EasinessFactor: p.EasinessFactor,
		IntervalDays:   int32(p.IntervalDays), // #nosec G115 -- SM-2 values are small
		Repetitions:    int32(p.Repetitions),  // #nosec G115 -- SM-2 values are small
		DueAt:          p.DueAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("inserting interval for note %d: %w", p.NoteID, err)
	}
	iv := toInterval(row)
	return &iv, nil
}

// DueCount returns the total number of notes currently due for review.
func (s *Store) DueCount(ctx context.Context) (int64, error) {
	count, err := s.q.DueCount(ctx)
	if err != nil {
		return 0, fmt.Errorf("counting due intervals: %w", err)
	}
	return count, nil
}

func toInterval(row db.SpacedInterval) Interval {
	return Interval{
		NoteID:         row.NoteID,
		EasinessFactor: row.EasinessFactor,
		IntervalDays:   int(row.IntervalDays),
		Repetitions:    int(row.Repetitions),
		LastQuality:    toIntPtr(row.LastQuality),
		DueAt:          row.DueAt,
		ReviewedAt:     row.ReviewedAt,
		CreatedAt:      row.CreatedAt,
	}
}

func toDueInterval(row db.DueIntervalsRow) DueInterval {
	return DueInterval{
		Interval: Interval{
			NoteID:         row.NoteID,
			EasinessFactor: row.EasinessFactor,
			IntervalDays:   int(row.IntervalDays),
			Repetitions:    int(row.Repetitions),
			LastQuality:    toIntPtr(row.LastQuality),
			DueAt:          row.DueAt,
			ReviewedAt:     row.ReviewedAt,
			CreatedAt:      row.CreatedAt,
		},
		Title:    row.Title,
		FilePath: row.FilePath,
		Type:     row.Type,
		Context:  row.Context,
	}
}

func toIntPtr(v *int32) *int {
	if v == nil {
		return nil
	}
	i := int(*v)
	return &i
}

func toInt32Ptr(v *int) *int32 {
	if v == nil {
		return nil
	}
	i := int32(*v) // #nosec G115 -- SM-2 quality values are 0-5, no overflow risk
	return &i
}
