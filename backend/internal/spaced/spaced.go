// Package spaced implements spaced repetition scheduling for obsidian notes
// using the SM-2 algorithm.
package spaced

import (
	"errors"
	"math"
	"time"
)

// ErrNotFound indicates the requested interval does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict indicates the note is already enrolled in spaced repetition.
var ErrConflict = errors.New("conflict")

// Interval represents the current spaced repetition state for a note.
type Interval struct {
	NoteID         int64      `json:"note_id"`
	EasinessFactor float64    `json:"easiness_factor"`
	IntervalDays   int        `json:"interval_days"`
	Repetitions    int        `json:"repetitions"`
	LastQuality    *int       `json:"last_quality"`
	DueAt          time.Time  `json:"due_at"`
	ReviewedAt     *time.Time `json:"reviewed_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// DueInterval is an Interval joined with note metadata for listing.
type DueInterval struct {
	Interval
	Title    *string `json:"title,omitempty"`
	FilePath string  `json:"file_path"`
	Type     *string `json:"type,omitempty"`
	Context  *string `json:"context,omitempty"`
}

// InsertParams holds parameters for enrolling a note (insert only, no update).
type InsertParams struct {
	NoteID         int64
	EasinessFactor float64
	IntervalDays   int
	Repetitions    int
	DueAt          time.Time
}

// UpsertParams holds parameters for creating or updating an interval.
type UpsertParams struct {
	NoteID         int64
	EasinessFactor float64
	IntervalDays   int
	Repetitions    int
	LastQuality    *int
	DueAt          time.Time
	ReviewedAt     *time.Time
}

// SM2Input holds the current state before a review.
type SM2Input struct {
	Quality        int     // 0-5: review quality rating
	Repetitions    int     // consecutive correct reviews
	EasinessFactor float64 // >= 1.3, default 2.5
	IntervalDays   int     // current interval in days
}

// SM2Output holds the computed next state after a review.
type SM2Output struct {
	Repetitions    int
	EasinessFactor float64
	IntervalDays   int
}

// DefaultEasinessFactor is the initial ease factor for new cards.
const DefaultEasinessFactor = 2.5

// minEasinessFactor is the minimum allowed ease factor per SM-2.
const minEasinessFactor = 1.3

// SM2 computes the next spaced repetition state using the SM-2 algorithm.
// Quality must be 0-5. EasinessFactor is clamped to >= 1.3.
func SM2(in SM2Input) SM2Output {
	q := in.Quality
	if q < 0 {
		q = 0
	}
	if q > 5 {
		q = 5
	}

	// Compute new easiness factor.
	ef := in.EasinessFactor + (0.1 - float64(5-q)*(0.08+float64(5-q)*0.02))
	if ef < minEasinessFactor {
		ef = minEasinessFactor
	}

	// Quality < 3: incorrect — reset repetitions and interval.
	if q < 3 {
		return SM2Output{
			Repetitions:    0,
			EasinessFactor: ef,
			IntervalDays:   1,
		}
	}

	// Quality >= 3: correct — advance schedule.
	reps := in.Repetitions + 1
	var interval int
	switch reps {
	case 1:
		interval = 1
	case 2:
		interval = 6
	default:
		interval = int(math.Round(float64(in.IntervalDays) * ef))
		if interval < 1 {
			interval = 1
		}
	}

	return SM2Output{
		Repetitions:    reps,
		EasinessFactor: ef,
		IntervalDays:   interval,
	}
}
