package fsrs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	gofsrs "github.com/open-spaced-repetition/go-fsrs/v4"

	"github.com/Koopa0/koopa/internal/db"
)

// Store owns FSRS review card and review log persistence.
type Store struct {
	q     *db.Queries
	sched *scheduler
}

// NewStore returns a Store backed by the given database connection.
// The scheduler is created with project-tuned parameters (short-term
// scheduling disabled — see scheduler doc in fsrs.go).
func NewStore(dbtx db.DBTX) *Store {
	return &Store{q: db.New(dbtx), sched: newScheduler()}
}

// WithTx returns a new Store that uses the given transaction.
func (s *Store) WithTx(tx pgx.Tx) *Store {
	return &Store{q: s.q.WithTx(tx), sched: s.sched}
}

// ReviewByOutcome performs a spaced repetition review on a learning target's
// card derived from an attempt outcome string. The outcome vocabulary comes
// from the learning/attempt domain; this method converts it to an FSRS rating
// via ratingFromOutcome.
//
// The card update + review log insert are atomic via the store's underlying
// DBTX. Callers using a pool get auto-commit per statement; callers using a
// tx get full atomicity.
func (s *Store) ReviewByOutcome(ctx context.Context, targetID uuid.UUID, outcome string, now time.Time) (time.Time, error) {
	rating, err := ratingFromOutcome(outcome)
	if err != nil {
		return time.Time{}, err
	}
	return s.reviewWithRating(ctx, targetID, rating, now)
}

// ReviewByRating performs a spaced repetition review using an explicit FSRS
// rating (1=Again, 2=Hard, 3=Good, 4=Easy) instead of deriving it from an
// attempt outcome. Use this when recall difficulty is independent of outcome
// — e.g. the attempt was solved_independent but recall was painful (rating=2),
// or needed_help but core concept is solid (rating=3).
//
// Validation errors are wrapped so callers can distinguish an invalid rating
// (user/input error) from a DB failure (infrastructure error).
func (s *Store) ReviewByRating(ctx context.Context, targetID uuid.UUID, rating int, now time.Time) (time.Time, error) {
	fr, err := fsrsRatingFromInt(rating)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid fsrs rating: %w", err)
	}
	return s.reviewWithRating(ctx, targetID, fr, now)
}

// reviewWithRating is the shared implementation behind ReviewByOutcome and
// ReviewByRating. It takes a resolved gofsrs.Rating so both code paths
// converge without re-doing card lookup or state marshaling.
func (s *Store) reviewWithRating(ctx context.Context, targetID uuid.UUID, rating gofsrs.Rating, now time.Time) (time.Time, error) {
	row, err := s.q.CardByLearningTarget(ctx, targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.createAndReviewCard(ctx, targetID, rating, now)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("querying card for target %s: %w", targetID, err)
	}

	cardState, err := unmarshalCardState(row.CardState)
	if err != nil {
		return time.Time{}, fmt.Errorf("unmarshaling card state for card %s: %w", row.ID, err)
	}

	updated, rl := s.sched.review(&cardState, rating, now)
	state, err := marshalCardState(&updated)
	if err != nil {
		return time.Time{}, fmt.Errorf("marshaling card state: %w", err)
	}

	if _, err := s.q.UpdateCardState(ctx, db.UpdateCardStateParams{
		CardState: state,
		Due:       updated.Due,
		ID:        row.ID,
	}); err != nil {
		return time.Time{}, fmt.Errorf("updating review card %s: %w", row.ID, err)
	}

	if err := s.writeReviewLog(ctx, row.ID, rl, now); err != nil {
		return time.Time{}, fmt.Errorf("writing review log for card %s: %w", row.ID, err)
	}

	return updated.Due, nil
}

// MarkDrift stamps last_sync_drift_at on the card backing the given target.
// Called when an attempt-driven review cannot be applied (e.g. ratingFromOutcome
// rejected an unknown outcome, or the UPDATE failed mid-transaction).
//
// Returns the number of rows affected (0 or 1). A zero return means no card
// exists for the target yet — the drift signal has nowhere to land. Callers
// should log the zero case so drift on brand-new targets is at least visible
// in operational telemetry (dashboard drift_suspect cannot surface it because
// there is no card row to carry the flag).
func (s *Store) MarkDrift(ctx context.Context, targetID uuid.UUID, reason string) (int64, error) {
	if reason == "" {
		return 0, fmt.Errorf("marking card drift: reason must not be empty")
	}
	return s.q.MarkCardDrift(ctx, db.MarkCardDriftParams{
		LearningTargetID: targetID,
		Reason:           &reason,
	})
}

// createAndReviewCard creates a new FSRS card and immediately reviews it.
// Handles TOCTOU race: if another goroutine created the card concurrently,
// catches the unique violation and falls back to reviewing the existing card.
func (s *Store) createAndReviewCard(ctx context.Context, targetID uuid.UUID, rating gofsrs.Rating, now time.Time) (time.Time, error) {
	newCard := s.sched.newCard()
	updated, rl := s.sched.review(&newCard, rating, now)

	state, err := marshalCardState(&updated)
	if err != nil {
		return time.Time{}, fmt.Errorf("marshaling card state: %w", err)
	}

	row, err := s.q.CreateCardForLearningTarget(ctx, db.CreateCardForLearningTargetParams{
		LearningTargetID: targetID,
		CardState:        state,
		Due:              updated.Due,
	})
	if err != nil {
		// TOCTOU: another goroutine created the card first. Retry via the review
		// path preserving the caller's original rating.
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return s.reviewWithRating(ctx, targetID, rating, now)
		}
		return time.Time{}, fmt.Errorf("creating review card for target %s: %w", targetID, err)
	}

	if err := s.writeReviewLog(ctx, row.ID, rl, now); err != nil {
		return time.Time{}, err
	}

	return updated.Due, nil
}

// writeReviewLog appends a review log entry for an FSRS card review.
func (s *Store) writeReviewLog(ctx context.Context, cardID uuid.UUID, rl gofsrs.ReviewLog, now time.Time) error {
	return s.q.InsertReviewLog(ctx, db.InsertReviewLogParams{
		CardID:        cardID,
		Rating:        int32(rl.Rating),
		ScheduledDays: int32(rl.ScheduledDays), //nolint:gosec // G115: FSRS ScheduledDays is small (days), never exceeds int32
		ElapsedDays:   int32(rl.ElapsedDays),   //nolint:gosec // G115: FSRS ElapsedDays is small (days), never exceeds int32
		State:         int32(rl.State),
		ReviewedAt:    now,
	})
}

// DueCount returns the number of review cards due before the given time.
func (s *Store) DueCount(ctx context.Context, before time.Time) (int, error) {
	n, err := s.q.DueReviewCount(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("counting due reviews: %w", err)
	}
	return int(n), nil
}
