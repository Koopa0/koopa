package retrieval

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles retrieval attempt persistence and queue queries.
type Store struct {
	q db.DBTX
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	if dbtx == nil {
		panic("retrieval: nil dbtx")
	}
	return &Store{q: dbtx}
}

// LogAttempt records a retrieval attempt, looking up the previous attempt for
// SM-2 calculation. Returns the created attempt with computed scheduling.
func (s *Store) LogAttempt(ctx context.Context, contentID uuid.UUID, tag *string, quality string, now time.Time) (*Attempt, error) {
	if !ValidQuality(quality) {
		return nil, fmt.Errorf("invalid quality %q", quality)
	}

	q := db.New(s.q)

	// Look up previous attempt for SM-2 continuity.
	var prevInterval int
	prevEase := 2.5

	prev, err := q.LatestAttempt(ctx, db.LatestAttemptParams{
		ContentID: contentID,
		Tag:       tag,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("querying latest attempt: %w", err)
	}
	if err == nil {
		prevInterval = int(prev.IntervalDays)
		prevEase = float64(prev.EaseFactor)
	}

	sm2 := SM2Calculate(prevInterval, prevEase, quality, now)
	nextDue, parseErr := time.Parse(time.DateOnly, sm2.NextDue)
	if parseErr != nil {
		return nil, fmt.Errorf("parsing next due: %w", parseErr)
	}

	row, err := q.InsertAttempt(ctx, db.InsertAttemptParams{
		ContentID:    contentID,
		Tag:          tag,
		Quality:      quality,
		IntervalDays: int32(sm2.IntervalDays), // #nosec G115 -- SM-2 intervals are small (max ~365 days)
		EaseFactor:   float32(sm2.EaseFactor),
		NextDue:      nextDue,
	})
	if err != nil {
		return nil, fmt.Errorf("inserting attempt: %w", err)
	}

	return &Attempt{
		ID:           row.ID,
		ContentID:    row.ContentID,
		Tag:          row.Tag,
		Quality:      row.Quality,
		IntervalDays: int(row.IntervalDays),
		EaseFactor:   float64(row.EaseFactor),
		NextDue:      row.NextDue.Format(time.DateOnly),
		CreatedAt:    row.CreatedAt,
	}, nil
}

// Queue returns items due for review: overdue SM-2 items + never-retrieved recent TILs.
// projectSlug is optional (nil for all projects).
func (s *Store) Queue(ctx context.Context, projectSlug *string, limit int) ([]DueItem, error) {
	q := db.New(s.q)

	// 1. Items where SM-2 next_due has arrived.
	dueRows, err := q.DueItems(ctx, db.DueItemsParams{
		ProjectSlug: projectSlug,
		Lim:         int32(limit), // #nosec G115 -- limit capped at 50 by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying due items: %w", err)
	}

	items := make([]DueItem, 0, len(dueRows)+limit)
	for i := range dueRows {
		r := &dueRows[i]
		reason := "overdue"
		if r.LastQuality == QualityFailed {
			reason = "failed-recently"
		}
		nextDue := r.NextDue.Format(time.DateOnly)
		lastAt := r.LastAttemptAt
		items = append(items, DueItem{
			ContentID:     r.ContentID,
			Slug:          r.Slug,
			Title:         r.Title,
			Tag:           r.Tag,
			Reason:        reason,
			LastQuality:   r.LastQuality,
			LastAttemptAt: &lastAt,
			NextDue:       &nextDue,
			AIMetadata:    r.AiMetadata,
		})
	}

	// 2. Recent TILs never retrieved (fill remaining slots).
	remaining := limit - len(items)
	if remaining <= 0 {
		return items, nil
	}

	neverRows, err := q.NeverRetrievedItems(ctx, db.NeverRetrievedItemsParams{
		ProjectSlug: projectSlug,
		Lim:         int32(remaining), // #nosec G115 -- remaining capped at 50
	})
	if err != nil {
		return nil, fmt.Errorf("querying never-retrieved items: %w", err)
	}

	for _, r := range neverRows {
		items = append(items, DueItem{
			ContentID:  r.ID,
			Slug:       r.Slug,
			Title:      r.Title,
			Reason:     "never-retrieved",
			AIMetadata: r.AiMetadata,
		})
	}

	return items, nil
}

// QueueResult is the response shape for the retrieval queue MCP tool / HTTP endpoint.
type QueueResult struct {
	Items []DueItem `json:"items"`
}
