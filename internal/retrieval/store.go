package retrieval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	fsrs "github.com/open-spaced-repetition/go-fsrs/v4"

	"github.com/Koopa0/koopa0.dev/internal/db"
)

// Store handles FSRS card persistence and queue queries.
type Store struct {
	q *db.Queries
}

// NewStore returns a Store backed by the given database connection.
func NewStore(dbtx db.DBTX) *Store {
	if dbtx == nil {
		panic("retrieval: nil dbtx")
	}
	return &Store{q: db.New(dbtx)}
}

// ReviewCard performs the full review cycle: get/create card → FSRS compute → upsert → log.
func (s *Store) ReviewCard(ctx context.Context, contentID uuid.UUID, tag *string, rating fsrs.Rating, now time.Time) (*ReviewResult, error) {
	q := s.q

	// 1. Get existing card (may not exist for first review).
	var card *fsrs.Card
	existing, err := q.GetCard(ctx, db.GetCardParams{
		ContentID: contentID,
		Tag:       tag,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("getting card: %w", err)
	}
	if err == nil {
		var c fsrs.Card
		if unmarshalErr := json.Unmarshal(existing.CardState, &c); unmarshalErr != nil {
			return nil, fmt.Errorf("unmarshaling card state: %w", unmarshalErr)
		}
		card = &c
	}

	// 2. Compute FSRS.
	newCard, reviewLog := Review(card, rating, now)

	// 3. Serialize and upsert card state.
	cardJSON, err := json.Marshal(newCard)
	if err != nil {
		return nil, fmt.Errorf("marshaling card state: %w", err)
	}
	cardID, err := q.UpsertCard(ctx, db.UpsertCardParams{
		ContentID: contentID,
		Tag:       tag,
		CardState: cardJSON,
		Due:       newCard.Due,
	})
	if err != nil {
		return nil, fmt.Errorf("upserting card: %w", err)
	}

	// 4. Log review.
	if err := q.InsertReviewLog(ctx, db.InsertReviewLogParams{
		CardID:        cardID,
		Rating:        int32(rating),                  // #nosec G115 -- Rating is 1-4
		ScheduledDays: int32(reviewLog.ScheduledDays), // #nosec G115 -- days bounded by MaximumInterval
		ElapsedDays:   int32(reviewLog.ElapsedDays),   // #nosec G115 -- days bounded by MaximumInterval
		State:         int32(reviewLog.State),         // #nosec G115 -- State is 0-3
		ReviewedAt:    now,
	}); err != nil {
		return nil, fmt.Errorf("inserting review log: %w", err)
	}

	return &ReviewResult{
		CardID:    cardID,
		Due:       newCard.Due,
		Stability: newCard.Stability,
		State:     StateString(newCard.State),
	}, nil
}

// Queue returns items due for review: overdue FSRS cards + never-reviewed recent TILs.
func (s *Store) Queue(ctx context.Context, projectID *uuid.UUID, now time.Time, limit int) ([]DueItem, error) {
	q := s.q

	// 1. Due cards.
	dueRows, err := q.DueCards(ctx, db.DueCardsParams{
		Now:       now,
		ProjectID: projectID,
		Lim:       int32(limit), // #nosec G115 -- limit capped at 50 by caller
	})
	if err != nil {
		return nil, fmt.Errorf("querying due cards: %w", err)
	}

	items := make([]DueItem, 0, len(dueRows)+limit)
	for i := range dueRows {
		r := &dueRows[i]
		var stability float64
		var c fsrs.Card
		if unmarshalErr := json.Unmarshal(r.CardState, &c); unmarshalErr == nil {
			stability = c.Stability
		}
		tag := ""
		if r.Tag != nil {
			tag = *r.Tag
		}
		items = append(items, DueItem{
			CardID:    r.CardID,
			ContentID: r.ContentID.String(),
			Slug:      r.Slug,
			Title:     r.Title,
			Tag:       tag,
			Reason:    "overdue",
			Stability: stability,
			Due:       r.Due.Format(time.RFC3339),
		})
	}

	// 2. Never-reviewed TILs (fill remaining slots).
	remaining := limit - len(items)
	if remaining <= 0 {
		return items, nil
	}

	neverRows, err := q.NeverReviewedTILs(ctx, db.NeverReviewedTILsParams{
		ProjectID: projectID,
		Lim:       int32(remaining), // #nosec G115 -- remaining capped at 50
	})
	if err != nil {
		return nil, fmt.Errorf("querying never-reviewed TILs: %w", err)
	}

	for _, r := range neverRows {
		items = append(items, DueItem{
			ContentID: r.ID.String(),
			Slug:      r.Slug,
			Title:     r.Title,
			Reason:    "never-reviewed",
		})
	}

	return items, nil
}
