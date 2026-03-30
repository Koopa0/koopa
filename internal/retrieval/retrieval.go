// Package retrieval provides spaced retrieval scheduling using the FSRS algorithm.
// FSRS (Free Spaced Repetition Scheduler) is a modern algorithm that predicts memory
// stability and schedules reviews based on a deep-learning-derived forgetting curve.
// go-fsrs v4 is the official Go implementation.
package retrieval

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	fsrs "github.com/open-spaced-repetition/go-fsrs/v4"
)

var defaultFSRS = fsrs.NewFSRS(fsrs.DefaultParam())

// Review computes the updated card state and review log for a given rating.
// If card is nil (first review), creates a new card automatically.
func Review(card *fsrs.Card, rating fsrs.Rating, now time.Time) (fsrs.Card, fsrs.ReviewLog) {
	if card == nil {
		c := fsrs.NewCard()
		card = &c
	}
	info := defaultFSRS.Next(*card, now, rating)
	return info.Card, info.ReviewLog
}

// ReviewResult is the response after recording a review.
type ReviewResult struct {
	CardID    int64     `json:"card_id"`
	Due       time.Time `json:"due"`
	Stability float64   `json:"stability"`
	State     string    `json:"state"`
}

// DueItem is a card that's due for review, enriched with content metadata.
type DueItem struct {
	CardID     int64           `json:"card_id"`
	ContentID  uuid.UUID       `json:"content_id"`
	Slug       string          `json:"slug"`
	Title      string          `json:"title"`
	Tag        *string         `json:"tag,omitempty"`
	Reason     string          `json:"reason"`
	Stability  *float64        `json:"stability,omitempty"`
	Due        *time.Time      `json:"due,omitempty"`
	AIMetadata json.RawMessage `json:"ai_metadata,omitempty"`
}

// QueueResult is the response shape for the retrieval queue.
type QueueResult struct {
	Items []DueItem `json:"items"`
}

// StateString converts an FSRS State to a human-readable string.
func StateString(s fsrs.State) string {
	switch s {
	case fsrs.New:
		return "new"
	case fsrs.Learning:
		return "learning"
	case fsrs.Review:
		return "review"
	case fsrs.Relearning:
		return "relearning"
	default:
		return "unknown"
	}
}
