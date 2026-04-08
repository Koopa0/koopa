package learning

import (
	"encoding/json"
	"time"

	gofsrs "github.com/open-spaced-repetition/go-fsrs/v4"
)

// FSRS rating constants re-exported for callers.
const (
	RatingAgain = gofsrs.Again // 1 — forgot
	RatingHard  = gofsrs.Hard  // 2 — partial recall
	RatingGood  = gofsrs.Good  // 3 — remembered
	RatingEasy  = gofsrs.Easy  // 4 — effortless
)

// scheduler wraps the FSRS algorithm with default parameters.
type scheduler struct {
	fsrs *gofsrs.FSRS
}

func newScheduler() *scheduler {
	return &scheduler{fsrs: gofsrs.NewFSRS(gofsrs.DefaultParam())}
}

// newCard creates a fresh FSRS card state (new card, due now).
func (s *scheduler) newCard() gofsrs.Card {
	return gofsrs.NewCard()
}

// review applies a rating to a card and returns the updated state + review log.
func (s *scheduler) review(card gofsrs.Card, rating gofsrs.Rating, now time.Time) (gofsrs.Card, gofsrs.ReviewLog) {
	info := s.fsrs.Next(card, now, rating)
	return info.Card, info.ReviewLog
}

// marshalCardState serializes an FSRS Card to JSON for card_state JSONB column.
func marshalCardState(card gofsrs.Card) (json.RawMessage, error) {
	return json.Marshal(card)
}

// unmarshalCardState deserializes an FSRS Card from card_state JSONB column.
func unmarshalCardState(data json.RawMessage) (gofsrs.Card, error) {
	var card gofsrs.Card
	err := json.Unmarshal(data, &card)
	return card, err
}

// RatingFromOutcome maps an attempt outcome string to an FSRS rating.
// This bridges the learning domain (attempt outcomes) and the SRS domain (ratings).
func RatingFromOutcome(outcome string) gofsrs.Rating {
	switch outcome {
	case "solved_independent", "completed":
		return gofsrs.Good
	case "solved_with_hint", "completed_with_support", "solved_after_solution":
		return gofsrs.Hard
	case "incomplete", "gave_up":
		return gofsrs.Again
	default:
		return gofsrs.Good
	}
}
