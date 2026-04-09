package learning

import (
	"encoding/json"
	"fmt"
	"time"

	gofsrs "github.com/open-spaced-repetition/go-fsrs/v4"
)

// fsrsRatingFromInt converts a 1..4 integer rating to an FSRS rating.
// 1=Again (forgot), 2=Hard (remembered with difficulty), 3=Good (remembered),
// 4=Easy (remembered without effort). Used when the caller has a direct
// recall-difficulty signal that is independent of attempt outcome.
func fsrsRatingFromInt(n int) (gofsrs.Rating, error) {
	switch n {
	case 1:
		return gofsrs.Again, nil
	case 2:
		return gofsrs.Hard, nil
	case 3:
		return gofsrs.Good, nil
	case 4:
		return gofsrs.Easy, nil
	default:
		return 0, fmt.Errorf("fsrs rating must be 1..4, got %d", n)
	}
}

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
// Accepts pointer to avoid copying the 104-byte Card struct.
func (s *scheduler) review(card *gofsrs.Card, rating gofsrs.Rating, now time.Time) (gofsrs.Card, gofsrs.ReviewLog) {
	info := s.fsrs.Next(*card, now, rating) // gofsrs.Next takes value — dereference here
	return info.Card, info.ReviewLog
}

// marshalCardState serializes an FSRS Card to JSON for card_state JSONB column.
func marshalCardState(card *gofsrs.Card) (json.RawMessage, error) {
	return json.Marshal(card)
}

// unmarshalCardState deserializes an FSRS Card from card_state JSONB column.
func unmarshalCardState(data json.RawMessage) (gofsrs.Card, error) {
	var card gofsrs.Card
	err := json.Unmarshal(data, &card)
	return card, err
}

// ratingFromOutcome maps an attempt outcome string to an FSRS rating.
// This bridges the learning domain (attempt outcomes) and the SRS domain (ratings).
// Default is Again (forgot) — unknown outcomes stay in the near-term review queue
// rather than being silently promoted to "remembered."
func ratingFromOutcome(outcome string) gofsrs.Rating {
	switch outcome {
	case "solved_independent", "completed":
		return gofsrs.Good
	case "solved_with_hint", "completed_with_support", "solved_after_solution":
		return gofsrs.Hard
	case "incomplete", "gave_up":
		return gofsrs.Again
	default:
		return gofsrs.Again
	}
}
