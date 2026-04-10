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

// scheduler wraps the FSRS algorithm with parameters tuned for the project's
// learning scenario (LeetCode-style practice, language drills, system design
// reasoning). The FSRS default puts new cards through a "Learning" state with
// short-term steps (1m / 10m) before they graduate to the multi-day Review
// state — the Anki flashcard model where each card needs a brief re-test to
// confirm encoding.
//
// That model does not match this project's use case. A LeetCode problem
// solved_independent does not need a re-test 10 minutes later: the user is
// not at risk of forgetting the stack implementation in the next ten minutes;
// they are at risk of forgetting it next week. EnableShortTerm = false skips
// the Learning state entirely so Good/Easy ratings produce the long-term
// interval directly (~3 days for first Good, ~15 days for first Easy under
// the default weight vector).
//
// Again/Hard ratings still pull cards back into near-term review, so the
// "I couldn't solve this — show it to me again soon" behaviour is preserved.
type scheduler struct {
	fsrs *gofsrs.FSRS
}

func newScheduler() *scheduler {
	p := gofsrs.DefaultParam()
	p.EnableShortTerm = false
	return &scheduler{fsrs: gofsrs.NewFSRS(p)}
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
