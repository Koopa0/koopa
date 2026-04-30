// Package fsrs implements spaced repetition scheduling on top of go-fsrs.
//
// This package owns the review_cards and review_logs tables. It is a distinct
// concept from the rest of learning analytics (attempts, observations,
// concepts): FSRS answers "when should I next review this learning target to
// maximise retention", while learning analytics answers "which concepts am I
// weak at". The two are coupled only via learning_target_id.
package fsrs

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	gofsrs "github.com/open-spaced-repetition/go-fsrs/v4"
)

// ErrUnknownOutcome is returned by ratingFromOutcome when the attempt
// outcome string is not recognised — usually a vocabulary drift between
// the schema enum and the Go switch. Callers branch on this via errors.Is
// to label the drift event so the retrieval view can surface it.
var ErrUnknownOutcome = errors.New("fsrs: unknown outcome")

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
// Bridges the learning domain (attempt outcomes) and the SRS domain (ratings).
// Returns an error for unknown outcomes so a new outcome value added to the
// schema enum cannot silently fall through to Again and reset FSRS intervals
// on every attempt. The caller routes the error to review_cards.last_sync_drift_at
// so the consumer (retrieval view) surfaces drift_suspect instead of silently
// producing a wrong schedule.
func ratingFromOutcome(outcome string) (gofsrs.Rating, error) {
	switch outcome {
	case "solved_independent", "completed":
		return gofsrs.Good, nil
	case "solved_with_hint", "completed_with_support", "solved_after_solution":
		return gofsrs.Hard, nil
	case "incomplete", "gave_up":
		return gofsrs.Again, nil
	default:
		return 0, fmt.Errorf("%w: %q (vocabulary drift between Go and schema)", ErrUnknownOutcome, outcome)
	}
}

// RatingFromOutcome is the public sibling of ratingFromOutcome. Exposed
// so callers can echo "what rating ReviewByOutcome will / did derive"
// without duplicating the mapping or actually performing the review.
// Returns the FSRS 1..4 integer rating (Again=1, Hard=2, Good=3,
// Easy=4) and ErrUnknownOutcome for outcomes outside the schema enum.
func RatingFromOutcome(outcome string) (int, error) {
	r, err := ratingFromOutcome(outcome)
	if err != nil {
		return 0, err
	}
	return int(r), nil
}
