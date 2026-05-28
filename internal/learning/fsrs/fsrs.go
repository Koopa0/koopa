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
	"math"
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

// review applies a rating to a card and returns the updated state, the review
// log, and the days elapsed since the card's previous review. Accepts pointer
// to avoid copying the Card struct.
//
// go-fsrs v4 dropped ReviewLog.ElapsedDays, so the adapter derives elapsed days
// from the pre-review card's LastReview — the same quantity the library uses
// internally. gofsrs.Next now returns an error for an invalid card state or
// rating; the adapter wraps and propagates it so a malformed card surfaces as
// drift rather than a silently wrong schedule.
func (s *scheduler) review(card *gofsrs.Card, rating gofsrs.Rating, now time.Time) (gofsrs.Card, gofsrs.ReviewLog, uint64, error) {
	elapsed := elapsedDays(card, now)
	info, err := s.fsrs.Next(*card, now, rating) // gofsrs.Next takes value — dereference here
	if err != nil {
		return gofsrs.Card{}, gofsrs.ReviewLog{}, 0, fmt.Errorf("scheduling card review: %w", err)
	}
	return info.Card, info.ReviewLog, elapsed, nil
}

// elapsedDays returns the whole days between the card's previous review and now
// (UTC date boundaries, floored, clamped at 0). A new or never-reviewed card
// has a zero LastReview and yields 0. Mirrors go-fsrs' internal dateDiffInDays
// so review_logs.elapsed_days matches the interval the library schedules on.
func elapsedDays(card *gofsrs.Card, now time.Time) uint64 {
	if card.State == gofsrs.New || card.LastReview.IsZero() {
		return 0
	}
	lr := card.LastReview.UTC()
	last := time.Date(lr.Year(), lr.Month(), lr.Day(), 0, 0, 0, 0, time.UTC)
	n := now.UTC()
	cur := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	hours := cur.Sub(last).Hours()
	if hours < 0 {
		return 0
	}
	return uint64(math.Floor(hours / 24))
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
//
// Mapping semantics:
//   - Good: independent recall (solved_independent, completed). The user
//     produced the answer/work without external help; FSRS schedules the
//     long interval that proves retention.
//   - Hard: partial recall after limited assistance (solved_with_hint,
//     completed_with_support). The user retrieved most of the structure
//     but needed a nudge; FSRS pulls the card forward to retest the gap.
//   - Again: no independent retrieval (incomplete, gave_up,
//     solved_after_solution). The card is rescheduled as if encoding just
//     started. solved_after_solution sits here intentionally — copying
//     or reading a full solution is solution-exposure, not recall, so
//     treating it as Hard (the prior mapping) would build a false retention
//     curve and surface in the retrieval queue as "already practised".
//
// Returns an error for unknown outcomes so a new outcome value added to the
// schema enum cannot silently fall through to Again and reset FSRS intervals
// on every attempt. The caller routes the error to review_cards.last_sync_drift_at
// so the consumer (retrieval view) surfaces drift_suspect instead of silently
// producing a wrong schedule.
func ratingFromOutcome(outcome string) (gofsrs.Rating, error) {
	switch outcome {
	case "solved_independent", "completed":
		return gofsrs.Good, nil
	case "solved_with_hint", "completed_with_support":
		return gofsrs.Hard, nil
	case "incomplete", "gave_up", "solved_after_solution":
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
