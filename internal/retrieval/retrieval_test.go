package retrieval

import (
	"testing"
	"time"

	fsrs "github.com/open-spaced-repetition/go-fsrs/v4"
)

func TestReview_NewCard(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)

	// First review of a new card with "Good" rating.
	card, log := Review(nil, fsrs.Good, now)

	if card.State != fsrs.Learning && card.State != fsrs.Review {
		t.Errorf("Review(nil, Good) State = %d, want Learning(1) or Review(2)", card.State)
	}
	if card.Due.Before(now) {
		t.Errorf("Review(nil, Good) Due = %v, want after %v", card.Due, now)
	}
	if log.Rating != fsrs.Good {
		t.Errorf("Review(nil, Good) log.Rating = %d, want %d", log.Rating, fsrs.Good)
	}
}

func TestReview_AgainEntersRelearning(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)

	// Build up a card through learning into review state.
	card, _ := Review(nil, fsrs.Good, now)
	for card.State != fsrs.Review {
		card, _ = Review(&card, fsrs.Good, card.Due)
	}

	// "Again" from review state should enter relearning.
	card, log := Review(&card, fsrs.Again, card.Due)

	if card.State != fsrs.Relearning {
		t.Errorf("Review(Again from Review) State = %d, want Relearning(3)", card.State)
	}
	if card.Lapses < 1 {
		t.Errorf("Review(Again) Lapses = %d, want >= 1", card.Lapses)
	}
	if log.Rating != fsrs.Again {
		t.Errorf("Review(Again) log.Rating = %d, want %d", log.Rating, fsrs.Again)
	}
}

func TestReview_GoodIntervalGrows(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)

	card, _ := Review(nil, fsrs.Good, now)
	firstDue := card.Due

	card, _ = Review(&card, fsrs.Good, card.Due)
	secondDue := card.Due

	card, _ = Review(&card, fsrs.Good, card.Due)
	thirdDue := card.Due

	// Intervals should grow: first < second < third.
	firstInterval := firstDue.Sub(now)
	secondInterval := secondDue.Sub(firstDue)
	thirdInterval := thirdDue.Sub(secondDue)

	if secondInterval <= firstInterval {
		t.Errorf("second interval (%v) should be > first (%v)", secondInterval, firstInterval)
	}
	if thirdInterval <= secondInterval {
		t.Errorf("third interval (%v) should be > second (%v)", thirdInterval, secondInterval)
	}
}

func TestReview_ExistingCard(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)

	// Pass an existing card (non-nil).
	existing := fsrs.NewCard()
	card, log := Review(&existing, fsrs.Hard, now)

	if card.Due.Before(now) {
		t.Errorf("Review(existing, Hard) Due = %v, want after %v", card.Due, now)
	}
	if log.Rating != fsrs.Hard {
		t.Errorf("Review(existing, Hard) log.Rating = %d, want %d", log.Rating, fsrs.Hard)
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state fsrs.State
		want  string
	}{
		{fsrs.New, "new"},
		{fsrs.Learning, "learning"},
		{fsrs.Review, "review"},
		{fsrs.Relearning, "relearning"},
		{fsrs.State(99), "unknown"},
	}

	for _, tt := range tests {
		if got := StateString(tt.state); got != tt.want {
			t.Errorf("StateString(%d) = %q, want %q", tt.state, got, tt.want)
		}
	}
}
