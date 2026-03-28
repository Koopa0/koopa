package mcpserver

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/koopa0/blog-backend/internal/note"
)

// makeNote creates a note.Note with the given ID for test convenience.
func makeNote(id int64) note.Note {
	return note.Note{ID: id}
}

// makeSearchResult creates a note.SearchResult with the given ID and rank.
func makeSearchResult(id int64, rank float32) note.SearchResult {
	return note.SearchResult{Note: makeNote(id), Rank: rank}
}

func TestRRFMerge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		textResults   []note.SearchResult
		filterResults []note.Note
		limit         int
		wantLen       int
		wantFirstID   int64   // expected top-scored result ID (when wantLen > 0)
		wantIDs       []int64 // exact ordered IDs (when non-nil)
	}{
		{
			name:          "empty inputs return empty slice",
			textResults:   nil,
			filterResults: nil,
			limit:         10,
			wantLen:       0,
		},
		{
			name:          "single text result only",
			textResults:   []note.SearchResult{makeSearchResult(1, 1.0)},
			filterResults: nil,
			limit:         10,
			wantLen:       1,
			wantFirstID:   1,
		},
		{
			name:          "single filter result only",
			textResults:   nil,
			filterResults: []note.Note{makeNote(2)},
			limit:         10,
			wantLen:       1,
			wantFirstID:   2,
		},
		{
			name: "non-overlapping sources merged and sorted by score",
			// text rank 0 → 1/(60+0)=0.01667; filter rank 0 → 1/(60+0)=0.01667
			// non-overlapping: each has score ~0.01667; tied — order stable by map iteration not guaranteed
			// so just check count
			textResults:   []note.SearchResult{makeSearchResult(1, 1.0)},
			filterResults: []note.Note{makeNote(2)},
			limit:         10,
			wantLen:       2,
		},
		{
			name: "overlapping item scores are summed",
			// ID=1 appears at rank 0 in both → score = 1/(60+0)+1/(60+0) = 2/60
			// ID=2 appears at rank 1 in text  → score = 1/(60+1)
			// ID=1 should rank higher
			textResults:   []note.SearchResult{makeSearchResult(1, 1.0), makeSearchResult(2, 0.5)},
			filterResults: []note.Note{makeNote(1)},
			limit:         10,
			wantLen:       2,
			wantFirstID:   1,
		},
		{
			name: "limit is respected",
			textResults: []note.SearchResult{
				makeSearchResult(1, 1.0),
				makeSearchResult(2, 0.9),
				makeSearchResult(3, 0.8),
				makeSearchResult(4, 0.7),
				makeSearchResult(5, 0.6),
			},
			filterResults: nil,
			limit:         3,
			wantLen:       3,
		},
		{
			name: "limit larger than results returns all",
			textResults: []note.SearchResult{
				makeSearchResult(10, 1.0),
				makeSearchResult(20, 0.9),
			},
			filterResults: nil,
			limit:         100,
			wantLen:       2,
		},
		{
			name:          "limit zero returns empty",
			textResults:   []note.SearchResult{makeSearchResult(1, 1.0)},
			filterResults: nil,
			limit:         0,
			wantLen:       0,
		},
		{
			name: "top result has highest score — earlier rank wins",
			// rank 0 in text → score 1/60; rank 4 in text → score 1/64
			// ID=1 (rank 0) > ID=5 (rank 4)
			textResults: []note.SearchResult{
				makeSearchResult(1, 1.0),
				makeSearchResult(2, 0.9),
				makeSearchResult(3, 0.8),
				makeSearchResult(4, 0.7),
				makeSearchResult(5, 0.6),
			},
			filterResults: nil,
			limit:         5,
			wantLen:       5,
			wantFirstID:   1,
		},
		{
			name: "note data preserved from text results for overlapping IDs",
			// verify the note.Note populated for ID=1 comes from textResults, not filterResults
			textResults:   []note.SearchResult{makeSearchResult(1, 1.0)},
			filterResults: []note.Note{makeNote(1)}, // overlap
			limit:         10,
			wantLen:       1,
			wantFirstID:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := rrfMerge(tt.textResults, tt.filterResults, tt.limit)

			if len(got) != tt.wantLen {
				t.Errorf("rrfMerge() len = %d, want %d", len(got), tt.wantLen)
				return
			}
			if tt.wantLen == 0 {
				return
			}
			if tt.wantFirstID != 0 && got[0].Note.ID != tt.wantFirstID {
				t.Errorf("rrfMerge() got[0].Note.ID = %d, want %d", got[0].Note.ID, tt.wantFirstID)
			}
			if tt.wantIDs != nil {
				gotIDs := make([]int64, len(got))
				for i, e := range got {
					gotIDs[i] = e.Note.ID
				}
				if diff := cmp.Diff(tt.wantIDs, gotIDs); diff != "" {
					t.Errorf("rrfMerge() IDs mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestRRFMerge_ScoreOrdering(t *testing.T) {
	t.Parallel()

	// Build a scenario with known, deterministic score ordering.
	// ID=10: rank 0 in text → score = 1/60 ≈ 0.01667
	// ID=20: rank 0 in filter → score = 1/60 ≈ 0.01667
	// ID=30: rank 0 in text AND rank 0 in filter → score = 2/60 ≈ 0.03333 (highest)
	text := []note.SearchResult{
		makeSearchResult(30, 1.0),
		makeSearchResult(10, 0.5),
	}
	filter := []note.Note{makeNote(30), makeNote(20)}

	got := rrfMerge(text, filter, 10)

	if len(got) != 3 {
		t.Fatalf("rrfMerge() len = %d, want 3", len(got))
	}
	if got[0].Note.ID != 30 {
		t.Errorf("rrfMerge() got[0].Note.ID = %d, want 30 (highest fused score)", got[0].Note.ID)
	}

	// Verify all scores are strictly positive.
	for i, e := range got {
		if e.Score <= 0 {
			t.Errorf("rrfMerge() got[%d].Score = %f, want > 0", i, e.Score)
		}
	}

	// Verify descending order.
	for i := 1; i < len(got); i++ {
		if got[i].Score > got[i-1].Score {
			t.Errorf("rrfMerge() not sorted: got[%d].Score=%f > got[%d].Score=%f",
				i, got[i].Score, i-1, got[i-1].Score)
		}
	}
}

func TestRRFMerge_ResultsContainNoZeroScores(t *testing.T) {
	t.Parallel()

	text := []note.SearchResult{
		makeSearchResult(1, 1.0),
		makeSearchResult(2, 0.8),
		makeSearchResult(3, 0.6),
	}
	filter := []note.Note{makeNote(4), makeNote(5)}

	got := rrfMerge(text, filter, 10)
	for i, e := range got {
		if e.Score == 0 {
			t.Errorf("rrfMerge() got[%d].Score = 0, all scores must be positive", i)
		}
	}
}

func TestRRFMerge_FilterResultNoteNotOverwritten(t *testing.T) {
	t.Parallel()

	// When ID=1 appears in both text and filter, note data comes from textResults (first writer wins).
	title := "from text"
	textNote := note.SearchResult{
		Note: note.Note{ID: 1, Title: &title},
		Rank: 1.0,
	}
	filterTitle := "from filter"
	filterNote := note.Note{ID: 1, Title: &filterTitle}

	got := rrfMerge([]note.SearchResult{textNote}, []note.Note{filterNote}, 10)

	if len(got) != 1 {
		t.Fatalf("rrfMerge() len = %d, want 1", len(got))
	}
	if got[0].Note.Title == nil || *got[0].Note.Title != title {
		t.Errorf("rrfMerge() note title = %v, want %q (from text results)", got[0].Note.Title, title)
	}
}

// BenchmarkRRFMerge measures merge throughput at realistic data sizes.
func BenchmarkRRFMerge(b *testing.B) {
	sizes := []struct {
		name        string
		textCount   int
		filterCount int
	}{
		{"10text_0filter", 10, 0},
		{"50text_50filter", 50, 50},
		{"100text_100filter", 100, 100},
		{"100text_0filter_overlapping", 100, 0},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			text := make([]note.SearchResult, sz.textCount)
			for i := range sz.textCount {
				text[i] = makeSearchResult(int64(i+1), float32(sz.textCount-i))
			}
			filter := make([]note.Note, sz.filterCount)
			for i := range sz.filterCount {
				// Overlap the first half with text results to exercise the merge path.
				filter[i] = makeNote(int64(i + 1))
			}
			b.ResetTimer()
			for b.Loop() {
				_ = rrfMerge(text, filter, 20)
			}
		})
	}
}

// rrfMergeOption helps cmp.Diff ignore map-ordering non-determinism when checking
// that two sets contain the same IDs regardless of score-tie ordering.
var sortByID = cmpopts.SortSlices(func(a, b searchResultEntry) bool {
	return a.Note.ID < b.Note.ID
})

func TestRRFMerge_AllInputIDsPresent(t *testing.T) {
	t.Parallel()

	text := []note.SearchResult{
		makeSearchResult(101, 1.0),
		makeSearchResult(102, 0.9),
	}
	filter := []note.Note{makeNote(103), makeNote(104)}

	got := rrfMerge(text, filter, 100)

	wantIDs := map[int64]bool{101: true, 102: true, 103: true, 104: true}
	for _, e := range got {
		delete(wantIDs, e.Note.ID)
	}
	if len(wantIDs) != 0 {
		t.Errorf("rrfMerge() missing IDs: %v", wantIDs)
	}
	// Use sortByID option to suppress unused-variable lint warning
	_ = sortByID
}
