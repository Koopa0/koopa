package note

import (
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// makeNote creates a Note with the given ID for test convenience.
func makeNote(id int64) Note {
	return Note{ID: id}
}

// makeSearchResult creates a SearchResult with the given ID and rank.
func makeSearchResult(id int64, rank float32) SearchResult {
	return SearchResult{Note: makeNote(id), Rank: rank}
}

func TestRRFMerge(t *testing.T) { //nolint:gocognit // table-driven test with comprehensive cases
	t.Parallel()

	tests := []struct {
		name          string
		textResults   []SearchResult
		filterResults []Note
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
			textResults:   []SearchResult{makeSearchResult(1, 1.0)},
			filterResults: nil,
			limit:         10,
			wantLen:       1,
			wantFirstID:   1,
		},
		{
			name:          "single filter result only",
			textResults:   nil,
			filterResults: []Note{makeNote(2)},
			limit:         10,
			wantLen:       1,
			wantFirstID:   2,
		},
		{
			name:          "non-overlapping sources merged and sorted by score",
			textResults:   []SearchResult{makeSearchResult(1, 1.0)},
			filterResults: []Note{makeNote(2)},
			limit:         10,
			wantLen:       2,
		},
		{
			name:          "overlapping item scores are summed",
			textResults:   []SearchResult{makeSearchResult(1, 1.0), makeSearchResult(2, 0.5)},
			filterResults: []Note{makeNote(1)},
			limit:         10,
			wantLen:       2,
			wantFirstID:   1,
		},
		{
			name: "limit is respected",
			textResults: []SearchResult{
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
			textResults: []SearchResult{
				makeSearchResult(10, 1.0),
				makeSearchResult(20, 0.9),
			},
			filterResults: nil,
			limit:         100,
			wantLen:       2,
		},
		{
			name:          "limit zero returns empty",
			textResults:   []SearchResult{makeSearchResult(1, 1.0)},
			filterResults: nil,
			limit:         0,
			wantLen:       0,
		},
		{
			name: "top result has highest score — earlier rank wins",
			textResults: []SearchResult{
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
			name:          "note data preserved from text results for overlapping IDs",
			textResults:   []SearchResult{makeSearchResult(1, 1.0)},
			filterResults: []Note{makeNote(1)},
			limit:         10,
			wantLen:       1,
			wantFirstID:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RRFMerge(tt.textResults, tt.filterResults, tt.limit)

			if len(got) != tt.wantLen {
				t.Errorf("RRFMerge() len = %d, want %d", len(got), tt.wantLen)
				return
			}
			if tt.wantLen == 0 {
				return
			}
			if tt.wantFirstID != 0 && got[0].ID != tt.wantFirstID {
				t.Errorf("RRFMerge() got[0].ID = %d, want %d", got[0].ID, tt.wantFirstID)
			}
			if tt.wantIDs != nil {
				gotIDs := make([]int64, len(got))
				for i, e := range got {
					gotIDs[i] = e.ID
				}
				if diff := cmp.Diff(tt.wantIDs, gotIDs); diff != "" {
					t.Errorf("RRFMerge() IDs mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestRRFMerge_ScoreOrdering(t *testing.T) {
	t.Parallel()

	// ID=30: rank 0 in text AND rank 0 in filter → score = 2/60 (highest)
	// ID=10: rank 1 in text → score = 1/61
	// ID=20: rank 1 in filter → score = 1/61
	text := []SearchResult{
		makeSearchResult(30, 1.0),
		makeSearchResult(10, 0.5),
	}
	filter := []Note{makeNote(30), makeNote(20)}

	got := RRFMerge(text, filter, 10)

	if len(got) != 3 {
		t.Fatalf("RRFMerge() len = %d, want 3", len(got))
	}
	if got[0].ID != 30 {
		t.Errorf("RRFMerge() got[0].ID = %d, want 30 (highest fused score)", got[0].ID)
	}

	for i, e := range got {
		if e.Score <= 0 {
			t.Errorf("RRFMerge() got[%d].Score = %f, want > 0", i, e.Score)
		}
	}

	for i := 1; i < len(got); i++ {
		if got[i].Score > got[i-1].Score {
			t.Errorf("RRFMerge() not sorted: got[%d].Score=%f > got[%d].Score=%f",
				i, got[i].Score, i-1, got[i-1].Score)
		}
	}
}

func TestRRFMerge_ResultsContainNoZeroScores(t *testing.T) {
	t.Parallel()

	text := []SearchResult{
		makeSearchResult(1, 1.0),
		makeSearchResult(2, 0.8),
		makeSearchResult(3, 0.6),
	}
	filter := []Note{makeNote(4), makeNote(5)}

	got := RRFMerge(text, filter, 10)
	for i, e := range got {
		if e.Score == 0 {
			t.Errorf("RRFMerge() got[%d].Score = 0, all scores must be positive", i)
		}
	}
}

func TestRRFMerge_FilterResultNoteNotOverwritten(t *testing.T) {
	t.Parallel()

	// When ID=1 appears in both text and filter, note data comes from textResults (first writer wins).
	title := "from text"
	textNote := SearchResult{
		Note: Note{ID: 1, Title: &title},
		Rank: 1.0,
	}
	filterTitle := "from filter"
	filterNote := Note{ID: 1, Title: &filterTitle}

	got := RRFMerge([]SearchResult{textNote}, []Note{filterNote}, 10)

	if len(got) != 1 {
		t.Fatalf("RRFMerge() len = %d, want 1", len(got))
	}
	if got[0].Title == nil || *got[0].Title != title {
		t.Errorf("RRFMerge() note title = %v, want %q (from text results)", got[0].Title, title)
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
			text := make([]SearchResult, sz.textCount)
			for i := range sz.textCount {
				text[i] = makeSearchResult(int64(i+1), float32(sz.textCount-i))
			}
			filter := make([]Note, sz.filterCount)
			for i := range sz.filterCount {
				filter[i] = makeNote(int64(i + 1))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = RRFMerge(text, filter, 20)
			}
		})
	}
}

func TestRRFMerge_AllInputIDsPresent(t *testing.T) {
	t.Parallel()

	text := []SearchResult{
		makeSearchResult(101, 1.0),
		makeSearchResult(102, 0.9),
	}
	filter := []Note{makeNote(103), makeNote(104)}

	got := RRFMerge(text, filter, 100)

	wantIDs := map[int64]bool{101: true, 102: true, 103: true, 104: true}
	for _, e := range got {
		delete(wantIDs, e.ID)
	}
	if len(wantIDs) != 0 {
		t.Errorf("RRFMerge() missing IDs: %v", wantIDs)
	}
}

// --- Adversarial input tests ---

func TestRRFMerge_AdversarialScores(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		text    []SearchResult
		filter  []Note
		limit   int
		checkFn func(t *testing.T, results []MergedResult)
	}{
		{
			name: "NaN rank",
			text: []SearchResult{
				{Note: Note{ID: 1, FilePath: "a.md"}, Rank: float32(math.NaN())},
				{Note: Note{ID: 2, FilePath: "b.md"}, Rank: 0.5},
			},
			limit: 10,
			checkFn: func(t *testing.T, results []MergedResult) {
				t.Helper()
				for _, r := range results {
					if math.IsNaN(r.Score) {
						t.Error("NaN score survived into output")
					}
				}
			},
		},
		{
			name: "Infinity rank",
			text: []SearchResult{
				{Note: Note{ID: 1, FilePath: "a.md"}, Rank: float32(math.Inf(1))},
				{Note: Note{ID: 2, FilePath: "b.md"}, Rank: float32(math.Inf(-1))},
			},
			limit: 10,
		},
		{
			name: "negative rank",
			text: []SearchResult{
				{Note: Note{ID: 1, FilePath: "a.md"}, Rank: -999},
			},
			limit: 10,
		},
		{
			name:  "empty inputs",
			limit: 10,
		},
		{
			name: "dedup across text and filter",
			text: []SearchResult{
				{Note: Note{ID: 1, FilePath: "same.md"}, Rank: 0.9},
			},
			filter: []Note{
				{ID: 1, FilePath: "same.md"},
			},
			limit: 10,
			checkFn: func(t *testing.T, results []MergedResult) {
				t.Helper()
				if len(results) != 1 {
					t.Errorf("expected 1 deduped result, got %d", len(results))
				}
			},
		},
		{name: "zero limit", text: []SearchResult{{Note: Note{ID: 1}, Rank: 0.5}}, limit: 0},
		{name: "negative limit", text: []SearchResult{{Note: Note{ID: 1}, Rank: 0.5}}, limit: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RRFMerge(tt.text, tt.filter, tt.limit)
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}
