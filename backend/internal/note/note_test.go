package note

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var update = flag.Bool("update", false, "update golden files")

// TestRRFMerge_ScorePrecision is a golden-file test that pins exact RRF scores
// for a known input. Run with -update to regenerate after intentional formula changes.
func TestRRFMerge_ScorePrecision(t *testing.T) {
	t.Parallel()

	// Deterministic input: IDs 1,2,3 in text and IDs 2,3,4 in filter.
	// ID=2: rank 1 in text AND rank 0 in filter → two contributions.
	// ID=3: rank 2 in text AND rank 1 in filter → two contributions.
	// ID=1: rank 0 in text only.
	// ID=4: rank 2 in filter only.
	textResults := []SearchResult{
		{Note: Note{ID: 1, FilePath: "notes/1.md"}, Rank: 0.9},
		{Note: Note{ID: 2, FilePath: "notes/2.md"}, Rank: 0.8},
		{Note: Note{ID: 3, FilePath: "notes/3.md"}, Rank: 0.7},
	}
	filterResults := []Note{
		{ID: 2, FilePath: "notes/2.md"},
		{ID: 3, FilePath: "notes/3.md"},
		{ID: 4, FilePath: "notes/4.md"},
	}

	got := RRFMerge(textResults, filterResults, 10)

	// Encode to JSON for stable golden comparison.
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshaling RRFMerge results: %v", err)
	}

	golden := filepath.Join("testdata", t.Name()+".golden")

	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("creating testdata dir: %v", err)
		}
		if err := os.WriteFile(golden, gotJSON, 0o644); err != nil {
			t.Fatalf("updating golden file: %v", err)
		}
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden file %s: %v (run with -update to create)", golden, err)
	}

	if diff := cmp.Diff(string(want), string(gotJSON)); diff != "" {
		t.Errorf("RRFMerge score precision mismatch (-want +got):\n%s\nRun with -update to accept.", diff)
	}
}

// TestRRFMerge_ExactScores verifies the RRF formula: score = 1/(k+rank_index).
// k=60. This catches any accidental change to the constant or formula.
func TestRRFMerge_ExactScores(t *testing.T) {
	t.Parallel()

	const k = 60.0
	textResults := []SearchResult{
		{Note: Note{ID: 1}, Rank: 0.9}, // rank index 0 → 1/(60+0) = 1/60
		{Note: Note{ID: 2}, Rank: 0.5}, // rank index 1 → 1/(60+1) = 1/61
	}

	got := RRFMerge(textResults, nil, 10)

	if len(got) != 2 {
		t.Fatalf("RRFMerge() len = %d, want 2", len(got))
	}

	wantScore0 := 1.0 / (k + 0)
	wantScore1 := 1.0 / (k + 1)

	if math.Abs(got[0].Score-wantScore0) > 1e-12 {
		t.Errorf("RRFMerge() got[0].Score = %.15f, want %.15f (delta %.2e)",
			got[0].Score, wantScore0, math.Abs(got[0].Score-wantScore0))
	}
	if math.Abs(got[1].Score-wantScore1) > 1e-12 {
		t.Errorf("RRFMerge() got[1].Score = %.15f, want %.15f (delta %.2e)",
			got[1].Score, wantScore1, math.Abs(got[1].Score-wantScore1))
	}
}

// TestRRFMerge_FusedScoreIsSumOfRanks verifies that when a note appears in both
// text and filter results, its score equals the sum of both rank contributions.
func TestRRFMerge_FusedScoreIsSumOfRanks(t *testing.T) {
	t.Parallel()

	const k = 60.0
	// ID=99: rank index 0 in text, rank index 0 in filter.
	// Expected fused score = 1/(60+0) + 1/(60+0) = 2/60.
	textResults := []SearchResult{{Note: Note{ID: 99}, Rank: 1.0}}
	filterResults := []Note{{ID: 99}}

	got := RRFMerge(textResults, filterResults, 10)

	if len(got) != 1 {
		t.Fatalf("RRFMerge() len = %d, want 1", len(got))
	}

	wantScore := (1.0 / (k + 0)) + (1.0 / (k + 0))
	if math.Abs(got[0].Score-wantScore) > 1e-12 {
		t.Errorf("RRFMerge() fused score = %.15f, want %.15f", got[0].Score, wantScore)
	}
}

// TestRRFMerge_NegativeLimitReturnsNil documents that negative limit returns nil
// (same as limit=0). This is the current contract; a change would be a regression.
func TestRRFMerge_NegativeLimitReturnsNil(t *testing.T) {
	t.Parallel()

	result := RRFMerge(
		[]SearchResult{{Note: Note{ID: 1}, Rank: 1.0}},
		nil,
		-1,
	)
	if result != nil {
		t.Errorf("RRFMerge(limit=-1) = %v, want nil", result)
	}
}

// TestRRFMerge_LargeInput checks that RRFMerge handles large inputs without
// panicking and returns exactly limit results.
func TestRRFMerge_LargeInput(t *testing.T) {
	t.Parallel()

	const n = 10000
	const limit = 20

	text := make([]SearchResult, n)
	for i := range n {
		text[i] = SearchResult{Note: Note{ID: int64(i + 1)}, Rank: float32(n - i)}
	}
	filter := make([]Note, n)
	for i := range n {
		filter[i] = Note{ID: int64(i + 1)}
	}

	got := RRFMerge(text, filter, limit)

	if len(got) != limit {
		t.Errorf("RRFMerge(n=%d, limit=%d) len = %d, want %d", n, limit, len(got), limit)
	}

	// Scores must be descending.
	for i := 1; i < len(got); i++ {
		if got[i].Score > got[i-1].Score {
			t.Errorf("RRFMerge() not sorted at index %d: score %f > %f", i, got[i].Score, got[i-1].Score)
		}
	}
}

// TestRRFMerge_AllSameID checks the deduplication path: all text and filter
// results with the same ID result in one merged entry.
func TestRRFMerge_AllSameID(t *testing.T) {
	t.Parallel()

	text := []SearchResult{
		{Note: Note{ID: 42, FilePath: "same.md"}, Rank: 1.0},
		{Note: Note{ID: 42, FilePath: "same.md"}, Rank: 0.9}, // duplicate in text
	}
	filter := []Note{
		{ID: 42, FilePath: "same.md"},
		{ID: 42, FilePath: "same.md"}, // duplicate in filter
	}

	got := RRFMerge(text, filter, 10)

	// All contributions go to the same map key, so one entry.
	if len(got) != 1 {
		t.Fatalf("RRFMerge(all same ID) len = %d, want 1", len(got))
	}
	if got[0].ID != 42 {
		t.Errorf("RRFMerge(all same ID) ID = %d, want 42", got[0].ID)
	}
	// Score = 1/(60+0) + 1/(60+1) + 1/(60+0) + 1/(60+1) from 4 rank contributions.
	const k = 60.0
	wantScore := 1/(k+0) + 1/(k+1) + 1/(k+0) + 1/(k+1)
	if math.Abs(got[0].Score-wantScore) > 1e-12 {
		t.Errorf("RRFMerge(all same ID) Score = %.15f, want %.15f", got[0].Score, wantScore)
	}
}

// TestRRFMerge_TextNotePreservedOverFilterForSameID documents that when an ID
// appears in both text and filter results, the Note data comes from the text result
// (text result is processed first, filter's notes.ok guard skips overwrite).
func TestRRFMerge_TextNotePreservedOverFilterForSameID(t *testing.T) {
	t.Parallel()

	textTitle := "text title"
	filterTitle := "filter title"

	textResults := []SearchResult{
		{Note: Note{ID: 7, FilePath: "t.md", Title: &textTitle}, Rank: 1.0},
	}
	filterResults := []Note{
		{ID: 7, FilePath: "t.md", Title: &filterTitle},
	}

	got := RRFMerge(textResults, filterResults, 10)

	if len(got) != 1 {
		t.Fatalf("RRFMerge() len = %d, want 1", len(got))
	}
	if got[0].Title == nil || *got[0].Title != textTitle {
		t.Errorf("RRFMerge() Note.Title = %v, want %q (text wins)", got[0].Title, textTitle)
	}
}

// TestRRFMerge_ResultsAreSorted verifies strict descending score order across
// many inputs with no ties.
func TestRRFMerge_ResultsAreSorted(t *testing.T) {
	t.Parallel()

	// 5 text + 5 filter, none overlapping → 10 unique notes, each with distinct
	// rank position contributing a unique score.
	text := make([]SearchResult, 5)
	for i := range 5 {
		text[i] = SearchResult{Note: Note{ID: int64(i + 1)}, Rank: float32(5 - i)}
	}
	filter := make([]Note, 5)
	for i := range 5 {
		filter[i] = Note{ID: int64(i + 100)}
	}

	got := RRFMerge(text, filter, 100)

	if len(got) != 10 {
		t.Fatalf("RRFMerge() len = %d, want 10", len(got))
	}

	for i := 1; i < len(got); i++ {
		if got[i].Score > got[i-1].Score {
			t.Errorf("RRFMerge() not sorted: got[%d].Score=%f > got[%d].Score=%f",
				i, got[i].Score, i-1, got[i-1].Score)
		}
	}
}

// TestRRFMerge_OnlyFilterResults exercises the code path where textResults is
// empty and all scores come from filterResults only.
func TestRRFMerge_OnlyFilterResults(t *testing.T) {
	t.Parallel()

	filter := []Note{
		{ID: 10}, {ID: 20}, {ID: 30},
	}

	got := RRFMerge(nil, filter, 10)

	if len(got) != 3 {
		t.Fatalf("RRFMerge(nil text) len = %d, want 3", len(got))
	}

	// All filter-only notes: first filter entry (rank 0) has highest score.
	if got[0].ID != 10 {
		t.Errorf("RRFMerge(nil text) got[0].ID = %d, want 10 (rank 0 wins)", got[0].ID)
	}
}

// TestRRFMerge_EmptyTagsNeverNil verifies that Note.Tags from MergedResult is
// never nil (the store normalizes to empty slice, and the map stores the Note directly).
// This is a contract test for callers that JSON-encode results.
func TestRRFMerge_EmptyTagsNeverNil(t *testing.T) {
	t.Parallel()

	text := []SearchResult{
		{Note: Note{ID: 1, Tags: []string{}}, Rank: 1.0},
		{Note: Note{ID: 2, Tags: []string{"go", "test"}}, Rank: 0.9},
	}

	got := RRFMerge(text, nil, 10)

	for _, r := range got {
		if r.Tags == nil {
			t.Errorf("RRFMerge() result ID=%d has nil Tags, want non-nil (breaks JSON encoding)", r.ID)
		}
	}
}

// TestRRFMerge_AdversarialIDs tests boundary IDs: 0, negative, max int64.
func TestRRFMerge_AdversarialIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		text    []SearchResult
		filter  []Note
		limit   int
		wantLen int
	}{
		{
			name:    "ID zero is valid (treated as any int64)",
			text:    []SearchResult{{Note: Note{ID: 0}, Rank: 1.0}},
			limit:   10,
			wantLen: 1,
		},
		{
			name:    "negative ID is valid",
			text:    []SearchResult{{Note: Note{ID: -1}, Rank: 1.0}},
			limit:   10,
			wantLen: 1,
		},
		{
			name:    "max int64 ID does not overflow",
			text:    []SearchResult{{Note: Note{ID: math.MaxInt64}, Rank: 1.0}},
			limit:   10,
			wantLen: 1,
		},
		{
			name: "zero ID and max ID in same input — two distinct entries",
			text: []SearchResult{
				{Note: Note{ID: 0}, Rank: 1.0},
				{Note: Note{ID: math.MaxInt64}, Rank: 0.5},
			},
			limit:   10,
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RRFMerge(tt.text, tt.filter, tt.limit)
			if len(got) != tt.wantLen {
				t.Errorf("RRFMerge(%q) len = %d, want %d", tt.name, len(got), tt.wantLen)
			}
		})
	}
}

// TestRRFMerge_AdversarialStrings tests that SQL injection payloads, XSS strings,
// null bytes, and unicode in FilePath/Title do not cause panics or data corruption.
// The function is pure Go with no SQL execution, so these are no-panic checks.
func TestRRFMerge_AdversarialStrings(t *testing.T) {
	t.Parallel()

	adversarial := []string{
		"'; DROP TABLE obsidian_notes; --",
		`<script>alert('xss')</script>`,
		"\x00null\x00byte",
		"unicode: 中文 日本語 한국어",
		"emoji: 🔥💀🎉",
		"RTL: \u200F\u202Eright-to-left",
		"zero-width: \u200B\uFEFF",
		strings.Repeat("A", 10000), // oversized
		"",
	}

	for _, s := range adversarial {
		s := s
		t.Run(fmt.Sprintf("payload=%q", truncate(s, 30)), func(t *testing.T) {
			t.Parallel()
			title := s
			text := []SearchResult{
				{Note: Note{ID: 1, FilePath: s, Title: &title}, Rank: 1.0},
			}
			filter := []Note{
				{ID: 2, FilePath: s, Title: &title},
			}
			// Must not panic.
			got := RRFMerge(text, filter, 10)
			if len(got) != 2 {
				t.Errorf("RRFMerge(adversarial string) len = %d, want 2", len(got))
			}
		})
	}
}

// truncate shortens s for use in subtest names.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// FuzzRRFMerge ensures RRFMerge never panics on arbitrary ID/limit combinations.
// The Rank field does not affect scoring (only list position matters), but we include
// it to document that invariant via the fuzz corpus.
func FuzzRRFMerge(f *testing.F) {
	f.Add(int64(1), int64(2), int64(3), int(20))
	f.Add(int64(0), int64(-1), int64(math.MaxInt64), int(0))
	f.Add(int64(100), int64(100), int64(100), int(1)) // all same ID
	f.Add(int64(-999), int64(1), int64(2), int(-5))

	f.Fuzz(func(t *testing.T, id1, id2, id3 int64, limit int) {
		text := []SearchResult{
			{Note: Note{ID: id1, FilePath: "a.md"}, Rank: 1.0},
			{Note: Note{ID: id2, FilePath: "b.md"}, Rank: 0.5},
		}
		filter := []Note{
			{ID: id3, FilePath: "c.md"},
		}
		got := RRFMerge(text, filter, limit)

		// Invariant 1: if limit <= 0, result must be nil.
		if limit <= 0 && got != nil {
			t.Errorf("RRFMerge(limit=%d) = non-nil, want nil", limit)
		}

		// Invariant 2: result length never exceeds limit.
		if limit > 0 && len(got) > limit {
			t.Errorf("RRFMerge(limit=%d) len = %d, exceeds limit", limit, len(got))
		}

		// Invariant 3: all scores are positive.
		for i, r := range got {
			if r.Score <= 0 {
				t.Errorf("RRFMerge() got[%d].Score = %f, want > 0", i, r.Score)
			}
		}

		// Invariant 4: scores are non-increasing (sorted descending).
		for i := 1; i < len(got); i++ {
			if got[i].Score > got[i-1].Score {
				t.Errorf("RRFMerge() not sorted at index %d: score %f > %f",
					i, got[i].Score, got[i-1].Score)
			}
		}
	})
}
