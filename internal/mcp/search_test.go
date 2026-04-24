package mcp

import (
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/Koopa0/koopa/internal/content"
)

// Stable per-index IDs so tests don't depend on random UUID generation.
func testID(i byte) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte{i})
}

func testContent(i byte) content.Content {
	return content.Content{ID: testID(i)}
}

// testRank returns the zero-based rank of want in out, or -1 if absent.
func testRank(out []content.Content, want uuid.UUID) int {
	for i := range out {
		if out[i].ID == want {
			return i
		}
	}
	return -1
}

// TestRrfMerge_SharedDocRanksFirst verifies the core hybrid-search
// invariant: a doc that appears in both branches (consensus) should beat
// any doc that appears in only one branch at the same rank. This is the
// whole point of RRF over naive concatenation.
func TestRrfMerge_SharedDocRanksFirst(t *testing.T) {
	// id(3) appears rank 3 in FTS and rank 1 in SEM — consensus case.
	fts := []content.Content{testContent(1), testContent(2), testContent(3)}
	sem := []content.Content{testContent(3), testContent(4), testContent(5)}
	got := rrfMerge(fts, sem, 5)

	if testRank(got, testID(3)) != 0 {
		t.Errorf("shared doc id(3) rank = %d, want 0 (consensus pick)",
			testRank(got, testID(3)))
	}
	if len(got) != 5 {
		t.Errorf("len(got) = %d, want 5 (all distinct docs preserved)", len(got))
	}
	if r := testRank(got, testID(1)); r > 1 {
		t.Errorf("FTS rank-1 doc id(1) landed at rank %d, want ≤ 1", r)
	}
}

// TestRrfMerge_LimitCapsOutput verifies the caller's limit is respected
// even when the union of inputs is larger.
func TestRrfMerge_LimitCapsOutput(t *testing.T) {
	fts := []content.Content{testContent(1), testContent(2), testContent(3)}
	sem := []content.Content{testContent(4), testContent(5)}
	got := rrfMerge(fts, sem, 2)
	if len(got) != 2 {
		t.Errorf("len(got) = %d, want 2 (limit)", len(got))
	}
}

// TestRrfMerge_EmptySemanticPreservesFTSOrder verifies that a single-
// branch RRF is a no-op on ordering — FTS rank 1 stays at output rank 1.
// This is important because the hybrid handler relies on this property
// when falling back to FTS on semantic branch failure.
func TestRrfMerge_EmptySemanticPreservesFTSOrder(t *testing.T) {
	fts := []content.Content{testContent(1), testContent(2), testContent(3)}
	got := rrfMerge(fts, nil, 5)
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	for i := range fts {
		if got[i].ID != fts[i].ID {
			t.Errorf("rank %d: got %s, want %s (FTS order must be preserved)",
				i, got[i].ID, fts[i].ID)
		}
	}
}

// TestRrfMerge_AllIDsPresentUnderLimit verifies completeness: when the
// union of inputs fits under limit, every input doc must appear exactly
// once in the output (dedup on ID).
func TestRrfMerge_AllIDsPresentUnderLimit(t *testing.T) {
	fts := []content.Content{testContent(1), testContent(2)}
	sem := []content.Content{testContent(3), testContent(4)}
	got := rrfMerge(fts, sem, 10)

	want := []uuid.UUID{testID(1), testID(2), testID(3), testID(4)}
	gotIDs := make([]uuid.UUID, len(got))
	for i := range got {
		gotIDs[i] = got[i].ID
	}
	for _, w := range want {
		if !slices.Contains(gotIDs, w) {
			t.Errorf("rrfMerge missing %s; got = %v", w, gotIDs)
		}
	}
}
