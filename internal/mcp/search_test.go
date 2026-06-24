// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"slices"
	"testing"
	"time"

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

// ============================================================================
// Consolidated from search_contract_test.go (Track-1K test-file consolidation).
// ============================================================================

// search_contract_test.go holds the pre-DB (nil-store) contract units for
// search_knowledge: input validation that fires before any store call.
// DB-backed corpus / envelope / filter / degradation coverage lives in
// search_integration_test.go.
//
// These units assert error contracts only — the DB-backed corpus, filter,
// and degradation coverage lives in the integration tests.

// TestSearchKnowledge_Validation pins the handler validation paths that return
// before search_knowledge touches the content store. newTestServer has nil
// stores, so any case here that reached a store would panic — the fact that
// these return a clean error proves the rejection is pre-store.
func TestSearchKnowledge_Validation(t *testing.T) {
	s := newTestServer()
	tests := []struct {
		name    string
		input   SearchKnowledgeInput
		wantErr string
	}{
		{name: "missing query", input: SearchKnowledgeInput{}, wantErr: "query is required"},
		{
			name:    "malformed after date",
			input:   SearchKnowledgeInput{Query: "go", After: new("not-a-date")},
			wantErr: "invalid after date",
		},
		{
			name:    "malformed before date",
			input:   SearchKnowledgeInput{Query: "go", Before: new("13/2026")},
			wantErr: "invalid before date",
		},
		{
			name:    "unsupported content_type rejected",
			input:   SearchKnowledgeInput{Query: "go", ContentType: new("banana-not-a-type")},
			wantErr: "unsupported content_type",
		},
		{
			name:    "project filter rejected as unsupported",
			input:   SearchKnowledgeInput{Query: "go", Project: new("koopa")},
			wantErr: "unsupported_filter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := callHandler(t, s.searchKnowledge, tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestSearchKnowledge_DateBoundaryFilter pins the whole-day-inclusive date
// semantics at the same-day boundary, the case Track 1G left untested. With
// after=D and before=D, a row created at ANY instant during day D — including
// 00:00:00 and 23:59:59 — must be kept, while the last instant of D-1 and the
// first instant of D+1 must be dropped. Exercises the real bound construction
// (parseDateStart / parseDateEnd) and the filter comparison together. No order
// or ranking assertion.
func TestSearchKnowledge_DateBoundaryFilter(t *testing.T) {
	loc := time.UTC
	const day = "2026-05-22"

	after, err := parseDateStart(new(day), loc)
	if err != nil {
		t.Fatalf("parseDateStart(%q): %v", day, err)
	}
	before, err := parseDateEnd(new(day), loc)
	if err != nil {
		t.Fatalf("parseDateEnd(%q): %v", day, err)
	}

	at := func(s string) time.Time {
		ts, perr := time.ParseInLocation(time.RFC3339, s, loc)
		if perr != nil {
			t.Fatalf("parse %q: %v", s, perr)
		}
		return ts
	}

	tests := []struct {
		name    string
		created time.Time
		wantIn  bool
	}{
		{name: "start of day D kept", created: at("2026-05-22T00:00:00Z"), wantIn: true},
		{name: "midday D kept", created: at("2026-05-22T12:30:00Z"), wantIn: true},
		{name: "last second of D kept", created: at("2026-05-22T23:59:59Z"), wantIn: true},
		{name: "last second of D-1 dropped", created: at("2026-05-21T23:59:59Z"), wantIn: false},
		{name: "start of D+1 dropped", created: at("2026-05-23T00:00:00Z"), wantIn: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Filtering now happens in SQL (created_at >= after AND
			// created_at < before). Assert the parsed bounds, applied with
			// that exact comparison, give whole-day-D-inclusive semantics.
			kept := !tt.created.Before(*after) && tt.created.Before(*before)
			if kept != tt.wantIn {
				t.Errorf("after=%s before=%s created=%s: kept=%v, want %v",
					after.Format(time.RFC3339), before.Format(time.RFC3339),
					tt.created.Format(time.RFC3339), kept, tt.wantIn)
			}
		})
	}
}
