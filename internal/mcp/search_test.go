// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/reading"
	"github.com/Koopa0/koopa/internal/song"
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
// search_knowledge: input validation that fires before any store call, and
// the source_types resolution helper. DB-backed corpus / envelope / filter /
// degradation coverage lives in search_integration_test.go.
//
// These units assert error contracts only. The Track 1G boundary remains
// intact for the DB-backed tier-1 evaluator, which still asserts presence/
// absence/narrowing only, never ranking METRICS (guarded by
// TestSearchRelevanceHarness_NoRankingAssertions).

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
			name:    "unknown source_type rejected",
			input:   SearchKnowledgeInput{Query: "go", SourceTypes: []string{"bookmark"}},
			wantErr: "unsupported source_type",
		},
		{
			name:    "mixed valid and invalid source_types rejected",
			input:   SearchKnowledgeInput{Query: "go", SourceTypes: []string{SourceTypeContent, "task"}},
			wantErr: "unsupported source_type",
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

// TestSearchKnowledge_SourceTypeValidation pins the strict source_types
// contract: only {content} is accepted; any other token (typo or an
// unsupported corpus) is a validation error, and an all-unknown list does NOT
// degrade to a silent empty success. Empty/nil is valid (resolves to content).
func TestSearchKnowledge_SourceTypeValidation(t *testing.T) {
	tests := []struct {
		name    string
		filter  []string
		wantErr bool
	}{
		{name: "nil accepted", filter: nil, wantErr: false},
		{name: "empty accepted", filter: []string{}, wantErr: false},
		{name: "content accepted", filter: []string{SourceTypeContent}, wantErr: false},
		{name: "single unknown rejected", filter: []string{"bookmark"}, wantErr: true},
		{name: "all unknown rejected", filter: []string{"bookmark", "task"}, wantErr: true},
		{name: "mixed valid and invalid rejected", filter: []string{SourceTypeContent, "task"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSourceTypes(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSourceTypes(%v) error = %v, wantErr = %v", tt.filter, err, tt.wantErr)
			}
		})
	}
}

// TestSearchKnowledge_SourceTypeValidation_Corpora pins that the expanded
// corpus set {content, reading, song} is accepted and reflections are not a
// source type. The pre-DB validator must accept each known corpus and any
// combination of them, while still rejecting unknown tokens and the
// reflection-as-corpus mistake.
func TestSearchKnowledge_SourceTypeValidation_Corpora(t *testing.T) {
	tests := []struct {
		name    string
		filter  []string
		wantErr bool
	}{
		{name: "reading accepted", filter: []string{SourceTypeReading}, wantErr: false},
		{name: "song accepted", filter: []string{SourceTypeSong}, wantErr: false},
		{name: "all three accepted", filter: []string{SourceTypeContent, SourceTypeReading, SourceTypeSong}, wantErr: false},
		{name: "reading plus song accepted", filter: []string{SourceTypeReading, SourceTypeSong}, wantErr: false},
		{name: "reflection is not a source type", filter: []string{"reflection"}, wantErr: true},
		{name: "song_reflection rejected", filter: []string{"song_reflection"}, wantErr: true},
		{name: "reading plus unknown rejected", filter: []string{SourceTypeReading, "bookmark"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSourceTypes(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSourceTypes(%v) error = %v, wantErr = %v", tt.filter, err, tt.wantErr)
			}
		})
	}
}

// TestSelectSources pins the corpus-resolution rules: nil/empty defaults to all
// three in canonical order, a subset is normalised to canonical order (caller
// order/repeats ignored), and a content_type filter collapses the corpus to
// content alone.
func TestSelectSources(t *testing.T) {
	article := "article"
	tests := []struct {
		name        string
		requested   []string
		contentType *string
		want        []string
	}{
		{name: "nil defaults to all", requested: nil, want: []string{SourceTypeContent, SourceTypeReading, SourceTypeSong}},
		{name: "empty defaults to all", requested: []string{}, want: []string{SourceTypeContent, SourceTypeReading, SourceTypeSong}},
		{name: "subset normalised to canonical order", requested: []string{SourceTypeSong, SourceTypeContent}, want: []string{SourceTypeContent, SourceTypeSong}},
		{name: "repeats deduped", requested: []string{SourceTypeReading, SourceTypeReading}, want: []string{SourceTypeReading}},
		{name: "content_type collapses to content", requested: nil, contentType: &article, want: []string{SourceTypeContent}},
		{name: "content_type collapses even with reading requested", requested: []string{SourceTypeContent, SourceTypeReading}, contentType: &article, want: []string{SourceTypeContent}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectSources(tt.requested, tt.contentType)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("selectSources(%v, %v) mismatch (-want +got):\n%s", tt.requested, tt.contentType, diff)
			}
		})
	}
}

// TestSearchKnowledge_ContentTypeConflict pins that content_type combined with
// an explicit source_types list that excludes content is rejected — a content
// filter over a non-content corpus is a contradiction, not a silent no-op.
func TestSearchKnowledge_ContentTypeConflict(t *testing.T) {
	article := "article"
	tests := []struct {
		name    string
		input   SearchKnowledgeInput
		wantErr bool
	}{
		{
			name:    "content_type with reading-only source rejected",
			input:   SearchKnowledgeInput{Query: "go", ContentType: &article, SourceTypes: []string{SourceTypeReading}},
			wantErr: true,
		},
		{
			name:    "content_type with content in source accepted",
			input:   SearchKnowledgeInput{Query: "go", ContentType: &article, SourceTypes: []string{SourceTypeContent, SourceTypeReading}},
			wantErr: false,
		},
		{
			name:    "content_type with empty source accepted",
			input:   SearchKnowledgeInput{Query: "go", ContentType: &article},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSearchKnowledgeInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSearchKnowledgeInput error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestMergeByRank pins the round-robin interleave: each corpus's rank-0 hit
// first, then rank-1, etc., preserving per-corpus order, stopping at limit, and
// not starving a shorter corpus. Cross-corpus order at the same rank follows
// the perCorpus slice order.
func TestMergeByRank(t *testing.T) {
	mk := func(st, id string) SearchKnowledgeResult {
		return SearchKnowledgeResult{ID: id, SourceType: st}
	}
	contentHits := []SearchKnowledgeResult{mk("content", "c0"), mk("content", "c1"), mk("content", "c2")}
	readingHits := []SearchKnowledgeResult{mk("reading", "r0")}
	songHits := []SearchKnowledgeResult{mk("song", "s0"), mk("song", "s1")}

	tests := []struct {
		name      string
		perCorpus [][]SearchKnowledgeResult
		limit     int
		wantIDs   []string
	}{
		{
			name:      "round robin interleaves by rank",
			perCorpus: [][]SearchKnowledgeResult{contentHits, readingHits, songHits},
			limit:     20,
			// rank 0: c0,r0,s0 — rank 1: c1,(reading exhausted),s1 — rank 2: c2
			wantIDs: []string{"c0", "r0", "s0", "c1", "s1", "c2"},
		},
		{
			name:      "limit caps output mid-rank",
			perCorpus: [][]SearchKnowledgeResult{contentHits, readingHits, songHits},
			limit:     4,
			wantIDs:   []string{"c0", "r0", "s0", "c1"},
		},
		{
			name:      "single corpus preserves order",
			perCorpus: [][]SearchKnowledgeResult{contentHits},
			limit:     20,
			wantIDs:   []string{"c0", "c1", "c2"},
		},
		{
			name:      "all empty yields empty non-nil",
			perCorpus: [][]SearchKnowledgeResult{{}, {}},
			limit:     20,
			wantIDs:   []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeByRank(tt.perCorpus, tt.limit)
			gotIDs := make([]string, len(got))
			for i := range got {
				gotIDs[i] = got[i].ID
			}
			if diff := cmp.Diff(tt.wantIDs, gotIDs); diff != "" {
				t.Errorf("mergeByRank IDs mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRrfMergeResults_ConsensusAndDistinctReflections pins two properties of
// the reading/song RRF: (1) the same matched row appearing in both branches
// (same id + excerpt) fuses and outranks single-branch hits; (2) two distinct
// reflections under the SAME parent book (same id, different excerpt) stay
// separate — keying on parent id alone would wrongly collapse them.
func TestRrfMergeResults_ConsensusAndDistinctReflections(t *testing.T) {
	const book = "book-1"
	shelf := SearchKnowledgeResult{ID: book, SourceType: SourceTypeReading, Excerpt: "The Title"}
	reflA := SearchKnowledgeResult{ID: book, SourceType: SourceTypeReading, Excerpt: "diary entry A"}
	reflB := SearchKnowledgeResult{ID: book, SourceType: SourceTypeReading, Excerpt: "diary entry B"}

	// reflA is rank 2 in FTS and rank 0 in semantic — consensus. shelf and
	// reflB appear once each.
	fts := []SearchKnowledgeResult{shelf, reflB, reflA}
	sem := []SearchKnowledgeResult{reflA}

	got := rrfMergeResults(fts, sem, 10)

	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3 (shelf + two distinct reflections, none collapsed)", len(got))
	}
	if got[0].Excerpt != "diary entry A" {
		t.Errorf("consensus hit rank = %q, want %q first", got[0].Excerpt, "diary entry A")
	}
	excerpts := map[string]bool{}
	for _, r := range got {
		excerpts[r.Excerpt] = true
	}
	for _, want := range []string{"The Title", "diary entry A", "diary entry B"} {
		if !excerpts[want] {
			t.Errorf("rrfMergeResults dropped distinct row %q", want)
		}
	}
}

// TestReadingHitsToResults pins the reading hit → uniform result mapping: the
// parent book id/title link, the matched excerpt, source_type=reading, and an
// empty slug (readings have no slug).
func TestReadingHitsToResults(t *testing.T) {
	id := uuid.New()
	created := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	hits := []reading.CorpusHit{{ReadingID: id, Title: "Norwegian Wood", Excerpt: "a diary line", CreatedAt: created}}

	got := readingHitsToResults(hits)
	want := []SearchKnowledgeResult{{
		ID:         id.String(),
		SourceType: SourceTypeReading,
		Title:      "Norwegian Wood",
		Excerpt:    "a diary line",
		CreatedAt:  created.Format(time.RFC3339),
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("readingHitsToResults mismatch (-want +got):\n%s", diff)
	}
}

// TestSongHitsToResults pins the song hit → uniform result mapping.
func TestSongHitsToResults(t *testing.T) {
	id := uuid.New()
	created := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	hits := []song.CorpusHit{{SongID: id, Title: "花に亡霊", Excerpt: "a reflection line", CreatedAt: created}}

	got := songHitsToResults(hits)
	want := []SearchKnowledgeResult{{
		ID:         id.String(),
		SourceType: SourceTypeSong,
		Title:      "花に亡霊",
		Excerpt:    "a reflection line",
		CreatedAt:  created.Format(time.RFC3339),
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("songHitsToResults mismatch (-want +got):\n%s", diff)
	}
}

// TestFilterResultsByDate pins the whole-day-inclusive date window over the
// uniform result shape (the reading/song corpora path): after=before=D keeps a
// row created any time during D and drops D-1 / D+1; an unparseable timestamp
// is kept (the bound is best-effort over a server-formatted value).
func TestFilterResultsByDate(t *testing.T) {
	loc := time.UTC
	const day = "2026-05-22"
	after, _ := parseDateStart(new(day), loc)
	before, _ := parseDateEnd(new(day), loc)

	mk := func(ts string) SearchKnowledgeResult { return SearchKnowledgeResult{ID: "x", CreatedAt: ts} }
	tests := []struct {
		name   string
		in     SearchKnowledgeResult
		wantIn bool
	}{
		{name: "start of day kept", in: mk("2026-05-22T00:00:00Z"), wantIn: true},
		{name: "last second kept", in: mk("2026-05-22T23:59:59Z"), wantIn: true},
		{name: "previous day dropped", in: mk("2026-05-21T23:59:59Z"), wantIn: false},
		{name: "next day dropped", in: mk("2026-05-23T00:00:00Z"), wantIn: false},
		{name: "unparseable kept", in: mk("not-a-time"), wantIn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterResultsByDate([]SearchKnowledgeResult{tt.in}, after, before)
			gotIn := len(got) == 1
			if gotIn != tt.wantIn {
				t.Errorf("filterResultsByDate(%q) kept=%v, want %v", tt.in.CreatedAt, gotIn, tt.wantIn)
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
	s := newTestServer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents := []content.Content{{ID: uuid.New(), CreatedAt: tt.created}}
			got := s.filterContentResults(t.Context(), contents, nil, after, before)
			gotIn := len(got) == 1
			if gotIn != tt.wantIn {
				t.Errorf("before=after=%s, created=%s: kept=%v, want %v",
					day, tt.created.Format(time.RFC3339), gotIn, tt.wantIn)
			}
		})
	}
}

// ============================================================================
// Consolidated from search_relevance_fixture_test.go (Track-1K test-file consolidation).
// ============================================================================

// fixtureIDPattern matches the stable id format used by the judgment set: a
// category prefix that starts with a letter and may contain digits (KN, NEG,
// FLT, LRN, PLAN), a dash, and a two-digit number
// (`^[A-Z][A-Z0-9]{1,3}-[0-9]{2}$`).
var fixtureIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,3}-\d{2}$`)

// automationPossibleValues is the quoted-string enum the loader accepts.
// A YAML boolean (a bare `false`) is rejected before reaching here.
var automationPossibleValues = map[string]bool{"yes": true, "no": true, "partial": true}

// expectedOutcomeValues is the deterministic-outcome enum (schema §2). The
// tier-1 evaluator branches on results / empty / validation_error; judgment is
// the human-label class and is never tier-1 runnable.
var expectedOutcomeValues = map[string]bool{
	"results": true, "empty": true, "validation_error": true, "judgment": true,
}

// searchFixtureFilters mirrors the filter subset of SearchKnowledgeInput
// (search.go) a fixture may set. YAML keys match the wire `filters` object
// (schema §4). An absent key leaves the field at its zero value.
type searchFixtureFilters struct {
	SourceTypes []string `yaml:"source_types"`
	ContentType string   `yaml:"content_type"`
	Project     string   `yaml:"project"`
	After       string   `yaml:"after"`
	Before      string   `yaml:"before"`
	Limit       int      `yaml:"limit"`
}

// searchFixture is one normalized YAML fixture block. Only loader/evaluator-
// relevant fields are decoded; report-only criteria are kept for the run log.
// The yes/no-valued human-judgment fields are intentionally not decoded — they
// resolve to YAML strings here but carry no tier-1 meaning.
type searchFixture struct {
	FixtureID          string
	Query              string
	ScenarioCategory   string
	ExpectedOutcome    string
	Filters            searchFixtureFilters
	SeedRequirements   []string
	AutomationPossible string
	DateAnchor         string
	ShouldNotAppear    string // should_not_appear_criteria — report only
	Notes              string
}

// judgmentSetPath resolves the normalized judgment set relative to THIS source
// file via runtime.Caller, so the loader works regardless of the test working
// directory.
func judgmentSetPath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..",
		"docs", "testing", "search-relevance-judgment-set.md")
}

// extractYAMLBlocks returns the body of every ```yaml fenced block in md, in
// document order. Headings and surrounding prose are ignored — only fenced
// yaml is a fixture (workflow §6.0: read the block, not the prose).
func extractYAMLBlocks(md string) []string {
	lines := strings.Split(md, "\n")
	var blocks []string
	start := -1 // index of the first body line of the open block, or -1
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		switch {
		case start < 0 && trimmed == "```yaml":
			start = i + 1
		case start >= 0 && trimmed == "```":
			blocks = append(blocks, strings.Join(lines[start:i], "\n"))
			start = -1
		}
	}
	return blocks
}

// parseSearchFixtureBlock decodes one normalized YAML block into a searchFixture
// and validates the schema invariants the loader depends on. It requires the
// exact keys fixture_id, query, filters, seed_requirements, automation_possible
// to be PRESENT (not inferred), rejects an automation_possible that is not a
// quoted-string enum member, and never recovers a value from prose.
func parseSearchFixtureBlock(block string) (searchFixture, error) {
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(block), &raw); err != nil {
		return searchFixture{}, fmt.Errorf("yaml unmarshal: %w", err)
	}

	for _, key := range []string{"fixture_id", "query", "filters", "seed_requirements", "automation_possible"} {
		if _, ok := raw[key]; !ok {
			return searchFixture{}, fmt.Errorf("missing required field %q", key)
		}
	}

	var fx searchFixture

	// yaml.Node.Decode is a pointer method; a map index is not addressable, so
	// each node is copied to a local before decoding.
	idNode := raw["fixture_id"]
	if err := idNode.Decode(&fx.FixtureID); err != nil {
		return searchFixture{}, fmt.Errorf("fixture_id: %w", err)
	}
	if !fixtureIDPattern.MatchString(fx.FixtureID) {
		return searchFixture{}, fmt.Errorf("fixture_id %q does not match %s", fx.FixtureID, fixtureIDPattern)
	}

	queryNode := raw["query"]
	if err := queryNode.Decode(&fx.Query); err != nil {
		return searchFixture{}, fmt.Errorf("%s: query: %w", fx.FixtureID, err)
	}
	if strings.TrimSpace(fx.Query) == "" {
		return searchFixture{}, fmt.Errorf("%s: query is empty", fx.FixtureID)
	}

	// automation_possible must be a quoted string (tag !!str) in the enum.
	// An unquoted YAML boolean (tag !!bool — the pre-cleanup `false`) is
	// rejected here so the vocabulary stays {"yes","no","partial"}.
	ap := raw["automation_possible"]
	if ap.Tag != "!!str" {
		return searchFixture{}, fmt.Errorf("%s: automation_possible must be a quoted string, got YAML %s", fx.FixtureID, ap.Tag)
	}
	fx.AutomationPossible = ap.Value
	if !automationPossibleValues[fx.AutomationPossible] {
		return searchFixture{}, fmt.Errorf("%s: unsupported automation_possible %q (want \"yes\"|\"no\"|\"partial\")", fx.FixtureID, fx.AutomationPossible)
	}

	filtersNode := raw["filters"]
	if err := filtersNode.Decode(&fx.Filters); err != nil {
		return searchFixture{}, fmt.Errorf("%s: filters: %w", fx.FixtureID, err)
	}
	seedNode := raw["seed_requirements"]
	if err := seedNode.Decode(&fx.SeedRequirements); err != nil {
		return searchFixture{}, fmt.Errorf("%s: seed_requirements: %w", fx.FixtureID, err)
	}

	if n, ok := raw["expected_outcome"]; ok {
		if err := n.Decode(&fx.ExpectedOutcome); err != nil {
			return searchFixture{}, fmt.Errorf("%s: expected_outcome: %w", fx.FixtureID, err)
		}
		if fx.ExpectedOutcome != "" && !expectedOutcomeValues[fx.ExpectedOutcome] {
			return searchFixture{}, fmt.Errorf("%s: unsupported expected_outcome %q", fx.FixtureID, fx.ExpectedOutcome)
		}
	}
	if n, ok := raw["scenario_category"]; ok {
		_ = n.Decode(&fx.ScenarioCategory)
	}
	if n, ok := raw["date_anchor"]; ok {
		_ = n.Decode(&fx.DateAnchor)
	}
	if n, ok := raw["should_not_appear_criteria"]; ok {
		_ = n.Decode(&fx.ShouldNotAppear)
	}
	if n, ok := raw["notes"]; ok {
		_ = n.Decode(&fx.Notes)
	}

	return fx, nil
}

// parseJudgmentSet extracts and parses every normalized fixture block from md.
// It is the pure core (no filesystem, no testing) so it can be unit-tested with
// synthetic input.
func parseJudgmentSet(md string) ([]searchFixture, error) {
	blocks := extractYAMLBlocks(md)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("no ```yaml fixture blocks found")
	}
	fixtures := make([]searchFixture, 0, len(blocks))
	for i, b := range blocks {
		fx, err := parseSearchFixtureBlock(b)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i+1, err)
		}
		fixtures = append(fixtures, fx)
	}
	return fixtures, nil
}

// loadSearchFixtures reads and parses the on-disk judgment set. It fatals the
// test on any read or parse error — a malformed fixture is a fixture bug to fix
// in the judgment set, never something the loader guesses around (workflow §6.0).
func loadSearchFixtures(t *testing.T) []searchFixture {
	t.Helper()
	path := judgmentSetPath()
	//nolint:gosec // G304: fixed repo-relative path from runtime.Caller, not user input
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read judgment set %s: %v", path, err)
	}
	fixtures, err := parseJudgmentSet(string(data))
	if err != nil {
		t.Fatalf("parse judgment set %s: %v", path, err)
	}
	return fixtures
}

// skippedFixture records a fixture excluded from the tier-1 run and why.
type skippedFixture struct {
	FixtureID string
	Reason    string
}

// selectTier1 partitions fixtures into the tier-1 mechanical subset and the
// skipped remainder. A fixture is selected iff automation_possible == "yes" AND
// its prefix is NEG or FLT. Both conditions are checked independently so the
// skip reason is precise even if the two ever diverge.
func selectTier1(fixtures []searchFixture) (selected []searchFixture, skipped []skippedFixture) {
	for i := range fixtures {
		fx := &fixtures[i]
		prefix, _, _ := strings.Cut(fx.FixtureID, "-")
		isNegFlt := prefix == "NEG" || prefix == "FLT"
		switch {
		case fx.AutomationPossible != "yes":
			skipped = append(skipped, skippedFixture{
				FixtureID: fx.FixtureID,
				Reason:    fmt.Sprintf("automation_possible=%q — needs a human label or is manual/product-routing (not tier-1)", fx.AutomationPossible),
			})
		case !isNegFlt:
			skipped = append(skipped, skippedFixture{
				FixtureID: fx.FixtureID,
				Reason:    fmt.Sprintf("prefix %q is not a NEG/FLT mechanical control", prefix),
			})
		default:
			selected = append(selected, *fx)
		}
	}
	return selected, skipped
}

// --- parser tests (no DB; run by `go test ./internal/mcp`) ---

// TestSearchFixtures_ParseAllBlocks loads the real judgment set and asserts the
// full set parses, every block carries the required fields, and the counts
// match the coverage summary (28 fixtures total).
func TestSearchFixtures_ParseAllBlocks(t *testing.T) {
	fixtures := loadSearchFixtures(t)

	// 28 = KN(5) + LRN(5) + PLAN(5) + NEG(5) + FLT(8), per the judgment-set
	// coverage summary.
	const wantTotal = 28
	if len(fixtures) != wantTotal {
		t.Errorf("parsed %d fixtures, want %d", len(fixtures), wantTotal)
	}

	seen := map[string]bool{}
	for i := range fixtures {
		fx := &fixtures[i]
		if !fixtureIDPattern.MatchString(fx.FixtureID) {
			t.Errorf("fixture_id %q invalid", fx.FixtureID)
		}
		if seen[fx.FixtureID] {
			t.Errorf("duplicate fixture_id %q", fx.FixtureID)
		}
		seen[fx.FixtureID] = true
		if strings.TrimSpace(fx.Query) == "" {
			t.Errorf("%s: empty query", fx.FixtureID)
		}
		if !automationPossibleValues[fx.AutomationPossible] {
			t.Errorf("%s: automation_possible=%q not in enum", fx.FixtureID, fx.AutomationPossible)
		}
		if fx.ExpectedOutcome != "" && !expectedOutcomeValues[fx.ExpectedOutcome] {
			t.Errorf("%s: expected_outcome=%q not in enum", fx.FixtureID, fx.ExpectedOutcome)
		}
	}
}

// TestSearchFixtures_RejectInvalidVocabulary pins that the parser refuses any
// block that violates the loader contract — chiefly an automation_possible that
// is not a quoted-string enum member, plus missing required keys and a bad
// fixture_id.
func TestSearchFixtures_RejectInvalidVocabulary(t *testing.T) {
	const valid = `fixture_id: NEG-09
query: "zqxprobe"
filters: {}
seed_requirements: [X-1]
automation_possible: "yes"
expected_outcome: empty`

	tests := []struct {
		name  string
		block string
	}{
		{
			name: "automation_possible unquoted bool false",
			block: `fixture_id: NEG-09
query: "zqxprobe"
filters: {}
seed_requirements: [X-1]
automation_possible: false`,
		},
		{
			name: "automation_possible unquoted bool true",
			block: `fixture_id: NEG-09
query: "zqxprobe"
filters: {}
seed_requirements: [X-1]
automation_possible: true`,
		},
		{
			name: "automation_possible unknown string",
			block: `fixture_id: NEG-09
query: "zqxprobe"
filters: {}
seed_requirements: [X-1]
automation_possible: "maybe"`,
		},
		{
			name: "missing query",
			block: `fixture_id: NEG-09
filters: {}
seed_requirements: [X-1]
automation_possible: "yes"`,
		},
		{
			name: "missing filters",
			block: `fixture_id: NEG-09
query: "zqxprobe"
seed_requirements: [X-1]
automation_possible: "yes"`,
		},
		{
			name: "missing seed_requirements",
			block: `fixture_id: NEG-09
query: "zqxprobe"
filters: {}
automation_possible: "yes"`,
		},
		{
			name: "missing automation_possible",
			block: `fixture_id: NEG-09
query: "zqxprobe"
filters: {}
seed_requirements: [X-1]`,
		},
		{
			name: "bad fixture_id",
			block: `fixture_id: neg-9
query: "zqxprobe"
filters: {}
seed_requirements: [X-1]
automation_possible: "yes"`,
		},
		{
			name: "empty query",
			block: `fixture_id: NEG-09
query: ""
filters: {}
seed_requirements: [X-1]
automation_possible: "yes"`,
		},
	}

	// Sanity: the valid control parses.
	if _, err := parseSearchFixtureBlock(valid); err != nil {
		t.Fatalf("control block must parse, got %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseSearchFixtureBlock(tt.block); err == nil {
				t.Errorf("parseSearchFixtureBlock(%s) = nil error, want rejection", tt.name)
			}
		})
	}
}

// TestSearchFixtures_SelectNegFltOnly asserts the tier-1 selection is exactly
// NEG-01..05 + FLT-01..08, and that every other fixture is skipped with a
// reason. This is the boundary that keeps natural-language and product-gap
// fixtures out of the mechanical run.
func TestSearchFixtures_SelectNegFltOnly(t *testing.T) {
	fixtures := loadSearchFixtures(t)
	selected, skipped := selectTier1(fixtures)

	got := make([]string, 0, len(selected))
	for i := range selected {
		fx := &selected[i]
		got = append(got, fx.FixtureID)
		if fx.AutomationPossible != "yes" {
			t.Errorf("selected %s has automation_possible=%q, want \"yes\"", fx.FixtureID, fx.AutomationPossible)
		}
		if p, _, _ := strings.Cut(fx.FixtureID, "-"); p != "NEG" && p != "FLT" {
			t.Errorf("selected %s has non-NEG/FLT prefix", fx.FixtureID)
		}
	}

	want := []string{
		"NEG-01", "NEG-02", "NEG-03", "NEG-04", "NEG-05",
		"FLT-01", "FLT-02", "FLT-03", "FLT-04", "FLT-05", "FLT-06", "FLT-07", "FLT-08",
	}
	wantSet := map[string]bool{}
	for _, id := range want {
		wantSet[id] = true
	}
	if len(got) != len(want) {
		t.Errorf("selected %d fixtures %v, want %d %v", len(got), got, len(want), want)
	}
	for _, id := range got {
		if !wantSet[id] {
			t.Errorf("unexpected fixture %q in tier-1 selection", id)
		}
	}

	if len(skipped) != len(fixtures)-len(want) {
		t.Errorf("skipped %d, want %d", len(skipped), len(fixtures)-len(want))
	}
	for _, sk := range skipped {
		if strings.TrimSpace(sk.Reason) == "" {
			t.Errorf("skipped %s has no reason", sk.FixtureID)
		}
	}
}

// TestSearchRelevanceHarness_NoRankingAssertions guards the hard scope boundary
// (search-relevance-evaluation-workflow.md §7): the tier-1 search-relevance
// evaluator — TestIntegration_SearchRelevance_Tier1 and its scoreResults /
// tier1Expectations helpers, consolidated into integration_test.go — asserts
// only contract criteria (presence / absence / narrowing / rejection / empty),
// never ranking metrics.
//
// It scans integration_test.go for ranking-METRIC identifiers (the unambiguous
// signal). It deliberately does NOT forbid positional result indexing like
// Results[0]: reading a field off a result is not a ranking claim, and other
// integration tests use it legitimately. The prose word "rank" is likewise not
// scanned — it appears in the no-ranking disclaimers. The fixture parser (also
// consolidated, into search_test.go) makes no result assertions, so it is not
// scanned — and scanning this file would self-match the forbidden list below.
func TestSearchRelevanceHarness_NoRankingAssertions(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	integrationFile := filepath.Join(filepath.Dir(thisFile), "integration_test.go")
	//nolint:gosec // G304: fixed repo-relative path from runtime.Caller, not user input
	src, err := os.ReadFile(integrationFile)
	if err != nil {
		t.Fatalf("read integration source %s: %v", integrationFile, err)
	}
	text := string(src)

	// Identifiers that only appear when someone computes or asserts a ranking
	// metric — never in a contract assertion or a disclaimer comment.
	forbidden := []string{
		"nDCG", "ndcg", "NDCG", "MRR", "precision@", "recall@",
		"ExpectedRank", "expected_rank", "expectedTop", "topResult",
	}
	for _, tok := range forbidden {
		if strings.Contains(text, tok) {
			t.Errorf("integration_test.go contains ranking-metric construct %q — the search-relevance tier-1 evaluator must not assert ranking", tok)
		}
	}
}
