// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pgvector/pgvector-go"
	"golang.org/x/sync/errgroup"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/embedder"
	"github.com/Koopa0/koopa/internal/note"
)

// searchKnowledgeHybridDeadline bounds the combined embed-query + semantic-SQL
// latency the handler is willing to spend on the semantic branch. On
// exhaustion the branch is abandoned and FTS results are served alone —
// search stays useful even when the Gemini API is slow or unreachable.
const searchKnowledgeHybridDeadline = 400 * time.Millisecond

// searchKnowledgeBranchSize controls how many rows each retrieval branch
// (FTS / semantic) returns before RRF. Top-30 per branch gives RRF enough
// recall to find consensus matches without shipping the full index
// through the process.
const searchKnowledgeBranchSize = 30

// rrfK is the standard RRF damping constant (Cormack et al. 2009). Small
// values over-weight top ranks; large values flatten the contribution of
// rank position. 60 is the canonical default and is what recent hybrid
// search literature uses as a baseline.
const rrfK = 60.0

// --- search_knowledge ---

// SourceType values for search results.
const (
	SourceTypeContent = "content"
	SourceTypeNote    = "note"
)

// SearchKnowledgeInput is the input for the search_knowledge tool.
type SearchKnowledgeInput struct {
	Query       string   `json:"query" jsonschema:"required" jsonschema_description:"Search query text"`
	ContentType *string  `json:"content_type,omitempty" jsonschema_description:"Filter by content type: article, essay, build-log, til, digest. An unknown value is rejected. Implies source_types=[\"content\"]; notes are excluded automatically. Mutually exclusive with note_kind."`
	NoteKind    *string  `json:"note_kind,omitempty" jsonschema_description:"Filter by note kind: solve-note, concept-note, debug-postmortem, decision-log, reading-note, musing. An unknown value is rejected. Implies source_types=[\"note\"]; content is excluded automatically. Mutually exclusive with content_type."`
	SourceTypes []string `json:"source_types,omitempty" jsonschema_description:"Filter by source: 'content' (articles/essays/etc), 'note' (Zettelkasten). Default: both. Any token outside {content, note} is rejected. Overridden by content_type or note_kind if either is set."`
	Project     *string  `json:"project,omitempty" jsonschema_description:"NOT SUPPORTED — passing a non-empty value is rejected as an unsupported_filter. Reserved for a future content-only project filter."`
	After       *string  `json:"after,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or after the whole of this day (server timezone, UTC by default)."`
	Before      *string  `json:"before,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or before the whole of this day, i.e. through 23:59:59 of the date (server timezone, UTC by default)."`
	Limit       FlexInt  `json:"limit,omitempty" jsonschema_description:"Max results (default 20, max 50)."`
}

// SearchKnowledgeResult is a single search result.
type SearchKnowledgeResult struct {
	ID          string `json:"id"`
	SourceType  string `json:"source_type"` // 'content' or 'note'
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	ContentType string `json:"content_type,omitempty"` // content.type when source_type=content
	NoteKind    string `json:"note_kind,omitempty"`    // note.kind when source_type=note
	Excerpt     string `json:"excerpt"`
	Project     string `json:"project,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// SearchKnowledgeOutput is the output of the search_knowledge tool.
type SearchKnowledgeOutput struct {
	Results []SearchKnowledgeResult `json:"results"`
	Total   int                     `json:"total"`
	Query   string                  `json:"query"`
	// SearchedCorpus lists the source types actually queried ("content",
	// "note"). It lets a caller read a 0-result response as "found none in
	// these corpora" rather than "does not exist".
	SearchedCorpus []string `json:"searched_corpus"`
}

func (s *Server) searchKnowledge(ctx context.Context, _ *mcp.CallToolRequest, input SearchKnowledgeInput) (*mcp.CallToolResult, SearchKnowledgeOutput, error) {
	if err := validateSearchKnowledgeInput(input); err != nil {
		return nil, SearchKnowledgeOutput{}, err
	}

	after, err := parseDateStart(input.After, s.loc)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("invalid after date: %w", err)
	}
	before, err := parseDateEnd(input.Before, s.loc)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("invalid before date: %w", err)
	}

	limit := clamp(int(input.Limit), 1, 50, 20)
	wantContent, wantNote := selectSources(input.SourceTypes)
	// A type-specific filter implies the corresponding source. Caller's
	// mental model is "I asked for articles, why did notes leak in?" —
	// passing content_type narrows to the content branch even if
	// source_types was unset (default both). Symmetric for note_kind.
	if input.ContentType != nil && *input.ContentType != "" {
		wantNote = false
	}
	if input.NoteKind != nil && *input.NoteKind != "" {
		wantContent = false
	}

	contentRows, noteRows, err := s.hybridSearch(ctx, input.Query, limit, wantContent, wantNote)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, err
	}

	// Each branch arrives already ordered by its own relevance score (fused
	// RRF rank, or native FTS rank when the semantic side came back empty).
	// The two scores live on incompatible scales, so the cross-source merge
	// fuses by rank position rather than comparing raw scores — see
	// mergeByRelevance.
	var contentResults, noteResults []SearchKnowledgeResult
	if wantContent {
		contentResults = s.filterContentResults(ctx, contentRows, input.ContentType, after, before)
	}
	if wantNote {
		noteResults = filterNoteResults(noteRows, input.NoteKind, after, before)
	}

	results := mergeByRelevance(contentResults, noteResults, limit)

	return nil, SearchKnowledgeOutput{
		Results:        results,
		Total:          len(results),
		Query:          input.Query,
		SearchedCorpus: searchedCorpusOf(wantContent, wantNote),
	}, nil
}

// searchedCorpusOf lists the source types actually queried, in stable order. It
// lets a 0-result response read as "found none in these corpora" rather than
// "does not exist".
func searchedCorpusOf(wantContent, wantNote bool) []string {
	out := make([]string, 0, 2)
	if wantContent {
		out = append(out, SourceTypeContent)
	}
	if wantNote {
		out = append(out, SourceTypeNote)
	}
	return out
}

// mergeByRelevance fuses the already-relevance-ranked branch result lists
// (content, note) into a single ranking, capped at limit. Each branch
// arrives ordered by its own relevance score — content by fused RRF rank,
// notes by ts_rank — and those scores live on incompatible scales, so raw
// scores are never compared across branches. Instead each result is scored by
// its RANK POSITION within its own branch via reciprocal rank fusion: a result
// at branch rank r (1-based) scores 1/(rrfK + r).
//
// CreatedAt (newer first) is a deterministic tie-breaker ONLY; it never
// outranks a more relevant result. The result envelope is always non-nil
// (JSON serialises to "results":[] when empty) — the json-api rule forbids
// null on list fields.
func mergeByRelevance(contentResults, noteResults []SearchKnowledgeResult, limit int) []SearchKnowledgeResult {
	type scored struct {
		result SearchKnowledgeResult
		score  float64
	}
	ranked := make([]scored, 0, len(contentResults)+len(noteResults))
	accumulate := func(branch []SearchKnowledgeResult, weight float64) {
		for i := range branch {
			ranked = append(ranked, scored{
				result: branch[i],
				score:  weight * (1.0 / (rrfK + float64(i+1))),
			})
		}
	}
	accumulate(contentResults, 1.0)
	accumulate(noteResults, 1.0)

	slices.SortStableFunc(ranked, func(a, b scored) int {
		if c := cmp.Compare(b.score, a.score); c != 0 {
			return c // higher fused rank score first
		}
		return cmp.Compare(b.result.CreatedAt, a.result.CreatedAt) // newer first on a tie
	})

	results := make([]SearchKnowledgeResult, 0, min(len(ranked), limit))
	for i := range ranked {
		if i >= limit {
			break
		}
		results = append(results, ranked[i].result)
	}
	return results
}

// hybridSearch runs the FTS branches and — when the embedder is wired —
// the semantic branches for the selected corpora in parallel, then fuses
// each corpus's two rankings with reciprocal rank fusion. An FTS error
// aborts the search; semantic failures degrade that corpus to FTS-only,
// so search stays useful when Gemini is slow or unreachable. Returned
// slices are ordered by fused rank (FTS rank when the semantic side is
// empty), capped at limit.
func (s *Server) hybridSearch(ctx context.Context, query string, limit int, wantContent, wantNote bool) ([]content.Content, []note.Note, error) {
	branchSize := max(limit, searchKnowledgeBranchSize)

	var (
		contentFTS, contentSem []content.Content
		noteFTS, noteSem       []note.Note
	)

	g, gctx := errgroup.WithContext(ctx)
	if wantContent {
		g.Go(func() error {
			rows, _, err := s.contents.InternalSearch(gctx, query, 1, branchSize)
			if err != nil {
				return fmt.Errorf("searching content: fts: %w", err)
			}
			contentFTS = rows
			return nil
		})
	}
	if wantNote {
		g.Go(func() error {
			rows, err := s.notes.Search(gctx, query, branchSize)
			if err != nil {
				return fmt.Errorf("searching notes: fts: %w", err)
			}
			noteFTS = rows
			return nil
		})
	}
	if s.embedder != nil && (wantContent || wantNote) {
		g.Go(func() error {
			contentSem, noteSem = s.semanticBranches(gctx, query, branchSize, wantContent, wantNote)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}

	contentRows := contentFTS
	if len(contentSem) > 0 {
		contentRows = rrfMerge(contentFTS, contentSem, limit)
	} else if len(contentRows) > limit {
		// FTS ordering is handed back unchanged — a single-source RRF
		// would be a no-op transform that discards the FTS-native rank.
		contentRows = contentRows[:limit]
	}
	noteRows := noteFTS
	if len(noteSem) > 0 {
		noteRows = rrfMergeNotes(noteFTS, noteSem, limit)
	} else if len(noteRows) > limit {
		noteRows = noteRows[:limit]
	}
	return contentRows, noteRows, nil
}

// semanticBranches produces the vector side of hybrid search: embed the
// query once via Gemini, then cosine-rank contents and notes in parallel
// with that one vector — EmbedQuery is never called twice for a single
// search. The embed plus both vector queries share a single
// searchKnowledgeHybridDeadline window, so a slow Gemini call cannot
// stall the MCP handler. Every failure is logged and swallowed; the
// caller treats an empty slice as "degrade that corpus to FTS-only"
// (ErrEmptyInput is the one shape that does not even log, since it is a
// caller-input issue).
func (s *Server) semanticBranches(ctx context.Context, query string, limit int, wantContent, wantNote bool) (contentRows []content.Content, noteRows []note.Note) {
	semCtx, cancel := context.WithTimeout(ctx, searchKnowledgeHybridDeadline)
	defer cancel()

	vec, err := s.embedder.EmbedQuery(semCtx, query)
	if err != nil {
		if !errors.Is(err, embedder.ErrEmptyInput) {
			s.logger.Warn("search_knowledge semantic branch skipped: embed_query failed", "err", err)
		}
		return nil, nil
	}
	queryVec := pgvector.NewVector(vec)

	var wg sync.WaitGroup
	if wantContent {
		wg.Go(func() {
			rows, semErr := s.contents.InternalSemanticSearch(semCtx, queryVec, limit)
			if semErr != nil {
				s.logger.Warn("search_knowledge semantic branch skipped: content vector query failed", "err", semErr)
				return
			}
			contentRows = rows
		})
	}
	if wantNote {
		wg.Go(func() {
			rows, semErr := s.notes.SemanticSearch(semCtx, queryVec, limit)
			if semErr != nil {
				s.logger.Warn("search_knowledge semantic branch skipped: note vector query failed", "err", semErr)
				return
			}
			noteRows = rows
		})
	}
	wg.Wait()
	return contentRows, noteRows
}

// rrfMerge fuses two ranked content lists via reciprocal rank fusion:
// score(c) = Σ 1 / (k + rank_i(c)) over the branches where c appears.
// rank_i starts at 1 (branch leader). Items appearing in only one branch
// still score — RRF is tolerant of partial overlap. Input slices are
// treated as already ranked in index order.
func rrfMerge(fts, sem []content.Content, limit int) []content.Content {
	scores := make(map[uuid.UUID]float64, len(fts)+len(sem))
	byID := make(map[uuid.UUID]content.Content, len(fts)+len(sem))
	accumulate := func(rows []content.Content) {
		for i := range rows {
			id := rows[i].ID
			scores[id] += 1.0 / (rrfK + float64(i+1))
			if _, ok := byID[id]; !ok {
				byID[id] = rows[i]
			}
		}
	}
	accumulate(fts)
	accumulate(sem)

	type scored struct {
		id    uuid.UUID
		score float64
	}
	ranked := make([]scored, 0, len(scores))
	for id, sc := range scores {
		ranked = append(ranked, scored{id: id, score: sc})
	}
	slices.SortFunc(ranked, func(a, b scored) int {
		if a.score != b.score {
			return cmp.Compare(b.score, a.score) // higher score first
		}
		// Stable tiebreaker: prefer FTS winner (rank 1 in FTS beats
		// rank 1 in semantic only when scores truly tie — negligible in
		// practice but keeps output deterministic).
		return cmp.Compare(a.id.String(), b.id.String())
	})

	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	out := make([]content.Content, len(ranked))
	for i := range ranked {
		out[i] = byID[ranked[i].id]
	}
	return out
}

// rrfMergeNotes fuses two ranked note lists via reciprocal rank fusion —
// the note counterpart of rrfMerge: score(n) = Σ 1 / (k + rank_i(n)) over
// the branches where n appears, rank_i starting at 1. Notes appearing in
// only one branch still score. Score ties break on note ID so output
// stays deterministic. Input slices are treated as already ranked in
// index order.
func rrfMergeNotes(fts, sem []note.Note, limit int) []note.Note {
	scores := make(map[uuid.UUID]float64, len(fts)+len(sem))
	byID := make(map[uuid.UUID]note.Note, len(fts)+len(sem))
	accumulate := func(rows []note.Note) {
		for i := range rows {
			id := rows[i].ID
			scores[id] += 1.0 / (rrfK + float64(i+1))
			if _, ok := byID[id]; !ok {
				byID[id] = rows[i]
			}
		}
	}
	accumulate(fts)
	accumulate(sem)

	type scored struct {
		id    uuid.UUID
		score float64
	}
	ranked := make([]scored, 0, len(scores))
	for id, sc := range scores {
		ranked = append(ranked, scored{id: id, score: sc})
	}
	slices.SortFunc(ranked, func(a, b scored) int {
		if a.score != b.score {
			return cmp.Compare(b.score, a.score) // higher score first
		}
		return cmp.Compare(a.id.String(), b.id.String())
	})

	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	out := make([]note.Note, len(ranked))
	for i := range ranked {
		out[i] = byID[ranked[i].id]
	}
	return out
}

// selectSources resolves the source_types filter into branch flags. Empty
// list = all sources. Tokens are assumed already validated by
// validateSourceTypes, so any unrecognized token here is a no-op rather than
// an error. Named wantContent / wantNote to avoid shadowing the
// internal/content package.
func selectSources(filter []string) (wantContent, wantNote bool) {
	if len(filter) == 0 {
		return true, true
	}
	for _, t := range filter {
		switch t {
		case SourceTypeContent:
			wantContent = true
		case SourceTypeNote:
			wantNote = true
		}
	}
	return wantContent, wantNote
}

// filterNoteResults applies note-specific filters and converts to wire shape.
func filterNoteResults(notes []note.Note, kindFilter *string, after, before *time.Time) []SearchKnowledgeResult {
	out := make([]SearchKnowledgeResult, 0, len(notes))
	for i := range notes {
		n := &notes[i]
		if kindFilter != nil && *kindFilter != "" && string(n.Kind) != *kindFilter {
			continue
		}
		if after != nil && n.CreatedAt.Before(*after) {
			continue
		}
		// before is the exclusive upper bound (start of the day after the
		// requested date), so the whole requested day is kept.
		if before != nil && !n.CreatedAt.Before(*before) {
			continue
		}
		out = append(out, SearchKnowledgeResult{
			ID:         n.ID.String(),
			SourceType: SourceTypeNote,
			Title:      n.Title,
			Slug:       n.Slug,
			NoteKind:   string(n.Kind),
			Excerpt:    truncate(n.Body, 200),
			CreatedAt:  n.CreatedAt.Format(time.RFC3339),
		})
	}
	return out
}

// truncate cuts s to at most n runes, appending an ellipsis if
// truncated. Rune-counted (not byte-counted) so a multi-byte UTF-8
// body — Koopa writes Chinese; CJK runes are 3 bytes — never gets
// split mid-rune into invalid UTF-8.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n]) + "…"
}

func (s *Server) filterContentResults(ctx context.Context, contents []content.Content, contentType *string, after, before *time.Time) []SearchKnowledgeResult {
	results := make([]SearchKnowledgeResult, 0, len(contents))
	for i := range contents {
		c := &contents[i]
		if contentType != nil && *contentType != "" && string(c.Type) != *contentType {
			continue
		}
		if after != nil && c.CreatedAt.Before(*after) {
			continue
		}
		// before is the exclusive upper bound (start of the day after the
		// requested date), so the whole requested day is kept.
		if before != nil && !c.CreatedAt.Before(*before) {
			continue
		}
		results = append(results, s.contentToResult(ctx, c))
	}
	return results
}

func (s *Server) contentToResult(ctx context.Context, c *content.Content) SearchKnowledgeResult {
	var projectTitle string
	if c.ProjectID != nil && s.projects != nil {
		if p, pErr := s.projects.ProjectByID(ctx, *c.ProjectID); pErr == nil {
			projectTitle = p.Title
		}
	}
	return SearchKnowledgeResult{
		ID:          c.ID.String(),
		SourceType:  SourceTypeContent,
		Title:       c.Title,
		Slug:        c.Slug,
		ContentType: string(c.Type),
		Excerpt:     c.Excerpt,
		Project:     projectTitle,
		CreatedAt:   c.CreatedAt.Format(time.RFC3339),
	}
}

// parseDateStart parses an optional YYYY-MM-DD date as the start of that day
// (00:00:00) in loc — the inclusive lower bound for the `after` filter. Whole
// content created on or after the named day is kept. nil/empty input returns
// (nil, nil) — caller treats as "no lower bound".
func parseDateStart(s *string, loc *time.Location) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.ParseInLocation(time.DateOnly, *s, loc)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// parseDateEnd parses an optional YYYY-MM-DD date as the start of the NEXT day
// in loc — the exclusive upper bound for the `before` filter. This makes
// `before=D` whole-day inclusive: a row created at any time during D is kept,
// while D+1 onward is dropped. nil/empty input returns (nil, nil).
func parseDateEnd(s *string, loc *time.Location) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := time.ParseInLocation(time.DateOnly, *s, loc)
	if err != nil {
		return nil, err
	}
	end := t.AddDate(0, 0, 1)
	return &end, nil
}

// validateSearchKnowledgeInput runs the pre-store filter validation for
// search_knowledge — required query, strict enum filters, source-type tokens,
// the content_type⊕note_kind mutex, and the unsupported project filter —
// returning the first violation. Date parsing stays in the handler because it
// needs the server timezone and produces values the handler consumes.
func validateSearchKnowledgeInput(input SearchKnowledgeInput) error {
	if input.Query == "" {
		return fmt.Errorf("query is required")
	}

	hasContentTypeFilter := input.ContentType != nil && *input.ContentType != ""
	hasNoteKindFilter := input.NoteKind != nil && *input.NoteKind != ""

	// Enum filters reject unknown values. The allowed sets (content.Type,
	// note.Kind) are closed and stable, so an out-of-enum value is a caller
	// bug — not a legitimate zero-result. Rejecting keeps "unsupported
	// filter" distinguishable from "no match" and matches create_content,
	// which already rejects invalid content types.
	if hasContentTypeFilter && !content.Type(*input.ContentType).Valid() {
		return fmt.Errorf("unsupported content_type %q (supported: article, essay, build-log, til, digest)", *input.ContentType)
	}
	if hasNoteKindFilter && !note.Kind(*input.NoteKind).Valid() {
		return fmt.Errorf("unsupported note_kind %q (supported: solve-note, concept-note, debug-postmortem, decision-log, reading-note, musing)", *input.NoteKind)
	}
	if hasContentTypeFilter && hasNoteKindFilter {
		return fmt.Errorf("content_type and note_kind are mutually exclusive — content_type filters articles/essays/etc; note_kind filters notes")
	}

	if err := validateSourceTypes(input.SourceTypes); err != nil {
		return err
	}

	// project is declared in the schema but has no retrieval path. Rather
	// than silently ignore it (a caller passing project would get unfiltered
	// results and never know), reject it as an unsupported filter until a
	// real content-only project filter is wired.
	if input.Project != nil && *input.Project != "" {
		return fmt.Errorf("unsupported_filter: project is not supported by search_knowledge")
	}

	return nil
}

// validateSourceTypes rejects any source token outside the supported corpus
// set {content, note}. An unknown token (a typo, or an unsupported corpus
// like "bookmark"/"task") is a caller error, not a silent no-op: returning it
// as an error keeps "unsupported filter" distinguishable from "no results".
func validateSourceTypes(filter []string) error {
	for _, t := range filter {
		switch t {
		case SourceTypeContent, SourceTypeNote:
		default:
			return fmt.Errorf("unsupported source_type %q (supported: content, note)", t)
		}
	}
	return nil
}
