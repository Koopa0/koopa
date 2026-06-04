// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pgvector/pgvector-go"
	"golang.org/x/sync/errgroup"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/embedder"
	"github.com/Koopa0/koopa/internal/note"
	"github.com/Koopa0/koopa/internal/research"
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
	SourceTypeReport  = "report"
)

// reportTrustedWeight and reportLowTrustWeight downrank report results in the
// cross-corpus merge relative to notes and content (which carry an implicit
// weight of 1.0). A human-trusted report ranks as a vetted source, just under
// digested notes/content; a low-trust report is pushed well down. Trust never
// gates visibility — every report still appears, only its rank changes.
const (
	reportTrustedWeight  = 0.8
	reportLowTrustWeight = 0.5
)

// SearchKnowledgeInput is the input for the search_knowledge tool.
type SearchKnowledgeInput struct {
	Query       string   `json:"query" jsonschema:"required" jsonschema_description:"Search query text"`
	ContentType *string  `json:"content_type,omitempty" jsonschema_description:"Filter by content type: article, essay, build-log, til, digest. An unknown value is rejected. Implies source_types=[\"content\"]; notes are excluded automatically. Mutually exclusive with note_kind."`
	NoteKind    *string  `json:"note_kind,omitempty" jsonschema_description:"Filter by note kind: solve-note, concept-note, debug-postmortem, decision-log, reading-note, musing. An unknown value is rejected. Implies source_types=[\"note\"]; content is excluded automatically. Mutually exclusive with content_type."`
	SourceTypes []string `json:"source_types,omitempty" jsonschema_description:"Filter by source: 'content' (articles/essays/etc), 'note' (Zettelkasten), 'report' (agent-produced research sources, low-trust by default and downranked). Default: all three. Any token outside {content, note, report} is rejected. Overridden by content_type or note_kind if either is set (both narrow away from reports)."`
	Project     *string  `json:"project,omitempty" jsonschema_description:"NOT SUPPORTED — passing a non-empty value is rejected as an unsupported_filter. Reserved for a future content-only project filter."`
	After       *string  `json:"after,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or after the whole of this day (server timezone, UTC by default)."`
	Before      *string  `json:"before,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or before the whole of this day, i.e. through 23:59:59 of the date (server timezone, UTC by default)."`
	Limit       FlexInt  `json:"limit,omitempty" jsonschema_description:"Max results (default 20, max 50)."`
}

// SearchKnowledgeResult is a single search result.
type SearchKnowledgeResult struct {
	ID          string   `json:"id"`
	SourceType  string   `json:"source_type"` // 'content' or 'note'
	Title       string   `json:"title"`
	Slug        string   `json:"slug"`
	ContentType string   `json:"content_type,omitempty"` // content.type when source_type=content
	NoteKind    string   `json:"note_kind,omitempty"`    // note.kind when source_type=note
	TrustStatus string   `json:"trust_status,omitempty"` // report trust (low_trust|trusted) when source_type=report
	Excerpt     string   `json:"excerpt"`
	Tags        []string `json:"tags,omitempty"`
	Project     string   `json:"project,omitempty"`
	CreatedAt   string   `json:"created_at"`
}

// SearchKnowledgeOutput is the output of the search_knowledge tool.
type SearchKnowledgeOutput struct {
	Results []SearchKnowledgeResult `json:"results"`
	Total   int                     `json:"total"`
	Query   string                  `json:"query"`
	// SearchedCorpus lists the source types actually queried ("content",
	// "note", "report"). It lets a caller read a 0-result response as "found
	// none in these corpora" rather than "does not exist". agent_notes are
	// never in this corpus by design — recall of your own breadcrumbs is
	// query_agent_notes.
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
	wantContent, wantNote, wantReport := selectSources(input.SourceTypes)
	// A type-specific filter implies the corresponding source. Caller's
	// mental model is "I asked for articles, why did notes leak in?" —
	// passing content_type narrows to the content branch even if
	// source_types was unset (default all). Symmetric for note_kind. Either
	// type-specific filter also excludes reports, which carry neither.
	if input.ContentType != nil && *input.ContentType != "" {
		wantNote = false
		wantReport = false
	}
	if input.NoteKind != nil && *input.NoteKind != "" {
		wantContent = false
		wantReport = false
	}

	// Each branch returns rows already ordered by its own relevance score
	// (content: fused RRF rank; notes: ts_rank). The two scores live on
	// incompatible scales, so the cross-source merge fuses by rank position
	// rather than comparing raw scores — see mergeByRelevance.
	var contentResults, noteResults, reportResults []SearchKnowledgeResult

	if wantContent {
		merged, cErr := s.contentHybridSearch(ctx, input.Query, limit)
		if cErr != nil {
			return nil, SearchKnowledgeOutput{}, fmt.Errorf("searching content: %w", cErr)
		}
		contentResults = s.filterContentResults(ctx, merged, input.ContentType, after, before)
	}

	if wantNote {
		notes, nErr := s.notes.Search(ctx, input.Query, limit)
		if nErr != nil {
			return nil, SearchKnowledgeOutput{}, fmt.Errorf("searching notes: %w", nErr)
		}
		noteResults = filterNoteResults(notes, input.NoteKind, after, before)
	}

	if wantReport {
		reports, rErr := s.research.Search(ctx, input.Query, limit)
		if rErr != nil {
			return nil, SearchKnowledgeOutput{}, fmt.Errorf("searching reports: %w", rErr)
		}
		reportResults = filterReportResults(reports, after, before)
	}

	results := mergeByRelevance(contentResults, noteResults, reportResults, limit)

	return nil, SearchKnowledgeOutput{
		Results:        results,
		Total:          len(results),
		Query:          input.Query,
		SearchedCorpus: searchedCorpusOf(wantContent, wantNote, wantReport),
	}, nil
}

// searchedCorpusOf lists the source types actually queried, in stable order. It
// lets a 0-result response read as "found none in these corpora" rather than
// "does not exist".
func searchedCorpusOf(wantContent, wantNote, wantReport bool) []string {
	out := make([]string, 0, 3)
	if wantContent {
		out = append(out, SourceTypeContent)
	}
	if wantNote {
		out = append(out, SourceTypeNote)
	}
	if wantReport {
		out = append(out, SourceTypeReport)
	}
	return out
}

// mergeByRelevance fuses the already-relevance-ranked branch result lists
// (content, note, report) into a single ranking, capped at limit. Each branch
// arrives ordered by its own relevance score — content by fused RRF rank,
// notes and reports by ts_rank — and those scores live on incompatible scales,
// so raw scores are never compared across branches. Instead each result is
// scored by its RANK POSITION within its own branch via reciprocal rank
// fusion: a result at branch rank r (1-based) scores 1/(rrfK + r). Content and
// note results take that score unweighted; report results multiply it by a
// trust weight (< 1.0) so an agent source ranks below digested knowledge at
// equal relevance without ever being hidden.
//
// CreatedAt (newer first) is a deterministic tie-breaker ONLY; it never
// outranks a more relevant result. The result envelope is always non-nil
// (JSON serialises to "results":[] when empty) — the json-api rule forbids
// null on list fields.
func mergeByRelevance(contentResults, noteResults, reportResults []SearchKnowledgeResult, limit int) []SearchKnowledgeResult {
	type scored struct {
		result SearchKnowledgeResult
		score  float64
	}
	ranked := make([]scored, 0, len(contentResults)+len(noteResults)+len(reportResults))
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
	for i := range reportResults {
		ranked = append(ranked, scored{
			result: reportResults[i],
			score:  reportWeight(reportResults[i].TrustStatus) * (1.0 / (rrfK + float64(i+1))),
		})
	}

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

// contentHybridSearch runs FTS + semantic branches in parallel and merges
// with reciprocal rank fusion. When the embedder is not configured or the
// semantic branch errors out (network, API key, timeout), the handler
// degrades to FTS-only — search stays useful, just without the semantic
// recall boost. The returned slice is ordered by fused rank, capped at
// limit.
func (s *Server) contentHybridSearch(ctx context.Context, query string, limit int) ([]content.Content, error) {
	// Bound semantic branch separately — it involves a network call to
	// Gemini for query embedding; FTS uses the local DB and gets the
	// parent ctx. On semantic timeout / error we log and fall back to FTS.
	branchSize := searchKnowledgeBranchSize
	if limit > branchSize {
		branchSize = limit
	}

	var (
		ftsResults, semResults []content.Content
		semErr                 error
	)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		rows, _, err := s.contents.InternalSearch(gctx, query, 1, branchSize)
		if err != nil {
			return fmt.Errorf("fts: %w", err)
		}
		ftsResults = rows
		return nil
	})

	if s.embedder != nil {
		g.Go(func() error {
			rows, err := s.semanticBranch(gctx, query, branchSize)
			if err != nil {
				semErr = err
				return nil // Fall back to FTS; log happens inside semanticBranch.
			}
			semResults = rows
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	if len(semResults) == 0 {
		// Either embedder unset, semantic failed gracefully, or no vector
		// hits. Hand back FTS ordering unchanged — a single-source RRF
		// would be a no-op transform that discards the FTS-native rank.
		_ = semErr
		if len(ftsResults) > limit {
			return ftsResults[:limit], nil
		}
		return ftsResults, nil
	}

	merged := rrfMerge(ftsResults, semResults, limit)
	return merged, nil
}

// semanticBranch produces the vector side of hybrid search: embed the
// query via Gemini, then cosine-rank contents via pgvector. Bounded by
// searchKnowledgeHybridDeadline so a slow Gemini call cannot stall the
// MCP handler. Any failure is logged and returned; the caller is expected
// to swallow the error and degrade to FTS-only (ErrEmptyInput is the one
// shape that should not even log, since it's a caller-input issue).
func (s *Server) semanticBranch(ctx context.Context, query string, limit int) ([]content.Content, error) {
	semCtx, cancel := context.WithTimeout(ctx, searchKnowledgeHybridDeadline)
	defer cancel()

	vec, err := s.embedder.EmbedQuery(semCtx, query)
	if err != nil {
		if !errors.Is(err, embedder.ErrEmptyInput) {
			s.logger.Warn("search_knowledge semantic branch skipped: embed_query failed", "err", err)
		}
		return nil, err
	}
	rows, err := s.contents.InternalSemanticSearch(semCtx, pgvector.NewVector(vec), limit)
	if err != nil {
		s.logger.Warn("search_knowledge semantic branch skipped: vector query failed", "err", err)
		return nil, err
	}
	return rows, nil
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
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		// Stable tiebreaker: prefer FTS winner (rank 1 in FTS beats
		// rank 1 in semantic only when scores truly tie — negligible in
		// practice but keeps output deterministic).
		return ranked[i].id.String() < ranked[j].id.String()
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

// selectSources resolves the source_types filter into branch flags. Empty
// list = all sources. Tokens are assumed already validated by
// validateSourceTypes, so any unrecognized token here is a no-op rather than
// an error. Named wantContent / wantNote / wantReport to avoid shadowing the
// internal/content package.
func selectSources(filter []string) (wantContent, wantNote, wantReport bool) {
	if len(filter) == 0 {
		return true, true, true
	}
	for _, t := range filter {
		switch t {
		case SourceTypeContent:
			wantContent = true
		case SourceTypeNote:
			wantNote = true
		case SourceTypeReport:
			wantReport = true
		}
	}
	return wantContent, wantNote, wantReport
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

// filterReportResults applies date filters and converts reports to the wire
// shape. Each result carries source_type=report and trust_status so the
// consumer can badge agent-generated sources and mergeByRelevance can downrank
// low-trust ones.
func filterReportResults(reports []research.Report, after, before *time.Time) []SearchKnowledgeResult {
	out := make([]SearchKnowledgeResult, 0, len(reports))
	for i := range reports {
		r := &reports[i]
		if after != nil && r.CreatedAt.Before(*after) {
			continue
		}
		// before is the exclusive upper bound (start of the day after the
		// requested date), so the whole requested day is kept.
		if before != nil && !r.CreatedAt.Before(*before) {
			continue
		}
		out = append(out, SearchKnowledgeResult{
			ID:          r.ID.String(),
			SourceType:  SourceTypeReport,
			Title:       r.Title,
			Excerpt:     truncate(r.Body, 200),
			TrustStatus: string(r.TrustStatus),
			CreatedAt:   r.CreatedAt.Format(time.RFC3339),
		})
	}
	return out
}

// reportWeight returns the cross-corpus merge weight for a report by trust:
// trusted reports rank as vetted sources, low-trust reports well below — never
// hidden, only downranked.
func reportWeight(trustStatus string) float64 {
	if trustStatus == string(research.TrustTrusted) {
		return reportTrustedWeight
	}
	return reportLowTrustWeight
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
		Tags:        c.Tags,
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
// set {content, note, report}. An unknown token (a typo, or an unsupported
// corpus like "bookmark"/"task") is a caller error, not a silent no-op:
// returning it as an error keeps "unsupported filter" distinguishable from
// "no results".
func validateSourceTypes(filter []string) error {
	for _, t := range filter {
		switch t {
		case SourceTypeContent, SourceTypeNote, SourceTypeReport:
		default:
			return fmt.Errorf("unsupported source_type %q (supported: content, note, report)", t)
		}
	}
	return nil
}
