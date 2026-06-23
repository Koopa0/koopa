// Copyright 2026 Koopa. All rights reserved.

package mcp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pgvector/pgvector-go"
	"golang.org/x/sync/errgroup"

	"github.com/Koopa0/koopa/internal/content"
	"github.com/Koopa0/koopa/internal/embedder"
	"github.com/Koopa0/koopa/internal/reading"
	"github.com/Koopa0/koopa/internal/song"
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

// SourceType values for search results. A reading_reflection hit folds under
// SourceTypeReading and a song_reflection hit under SourceTypeSong — reflections
// are NOT their own source type, they surface linked to their parent shelf row.
const (
	SourceTypeContent = "content"
	SourceTypeReading = "reading"
	SourceTypeSong    = "song"
)

// allSourceTypes is the full corpus set search_knowledge queries when the
// caller passes no source_types filter (nil or empty). Order fixes the
// default SearchedCorpus order and the round-robin merge order.
var allSourceTypes = []string{SourceTypeContent, SourceTypeReading, SourceTypeSong}

// SearchKnowledgeInput is the input for the search_knowledge tool.
type SearchKnowledgeInput struct {
	Query       string   `json:"query" jsonschema:"required" jsonschema_description:"Search query text"`
	ContentType *string  `json:"content_type,omitempty" jsonschema_description:"Filter by content type: article, essay, build-log, til, digest. An unknown value is rejected. Applies only to content hits; it narrows the corpus to content."`
	SourceTypes []string `json:"source_types,omitempty" jsonschema_description:"Filter by source: 'content' (articles/essays/build-logs/TILs), 'reading' (the reading shelf + diary), 'song' (the ヨルシカ song shelf + reflections). Default: all three. Any token outside {content, reading, song} is rejected."`
	Project     *string  `json:"project,omitempty" jsonschema_description:"NOT SUPPORTED — passing a non-empty value is rejected as an unsupported_filter. Reserved for a future content-only project filter."`
	After       *string  `json:"after,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or after the whole of this day (server timezone, UTC by default)."`
	Before      *string  `json:"before,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or before the whole of this day, i.e. through 23:59:59 of the date (server timezone, UTC by default)."`
	Limit       FlexInt  `json:"limit,omitempty" jsonschema_description:"Max results (default 20, max 50)."`
}

// SearchKnowledgeResult is a single search result. The fields carry a uniform
// shape across corpora:
//   - source_type=content: id/slug/title are the content's, content_type is set,
//     excerpt is the content excerpt.
//   - source_type=reading: id/title are the parent BOOK's (link via get_reading),
//     slug is empty (readings have no slug), excerpt is the matched text — the
//     book title for a shelf hit, the diary body for a reflection hit.
//   - source_type=song: id/title are the parent SONG's, slug is empty, excerpt is
//     the matched text — the song title for a shelf hit, the reflection body for
//     a reflection hit.
type SearchKnowledgeResult struct {
	ID          string `json:"id"`
	SourceType  string `json:"source_type"` // content | reading | song
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	ContentType string `json:"content_type,omitempty"` // content.type when source_type=content
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
	// "reading", "song"). It lets a caller read a 0-result response as "found
	// none in these corpora" rather than "does not exist".
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
	corpora := selectSources(input.SourceTypes, input.ContentType)

	// Each corpus runs its own hybrid retrieval and returns a relevance-ordered
	// slice. perCorpus preserves corpus order so the round-robin merge is
	// deterministic and no corpus is starved — RRF scores are not comparable
	// across corpora, so we interleave by per-corpus rank rather than fuse.
	perCorpus := make([][]SearchKnowledgeResult, 0, len(corpora))
	for _, src := range corpora {
		rows, searchErr := s.searchCorpus(ctx, src, input.Query, limit, input.ContentType, after, before)
		if searchErr != nil {
			return nil, SearchKnowledgeOutput{}, searchErr
		}
		perCorpus = append(perCorpus, rows)
	}

	results := mergeByRank(perCorpus, limit)

	return nil, SearchKnowledgeOutput{
		Results:        results,
		Total:          len(results),
		Query:          input.Query,
		SearchedCorpus: corpora,
	}, nil
}

// searchCorpus runs the hybrid retrieval for one corpus and maps the hits to
// the uniform SearchKnowledgeResult shape, applying the date filter (and, for
// content, the content_type filter). Results arrive relevance-ordered (fused
// RRF rank, or native FTS rank when the semantic side is empty).
func (s *Server) searchCorpus(ctx context.Context, src, query string, limit int, contentType *string, after, before *time.Time) ([]SearchKnowledgeResult, error) {
	switch src {
	case SourceTypeContent:
		rows, err := s.hybridSearch(ctx, query, limit)
		if err != nil {
			return nil, err
		}
		return s.filterContentResults(ctx, rows, contentType, after, before), nil
	case SourceTypeReading:
		hits, err := s.hybridReadingSearch(ctx, query, limit)
		if err != nil {
			return nil, err
		}
		return filterReadingHits(hits, after, before), nil
	case SourceTypeSong:
		hits, err := s.hybridSongSearch(ctx, query, limit)
		if err != nil {
			return nil, err
		}
		return filterSongHits(hits, after, before), nil
	default:
		panic("mcp: unknown search corpus: " + src)
	}
}

// selectSources resolves the requested corpus set. A nil/empty source_types
// list means "all corpora". A content_type filter is content-specific, so it
// narrows the corpus to content alone regardless of the source_types default —
// validateSearchKnowledgeInput already rejects content_type combined with a
// source_types list that excludes content, so this only collapses the default.
func selectSources(requested []string, contentType *string) []string {
	if contentType != nil && *contentType != "" {
		return []string{SourceTypeContent}
	}
	if len(requested) == 0 {
		return slices.Clone(allSourceTypes)
	}
	// Preserve the canonical order and dedup, ignoring caller order/repeats.
	out := make([]string, 0, len(allSourceTypes))
	for _, st := range allSourceTypes {
		if slices.Contains(requested, st) {
			out = append(out, st)
		}
	}
	return out
}

// mergeByRank interleaves the per-corpus relevance-ordered slices round-robin
// by rank position: every corpus's rank-0 hit, then every rank-1 hit, and so
// on, until limit is reached. This keeps each corpus's internal order while
// giving each a fair share of the result budget — RRF scores are not
// comparable across corpora, so a global sort would be meaningless. The
// envelope is always non-nil (serialises to "results":[] when empty).
func mergeByRank(perCorpus [][]SearchKnowledgeResult, limit int) []SearchKnowledgeResult {
	out := make([]SearchKnowledgeResult, 0, limit)
	for rank := 0; len(out) < limit; rank++ {
		progressed := false
		for _, corpus := range perCorpus {
			if rank >= len(corpus) {
				continue
			}
			progressed = true
			out = append(out, corpus[rank])
			if len(out) == limit {
				return out
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// hybridSearch runs the content FTS branch and — when the embedder is wired —
// the content semantic branch in parallel, then fuses the two rankings with
// reciprocal rank fusion. An FTS error aborts the search; a semantic failure
// degrades to FTS-only, so search stays useful when Gemini is slow or
// unreachable. Returned slice is ordered by fused rank (FTS rank when the
// semantic side is empty), capped at limit.
func (s *Server) hybridSearch(ctx context.Context, query string, limit int) ([]content.Content, error) {
	branchSize := max(limit, searchKnowledgeBranchSize)

	var (
		contentFTS, contentSem []content.Content
	)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		rows, err := s.contents.InternalSearch(gctx, query, 1, branchSize)
		if err != nil {
			return fmt.Errorf("searching content: fts: %w", err)
		}
		contentFTS = rows
		return nil
	})
	if s.embedder != nil {
		g.Go(func() error {
			contentSem = s.semanticBranch(gctx, query, branchSize)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	contentRows := contentFTS
	if len(contentSem) > 0 {
		contentRows = rrfMerge(contentFTS, contentSem, limit)
	} else if len(contentRows) > limit {
		// FTS ordering is handed back unchanged — a single-source RRF
		// would be a no-op transform that discards the FTS-native rank.
		contentRows = contentRows[:limit]
	}
	return contentRows, nil
}

// semanticBranch produces the vector side of hybrid search: embed the query
// once via Gemini, then cosine-rank contents with that vector. The embed plus
// the vector query share a single searchKnowledgeHybridDeadline window, so a
// slow Gemini call cannot stall the MCP handler. Every failure is logged and
// swallowed; the caller treats an empty slice as "degrade to FTS-only"
// (ErrEmptyInput is the one shape that does not even log, since it is a
// caller-input issue).
func (s *Server) semanticBranch(ctx context.Context, query string, limit int) []content.Content {
	semCtx, cancel := context.WithTimeout(ctx, searchKnowledgeHybridDeadline)
	defer cancel()

	vec, err := s.embedder.EmbedQuery(semCtx, query)
	if err != nil {
		if !errors.Is(err, embedder.ErrEmptyInput) {
			s.logger.Warn("search_knowledge semantic branch skipped: embed_query failed", "err", err)
		}
		return nil
	}
	queryVec := pgvector.NewVector(vec)

	rows, semErr := s.contents.InternalSemanticSearch(semCtx, queryVec, limit)
	if semErr != nil {
		s.logger.Warn("search_knowledge semantic branch skipped: content vector query failed", "err", semErr)
		return nil
	}
	return rows
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

// hybridReadingSearch runs the reading-corpus FTS branch and — when the
// embedder is wired — the semantic branch in parallel, mapping each to the
// uniform result shape, then fuses the two with RRF. Mirrors hybridSearch: an
// FTS error aborts; a semantic failure degrades to FTS-only. The result rows
// arrive relevance-ordered, capped at limit.
func (s *Server) hybridReadingSearch(ctx context.Context, query string, limit int) ([]SearchKnowledgeResult, error) {
	branchSize := max(limit, searchKnowledgeBranchSize)

	var ftsResults, semResults []SearchKnowledgeResult
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		hits, err := s.readings.SearchCorpus(gctx, query, branchSize)
		if err != nil {
			return fmt.Errorf("searching reading: fts: %w", err)
		}
		ftsResults = readingHitsToResults(hits)
		return nil
	})
	if s.embedder != nil {
		g.Go(func() error {
			semResults = s.readingSemanticBranch(gctx, query, branchSize)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return rrfMergeResults(ftsResults, semResults, limit), nil
}

// hybridSongSearch is the song-corpus twin of hybridReadingSearch.
func (s *Server) hybridSongSearch(ctx context.Context, query string, limit int) ([]SearchKnowledgeResult, error) {
	branchSize := max(limit, searchKnowledgeBranchSize)

	var ftsResults, semResults []SearchKnowledgeResult
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		hits, err := s.songs.SearchCorpus(gctx, query, branchSize)
		if err != nil {
			return fmt.Errorf("searching song: fts: %w", err)
		}
		ftsResults = songHitsToResults(hits)
		return nil
	})
	if s.embedder != nil {
		g.Go(func() error {
			semResults = s.songSemanticBranch(gctx, query, branchSize)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return rrfMergeResults(ftsResults, semResults, limit), nil
}

// readingSemanticBranch embeds the query once and cosine-ranks the reading
// corpus with it, sharing the single hybrid deadline. Every failure is logged
// (except ErrEmptyInput) and swallowed — the caller treats an empty slice as
// "degrade to FTS-only".
func (s *Server) readingSemanticBranch(ctx context.Context, query string, limit int) []SearchKnowledgeResult {
	semCtx, cancel := context.WithTimeout(ctx, searchKnowledgeHybridDeadline)
	defer cancel()

	vec, err := s.embedder.EmbedQuery(semCtx, query)
	if err != nil {
		if !errors.Is(err, embedder.ErrEmptyInput) {
			s.logger.Warn("search_knowledge reading semantic branch skipped: embed_query failed", "err", err)
		}
		return nil
	}
	hits, semErr := s.readings.SemanticSearchCorpus(semCtx, pgvector.NewVector(vec), limit)
	if semErr != nil {
		s.logger.Warn("search_knowledge reading semantic branch skipped: vector query failed", "err", semErr)
		return nil
	}
	return readingHitsToResults(hits)
}

// songSemanticBranch is the song-corpus twin of readingSemanticBranch.
func (s *Server) songSemanticBranch(ctx context.Context, query string, limit int) []SearchKnowledgeResult {
	semCtx, cancel := context.WithTimeout(ctx, searchKnowledgeHybridDeadline)
	defer cancel()

	vec, err := s.embedder.EmbedQuery(semCtx, query)
	if err != nil {
		if !errors.Is(err, embedder.ErrEmptyInput) {
			s.logger.Warn("search_knowledge song semantic branch skipped: embed_query failed", "err", err)
		}
		return nil
	}
	hits, semErr := s.songs.SemanticSearchCorpus(semCtx, pgvector.NewVector(vec), limit)
	if semErr != nil {
		s.logger.Warn("search_knowledge song semantic branch skipped: vector query failed", "err", semErr)
		return nil
	}
	return songHitsToResults(hits)
}

// readingHitsToResults maps reading corpus hits onto the uniform result shape:
// source_type=reading, id/title = the parent book, excerpt = the matched text,
// slug empty (readings have no slug).
func readingHitsToResults(hits []reading.CorpusHit) []SearchKnowledgeResult {
	out := make([]SearchKnowledgeResult, len(hits))
	for i := range hits {
		out[i] = SearchKnowledgeResult{
			ID:         hits[i].ReadingID.String(),
			SourceType: SourceTypeReading,
			Title:      hits[i].Title,
			Excerpt:    hits[i].Excerpt,
			CreatedAt:  hits[i].CreatedAt.Format(time.RFC3339),
		}
	}
	return out
}

// songHitsToResults maps song corpus hits onto the uniform result shape:
// source_type=song, id/title = the parent song, excerpt = the matched text.
func songHitsToResults(hits []song.CorpusHit) []SearchKnowledgeResult {
	out := make([]SearchKnowledgeResult, len(hits))
	for i := range hits {
		out[i] = SearchKnowledgeResult{
			ID:         hits[i].SongID.String(),
			SourceType: SourceTypeSong,
			Title:      hits[i].Title,
			Excerpt:    hits[i].Excerpt,
			CreatedAt:  hits[i].CreatedAt.Format(time.RFC3339),
		}
	}
	return out
}

// resultRRFKey identifies one matched row across the FTS and semantic branches.
// Parent id alone is not enough: a single book can yield a shelf hit plus
// several distinct reflection hits, and collapsing them on parent id would drop
// real matches. (id, excerpt) is stable per matched row — the excerpt is the
// shelf title or the diary body — so the same row appearing in both branches
// fuses (consensus) while distinct reflections stay distinct.
func resultRRFKey(r *SearchKnowledgeResult) string {
	return r.ID + "\x00" + r.Excerpt
}

// rrfMergeResults fuses two ranked result lists via reciprocal rank fusion,
// keyed by resultRRFKey. Same algorithm as rrfMerge (content) but over the
// already-mapped uniform result shape, so the reading/song corpora reuse the
// hybrid fusion without a per-corpus generic. A single-branch input is a no-op
// on ordering. Capped at limit.
func rrfMergeResults(fts, sem []SearchKnowledgeResult, limit int) []SearchKnowledgeResult {
	scores := make(map[string]float64, len(fts)+len(sem))
	byKey := make(map[string]SearchKnowledgeResult, len(fts)+len(sem))
	accumulate := func(rows []SearchKnowledgeResult) {
		for i := range rows {
			key := resultRRFKey(&rows[i])
			scores[key] += 1.0 / (rrfK + float64(i+1))
			if _, ok := byKey[key]; !ok {
				byKey[key] = rows[i]
			}
		}
	}
	accumulate(fts)
	accumulate(sem)

	type scored struct {
		key   string
		score float64
	}
	ranked := make([]scored, 0, len(scores))
	for key, sc := range scores {
		ranked = append(ranked, scored{key: key, score: sc})
	}
	slices.SortFunc(ranked, func(a, b scored) int {
		if a.score != b.score {
			return cmp.Compare(b.score, a.score) // higher score first
		}
		return cmp.Compare(a.key, b.key) // deterministic tiebreak
	})

	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	out := make([]SearchKnowledgeResult, len(ranked))
	for i := range ranked {
		out[i] = byKey[ranked[i].key]
	}
	return out
}

// filterReadingHits keeps only reading results within the date window. No
// content_type filter applies (readings have no content type); a content_type
// filter already narrows the corpus to content in selectSources.
func filterReadingHits(results []SearchKnowledgeResult, after, before *time.Time) []SearchKnowledgeResult {
	return filterResultsByDate(results, after, before)
}

// filterSongHits is the song twin of filterReadingHits.
func filterSongHits(results []SearchKnowledgeResult, after, before *time.Time) []SearchKnowledgeResult {
	return filterResultsByDate(results, after, before)
}

// filterResultsByDate drops results whose CreatedAt falls outside [after,
// before). before is the exclusive upper bound (start of the day after the
// requested date) so the whole requested day is kept — same semantics as the
// content path. A result whose CreatedAt fails to parse is kept (the bound is
// best-effort over an already-trusted server-formatted timestamp).
func filterResultsByDate(results []SearchKnowledgeResult, after, before *time.Time) []SearchKnowledgeResult {
	if after == nil && before == nil {
		return results
	}
	out := make([]SearchKnowledgeResult, 0, len(results))
	for i := range results {
		created, err := time.Parse(time.RFC3339, results[i].CreatedAt)
		if err == nil {
			if after != nil && created.Before(*after) {
				continue
			}
			if before != nil && !created.Before(*before) {
				continue
			}
		}
		out = append(out, results[i])
	}
	return out
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
// search_knowledge — required query, strict content_type enum, source-type
// tokens, and the unsupported project filter — returning the first violation.
// Date parsing stays in the handler because it needs the server timezone and
// produces values the handler consumes.
func validateSearchKnowledgeInput(input SearchKnowledgeInput) error {
	if input.Query == "" {
		return fmt.Errorf("query is required")
	}

	hasContentTypeFilter := input.ContentType != nil && *input.ContentType != ""

	// The content_type enum rejects unknown values. The allowed set
	// (content.Type) is closed and stable, so an out-of-enum value is a
	// caller bug — not a legitimate zero-result. Rejecting keeps
	// "unsupported filter" distinguishable from "no match".
	if hasContentTypeFilter && !content.Type(*input.ContentType).Valid() {
		return fmt.Errorf("unsupported content_type %q (supported: article, essay, build-log, til, digest)", *input.ContentType)
	}

	if err := validateSourceTypes(input.SourceTypes); err != nil {
		return err
	}

	// content_type is a content-only filter. Combining it with a source_types
	// list that excludes content asks for a content filter over a corpus that
	// is not content — a contradiction the caller should fix, not a silent
	// no-op. (An empty source_types list defaults to all corpora, so
	// content_type narrows it to content; only an EXPLICIT content-excluding
	// list conflicts.)
	if hasContentTypeFilter && len(input.SourceTypes) > 0 && !slices.Contains(input.SourceTypes, SourceTypeContent) {
		return fmt.Errorf("unsupported_filter: content_type applies only to source_type=content, but it is not in source_types %v", input.SourceTypes)
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
// set {content, reading, song}. An unknown token (a typo, or an unsupported
// corpus like "bookmark"/"task") is a caller error, not a silent no-op:
// returning it as an error keeps "unsupported filter" distinguishable from "no
// results". A reflection is not a source type — it folds under reading/song.
func validateSourceTypes(filter []string) error {
	for _, t := range filter {
		switch t {
		case SourceTypeContent, SourceTypeReading, SourceTypeSong:
		default:
			return fmt.Errorf("unsupported source_type %q (supported: content, reading, song)", t)
		}
	}
	return nil
}
