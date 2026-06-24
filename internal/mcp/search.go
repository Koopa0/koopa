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

// SourceTypeContent is the source label every search_knowledge result carries.
// search_knowledge queries the content corpus only; the constant keeps the
// wire field explicit rather than hardcoding the literal at the mapping site.
const SourceTypeContent = "content"

// SearchKnowledgeInput is the input for the search_knowledge tool.
type SearchKnowledgeInput struct {
	Query       string  `json:"query" jsonschema:"required" jsonschema_description:"Search query text"`
	ContentType *string `json:"content_type,omitempty" jsonschema_description:"Filter by content type: article, essay, build-log, til, digest. An unknown value is rejected."`
	After       *string `json:"after,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or after the whole of this day (server timezone, UTC by default)."`
	Before      *string `json:"before,omitempty" jsonschema_description:"Filter by created date YYYY-MM-DD: keep rows created on or before the whole of this day, i.e. through 23:59:59 of the date (server timezone, UTC by default)."`
	Limit       FlexInt `json:"limit,omitempty" jsonschema_description:"Max results (default 20, max 50)."`
}

// SearchKnowledgeResult is a single search result over the content corpus:
// id/slug/title are the content's, content_type is set, excerpt is the content
// excerpt, project is the parent project title when the content links to one.
type SearchKnowledgeResult struct {
	ID          string `json:"id"`
	SourceType  string `json:"source_type"` // always "content"
	Title       string `json:"title"`
	Slug        string `json:"slug"`
	ContentType string `json:"content_type,omitempty"` // content.type
	Excerpt     string `json:"excerpt"`
	Project     string `json:"project,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// SearchKnowledgeOutput is the output of the search_knowledge tool.
type SearchKnowledgeOutput struct {
	Results []SearchKnowledgeResult `json:"results"`
	Total   int                     `json:"total"`
	Query   string                  `json:"query"`
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

	filter := buildSearchFilter(input.ContentType, after, before)
	rows, err := s.hybridSearch(ctx, input.Query, limit, filter)
	if err != nil {
		return nil, SearchKnowledgeOutput{}, err
	}
	results := s.mapContentResults(ctx, rows)

	return nil, SearchKnowledgeOutput{
		Results: results,
		Total:   len(results),
		Query:   input.Query,
	}, nil
}

// buildSearchFilter converts the tool's wire filters into a content.SearchFilter
// the store pushes into SQL. content_type is validated to a known enum upstream;
// after/before are already parsed to the inclusive-lower / exclusive-upper
// bounds the store expects.
func buildSearchFilter(contentType *string, after, before *time.Time) content.SearchFilter {
	var ct *content.Type
	if contentType != nil && *contentType != "" {
		t := content.Type(*contentType)
		ct = &t
	}
	return content.SearchFilter{ContentType: ct, CreatedAfter: after, CreatedBefore: before}
}

// hybridSearch runs the content FTS branch and — when the embedder is wired —
// the content semantic branch in parallel, then fuses the two rankings with
// reciprocal rank fusion. An FTS error aborts the search; a semantic failure
// degrades to FTS-only, so search stays useful when Gemini is slow or
// unreachable. Returned slice is ordered by fused rank (FTS rank when the
// semantic side is empty), capped at limit.
func (s *Server) hybridSearch(ctx context.Context, query string, limit int, filter content.SearchFilter) ([]content.Content, error) {
	branchSize := max(limit, searchKnowledgeBranchSize)

	var (
		contentFTS, contentSem []content.Content
	)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		rows, err := s.contents.InternalSearch(gctx, query, 1, branchSize, filter)
		if err != nil {
			return fmt.Errorf("searching content: fts: %w", err)
		}
		contentFTS = rows
		return nil
	})
	if s.embedder != nil {
		g.Go(func() error {
			contentSem = s.semanticBranch(gctx, query, branchSize, filter)
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
func (s *Server) semanticBranch(ctx context.Context, query string, limit int, filter content.SearchFilter) []content.Content {
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

	rows, semErr := s.contents.InternalSemanticSearch(semCtx, queryVec, limit, filter)
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
		// Stable tiebreaker on id (lexicographic UUID order) so two rows with
		// truly equal fused scores keep a deterministic, reproducible order.
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

// mapContentResults maps fused content rows to wire results. content_type and
// date filtering already happened in SQL (pushed into both retrieval branches),
// so no filtering is done here — the rows are exactly the matches, in fused
// rank order.
func (s *Server) mapContentResults(ctx context.Context, contents []content.Content) []SearchKnowledgeResult {
	results := make([]SearchKnowledgeResult, 0, len(contents))
	for i := range contents {
		results = append(results, s.contentToResult(ctx, &contents[i]))
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
// search_knowledge — required query, strict content_type enum, and the
// unsupported project filter — returning the first violation.
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

	return nil
}
