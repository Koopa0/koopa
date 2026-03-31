package mcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Koopa0/koopa0.dev/internal/activity"
	"github.com/Koopa0/koopa0.dev/internal/content"
)

// --- content tools (split from manage_content) ---

// slugRe matches any character that is not a lowercase letter, digit, or hyphen.
var slugRe = regexp.MustCompile(`[^a-z0-9-]+`)

// slugify converts a title to a URL-safe slug: lowercase, spaces to hyphens,
// strip non-alphanumeric, truncate to 80 characters.
func slugify(title string) string {
	s := strings.ToLower(strings.TrimSpace(title))
	s = strings.ReplaceAll(s, " ", "-")
	s = slugRe.ReplaceAllString(s, "")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > 80 {
		s = s[:80]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// ContentActionOutput is the shared output for create/update/publish content.
type ContentActionOutput struct {
	ContentID string `json:"content_id"`
	Slug      string `json:"slug"`
	Status    string `json:"status"`
	Title     string `json:"title"`
	Message   string `json:"message"`
}

// CreateContentInput is the input for the create_content tool.
type CreateContentInput struct {
	Title       string   `json:"title" jsonschema_description:"content title (required)"`
	Body        string   `json:"body" jsonschema_description:"markdown body (required)"`
	ContentType string   `json:"content_type" jsonschema_description:"article|build-log|til|bookmark|essay|note|digest (required)"`
	Tags        []string `json:"tags,omitempty"`
	Project     string   `json:"project,omitempty" jsonschema_description:"project slug/alias/title"`
}

func (s *Server) createContent(ctx context.Context, _ *mcp.CallToolRequest, input *CreateContentInput) (*mcp.CallToolResult, ContentActionOutput, error) {
	if input.Title == "" {
		return nil, ContentActionOutput{}, fmt.Errorf("title is required")
	}
	if input.Body == "" {
		return nil, ContentActionOutput{}, fmt.Errorf("body is required")
	}
	if input.ContentType == "" {
		return nil, ContentActionOutput{}, fmt.Errorf("content_type is required")
	}
	ct := content.Type(input.ContentType)
	if !ct.Valid() {
		return nil, ContentActionOutput{}, fmt.Errorf("invalid content_type %q: use article, build-log, til, bookmark, essay, note, or digest", input.ContentType)
	}

	slug := slugify(input.Title)
	if slug == "" {
		slug = fmt.Sprintf("content-%d", time.Now().Unix())
	}

	params := &content.CreateParams{
		Slug:        slug,
		Title:       input.Title,
		Body:        input.Body,
		Type:        ct,
		Status:      content.StatusDraft,
		ReviewLevel: content.ReviewStandard,
		IsPublic:    true,
	}

	if input.Project != "" {
		proj, err := s.resolveProjectChain(ctx, input.Project)
		if err != nil {
			return nil, ContentActionOutput{}, err
		}
		params.ProjectID = &proj.ID
	}

	now := time.Now()
	created, err := s.createContentWithRetry(ctx, params, slug, now)
	if err != nil {
		return nil, ContentActionOutput{}, fmt.Errorf("creating content: %w", err)
	}

	s.logger.Info("content created via create_content",
		"content_id", created.ID,
		"slug", created.Slug,
		"type", input.ContentType,
	)

	return nil, ContentActionOutput{
		ContentID: created.ID.String(),
		Slug:      created.Slug,
		Status:    string(created.Status),
		Title:     created.Title,
		Message:   "content created as draft",
	}, nil
}

// UpdateContentInput is the input for the update_content tool.
type UpdateContentInput struct {
	ContentID   string   `json:"content_id" jsonschema_description:"content UUID (required)"`
	Title       string   `json:"title,omitempty"`
	Body        string   `json:"body,omitempty"`
	ContentType string   `json:"content_type,omitempty" jsonschema_description:"article|build-log|til|bookmark|essay|note|digest"`
	Tags        []string `json:"tags,omitempty"`
	Project     string   `json:"project,omitempty" jsonschema_description:"project slug/alias/title"`
}

func (s *Server) updateContent(ctx context.Context, _ *mcp.CallToolRequest, input *UpdateContentInput) (*mcp.CallToolResult, ContentActionOutput, error) {
	if input.ContentID == "" {
		return nil, ContentActionOutput{}, fmt.Errorf("content_id is required")
	}
	id, err := uuid.Parse(input.ContentID)
	if err != nil {
		return nil, ContentActionOutput{}, fmt.Errorf("invalid content_id %q: %w", input.ContentID, err)
	}

	p := &content.UpdateParams{}
	if input.Title != "" {
		p.Title = &input.Title
	}
	if input.Body != "" {
		p.Body = &input.Body
	}
	if input.ContentType != "" {
		ct := content.Type(input.ContentType)
		if !ct.Valid() {
			return nil, ContentActionOutput{}, fmt.Errorf("invalid content_type %q", input.ContentType)
		}
		p.Type = &ct
	}
	if input.Project != "" {
		proj, projErr := s.resolveProjectChain(ctx, input.Project)
		if projErr != nil {
			return nil, ContentActionOutput{}, projErr
		}
		p.ProjectID = &proj.ID
	}

	updated, err := s.contents.UpdateContent(ctx, id, p)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return nil, ContentActionOutput{}, fmt.Errorf("content %s not found", input.ContentID)
		}
		return nil, ContentActionOutput{}, fmt.Errorf("updating content: %w", err)
	}

	return nil, ContentActionOutput{
		ContentID: updated.ID.String(),
		Slug:      updated.Slug,
		Status:    string(updated.Status),
		Title:     updated.Title,
		Message:   "content updated",
	}, nil
}

// PublishContentInput is the input for the publish_content tool.
type PublishContentInput struct {
	ContentID string `json:"content_id" jsonschema_description:"content UUID (required)"`
}

func (s *Server) publishContent(ctx context.Context, _ *mcp.CallToolRequest, input PublishContentInput) (*mcp.CallToolResult, ContentActionOutput, error) {
	if input.ContentID == "" {
		return nil, ContentActionOutput{}, fmt.Errorf("content_id is required")
	}
	id, err := uuid.Parse(input.ContentID)
	if err != nil {
		return nil, ContentActionOutput{}, fmt.Errorf("invalid content_id %q: %w", input.ContentID, err)
	}

	published, err := s.contents.PublishContent(ctx, id)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return nil, ContentActionOutput{}, fmt.Errorf("content %s not found", input.ContentID)
		}
		return nil, ContentActionOutput{}, fmt.Errorf("publishing content: %w", err)
	}

	if s.activity != nil {
		evTitle := fmt.Sprintf("published: %s", published.Title)
		_, actErr := s.activity.CreateEvent(ctx, &activity.RecordParams{
			Timestamp: time.Now(),
			Source:    "mcp",
			EventType: "content_published",
			Title:     &evTitle,
		})
		if actErr != nil {
			s.logger.Warn("publish_content: failed to record activity", "error", actErr)
		}
	}

	return nil, ContentActionOutput{
		ContentID: published.ID.String(),
		Slug:      published.Slug,
		Status:    string(published.Status),
		Title:     published.Title,
		Message:   "content published",
	}, nil
}

// --- get_content_pipeline tool ---

// ContentPipelineInput is the input for the get_content_pipeline tool.
type ContentPipelineInput struct {
	View        string `json:"view,omitempty" jsonschema_description:"queue|calendar|recent (default: queue)"`
	Status      string `json:"status,omitempty" jsonschema_description:"draft|review|published|all"`
	ContentType string `json:"content_type,omitempty"`
	Limit       int    `json:"limit,omitempty" jsonschema_description:"max results (default 20)"`
}

// ContentPipelineOutput is the output for the get_content_pipeline tool.
type ContentPipelineOutput struct {
	View  string                 `json:"view"`
	Items []contentPipelineEntry `json:"items"`
	Total int                    `json:"total"`
}

type contentPipelineEntry struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	Tags        []string `json:"tags"`
	CreatedAt   string   `json:"created_at"`
	PublishedAt string   `json:"published_at,omitempty"`
	WordCount   int      `json:"word_count"`
}

func toContentPipelineEntry(c *content.Content) contentPipelineEntry {
	e := contentPipelineEntry{
		ID:        c.ID.String(),
		Slug:      c.Slug,
		Title:     c.Title,
		Type:      string(c.Type),
		Status:    string(c.Status),
		Tags:      c.Tags,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
		WordCount: estimateWordCount(c.Body),
	}
	if c.PublishedAt != nil {
		e.PublishedAt = c.PublishedAt.Format(time.RFC3339)
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	return e
}

// estimateWordCount returns a rough word count for a string.
func estimateWordCount(body string) int {
	if body == "" {
		return 0
	}
	return len(strings.Fields(body))
}

func (s *Server) getContentPipeline(ctx context.Context, _ *mcp.CallToolRequest, input ContentPipelineInput) (*mcp.CallToolResult, ContentPipelineOutput, error) {
	view := input.View
	if view == "" {
		view = "queue"
	}
	limit := clamp(input.Limit, 1, 100, 20)

	// Fetch a generous page from AdminContents and filter in memory.
	var typeFilter *content.Type
	if input.ContentType != "" {
		ct := content.Type(input.ContentType)
		if ct.Valid() {
			typeFilter = &ct
		}
	}

	all, _, err := s.contents.AdminContents(ctx, content.AdminFilter{
		Page:    1,
		PerPage: 200,
		Type:    typeFilter,
	})
	if err != nil {
		return nil, ContentPipelineOutput{}, fmt.Errorf("listing contents: %w", err)
	}

	filtered, err := filterContentByView(all, view, input.Status)
	if err != nil {
		return nil, ContentPipelineOutput{}, err
	}

	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	entries := make([]contentPipelineEntry, len(filtered))
	for i := range filtered {
		entries[i] = toContentPipelineEntry(&filtered[i])
	}

	return nil, ContentPipelineOutput{
		View:  view,
		Items: entries,
		Total: len(entries),
	}, nil
}

// filterContentByView applies the view-specific filter to content items.
func filterContentByView(all []content.Content, view, status string) ([]content.Content, error) {
	switch view {
	case "queue":
		return filterQueueView(all, status), nil
	case "calendar":
		return filterCalendarView(all), nil
	case "recent":
		return filterRecentView(all), nil
	default:
		return nil, fmt.Errorf("invalid view %q: use queue, calendar, or recent", view)
	}
}

// filterQueueView returns draft/review items, optionally filtered by explicit status.
func filterQueueView(all []content.Content, status string) []content.Content {
	var filtered []content.Content
	for i := range all {
		c := &all[i]
		if status != "" && status != "all" {
			if string(c.Status) != status {
				continue
			}
		} else if c.Status != content.StatusDraft && c.Status != content.StatusReview {
			continue
		}
		filtered = append(filtered, *c)
	}
	return filtered
}

// filterCalendarView returns recently published items and drafts/review items.
func filterCalendarView(all []content.Content) []content.Content {
	sevenDaysAgo := time.Now().AddDate(0, 0, -7)
	var filtered []content.Content
	for i := range all {
		c := &all[i]
		if c.Status == content.StatusPublished && c.PublishedAt != nil && c.PublishedAt.After(sevenDaysAgo) {
			filtered = append(filtered, *c)
			continue
		}
		if c.Status == content.StatusDraft || c.Status == content.StatusReview {
			filtered = append(filtered, *c)
		}
	}
	return filtered
}

// filterRecentView returns only published items.
func filterRecentView(all []content.Content) []content.Content {
	var filtered []content.Content
	for i := range all {
		c := &all[i]
		if c.Status == content.StatusPublished {
			filtered = append(filtered, *c)
		}
	}
	return filtered
}

// --- synthesize_topic ---

// SynthesizeTopicInput is the input for the synthesize_topic tool.
type SynthesizeTopicInput struct {
	Query              string `json:"query" jsonschema_description:"topic to synthesize (required)"`
	MaxSources         int    `json:"max_sources,omitempty" jsonschema_description:"max source items to use (default 15, max 30)"`
	IncludeGapAnalysis *bool  `json:"include_gap_analysis,omitempty" jsonschema_description:"include sub-topic coverage gaps (default true)"`
}

// SynthesizeTopicOutput is the output for the synthesize_topic tool.
type SynthesizeTopicOutput struct {
	Query       string            `json:"query"`
	Sources     []synthesisSource `json:"sources"`
	SourceCount map[string]int    `json:"source_count"`
	Synthesis   synthesisSections `json:"synthesis"`
	Gaps        []synthesisGap    `json:"gaps,omitempty"`
	Disclaimer  string            `json:"disclaimer,omitempty"`
}

type synthesisSource struct {
	Slug       string `json:"slug,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	Title      string `json:"title"`
	Type       string `json:"type"`
	SourceType string `json:"source_type"` // "content" or "note"
	Excerpt    string `json:"excerpt"`
}

type synthesisSections struct {
	PracticalExperience string `json:"practical_experience"` // from build logs, TILs
	ExternalKnowledge   string `json:"external_knowledge"`   // from RSS bookmarks
	TheoreticalBasis    string `json:"theoretical_basis"`    // from Obsidian notes
	CommonPatterns      string `json:"common_patterns"`      // cross-source patterns
}

type synthesisGap struct {
	SubTopic string `json:"sub_topic"`
	Reason   string `json:"reason"`
}

// broadenSearchResults tries individual words from the query to find additional
// results when the initial search returned fewer than 5 items.
func (s *Server) broadenSearchResults(ctx context.Context, results []knowledgeResult, query string, maxSources int) []knowledgeResult {
	if len(results) >= 5 {
		return results
	}
	words := strings.FieldsSeq(query)
	for w := range words {
		if len(w) < 3 || len(results) >= maxSources {
			continue
		}
		_, extraOut, extraErr := s.searchKnowledge(ctx, nil, &SearchKnowledgeInput{
			Query: w,
			Limit: 5,
		})
		if extraErr != nil {
			continue
		}
		results = mergeUniqueResults(results, extraOut.Results, maxSources)
	}
	return results
}

// mergeUniqueResults appends non-duplicate results up to maxSources.
func mergeUniqueResults(existing, candidates []knowledgeResult, maxSources int) []knowledgeResult {
	for _, r := range candidates {
		if len(existing) >= maxSources {
			break
		}
		if !isDuplicateResult(existing, &r) {
			existing = append(existing, r)
		}
	}
	return existing
}

// isDuplicateResult checks if a result already exists in the slice by slug or file path.
func isDuplicateResult(results []knowledgeResult, candidate *knowledgeResult) bool {
	for _, existing := range results {
		if (candidate.Slug != "" && candidate.Slug == existing.Slug) || (candidate.FilePath != "" && candidate.FilePath == existing.FilePath) {
			return true
		}
	}
	return false
}

// sourceClassification holds classified source lines and counts from knowledge results.
type sourceClassification struct {
	practical   []string
	external    []string
	theoretical []string
	sourceCount map[string]int
	sources     []synthesisSource
}

// classifySources categorizes knowledge results into practical/external/theoretical buckets.
func classifySources(results []knowledgeResult) sourceClassification {
	c := sourceClassification{
		sourceCount: map[string]int{},
		sources:     make([]synthesisSource, len(results)),
	}
	for i := range results {
		r := &results[i]
		c.sources[i] = synthesisSource{
			Slug:       r.Slug,
			FilePath:   r.FilePath,
			Title:      r.Title,
			Type:       r.Type,
			SourceType: r.SourceType,
			Excerpt:    r.Excerpt,
		}
		switch r.Type {
		case "build-log", "til":
			c.practical = append(c.practical, fmt.Sprintf("- [%s] %s: %s", r.Type, r.Title, truncate(r.Excerpt, 150)))
			c.sourceCount["practical"]++
		case "bookmark", "digest":
			c.external = append(c.external, fmt.Sprintf("- [%s] %s: %s", r.Type, r.Title, truncate(r.Excerpt, 150)))
			c.sourceCount["external"]++
		case "article", "essay":
			c.external = append(c.external, fmt.Sprintf("- [%s] %s: %s", r.Type, r.Title, truncate(r.Excerpt, 150)))
			c.sourceCount["article"]++
		default:
			if r.SourceType == "note" {
				c.theoretical = append(c.theoretical, fmt.Sprintf("- %s: %s", r.Title, truncate(r.Excerpt, 150)))
				c.sourceCount["note"]++
			}
		}
	}
	return c
}

// buildSynthesisSections assembles synthesis text from classified source lines.
func buildSynthesisSections(c *sourceClassification, query string, totalResults int) synthesisSections {
	s := synthesisSections{
		PracticalExperience: "No build logs or TILs found for this topic.",
		ExternalKnowledge:   "No RSS bookmarks or external articles found for this topic.",
		TheoreticalBasis:    "No Obsidian notes found for this topic.",
		CommonPatterns:      "Insufficient data to identify cross-source patterns.",
	}
	if len(c.practical) > 0 {
		s.PracticalExperience = strings.Join(c.practical, "\n")
	}
	if len(c.external) > 0 {
		s.ExternalKnowledge = strings.Join(c.external, "\n")
	}
	if len(c.theoretical) > 0 {
		s.TheoreticalBasis = strings.Join(c.theoretical, "\n")
	}
	if totalResults >= 3 {
		s.CommonPatterns = fmt.Sprintf("Found %d sources across %d categories covering '%s'.", totalResults, len(c.sourceCount), query)
	}
	return s
}

// analyzeGaps identifies knowledge coverage gaps based on source classification counts.
func analyzeGaps(sourceCount map[string]int, query string) []synthesisGap {
	var gaps []synthesisGap
	if sourceCount["practical"] == 0 {
		gaps = append(gaps, synthesisGap{
			SubTopic: "hands-on experience",
			Reason:   fmt.Sprintf("No build logs or TILs found about %q — consider doing a practice project", query),
		})
	}
	if sourceCount["note"] == 0 {
		gaps = append(gaps, synthesisGap{
			SubTopic: "theoretical foundation",
			Reason:   fmt.Sprintf("No Obsidian notes found about %q — consider writing study notes", query),
		})
	}
	if sourceCount["external"] == 0 && sourceCount["article"] == 0 {
		gaps = append(gaps, synthesisGap{
			SubTopic: "external perspectives",
			Reason:   fmt.Sprintf("No bookmarked articles about %q — check RSS feeds or curate relevant items", query),
		})
	}
	return gaps
}

func (s *Server) synthesizeTopic(ctx context.Context, _ *mcp.CallToolRequest, input SynthesizeTopicInput) (*mcp.CallToolResult, SynthesizeTopicOutput, error) {
	if input.Query == "" {
		return nil, SynthesizeTopicOutput{}, fmt.Errorf("query is required")
	}
	maxSources := clamp(input.MaxSources, 5, 30, 15)

	// Step 1: search and broaden
	_, searchOut, err := s.searchKnowledge(ctx, nil, &SearchKnowledgeInput{
		Query: input.Query,
		Limit: maxSources,
	})
	if err != nil {
		return nil, SynthesizeTopicOutput{}, fmt.Errorf("searching knowledge: %w", err)
	}
	results := s.broadenSearchResults(ctx, searchOut.Results, input.Query, maxSources)

	// Step 2: classify and synthesize
	classified := classifySources(results)
	synthesis := buildSynthesisSections(&classified, input.Query, len(results))

	out := SynthesizeTopicOutput{
		Query:       input.Query,
		Sources:     classified.sources,
		SourceCount: classified.sourceCount,
		Synthesis:   synthesis,
	}

	// Step 3: gap analysis
	if input.IncludeGapAnalysis == nil || *input.IncludeGapAnalysis {
		out.Gaps = analyzeGaps(classified.sourceCount, input.Query)
	}

	if len(results) < 5 {
		out.Disclaimer = fmt.Sprintf("Only %d sources found. Gap analysis may be incomplete due to limited data.", len(results))
	}

	return nil, out, nil
}
