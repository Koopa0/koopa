package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/content"
)

// --- manage_content tool ---

// ManageContentInput is the input for the manage_content tool.
type ManageContentInput struct {
	Action      string   `json:"action" jsonschema_description:"create|update|publish (required)"`
	ContentID   string   `json:"content_id,omitempty" jsonschema_description:"content UUID (required for update/publish)"`
	Title       string   `json:"title,omitempty" jsonschema_description:"content title (required for create)"`
	Body        string   `json:"body,omitempty" jsonschema_description:"markdown body (required for create)"`
	ContentType string   `json:"content_type,omitempty" jsonschema_description:"article|build-log|til|bookmark|essay|note|digest (required for create)"`
	Tags        []string `json:"tags,omitempty"`
	Project     string   `json:"project,omitempty" jsonschema_description:"project slug/alias/title"`
}

// ManageContentOutput is the output for the manage_content tool.
type ManageContentOutput struct {
	Action    string `json:"action"`
	ContentID string `json:"content_id,omitempty"`
	Slug      string `json:"slug,omitempty"`
	Status    string `json:"status,omitempty"`
	Title     string `json:"title,omitempty"`
	Message   string `json:"message,omitempty"`
}

// slugRe matches any character that is not a lowercase letter, digit, or hyphen.
var slugRe = regexp.MustCompile(`[^a-z0-9-]+`)

// slugify converts a title to a URL-safe slug: lowercase, spaces to hyphens,
// strip non-alphanumeric, truncate to 80 characters.
func slugify(title string) string {
	s := strings.ToLower(strings.TrimSpace(title))
	s = strings.ReplaceAll(s, " ", "-")
	s = slugRe.ReplaceAllString(s, "")
	// Collapse consecutive hyphens.
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

func (s *Server) manageContent(ctx context.Context, _ *mcp.CallToolRequest, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	switch input.Action {
	case "create":
		return s.manageContentCreate(ctx, input)
	case "update":
		return s.manageContentUpdate(ctx, input)
	case "publish":
		return s.manageContentPublish(ctx, input)
	default:
		return nil, ManageContentOutput{}, fmt.Errorf("invalid action %q: use create, update, or publish", input.Action)
	}
}

func (s *Server) manageContentCreate(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.Title == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("title is required for create")
	}
	if input.Body == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("body is required for create")
	}
	if input.ContentType == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_type is required for create")
	}
	ct := content.Type(input.ContentType)
	if !ct.Valid() {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_type %q: use article, build-log, til, bookmark, essay, note, or digest", input.ContentType)
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
		Tags:        input.Tags,
		ReviewLevel: content.ReviewStandard,
		Visibility:  content.VisibilityPublic,
	}

	if input.Project != "" {
		proj, err := s.resolveProjectChain(ctx, input.Project)
		if err != nil {
			return nil, ManageContentOutput{}, err
		}
		params.ProjectID = &proj.ID
	}

	now := time.Now()
	created, err := s.createContentWithRetry(ctx, params, slug, now)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("creating content: %w", err)
	}

	s.logger.Info("content created via manage_content",
		"content_id", created.ID,
		"slug", created.Slug,
		"type", input.ContentType,
	)

	return nil, ManageContentOutput{
		Action:    "create",
		ContentID: created.ID.String(),
		Slug:      created.Slug,
		Status:    string(created.Status),
		Title:     created.Title,
		Message:   "content created as draft",
	}, nil
}

func (s *Server) manageContentUpdate(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for update")
	}
	id, err := uuid.Parse(input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id %q: %w", input.ContentID, err)
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
			return nil, ManageContentOutput{}, fmt.Errorf("invalid content_type %q", input.ContentType)
		}
		p.Type = &ct
	}
	if len(input.Tags) > 0 {
		p.Tags = input.Tags
	}
	if input.Project != "" {
		proj, projErr := s.resolveProjectChain(ctx, input.Project)
		if projErr != nil {
			return nil, ManageContentOutput{}, projErr
		}
		p.ProjectID = &proj.ID
	}

	updated, err := s.contents.UpdateContent(ctx, id, p)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return nil, ManageContentOutput{}, fmt.Errorf("content %s not found", input.ContentID)
		}
		return nil, ManageContentOutput{}, fmt.Errorf("updating content: %w", err)
	}

	return nil, ManageContentOutput{
		Action:    "update",
		ContentID: updated.ID.String(),
		Slug:      updated.Slug,
		Status:    string(updated.Status),
		Title:     updated.Title,
		Message:   "content updated",
	}, nil
}

func (s *Server) manageContentPublish(ctx context.Context, input *ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
	if input.ContentID == "" {
		return nil, ManageContentOutput{}, fmt.Errorf("content_id is required for publish")
	}
	id, err := uuid.Parse(input.ContentID)
	if err != nil {
		return nil, ManageContentOutput{}, fmt.Errorf("invalid content_id %q: %w", input.ContentID, err)
	}

	published, err := s.contents.PublishContent(ctx, id)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return nil, ManageContentOutput{}, fmt.Errorf("content %s not found", input.ContentID)
		}
		return nil, ManageContentOutput{}, fmt.Errorf("publishing content: %w", err)
	}

	// Record activity event if writer is available.
	if s.activityWriter != nil {
		evTitle := fmt.Sprintf("published: %s", published.Title)
		_, actErr := s.activityWriter.CreateEvent(ctx, &activity.RecordParams{
			Timestamp: time.Now(),
			Source:    "mcp",
			EventType: "content_published",
			Title:     &evTitle,
		})
		if actErr != nil {
			s.logger.Warn("manage_content: failed to record activity", "error", actErr)
		}
	}

	return nil, ManageContentOutput{
		Action:    "publish",
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

	var filtered []content.Content
	switch view {
	case "queue":
		for i := range all {
			c := &all[i]
			if input.Status != "" && input.Status != "all" {
				if string(c.Status) != input.Status {
					continue
				}
			} else if c.Status != content.StatusDraft && c.Status != content.StatusReview {
				continue
			}
			filtered = append(filtered, *c)
		}
	case "calendar":
		sevenDaysAgo := time.Now().AddDate(0, 0, -7)
		for i := range all {
			c := &all[i]
			// Published in last 7 days.
			if c.Status == content.StatusPublished && c.PublishedAt != nil && c.PublishedAt.After(sevenDaysAgo) {
				filtered = append(filtered, *c)
				continue
			}
			// Drafts and review items (potential scheduled content).
			if c.Status == content.StatusDraft || c.Status == content.StatusReview {
				filtered = append(filtered, *c)
			}
		}
	case "recent":
		for i := range all {
			c := &all[i]
			if c.Status == content.StatusPublished {
				filtered = append(filtered, *c)
			}
		}
	default:
		return nil, ContentPipelineOutput{}, fmt.Errorf("invalid view %q: use queue, calendar, or recent", view)
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

func (s *Server) synthesizeTopic(ctx context.Context, _ *mcp.CallToolRequest, input SynthesizeTopicInput) (*mcp.CallToolResult, SynthesizeTopicOutput, error) {
	if input.Query == "" {
		return nil, SynthesizeTopicOutput{}, fmt.Errorf("query is required")
	}
	maxSources := clamp(input.MaxSources, 5, 30, 15)

	// Step 1: Search across all content types
	_, searchOut, err := s.searchKnowledge(ctx, nil, SearchKnowledgeInput{
		Query: input.Query,
		Limit: maxSources,
	})
	if err != nil {
		return nil, SynthesizeTopicOutput{}, fmt.Errorf("searching knowledge: %w", err)
	}

	results := searchOut.Results

	// If too few results, try a broader search with individual words
	if len(results) < 5 {
		words := strings.Fields(input.Query)
		for _, w := range words {
			if len(w) < 3 || len(results) >= maxSources {
				continue
			}
			_, extraOut, extraErr := s.searchKnowledge(ctx, nil, SearchKnowledgeInput{
				Query: w,
				Limit: 5,
			})
			if extraErr == nil {
				for _, r := range extraOut.Results {
					// Dedup by slug/filepath
					dup := false
					for _, existing := range results {
						if (r.Slug != "" && r.Slug == existing.Slug) || (r.FilePath != "" && r.FilePath == existing.FilePath) {
							dup = true
							break
						}
					}
					if !dup && len(results) < maxSources {
						results = append(results, r)
					}
				}
			}
		}
	}

	// Step 2: Classify sources and build synthesis sections
	var practical, external, theoretical []string
	sourceCount := map[string]int{}
	sources := make([]synthesisSource, len(results))

	for i := range results {
		r := &results[i]
		sources[i] = synthesisSource{
			Slug:       r.Slug,
			FilePath:   r.FilePath,
			Title:      r.Title,
			Type:       r.Type,
			SourceType: r.SourceType,
			Excerpt:    r.Excerpt,
		}

		// Classify by type
		switch r.Type {
		case "build-log", "til":
			practical = append(practical, fmt.Sprintf("- [%s] %s: %s", r.Type, r.Title, truncate(r.Excerpt, 150)))
			sourceCount["practical"]++
		case "bookmark", "digest":
			external = append(external, fmt.Sprintf("- [%s] %s: %s", r.Type, r.Title, truncate(r.Excerpt, 150)))
			sourceCount["external"]++
		case "article", "essay":
			external = append(external, fmt.Sprintf("- [%s] %s: %s", r.Type, r.Title, truncate(r.Excerpt, 150)))
			sourceCount["article"]++
		default:
			if r.SourceType == "note" {
				theoretical = append(theoretical, fmt.Sprintf("- %s: %s", r.Title, truncate(r.Excerpt, 150)))
				sourceCount["note"]++
			}
		}
	}

	synthesis := synthesisSections{
		PracticalExperience: "No build logs or TILs found for this topic.",
		ExternalKnowledge:   "No RSS bookmarks or external articles found for this topic.",
		TheoreticalBasis:    "No Obsidian notes found for this topic.",
		CommonPatterns:      "Insufficient data to identify cross-source patterns.",
	}
	if len(practical) > 0 {
		synthesis.PracticalExperience = strings.Join(practical, "\n")
	}
	if len(external) > 0 {
		synthesis.ExternalKnowledge = strings.Join(external, "\n")
	}
	if len(theoretical) > 0 {
		synthesis.TheoreticalBasis = strings.Join(theoretical, "\n")
	}
	if len(results) >= 3 {
		synthesis.CommonPatterns = fmt.Sprintf("Found %d sources across %d categories covering '%s'.", len(results), len(sourceCount), input.Query)
	}

	out := SynthesizeTopicOutput{
		Query:       input.Query,
		Sources:     sources,
		SourceCount: sourceCount,
		Synthesis:   synthesis,
	}

	// Step 3: Gap analysis
	if input.IncludeGapAnalysis == nil || *input.IncludeGapAnalysis { // default true when omitted
		if sourceCount["practical"] == 0 {
			out.Gaps = append(out.Gaps, synthesisGap{
				SubTopic: "hands-on experience",
				Reason:   fmt.Sprintf("No build logs or TILs found about %q — consider doing a practice project", input.Query),
			})
		}
		if sourceCount["note"] == 0 {
			out.Gaps = append(out.Gaps, synthesisGap{
				SubTopic: "theoretical foundation",
				Reason:   fmt.Sprintf("No Obsidian notes found about %q — consider writing study notes", input.Query),
			})
		}
		if sourceCount["external"] == 0 && sourceCount["article"] == 0 {
			out.Gaps = append(out.Gaps, synthesisGap{
				SubTopic: "external perspectives",
				Reason:   fmt.Sprintf("No bookmarked articles about %q — check RSS feeds or curate relevant items", input.Query),
			})
		}
	}

	// Disclaimer if data is thin
	totalContent := len(results)
	if totalContent < 5 {
		out.Disclaimer = fmt.Sprintf("Only %d sources found. Gap analysis may be incomplete due to limited data.", totalContent)
	}

	return nil, out, nil
}
