package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/project"
)

// Server is the MCP server exposing read-only knowledge tools.
type Server struct {
	server    *mcp.Server
	notes     NoteSearcher
	activity  ActivityReader
	projects  ProjectReader
	collected CollectedReader
	stats     StatsReader
	tasks     TaskReader
	contents  ContentReader
	goals     GoalReader
	logger    *slog.Logger
}

// NewServer creates an MCP server with all tools registered.
func NewServer(
	notes NoteSearcher,
	activity ActivityReader,
	projects ProjectReader,
	collected CollectedReader,
	stats StatsReader,
	tasks TaskReader,
	contents ContentReader,
	goals GoalReader,
	logger *slog.Logger,
) *Server {
	s := &Server{
		notes:     notes,
		activity:  activity,
		projects:  projects,
		collected: collected,
		stats:     stats,
		tasks:     tasks,
		contents:  contents,
		goals:     goals,
		logger:    logger,
	}

	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "koopa0-knowledge",
		Version: "v0.2.0",
	}, nil)

	// --- existing tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "search_notes",
		Description: "Search obsidian knowledge notes by text query and/or frontmatter filters. Uses full-text search with Reciprocal Rank Fusion when both text and filters are provided. Use this when you know the content is an Obsidian note. For broader searches across all content types, use search_knowledge instead.",
	}, s.searchNotes)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_project_context",
		Description: "Get full context for a single project by name, slug, or alias. Returns project details, recent activity, and related notes. Use list_projects first if you need to see all projects.",
	}, s.getProjectContext)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_recent_activity",
		Description: "Get recent development activity events, optionally filtered by source (github, obsidian, notion) or project name. Groups results by source. Use when the user asks what they've been working on, wants a summary of recent progress, or needs to understand time allocation.",
	}, s.getRecentActivity)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_decision_log",
		Description: "Retrieve decision-log notes, optionally filtered by project context. Use when looking for past architectural decisions, design rationale, or 'why did we choose X' questions.",
	}, s.getDecisionLog)

	// --- new Phase 1 tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_rss_highlights",
		Description: "Get high-quality RSS articles collected and scored by AI. Returns curated external content with AI summaries, Chinese translations, and relevance scores. Use when the user asks about recent tech news, wants reading recommendations, or needs to know what's trending in their tracked topics.",
	}, s.getRSSHighlights)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_platform_stats",
		Description: "Get a full snapshot of the koopa0.dev knowledge engine: content counts, project stats, activity trends, spaced repetition status, goal alignment drift, and learning progress. Use when the user wants an overview of their system, asks 'how is everything going', or needs to assess platform health.",
	}, s.getPlatformStats)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_pending_tasks",
		Description: "Get pending (not-done) tasks sorted by urgency: tasks with deadlines first (earliest deadline on top), then tasks without deadlines sorted by staleness (least recently touched first). Optionally filter by project. Use when the user asks what to work on, needs to plan their day, or wants to see overdue items.",
	}, s.getPendingTasks)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "search_knowledge",
		Description: "Search across ALL content types: articles, build logs, TILs, notes, and Obsidian notes. Returns excerpts with source type markers. Use when the user asks 'have I written about X before', needs to find past insights, or wants to search without knowing which content type contains the answer. For full article content, follow up with get_content_detail using the slug.",
	}, s.searchKnowledge)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_content_detail",
		Description: "Get the full content of an article, build log, TIL, or note by slug. Returns complete body text, tags, topics, and metadata. Use after search_knowledge to read the full content of a specific result.",
	}, s.getContentDetail)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "list_projects",
		Description: "List all active projects with status, area, tech stack, and URLs. Use when the user wants to see all their projects at a glance, needs to pick which project to work on, or asks about project health. For deep context on a single project, follow up with get_project_context.",
	}, s.listProjects)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_goals",
		Description: "Get personal goals synced from Notion, with status, area, quarter, and deadline. Use when the user asks about their goals, wants to check progress, or needs to align daily work with long-term objectives.",
	}, s.getGoals)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_learning_progress",
		Description: "Get learning metrics: spaced repetition stats (enrolled, due), note growth trends, weekly activity comparison, and top knowledge tags. Use when the user asks about their learning progress, wants to know what topics they've been studying, or needs motivation data.",
	}, s.getLearningProgress)

	return s
}

// MCPServer returns the underlying mcp.Server for use with HTTP transports.
func (s *Server) MCPServer() *mcp.Server {
	return s.server
}

// Run starts the MCP server over stdio transport, blocking until the client disconnects.
func (s *Server) Run(ctx context.Context) error {
	return s.server.Run(ctx, &mcp.StdioTransport{})
}

// --- Tool input/output types ---

// SearchNotesInput is the input for the search_notes tool.
type SearchNotesInput struct {
	Query   string `json:"query,omitempty" jsonschema_description:"free-text search query"`
	Type    string `json:"type,omitempty" jsonschema_description:"filter by note type (e.g. til article note build-log)"`
	Source  string `json:"source,omitempty" jsonschema_description:"filter by source"`
	Context string `json:"context,omitempty" jsonschema_description:"filter by context (e.g. project name)"`
	Book    string `json:"book,omitempty" jsonschema_description:"filter by book name"`
	Limit   int    `json:"limit,omitempty" jsonschema_description:"max results (default 10 max 50)"`
}

// SearchNotesOutput is the output for the search_notes tool.
type SearchNotesOutput struct {
	Results []noteResult `json:"results"`
	Total   int          `json:"total"`
}

type noteResult struct {
	ID       int64    `json:"id"`
	FilePath string   `json:"file_path"`
	Title    string   `json:"title,omitempty"`
	Type     string   `json:"type,omitempty"`
	Context  string   `json:"context,omitempty"`
	Source   string   `json:"source,omitempty"`
	Tags     []string `json:"tags"`
	Excerpt  string   `json:"excerpt,omitempty"`
	Score    float64  `json:"score,omitempty"`
}

const (
	maxQueryLen  = 500
	maxFilterLen = 100
)

func (s *Server) searchNotes(ctx context.Context, _ *mcp.CallToolRequest, input SearchNotesInput) (*mcp.CallToolResult, SearchNotesOutput, error) {
	if len(input.Query) > maxQueryLen {
		return nil, SearchNotesOutput{}, fmt.Errorf("query too long (max %d characters)", maxQueryLen)
	}
	for _, v := range []string{input.Type, input.Source, input.Context, input.Book} {
		if len(v) > maxFilterLen {
			return nil, SearchNotesOutput{}, fmt.Errorf("filter value too long (max %d characters)", maxFilterLen)
		}
	}

	limit := clamp(input.Limit, 1, 50, 10)

	hasQuery := input.Query != ""
	hasFilters := input.Type != "" || input.Source != "" || input.Context != "" || input.Book != ""

	if !hasQuery && !hasFilters {
		return nil, SearchNotesOutput{}, fmt.Errorf("at least one of query or filter fields is required")
	}

	var results []searchResultEntry

	switch {
	case hasQuery && hasFilters:
		fetchLimit := limit * 3

		textResults, err := s.notes.SearchByText(ctx, input.Query, fetchLimit)
		if err != nil {
			return nil, SearchNotesOutput{}, fmt.Errorf("text search: %w", err)
		}

		filterResults, err := s.notes.SearchByFilters(ctx, toSearchFilter(input), fetchLimit)
		if err != nil {
			return nil, SearchNotesOutput{}, fmt.Errorf("filter search: %w", err)
		}

		results = rrfMerge(textResults, filterResults, limit)
	case hasQuery:
		textResults, err := s.notes.SearchByText(ctx, input.Query, limit)
		if err != nil {
			return nil, SearchNotesOutput{}, fmt.Errorf("text search: %w", err)
		}
		results = make([]searchResultEntry, len(textResults))
		for i, r := range textResults {
			results[i] = searchResultEntry{Note: r.Note, Score: float64(r.Rank)}
		}
	default:
		filterResults, err := s.notes.SearchByFilters(ctx, toSearchFilter(input), limit)
		if err != nil {
			return nil, SearchNotesOutput{}, fmt.Errorf("filter search: %w", err)
		}
		results = make([]searchResultEntry, len(filterResults))
		for i, n := range filterResults {
			results[i] = searchResultEntry{Note: n}
		}
	}

	out := SearchNotesOutput{
		Results: make([]noteResult, len(results)),
		Total:   len(results),
	}
	for i, r := range results {
		out.Results[i] = toNoteResult(r)
	}

	return nil, out, nil
}

// ProjectContextInput is the input for the get_project_context tool.
type ProjectContextInput struct {
	Project string `json:"project" jsonschema_description:"project name slug or alias (required)"`
}

// ProjectContextOutput is the output for the get_project_context tool.
type ProjectContextOutput struct {
	Project        projectSummary   `json:"project"`
	RecentActivity []activityResult `json:"recent_activity"`
	RelatedNotes   []noteResult     `json:"related_notes"`
}

// projectSummary is a safe subset of project.Project for MCP output.
type projectSummary struct {
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Role        string   `json:"role"`
	TechStack   []string `json:"tech_stack"`
	Status      string   `json:"status"`
	Area        string   `json:"area"`
	GithubURL   string   `json:"github_url,omitempty"`
	LiveURL     string   `json:"live_url,omitempty"`
}

type activityResult struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Source    string `json:"source"`
	Title     string `json:"title,omitempty"`
	Repo      string `json:"repo,omitempty"`
}

func (s *Server) getProjectContext(ctx context.Context, _ *mcp.CallToolRequest, input ProjectContextInput) (*mcp.CallToolResult, ProjectContextOutput, error) {
	if input.Project == "" {
		return nil, ProjectContextOutput{}, fmt.Errorf("project is required")
	}

	proj, err := s.projects.ProjectBySlug(ctx, input.Project)
	if err != nil {
		if !errors.Is(err, project.ErrNotFound) {
			return nil, ProjectContextOutput{}, fmt.Errorf("querying project: %w", err)
		}
		proj, err = s.projects.ProjectByAlias(ctx, input.Project)
		if err != nil {
			return nil, ProjectContextOutput{}, fmt.Errorf("project %q not found by slug or alias", input.Project)
		}
	}

	events, err := s.activity.EventsByProject(ctx, proj.Title, 20)
	if err != nil {
		s.logger.Error("fetching project activity", "project", proj.Title, "error", err)
		events = nil
	}

	relatedNotes, err := s.notes.SearchByFilters(ctx, note.SearchFilter{Context: &proj.Title}, 10)
	if err != nil {
		s.logger.Error("fetching related notes", "project", proj.Title, "error", err)
		relatedNotes = nil
	}

	out := ProjectContextOutput{
		Project:        toProjectSummary(proj),
		RecentActivity: make([]activityResult, len(events)),
		RelatedNotes:   make([]noteResult, len(relatedNotes)),
	}
	for i, e := range events {
		out.RecentActivity[i] = eventToResult(e)
	}
	for i, n := range relatedNotes {
		out.RelatedNotes[i] = toNoteResult(searchResultEntry{Note: n})
	}

	return nil, out, nil
}

// RecentActivityInput is the input for the get_recent_activity tool.
type RecentActivityInput struct {
	Days    int    `json:"days,omitempty" jsonschema_description:"number of days to look back (default 7 max 30)"`
	Source  string `json:"source,omitempty" jsonschema_description:"filter by source (e.g. github obsidian notion)"`
	Project string `json:"project,omitempty" jsonschema_description:"filter by project name"`
}

// RecentActivityOutput is the output for the get_recent_activity tool.
type RecentActivityOutput struct {
	Period         string                      `json:"period"`
	EventsBySource map[string][]activityResult `json:"events_by_source"`
	Total          int                         `json:"total"`
}

func (s *Server) getRecentActivity(ctx context.Context, _ *mcp.CallToolRequest, input RecentActivityInput) (*mcp.CallToolResult, RecentActivityOutput, error) {
	days := clamp(input.Days, 1, 30, 7)

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	var source, proj *string
	if input.Source != "" {
		source = &input.Source
	}
	if input.Project != "" {
		proj = &input.Project
	}

	events, err := s.activity.EventsByFilters(ctx, start, now, source, proj, 100)
	if err != nil {
		return nil, RecentActivityOutput{}, fmt.Errorf("querying activity: %w", err)
	}

	grouped := make(map[string][]activityResult)
	for _, e := range events {
		grouped[e.Source] = append(grouped[e.Source], eventToResult(e))
	}

	return nil, RecentActivityOutput{
		Period:         fmt.Sprintf("%d days", days),
		EventsBySource: grouped,
		Total:          len(events),
	}, nil
}

// DecisionLogInput is the input for the get_decision_log tool.
type DecisionLogInput struct {
	Project string `json:"project,omitempty" jsonschema_description:"filter by project context"`
	Limit   int    `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 50)"`
}

// DecisionLogOutput is the output for the get_decision_log tool.
type DecisionLogOutput struct {
	Decisions []noteResult `json:"decisions"`
	Total     int          `json:"total"`
}

func (s *Server) getDecisionLog(ctx context.Context, _ *mcp.CallToolRequest, input DecisionLogInput) (*mcp.CallToolResult, DecisionLogOutput, error) {
	limit := clamp(input.Limit, 1, 50, 20)

	var filterCtx *string
	if input.Project != "" {
		filterCtx = &input.Project
	}

	notes, err := s.notes.NotesByType(ctx, "decision-log", filterCtx, limit)
	if err != nil {
		return nil, DecisionLogOutput{}, fmt.Errorf("querying decision log: %w", err)
	}

	out := DecisionLogOutput{
		Decisions: make([]noteResult, len(notes)),
		Total:     len(notes),
	}
	for i, n := range notes {
		out.Decisions[i] = toNoteResult(searchResultEntry{Note: n})
	}

	return nil, out, nil
}

// --- Phase 1 new tools ---

// RSSHighlightsInput is the input for the get_rss_highlights tool.
type RSSHighlightsInput struct {
	Days     int `json:"days,omitempty" jsonschema_description:"number of days to look back (default 7 max 30)"`
	MinScore int `json:"min_score,omitempty" jsonschema_description:"minimum AI score threshold 0-100 (default 70)"`
	Limit    int `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 50)"`
}

// RSSHighlightsOutput is the output for the get_rss_highlights tool.
type RSSHighlightsOutput struct {
	Items []rssItem `json:"items"`
	Total int       `json:"total"`
}

type rssItem struct {
	Title       string   `json:"title"`
	TitleZH     string   `json:"title_zh,omitempty"`
	SourceName  string   `json:"source_name"`
	URL         string   `json:"url"`
	AIScore     int      `json:"ai_score"`
	Summary     string   `json:"summary,omitempty"`
	SummaryZH   string   `json:"summary_zh,omitempty"`
	Topics      []string `json:"topics"`
	CollectedAt string   `json:"collected_at"`
}

func (s *Server) getRSSHighlights(ctx context.Context, _ *mcp.CallToolRequest, input RSSHighlightsInput) (*mcp.CallToolResult, RSSHighlightsOutput, error) {
	days := clamp(input.Days, 1, 30, 7)
	minScore := clamp(input.MinScore, 0, 100, 70)
	limit := clamp(input.Limit, 1, 50, 20)

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	data, err := s.collected.HighScoreCollectedData(ctx, start, now, int16(minScore)) // #nosec G115 -- minScore is clamped 0-100
	if err != nil {
		return nil, RSSHighlightsOutput{}, fmt.Errorf("querying rss highlights: %w", err)
	}

	if len(data) > limit {
		data = data[:limit]
	}

	items := make([]rssItem, len(data))
	for i, d := range data {
		item := rssItem{
			Title:       d.Title,
			SourceName:  d.SourceName,
			URL:         d.SourceURL,
			Topics:      d.Topics,
			CollectedAt: d.CollectedAt.Format(time.RFC3339),
		}
		if d.AIScore != nil {
			item.AIScore = int(*d.AIScore)
		}
		if d.AISummary != nil {
			item.Summary = *d.AISummary
		}
		if d.AISummaryZH != nil {
			item.SummaryZH = *d.AISummaryZH
		}
		if d.AITitleZH != nil {
			item.TitleZH = *d.AITitleZH
		}
		items[i] = item
	}

	return nil, RSSHighlightsOutput{Items: items, Total: len(items)}, nil
}

// PlatformStatsInput is the input for the get_platform_stats tool.
type PlatformStatsInput struct {
	IncludeDrift bool `json:"include_drift,omitempty" jsonschema_description:"include goal vs activity drift analysis (default true)"`
	DriftDays    int  `json:"drift_days,omitempty" jsonschema_description:"number of days for drift analysis (default 30 max 90)"`
}

// PlatformStatsOutput is the output for the get_platform_stats tool.
type PlatformStatsOutput struct {
	Overview interface{} `json:"overview"`
	Drift    interface{} `json:"drift,omitempty"`
}

func (s *Server) getPlatformStats(ctx context.Context, _ *mcp.CallToolRequest, input PlatformStatsInput) (*mcp.CallToolResult, PlatformStatsOutput, error) {
	overview, err := s.stats.Overview(ctx)
	if err != nil {
		return nil, PlatformStatsOutput{}, fmt.Errorf("querying platform stats: %w", err)
	}

	out := PlatformStatsOutput{Overview: overview}

	driftDays := clamp(input.DriftDays, 1, 90, 30)
	drift, err := s.stats.Drift(ctx, driftDays)
	if err != nil {
		s.logger.Error("querying drift report", "error", err)
		// best-effort: return overview without drift
	} else {
		out.Drift = drift
	}

	return nil, out, nil
}

// PendingTasksInput is the input for the get_pending_tasks tool.
type PendingTasksInput struct {
	Project string `json:"project,omitempty" jsonschema_description:"filter by project slug"`
	Limit   int    `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 100)"`
}

// PendingTasksOutput is the output for the get_pending_tasks tool.
type PendingTasksOutput struct {
	Tasks []taskResult `json:"tasks"`
	Total int          `json:"total"`
}

type taskResult struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Status       string `json:"status"`
	Due          string `json:"due,omitempty"`
	ProjectTitle string `json:"project_title,omitempty"`
	ProjectSlug  string `json:"project_slug,omitempty"`
	UpdatedAt    string `json:"updated_at"`
}

func (s *Server) getPendingTasks(ctx context.Context, _ *mcp.CallToolRequest, input PendingTasksInput) (*mcp.CallToolResult, PendingTasksOutput, error) {
	limit := clamp(input.Limit, 1, 100, 20)

	var projectSlug *string
	if input.Project != "" {
		projectSlug = &input.Project
	}

	tasks, err := s.tasks.PendingTasksWithProject(ctx, projectSlug, int32(limit)) // #nosec G115 -- limit is clamped 1-100
	if err != nil {
		return nil, PendingTasksOutput{}, fmt.Errorf("querying pending tasks: %w", err)
	}

	results := make([]taskResult, len(tasks))
	for i, t := range tasks {
		r := taskResult{
			ID:           t.ID.String(),
			Title:        t.Title,
			Status:       string(t.Status),
			ProjectTitle: t.ProjectTitle,
			ProjectSlug:  t.ProjectSlug,
			UpdatedAt:    t.UpdatedAt.Format(time.RFC3339),
		}
		if t.Due != nil {
			r.Due = t.Due.Format(time.DateOnly)
		}
		results[i] = r
	}

	return nil, PendingTasksOutput{Tasks: results, Total: len(results)}, nil
}

// SearchKnowledgeInput is the input for the search_knowledge tool.
type SearchKnowledgeInput struct {
	Query string `json:"query" jsonschema_description:"search query (required)"`
	Limit int    `json:"limit,omitempty" jsonschema_description:"max results (default 10 max 30)"`
}

// SearchKnowledgeOutput is the output for the search_knowledge tool.
type SearchKnowledgeOutput struct {
	Results []knowledgeResult `json:"results"`
	Total   int               `json:"total"`
}

type knowledgeResult struct {
	SourceType string   `json:"source_type"` // "content" or "note"
	Slug       string   `json:"slug,omitempty"`
	FilePath   string   `json:"file_path,omitempty"`
	Title      string   `json:"title"`
	Excerpt    string   `json:"excerpt"`
	Type       string   `json:"type,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func (s *Server) searchKnowledge(ctx context.Context, _ *mcp.CallToolRequest, input SearchKnowledgeInput) (*mcp.CallToolResult, SearchKnowledgeOutput, error) {
	if input.Query == "" {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("query is required")
	}
	if len(input.Query) > maxQueryLen {
		return nil, SearchKnowledgeOutput{}, fmt.Errorf("query too long (max %d characters)", maxQueryLen)
	}

	limit := clamp(input.Limit, 1, 30, 10)

	// Search content (articles, build logs, TILs) and notes concurrently.
	type contentResult struct {
		contents []content.Content
		err      error
	}
	type noteSearchResult struct {
		notes []note.SearchResult
		err   error
	}

	contentCh := make(chan contentResult, 1)
	noteCh := make(chan noteSearchResult, 1)

	go func() {
		contents, _, err := s.contents.Search(ctx, input.Query, 1, limit)
		contentCh <- contentResult{contents, err}
	}()

	go func() {
		notes, err := s.notes.SearchByText(ctx, input.Query, limit)
		noteCh <- noteSearchResult{notes, err}
	}()

	cr := <-contentCh
	nr := <-noteCh

	var results []knowledgeResult

	// Content results first (higher signal — published, structured content).
	if cr.err != nil {
		s.logger.Error("search_knowledge: content search failed", "error", cr.err)
	} else {
		for _, c := range cr.contents {
			excerpt := c.Excerpt
			if excerpt == "" {
				excerpt = truncate(c.Body, 300)
			}
			results = append(results, knowledgeResult{
				SourceType: "content",
				Slug:       c.Slug,
				Title:      c.Title,
				Excerpt:    excerpt,
				Type:       string(c.Type),
				Tags:       c.Tags,
			})
		}
	}

	// Note results second.
	if nr.err != nil {
		s.logger.Error("search_knowledge: note search failed", "error", nr.err)
	} else {
		for _, n := range nr.notes {
			results = append(results, knowledgeResult{
				SourceType: "note",
				FilePath:   n.FilePath,
				Title:      deref(n.Title),
				Excerpt:    truncate(deref(n.ContentText), 300),
				Type:       deref(n.Type),
				Tags:       n.Tags,
			})
		}
	}

	if len(results) > limit {
		results = results[:limit]
	}

	return nil, SearchKnowledgeOutput{Results: results, Total: len(results)}, nil
}

// ContentDetailInput is the input for the get_content_detail tool.
type ContentDetailInput struct {
	Slug string `json:"slug" jsonschema_description:"content slug (required)"`
}

// ContentDetailOutput is the output for the get_content_detail tool.
type ContentDetailOutput struct {
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Body        string   `json:"body"`
	Excerpt     string   `json:"excerpt"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	Tags        []string `json:"tags"`
	ReadingTime int      `json:"reading_time"`
	PublishedAt string   `json:"published_at,omitempty"`
	CreatedAt   string   `json:"created_at"`
}

func (s *Server) getContentDetail(ctx context.Context, _ *mcp.CallToolRequest, input ContentDetailInput) (*mcp.CallToolResult, ContentDetailOutput, error) {
	if input.Slug == "" {
		return nil, ContentDetailOutput{}, fmt.Errorf("slug is required")
	}

	c, err := s.contents.ContentBySlug(ctx, input.Slug)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			return nil, ContentDetailOutput{}, fmt.Errorf("content %q not found", input.Slug)
		}
		return nil, ContentDetailOutput{}, fmt.Errorf("querying content: %w", err)
	}

	out := ContentDetailOutput{
		Slug:        c.Slug,
		Title:       c.Title,
		Body:        c.Body,
		Excerpt:     c.Excerpt,
		Type:        string(c.Type),
		Status:      string(c.Status),
		Tags:        c.Tags,
		ReadingTime: c.ReadingTime,
		CreatedAt:   c.CreatedAt.Format(time.RFC3339),
	}
	if c.PublishedAt != nil {
		out.PublishedAt = c.PublishedAt.Format(time.RFC3339)
	}

	return nil, out, nil
}

// ListProjectsInput is the input for the list_projects tool.
type ListProjectsInput struct {
	Limit int `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 50)"`
}

// ListProjectsOutput is the output for the list_projects tool.
type ListProjectsOutput struct {
	Projects []projectSummary `json:"projects"`
	Total    int              `json:"total"`
}

func (s *Server) listProjects(ctx context.Context, _ *mcp.CallToolRequest, input ListProjectsInput) (*mcp.CallToolResult, ListProjectsOutput, error) {
	limit := clamp(input.Limit, 1, 50, 20)

	projects, err := s.projects.ActiveProjects(ctx)
	if err != nil {
		return nil, ListProjectsOutput{}, fmt.Errorf("querying active projects: %w", err)
	}

	if len(projects) > limit {
		projects = projects[:limit]
	}

	summaries := make([]projectSummary, len(projects))
	for i, p := range projects {
		summaries[i] = toProjectSummary(&p)
	}

	return nil, ListProjectsOutput{Projects: summaries, Total: len(summaries)}, nil
}

// GetGoalsInput is the input for the get_goals tool.
type GetGoalsInput struct {
	Area   string `json:"area,omitempty" jsonschema_description:"filter by area"`
	Status string `json:"status,omitempty" jsonschema_description:"filter by status (not-started in-progress done abandoned)"`
	Limit  int    `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 50)"`
}

// GetGoalsOutput is the output for the get_goals tool.
type GetGoalsOutput struct {
	Goals []goalResult `json:"goals"`
	Total int          `json:"total"`
}

type goalResult struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
	Area        string `json:"area,omitempty"`
	Quarter     string `json:"quarter,omitempty"`
	Deadline    string `json:"deadline,omitempty"`
}

func (s *Server) getGoals(ctx context.Context, _ *mcp.CallToolRequest, input GetGoalsInput) (*mcp.CallToolResult, GetGoalsOutput, error) {
	limit := clamp(input.Limit, 1, 50, 20)

	goals, err := s.goals.Goals(ctx)
	if err != nil {
		return nil, GetGoalsOutput{}, fmt.Errorf("querying goals: %w", err)
	}

	// Client-side filtering (goal store returns all, we filter here).
	var filtered []goalResult
	for _, g := range goals {
		if input.Area != "" && g.Area != input.Area {
			continue
		}
		if input.Status != "" && string(g.Status) != input.Status {
			continue
		}
		r := goalResult{
			Title:       g.Title,
			Description: g.Description,
			Status:      string(g.Status),
			Area:        g.Area,
			Quarter:     g.Quarter,
		}
		if g.Deadline != nil {
			r.Deadline = g.Deadline.Format(time.DateOnly)
		}
		filtered = append(filtered, r)
		if len(filtered) >= limit {
			break
		}
	}

	if filtered == nil {
		filtered = []goalResult{}
	}

	return nil, GetGoalsOutput{Goals: filtered, Total: len(filtered)}, nil
}

// LearningProgressInput is the input for the get_learning_progress tool.
type LearningProgressInput struct{}

// LearningProgressOutput is the output for the get_learning_progress tool.
type LearningProgressOutput struct {
	Spaced   interface{} `json:"spaced"`
	Notes    interface{} `json:"notes"`
	Activity interface{} `json:"activity"`
	TopTags  interface{} `json:"top_tags"`
}

func (s *Server) getLearningProgress(ctx context.Context, _ *mcp.CallToolRequest, _ LearningProgressInput) (*mcp.CallToolResult, LearningProgressOutput, error) {
	ld, err := s.stats.Learning(ctx)
	if err != nil {
		return nil, LearningProgressOutput{}, fmt.Errorf("querying learning progress: %w", err)
	}

	return nil, LearningProgressOutput{
		Spaced:   ld.Spaced,
		Notes:    ld.Notes,
		Activity: ld.Activity,
		TopTags:  ld.TopTags,
	}, nil
}

// --- helpers ---

func toSearchFilter(input SearchNotesInput) note.SearchFilter {
	var f note.SearchFilter
	if input.Type != "" {
		f.Type = &input.Type
	}
	if input.Source != "" {
		f.Source = &input.Source
	}
	if input.Context != "" {
		f.Context = &input.Context
	}
	if input.Book != "" {
		f.Book = &input.Book
	}
	return f
}

func toNoteResult(r searchResultEntry) noteResult {
	return noteResult{
		ID:       r.Note.ID,
		FilePath: r.Note.FilePath,
		Title:    deref(r.Note.Title),
		Type:     deref(r.Note.Type),
		Context:  deref(r.Note.Context),
		Source:   deref(r.Note.Source),
		Tags:     r.Note.Tags,
		Excerpt:  truncate(deref(r.Note.ContentText), 200),
		Score:    r.Score,
	}
}

func toProjectSummary(p *project.Project) projectSummary {
	return projectSummary{
		Slug:        p.Slug,
		Title:       p.Title,
		Description: p.Description,
		Role:        p.Role,
		TechStack:   p.TechStack,
		Status:      string(p.Status),
		Area:        p.Area,
		GithubURL:   deref(p.GithubURL),
		LiveURL:     deref(p.LiveURL),
	}
}

func eventToResult(e activity.Event) activityResult {
	return activityResult{
		ID:        e.ID,
		Timestamp: e.Timestamp.Format(time.RFC3339),
		EventType: e.EventType,
		Source:    e.Source,
		Title:     deref(e.Title),
		Repo:      deref(e.Repo),
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

func clamp(val, minVal, maxVal, defaultVal int) int {
	if val <= 0 {
		return defaultVal
	}
	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}
	return val
}
