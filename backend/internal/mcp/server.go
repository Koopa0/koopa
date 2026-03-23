package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/project"
)

// Server is the MCP server exposing knowledge tools.
type Server struct {
	server              *mcp.Server
	notes               NoteSearcher
	activity            ActivityReader
	projects            ProjectReader
	collected           CollectedReader
	collectedLatest     CollectedLatestReader
	stats               StatsReader
	tasks               TaskReader
	taskWriter          TaskWriter
	contents            ContentReader
	contentSearcher     ContentSearcher
	contentWriter       ContentWriter
	goals               GoalReader
	goalWriter          GoalWriter
	projectWriter       ProjectWriter
	notionTasks         NotionTaskWriter
	taskDBResolver      TaskDBIDResolver
	sessionReader       SessionNoteReader
	sessionWriter       SessionNoteWriter
	activityWriter      ActivityWriter
	collectedHighlights CollectedHighlightReader
	semanticNotes       NoteSemanticSearcher
	queryEmbedder       QueryEmbedder
	logger              *slog.Logger
}

// ServerOption configures optional Server dependencies.
type ServerOption func(*Server)

// WithNotionTaskWriter sets the Notion task writer for complete/create operations.
func WithNotionTaskWriter(n NotionTaskWriter, resolver TaskDBIDResolver) ServerOption {
	return func(s *Server) {
		s.notionTasks = n
		s.taskDBResolver = resolver
	}
}

// WithGoalWriter enables goal status update tools.
func WithGoalWriter(w GoalWriter) ServerOption {
	return func(s *Server) { s.goalWriter = w }
}

// WithProjectWriter enables project status update tools.
func WithProjectWriter(w ProjectWriter) ServerOption {
	return func(s *Server) { s.projectWriter = w }
}

// WithCollectedLatest enables time-optional collected data queries.
func WithCollectedLatest(r CollectedLatestReader) ServerOption {
	return func(s *Server) { s.collectedLatest = r }
}

// WithContentSearcher enables OR-fallback search.
func WithContentSearcher(cs ContentSearcher) ServerOption {
	return func(s *Server) { s.contentSearcher = cs }
}

// WithActivityWriter enables activity event recording for task completion audit trail.
func WithActivityWriter(w ActivityWriter) ServerOption {
	return func(s *Server) { s.activityWriter = w }
}

// WithCollectedHighlights enables RSS highlight summary in morning context.
func WithCollectedHighlights(r CollectedHighlightReader) ServerOption {
	return func(s *Server) { s.collectedHighlights = r }
}

// WithSemanticSearch enables embedding-based semantic search for notes.
func WithSemanticSearch(ns NoteSemanticSearcher, qe QueryEmbedder) ServerOption {
	return func(s *Server) {
		s.semanticNotes = ns
		s.queryEmbedder = qe
	}
}

// WithSessionNotes enables session note read/write tools.
func WithSessionNotes(r SessionNoteReader, w SessionNoteWriter) ServerOption {
	return func(s *Server) {
		s.sessionReader = r
		s.sessionWriter = w
	}
}

// NewServer creates an MCP server with all tools registered.
func NewServer(
	notes NoteSearcher,
	activity ActivityReader,
	projects ProjectReader,
	collected CollectedReader,
	stats StatsReader,
	tasks TaskReader,
	taskWriter TaskWriter,
	contents ContentReader,
	contentWriter ContentWriter,
	goals GoalReader,
	logger *slog.Logger,
	opts ...ServerOption,
) *Server {
	s := &Server{
		notes:         notes,
		activity:      activity,
		projects:      projects,
		collected:     collected,
		stats:         stats,
		tasks:         tasks,
		taskWriter:    taskWriter,
		contents:      contents,
		contentWriter: contentWriter,
		goals:         goals,
		logger:        logger,
	}
	for _, opt := range opts {
		opt(s)
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
		Description: "Get recently collected RSS articles from tracked feeds, ordered by most recent first. Use when the user asks about recent tech news, wants reading recommendations, or needs to know what's trending in their tracked topics.",
	}, s.getRSSHighlights)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_platform_stats",
		Description: "Get a full snapshot of the koopa0.dev knowledge engine: content counts, project stats, activity trends, goal alignment drift, and learning progress. Use when the user wants an overview of their system, asks 'how is everything going', or needs to assess platform health.",
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
		Description: "Get learning metrics: note growth trends, weekly activity comparison, and top knowledge tags. Use when the user asks about their learning progress, wants to know what topics they've been studying, or needs motivation data.",
	}, s.getLearningProgress)

	// --- write tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "log_dev_session",
		Description: "Log a development session as a build-log entry. Use at the end of a coding session or after completing a feature/bugfix/refactor/research milestone to record what was done, why, and what decisions were made. This creates a draft content record that the user can review and publish. The body should be in Markdown format with sections like: what was done, decisions made, problems solved, impact scope.",
	}, s.logDevSession)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "complete_task",
		Description: "Mark a task as done. Use when the user says they've finished something: 'done', 'completed', '做完了', '這題寫完了', 'OK next', or any phrase indicating task completion. Always confirm the specific task before calling. Returns next recurrence date for recurring tasks.",
	}, s.completeTask)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "create_task",
		Description: "Create a new task in Notion. Use during morning planning when the user confirms a suggested schedule, or when the user says 'add a task', 'remind me to', '幫我建一個任務'. Supports project linking, priority, energy level, and My Day assignment.",
	}, s.createTask)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_task",
		Description: "Update any task property — due date, priority, energy, project, My Day, or status. Use when the user says 'move this to tomorrow', 'change priority to high', '這個改成下週', 'put this on my day'. For marking tasks complete, prefer complete_task instead.",
	}, s.updateTask)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "batch_my_day",
		Description: "Set today's planned tasks on Notion My Day. Use at the end of morning planning after the user confirms the daily schedule. Optionally clears previous My Day selections first.",
	}, s.batchMyDay)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "log_learning_session",
		Description: "Record a learning outcome — LeetCode solution, book chapter insight, course concept, or discussion takeaway. Use after completing a learning discussion when the user gained new insight, finished a problem, or completed study material. Captures the knowledge for future retrieval via search_knowledge.",
	}, s.logLearningSession)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_project_status",
		Description: "Update a project's status during weekly or monthly review. Use when the user says 'put this project on hold', 'mark as done', '這個 project 暫停', or discusses project lifecycle changes. Supports optional review notes.",
	}, s.updateProjectStatus)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_goal_status",
		Description: "Update a goal's status. Use when the user says 'this goal is now active', 'achieved', '這個目標完成了', or discusses goal progress changes. Maps to Dream (not-started), Active (in-progress), Achieved (done), Abandoned.",
	}, s.updateGoalStatus)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_morning_context",
		Description: "Get everything needed for daily planning in one call: overdue tasks, today's tasks, recent activity summary, latest build logs, project health, active goals, yesterday's reflection, and planning history (completion rates). Use when the user starts their day with phrases like 'good morning', '早安', 'what should I work on today', '今天有什麼事', 'start planning'. This should be the FIRST tool called in a morning planning session.",
	}, s.getMorningContext)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_session_delta",
		Description: "Show what changed since the last Claude.ai session: tasks completed, tasks created, tasks that became overdue, build logs, insight changes, session notes, and metrics trend. Use when resuming after a gap, e.g. 'what happened since last time', '上次之後有什麼變化', 'catch me up'. Defaults to changes since the last claude session note.",
	}, s.getSessionDelta)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_weekly_summary",
		Description: "Get a comprehensive weekly summary: task completion by project, metrics trends, project health, insight activity, goal alignment, auto-generated highlights and concerns. Use for weekly reviews, '這週做了什麼', 'weekly review', 'how was this week'. Set weeks_back=1 for last week.",
	}, s.getWeeklySummary)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_goal_progress",
		Description: "Show progress toward each active goal: related projects, tasks completed in the lookback period, weekly task rate, and on-track assessment. Use when reviewing goals, '目標進度', 'goal check', 'am I on track'.",
	}, s.getGoalProgress)

	// --- session notes tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "save_session_note",
		Description: "Save a session note for cross-environment context sharing. Use during morning planning (type=plan, source=claude), development sessions (type=context, source=claude-code), evening reflection (type=reflection, source=claude), or metrics recording (type=metrics with metadata). This bridges context between claude.ai and Claude Code.",
	}, s.saveSessionNote)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_session_notes",
		Description: "Retrieve session notes for a date or date range, optionally filtered by type. Use when starting a development session to see today's plan, or when doing evening reflection to review the day. Types: plan, reflection, context, metrics, insight.",
	}, s.getSessionNotes)

	// --- insight tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_active_insights",
		Description: "Get tracked insights (pattern observations and hypotheses) from past sessions. Use during morning planning to see unverified hypotheses that can inform today's schedule, or during evening reflection to review which insights have been confirmed or invalidated. Default returns unverified insights; use status='all' for everything.",
	}, s.getActiveInsights)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_insight",
		Description: "Update an insight's status or append evidence. Use during evening reflection when today's data supports or contradicts a hypothesis — append evidence, or change status to 'verified'/'invalidated'. Use 'archived' to retire old insights.",
	}, s.updateInsight)

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
			if !errors.Is(err, project.ErrNotFound) {
				return nil, ProjectContextOutput{}, fmt.Errorf("querying project by alias: %w", err)
			}
			proj, err = s.projects.ProjectByTitle(ctx, input.Project)
			if err != nil {
				return nil, ProjectContextOutput{}, fmt.Errorf("project %q not found by slug, alias, or title", input.Project)
			}
		}
	}

	events, err := s.activity.EventsByProject(ctx, proj.Slug, 20)
	if err != nil {
		s.logger.Error("fetching project activity", "project", proj.Slug, "error", err)
		events = nil
	}

	relatedNotes, err := s.notes.SearchByFilters(ctx, note.SearchFilter{Context: &proj.Slug}, 10)
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
	Days  int `json:"days,omitempty" jsonschema_description:"number of days to look back (default 7 max 365)"`
	Limit int `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 100)"`
}

// RSSHighlightsOutput is the output for the get_rss_highlights tool.
type RSSHighlightsOutput struct {
	Items []rssItem `json:"items"`
	Total int       `json:"total"`
}

type rssItem struct {
	Title       string   `json:"title"`
	SourceName  string   `json:"source_name"`
	URL         string   `json:"url"`
	Topics      []string `json:"topics"`
	CollectedAt string   `json:"collected_at"`
}

func (s *Server) getRSSHighlights(ctx context.Context, _ *mcp.CallToolRequest, input RSSHighlightsInput) (*mcp.CallToolResult, RSSHighlightsOutput, error) {
	days := clamp(input.Days, 1, 365, 7)
	limit := clamp(input.Limit, 1, 100, 20)

	// Prefer LatestCollectedData (no mandatory time constraint) if available.
	// Falls back to RecentCollectedData with time range if not.
	var data []collected.CollectedData
	var err error

	if s.collectedLatest != nil {
		since := time.Now().AddDate(0, 0, -days)
		data, err = s.collectedLatest.LatestCollectedData(ctx, &since, int32(limit)) // #nosec G115 -- limit clamped
		// If time-filtered query returns nothing, retry without time constraint
		if err == nil && len(data) == 0 {
			data, err = s.collectedLatest.LatestCollectedData(ctx, nil, int32(limit)) // #nosec G115
		}
	} else {
		now := time.Now()
		start := now.AddDate(0, 0, -days)
		data, err = s.collected.RecentCollectedData(ctx, start, now, int32(limit)) // #nosec G115
	}
	if err != nil {
		return nil, RSSHighlightsOutput{}, fmt.Errorf("querying rss highlights: %w", err)
	}

	items := make([]rssItem, len(data))
	for i, d := range data {
		items[i] = rssItem{
			Title:       d.Title,
			SourceName:  d.SourceName,
			URL:         d.SourceURL,
			Topics:      d.Topics,
			CollectedAt: d.CollectedAt.Format(time.RFC3339),
		}
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
	Overview map[string]any `json:"overview"`
	Drift    map[string]any `json:"drift,omitempty"`
}

func (s *Server) getPlatformStats(ctx context.Context, _ *mcp.CallToolRequest, input PlatformStatsInput) (*mcp.CallToolResult, PlatformStatsOutput, error) {
	overview, err := s.stats.Overview(ctx)
	if err != nil {
		return nil, PlatformStatsOutput{}, fmt.Errorf("querying platform stats: %w", err)
	}

	out := PlatformStatsOutput{Overview: toMapAny(overview)}

	driftDays := clamp(input.DriftDays, 1, 90, 30)
	drift, err := s.stats.Drift(ctx, driftDays)
	if err != nil {
		s.logger.Error("querying drift report", "error", err)
		// best-effort: return overview without drift
	} else {
		out.Drift = toMapAny(drift)
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
	Energy       string `json:"energy,omitempty"`
	Priority     string `json:"priority,omitempty"`
	IsRecurring  bool   `json:"is_recurring"`
	OverdueDays  int    `json:"overdue_days,omitempty"`
	MyDay        bool   `json:"my_day"`
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

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	results := make([]taskResult, len(tasks))
	for i, t := range tasks {
		r := taskResult{
			ID:           t.ID.String(),
			Title:        t.Title,
			Status:       string(t.Status),
			ProjectTitle: t.ProjectTitle,
			ProjectSlug:  t.ProjectSlug,
			Energy:       t.Energy,
			Priority:     t.Priority,
			IsRecurring:  t.RecurInterval != nil && *t.RecurInterval > 0,
			MyDay:        t.MyDay,
			UpdatedAt:    t.UpdatedAt.Format(time.RFC3339),
		}
		if t.Due != nil {
			r.Due = t.Due.Format(time.DateOnly)
			dueDate := time.Date(t.Due.Year(), t.Due.Month(), t.Due.Day(), 0, 0, 0, 0, t.Due.Location())
			if dueDate.Before(today) {
				r.OverdueDays = int(today.Sub(dueDate).Hours() / 24)
			}
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

	// Search content, notes (text), and notes (semantic) concurrently.
	type contentResult struct {
		contents []content.Content
		err      error
	}
	type noteSearchResult struct {
		notes []note.SearchResult
		err   error
	}
	type semanticResult struct {
		notes []note.SimilarityResult
		err   error
	}

	contentCh := make(chan contentResult, 1)
	noteCh := make(chan noteSearchResult, 1)
	semanticCh := make(chan semanticResult, 1)

	go func() {
		contents, _, err := s.contents.Search(ctx, input.Query, 1, limit)
		// AND→OR fallback: if AND search returns 0 results, try OR semantics
		if err == nil && len(contents) == 0 && s.contentSearcher != nil {
			contents, _, err = s.contentSearcher.SearchOR(ctx, input.Query, 1, limit)
		}
		contentCh <- contentResult{contents, err}
	}()

	go func() {
		notes, err := s.notes.SearchByText(ctx, input.Query, limit)
		noteCh <- noteSearchResult{notes, err}
	}()

	go func() {
		if s.queryEmbedder == nil || s.semanticNotes == nil {
			semanticCh <- semanticResult{}
			return
		}
		vec, err := s.queryEmbedder.EmbedQuery(ctx, input.Query)
		if err != nil {
			semanticCh <- semanticResult{err: err}
			return
		}
		notes, err := s.semanticNotes.SearchBySimilarity(ctx, vec, limit)
		semanticCh <- semanticResult{notes, err}
	}()

	cr := <-contentCh
	nr := <-noteCh
	sr := <-semanticCh

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

	// Note text search results second.
	seen := make(map[string]bool) // dedup by file_path across text and semantic results
	if nr.err != nil {
		s.logger.Error("search_knowledge: note search failed", "error", nr.err)
	} else {
		for _, n := range nr.notes {
			seen[n.FilePath] = true
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

	// Semantic note results third (deduped against text results).
	if sr.err != nil {
		s.logger.Error("search_knowledge: semantic search failed", "error", sr.err)
	} else {
		for _, n := range sr.notes {
			if seen[n.FilePath] {
				continue
			}
			seen[n.FilePath] = true
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
	Notes    map[string]any `json:"notes"`
	Activity map[string]any `json:"activity"`
	TopTags  map[string]any `json:"top_tags"`
}

func (s *Server) getLearningProgress(ctx context.Context, _ *mcp.CallToolRequest, _ LearningProgressInput) (*mcp.CallToolResult, LearningProgressOutput, error) {
	ld, err := s.stats.Learning(ctx)
	if err != nil {
		return nil, LearningProgressOutput{}, fmt.Errorf("querying learning progress: %w", err)
	}

	return nil, LearningProgressOutput{
		Notes:    toMapAny(ld.Notes),
		Activity: toMapAny(ld.Activity),
		TopTags:  toMapAny(ld.TopTags),
	}, nil
}

// --- session notes (read) ---

// GetSessionNotesInput is the input for the get_session_notes tool.
type GetSessionNotesInput struct {
	Date     string `json:"date,omitempty" jsonschema_description:"ISO date YYYY-MM-DD (default today)"`
	NoteType string `json:"note_type,omitempty" jsonschema_description:"filter by type: plan, reflection, context, metrics, insight"`
	Days     int    `json:"days,omitempty" jsonschema_description:"number of days to look back (default 1, max 30)"`
}

// GetSessionNotesOutput is the output of the get_session_notes tool.
type GetSessionNotesOutput struct {
	Notes []sessionNoteResult `json:"notes"`
}

type sessionNoteResult struct {
	ID        int64           `json:"id"`
	NoteDate  string          `json:"note_date"`
	NoteType  string          `json:"note_type"`
	Source    string          `json:"source"`
	Content   string          `json:"content"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt string          `json:"created_at"`
}

func (s *Server) getSessionNotes(ctx context.Context, _ *mcp.CallToolRequest, input GetSessionNotesInput) (*mcp.CallToolResult, GetSessionNotesOutput, error) {
	if s.sessionReader == nil {
		return nil, GetSessionNotesOutput{}, fmt.Errorf("session notes not configured")
	}

	days := clamp(input.Days, 1, 30, 1)

	now := time.Now().UTC()
	endDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if input.Date != "" {
		parsed, err := time.Parse(time.DateOnly, input.Date)
		if err != nil {
			return nil, GetSessionNotesOutput{}, fmt.Errorf("invalid date %q (expected YYYY-MM-DD)", input.Date)
		}
		endDate = parsed
	}
	startDate := endDate.AddDate(0, 0, -(days - 1))

	var noteType *string
	if input.NoteType != "" {
		switch input.NoteType {
		case "plan", "reflection", "context", "metrics", "insight":
			noteType = &input.NoteType
		default:
			return nil, GetSessionNotesOutput{}, fmt.Errorf("invalid note_type %q (must be plan, reflection, context, metrics, or insight)", input.NoteType)
		}
	}

	notes, err := s.sessionReader.NotesByDate(ctx, startDate, endDate, noteType)
	if err != nil {
		return nil, GetSessionNotesOutput{}, fmt.Errorf("querying session notes: %w", err)
	}

	results := make([]sessionNoteResult, len(notes))
	for i, n := range notes {
		results[i] = sessionNoteResult{
			ID:        n.ID,
			NoteDate:  n.NoteDate.Format(time.DateOnly),
			NoteType:  n.NoteType,
			Source:    n.Source,
			Content:   n.Content,
			Metadata:  n.Metadata,
			CreatedAt: n.CreatedAt.Format(time.RFC3339),
		}
	}

	return nil, GetSessionNotesOutput{Notes: results}, nil
}

// --- write tools ---

// DevSessionInput is the input for the log_dev_session tool.
type DevSessionInput struct {
	Project     string   `json:"project" jsonschema_description:"project name, slug, or alias (required)"`
	SessionType string   `json:"session_type" jsonschema_description:"type of work: feature, refactor, bugfix, research, infra (required)"`
	Title       string   `json:"title" jsonschema_description:"short summary of what was done (required)"`
	Body        string   `json:"body" jsonschema_description:"markdown body with sections: what was done, decisions, problems solved, impact (required)"`
	Tags        []string `json:"tags,omitempty" jsonschema_description:"tags for categorization"`
}

// DevSessionOutput is the output of the log_dev_session tool.
type DevSessionOutput struct {
	ContentID string `json:"content_id"`
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Status    string `json:"status"`
}

func (s *Server) logDevSession(ctx context.Context, _ *mcp.CallToolRequest, input DevSessionInput) (*mcp.CallToolResult, DevSessionOutput, error) {
	if input.Project == "" {
		return nil, DevSessionOutput{}, fmt.Errorf("project is required")
	}
	if input.Title == "" {
		return nil, DevSessionOutput{}, fmt.Errorf("title is required")
	}
	if input.Body == "" {
		return nil, DevSessionOutput{}, fmt.Errorf("body is required")
	}
	if input.SessionType == "" {
		input.SessionType = "feature"
	}

	validTypes := map[string]bool{
		"feature": true, "refactor": true, "bugfix": true,
		"research": true, "infra": true,
	}
	if !validTypes[input.SessionType] {
		return nil, DevSessionOutput{}, fmt.Errorf("invalid session_type %q (must be feature, refactor, bugfix, research, or infra)", input.SessionType)
	}

	// Resolve project (slug → alias → title)
	proj, err := s.projects.ProjectBySlug(ctx, input.Project)
	if err != nil {
		if !errors.Is(err, project.ErrNotFound) {
			return nil, DevSessionOutput{}, fmt.Errorf("querying project: %w", err)
		}
		proj, err = s.projects.ProjectByAlias(ctx, input.Project)
		if err != nil {
			if !errors.Is(err, project.ErrNotFound) {
				return nil, DevSessionOutput{}, fmt.Errorf("querying project by alias: %w", err)
			}
			proj, err = s.projects.ProjectByTitle(ctx, input.Project)
			if err != nil {
				return nil, DevSessionOutput{}, fmt.Errorf("project %q not found", input.Project)
			}
		}
	}

	now := time.Now()
	slug := fmt.Sprintf("%s-dev-log-%s", proj.Slug, now.Format("2006-01-02"))
	source := fmt.Sprintf("claude-code:%s", input.SessionType)
	sourceType := content.SourceAIGenerated

	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}
	// Ensure session_type is in tags
	hasType := false
	for _, t := range tags {
		if t == input.SessionType {
			hasType = true
			break
		}
	}
	if !hasType {
		tags = append(tags, input.SessionType)
	}

	// Prepend metadata header so the frontend can parse project/session_type
	body := fmt.Sprintf("project: %s\nsession_type: %s\n\n%s", proj.Title, input.SessionType, input.Body)

	created, err := s.contentWriter.CreateContent(ctx, content.CreateParams{
		Slug:        slug,
		Title:       input.Title,
		Body:        body,
		Type:        content.TypeBuildLog,
		Status:      content.StatusPublished,
		Tags:        tags,
		Source:      &source,
		SourceType:  &sourceType,
		ReviewLevel: content.ReviewAuto,
	})
	if err != nil {
		if errors.Is(err, content.ErrConflict) {
			// Slug conflict: append timestamp to make unique
			slug = fmt.Sprintf("%s-dev-log-%s-%d", proj.Slug, now.Format("2006-01-02"), now.Unix()%10000)
			created, err = s.contentWriter.CreateContent(ctx, content.CreateParams{
				Slug:        slug,
				Title:       input.Title,
				Body:        body,
				Type:        content.TypeBuildLog,
				Status:      content.StatusPublished,
				Tags:        tags,
				Source:      &source,
				SourceType:  &sourceType,
				ReviewLevel: content.ReviewAuto,
			})
			if err != nil {
				return nil, DevSessionOutput{}, fmt.Errorf("creating dev session log: %w", err)
			}
		} else {
			return nil, DevSessionOutput{}, fmt.Errorf("creating dev session log: %w", err)
		}
	}

	s.logger.Info("dev session logged",
		"project", proj.Title,
		"content_id", created.ID,
		"session_type", input.SessionType,
		"title", input.Title,
	)

	return nil, DevSessionOutput{
		ContentID: created.ID.String(),
		Slug:      created.Slug,
		Title:     created.Title,
		Status:    string(created.Status),
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

// extractFrontmatter extracts a value from loose frontmatter lines like "key: value".
// Returns empty string if the key is not found — safe for bodies without frontmatter.
func extractFrontmatter(body, key string) string {
	for _, line := range strings.SplitN(body, "\n", 20) {
		line = strings.TrimSpace(line)
		if line == "" || line == "---" {
			continue
		}
		// Stop at first markdown heading — past frontmatter zone
		if len(line) > 0 && line[0] == '#' {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// toMapAny converts any struct/map to map[string]any via JSON round-trip.
// This avoids jsonschema generating bare "true" (from interface{}) or
// ["null","array"] (from json.RawMessage) for dynamic output fields.
func toMapAny(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
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
