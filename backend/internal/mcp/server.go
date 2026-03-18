package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/project"
)

// Server is the MCP server exposing read-only knowledge tools.
type Server struct {
	server   *mcp.Server
	notes    NoteSearcher
	activity ActivityReader
	projects ProjectReader
	logger   *slog.Logger
}

// NewServer creates an MCP server with all tools registered.
func NewServer(notes NoteSearcher, activity ActivityReader, projects ProjectReader, logger *slog.Logger) *Server {
	s := &Server{
		notes:    notes,
		activity: activity,
		projects: projects,
		logger:   logger,
	}

	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "koopa0-knowledge",
		Version: "v0.1.0",
	}, nil)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "search_notes",
		Description: "Search obsidian knowledge notes by text query and/or frontmatter filters. Uses full-text search with Reciprocal Rank Fusion when both text and filters are provided.",
	}, s.searchNotes)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_project_context",
		Description: "Get full context for a project by name, slug, or alias. Returns project details, recent activity, and related notes.",
	}, s.getProjectContext)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_recent_activity",
		Description: "Get recent development activity events, optionally filtered by source (github, obsidian, notion) or project name. Groups results by source.",
	}, s.getRecentActivity)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_decision_log",
		Description: "Retrieve decision-log notes, optionally filtered by project context.",
	}, s.getDecisionLog)

	return s
}

// Run starts the MCP server over stdio transport, blocking until the client disconnects.
func (s *Server) Run(ctx context.Context) error {
	return s.server.Run(ctx, &mcp.StdioTransport{})
}

// --- Tool input/output types ---

// SearchNotesInput is the input for the search_notes tool.
type SearchNotesInput struct {
	Query   string `json:"query,omitempty" jsonschema:"description=free-text search query"`
	Type    string `json:"type,omitempty" jsonschema:"description=filter by note type (e.g. til article note build-log)"`
	Source  string `json:"source,omitempty" jsonschema:"description=filter by source"`
	Context string `json:"context,omitempty" jsonschema:"description=filter by context (e.g. project name)"`
	Book    string `json:"book,omitempty" jsonschema:"description=filter by book name"`
	Limit   int    `json:"limit,omitempty" jsonschema:"description=max results (default 10 max 50)"`
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
		// RRF merge: run both searches with 3x limit, then merge.
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
	Project string `json:"project" jsonschema:"description=project name slug or alias (required)"`
}

// ProjectContextOutput is the output for the get_project_context tool.
type ProjectContextOutput struct {
	Project        projectSummary   `json:"project"`
	RecentActivity []activityResult `json:"recent_activity"`
	RelatedNotes   []noteResult     `json:"related_notes"`
}

// projectSummary is a safe subset of project.Project for MCP output.
// Omits NotionPageID and other internal fields.
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

	// Resolve project: try slug first, then alias.
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

	// Fetch recent activity by project title.
	events, err := s.activity.EventsByProject(ctx, proj.Title, 20)
	if err != nil {
		s.logger.Error("fetching project activity", "project", proj.Title, "error", err)
		events = nil // best-effort: missing activity does not fail the tool
	}

	// Fetch related notes by context.
	relatedNotes, err := s.notes.SearchByFilters(ctx, note.SearchFilter{Context: &proj.Title}, 10)
	if err != nil {
		s.logger.Error("fetching related notes", "project", proj.Title, "error", err)
		relatedNotes = nil // best-effort: missing notes does not fail the tool
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
	Days    int    `json:"days,omitempty" jsonschema:"description=number of days to look back (default 7 max 30)"`
	Source  string `json:"source,omitempty" jsonschema:"description=filter by source (e.g. github obsidian notion)"`
	Project string `json:"project,omitempty" jsonschema:"description=filter by project name"`
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

	// Group by source.
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
	Project string `json:"project,omitempty" jsonschema:"description=filter by project context"`
	Limit   int    `json:"limit,omitempty" jsonschema:"description=max results (default 20 max 50)"`
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
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
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
