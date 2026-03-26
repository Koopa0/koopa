package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/note"
	"github.com/koopa0/blog-backend/internal/task"
)

// --- Tool input/output types ---

// SearchNotesInput is the input for the search_notes tool.
type SearchNotesInput struct {
	Query   string `json:"query,omitempty" jsonschema_description:"free-text search query"`
	Type    string `json:"type,omitempty" jsonschema_description:"filter by note type (til|article|note|build-log|bookmark|essay|digest)"`
	Source  string `json:"source,omitempty" jsonschema_description:"filter by source (leetcode|book|course|discussion|practice|video)"`
	Context string `json:"context,omitempty" jsonschema_description:"filter by context (e.g. project name)"`
	Book    string `json:"book,omitempty" jsonschema_description:"filter by book name"`
	After   string `json:"after,omitempty" jsonschema_description:"only results after this date (YYYY-MM-DD)"`
	Before  string `json:"before,omitempty" jsonschema_description:"only results before this date (YYYY-MM-DD)"`
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
	hasFilters := input.Type != "" || input.Source != "" || input.Context != "" || input.Book != "" || input.After != "" || input.Before != ""

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

		filterResults, err := s.notes.SearchByFilters(ctx, toSearchFilter(&input), fetchLimit)
		if err != nil {
			return nil, SearchNotesOutput{}, fmt.Errorf("filter search: %w", err)
		}

		results = rrfMerge(textResults, filterResults, limit)
	case hasQuery:
		textResults, err := s.notes.SearchByText(ctx, input.Query, limit)
		if err != nil {
			return nil, SearchNotesOutput{}, fmt.Errorf("text search: %w", err)
		}
		results = toSearchEntries(textResults)
	default:
		filterResults, err := s.notes.SearchByFilters(ctx, toSearchFilter(&input), limit)
		if err != nil {
			return nil, SearchNotesOutput{}, fmt.Errorf("filter search: %w", err)
		}
		results = toFilterEntries(filterResults)
	}

	out := SearchNotesOutput{
		Results: make([]noteResult, len(results)),
		Total:   len(results),
	}
	for i := range results {
		out.Results[i] = toNoteResult(&results[i])
	}

	return nil, out, nil
}

// toSearchEntries converts text search results to the common searchResultEntry type.
func toSearchEntries(textResults []note.SearchResult) []searchResultEntry {
	entries := make([]searchResultEntry, len(textResults))
	for i := range textResults {
		entries[i] = searchResultEntry{Note: textResults[i].Note, Score: float64(textResults[i].Rank)}
	}
	return entries
}

// toFilterEntries converts filter search results to the common searchResultEntry type.
func toFilterEntries(filterResults []note.Note) []searchResultEntry {
	entries := make([]searchResultEntry, len(filterResults))
	for i := range filterResults {
		entries[i] = searchResultEntry{Note: filterResults[i]}
	}
	return entries
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
	PendingTasks   []taskResult     `json:"pending_tasks"`
	RelatedGoals   []goalBrief      `json:"related_goals"`
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

	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, ProjectContextOutput{}, err
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
		PendingTasks:   []taskResult{},
		RelatedGoals:   []goalBrief{},
	}
	for i := range events {
		out.RecentActivity[i] = eventToResult(&events[i])
	}
	for i := range relatedNotes {
		out.RelatedNotes[i] = toNoteResult(&searchResultEntry{Note: relatedNotes[i]})
	}

	// Pending tasks for this project
	pendingTasks, ptErr := s.tasks.PendingTasksWithProject(ctx, &proj.Slug, nil, 10)
	if ptErr != nil {
		s.logger.Error("project_context: pending tasks", "project", proj.Slug, "error", ptErr)
	} else {
		now := time.Now()
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		out.PendingTasks = make([]taskResult, len(pendingTasks))
		for i := range pendingTasks {
			out.PendingTasks[i] = toTaskResult(&pendingTasks[i], today)
		}
	}

	// Related goals (by goal_id FK)
	if proj.GoalID != nil {
		goals, goalsErr := s.goals.Goals(ctx)
		if goalsErr != nil {
			s.logger.Error("project_context: related goals", "error", goalsErr)
		} else {
			for i := range goals {
				g := &goals[i]
				if g.ID != *proj.GoalID {
					continue
				}
				gb := goalBrief{Title: g.Title, Status: string(g.Status), Area: g.Area}
				if g.Deadline != nil {
					gb.Deadline = g.Deadline.Format(time.DateOnly)
				}
				out.RelatedGoals = append(out.RelatedGoals, gb)
				break // goal_id is a unique FK; stop after first match
			}
		}
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
	for i := range events {
		e := &events[i]
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
	for i := range notes {
		n := notes[i]
		entry := searchResultEntry{Note: n}
		out.Decisions[i] = toNoteResult(&entry)
	}

	return nil, out, nil
}

// --- Phase 1 new tools ---

// RSSHighlightsInput is the input for the get_rss_highlights tool.
type RSSHighlightsInput struct {
	Days   int    `json:"days,omitempty" jsonschema_description:"number of days to look back (default 7 max 365)"`
	Limit  int    `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 100)"`
	SortBy string `json:"sort_by,omitempty" jsonschema_description:"sort order: relevance (default) or recency"`
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
	Excerpt     string   `json:"excerpt,omitempty"`
}

func (s *Server) getRSSHighlights(ctx context.Context, _ *mcp.CallToolRequest, input RSSHighlightsInput) (*mcp.CallToolResult, RSSHighlightsOutput, error) {
	days := clamp(input.Days, 1, 365, 7)
	limit := clamp(input.Limit, 1, 100, 20)

	var data []collected.Item
	var err error

	since := time.Now().AddDate(0, 0, -days)

	switch {
	case input.SortBy == "recency":
		data, err = s.collected.LatestByRecency(ctx, &since, int32(limit)) // #nosec G115 -- limit clamped
		if err == nil && len(data) == 0 {
			data, err = s.collected.LatestByRecency(ctx, nil, int32(limit)) // #nosec G115
		}
	default:
		data, err = s.collected.LatestCollectedData(ctx, &since, int32(limit)) // #nosec G115 -- limit clamped
		if err == nil && len(data) == 0 {
			data, err = s.collected.LatestCollectedData(ctx, nil, int32(limit)) // #nosec G115
		}
	}
	if err != nil {
		return nil, RSSHighlightsOutput{}, fmt.Errorf("querying rss highlights: %w", err)
	}

	items := make([]rssItem, len(data))
	for i := range data {
		items[i] = rssItem{
			Title:       data[i].Title,
			SourceName:  data[i].SourceName,
			URL:         data[i].SourceURL,
			Topics:      data[i].Topics,
			CollectedAt: data[i].CollectedAt.Format(time.RFC3339),
			Excerpt:     truncate(stripHTMLTags(deref(data[i].OriginalContent)), 200),
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
	Project  string `json:"project,omitempty" jsonschema_description:"filter by project slug, alias, or title"`
	Assignee string `json:"assignee,omitempty" jsonschema_description:"filter by assignee (human|claude-code|cowork)"`
	Limit    int    `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 100)"`
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

// toTaskResult converts a pending task to a taskResult with overdue-days calculation.
// today must be a date-only time (midnight, local timezone) for correct overdue math.
func toTaskResult(t *task.PendingTaskDetail, today time.Time) taskResult {
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
	return r
}

func (s *Server) getPendingTasks(ctx context.Context, _ *mcp.CallToolRequest, input PendingTasksInput) (*mcp.CallToolResult, PendingTasksOutput, error) {
	limit := clamp(input.Limit, 1, 100, 20)

	var projectSlug *string
	if input.Project != "" {
		proj, projErr := s.resolveProjectChain(ctx, input.Project)
		if projErr == nil {
			projectSlug = &proj.Slug
		} else {
			// Fallback: try as raw slug (backward compat)
			projectSlug = &input.Project
		}
	}

	var assignee *string
	if input.Assignee != "" {
		assignee = &input.Assignee
	}

	tasks, err := s.tasks.PendingTasksWithProject(ctx, projectSlug, assignee, int32(limit)) // #nosec G115 -- limit is clamped 1-100
	if err != nil {
		return nil, PendingTasksOutput{}, fmt.Errorf("querying pending tasks: %w", err)
	}

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	results := make([]taskResult, len(tasks))
	for i := range tasks {
		results[i] = toTaskResult(&tasks[i], today)
	}

	return nil, PendingTasksOutput{Tasks: results, Total: len(results)}, nil
}

// --- search_tasks ---

// SearchTasksInput is the input for the search_tasks tool.
type SearchTasksInput struct {
	Query           string `json:"query,omitempty" jsonschema_description:"search title and description (fuzzy match)"`
	Project         string `json:"project,omitempty" jsonschema_description:"filter by project slug, alias, or title"`
	Status          string `json:"status,omitempty" jsonschema_description:"pending|done|all (default: all)"`
	Assignee        string `json:"assignee,omitempty" jsonschema_description:"human|claude-code|cowork|all (default: all)"`
	CompletedAfter  string `json:"completed_after,omitempty" jsonschema_description:"ISO date YYYY-MM-DD"`
	CompletedBefore string `json:"completed_before,omitempty" jsonschema_description:"ISO date YYYY-MM-DD"`
	Limit           int    `json:"limit,omitempty" jsonschema_description:"max results (default 20 max 100)"`
}

// SearchTasksOutput is the output for the search_tasks tool.
type SearchTasksOutput struct {
	Tasks []searchTaskResult `json:"tasks"`
	Total int                `json:"total"`
}

type searchTaskResult struct {
	TaskID      string `json:"task_id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Due         string `json:"due,omitempty"`
	Project     string `json:"project,omitempty"`
	Energy      string `json:"energy,omitempty"`
	Priority    string `json:"priority,omitempty"`
	Assignee    string `json:"assignee"`
	IsRecurring bool   `json:"is_recurring"`
	MyDay       bool   `json:"my_day"`
	CompletedAt string `json:"completed_at,omitempty"`
	Description string `json:"description,omitempty"`
}

func (s *Server) searchTasks(ctx context.Context, _ *mcp.CallToolRequest, input SearchTasksInput) (*mcp.CallToolResult, SearchTasksOutput, error) {
	limit := clamp(input.Limit, 1, 100, 20)

	var query, projectSlug, statusFilter, assignee *string
	if input.Query != "" {
		query = &input.Query
	}
	if input.Project != "" {
		proj, projErr := s.resolveProjectChain(ctx, input.Project)
		if projErr == nil {
			projectSlug = &proj.Slug
		} else {
			projectSlug = &input.Project
		}
	}
	if input.Status != "" && input.Status != "all" {
		statusFilter = &input.Status
	}
	if input.Assignee != "" && input.Assignee != "all" {
		assignee = &input.Assignee
	}

	var completedAfter, completedBefore *time.Time
	if input.CompletedAfter != "" {
		if t, err := time.Parse(time.DateOnly, input.CompletedAfter); err == nil {
			completedAfter = &t
		}
	}
	if input.CompletedBefore != "" {
		if t, err := time.Parse(time.DateOnly, input.CompletedBefore); err == nil {
			end := t.AddDate(0, 0, 1)
			completedBefore = &end
		}
	}

	tasks, err := s.tasks.SearchTasks(ctx, query, projectSlug, statusFilter, assignee, completedAfter, completedBefore, int32(limit)) // #nosec G115 -- limit is clamped 1-100
	if err != nil {
		return nil, SearchTasksOutput{}, fmt.Errorf("searching tasks: %w", err)
	}

	results := make([]searchTaskResult, len(tasks))
	for i := range tasks {
		t := &tasks[i]
		r := searchTaskResult{
			TaskID:      t.ID.String(),
			Title:       t.Title,
			Status:      string(t.Status),
			Project:     t.ProjectTitle,
			Energy:      t.Energy,
			Priority:    t.Priority,
			Assignee:    t.Assignee,
			IsRecurring: t.RecurInterval != nil && *t.RecurInterval > 0,
			MyDay:       t.MyDay,
		}
		if t.Due != nil {
			r.Due = t.Due.Format(time.DateOnly)
		}
		if t.CompletedAt != nil {
			r.CompletedAt = t.CompletedAt.Format(time.RFC3339)
		}
		if t.Description != "" {
			r.Description = truncate(t.Description, 200)
		}
		results[i] = r
	}

	return nil, SearchTasksOutput{Tasks: results, Total: len(results)}, nil
}

// SearchKnowledgeInput is the input for the search_knowledge tool.
type SearchKnowledgeInput struct {
	Query       string `json:"query" jsonschema_description:"search query (required)"`
	Project     string `json:"project,omitempty" jsonschema_description:"filter results by project name, slug, or alias"`
	After       string `json:"after,omitempty" jsonschema_description:"only results after this date (YYYY-MM-DD)"`
	Before      string `json:"before,omitempty" jsonschema_description:"only results before this date (YYYY-MM-DD)"`
	ContentType string `json:"content_type,omitempty" jsonschema_description:"filter by content type (article|essay|build-log|til|note|bookmark|digest)"`
	Limit       int    `json:"limit,omitempty" jsonschema_description:"max results (default 10 max 30)"`
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

	// Resolve project filter for content FK matching and note context filtering
	var projectSlug string
	var projectID uuid.UUID
	if input.Project != "" {
		proj, projErr := s.resolveProjectChain(ctx, input.Project)
		if projErr == nil {
			projectSlug = proj.Slug
			projectID = proj.ID
		} else {
			projectSlug = input.Project // fallback to raw input
		}
	}

	// Parse date range filters
	var afterTime, beforeTime *time.Time
	if input.After != "" {
		if t, err := time.Parse(time.DateOnly, input.After); err == nil {
			afterTime = &t
		}
	}
	if input.Before != "" {
		if t, err := time.Parse(time.DateOnly, input.Before); err == nil {
			end := t.AddDate(0, 0, 1)
			beforeTime = &end
		}
	}

	// Parse content type filter
	var filterType content.Type
	if input.ContentType != "" {
		filterType = content.Type(input.ContentType)
	}

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

	var cr contentResult
	var nr noteSearchResult
	var sr semanticResult

	var wg sync.WaitGroup
	wg.Go(func() {
		// Internal search: no visibility filter so MCP can find private content.
		cr.contents, _, cr.err = s.contents.InternalSearch(ctx, input.Query, 1, limit)
		// AND→OR fallback: if AND search returns 0 results, try OR semantics
		if cr.err == nil && len(cr.contents) == 0 {
			cr.contents, _, cr.err = s.contents.InternalSearchOR(ctx, input.Query, 1, limit)
		}
	})
	wg.Go(func() {
		if projectSlug != "" {
			filterResults, filterErr := s.notes.SearchByFilters(ctx, note.SearchFilter{Context: &projectSlug, After: afterTime, Before: beforeTime}, limit*3)
			if filterErr != nil {
				nr.err = filterErr
				return
			}
			textResults, textErr := s.notes.SearchByText(ctx, input.Query, limit*3)
			if textErr != nil {
				nr.err = textErr
				return
			}
			merged := rrfMerge(textResults, filterResults, limit)
			nr.notes = make([]note.SearchResult, len(merged))
			for j := range merged {
				nr.notes[j] = note.SearchResult{Note: merged[j].Note, Rank: float32(merged[j].Score)}
			}
		} else {
			nr.notes, nr.err = s.notes.SearchByText(ctx, input.Query, limit)
		}
	})
	wg.Go(func() {
		if s.queryEmbedder == nil || s.semanticNotes == nil {
			return
		}
		vec, err := s.queryEmbedder.EmbedQuery(ctx, input.Query)
		if err != nil {
			sr.err = err
			return
		}
		sr.notes, sr.err = s.semanticNotes.SearchBySimilarity(ctx, vec, limit)
	})
	wg.Wait()

	var results []knowledgeResult

	// Content results first (higher signal — published, structured content).
	if cr.err != nil {
		s.logger.Error("search_knowledge: content search failed", "error", cr.err)
	}
	for i := range cr.contents {
		c := &cr.contents[i]
		// Project filter: check slug prefix or body frontmatter
		if projectSlug != "" && !contentMatchesProject(c, projectID, projectSlug) {
			continue
		}
		// Content type filter
		if filterType != "" && c.Type != filterType {
			continue
		}
		// Date range filter (use created_at for content)
		if afterTime != nil && c.CreatedAt.Before(*afterTime) {
			continue
		}
		if beforeTime != nil && !c.CreatedAt.Before(*beforeTime) {
			continue
		}
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

	// Note text search results second.
	seen := make(map[string]bool) // dedup by file_path across text and semantic results
	if nr.err != nil {
		s.logger.Error("search_knowledge: note search failed", "error", nr.err)
	}
	for i := range nr.notes {
		n := &nr.notes[i]
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

	// Semantic note results third (deduped against text results, project-filtered).
	if sr.err != nil {
		s.logger.Error("search_knowledge: semantic search failed", "error", sr.err)
	}
	for i := range sr.notes {
		n := &sr.notes[i]
		if seen[n.FilePath] {
			continue
		}
		if projectSlug != "" && (n.Context == nil || *n.Context != projectSlug) {
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
	for i := range projects {
		summaries[i] = toProjectSummary(&projects[i])
	}

	return nil, ListProjectsOutput{Projects: summaries, Total: len(summaries)}, nil
}

// LearningProgressInput is the input for the get_learning_progress tool.
type LearningProgressInput struct{}

// LearningProgressOutput is the output for the get_learning_progress tool.
type LearningProgressOutput struct {
	Notes    learningNotes    `json:"notes"`
	Activity learningActivity `json:"activity"`
	TopTags  []learningTag    `json:"top_tags"`
}

type learningNotes struct {
	Total     int            `json:"total"`
	LastWeek  int            `json:"last_week"`
	LastMonth int            `json:"last_month"`
	ByType    map[string]int `json:"by_type"`
}

type learningActivity struct {
	ThisWeek int    `json:"this_week"`
	LastWeek int    `json:"last_week"`
	Trend    string `json:"trend"`
}

type learningTag struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func (s *Server) getLearningProgress(ctx context.Context, _ *mcp.CallToolRequest, _ LearningProgressInput) (*mcp.CallToolResult, LearningProgressOutput, error) {
	ld, err := s.stats.Learning(ctx)
	if err != nil {
		return nil, LearningProgressOutput{}, fmt.Errorf("querying learning progress: %w", err)
	}

	tags := make([]learningTag, len(ld.TopTags))
	for i := range ld.TopTags {
		tags[i] = learningTag{Name: ld.TopTags[i].Name, Count: ld.TopTags[i].Count}
	}

	return nil, LearningProgressOutput{
		Notes: learningNotes{
			Total:     ld.Notes.Total,
			LastWeek:  ld.Notes.LastWeek,
			LastMonth: ld.Notes.LastMonth,
			ByType:    ld.Notes.ByType,
		},
		Activity: learningActivity{
			ThisWeek: ld.Activity.ThisWeek,
			LastWeek: ld.Activity.LastWeek,
			Trend:    ld.Activity.Trend,
		},
		TopTags: tags,
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

// sessionNoteResult uses map[string]any for Metadata (not json.RawMessage)
// because the MCP SDK infers json.RawMessage as []byte → array[integer] in
// the output schema, which fails validation against the actual JSON object.
type sessionNoteResult struct {
	ID        int64          `json:"id"`
	NoteDate  string         `json:"note_date"`
	NoteType  string         `json:"note_type"`
	Source    string         `json:"source"`
	Content   string         `json:"content"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt string         `json:"created_at"`
}

func (s *Server) getSessionNotes(ctx context.Context, _ *mcp.CallToolRequest, input GetSessionNotesInput) (*mcp.CallToolResult, GetSessionNotesOutput, error) {
	if s.sessions == nil {
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

	notes, err := s.sessions.NotesByDate(ctx, startDate, endDate, noteType)
	if err != nil {
		return nil, GetSessionNotesOutput{}, fmt.Errorf("querying session notes: %w", err)
	}

	results := make([]sessionNoteResult, len(notes))
	for i := range notes {
		n := &notes[i]
		var meta map[string]any
		if len(n.Metadata) > 0 {
			_ = json.Unmarshal(n.Metadata, &meta) // best-effort
		}
		results[i] = sessionNoteResult{
			ID:        n.ID,
			NoteDate:  n.NoteDate.Format(time.DateOnly),
			NoteType:  n.NoteType,
			Source:    n.Source,
			Content:   n.Content,
			Metadata:  meta,
			CreatedAt: n.CreatedAt.Format(time.RFC3339),
		}
	}

	return nil, GetSessionNotesOutput{Notes: results}, nil
}

// --- write tools ---

// DevSessionInput is the input for the log_dev_session tool.
type DevSessionInput struct {
	Project       string   `json:"project" jsonschema_description:"project name, slug, or alias (required)"`
	SessionType   string   `json:"session_type" jsonschema_description:"type of work: feature, refactor, bugfix, research, infra (required)"`
	Title         string   `json:"title" jsonschema_description:"short summary of what was done (required)"`
	Body          string   `json:"body" jsonschema_description:"markdown body with sections: what was done, decisions, problems solved, impact (required)"`
	Tags          []string `json:"tags,omitempty" jsonschema_description:"tags for categorization"`
	PlanSummary   string   `json:"plan_summary,omitempty" jsonschema_description:"summary of .claude/plans/<feature>.md — design goals, key decisions, implementation approach"`
	ReviewSummary string   `json:"review_summary,omitempty" jsonschema_description:"go-reviewer/review-code findings summary (e.g. critical:0 high:1 medium:3)"`
	Tier          string   `json:"tier,omitempty" jsonschema_description:"change tier: tier-1|tier-2|tier-3"`
	DiffStats     string   `json:"diff_stats,omitempty" jsonschema_description:"diff size (e.g. +120 -30)"`
}

// DevSessionOutput is the output of the log_dev_session tool.
type DevSessionOutput struct {
	ContentID string `json:"content_id"`
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Status    string `json:"status"`
}

func (s *Server) logDevSession(ctx context.Context, _ *mcp.CallToolRequest, input *DevSessionInput) (*mcp.CallToolResult, DevSessionOutput, error) {
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
	proj, err := s.resolveProjectChain(ctx, input.Project)
	if err != nil {
		return nil, DevSessionOutput{}, err
	}

	now := time.Now()
	slug := fmt.Sprintf("%s-dev-log-%s", proj.Slug, now.Format("2006-01-02"))
	source := fmt.Sprintf("claude-code:%s", input.SessionType)
	sourceType := content.SourceAIGenerated

	tags := ensureTag(input.Tags, input.SessionType)

	// Prepend metadata header so the frontend can parse project/session_type
	var bodyBuilder strings.Builder
	fmt.Fprintf(&bodyBuilder, "project: %s\nsession_type: %s\n", proj.Title, input.SessionType)
	if input.Tier != "" {
		fmt.Fprintf(&bodyBuilder, "tier: %s\n", input.Tier)
	}
	if input.DiffStats != "" {
		fmt.Fprintf(&bodyBuilder, "diff_stats: %s\n", input.DiffStats)
	}
	bodyBuilder.WriteString("\n")
	bodyBuilder.WriteString(input.Body)
	if input.PlanSummary != "" {
		fmt.Fprintf(&bodyBuilder, "\n\n## Plan Summary\n\n%s", input.PlanSummary)
	}
	if input.ReviewSummary != "" {
		fmt.Fprintf(&bodyBuilder, "\n\n## Review Summary\n\n%s", input.ReviewSummary)
	}
	body := bodyBuilder.String()

	params := &content.CreateParams{
		Slug:        slug,
		Title:       input.Title,
		Body:        body,
		Type:        content.TypeBuildLog,
		Status:      content.StatusPublished,
		Tags:        tags,
		Source:      &source,
		SourceType:  &sourceType,
		ReviewLevel: content.ReviewAuto,
		Visibility:  content.VisibilityPublic,
		ProjectID:   &proj.ID,
	}
	created, err := s.createContentWithRetry(ctx, params, fmt.Sprintf("%s-dev-log-%s", proj.Slug, now.Format("2006-01-02")), now)
	if err != nil {
		return nil, DevSessionOutput{}, fmt.Errorf("creating dev session log: %w", err)
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

func toSearchFilter(input *SearchNotesInput) note.SearchFilter {
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
	if input.After != "" {
		if t, err := time.Parse(time.DateOnly, input.After); err == nil {
			f.After = &t
		}
	}
	if input.Before != "" {
		if t, err := time.Parse(time.DateOnly, input.Before); err == nil {
			// End-of-day: shift to start of next day for < comparison
			end := t.AddDate(0, 0, 1)
			f.Before = &end
		}
	}
	return f
}

func toNoteResult(r *searchResultEntry) noteResult {
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
