package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/project"
	"github.com/koopa0/blog-backend/internal/session"
	"github.com/koopa0/blog-backend/internal/task"
)

// Server is the MCP server exposing knowledge tools.
type Server struct {
	server          *mcp.Server
	notes           NoteSearcher
	activity        ActivityReader
	projects        ProjectReader
	collected       *collected.Store
	stats           StatsReader
	tasks           *task.Store
	contents        *content.Store
	goals           GoalReader
	goalWriter      GoalWriter
	projectWriter   ProjectWriter
	notionTasks     NotionTaskWriter
	taskDBResolver  TaskDBIDResolver
	sessions        *session.Store
	activityWriter  ActivityWriter
	semanticNotes   NoteSemanticSearcher
	queryEmbedder   QueryEmbedder
	feeds           *feed.Store
	oreilly         *OReillyClient
	systemStatus    SystemStatusReader
	pipelineTrigger PipelineTrigger
	flowInvoker     FlowInvoker
	recordToolCall  func(name string, d time.Duration, isErr bool) // optional telemetry
	lastTrigger     map[string]time.Time                           // rate limit: pipeline name -> last trigger time
	triggerMu       sync.Mutex                                     // protects lastTrigger
	logger          *slog.Logger
	loc             *time.Location // user timezone for day boundaries
}

// ServerOption configures optional Server dependencies.
type ServerOption func(*Server)

// WithFeedStore enables feed management tools.
func WithFeedStore(fs *feed.Store) ServerOption {
	return func(s *Server) { s.feeds = fs }
}

// WithNotionTaskWriter sets the Notion task writer for complete/create operations.
func WithNotionTaskWriter(n NotionTaskWriter, resolver TaskDBIDResolver) ServerOption {
	return func(s *Server) {
		s.notionTasks = n
		s.taskDBResolver = resolver
	}
}

// WithLocation sets the user timezone for day boundary calculations.
func WithLocation(loc *time.Location) ServerOption {
	return func(s *Server) { s.loc = loc }
}

// WithGoalWriter enables goal status update tools.
func WithGoalWriter(w GoalWriter) ServerOption {
	return func(s *Server) { s.goalWriter = w }
}

// WithProjectWriter enables project status update tools.
func WithProjectWriter(w ProjectWriter) ServerOption {
	return func(s *Server) { s.projectWriter = w }
}

// WithActivityWriter enables activity event recording for task completion audit trail.
func WithActivityWriter(w ActivityWriter) ServerOption {
	return func(s *Server) { s.activityWriter = w }
}

// WithSemanticSearch enables embedding-based semantic search for notes.
func WithSemanticSearch(ns NoteSemanticSearcher, qe QueryEmbedder) ServerOption {
	return func(s *Server) {
		s.semanticNotes = ns
		s.queryEmbedder = qe
	}
}

// WithOReilly enables O'Reilly content search tools.
func WithOReilly(client *OReillyClient) ServerOption {
	return func(s *Server) { s.oreilly = client }
}

// WithSystemStatus enables the get_system_status tool.
func WithSystemStatus(r SystemStatusReader) ServerOption {
	return func(s *Server) { s.systemStatus = r }
}

// WithPipelineTrigger enables the trigger_pipeline tool.
func WithPipelineTrigger(t PipelineTrigger) ServerOption {
	return func(s *Server) {
		s.pipelineTrigger = t
		s.lastTrigger = make(map[string]time.Time)
	}
}

// WithFlowInvoker enables AI flow invocation tools (polish, strategy).
func WithFlowInvoker(f FlowInvoker) ServerOption {
	return func(s *Server) { s.flowInvoker = f }
}

// WithTelemetry enables async tool call logging for convergence analysis.
// The recorder is called in a goroutine after each tool call completes.
func WithTelemetry(recorder func(name string, d time.Duration, isErr bool)) ServerOption {
	return func(s *Server) { s.recordToolCall = recorder }
}

// NewServer creates an MCP server with all tools registered.
func NewServer(
	notes NoteSearcher,
	activityReader ActivityReader,
	projects ProjectReader,
	collectedStore *collected.Store,
	stats StatsReader,
	tasks *task.Store,
	contents *content.Store,
	sessions *session.Store,
	goals GoalReader,
	logger *slog.Logger,
	opts ...ServerOption,
) *Server {
	s := &Server{
		notes:     notes,
		activity:  activityReader,
		projects:  projects,
		collected: collectedStore,
		stats:     stats,
		tasks:     tasks,
		contents:  contents,
		sessions:  sessions,
		goals:     goals,
		logger:    logger,
		loc:       time.UTC, // default; override with WithLocation
	}
	for _, opt := range opts {
		opt(s)
	}

	s.server = mcp.NewServer(&mcp.Implementation{
		Name:    "koopa0-knowledge",
		Version: "v0.2.0",
	}, nil)

	// Tool annotation presets.
	f := false
	readOnly := &mcp.ToolAnnotations{
		ReadOnlyHint:  true,
		OpenWorldHint: &f,
	}
	readOnlyOpenWorld := &mcp.ToolAnnotations{
		ReadOnlyHint: true,
	}
	additive := &mcp.ToolAnnotations{
		DestructiveHint: &f,
		OpenWorldHint:   &f,
	}
	additiveIdempotent := &mcp.ToolAnnotations{
		DestructiveHint: &f,
		IdempotentHint:  true,
		OpenWorldHint:   &f,
	}
	mutating := &mcp.ToolAnnotations{
		OpenWorldHint: &f,
	}

	// --- read-only tools ---

	addTool(s, &mcp.Tool{
		Name:        "search_notes",
		Description: "Search obsidian knowledge notes by text query and/or frontmatter filters. Filters: type (til|article|note|build-log|bookmark|essay|digest), source (leetcode|book|course|discussion|practice|video), context (project name), book (book title). Uses full-text search with Reciprocal Rank Fusion when both text and filters are provided. Use this when you know the content is an Obsidian note. For broader searches across all content types, use search_knowledge instead. Example: search_notes(query=\"binary search\", type=\"til\", context=\"leetcode-prep\")",
		Annotations: readOnly,
	}, s.searchNotes)

	addTool(s, &mcp.Tool{
		Name:        "get_project_context",
		Description: "Get full context for a single project by name, slug, or alias. Returns project details, recent activity, and related notes. Use list_projects first if you need to see all projects.",
		Annotations: readOnly,
	}, s.getProjectContext)

	addTool(s, &mcp.Tool{
		Name:        "get_recent_activity",
		Description: "Get recent development activity events, optionally filtered by source (github, obsidian, notion) or project name. Groups results by source. Use when the user asks what they've been working on, wants a summary of recent progress, or needs to understand time allocation.",
		Annotations: readOnly,
	}, s.getRecentActivity)

	addTool(s, &mcp.Tool{
		Name:        "get_decision_log",
		Description: "Retrieve decision-log notes, optionally filtered by project context. Use when looking for past architectural decisions, design rationale, or 'why did we choose X' questions.",
		Annotations: readOnly,
	}, s.getDecisionLog)

	// --- new Phase 1 tools ---

	addTool(s, &mcp.Tool{
		Name:        "get_rss_highlights",
		Description: "Get recently collected RSS articles from tracked feeds, ordered by most recent first. Use when the user asks about recent tech news, wants reading recommendations, or needs to know what's trending in their tracked topics.",
		Annotations: readOnly,
	}, s.getRSSHighlights)

	addTool(s, &mcp.Tool{
		Name:        "get_platform_stats",
		Description: "Get a full snapshot of the koopa0.dev knowledge engine: content counts, project stats, activity trends, goal alignment drift, and learning progress. Use when the user wants an overview of their system, asks 'how is everything going', or needs to assess platform health.",
		Annotations: readOnly,
	}, s.getPlatformStats)

	addTool(s, &mcp.Tool{
		Name:        "get_pending_tasks",
		Description: "Get pending (not-done) tasks sorted by urgency. Filters: project (slug/alias/title), assignee (human|claude-code|cowork). Use when the user asks what to work on, needs to plan their day, or wants to see overdue items.",
		Annotations: readOnly,
	}, s.getPendingTasks)

	addTool(s, &mcp.Tool{
		Name:        "search_tasks",
		Description: "Search tasks by title/description with filters. Filters: query (fuzzy match title+description), project (slug/alias/title), status (pending|done|all, default: all), assignee (human|claude-code|cowork|all), completed_after/completed_before (YYYY-MM-DD). Use when looking for specific tasks, checking completed work, or finding tasks across projects. Example: search_tasks(query=\"refactor\", status=\"done\", completed_after=\"2026-03-01\")",
		Annotations: readOnly,
	}, s.searchTasks)

	addTool(s, &mcp.Tool{
		Name:        "search_knowledge",
		Description: "Search across ALL content types: articles, build logs, TILs, notes, and Obsidian notes. Returns excerpts with source type markers. Filters: project (slug/alias/title), after/before (YYYY-MM-DD date range), content_type (article|essay|build-log|til|note|bookmark|digest). All filters are optional and combinable. Use when the user asks 'have I written about X before', needs to find past insights, or wants to search without knowing which content type contains the answer. Example: search_knowledge(query=\"pagination\", after=\"2026-03-18\", content_type=\"til\")",
		Annotations: readOnly,
	}, s.searchKnowledge)

	addTool(s, &mcp.Tool{
		Name:        "get_content_detail",
		Description: "Get the full content of an article, build log, TIL, or note by slug. Returns complete body text, tags, topics, and metadata. Use after search_knowledge to read the full content of a specific result.",
		Annotations: readOnly,
	}, s.getContentDetail)

	addTool(s, &mcp.Tool{
		Name:        "list_projects",
		Description: "List all active projects with status, area, tech stack, and URLs. Use when the user wants to see all their projects at a glance, needs to pick which project to work on, or asks about project health. For deep context on a single project, follow up with get_project_context.",
		Annotations: readOnly,
	}, s.listProjects)

	addTool(s, &mcp.Tool{
		Name:        "get_learning_progress",
		Description: "Get learning metrics: note growth trends, weekly activity comparison, and top knowledge tags. Use when the user asks about their learning progress, wants to know what topics they've been studying, or needs motivation data.",
		Annotations: readOnly,
	}, s.getLearningProgress)

	// --- write tools ---

	addTool(s, &mcp.Tool{
		Name:        "log_dev_session",
		Description: "Log a development session as a build-log entry. Use at the end of a coding session. Required: project, session_type (feature|refactor|bugfix|research|infra), title, body (markdown). Optional: plan_summary (from .claude/plans/), review_summary (reviewer findings), tier (tier-1|tier-2|tier-3), diff_stats (+N -N). plan_summary and review_summary bridge context to Claude Web for weekly review.",
		Annotations: additive,
	}, s.logDevSession)

	addTool(s, &mcp.Tool{
		Name:        "complete_task",
		Description: "Mark a task as done. Use when the user says they've finished something: 'done', 'completed', '做完了', '這題寫完了', 'OK next', or any phrase indicating task completion. Always confirm the specific task before calling. Returns next recurrence date for recurring tasks.",
		Annotations: mutating,
	}, s.completeTask)

	addTool(s, &mcp.Tool{
		Name:        "create_task",
		Description: "Create a new task in Notion. Fields: title (required), project (slug/alias/title), due (YYYY-MM-DD), priority (Low|Medium|High), energy (Low|High), my_day (bool), notes (description text). Use during morning planning or when the user says 'add a task', 'remind me to', '幫我建一個任務'. Example: create_task(title=\"Review PR\", project=\"koopa0.dev\", due=\"2026-03-26\", priority=\"High\", energy=\"High\", my_day=true)",
		Annotations: additive,
	}, s.createTask)

	addTool(s, &mcp.Tool{
		Name:        "update_task",
		Description: "Update any task property. Fields: new_title (string), due (YYYY-MM-DD), priority (Low|Medium|High), energy (Low|High), project (slug/alias/title), my_day (bool), status (To Do|Doing|Done), notes (appended to description). Identify task by task_id (UUID) or task_title (fuzzy match). Use when the user says 'move this to tomorrow', 'change priority to high', '這個改成下週', 'put this on my day'. For marking tasks complete, prefer complete_task instead. Example: update_task(task_title=\"Weekly LeetCode\", due=\"2026-04-01\", priority=\"High\")",
		Annotations: mutating,
	}, s.updateTask)

	addTool(s, &mcp.Tool{
		Name:        "batch_my_day",
		Description: "Set today's planned tasks on Notion My Day. Use at the end of morning planning after the user confirms the daily schedule. Optionally clears previous My Day selections first.",
		Annotations: additiveIdempotent,
	}, s.batchMyDay)

	addTool(s, &mcp.Tool{
		Name:        "log_learning_session",
		Description: "Record a learning outcome — LeetCode solution, book chapter insight, course concept, or discussion takeaway. Tags use a controlled vocabulary: topic tags (array, string, hash-table, two-pointers, sliding-window, binary-search, stack, queue, linked-list, tree, binary-tree, bst, graph, bfs, dfs, heap, trie, union-find, dp, greedy, backtracking, bit-manipulation, math, matrix, interval, topological-sort, sorting, design, simulation, prefix-sum, divide-and-conquer, segment-tree, binary-indexed-tree), result (ac-independent, ac-with-hints, ac-after-solution, incomplete), weakness:xxx, improvement:xxx. Difficulty: easy, medium, hard.",
		Annotations: additive,
	}, s.logLearningSession)

	addTool(s, &mcp.Tool{
		Name:        "update_project_status",
		Description: "Update a project's status during weekly or monthly review. Use when the user says 'put this project on hold', 'mark as done', '這個 project 暫停', or discusses project lifecycle changes. Supports optional review notes.",
		Annotations: mutating,
	}, s.updateProjectStatus)

	addTool(s, &mcp.Tool{
		Name:        "update_goal_status",
		Description: "Update a goal's status. Valid statuses: not-started (Dream), in-progress (Active), done (Achieved), abandoned. Use when the user says 'this goal is now active', 'achieved', '這個目標完成了', or discusses goal progress changes. Example: update_goal_status(goal=\"學好英文\", status=\"in-progress\")",
		Annotations: mutating,
	}, s.updateGoalStatus)

	addTool(s, &mcp.Tool{
		Name:        "get_morning_context",
		Description: "Get everything needed for daily planning in one call: overdue tasks, today's tasks, recent activity summary, latest build logs, project health, active goals, yesterday's reflection, and planning history (completion rates). Use when the user starts their day with phrases like 'good morning', '早安', 'what should I work on today', '今天有什麼事', 'start planning'. This should be the FIRST tool called in a morning planning session. Optional sections parameter limits response to specific sections: tasks, activity, build_logs, projects, goals, insights, reflection, planning_history, rss, plan, completions. Omit sections to get all.",
		Annotations: readOnly,
	}, s.getMorningContext)

	addTool(s, &mcp.Tool{
		Name:        "get_session_delta",
		Description: "Show what changed since the last Claude.ai session: tasks completed, tasks created, tasks that became overdue, build logs, insight changes, session notes, and metrics trend. Use when resuming after a gap, e.g. 'what happened since last time', '上次之後有什麼變化', 'catch me up'. Defaults to changes since the last claude session note.",
		Annotations: readOnly,
	}, s.getSessionDelta)

	addTool(s, &mcp.Tool{
		Name:        "get_weekly_summary",
		Description: "Get a comprehensive weekly summary: task completion by project, metrics trends, project health, insight activity, goal alignment, auto-generated highlights and concerns. Use for weekly reviews, '這週做了什麼', 'weekly review', 'how was this week'. Set weeks_back=1 for last week.",
		Annotations: readOnly,
	}, s.getWeeklySummary)

	addTool(s, &mcp.Tool{
		Name:        "get_goal_progress",
		Description: "Show progress toward each active goal: related projects, tasks completed in the lookback period, weekly task rate, and on-track assessment. Supports optional area and status filters. Use when reviewing goals, '目標進度', 'goal check', 'am I on track', or to list goals with filtering (replaces get_goals).",
		Annotations: readOnly,
	}, s.getGoalProgress)

	// --- session notes tools ---

	addTool(s, &mcp.Tool{
		Name:        "save_session_note",
		Description: "Save a session note for cross-environment context sharing. note_type: plan|reflection|context|metrics|insight. source: claude|claude-code|manual. Required metadata by type — insight: {hypothesis (string), invalidation_condition (string)}; plan: {committed_task_ids (array), reasoning (string)}; metrics: {tasks_planned (int), tasks_completed (int), adjustments (array)}; context and reflection: no required metadata. Example: save_session_note(note_type=\"insight\", source=\"claude\", content=\"...\", metadata={hypothesis: \"...\", invalidation_condition: \"...\"})",
		Annotations: additive,
	}, s.saveSessionNote)

	addTool(s, &mcp.Tool{
		Name:        "get_session_notes",
		Description: "Retrieve session notes for a date or date range, optionally filtered by note_type (plan|reflection|context|metrics|insight). Set days (1-30, default 1) for lookback range. Use when starting a development session to see today's plan, or when doing evening reflection to review the day. Example: get_session_notes(note_type=\"plan\", days=7)",
		Annotations: readOnly,
	}, s.getSessionNotes)

	// --- reflection tool ---

	addTool(s, &mcp.Tool{
		Name:        "get_reflection_context",
		Description: "Get everything needed for evening reflection in one call: today's plan vs actual completions, My Day task status, daily summary metrics, unverified insights for review, planning history, and yesterday's adjustments. Use when doing evening reflection, '今天做了什麼', 'reflection time', 'how did today go'. This is the evening counterpart to get_morning_context.",
		Annotations: readOnly,
	}, s.getReflectionContext)

	// --- insight tools ---

	addTool(s, &mcp.Tool{
		Name:        "get_active_insights",
		Description: "Get tracked insights (pattern observations and hypotheses) from past sessions. Use during morning planning to see unverified hypotheses that can inform today's schedule, or during evening reflection to review which insights have been confirmed or invalidated. Default returns unverified insights; use status='all' for everything.",
		Annotations: readOnly,
	}, s.getActiveInsights)

	addTool(s, &mcp.Tool{
		Name:        "update_insight",
		Description: "Update an insight's status or append evidence. Use during evening reflection when today's data supports or contradicts a hypothesis — append evidence, or change status to 'verified'/'invalidated'. Use 'archived' to retire old insights.",
		Annotations: mutating,
	}, s.updateInsight)

	// --- O'Reilly tools ---

	if s.oreilly != nil {
		addTool(s, &mcp.Tool{
			Name:        "search_oreilly_content",
			Description: "Search O'Reilly Learning for books, videos, articles, courses, and other content. Use when the user asks for learning resources, book recommendations, wants to find technical content on a topic, or says 'find me a book about X'. Supports filtering by format (book, video, article, course), publisher, and author.",
			Annotations: readOnlyOpenWorld,
		}, s.searchOReillyContent)

		addTool(s, &mcp.Tool{
			Name:        "get_oreilly_book_detail",
			Description: "Get book metadata and full table of contents from O'Reilly Learning. Use after search_oreilly_content to see a book's chapters and structure before reading. Returns chapter titles, filenames (for read_oreilly_chapter), estimated reading time, and section headings.",
			Annotations: readOnlyOpenWorld,
		}, s.getOReillyBookDetail)

		addTool(s, &mcp.Tool{
			Name:        "read_oreilly_chapter",
			Description: "Read the full text content of an O'Reilly book chapter. Use after get_oreilly_book_detail to read specific chapters. Requires archive_id and filename (from book detail chapters list). Returns plain text content stripped of HTML formatting.",
			Annotations: readOnlyOpenWorld,
		}, s.readOReillyChapter)
	}

	addTool(s, &mcp.Tool{
		Name:        "curate_collected_item",
		Description: "Curate an RSS article into the knowledge base as a bookmark. Creates a content record (type=bookmark, status=draft) and links it back to the collected item. The bookmark will be processed by the content-review pipeline (generating embedding, excerpt, tags). Use when a high-value article should be preserved for future search_knowledge retrieval.",
		Annotations: additive,
	}, s.curateCollectedItem)

	// --- Sprint 3 content management tools ---

	addTool(s, &mcp.Tool{
		Name:        "manage_content",
		Description: "Manage content records. Actions: create (title+body+content_type required, returns content_id+slug), update (content_id required, updates provided fields), publish (content_id required, sets status to published). Use when creating articles, build logs, TILs, or other content types. For dev session logs, prefer log_dev_session instead.",
		Annotations: mutating,
	}, s.manageContent)

	addTool(s, &mcp.Tool{
		Name:        "get_content_pipeline",
		Description: "View the content pipeline: drafts awaiting work, review queue, recently published, and scheduled content. Views: queue (draft+review items), calendar (published last 7 days + scheduled drafts), recent (published content). Use when checking what content needs attention, reviewing publishing cadence, or planning what to write next.",
		Annotations: readOnly,
	}, s.getContentPipeline)

	// --- Sprint 2 tools ---

	if s.feeds != nil {
		addTool(s, &mcp.Tool{
			Name:        "manage_feeds",
			Description: "Manage RSS/Atom feed sources. Actions: list (all feeds with status), add (url+name required, schedule defaults to daily), disable/enable/remove (feed_id required). Use when the user wants to add a new feed source, check feed health, or manage existing subscriptions.",
			Annotations: mutating,
		}, s.manageFeeds)
	}

	addTool(s, &mcp.Tool{
		Name:        "get_collection_stats",
		Description: "Get collection pipeline statistics: per-feed item counts, average relevance scores, last collection timestamps, and global totals. Optionally filter by feed_id and lookback period (days, default 30, max 90). Use when checking feed health, collection pipeline performance, or diagnosing why certain feeds aren't producing results.",
		Annotations: readOnly,
	}, s.getCollectionStats)

	if s.systemStatus != nil {
		addTool(s, &mcp.Tool{
			Name:        "get_system_status",
			Description: "Get system observability: flow run stats, feed health, pipeline summaries, and recent flow runs. Scopes: summary (flow stats + feed health), pipelines (per-flow-name aggregation), flows (recent individual flow runs). Use when checking system health, diagnosing pipeline failures, or monitoring background jobs.",
			Annotations: readOnly,
		}, s.getSystemStatus)
	}

	if s.pipelineTrigger != nil {
		addTool(s, &mcp.Tool{
			Name:        "trigger_pipeline",
			Description: "Manually trigger a background pipeline. Valid pipelines: rss_collector (fetch all enabled RSS feeds), notion_sync (sync all Notion pages). Rate limited to once per 5 minutes per pipeline. Use when the user wants to force a feed collection or Notion sync outside the regular schedule.",
			Annotations: mutating,
		}, s.triggerPipeline)
	}

	// --- Sprint 3: AI flow tools ---

	if s.flowInvoker != nil {
		addTool(s, &mcp.Tool{
			Name:        "invoke_content_polish",
			Description: "Polish a draft content using AI. Improves writing quality, fixes grammar, enhances readability. Input: content_id (required). Returns polished version of the content body.",
			Annotations: mutating,
		}, s.invokeContentPolish)

		addTool(s, &mcp.Tool{
			Name:        "invoke_content_strategy",
			Description: "Get AI-powered content topic suggestions based on existing content, RSS trends, and Koopa's positioning as a Go backend consultant. Returns suggested topics with rationale.",
			Annotations: readOnly,
		}, s.invokeContentStrategy)
	}

	addTool(s, &mcp.Tool{
		Name:        "generate_social_excerpt",
		Description: "Generate a social media excerpt from published content. Platforms: linkedin (150-300 words, professional), twitter (280 chars, concise). Returns excerpt, hook, CTA, and hashtags.",
		Annotations: readOnly,
	}, s.generateSocialExcerpt)

	// --- Sprint 4: Knowledge synthesis ---

	addTool(s, &mcp.Tool{
		Name:        "synthesize_topic",
		Description: "Synthesize knowledge across ALL content sources for a topic. Searches articles, build logs, TILs, Obsidian notes, and RSS bookmarks, then produces a structured synthesis grouped by source type. Includes gap analysis showing which sub-topics lack coverage. HIGH TOKEN COST — this tool searches broadly and generates a long synthesis. Use when preparing discovery calls, writing topic overviews, or analyzing knowledge coverage. Example: synthesize_topic(query=\"PostgreSQL connection pooling\")",
		Annotations: readOnly,
	}, s.synthesizeTopic)

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

func eventToResult(e *activity.Event) activityResult {
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
		if line != "" && line[0] == '#' {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// contentMatchesProject checks if a content item belongs to a project.
// Priority: project_id FK > tag match > slug prefix > body frontmatter.
func contentMatchesProject(c *content.Content, projectID uuid.UUID, projectSlug string) bool {
	if c.ProjectID != nil && *c.ProjectID == projectID {
		return true
	}
	slugLower := strings.ToLower(projectSlug)
	for _, t := range c.Tags {
		if strings.ToLower(t) == slugLower {
			return true
		}
	}
	if strings.HasPrefix(c.Slug, projectSlug) {
		return true
	}
	if p := extractFrontmatter(c.Body, "project"); p != "" {
		return strings.EqualFold(p, projectSlug) || strings.Contains(strings.ToLower(p), slugLower)
	}
	return false
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

// stripHTMLTags removes HTML tags and collapses whitespace for plain-text excerpts.
func stripHTMLTags(s string) string {
	clean := htmlTagRe.ReplaceAllString(s, " ")
	return strings.Join(strings.Fields(clean), " ")
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

// resolveProjectChain resolves a project by slug, alias, or title (in that order).
// It distinguishes between "not found" and other errors.
func (s *Server) resolveProjectChain(ctx context.Context, input string) (*project.Project, error) {
	proj, err := s.projects.ProjectBySlug(ctx, input)
	if err == nil {
		return proj, nil
	}
	if !errors.Is(err, project.ErrNotFound) {
		return nil, fmt.Errorf("querying project: %w", err)
	}

	proj, err = s.projects.ProjectByAlias(ctx, input)
	if err == nil {
		return proj, nil
	}
	if !errors.Is(err, project.ErrNotFound) {
		return nil, fmt.Errorf("querying project by alias: %w", err)
	}

	proj, err = s.projects.ProjectByTitle(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("project %q not found", input)
	}
	return proj, nil
}

// createContentWithRetry creates content, retrying once with a timestamped slug on conflict.
func (s *Server) createContentWithRetry(ctx context.Context, params *content.CreateParams, baseSlug string, now time.Time) (*content.Content, error) {
	created, err := s.contents.CreateContent(ctx, params)
	if err == nil {
		return created, nil
	}
	if !errors.Is(err, content.ErrConflict) {
		return nil, err
	}
	// Slug conflict: append timestamp to make unique
	params.Slug = fmt.Sprintf("%s-%d", baseSlug, now.Unix()%10000)
	return s.contents.CreateContent(ctx, params)
}

// addTool registers a tool with optional telemetry wrapping.
// When s.recordToolCall is set, each tool call records name, duration, and error status.
func addTool[I, O any](s *Server, tool *mcp.Tool, handler func(context.Context, *mcp.CallToolRequest, I) (*mcp.CallToolResult, O, error)) {
	if s.recordToolCall == nil {
		mcp.AddTool(s.server, tool, handler)
		return
	}
	record := s.recordToolCall
	name := tool.Name
	mcp.AddTool(s.server, tool, func(ctx context.Context, req *mcp.CallToolRequest, input I) (*mcp.CallToolResult, O, error) {
		start := time.Now()
		result, output, err := handler(ctx, req, input)
		go record(name, time.Since(start), err != nil)
		return result, output, err
	})
}
