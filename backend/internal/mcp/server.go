package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/koopa0/blog-backend/internal/activity"
	"github.com/koopa0/blog-backend/internal/collected"
	"github.com/koopa0/blog-backend/internal/content"
	"github.com/koopa0/blog-backend/internal/feed"
	"github.com/koopa0/blog-backend/internal/note"
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
	taskWriter      TaskWriter
	contents        *content.Store
	contentWriter   ContentWriter
	goals           GoalReader
	goalWriter      GoalWriter
	projectWriter   ProjectWriter
	notionTasks     NotionTaskWriter
	taskDBResolver  TaskDBIDResolver
	sessionReader   *session.Store
	sessionWriter   SessionNoteWriter
	activityWriter  ActivityWriter
	semanticNotes   NoteSemanticSearcher
	queryEmbedder   QueryEmbedder
	feeds           *feed.Store
	oreilly         *OReillyClient
	systemStatus    SystemStatusReader
	pipelineTrigger PipelineTrigger
	flowInvoker     FlowInvoker
	lastTrigger     map[string]time.Time // rate limit: pipeline name -> last trigger time
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

// WithSessionNotes enables session note read/write tools.
func WithSessionNotes(r *session.Store, w SessionNoteWriter) ServerOption {
	return func(s *Server) {
		s.sessionReader = r
		s.sessionWriter = w
	}
}

// NewServer creates an MCP server with all tools registered.
func NewServer(
	notes NoteSearcher,
	activityReader ActivityReader,
	projects ProjectReader,
	collectedStore *collected.Store,
	stats StatsReader,
	tasks *task.Store,
	taskWriter TaskWriter,
	contents *content.Store,
	contentWriter ContentWriter,
	goals GoalReader,
	logger *slog.Logger,
	opts ...ServerOption,
) *Server {
	s := &Server{
		notes:         notes,
		activity:      activityReader,
		projects:      projects,
		collected:     collectedStore,
		stats:         stats,
		tasks:         tasks,
		taskWriter:    taskWriter,
		contents:      contents,
		contentWriter: contentWriter,
		goals:         goals,
		logger:        logger,
		loc:           time.UTC, // default; override with WithLocation
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

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "search_notes",
		Description: "Search obsidian knowledge notes by text query and/or frontmatter filters. Filters: type (til|article|note|build-log|bookmark|essay|digest), source (leetcode|book|course|discussion|practice|video), context (project name), book (book title). Uses full-text search with Reciprocal Rank Fusion when both text and filters are provided. Use this when you know the content is an Obsidian note. For broader searches across all content types, use search_knowledge instead. Example: search_notes(query=\"binary search\", type=\"til\", context=\"leetcode-prep\")",
		Annotations: readOnly,
	}, s.searchNotes)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_project_context",
		Description: "Get full context for a single project by name, slug, or alias. Returns project details, recent activity, and related notes. Use list_projects first if you need to see all projects.",
		Annotations: readOnly,
	}, s.getProjectContext)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_recent_activity",
		Description: "Get recent development activity events, optionally filtered by source (github, obsidian, notion) or project name. Groups results by source. Use when the user asks what they've been working on, wants a summary of recent progress, or needs to understand time allocation.",
		Annotations: readOnly,
	}, s.getRecentActivity)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_decision_log",
		Description: "Retrieve decision-log notes, optionally filtered by project context. Use when looking for past architectural decisions, design rationale, or 'why did we choose X' questions.",
		Annotations: readOnly,
	}, s.getDecisionLog)

	// --- new Phase 1 tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_rss_highlights",
		Description: "Get recently collected RSS articles from tracked feeds, ordered by most recent first. Use when the user asks about recent tech news, wants reading recommendations, or needs to know what's trending in their tracked topics.",
		Annotations: readOnly,
	}, s.getRSSHighlights)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_platform_stats",
		Description: "Get a full snapshot of the koopa0.dev knowledge engine: content counts, project stats, activity trends, goal alignment drift, and learning progress. Use when the user wants an overview of their system, asks 'how is everything going', or needs to assess platform health.",
		Annotations: readOnly,
	}, s.getPlatformStats)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_pending_tasks",
		Description: "Get pending (not-done) tasks sorted by urgency. Filters: project (slug/alias/title), assignee (human|claude-code|cowork). Use when the user asks what to work on, needs to plan their day, or wants to see overdue items.",
		Annotations: readOnly,
	}, s.getPendingTasks)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "search_tasks",
		Description: "Search tasks by title/description with filters. Filters: query (fuzzy match title+description), project (slug/alias/title), status (pending|done|all, default: all), assignee (human|claude-code|cowork|all), completed_after/completed_before (YYYY-MM-DD). Use when looking for specific tasks, checking completed work, or finding tasks across projects. Example: search_tasks(query=\"refactor\", status=\"done\", completed_after=\"2026-03-01\")",
		Annotations: readOnly,
	}, s.searchTasks)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "search_knowledge",
		Description: "Search across ALL content types: articles, build logs, TILs, notes, and Obsidian notes. Returns excerpts with source type markers. Filters: project (slug/alias/title), after/before (YYYY-MM-DD date range), content_type (article|essay|build-log|til|note|bookmark|digest). All filters are optional and combinable. Use when the user asks 'have I written about X before', needs to find past insights, or wants to search without knowing which content type contains the answer. Example: search_knowledge(query=\"pagination\", after=\"2026-03-18\", content_type=\"til\")",
		Annotations: readOnly,
	}, s.searchKnowledge)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_content_detail",
		Description: "Get the full content of an article, build log, TIL, or note by slug. Returns complete body text, tags, topics, and metadata. Use after search_knowledge to read the full content of a specific result.",
		Annotations: readOnly,
	}, s.getContentDetail)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "list_projects",
		Description: "List all active projects with status, area, tech stack, and URLs. Use when the user wants to see all their projects at a glance, needs to pick which project to work on, or asks about project health. For deep context on a single project, follow up with get_project_context.",
		Annotations: readOnly,
	}, s.listProjects)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_learning_progress",
		Description: "Get learning metrics: note growth trends, weekly activity comparison, and top knowledge tags. Use when the user asks about their learning progress, wants to know what topics they've been studying, or needs motivation data.",
		Annotations: readOnly,
	}, s.getLearningProgress)

	// --- write tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "log_dev_session",
		Description: "Log a development session as a build-log entry. Use at the end of a coding session. Required: project, session_type (feature|refactor|bugfix|research|infra), title, body (markdown). Optional: plan_summary (from .claude/plans/), review_summary (reviewer findings), tier (tier-1|tier-2|tier-3), diff_stats (+N -N). plan_summary and review_summary bridge context to Claude Web for weekly review.",
		Annotations: additive,
	}, s.logDevSession)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "complete_task",
		Description: "Mark a task as done. Use when the user says they've finished something: 'done', 'completed', '做完了', '這題寫完了', 'OK next', or any phrase indicating task completion. Always confirm the specific task before calling. Returns next recurrence date for recurring tasks.",
		Annotations: mutating,
	}, s.completeTask)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "create_task",
		Description: "Create a new task in Notion. Fields: title (required), project (slug/alias/title), due (YYYY-MM-DD), priority (Low|Medium|High), energy (Low|High), my_day (bool), notes (description text). Use during morning planning or when the user says 'add a task', 'remind me to', '幫我建一個任務'. Example: create_task(title=\"Review PR\", project=\"koopa0.dev\", due=\"2026-03-26\", priority=\"High\", energy=\"High\", my_day=true)",
		Annotations: additive,
	}, s.createTask)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_task",
		Description: "Update any task property. Fields: new_title (string), due (YYYY-MM-DD), priority (Low|Medium|High), energy (Low|High), project (slug/alias/title), my_day (bool), status (To Do|Doing|Done), notes (appended to description). Identify task by task_id (UUID) or task_title (fuzzy match). Use when the user says 'move this to tomorrow', 'change priority to high', '這個改成下週', 'put this on my day'. For marking tasks complete, prefer complete_task instead. Example: update_task(task_title=\"Weekly LeetCode\", due=\"2026-04-01\", priority=\"High\")",
		Annotations: mutating,
	}, s.updateTask)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "batch_my_day",
		Description: "Set today's planned tasks on Notion My Day. Use at the end of morning planning after the user confirms the daily schedule. Optionally clears previous My Day selections first.",
		Annotations: additiveIdempotent,
	}, s.batchMyDay)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "log_learning_session",
		Description: "Record a learning outcome — LeetCode solution, book chapter insight, course concept, or discussion takeaway. Tags use a controlled vocabulary: topic tags (array, string, hash-table, two-pointers, sliding-window, binary-search, stack, queue, linked-list, tree, binary-tree, bst, graph, bfs, dfs, heap, trie, union-find, dp, greedy, backtracking, bit-manipulation, math, matrix, interval, topological-sort, sorting, design, simulation, prefix-sum, divide-and-conquer, segment-tree, binary-indexed-tree), result (ac-independent, ac-with-hints, ac-after-solution, incomplete), weakness:xxx, improvement:xxx. Difficulty: easy, medium, hard.",
		Annotations: additive,
	}, s.logLearningSession)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_project_status",
		Description: "Update a project's status during weekly or monthly review. Use when the user says 'put this project on hold', 'mark as done', '這個 project 暫停', or discusses project lifecycle changes. Supports optional review notes.",
		Annotations: mutating,
	}, s.updateProjectStatus)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_goal_status",
		Description: "Update a goal's status. Valid statuses: not-started (Dream), in-progress (Active), done (Achieved), abandoned. Use when the user says 'this goal is now active', 'achieved', '這個目標完成了', or discusses goal progress changes. Example: update_goal_status(goal=\"學好英文\", status=\"in-progress\")",
		Annotations: mutating,
	}, s.updateGoalStatus)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_morning_context",
		Description: "Get everything needed for daily planning in one call: overdue tasks, today's tasks, recent activity summary, latest build logs, project health, active goals, yesterday's reflection, and planning history (completion rates). Use when the user starts their day with phrases like 'good morning', '早安', 'what should I work on today', '今天有什麼事', 'start planning'. This should be the FIRST tool called in a morning planning session. Optional sections parameter limits response to specific sections: tasks, activity, build_logs, projects, goals, insights, reflection, planning_history, rss, plan, completions. Omit sections to get all.",
		Annotations: readOnly,
	}, s.getMorningContext)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_session_delta",
		Description: "Show what changed since the last Claude.ai session: tasks completed, tasks created, tasks that became overdue, build logs, insight changes, session notes, and metrics trend. Use when resuming after a gap, e.g. 'what happened since last time', '上次之後有什麼變化', 'catch me up'. Defaults to changes since the last claude session note.",
		Annotations: readOnly,
	}, s.getSessionDelta)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_weekly_summary",
		Description: "Get a comprehensive weekly summary: task completion by project, metrics trends, project health, insight activity, goal alignment, auto-generated highlights and concerns. Use for weekly reviews, '這週做了什麼', 'weekly review', 'how was this week'. Set weeks_back=1 for last week.",
		Annotations: readOnly,
	}, s.getWeeklySummary)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_goal_progress",
		Description: "Show progress toward each active goal: related projects, tasks completed in the lookback period, weekly task rate, and on-track assessment. Supports optional area and status filters. Use when reviewing goals, '目標進度', 'goal check', 'am I on track', or to list goals with filtering (replaces get_goals).",
		Annotations: readOnly,
	}, s.getGoalProgress)

	// --- session notes tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "save_session_note",
		Description: "Save a session note for cross-environment context sharing. note_type: plan|reflection|context|metrics|insight. source: claude|claude-code|manual. Required metadata by type — insight: {hypothesis (string), invalidation_condition (string)}; plan: {committed_task_ids (array), reasoning (string)}; metrics: {tasks_planned (int), tasks_completed (int), adjustments (array)}; context and reflection: no required metadata. Example: save_session_note(note_type=\"insight\", source=\"claude\", content=\"...\", metadata={hypothesis: \"...\", invalidation_condition: \"...\"})",
		Annotations: additive,
	}, s.saveSessionNote)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_session_notes",
		Description: "Retrieve session notes for a date or date range, optionally filtered by note_type (plan|reflection|context|metrics|insight). Set days (1-30, default 1) for lookback range. Use when starting a development session to see today's plan, or when doing evening reflection to review the day. Example: get_session_notes(note_type=\"plan\", days=7)",
		Annotations: readOnly,
	}, s.getSessionNotes)

	// --- reflection tool ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_reflection_context",
		Description: "Get everything needed for evening reflection in one call: today's plan vs actual completions, My Day task status, daily summary metrics, unverified insights for review, planning history, and yesterday's adjustments. Use when doing evening reflection, '今天做了什麼', 'reflection time', 'how did today go'. This is the evening counterpart to get_morning_context.",
		Annotations: readOnly,
	}, s.getReflectionContext)

	// --- insight tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_active_insights",
		Description: "Get tracked insights (pattern observations and hypotheses) from past sessions. Use during morning planning to see unverified hypotheses that can inform today's schedule, or during evening reflection to review which insights have been confirmed or invalidated. Default returns unverified insights; use status='all' for everything.",
		Annotations: readOnly,
	}, s.getActiveInsights)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "update_insight",
		Description: "Update an insight's status or append evidence. Use during evening reflection when today's data supports or contradicts a hypothesis — append evidence, or change status to 'verified'/'invalidated'. Use 'archived' to retire old insights.",
		Annotations: mutating,
	}, s.updateInsight)

	// --- O'Reilly tools ---

	if s.oreilly != nil {
		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "search_oreilly_content",
			Description: "Search O'Reilly Learning for books, videos, articles, courses, and other content. Use when the user asks for learning resources, book recommendations, wants to find technical content on a topic, or says 'find me a book about X'. Supports filtering by format (book, video, article, course), publisher, and author.",
			Annotations: readOnlyOpenWorld,
		}, s.searchOReillyContent)

		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "get_oreilly_book_detail",
			Description: "Get book metadata and full table of contents from O'Reilly Learning. Use after search_oreilly_content to see a book's chapters and structure before reading. Returns chapter titles, filenames (for read_oreilly_chapter), estimated reading time, and section headings.",
			Annotations: readOnlyOpenWorld,
		}, s.getOReillyBookDetail)

		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "read_oreilly_chapter",
			Description: "Read the full text content of an O'Reilly book chapter. Use after get_oreilly_book_detail to read specific chapters. Requires archive_id and filename (from book detail chapters list). Returns plain text content stripped of HTML formatting.",
			Annotations: readOnlyOpenWorld,
		}, s.readOReillyChapter)
	}

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "curate_collected_item",
		Description: "Curate an RSS article into the knowledge base as a bookmark. Creates a content record (type=bookmark, status=draft) and links it back to the collected item. The bookmark will be processed by the content-review pipeline (generating embedding, excerpt, tags). Use when a high-value article should be preserved for future search_knowledge retrieval.",
		Annotations: additive,
	}, s.curateCollectedItem)

	// --- Sprint 3 content management tools ---

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "manage_content",
		Description: "Manage content records. Actions: create (title+body+content_type required, returns content_id+slug), update (content_id required, updates provided fields), publish (content_id required, sets status to published). Use when creating articles, build logs, TILs, or other content types. For dev session logs, prefer log_dev_session instead.",
		Annotations: mutating,
	}, s.manageContent)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_content_pipeline",
		Description: "View the content pipeline: drafts awaiting work, review queue, recently published, and scheduled content. Views: queue (draft+review items), calendar (published last 7 days + scheduled drafts), recent (published content). Use when checking what content needs attention, reviewing publishing cadence, or planning what to write next.",
		Annotations: readOnly,
	}, s.getContentPipeline)

	// --- Sprint 2 tools ---

	if s.feeds != nil {
		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "manage_feeds",
			Description: "Manage RSS/Atom feed sources. Actions: list (all feeds with status), add (url+name required, schedule defaults to daily), disable/enable/remove (feed_id required). Use when the user wants to add a new feed source, check feed health, or manage existing subscriptions.",
			Annotations: mutating,
		}, s.manageFeeds)
	}

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "get_collection_stats",
		Description: "Get collection pipeline statistics: per-feed item counts, average relevance scores, last collection timestamps, and global totals. Optionally filter by feed_id and lookback period (days, default 30, max 90). Use when checking feed health, collection pipeline performance, or diagnosing why certain feeds aren't producing results.",
		Annotations: readOnly,
	}, s.getCollectionStats)

	if s.systemStatus != nil {
		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "get_system_status",
			Description: "Get system observability: flow run stats, feed health, pipeline summaries, and recent flow runs. Scopes: summary (flow stats + feed health), pipelines (per-flow-name aggregation), flows (recent individual flow runs). Use when checking system health, diagnosing pipeline failures, or monitoring background jobs.",
			Annotations: readOnly,
		}, s.getSystemStatus)
	}

	if s.pipelineTrigger != nil {
		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "trigger_pipeline",
			Description: "Manually trigger a background pipeline. Valid pipelines: rss_collector (fetch all enabled RSS feeds), notion_sync (sync all Notion pages). Rate limited to once per 5 minutes per pipeline. Use when the user wants to force a feed collection or Notion sync outside the regular schedule.",
			Annotations: mutating,
		}, s.triggerPipeline)
	}

	// --- Sprint 3: AI flow tools ---

	if s.flowInvoker != nil {
		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "invoke_content_polish",
			Description: "Polish a draft content using AI. Improves writing quality, fixes grammar, enhances readability. Input: content_id (required). Returns polished version of the content body.",
			Annotations: mutating,
		}, s.invokeContentPolish)

		mcp.AddTool(s.server, &mcp.Tool{
			Name:        "invoke_content_strategy",
			Description: "Get AI-powered content topic suggestions based on existing content, RSS trends, and Koopa's positioning as a Go backend consultant. Returns suggested topics with rationale.",
			Annotations: readOnly,
		}, s.invokeContentStrategy)
	}

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "generate_social_excerpt",
		Description: "Generate a social media excerpt from published content. Platforms: linkedin (150-300 words, professional), twitter (280 chars, concise). Returns excerpt, hook, CTA, and hashtags.",
		Annotations: readOnly,
	}, s.generateSocialExcerpt)

	// --- Sprint 4: Knowledge synthesis ---

	mcp.AddTool(s.server, &mcp.Tool{
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

	tasks, err := s.tasks.SearchTasks(ctx, query, projectSlug, statusFilter, assignee, completedAfter, completedBefore, int32(limit))
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

	contentCh := make(chan contentResult, 1)
	noteCh := make(chan noteSearchResult, 1)
	semanticCh := make(chan semanticResult, 1)

	go func() {
		// Internal search: no visibility filter so MCP can find private content.
		contents, _, err := s.contents.InternalSearch(ctx, input.Query, 1, limit)
		// AND→OR fallback: if AND search returns 0 results, try OR semantics
		if err == nil && len(contents) == 0 {
			contents, _, err = s.contents.InternalSearchOR(ctx, input.Query, 1, limit)
		}
		contentCh <- contentResult{contents, err}
	}()

	go func() {
		if projectSlug != "" {
			// When project is set, use filter-based search with context + query
			filterResults, err := s.notes.SearchByFilters(ctx, note.SearchFilter{Context: &projectSlug, After: afterTime, Before: beforeTime}, limit*3)
			if err != nil {
				noteCh <- noteSearchResult{err: err}
				return
			}
			// Text search separately and RRF merge
			textResults, textErr := s.notes.SearchByText(ctx, input.Query, limit*3)
			if textErr != nil {
				noteCh <- noteSearchResult{err: textErr}
				return
			}
			merged := rrfMerge(textResults, filterResults, limit)
			// Convert back to SearchResult format
			sr := make([]note.SearchResult, len(merged))
			for j := range merged {
				sr[j] = note.SearchResult{Note: merged[j].Note, Rank: float32(merged[j].Score)}
			}
			noteCh <- noteSearchResult{notes: sr}
		} else {
			notes, err := s.notes.SearchByText(ctx, input.Query, limit)
			noteCh <- noteSearchResult{notes, err}
		}
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

// GetGoalsInput is the input for the get_goals tool.
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
// Priority: project_id FK > slug prefix > body frontmatter.
func contentMatchesProject(c *content.Content, projectID uuid.UUID, projectSlug string) bool {
	if c.ProjectID != nil && *c.ProjectID == projectID {
		return true
	}
	if strings.HasPrefix(c.Slug, projectSlug) {
		return true
	}
	if p := extractFrontmatter(c.Body, "project"); p != "" {
		return strings.EqualFold(p, projectSlug) || strings.Contains(strings.ToLower(p), strings.ToLower(projectSlug))
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
	created, err := s.contentWriter.CreateContent(ctx, params)
	if err == nil {
		return created, nil
	}
	if !errors.Is(err, content.ErrConflict) {
		return nil, err
	}
	// Slug conflict: append timestamp to make unique
	params.Slug = fmt.Sprintf("%s-%d", baseSlug, now.Unix()%10000)
	return s.contentWriter.CreateContent(ctx, params)
}

// --- curate tool ---

// CurateInput is the input for the curate_collected_item tool.
type CurateInput struct {
	CollectedID string   `json:"collected_id" jsonschema_description:"UUID of the collected_data item to curate (required)"`
	Notes       string   `json:"notes,omitempty" jsonschema_description:"personal notes or commentary on why this is valuable"`
	Tags        []string `json:"tags,omitempty" jsonschema_description:"tags for the bookmark"`
}

// CurateOutput is the output of the curate_collected_item tool.
type CurateOutput struct {
	ContentID string `json:"content_id"`
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Status    string `json:"status"`
}

func (s *Server) curateCollectedItem(ctx context.Context, _ *mcp.CallToolRequest, input CurateInput) (*mcp.CallToolResult, CurateOutput, error) {
	if input.CollectedID == "" {
		return nil, CurateOutput{}, fmt.Errorf("collected_id is required")
	}

	collectedID, err := uuid.Parse(input.CollectedID)
	if err != nil {
		return nil, CurateOutput{}, fmt.Errorf("invalid collected_id: %w", err)
	}

	item, err := s.collected.Item(ctx, collectedID)
	if err != nil {
		return nil, CurateOutput{}, fmt.Errorf("fetching collected item: %w", err)
	}

	if item.Status == collected.StatusCurated {
		return nil, CurateOutput{}, fmt.Errorf("item already curated")
	}

	now := time.Now()
	slug := fmt.Sprintf("bookmark-%s", item.URLHash)
	if item.URLHash == "" {
		slug = fmt.Sprintf("bookmark-%d", now.Unix())
	}

	sourceType := content.SourceExternal
	body := fmt.Sprintf("source: %s\nurl: %s\n\n", item.SourceName, item.SourceURL)
	if input.Notes != "" {
		body += input.Notes + "\n\n"
	}
	if item.OriginalContent != nil && *item.OriginalContent != "" {
		body += "---\n\n" + *item.OriginalContent
	}

	tags := input.Tags
	if tags == nil {
		tags = []string{}
	}
	tags = ensureTag(tags, "bookmark")
	for _, t := range item.Topics {
		tags = ensureTag(tags, t)
	}

	params := &content.CreateParams{
		Slug:        slug,
		Title:       item.Title,
		Body:        body,
		Type:        content.TypeBookmark,
		Status:      content.StatusDraft,
		Tags:        tags,
		Source:      &item.SourceURL,
		SourceType:  &sourceType,
		ReviewLevel: content.ReviewLight,
	}

	created, err := s.createContentWithRetry(ctx, params, slug, now)
	if err != nil {
		return nil, CurateOutput{}, fmt.Errorf("creating bookmark content: %w", err)
	}

	if curateErr := s.collected.Curate(ctx, collectedID, created.ID); curateErr != nil {
		s.logger.Error("curate: failed to link collected item", "collected_id", collectedID, "content_id", created.ID, "error", curateErr)
	}

	return nil, CurateOutput{
		ContentID: created.ID.String(),
		Slug:      created.Slug,
		Title:     created.Title,
		Status:    string(created.Status),
	}, nil
}

// ensureTag returns a copy of tags that includes target, adding it if absent.
func ensureTag(tags []string, target string) []string {
	if tags == nil {
		tags = []string{}
	}
	for _, t := range tags {
		if t == target {
			return tags
		}
	}
	return append(tags, target)
}

// --- manage_feeds tool ---

// ManageFeedsInput is the input for the manage_feeds tool.
type ManageFeedsInput struct {
	Action   string   `json:"action" jsonschema_description:"list|add|disable|enable|remove (required)"`
	FeedID   string   `json:"feed_id,omitempty" jsonschema_description:"feed UUID (required for disable/enable/remove)"`
	URL      string   `json:"url,omitempty" jsonschema_description:"feed URL (required for add)"`
	Name     string   `json:"name,omitempty" jsonschema_description:"feed name (required for add)"`
	Schedule string   `json:"schedule,omitempty" jsonschema_description:"daily or weekly (default: daily)"`
	Topics   []string `json:"topics,omitempty" jsonschema_description:"topic tags for the feed"`
}

// ManageFeedsOutput is the output for the manage_feeds tool.
type ManageFeedsOutput struct {
	Action  string      `json:"action"`
	Feeds   []feedBrief `json:"feeds,omitempty"`
	Feed    *feedBrief  `json:"feed,omitempty"`
	Message string      `json:"message,omitempty"`
}

type feedBrief struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	Enabled       bool     `json:"enabled"`
	Schedule      string   `json:"schedule"`
	Topics        []string `json:"topics"`
	LastFetchedAt string   `json:"last_fetched_at,omitempty"`
}

func toFeedBrief(f *feed.Feed) feedBrief {
	fb := feedBrief{
		ID:       f.ID.String(),
		Name:     f.Name,
		URL:      f.URL,
		Enabled:  f.Enabled,
		Schedule: f.Schedule,
		Topics:   f.Topics,
	}
	if f.LastFetchedAt != nil {
		fb.LastFetchedAt = f.LastFetchedAt.Format(time.RFC3339)
	}
	return fb
}

func (s *Server) manageFeeds(ctx context.Context, _ *mcp.CallToolRequest, input ManageFeedsInput) (*mcp.CallToolResult, ManageFeedsOutput, error) {
	switch input.Action {
	case "list":
		feeds, err := s.feeds.Feeds(ctx, nil)
		if err != nil {
			return nil, ManageFeedsOutput{}, fmt.Errorf("listing feeds: %w", err)
		}
		briefs := make([]feedBrief, len(feeds))
		for i := range feeds {
			briefs[i] = toFeedBrief(&feeds[i])
		}
		return nil, ManageFeedsOutput{Action: "list", Feeds: briefs}, nil

	case "add":
		if input.URL == "" || input.Name == "" {
			return nil, ManageFeedsOutput{}, fmt.Errorf("url and name are required for add action")
		}
		schedule := input.Schedule
		if schedule == "" {
			schedule = feed.ScheduleDaily
		}
		if !feed.ValidSchedule(schedule) {
			return nil, ManageFeedsOutput{}, fmt.Errorf("invalid schedule %q: use daily, weekly, or hourly_4", schedule)
		}
		created, err := s.feeds.CreateFeed(ctx, &feed.CreateParams{
			URL:      input.URL,
			Name:     input.Name,
			Schedule: schedule,
			Topics:   input.Topics,
		})
		if err != nil {
			if errors.Is(err, feed.ErrConflict) {
				return nil, ManageFeedsOutput{}, fmt.Errorf("feed with this URL already exists")
			}
			return nil, ManageFeedsOutput{}, fmt.Errorf("creating feed: %w", err)
		}
		fb := toFeedBrief(created)
		return nil, ManageFeedsOutput{Action: "add", Feed: &fb, Message: "feed created"}, nil

	case "disable":
		id, err := parseFeedID(input.FeedID)
		if err != nil {
			return nil, ManageFeedsOutput{}, err
		}
		enabled := false
		_, err = s.feeds.UpdateFeed(ctx, id, &feed.UpdateParams{Enabled: &enabled})
		if err != nil {
			if errors.Is(err, feed.ErrNotFound) {
				return nil, ManageFeedsOutput{}, fmt.Errorf("feed %s not found", input.FeedID)
			}
			return nil, ManageFeedsOutput{}, fmt.Errorf("disabling feed: %w", err)
		}
		return nil, ManageFeedsOutput{Action: "disable", Message: fmt.Sprintf("feed %s disabled", input.FeedID)}, nil

	case "enable":
		id, err := parseFeedID(input.FeedID)
		if err != nil {
			return nil, ManageFeedsOutput{}, err
		}
		enabled := true
		_, err = s.feeds.UpdateFeed(ctx, id, &feed.UpdateParams{Enabled: &enabled})
		if err != nil {
			if errors.Is(err, feed.ErrNotFound) {
				return nil, ManageFeedsOutput{}, fmt.Errorf("feed %s not found", input.FeedID)
			}
			return nil, ManageFeedsOutput{}, fmt.Errorf("enabling feed: %w", err)
		}
		return nil, ManageFeedsOutput{Action: "enable", Message: fmt.Sprintf("feed %s enabled", input.FeedID)}, nil

	case "remove":
		id, err := parseFeedID(input.FeedID)
		if err != nil {
			return nil, ManageFeedsOutput{}, err
		}
		if err := s.feeds.DeleteFeed(ctx, id); err != nil {
			return nil, ManageFeedsOutput{}, fmt.Errorf("removing feed: %w", err)
		}
		return nil, ManageFeedsOutput{Action: "remove", Message: fmt.Sprintf("feed %s removed", input.FeedID)}, nil

	default:
		return nil, ManageFeedsOutput{}, fmt.Errorf("invalid action %q: use list, add, disable, enable, or remove", input.Action)
	}
}

func parseFeedID(raw string) (uuid.UUID, error) {
	if raw == "" {
		return uuid.UUID{}, fmt.Errorf("feed_id is required")
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid feed_id %q: %w", raw, err)
	}
	return id, nil
}

// --- get_collection_stats tool ---

// CollectionStatsInput is the input for the get_collection_stats tool.
type CollectionStatsInput struct {
	FeedID string `json:"feed_id,omitempty" jsonschema_description:"specific feed UUID (omit for global stats)"`
	Days   int    `json:"days,omitempty" jsonschema_description:"lookback period in days (default: 30, max: 90)"`
}

// CollectionStatsOutput is the output for the get_collection_stats tool.
type CollectionStatsOutput struct {
	Feeds  []feedCollectionStat `json:"feeds"`
	Global globalCollectionStat `json:"global"`
	Days   int                  `json:"days"`
}

type feedCollectionStat struct {
	FeedID          string  `json:"feed_id"`
	FeedName        string  `json:"feed_name"`
	TotalItems      int     `json:"total_items"`
	AvgScore        float64 `json:"avg_score"`
	LastCollectedAt string  `json:"last_collected_at,omitempty"`
}

type globalCollectionStat struct {
	TotalItems   int     `json:"total_items"`
	TotalFeeds   int     `json:"total_feeds"`
	AvgScore     float64 `json:"avg_score"`
	UnreadCount  int     `json:"unread_count"`
	CuratedCount int     `json:"curated_count"`
}

func (s *Server) getCollectionStats(ctx context.Context, _ *mcp.CallToolRequest, input CollectionStatsInput) (*mcp.CallToolResult, CollectionStatsOutput, error) {
	days := clamp(input.Days, 1, 90, 30)

	var feedID *uuid.UUID
	if input.FeedID != "" {
		id, err := uuid.Parse(input.FeedID)
		if err != nil {
			return nil, CollectionStatsOutput{}, fmt.Errorf("invalid feed_id %q: %w", input.FeedID, err)
		}
		feedID = &id
	}

	cs, err := s.collected.CollectionStats(ctx, feedID, days)
	if err != nil {
		return nil, CollectionStatsOutput{}, fmt.Errorf("querying collection stats: %w", err)
	}

	feeds := make([]feedCollectionStat, len(cs.Feeds))
	for i := range cs.Feeds {
		f := &cs.Feeds[i]
		feeds[i] = feedCollectionStat{
			FeedID:     f.FeedID.String(),
			FeedName:   f.FeedName,
			TotalItems: f.TotalItems,
			AvgScore:   f.AvgScore,
		}
		if f.LastCollectedAt != nil {
			feeds[i].LastCollectedAt = f.LastCollectedAt.Format(time.RFC3339)
		}
	}

	return nil, CollectionStatsOutput{
		Feeds: feeds,
		Global: globalCollectionStat{
			TotalItems:   cs.Global.TotalItems,
			TotalFeeds:   cs.Global.TotalFeeds,
			AvgScore:     cs.Global.AvgScore,
			UnreadCount:  cs.Global.UnreadCount,
			CuratedCount: cs.Global.CuratedCount,
		},
		Days: days,
	}, nil
}

// --- get_system_status tool ---

// SystemStatusInput is the input for the get_system_status tool.
type SystemStatusInput struct {
	Scope    string `json:"scope,omitempty" jsonschema_description:"summary|pipelines|flows (default: summary)"`
	FlowName string `json:"flow_name,omitempty" jsonschema_description:"filter by flow name (only for scope=flows)"`
	Status   string `json:"status,omitempty" jsonschema_description:"completed|failed|running (only for scope=flows)"`
	Hours    int    `json:"hours,omitempty" jsonschema_description:"lookback hours (default: 24, max: 168)"`
}

// SystemStatusOutput is the output for the get_system_status tool.
type SystemStatusOutput struct {
	Scope      string              `json:"scope"`
	Hours      int                 `json:"hours"`
	FlowStats  *flowStatusSummary  `json:"flow_stats,omitempty"`
	FeedHealth *feedHealthSummary  `json:"feed_health,omitempty"`
	Pipelines  []pipelineSummary   `json:"pipelines,omitempty"`
	FlowRuns   []recentFlowRunItem `json:"flow_runs,omitempty"`
}

type flowStatusSummary struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Running   int `json:"running"`
}

type feedHealthSummary struct {
	Total        int `json:"total"`
	Enabled      int `json:"enabled"`
	FailingFeeds int `json:"failing_feeds"`
}

type pipelineSummary struct {
	FlowName   string  `json:"flow_name"`
	Total      int     `json:"total"`
	Completed  int     `json:"completed"`
	Failed     int     `json:"failed"`
	Running    int     `json:"running"`
	LastRunAt  *string `json:"last_run_at,omitempty"`
	LastStatus *string `json:"last_status,omitempty"`
}

type recentFlowRunItem struct {
	ID        string  `json:"id"`
	FlowName  string  `json:"flow_name"`
	Status    string  `json:"status"`
	Error     *string `json:"error,omitempty"`
	CreatedAt string  `json:"created_at"`
	EndedAt   *string `json:"ended_at,omitempty"`
}

func (s *Server) getSystemStatus(ctx context.Context, _ *mcp.CallToolRequest, input SystemStatusInput) (*mcp.CallToolResult, SystemStatusOutput, error) {
	scope := input.Scope
	if scope == "" {
		scope = "summary"
	}

	hours := clamp(input.Hours, 1, 168, 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	out := SystemStatusOutput{Scope: scope, Hours: hours}

	var err error
	switch scope {
	case "summary":
		err = s.statusScopeSummary(ctx, since, &out)
	case "pipelines":
		err = s.statusScopePipelines(ctx, since, &out)
	case "flows":
		err = s.statusScopeFlows(ctx, since, &input, &out)
	default:
		return nil, SystemStatusOutput{}, fmt.Errorf("invalid scope %q: must be summary, pipelines, or flows", scope)
	}
	if err != nil {
		return nil, SystemStatusOutput{}, err
	}

	return nil, out, nil
}

func (s *Server) statusScopeSummary(ctx context.Context, since time.Time, out *SystemStatusOutput) error {
	fs, err := s.systemStatus.FlowRunsSince(ctx, since, nil, nil)
	if err != nil {
		return fmt.Errorf("querying flow stats: %w", err)
	}
	out.FlowStats = &flowStatusSummary{
		Total:     fs.Total,
		Completed: fs.Completed,
		Failed:    fs.Failed,
		Running:   fs.Running,
	}

	fh, err := s.systemStatus.FeedHealth(ctx)
	if err != nil {
		return fmt.Errorf("querying feed health: %w", err)
	}
	out.FeedHealth = &feedHealthSummary{
		Total:        fh.Total,
		Enabled:      fh.Enabled,
		FailingFeeds: fh.FailingFeeds,
	}
	return nil
}

func (s *Server) statusScopePipelines(ctx context.Context, since time.Time, out *SystemStatusOutput) error {
	summaries, err := s.systemStatus.PipelineSummaries(ctx, since)
	if err != nil {
		return fmt.Errorf("querying pipeline summaries: %w", err)
	}
	out.Pipelines = make([]pipelineSummary, len(summaries))
	for i, ps := range summaries {
		out.Pipelines[i] = pipelineSummary{
			FlowName:   ps.FlowName,
			Total:      ps.Total,
			Completed:  ps.Completed,
			Failed:     ps.Failed,
			Running:    ps.Running,
			LastRunAt:  ps.LastRunAt,
			LastStatus: ps.LastStatus,
		}
	}
	return nil
}

func (s *Server) statusScopeFlows(ctx context.Context, since time.Time, input *SystemStatusInput, out *SystemStatusOutput) error {
	var flowName, status *string
	if input.FlowName != "" {
		flowName = &input.FlowName
	}
	if input.Status != "" {
		switch input.Status {
		case "completed", "failed", "running":
			status = &input.Status
		default:
			return fmt.Errorf("invalid status %q: must be completed, failed, or running", input.Status)
		}
	}

	runs, err := s.systemStatus.RecentFlowRuns(ctx, since, flowName, status, 50)
	if err != nil {
		return fmt.Errorf("querying recent flow runs: %w", err)
	}
	out.FlowRuns = make([]recentFlowRunItem, len(runs))
	for i, r := range runs {
		out.FlowRuns[i] = recentFlowRunItem{
			ID:        r.ID,
			FlowName:  r.FlowName,
			Status:    r.Status,
			Error:     r.Error,
			CreatedAt: r.CreatedAt,
			EndedAt:   r.EndedAt,
		}
	}
	return nil
}

// --- trigger_pipeline tool ---

// TriggerPipelineInput is the input for the trigger_pipeline tool.
type TriggerPipelineInput struct {
	Pipeline string `json:"pipeline" jsonschema_description:"rss_collector|notion_sync (required)"`
}

// TriggerPipelineOutput is the output for the trigger_pipeline tool.
type TriggerPipelineOutput struct {
	Triggered bool   `json:"triggered"`
	Pipeline  string `json:"pipeline"`
	Message   string `json:"message"`
}

// triggerCooldown is the minimum interval between triggers of the same pipeline.
const triggerCooldown = 5 * time.Minute

func (s *Server) triggerPipeline(ctx context.Context, _ *mcp.CallToolRequest, input TriggerPipelineInput) (*mcp.CallToolResult, TriggerPipelineOutput, error) {
	switch input.Pipeline {
	case "rss_collector", "notion_sync":
		// valid
	case "":
		return nil, TriggerPipelineOutput{}, fmt.Errorf("pipeline is required: valid values are rss_collector, notion_sync")
	default:
		return nil, TriggerPipelineOutput{}, fmt.Errorf("invalid pipeline %q: valid values are rss_collector, notion_sync", input.Pipeline)
	}

	// Rate limit check.
	if last, ok := s.lastTrigger[input.Pipeline]; ok {
		if time.Since(last) < triggerCooldown {
			remaining := triggerCooldown - time.Since(last)
			return nil, TriggerPipelineOutput{
				Triggered: false,
				Pipeline:  input.Pipeline,
				Message:   fmt.Sprintf("rate limited: try again in %s", remaining.Truncate(time.Second)),
			}, nil
		}
	}

	s.lastTrigger[input.Pipeline] = time.Now()

	switch input.Pipeline {
	case "rss_collector":
		s.pipelineTrigger.TriggerCollect(ctx)
	case "notion_sync":
		s.pipelineTrigger.TriggerNotionSync(ctx)
	}

	return nil, TriggerPipelineOutput{
		Triggered: true,
		Pipeline:  input.Pipeline,
		Message:   "pipeline triggered successfully",
	}, nil
}

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

func (s *Server) manageContent(ctx context.Context, _ *mcp.CallToolRequest, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
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

func (s *Server) manageContentCreate(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
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

func (s *Server) manageContentUpdate(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
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
		proj, err := s.resolveProjectChain(ctx, input.Project)
		if err != nil {
			return nil, ManageContentOutput{}, err
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

func (s *Server) manageContentPublish(ctx context.Context, input ManageContentInput) (*mcp.CallToolResult, ManageContentOutput, error) {
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
	IncludeGapAnalysis bool   `json:"include_gap_analysis,omitempty" jsonschema_description:"include sub-topic coverage gaps (default true)"`
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
	if input.IncludeGapAnalysis || input.MaxSources == 0 { // default true
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
