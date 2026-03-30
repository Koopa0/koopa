// Design note: mcp is intentionally a wide package — it is a transport gateway
// that exposes domain stores as MCP tools. High import count is inherent to this
// role (same as server/ for HTTP routes). Tool handlers are organized by file
// (search.go, content.go, goals.go, etc.) but share the Server struct for
// connection lifecycle and telemetry. Sub-packaging was evaluated and rejected:
// tools don't depend on each other, so splitting would only add export surface.
package mcp

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

	"github.com/Koopa0/koopa0.dev/internal/activity"
	"github.com/Koopa0/koopa0.dev/internal/content"
	"github.com/Koopa0/koopa0.dev/internal/feed"
	"github.com/Koopa0/koopa0.dev/internal/feed/entry"
	"github.com/Koopa0/koopa0.dev/internal/goal"
	"github.com/Koopa0/koopa0.dev/internal/note"
	"github.com/Koopa0/koopa0.dev/internal/notion"
	"github.com/Koopa0/koopa0.dev/internal/oreilly"
	"github.com/Koopa0/koopa0.dev/internal/project"
	"github.com/Koopa0/koopa0.dev/internal/retrieval"
	"github.com/Koopa0/koopa0.dev/internal/session"
	"github.com/Koopa0/koopa0.dev/internal/stats"
	"github.com/Koopa0/koopa0.dev/internal/task"
)

// Server is the MCP server exposing knowledge tools.
type Server struct {
	server          *mcp.Server
	notes           *note.Store
	activity        *activity.Store
	projects        *project.Store
	collected       *entry.Store
	stats           *stats.Store
	tasks           *task.Store
	contents        *content.Store
	goals           *goal.Store
	notionClient    *notion.Client
	taskDBResolver  *notion.Store
	sessions        *session.Store
	queryEmbedder   QueryEmbedder
	feeds           *feed.Store
	oreilly         *oreilly.Client
	pipelineTrigger PipelineTrigger
	retrieval       *retrieval.Store                      // optional: spaced retrieval
	recordToolCall  func(context.Context, ToolCallRecord) // optional telemetry
	lastTrigger     map[string]time.Time                  // rate limit: pipeline name -> last trigger time
	triggerMu       sync.Mutex                            // protects lastTrigger
	logger          *slog.Logger
	loc             *time.Location // user timezone for day boundaries
}

// ServerOption configures optional Server dependencies.
type ServerOption func(*Server)

// WithFeedStore enables feed management tools.
func WithFeedStore(fs *feed.Store) ServerOption {
	return func(s *Server) { s.feeds = fs }
}

// WithNotionClient sets the Notion client for task create/complete/update operations.
func WithNotionClient(c *notion.Client, resolver *notion.Store) ServerOption {
	return func(s *Server) {
		s.notionClient = c
		s.taskDBResolver = resolver
	}
}

// WithLocation sets the user timezone for day boundary calculations.
func WithLocation(loc *time.Location) ServerOption {
	return func(s *Server) { s.loc = loc }
}

// WithGoalWriter enables goal status update tools.
// Uses the same *goal.Store that provides reads; the Server stores it on the
// goals field. This option is kept so goal writes remain opt-in at the wiring
// site (cmd/mcp), even though reads and writes share the same store instance.
func WithGoalWriter(w *goal.Store) ServerOption {
	return func(s *Server) { s.goals = w }
}

// WithProjectWriter overrides the project store for write operations.
// After the store field consolidation, reads and writes share s.projects
// (set via ServerDeps). This option exists for wiring sites that construct
// a separate write-only store instance; pass nil to keep the default.
func WithProjectWriter(w *project.Store) ServerOption {
	return func(s *Server) {
		if w != nil {
			s.projects = w
		}
	}
}

// WithRetrieval enables spaced retrieval tools (log_retrieval_attempt, get_retrieval_queue).
func WithRetrieval(rs *retrieval.Store) ServerOption {
	return func(s *Server) { s.retrieval = rs }
}

// WithActivityWriter enables activity event recording for task completion audit trail.
func WithActivityWriter(w *activity.Store) ServerOption {
	return func(s *Server) { s.activity = w }
}

// WithSemanticSearch enables embedding-based semantic search for notes.
func WithSemanticSearch(ns *note.Store, qe QueryEmbedder) ServerOption {
	return func(s *Server) {
		s.notes = ns
		s.queryEmbedder = qe
	}
}

// WithOReilly enables O'Reilly content search tools.
func WithOReilly(client *oreilly.Client) ServerOption {
	return func(s *Server) { s.oreilly = client }
}

// WithSystemStatus enables the get_system_status tool.
// Uses the same *stats.Store that provides collection stats; kept as an
// option so system-status tools remain opt-in at the wiring site.
func WithSystemStatus(r *stats.Store) ServerOption {
	return func(s *Server) { s.stats = r }
}

// WithPipelineTrigger enables the trigger_pipeline tool.
func WithPipelineTrigger(t PipelineTrigger) ServerOption {
	return func(s *Server) {
		s.pipelineTrigger = t
		s.lastTrigger = make(map[string]time.Time)
	}
}

// ToolCallRecord holds telemetry data for a single tool invocation.
type ToolCallRecord struct {
	Name        string
	Duration    time.Duration
	IsError     bool
	IsEmpty     bool // true when search/list tools return 0 results
	InputBytes  int  // approximate JSON size of input
	OutputBytes int  // approximate JSON size of output
}

// WithTelemetry enables async tool call logging for convergence analysis.
// The recorder is called in a goroutine with a 5-second timeout context
// after each tool call completes.
func WithTelemetry(recorder func(context.Context, ToolCallRecord)) ServerOption {
	return func(s *Server) { s.recordToolCall = recorder }
}

// ServerDeps holds the required dependencies for NewServer.
type ServerDeps struct {
	Notes     *note.Store
	Activity  *activity.Store
	Projects  *project.Store
	Collected *entry.Store
	Stats     *stats.Store
	Tasks     *task.Store
	Contents  *content.Store
	Sessions  *session.Store
	Goals     *goal.Store
	Logger    *slog.Logger
}

// NewServer creates an MCP server with all tools registered.
func NewServer(deps ServerDeps, opts ...ServerOption) *Server {
	s := &Server{
		notes:     deps.Notes,
		activity:  deps.Activity,
		projects:  deps.Projects,
		collected: deps.Collected,
		stats:     deps.Stats,
		tasks:     deps.Tasks,
		contents:  deps.Contents,
		sessions:  deps.Sessions,
		goals:     deps.Goals,
		logger:    deps.Logger,
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
	t := true
	destructive := &mcp.ToolAnnotations{
		DestructiveHint: &t,
		OpenWorldHint:   &f,
	}

	// --- read-only tools ---

	// search_notes MERGED into search_knowledge (A1).
	// Obsidian note frontmatter filters (source, context, book) are now parameters
	// on search_knowledge. Use content_type="obsidian-note" to search notes only.

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
		Description: "Retrieve decision-log notes from Obsidian (notes with type=decision-log in frontmatter), optionally filtered by project context. Unlike search_knowledge which searches by text query, this returns all decision-log entries without requiring a search term. Use when looking for past architectural decisions, design rationale, or 'why did we choose X' questions.",
		Annotations: readOnly,
	}, s.getDecisionLog)

	// --- new Phase 1 tools ---

	addTool(s, &mcp.Tool{
		Name:        "get_rss_highlights",
		Description: "Get recently collected RSS articles from tracked feeds, ordered by most recent first. Use when the user asks about recent tech news, wants reading recommendations, or needs to know what's trending in their tracked topics.",
		Annotations: readOnly,
	}, s.getRSSHighlights)

	// get_platform_stats REMOVED — drift analysis moved to get_goal_progress(include_drift=true).
	// Overview stats covered by individual domain tools (system_status, weekly_summary, learning_progress).

	// get_pending_tasks MERGED into search_tasks (A3).
	// Use search_tasks(status="pending") for the same functionality with urgency sort.

	addTool(s, &mcp.Tool{
		Name:        "search_tasks",
		Description: "Search and list tasks with flexible filters. Replaces get_pending_tasks — use status=\"pending\" for the same urgency-sorted view. Filters: query (fuzzy match title+description), project (slug/alias/title), status (pending|done|all, default: all), assignee (human|claude-code|cowork|all), completed_after/completed_before (YYYY-MM-DD). Pending tasks include overdue_days calculation. Examples: search_tasks(status=\"pending\", assignee=\"claude-code\") for pending work, search_tasks(query=\"refactor\", status=\"done\", completed_after=\"2026-03-01\") for completed work.",
		Annotations: readOnly,
	}, s.searchTasks)

	addTool(s, &mcp.Tool{
		Name:        "search_knowledge",
		Description: "Search across ALL content types: articles, build logs, TILs, notes, and Obsidian knowledge notes. Returns excerpts with source type markers. Filters: project (slug/alias/title), after/before (YYYY-MM-DD, exclusive), content_type (article|essay|build-log|til|note|bookmark|digest|obsidian-note). Obsidian note filters: source (leetcode|book|course|discussion|practice|video), context (project name in frontmatter), book (book title). All filters are optional and combinable. Use content_type=\"obsidian-note\" to search only Obsidian notes. Examples: search_knowledge(query=\"pagination\", content_type=\"til\"), search_knowledge(query=\"binary search\", content_type=\"obsidian-note\", source=\"leetcode\", context=\"leetcode-prep\")",
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
		Description: "Mark a task as done. Use when the user says they've finished something: 'done', 'completed', '做完了', '這題寫完了', 'OK next'. Always confirm the specific task before calling. Returns next recurrence date for recurring tasks.",
		Annotations: destructive, // recurring task due date push is irreversible
	}, s.completeTask)

	addTool(s, &mcp.Tool{
		Name:        "create_task",
		Description: "Create a new task in Notion. Fields: title (required), project (slug/alias/title), due (YYYY-MM-DD), priority (Low|Medium|High), energy (Low|High), my_day (bool), notes (description text). Use during morning planning or when the user says 'add a task', 'remind me to', '幫我建一個任務'. Example: create_task(title=\"Review PR\", project=\"koopa0.dev\", due=\"2026-03-26\", priority=\"High\", energy=\"High\", my_day=true)",
		Annotations: additive,
	}, s.createTask)

	addTool(s, &mcp.Tool{
		Name:        "update_task",
		Description: "Update any task property. Fields: new_title (string), due (YYYY-MM-DD), priority (Low|Medium|High), energy (Low|High), project (slug/alias/title), my_day (bool), status (To Do|Doing|Done), notes (appended to description). Identify task by task_id (UUID) or task_title (fuzzy match). For marking tasks complete, prefer complete_task instead.",
		Annotations: additiveIdempotent,
	}, s.updateTask)

	addTool(s, &mcp.Tool{
		Name:        "batch_my_day",
		Description: "Set today's planned tasks on Notion My Day. Use at the end of morning planning after the user confirms the daily schedule. Optionally clears previous My Day selections first.",
		Annotations: additiveIdempotent,
	}, s.batchMyDay)

	addTool(s, &mcp.Tool{
		Name: "log_learning_session",
		Description: "Record a learning outcome. Tags: topic (array, string, hash-table, two-pointers, sliding-window, binary-search, stack, queue, linked-list, tree, binary-tree, bst, graph, bfs, dfs, heap, trie, union-find, dp, greedy, backtracking, bit-manipulation, math, matrix, interval, topological-sort, sorting, design, simulation, prefix-sum, divide-and-conquer, segment-tree), result (ac-independent, ac-with-hints, ac-after-solution, incomplete), weakness:xxx, improvement:xxx. Difficulty: easy, medium, hard. " +
			"Optional learning_type with per-type metadata schema: " +
			"leetcode: {problem_number (int), pattern (string), complexity: {time, space}, weakness_observations: [{tag (required, e.g. weakness:complexity-analysis), observation (required, string), status (required: new|persistent|improving|graduated)}]}. " +
			"book-reading: {book (string), chapter (string), sections (string[]), mode (feynman-recall|led-by-claude), key_concepts: [{name (required), understanding (required: clear|fuzzy|not-understood), connection (optional), retrieval_target (optional bool)}]}. " +
			"course: {course, module, lesson, source_type, key_concepts (same as book-reading)}. " +
			"system-design: {topic, source, design_exercise (bool), key_concepts (same), related_systems (string[])}. " +
			"language: {language, activity_type, duration_minutes (int), platform, focus, notes}.",
		Annotations: additive,
	}, s.logLearningSession)

	addTool(s, &mcp.Tool{
		Name:        "update_project_status",
		Description: "Update a project's status during weekly or monthly review. Supports optional review notes.",
		Annotations: additiveIdempotent,
	}, s.updateProjectStatus)

	addTool(s, &mcp.Tool{
		Name:        "update_goal_status",
		Description: "Update a goal's status. Valid statuses: not-started (Dream), in-progress (Active), done (Achieved), abandoned.",
		Annotations: additiveIdempotent,
	}, s.updateGoalStatus)

	addTool(s, &mcp.Tool{
		Name:        "get_morning_context",
		Description: "Get everything needed for daily planning in one call. Use when the user starts their day ('good morning', '早安', 'what should I work on today'). This should be the FIRST tool called in a morning planning session. Returns four task lists: overdue_tasks (past due), today_tasks (due today, not yet committed), my_day_tasks (explicitly committed via Notion My Day), upcoming_tasks (due within 7 days). Optional sections parameter limits response: tasks, activity, build_logs, projects, goals, insights, reflection, planning_history, rss, plan, completions. Examples: Full daily planning (omit sections), Learning session: sections=[\"tasks\",\"plan\"], Claude Code session: sections=[\"tasks\",\"plan\",\"build_logs\",\"activity\"].",
		Annotations: readOnly,
	}, s.getMorningContext)

	addTool(s, &mcp.Tool{
		Name:        "get_session_delta",
		Description: "Show what changed since the last Claude.ai session: tasks completed, tasks created, tasks that became overdue, build logs, insight changes, session notes, and metrics trend. Use when resuming after a gap, e.g. 'what happened since last time', '上次之後有什麼變化', 'catch me up'. Defaults to changes since the last claude session note.",
		Annotations: readOnly,
	}, s.getSessionDelta)

	addTool(s, &mcp.Tool{
		Name:        "get_weekly_summary",
		Description: "Get a comprehensive weekly summary: task completion by project, metrics trends, project health, insight activity, goal alignment, highlights and concerns. Set weeks_back=1 for last week. Set compare_previous=true to include previous week data and delta (tasks completed diff, avg capacity diff).",
		Annotations: readOnly,
	}, s.getWeeklySummary)

	addTool(s, &mcp.Tool{
		Name:        "get_goal_progress",
		Description: "Show progress toward each active goal: related projects, tasks completed in the lookback period, weekly task rate, and on-track assessment. Supports optional area and status filters. Set include_drift=true for goal-vs-activity alignment analysis (per-area drift%). Use when reviewing goals, '目標進度', 'goal check', 'am I on track', or to list goals with filtering (replaces get_goals).",
		Annotations: readOnly,
	}, s.getGoalProgress)

	// --- session notes tools ---

	addTool(s, &mcp.Tool{
		Name:        "save_session_note",
		Description: "Save a session note for cross-environment context sharing. note_type: plan|reflection|context|metrics|insight. source: claude|claude-code|manual. Required metadata by type — insight: {hypothesis, invalidation_condition}; plan: {reasoning (required), committed_task_ids (UUID array) and/or committed_items (free-text string array)}; metrics: {tasks_planned, tasks_completed, adjustments}; context and reflection: no required metadata.",
		Annotations: additive,
	}, s.saveSessionNote)

	addTool(s, &mcp.Tool{
		Name:        "get_session_notes",
		Description: "Retrieve session notes for a date or date range, optionally filtered by note_type (plan|reflection|context|metrics|insight). Set days (1-30, default 1) for lookback range. Use when starting a development session to see today's plan, or when doing evening reflection to review the day. Example: get_session_notes(note_type=\"plan\", days=7)",
		Annotations: readOnly,
	}, s.sessionNotes)

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
	}, s.activeInsights)

	addTool(s, &mcp.Tool{
		Name:        "update_insight",
		Description: "Update an insight's status or append evidence. Use during evening reflection when today's data supports or contradicts a hypothesis — append evidence, or change status to 'verified'/'invalidated'. Use 'archived' to retire old insights.",
		Annotations: additiveIdempotent,
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

	// D2: renamed curate_collected_item → bookmark_rss_item
	addTool(s, &mcp.Tool{
		Name:        "bookmark_rss_item",
		Description: "Save an RSS collected item as a bookmark in the knowledge base. Creates a content record (type=bookmark, status=draft) and links it to the collected item. Use when a high-value article should be preserved for future search_knowledge retrieval.",
		Annotations: additive,
	}, s.curateCollectedItem)

	// --- B2: content tools (split from manage_content) ---

	addTool(s, &mcp.Tool{
		Name:        "create_content",
		Description: "Create a new draft content record. Required: title, body, content_type. Types: article (deep technical writing), essay (personal/non-technical reflection), build-log (project dev record — prefer log_dev_session for coding sessions), til (short daily learning), note (technical reference snippet), bookmark (external resource + commentary), digest (weekly/monthly roundup). Optional: tags, project.",
		Annotations: additive,
	}, s.createContent)

	addTool(s, &mcp.Tool{
		Name:        "update_content",
		Description: "Update a draft or review content's properties. Required: content_id. Optional: title, body, content_type, tags, project. Only provided fields are updated.",
		Annotations: additiveIdempotent,
	}, s.updateContent)

	addTool(s, &mcp.Tool{
		Name:        "publish_content",
		Description: "Publish a content record (status → published). This is irreversible. Required: content_id.",
		Annotations: destructive,
	}, s.publishContent)

	// D1: renamed get_content_pipeline → list_content_queue
	addTool(s, &mcp.Tool{
		Name:        "list_content_queue",
		Description: "View the content queue: drafts awaiting work, review items, recently published, and scheduled content. Views: queue (draft+review items, default), calendar (published last 7 days + scheduled), recent (published). Use when checking what content needs attention or planning what to write next.",
		Annotations: readOnly,
	}, s.getContentPipeline)

	// --- B1: feed tools (split from manage_feeds) ---

	if s.feeds != nil {
		addTool(s, &mcp.Tool{
			Name:        "list_feeds",
			Description: "List all RSS/Atom feed subscriptions with id, name, url, enabled status, schedule, topics, and last_fetched_at.",
			Annotations: readOnly,
		}, s.listFeeds)

		addTool(s, &mcp.Tool{
			Name:        "add_feed",
			Description: "Add a new RSS/Atom feed subscription. Required: url, name. Optional: schedule (daily|weekly, default daily), topics.",
			Annotations: additive,
		}, s.addFeed)

		// disable_feed + enable_feed MERGED into update_feed (boolean toggle, not multiplexer).
		addTool(s, &mcp.Tool{
			Name:        "update_feed",
			Description: "Update a feed subscription. Currently supports enabling/disabling. Required: feed_id, enabled (bool). Stops or resumes collection while preserving historical data.",
			Annotations: additiveIdempotent,
		}, s.updateFeed)

		addTool(s, &mcp.Tool{
			Name:        "remove_feed",
			Description: "Permanently delete a feed subscription and its record. Required: feed_id.",
			Annotations: destructive,
		}, s.removeFeed)
	}

	addTool(s, &mcp.Tool{
		Name:        "get_collection_stats",
		Description: "Get collection pipeline statistics: per-feed item counts, average relevance scores, last collection timestamps, and global totals. Optionally filter by feed_id and lookback period (days, default 30, max 90).",
		Annotations: readOnly,
	}, s.getCollectionStats)

	if s.stats != nil {
		addTool(s, &mcp.Tool{
			Name:        "get_system_status",
			Description: "Get system observability: flow run stats, feed health, pipeline summaries, and recent flow runs. Scopes: summary (flow stats + feed health), pipelines (per-flow-name aggregation), flows (recent individual runs).",
			Annotations: readOnly,
		}, s.getSystemStatus)
	}

	if s.pipelineTrigger != nil {
		addTool(s, &mcp.Tool{
			Name:        "trigger_pipeline",
			Description: "Manually trigger a background pipeline: rss_collector or notion_sync. Use when you need immediate pipeline execution instead of waiting for the next scheduled run — e.g., after adding a new RSS feed, after deploying new scoring logic, or when debugging collection issues. Rate limited to once per 5 minutes per pipeline.",
			Annotations: destructive,
		}, s.triggerPipeline)
	}

	// --- Learning analytics tools (B1-B3) ---

	addTool(s, &mcp.Tool{
		Name:        "get_tag_summary",
		Description: "Aggregate tag frequency for a project's TIL entries. Returns each tag with its occurrence count, optionally filtered by prefix. Use for learning analytics: get_tag_summary(project=\"leetcode\") for all tags, get_tag_summary(project=\"leetcode\", tag_prefix=\"weakness:\") for weaknesses only.",
		Annotations: readOnly,
	}, s.getTagSummary)

	addTool(s, &mcp.Tool{
		Name:        "get_coverage_matrix",
		Description: "Coverage matrix of topic patterns for a project's TIL entries. For each topic tag (e.g. two-pointers, dp, graph), returns: total count, last practice date, and result distribution (ac-independent / ac-with-hints / ac-after-solution / incomplete). Use for adaptive coaching: identifying under-practiced or low-accuracy topics.",
		Annotations: readOnly,
	}, s.getCoverageMatrix)

	addTool(s, &mcp.Tool{
		Name:        "get_weakness_trend",
		Description: "Time series of a specific weakness tag's occurrences with trend analysis. Returns chronological list of occurrences with result tags, slug, title, and observation text (from structured metadata). Computed trend: improving / stable / declining / insufficient-data. Use for tracking whether a weakness is getting better over time. Example: get_weakness_trend(project=\"leetcode\", tag=\"weakness:pattern-recognition\", days=60).",
		Annotations: readOnly,
	}, s.getWeaknessTrend)

	addTool(s, &mcp.Tool{
		Name:        "get_learning_timeline",
		Description: "Get recent learning entries grouped by day with summary stats (active days, current streak, project distribution). Returns per-entry structured metadata (weakness observations, key concepts) when available. Use at the start of a learning session for context, or when the user asks about recent learning activity. Optional project filter; defaults to 14-day lookback.",
		Annotations: readOnly,
	}, s.getLearningTimeline)

	// --- Knowledge synthesis ---

	addTool(s, &mcp.Tool{
		Name:        "synthesize_topic",
		Description: "Synthesize knowledge across ALL content sources for a topic: articles, build logs, TILs, Obsidian notes, and RSS bookmarks. Produces a structured synthesis grouped by source type with gap analysis. Use when you need cross-source synthesis across 5+ related items or want to identify knowledge gaps. For quick lookups of 1-2 results, search_knowledge is faster and cheaper. Note: higher token cost than search tools due to multi-source aggregation.",
		Annotations: readOnly,
	}, s.synthesizeTopic)

	addTool(s, &mcp.Tool{
		Name:        "find_similar_content",
		Description: "Find semantically similar TILs using embedding cosine similarity. Use when Learning Claude wants to discover cross-topic concept connections, or when reviewing a TIL and looking for related concepts. Requires content to have an embedding (generated hourly by cron). Returns empty array if no embedding exists.",
		Annotations: readOnly,
	}, s.findSimilarContent)

	// --- Spaced retrieval tools (conditional: requires retrieval store) ---

	if s.retrieval != nil {
		addTool(s, &mcp.Tool{
			Name:        "log_retrieval_attempt",
			Description: "Record a spaced retrieval self-test result using FSRS scheduling. Required: content_slug, rating (1=forgot, 2=partial recall, 3=remembered). Optional: tag (specific weakness tag; omit for whole-content retrieval). Returns next due date, memory stability, and card state.",
			Annotations: additive,
		}, s.logRetrievalAttempt)

		addTool(s, &mcp.Tool{
			Name:        "get_retrieval_queue",
			Description: "Get TILs due for spaced retrieval review: overdue FSRS cards + recent TILs never tested. Use at the start of a learning session for review, or when the user asks 'what should I review'. Optional project filter; default limit 10.",
			Annotations: readOnly,
		}, s.getRetrievalQueue)
	}

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
	for _, t := range c.Tags {
		if strings.EqualFold(t, projectSlug) {
			return true
		}
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
	if maxLen <= 0 {
		return ""
	}
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
// When s.recordToolCall is set, each tool call records name, duration, error status,
// input/output sizes, and empty-result detection.
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

		// Compute telemetry asynchronously with timeout to prevent goroutine leaks.
		inputBytes, _ := json.Marshal(input)
		outputBytes, _ := json.Marshal(output)
		rec := ToolCallRecord{
			Name:        name,
			Duration:    time.Since(start),
			IsError:     err != nil,
			IsEmpty:     isEmptyResult(output),
			InputBytes:  len(inputBytes),
			OutputBytes: len(outputBytes),
		}
		go func() { //nolint:gosec // G118: intentionally detached from request context — telemetry must outlive the request
			tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			record(tctx, rec)
		}()

		return result, output, err
	})
}

// isEmptyResult checks if an output struct has a Total field with value 0,
// indicating a search or list tool returned no results.
func isEmptyResult(output any) bool {
	b, err := json.Marshal(output)
	if err != nil {
		return false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return false
	}
	raw, ok := m["total"]
	if !ok {
		return false
	}
	return string(raw) == "0"
}
