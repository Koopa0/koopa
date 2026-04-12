package ops

// Since marks the project-wide baseline version for tools that have been
// in place since the MCP v2 surface was introduced. New tools added after
// v2 ships should carry their own Since literal.
const sinceV2 = "v2.0.0"

// Catalog accessor design
// -----------------------
// Each tool is exposed as a package-level function returning a fresh
// Meta value. The catalog has no mutable package-level state: callers
// receive a copy, cannot mutate the source, and the compiler enforces
// named references so a typo fails to build.
//
// The trade-off is that every accessor call allocates a ~96-byte Meta.
// All tool registration happens once at NewServer time and the admin
// metadata endpoint runs well under a QPS — the allocation cost is
// irrelevant in both paths and not worth a global-state optimisation.

// MorningContext returns metadata for the morning planning query.
func MorningContext() Meta {
	return Meta{
		Name:        "morning_context",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Get everything needed for daily planning: overdue tasks, today's tasks, committed daily plan items, upcoming tasks, and recent plan history. Use when the user starts their day.",
	}
}

// ReflectionContext returns metadata for the evening reflection query.
func ReflectionContext() Meta {
	return Meta{
		Name:        "reflection_context",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Get everything needed for evening reflection: plan vs actual completion, daily plan item outcomes, today's journal entries. Use for evening reflection or reviewing the day.",
	}
}

// SearchKnowledge returns metadata for the cross-content search tool.
func SearchKnowledge() Meta {
	return Meta{
		Name:        "search_knowledge",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Search across all content types: articles, build logs, TILs, notes. Filters: content_type, project, date range. Use when looking for past knowledge or content.",
	}
}

// CaptureInbox returns metadata for the GTD inbox capture tool.
func CaptureInbox() Meta {
	return Meta{
		Name:        "capture_inbox",
		Domain:      DomainDaily,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Quick task capture to inbox. Only title is required. Status is always inbox. Use when the user says 'add a task', 'remind me to', or expresses a concrete work item to capture.",
	}
}

// AdvanceWork returns metadata for the GTD task lifecycle transitions.
func AdvanceWork() Meta {
	return Meta{
		Name:        "advance_work",
		Domain:      DomainDaily,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Task state transitions. Actions: clarify (inbox→todo with optional project/due/priority/energy), start (todo→in-progress), complete (→done, auto-updates daily plan item), defer (→someday). Use when the user wants to progress a task.",
	}
}

// PlanDay returns metadata for the daily plan commit tool.
func PlanDay() Meta {
	return Meta{
		Name:        "plan_day",
		Domain:      DomainDaily,
		Writability: Idempotent,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Set daily plan items for a date. Accepts task IDs with positions. Idempotent: re-planning replaces existing items. Use after morning_context when the user confirms their daily plan.",
	}
}

// WriteJournal returns metadata for the journal entry writer.
func WriteJournal() Meta {
	return Meta{
		Name:        "write_journal",
		Domain:      DomainMeta,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Create a journal entry. Kind: plan (daily plan reasoning), context (session state snapshot), reflection (review), metrics (quantitative snapshot). Use for session logging and reflection.",
	}
}

// ProposeCommitment returns metadata for the high-commitment entity preview tool.
func ProposeCommitment() Meta {
	return Meta{
		Name:        "propose_commitment",
		Domain:      DomainMeta,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Propose creating a goal, project, milestone, directive, or insight. Returns a preview and signed proposal token. Does NOT write to the database. Use when the user wants to create a high-commitment entity — present the preview for approval before calling commit_proposal.",
	}
}

// CommitProposal returns metadata for the proposal-token commit tool.
func CommitProposal() Meta {
	return Meta{
		Name:        "commit_proposal",
		Domain:      DomainMeta,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Commit a previously proposed entity using the proposal_token from propose_commitment. Creates the entity in the database. Supports optional modifications to override fields before commit.",
	}
}

// GoalProgress returns metadata for the active-goals query.
func GoalProgress() Meta {
	return Meta{
		Name:        "goal_progress",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Show active goals with milestone progress (completed/total), area, quarter, and deadline. Use for goal reviews, weekly planning, or 'am I on track' questions.",
	}
}

// FileReport returns metadata for the IPC report filing tool.
func FileReport() Meta {
	return Meta{
		Name:        "file_report",
		Domain:      DomainIPC,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Create a report. Optionally links to a directive via in_response_to. Set resolve_directive=true to mark the directive as resolved (requires directive to be acknowledged first). Source must be a participant with can_write_reports. Use when a participant completes directive work and files the final deliverable.",
	}
}

// AcknowledgeDirective returns metadata for the directive acknowledgement tool.
func AcknowledgeDirective() Meta {
	return Meta{
		Name:        "acknowledge_directive",
		Domain:      DomainIPC,
		Writability: Idempotent,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Mark a directive as acknowledged by the calling participant. Validates the caller is the target. Use when the AI picks up a directive during morning_context.",
	}
}

// TrackInsight returns metadata for the insight lifecycle update tool.
func TrackInsight() Meta {
	return Meta{
		Name:        "track_insight",
		Domain:      DomainMeta,
		Writability: Idempotent,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Update an existing insight. Actions: verify (hypothesis confirmed), invalidate (hypothesis disproven), archive (retire), add_evidence (append supporting data). Insight creation goes through propose_commitment.",
	}
}

// StartSession returns metadata for the learning session start tool.
func StartSession() Meta {
	return Meta{
		Name:        "start_session",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Begin a learning session. Required: domain (e.g. leetcode, japanese), mode (retrieval/practice/mixed/review/reading). Validates no other active session exists. Use when the user wants to start a learning/practice session.",
	}
}

// RecordAttempt returns metadata for the in-session attempt recorder.
func RecordAttempt() Meta {
	return Meta{
		Name:        "record_attempt",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Record an attempt within the active learning session. Accepts semantic outcomes ('got it', 'needed help', 'gave up') mapped to schema enums by session mode. Auto-creates learning items and concepts. Both high and low confidence observations are persisted; dashboard filters at read time. Observation constraint: severity is only valid for signal='weakness'; passing severity on mastery/improvement will reject the entire observation (check observation_warnings in response).",
	}
}

// EndSession returns metadata for the learning session terminator.
func EndSession() Meta {
	return Meta{
		Name:        "end_session",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "End the active learning session. Optional reflection text creates a journal entry linked to the session. Returns session summary with all attempts.",
	}
}

// LearningDashboard returns metadata for the learning analytics dashboard.
func LearningDashboard() Meta {
	return Meta{
		Name:        "learning_dashboard",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Learning analytics dashboard. Views: overview (sessions list), mastery (per-concept signal counts; mastery floor: <3 observations → always 'developing' regardless of signal distribution), weaknesses (cross-pattern weakness analysis by category+severity), retrieval (items with due <= now only; newly reviewed cards get future due dates and won't reappear until due), timeline (sessions with attempt stats by day), variations (problem relationship graph). Filter by domain and lookback period.",
	}
}

// AttemptHistory returns metadata for the attempt lookup tool.
func AttemptHistory() Meta {
	return Meta{
		Name:        "attempt_history",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Read-side counterpart to record_attempt. Three lookup modes (exactly one required): item (title+domain — returns this problem's attempt history for Improvement Verification Loop), concept_slug (returns attempts that observed the concept, with the matched observation attached), session_id (returns all attempts for a past session). Empty result with resolved=false means the lookup target does not exist.",
	}
}

// ManagePlan returns metadata for the learning plan lifecycle multiplexer.
func ManagePlan() Meta {
	return Meta{
		Name:        "manage_plan",
		Domain:      DomainLearning,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Learning plan lifecycle and items. Actions: add_items (accepts learning_item_id OR title for find-or-create using plan domain), remove_items (draft only), update_item (complete/skip/substitute), reorder, update_plan (activate/pause/complete/abandon), progress. The progress action returns aggregate counts plus a flat item list with plan_item_id, learning_item_id, title, position, status, phase — call it before update_item to look up plan_item_id.",
	}
}

// ManageContent returns metadata for the content lifecycle multiplexer.
func ManageContent() Meta {
	return Meta{
		Name:        "manage_content",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Content lifecycle: create (draft), update (fields+status), publish (→published), list (filter by status/type), read (full content by ID), bookmark_rss (RSS entry → bookmark). Requires content_id for update/publish/read, entry_id for bookmark_rss.",
	}
}

// ManageFeeds returns metadata for the RSS feed subscription multiplexer.
func ManageFeeds() Meta {
	return Meta{
		Name:        "manage_feeds",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Feed management: list, add (url+name), update (enable/disable), remove. Use for RSS feed subscription management.",
	}
}

// SystemStatus returns metadata for the pipeline health query.
func SystemStatus() Meta {
	return Meta{
		Name:        "system_status",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "System health: pipeline stats, feed health, flow run summaries. Scopes: summary (default), pipelines, flows.",
	}
}

// SessionDelta returns metadata for the cross-session context bridge.
func SessionDelta() Meta {
	return Meta{
		Name:        "session_delta",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "What changed since last session: tasks created/completed, journal entries, learning sessions. Default lookback: 24 hours. Use at session start to bridge context.",
	}
}

// WeeklySummary returns metadata for the week retrospective query.
func WeeklySummary() Meta {
	return Meta{
		Name:        "weekly_summary",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       sinceV2,
		Description: "Week retrospective: tasks completed, journal entries, learning sessions, concept mastery. Defaults to current week (Monday-Sunday). Use for weekly reviews.",
	}
}

// All returns every tool meta in stable registration order. The order
// mirrors the addTool call sequence in internal/mcp/server.go and is
// enforced by TestOpsCatalogDrift. Adding a new tool requires appending
// an accessor here and registering a handler in the mcp package.
func All() []Meta {
	return []Meta{
		MorningContext(),
		ReflectionContext(),
		SearchKnowledge(),
		CaptureInbox(),
		AdvanceWork(),
		PlanDay(),
		WriteJournal(),
		ProposeCommitment(),
		CommitProposal(),
		GoalProgress(),
		FileReport(),
		AcknowledgeDirective(),
		TrackInsight(),
		StartSession(),
		RecordAttempt(),
		EndSession(),
		LearningDashboard(),
		AttemptHistory(),
		ManagePlan(),
		ManageContent(),
		ManageFeeds(),
		SystemStatus(),
		SessionDelta(),
		WeeklySummary(),
	}
}
