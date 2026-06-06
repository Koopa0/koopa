// Copyright 2026 Koopa. All rights reserved.

package ops

// Regenerate the tool-inventory block in the koopa-system skills manual
// (references/tools.md) from this catalog whenever the tool surface changes.
//go:generate go run ./gen

// since marks the project-wide baseline version for all tools shipped with
// the initial MCP surface. New tools added later should carry their own
// Since literal.
const since = "1.0.0"

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
		Since:       since,
		Description: "Single-call daily-planning briefing. Filterable via the sections parameter — valid keys (omit or pass [] for all): 'tasks' (overdue/today/committed/upcoming todos), 'goals' (active_goals), 'pending_tasks' (pending_tasks_received + pending_tasks_issued — inter-agent coordination work), 'hypotheses' (unverified_hypotheses), 'rss' (rss_highlights — feeds tagged priority=high, NOT relevance-ranked; use search_knowledge for ranked retrieval), 'plan_history' (recent daily plan notes), 'content_pipeline' (content_pipeline). Per-agent default sections: learning-studio defaults to ['tasks', 'pending_tasks', 'hypotheses', 'plan_history']; every other caller (incl. hq) gets all sections. Further role guidance lives in each cowork project's CLAUDE.md. Scope is today (not since-last-session). For mid-day catch-up after a break, use session_delta instead. For week-level retrospective, use weekly_summary.",
	}
}

// ReflectionContext returns metadata for the evening reflection query.
func ReflectionContext() Meta {
	return Meta{
		Name:        "reflection_context",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "End-of-day retrospective: plan vs actual completion, daily plan item outcomes, today's agent notes. Day-level scope (today only) — for week-level retrospective use weekly_summary; for since-last-session activity use session_delta.",
	}
}

// SearchKnowledge returns metadata for the cross-content search tool.
func SearchKnowledge() Meta {
	return Meta{
		Name:        "search_knowledge",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Search across content (articles, build logs, TILs, etc.) and notes (Zettelkasten) — i.e. what we KNOW. CURRENT behavior: PostgreSQL full-text search (lexical, tsvector + websearch syntax, GIN-indexed) only — there is no production document-embedding write path today, so the semantic / pgvector branch returns no rows for app-created content. Hybrid lexical + pgvector + RRF is PLANNED but not active; do not assume semantic recall. Filters: source_types (default both), content_type (implies content-only; mutex with note_kind), note_kind (implies note-only; mutex with content_type), project, date range. Does NOT cover agent_notes (your runtime plan/context/reflection breadcrumbs) — to recall what you DECIDED/PLANNED/REFLECTED, use query_agent_notes instead.",
	}
}

// CaptureInbox returns metadata for the GTD inbox capture tool.
// FieldEnums advertises the energy enum structurally so callers do not
// have to discover the closed value set by trial-and-error.
func CaptureInbox() Meta {
	return Meta{
		Name:        "capture_inbox",
		Domain:      DomainDaily,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Quick task capture to inbox. Only title is required. Status is always inbox. Use when the user says 'add a task', 'remind me to', or expresses a concrete work item to capture.",
		FieldEnums: map[string][]string{
			"energy": {"high", "medium", "low"},
		},
	}
}

// PlanDay returns metadata for the daily plan commit tool.
func PlanDay() Meta {
	return Meta{
		Name:        "plan_day",
		Domain:      DomainDaily,
		Writability: Idempotent,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Set the day's plan as one atomic replacement. Each todo MUST already be in state=todo (inbox/done/someday rejected — clarify inbox todos to state=todo via the admin UI first). The items list MUST be non-empty; to leave the day unplanned, do not call plan_day at all. The whole call (delete-existing + insert-new) runs in one transaction, so any per-item validation failure rolls back to the previous plan. items_removed reports todos that were in the previous plan but are NOT in the new list (true displacements only — todos carried over with the same task_id are not reported as removed even though their plan_item row gets a new id).",
	}
}

// WriteAgentNote returns metadata for the agent-note writer.
func WriteAgentNote() Meta {
	return Meta{
		Name:        "write_agent_note",
		Domain:      DomainMeta,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Create an agent note. Kind: plan (daily plan reasoning), context (session state snapshot), reflection (retrospective review). Use for session logging and reflection.",
		FieldEnums: map[string][]string{
			"kind": {"plan", "context", "reflection"},
		},
	}
}

// QueryAgentNotes returns metadata for the agent-note reader.
func QueryAgentNotes() Meta {
	return Meta{
		Name:        "query_agent_notes",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Recall prior agent notes — your runtime breadcrumbs of what you DECIDED/PLANNED/REFLECTED — across date ranges. Filters: kind (plan|context|reflection), since/until (YYYY-MM-DD, default last 90 days), author. Use when conversation context no longer contains a note you wrote earlier — session reflections, plan reasoning, context snapshots. For published knowledge or content (what we KNOW), use search_knowledge instead. Ordered newest-first.",
	}
}

// StartSession returns metadata for the learning session start tool.
func StartSession() Meta {
	return Meta{
		Name:        "start_session",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Begin a learning session. Required: domain (e.g. leetcode, japanese), mode (retrieval/practice/mixed/review/reading). Validates no other active session exists. Use when the user wants to start a learning/practice session.",
		FieldEnums: map[string][]string{
			"mode": {"retrieval", "practice", "mixed", "review", "reading"},
		},
	}
}

// RecordAttempt returns metadata for the in-session attempt recorder.
// FieldEnums lists every accepted outcome value — both canonical DB
// enums (solved_independent, solved_with_hint, ...) and the semantic
// synonyms the coach is encouraged to type ("got it", "needed help",
// ...). Sourced from learning.mapProblemSolving + learning.mapImmersive.
//
// Description prose duplicates the partial-write contract from
// internal/mcp/learning.go::RecordAttemptOutput doc — keep both in sync
// when changing the contract. They serve different audiences (Description
// is the MCP client tooltip; the Go doc is for code authors) so neither
// can be eliminated.
func RecordAttempt() Meta {
	return Meta{
		Name:        "record_attempt",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Record an attempt within the active learning session. Accepts semantic outcomes ('got it', 'needed help', 'gave up') mapped to schema enums by session mode. Response echoes canonical_outcome alongside the input so the coach sees the normalized storage form. Auto-creates learning targets and concepts. Both high and low confidence observations are persisted; dashboard filters at read time. Partial-write contract: observations are validated per-element. Severity is only valid for signal='weakness'; passing severity on mastery/improvement rejects that observation only — sibling observations still try independently and the attempt row still persists. observations_recorded < input length is therefore a legal state; rejected indices are named in observation_warnings. Same per-element semantics apply to related_targets — relations_linked < len(related_targets) is legal and rejected entries land in relation_warnings. Response.attempt_number is PER-TARGET, not per-session: it counts how many times this same learning_target_id has been attempted across all sessions. Three attempts on three different targets in one session all return attempt_number=1. For session-scoped count use session_progress.attempt_count.",
		FieldEnums: map[string][]string{
			"outcome": {
				// Canonical DB-stored values.
				"solved_independent", "solved_with_hint", "solved_after_solution",
				"completed", "completed_with_support",
				"incomplete", "gave_up",
				// Semantic synonyms — problem_solving.
				"got it", "solved it", "nailed it",
				"needed help", "needed a hint", "got help",
				"saw answer", "saw the answer", "saw the answer first",
				"didn't finish", "not done",
				"gave up", "stuck",
				// Semantic synonyms — immersive (overlap with problem_solving
				// for shared outcomes; duplicates are acceptable in the enum
				// list since JSON Schema treats enum as a set).
				"finished", "done", "needed support",
			},
		},
	}
}

// EndSession returns metadata for the learning session terminator.
func EndSession() Meta {
	return Meta{
		Name:        "end_session",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "End the active learning session. Optional reflection text creates an agent note linked to the session. Returns session summary with all attempts.",
	}
}

// LearningRead returns metadata for the read-only learning-analytics
// multiplexer. It subsumes the former learning_dashboard (overview view only),
// recommend_next_target, attempt_history, and session_progress tools behind a
// single `view` discriminator. FieldEnums advertises the view enum so
// tools/list callers see valid values structurally.
//
// The former dashboard mastery / weaknesses / timeline / variations views are
// deliberately NOT exposed here — they remain HTTP-admin-only. learning_read
// rejects any view outside the four below.
func LearningRead() Meta {
	return Meta{
		Name:        "learning_read",
		Domain:      DomainLearning,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Read-only learning analytics. Pick a view: overview (recent learning sessions; filter by domain + window_days), next_target (in-session next-problem recommendation combining weakness analysis with the untried-variation graph — requires session_id, the active session, plus optional count + exclude_patterns), attempts (attempt history: exactly one of target {title+domain}, concept_slug, or session_id; each attempt carries its observation list with confidence labels, and concept_slug mode adds matched_observation_id; sort is target/concept DESC, session ASC; resolved=false means the lookup target does not exist), session_progress (in-session aggregate for the currently-active session: attempt count, elapsed time, paradigm/concept/category distributions; when no session is active returns {active:false, last_ended_session_id} as a pivot affordance). Response is the selected view's payload plus a top-level `view` tag.",
		FieldEnums: map[string][]string{
			"view": {"overview", "next_target", "attempts", "session_progress"},
		},
	}
}

// ManagePlan returns metadata for the learning plan lifecycle multiplexer.
func ManagePlan() Meta {
	return Meta{
		Name:        "manage_plan",
		Domain:      DomainLearning,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Learning plan lifecycle and entries. Actions: add_entries (accepts learning_target_id OR title for find-or-create using plan domain), remove_entries (draft only), update_entry (complete/skip/substitute), reorder, progress. The progress action returns aggregate counts plus a flat entry list with plan_entry_id, learning_target_id, title, position, status, phase — call it before update_entry to look up plan_entry_id. Completing an entry (status=completed) requires a non-blank reason and a completed_by_attempt_id whose learning_target matches the entry's; mismatched IDs are rejected. Skipping an entry (status=skipped) also requires a non-blank reason — skip is a decision and cross-agent review needs to know why an active plan entry was dropped (no force-mode escape hatch for skip). Use force=true with a reason starting with 'manual override:' (≥60 chars) when no aligned attempt exists for completion — the prefix is the audit signal for retroactive completions.",
		FieldEnums: map[string][]string{
			"action": {"add_entries", "remove_entries", "update_entry", "reorder", "progress"},
		},
	}
}

// Content tools — flat per-intent design.
// 8 separate tools instead of one manage_content multiplexer. Rationale:
// actions have divergent input schemas + mixed authorization (publish is
// human-only); mapping one-intent-one-tool gives the LLM crisp tool
// selection and MCP annotations match the action (Destructive on
// publish/archive; read-only on list/read).

// CreateContent returns metadata for the create_content tool.
func CreateContent() Meta {
	return Meta{
		Name:        "create_content",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Create a new content row in status=draft. type is one of: article, essay, build-log, til, digest. Notes are NOT a content type — use create_note. Slug collisions surface as output.slug_conflict (caller can pick a new slug or switch to update_content).",
		FieldEnums: map[string][]string{
			"content_type": {"article", "essay", "build-log", "til", "digest"},
		},
	}
}

// UpdateContent returns metadata for the update_content tool.
func UpdateContent() Meta {
	return Meta{
		Name:        "update_content",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Update editable fields (title/body/slug/type) on a content row. Any field may be omitted. Slug rename triggers slug_conflict path on collision. Fields-only: it does NOT change status — passing a status is rejected. Use set_content_review_state / publish_content / archive_content for lifecycle transitions.",
	}
}

// SetContentReviewState returns metadata for set_content_review_state.
func SetContentReviewState() Meta {
	return Meta{
		Name:        "set_content_review_state",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Set a content row's review state. state='review' submits a draft for review (the Claude → human publish handoff signal — content is done on Claude's side and awaits human publish or revert); state='draft' reverts a review item back to draft for more work. The target state is an idempotent no-op when already there (no second event). Rejected from published / archived / any state that isn't the required source (invalid_state, no mutation).",
	}
}

// PublishContent returns metadata for publish_content. Human-only.
func PublishContent() Meta {
	return Meta{
		Name:        "publish_content",
		Domain:      DomainContent,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "HUMAN-ONLY. Publish a review content row: status='published', is_public=true, published_at=now(). Requires explicit `as` field + registry Platform='human' — the server default does NOT confer publish authority. published → published is an idempotent no-op (no second event). Rejected from draft / archived (invalid_state, no mutation).",
	}
}

// ArchiveContent returns metadata for archive_content.
func ArchiveContent() Meta {
	return Meta{
		Name:        "archive_content",
		Domain:      DomainContent,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Soft-delete a content row by archiving it. Allowed: draft → archived, review → archived. archived → archived is an idempotent no-op (no second event). PUBLISHED content is rejected (invalid_state, no mutation) — depublication is a separate lifecycle decision and must not be hidden inside archive_content. Archived rows keep their audit trail.",
	}
}

// ListContent returns metadata for list_content.
func ListContent() Meta {
	return Meta{
		Name:        "list_content",
		Domain:      DomainContent,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "List content rows with optional filters (type, status, project). Returns summaries — use read_content for the full body.",
	}
}

// ReadContent returns metadata for read_content.
func ReadContent() Meta {
	return Meta{
		Name:        "read_content",
		Domain:      DomainContent,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Fetch a single content row with full body by ID.",
	}
}

// Note tools — flat per-intent design. Three tools map 1:1 to user intent.

// CreateNote returns metadata for create_note.
func CreateNote() Meta {
	return Meta{
		Name:        "create_note",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Create a Zettelkasten note (notes table). kind one of: solve-note, concept-note, debug-postmortem, decision-log, reading-note, musing. Default maturity 'seed'. Notes are Koopa-private; no publication lifecycle.",
	}
}

// UpdateNote returns metadata for update_note.
func UpdateNote() Meta {
	return Meta{
		Name:        "update_note",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Update editable fields (slug / title / body / kind) on a note. Maturity transitions have their own tool (update_note_maturity) so state changes are auditable separately from content edits.",
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
		PlanDay(),
		WriteAgentNote(),
		QueryAgentNotes(),
		StartSession(),
		RecordAttempt(),
		EndSession(),
		LearningRead(),
		ManagePlan(),
		CreateContent(),
		UpdateContent(),
		SetContentReviewState(),
		PublishContent(),
		ArchiveContent(),
		ListContent(),
		ReadContent(),
		CreateNote(),
		UpdateNote(),
	}
}
