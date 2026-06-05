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

// AdvanceWork returns metadata for the GTD task lifecycle transitions.
// FieldEnums advertises the action / priority / energy enums
// structurally — they are closed value sets enforced by the handler,
// and surfacing them in tools/list saves callers a 422 round-trip.
func AdvanceWork() Meta {
	return Meta{
		Name:        "advance_work",
		Domain:      DomainDaily,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Personal-todo state transitions. Actions: clarify (inbox→todo, supply project/due/priority/energy to make it actionable; required before plan_day will accept the todo), start (todo→in_progress), complete (→done; if the todo is on today's daily plan, the matching plan_item is auto-marked done in the same transaction; recurring todos are auto-reset to next due date), defer (→someday).",
		FieldEnums: map[string][]string{
			"action":   {"clarify", "start", "complete", "defer"},
			"priority": {"high", "medium", "low"},
			"energy":   {"high", "medium", "low"},
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
		Description: "Set the day's plan as one atomic replacement. Each todo MUST already be in state=todo (inbox/done/someday rejected — promote inbox via advance_work(action=clarify) first). The items list MUST be non-empty; to leave the day unplanned, do not call plan_day at all. The whole call (delete-existing + insert-new) runs in one transaction, so any per-item validation failure rolls back to the previous plan. items_removed reports todos that were in the previous plan but are NOT in the new list (true displacements only — todos carried over with the same task_id are not reported as removed even though their plan_item row gets a new id).",
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

// LearningDashboard returns metadata for the learning analytics dashboard.
// FieldEnums advertises the view + confidence_filter enums so tools/list
// callers see valid values structurally without parsing Description prose.
func LearningDashboard() Meta {
	return Meta{
		Name:        "learning_dashboard",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Learning analytics dashboard. Views: overview (sessions list), mastery (per-concept signal counts; mastery floor: <3 observations → always 'developing' regardless of signal distribution), weaknesses (cross-pattern weakness analysis by category+severity), timeline (sessions with attempt stats by day), variations (problem relationship graph). Filter by domain and lookback period. Response shape is stable across views: {view, total, <view_key>: [...]} — the view-specific array is always present (empty [] on no data), other view keys are absent.",
		FieldEnums: map[string][]string{
			"view":              {"overview", "mastery", "weaknesses", "timeline", "variations"},
			"confidence_filter": {"high", "all"},
		},
	}
}

// RecommendNextTarget returns metadata for the session-scoped next-target
// recommender.
func RecommendNextTarget() Meta {
	return Meta{
		Name:        "recommend_next_target",
		Domain:      DomainLearning,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Recommend the next learning target during an active session. Combines weaknesses (concepts by severity × recency) with the variation graph (untried harder_variant / follow_up / same_pattern / similar_structure of problems the user already practiced on each weak concept). Interleaving filter operates on current session only — skips candidates whose anchor pattern was practiced in this session. Cross-session interleaving is the coach's job at session start via learning_dashboard view=timeline. Returns up to N candidates with source_concept + reason so the coach can explain the choice. When candidates are skipped, use recommended_by='tool' in the metadata of the resulting record_attempt to preserve the recommendation provenance.",
	}
}

// AttemptHistory returns metadata for the attempt lookup tool.
func AttemptHistory() Meta {
	return Meta{
		Name:        "attempt_history",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Read-side counterpart to record_attempt. Three lookup modes (exactly one required): target (title+domain — primary Improvement Verification Loop entry for 'how did this problem go last time'), concept_slug (returns attempts that observed the concept), session_id (returns all attempts for a past session, oldest first). Every returned attempt carries its full observations list (each with confidence label) and — on concept_slug mode — a matched_observation_id pointer into that list indicating which observation drove the query match. Observations within each attempt are ordered by coach-insertion (position ASC). Sort order: target/concept_slug DESC, session_id ASC. Empty result with resolved=false means the lookup target does not exist. attempt_number on each returned attempt is PER-TARGET (counts attempts on the same learning_target_id across all sessions), NOT per-session — three attempts on three different targets in one session each get attempt_number=1. Example (concept_slug, include_observations=false): {\"mode\":\"concept\",\"resolved\":true,\"attempts\":[{\"id\":\"...\",\"outcome\":\"solved_with_hint\",\"observations\":null,\"matched_observation_id\":\"obs-uuid\"}]} — matched_observation_id is still populated because the query did match an observation even though the list is skipped; pass include_observations=true (default) to see the observation itself.",
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
		Description: "Learning plan lifecycle and entries. Actions: add_entries (accepts learning_target_id OR title for find-or-create using plan domain), remove_entries (draft only), update_entry (complete/skip/substitute), reorder, update_plan (activate/pause/complete/abandon), progress. The progress action returns aggregate counts plus a flat entry list with plan_entry_id, learning_target_id, title, position, status, phase — call it before update_entry to look up plan_entry_id. Completing an entry (status=completed) requires a non-blank reason and a completed_by_attempt_id whose learning_target matches the entry's; mismatched IDs are rejected. Skipping an entry (status=skipped) also requires a non-blank reason — skip is a decision and cross-agent review needs to know why an active plan entry was dropped (no force-mode escape hatch for skip). Use force=true with a reason starting with 'manual override:' (≥60 chars) when no aligned attempt exists for completion — the prefix is the audit signal for retroactive completions.",
		FieldEnums: map[string][]string{
			"action": {"add_entries", "remove_entries", "update_entry", "reorder", "update_plan", "progress"},
		},
	}
}

// ArchiveLearningTarget returns metadata for the flat learning-target
// archive tool (formerly the single-action manage_targets multiplexer).
func ArchiveLearningTarget() Meta {
	return Meta{
		Name:        "archive_learning_target",
		Domain:      DomainLearning,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Archive a learning target (soft-delete). When cascade_relations=true (default), every learning_target_relations row referencing it is archived too; the symmetric-reverse edge for same_pattern/similar_structure is auto-cascaded because it sits in the same anchor|related filter. Returns the archived target plus a cascaded_relations list so the caller can show 'what got archived alongside the target' without a follow-up query. Authorization is U2 self-bound — caller must equal the target's created_by, with Platform=human as universal override. Archive is reversible; the archive_batch_id stamped on every cascaded row scopes a future unarchive to exactly this batch, not every relation involving the target.",
	}
}

// SessionProgress returns metadata for the in-session aggregate tool.
func SessionProgress() Meta {
	return Meta{
		Name:        "session_progress",
		Domain:      DomainLearning,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "In-session aggregate for the currently-active learning session: attempt count, elapsed time, paradigm distribution (problem_solving vs immersive with total minutes), concept slug distribution, and observation category (signal_type × category) distribution. Scope is the ACTIVE session only — when no session is active, returns {active: false, last_ended_session_id, last_ended_at} so the caller can pivot to attempt_history(session_id=...) for past-session review; this is an affordance, not a fallback, and aggregate fields are NOT populated for the ended session. Does NOT return concept kind distribution (pattern/skill/principle) because kind is currently auto-assigned to 'skill' for all session-created concepts; tracking would be trivial noise — see HERMES W-10 if kind discrimination becomes meaningful. paradigm_distribution is informational only — most sessions are single-paradigm by design, so do not infer mixing-ratio intent from a 0/N split. Distinct from session_delta, which is a 24h pan-feature snapshot (todos + agent notes + session count) not scoped to any learning_session.",
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

// UpdateNoteMaturity returns metadata for update_note_maturity.
func UpdateNoteMaturity() Meta {
	return Meta{
		Name:        "update_note_maturity",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Transition a note's maturity state. to_maturity one of: seed, stub, evergreen, needs_revision, archived. Any transition permitted (including recovery from archived).",
		FieldEnums: map[string][]string{
			"to_maturity": {"seed", "stub", "evergreen", "needs_revision", "archived"},
		},
	}
}

// SessionDelta returns metadata for the cross-session context bridge.
func SessionDelta() Meta {
	return Meta{
		Name:        "session_delta",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Activity snapshot since a point in time: todos created, todos completed, agent notes written, and learning session count. Returns what happened in the window (not a diff between two sessions, and not scoped to any learning_session). Default lookback: 24 hours. Use when reopening a session mid-day after a break — for the morning briefing call morning_context (today-scoped, broader sections) instead.",
	}
}

// WeeklySummary returns metadata for the week retrospective query.
func WeeklySummary() Meta {
	return Meta{
		Name:        "weekly_summary",
		Domain:      DomainSystem,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Week-level retrospective: todos completed, agent notes grouped by kind, learning session count and domains, concept mastery, and the self_audit block (P0 verification metrics for the Phase 2 audit fixes — force_true_count, solved_after_solution_rate + counts, same_concept_repeated_within_week with threshold >= 3 distinct attempts, skipped_count + skip_reason_prefix_histogram). skip_reason_prefix_histogram buckets reasons by the 'skipped:' soft convention: 'skipped: solved offline' → 'solved offline'; reasons that do NOT start with 'skipped:' or that are empty after the prefix bucket under 'unclassified' (the 'unclassified' share is itself a convention-adherence signal). Defaults to current week (Monday-Sunday). Use Monday for last week's review or any time you need cross-day patterns. For today only, use reflection_context. For since-last-session activity, use session_delta. self_audit is always emitted (slice fields are [] when empty); recommendation_acceptance_rate is intentionally deferred because it requires new tracking infrastructure (see audit decisions memo §E.4).",
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
		WriteAgentNote(),
		QueryAgentNotes(),
		StartSession(),
		RecordAttempt(),
		EndSession(),
		LearningDashboard(),
		RecommendNextTarget(),
		AttemptHistory(),
		ManagePlan(),
		ArchiveLearningTarget(),
		SessionProgress(),
		CreateContent(),
		UpdateContent(),
		SetContentReviewState(),
		PublishContent(),
		ArchiveContent(),
		ListContent(),
		ReadContent(),
		CreateNote(),
		UpdateNote(),
		UpdateNoteMaturity(),
		SessionDelta(),
		WeeklySummary(),
	}
}
