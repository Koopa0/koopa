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

// Brief returns metadata for the read-only planning-state multiplexer that
// replaces the former morning_context + reflection_context tools.
func Brief() Meta {
	return Meta{
		Name:        "brief",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Read-only planning-state pull. Pick a mode (required): 'morning' = single-call daily-planning briefing (overdue/today/committed/upcoming todos, active_goals, unverified_hypotheses, rss_highlights, content_pipeline); 'reflection' = end-of-day plan-vs-actual retrospective (planned_items + completed/deferred/planned counts + completion_rate). brief is a pure planning-state pull and carries no agent memory. Morning mode is filterable via the sections parameter (ignored in reflection mode) — valid keys (omit or pass [] for all): 'tasks' (overdue/today/committed/upcoming todos), 'goals' (active_goals), 'hypotheses' (unverified_hypotheses), 'rss' (rss_highlights — feeds tagged priority=high, NOT relevance-ranked; use search_knowledge for ranked retrieval), 'content_pipeline' (content_pipeline). Per-agent default sections: learning-studio defaults to ['tasks', 'hypotheses']; every other caller (incl. planner) gets all sections. Scope is the target date (default today), not since-last-session.",
		FieldEnums: map[string][]string{
			"mode": {"morning", "reflection"},
		},
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
		Description: "Search across content (articles, build logs, TILs, etc.) and notes (Zettelkasten) — i.e. what we KNOW. CURRENT behavior: PostgreSQL full-text search (lexical, tsvector + websearch syntax, GIN-indexed) only — there is no production document-embedding write path today, so the semantic / pgvector branch returns no rows for app-created content. Hybrid lexical + pgvector + RRF is PLANNED but not active; do not assume semantic recall. Filters: source_types (default both), content_type (implies content-only; mutex with note_kind), note_kind (implies note-only; mutex with content_type), project, date range.",
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
		Description: "End the active learning session. Returns session summary with all attempts.",
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

// DraftHypothesis returns metadata for the agent hypothesis-drafting tool —
// the only write surface that produces an inert draft for the owner to act on.
func DraftHypothesis() Meta {
	return Meta{
		Name:        "draft_hypothesis",
		Domain:      DomainLearning,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       "1.1.0",
		Description: "Draft a falsifiable learning hypothesis (claim + invalidation_condition) in state=draft. A draft is INERT until the owner endorses it in the admin UI — it feeds no dashboard, counts toward no progress, and never appears in brief(morning), the Today page, or any default listing. Draft only to materialize a pattern that surfaced in a conversation the owner was part of — NEVER from scheduled or autonomous runs. Use when the user exhibits a recurring, falsifiable pattern (e.g. 'graph 題每次卡在 DFS 終止條件'). Endorsement (draft→unverified), verdicts (verify/invalidate), and draft deletion are owner actions in admin, not MCP.",
	}
}

// ProposeArea returns metadata for the agent area-proposal tool — an inert
// PARA-theme draft for the owner to activate or reject in admin triage.
func ProposeArea() Meta {
	return Meta{
		Name:        "propose_area",
		Domain:      DomainDaily,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       "1.2.0",
		Description: "Propose a PARA area (ongoing domain of responsibility) as an INERT draft in status=proposed. A proposed area is invisible until the owner activates it — it appears in no area selector, backs no goal, and surfaces only in the admin proposals triage. The slug is derived from name. Propose only to materialize a theme that surfaced in a conversation the owner was part of — NEVER from scheduled or autonomous runs. Activation (proposed→active) and rejection (hard delete) are owner actions in admin, not MCP.",
	}
}

// ProposeGoal returns metadata for the agent goal-proposal tool — an inert
// goal+milestones draft for the owner to activate or reject in admin triage.
func ProposeGoal() Meta {
	return Meta{
		Name:        "propose_goal",
		Domain:      DomainDaily,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       "1.2.0",
		Description: "Propose a goal (with optional ordered milestones) as an INERT draft in status=proposed. A proposed goal feeds no list, no alignment, and never appears in brief or any default goal listing — it surfaces only in the admin proposals triage. Optionally file it under an area: an existing ACTIVE area's slug/name, or an area that has been proposed but not yet activated (the proposal bundle). Propose only to materialize an objective that surfaced in a conversation the owner was part of — NEVER from scheduled or autonomous runs. Activation (proposed→not_started) and rejection (hard delete, milestones cascade) are owner actions in admin, not MCP.",
	}
}

// ProposeProject returns metadata for the agent project-proposal tool — an
// inert project draft for the owner to activate or reject in admin triage.
func ProposeProject() Meta {
	return Meta{
		Name:        "propose_project",
		Domain:      DomainDaily,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       "1.4.0",
		Description: "Propose a NEW project (a short-term effort with a clear outcome) as an INERT draft in status=proposed. A proposed project is invisible until the owner activates it — it appears in no project list or picker and no public portfolio, surfacing only in the admin proposals triage. The slug is derived from name. capture_inbox can still link a todo to the proposed project by slug before activation; the link survives activation, and a rejected project's todos are unlinked (not deleted). Reference an EXISTING project directly via capture_inbox.project — propose_project is for genuinely-new projects only. Propose only to materialize a project that surfaced in a conversation the owner was part of — NEVER from scheduled or autonomous runs. Activation (proposed→in_progress) and rejection (hard delete) are owner actions in admin, not MCP.",
	}
}

// ListTasks returns metadata for the read-only proposal-readback tool — an
// agent reads the disposition of the todos it created.
func ListTasks() Meta {
	return Meta{
		Name:        "list_tasks",
		Domain:      DomainDaily,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.3.0",
		Description: "Read-only readback of the todos you created (created_by = your resolved caller identity) so you can learn their disposition — accept = state todo/done, pending = inbox, reject = absent from this list (the owner triages in admin; a rejected proposal simply disappears). Caller-scoped: returns only your own todos, never the owner's personal todos or another agent's. Use to close the capture_inbox loop — after you push a suggestion, list_tasks shows how the owner acted on it.",
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
		Description: "Update editable fields (slug / title / body / kind) on a note. Maturity is not editable via the MCP surface.",
	}
}

// All returns every tool meta in stable registration order. The order
// mirrors the addTool call sequence in internal/mcp/server.go and is
// enforced by TestOpsCatalogDrift. Adding a new tool requires appending
// an accessor here and registering a handler in the mcp package.
func All() []Meta {
	return []Meta{
		Brief(),
		SearchKnowledge(),
		CaptureInbox(),
		PlanDay(),
		StartSession(),
		RecordAttempt(),
		EndSession(),
		LearningRead(),
		ManagePlan(),
		DraftHypothesis(),
		ProposeArea(),
		ProposeGoal(),
		ProposeProject(),
		ListTasks(),
		CreateNote(),
		UpdateNote(),
	}
}
