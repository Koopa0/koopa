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
		Description: "Read-only planning-state pull. Pick a mode (required): 'morning' = single-call daily-planning briefing (overdue/today/committed/upcoming todos, active_goals, rss_highlights, content_pipeline); 'reflection' = end-of-day plan-vs-actual retrospective (planned_items + completed/deferred/planned counts + completion_rate). brief is a pure planning-state pull and carries no agent memory. Morning mode is filterable via the sections parameter (ignored in reflection mode) — valid keys (omit or pass [] for all): 'tasks' (overdue/today/committed/upcoming todos), 'goals' (active_goals), 'rss' (rss_highlights — feeds tagged priority=high, NOT relevance-ranked; use search_knowledge for ranked retrieval), 'content_pipeline' (content_pipeline). Per-agent default sections: learning-studio defaults to ['tasks']; every other caller (incl. planner) gets all sections. Scope is the target date (default today), not since-last-session.",
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

// ResolveTask returns metadata for the write half of the proposal-readback
// loop — an agent moves a todo IT created to a terminal state to self-clear it.
func ResolveTask() Meta {
	return Meta{
		Name:        "resolve_task",
		Domain:      DomainDaily,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       "1.5.0",
		Description: "Move a todo YOU created to a terminal state: done (completed), archived (filed away), or dismissed (won't do). Caller-scoped — you can only resolve todos whose created_by = your resolved identity; resolving anyone else's todo returns not-found and changes nothing. Closes the write half of the capture_inbox/list_tasks readback loop: after you read a todo's disposition, resolve_task lets you self-clear the ones you've finished processing instead of leaving them for the owner to archive.",
		FieldEnums: map[string][]string{
			"state": {"done", "archived", "dismissed"},
		},
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
		ProposeArea(),
		ProposeGoal(),
		ProposeProject(),
		ListTasks(),
		ResolveTask(),
		CreateNote(),
		UpdateNote(),
	}
}
