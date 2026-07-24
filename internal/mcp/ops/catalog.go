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

// Brief returns metadata for the read-only planning-state multiplexer with two
// modes: morning (daily-planning briefing) and reflection (plan-vs-actual).
func Brief() Meta {
	return Meta{
		Name:        "brief",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Read-only planning-state pull. Pick a mode (required): 'morning' = single-call daily-planning briefing (overdue/today/active/recurring/committed/upcoming todos, active_goals, rss_highlights, content_pipeline, proposals_pending); 'reflection' = end-of-day plan-vs-actual retrospective (planned_items + completed/deferred/planned counts + completion_rate). brief is a pure planning-state pull and carries no agent memory. Morning mode is filterable via the sections parameter (ignored in reflection mode) — valid keys (omit or pass [] for all): 'todos' (overdue/today/active/recurring/committed/upcoming todos), 'goals' (active_goals), 'rss' (rss_highlights — feeds tagged priority=high, not relevance-ranked), 'content_pipeline' (content_pipeline), 'proposals' (proposals_pending — count of agent-proposed area/goal/project drafts awaiting owner triage). Every caller gets all sections by default; pass an explicit sections list to narrow the briefing. Scope is the target date (default today), not since-last-session.",
		FieldEnums: map[string][]string{
			"mode": {"morning", "reflection"},
		},
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
		Description: "Quick todo capture to the inbox. Only title is required. Status is always inbox. Optionally attach a recurrence (weekdays OR interval+unit) to capture a routine in one call instead of capture + set_todo_recurrence; like due/energy it is a captured attribute, so the recurring todo stays in inbox and dormant until the owner clarifies it. Use when the user says 'add a task', 'remind me to', or expresses a concrete work item to capture.",
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
		Description: "Set the day's plan as one atomic replacement. Each todo MUST be in state=todo or in_progress (inbox/done/someday/archived/dismissed rejected — clarify inbox todos via the admin UI first). The items list MUST be non-empty; to leave the day unplanned, do not call plan_day at all. The whole call (delete-existing + insert-new) runs in one transaction, so any per-item validation failure rolls back to the previous plan. items_removed reports todos that were in the previous plan but are NOT in the new list (true displacements only — todos carried over with the same todo_id are not reported as removed even though their plan_item row gets a new id).",
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
		Description: "Propose a goal (with optional ordered milestones) as an INERT draft in status=proposed. A proposed goal feeds no list, no alignment, and never appears in brief or any default goal listing — it surfaces only in the admin proposals triage. Optionally file it under an area: an existing ACTIVE area's slug/name, or an area that has been proposed but not yet activated (the proposal bundle). Propose only to materialize an objective that surfaced in a conversation the owner was part of — NEVER from scheduled or autonomous runs. Activation (proposed→in_progress — it starts being tracked, so it appears in brief's active_goals immediately) and rejection (hard delete, milestones cascade) are owner actions in admin, not MCP.",
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
		Description: "Propose a NEW project (a short-term effort with a clear outcome) as an INERT draft in status=proposed. A proposed project is invisible until the owner activates it — it appears in no project list or picker, surfacing only in the admin proposals triage. The slug is derived from name. capture_inbox can still link a todo to the proposed project by slug before activation; the link survives activation, and a rejected project's todos are unlinked (not deleted). Reference an EXISTING project directly via capture_inbox.project — propose_project is for genuinely-new projects only. Propose only to materialize a project that surfaced in a conversation the owner was part of — NEVER from scheduled or autonomous runs. Activation (proposed→in_progress) and rejection (hard delete) are owner actions in admin, not MCP.",
	}
}

// ProposeContent returns metadata for the agent content-proposal tool — a
// finished content draft pushed into the editorial review queue for the owner
// to publish or reject.
func ProposeContent() Meta {
	return Meta{
		Name:        "propose_content",
		Domain:      DomainContent,
		Writability: Additive,
		Stability:   StabilityStable,
		Since:       "1.8.0",
		Description: "Submit a FINISHED publication snapshot (article, essay, build-log, til, or digest) into the editorial review queue. Required: title, type, body, source_vault_path, and source_git_blob_sha. The source coordinate must identify the Vault-relative Markdown file and its lowercase Git blob object ID; Koopa records but does not fetch or verify Vault bytes. The row always lands in review/private and cannot be edited in Koopa. The owner can publish or send it back; an agent can never publish. Optional: excerpt, slug, topic_ids, and proposal_rationale.",
		FieldEnums: map[string][]string{
			"type": {"article", "essay", "build-log", "til", "digest"},
		},
	}
}

// ListTodos returns metadata for the read-only proposal-readback tool — an
// agent reads the disposition of the todos it created.
func ListTodos() Meta {
	return Meta{
		Name:        "list_todos",
		Domain:      DomainDaily,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.3.0",
		Description: "Read-only readback of the todos you created (created_by = your resolved caller identity) so you can learn their disposition — accept = state todo/done, pending = inbox, reject = absent from this list (the owner triages in admin; a rejected proposal simply disappears). Caller-scoped: returns only your own todos, never the owner's personal todos or another agent's. Use to close the capture_inbox loop — after you push a suggestion, list_todos shows how the owner acted on it.",
	}
}

// ResolveTodo returns metadata for the write half of the proposal-readback
// loop — an agent moves a todo IT created to a terminal state to self-clear it.
func ResolveTodo() Meta {
	return Meta{
		Name:        "resolve_todo",
		Domain:      DomainDaily,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       "1.5.0",
		Description: "Move a todo YOU created to a terminal state: done (completed), archived (filed away), or dismissed (won't do). Caller-scoped — you can only resolve todos whose created_by = your resolved identity; resolving anyone else's todo returns not-found and changes nothing. Closes the write half of the capture_inbox/list_todos readback loop: after you read a todo's disposition, resolve_todo lets you self-clear the ones you've finished processing instead of leaving them for the owner to archive. SPECIAL CASE — if the todo is recurring (see set_todo_recurrence), state=done completes TODAY's occurrence (stamps the last-completed date and keeps the todo recurring) rather than closing it; archived/dismissed still stop the recurrence for good.",
		FieldEnums: map[string][]string{
			"state": {"done", "archived", "dismissed"},
		},
	}
}

// SetTodoRecurrence returns metadata for the agent recurrence-scheduling tool —
// it turns a caller-created todo into a weekday- or interval-recurring one (or
// clears it). Recurrence drives the compute-on-read due-today surface.
func SetTodoRecurrence() Meta {
	return Meta{
		Name:        "set_todo_recurrence",
		Domain:      DomainDaily,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       since,
		Description: "Set or clear the recurrence of a todo YOU created. Weekday-mode: pass weekdays (any of mon,tue,wed,thu,fri,sat,sun) — e.g. Mon-Sat for a six-day-a-week habit, or all seven for daily. Interval-mode: pass interval + unit (days/weeks/months/years) to recur every N units measured from the last completion (self-pacing). Pass clear=true to make the todo a one-shot again. Exactly one mode per call; weekday and interval are mutually exclusive. Caller-scoped — you can only schedule todos whose created_by = your resolved identity. A recurring todo surfaces in the morning brief and the recurring view on every day its rule matches; resolve_todo state=done then completes that day's occurrence and the todo keeps recurring.",
	}
}

// ListInbox returns metadata for the read half of the owner triage loop —
// the cross-creator inbox queue, every capture regardless of creator.
func ListInbox() Meta {
	return Meta{
		Name:        "list_inbox",
		Domain:      DomainDaily,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.10.0",
		Description: "Read-only owner-triage queue: every todo in state=inbox regardless of who captured it — cross-creator BY DESIGN, unlike the caller-scoped list_todos. Each row carries id, title, created_by, age_days (whole days since capture), and description (empty string when absent); ordering is created_at ascending, so the longest-waiting capture comes first. Use it to ground a triage conversation before executing the owner's verdicts with triage_todo. Call it only in conversations the owner is present in — NEVER from scheduled or autonomous runs; the Hermes contract forbids using list_inbox and triage_todo. list_inbox itself writes nothing, and every triage mutation that follows leaves an audit trail.",
	}
}

// TriageTodo returns metadata for the write half of the owner triage loop —
// executing the owner's verdict on an inbox (or mis-triaged) todo.
func TriageTodo() Meta {
	return Meta{
		Name:        "triage_todo",
		Domain:      DomainDaily,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       "1.10.0",
		Description: "Execute the owner's triage verdict on a todo — cross-creator BY DESIGN: it carries out the owner's decision, not caller self-cleanup, so it reaches any creator's row. Verdicts: 'accept' (inbox → todo), 'someday' (inbox → someday), 'dismiss' (inbox → dismissed) — these three act only on state=inbox; 'restore' (dismissed|someday → inbox) recovers a mis-triaged todo. The optional project, due (YYYY-MM-DD), and energy fields are valid only with accept and are rejected for every other verdict; omitted accept fields preserve the values captured on the row, and recurrence fields are never touched. Call it only in conversations the owner is present in — NEVER from scheduled or autonomous runs; the Hermes contract forbids using list_inbox and triage_todo. Every triage mutation leaves an audit trail attributed to the calling agent.",
		FieldEnums: map[string][]string{
			"verdict": {"accept", "someday", "dismiss", "restore"},
			"energy":  {"high", "medium", "low"},
		},
	}
}

// ProjectProgress returns metadata for the read-only PARA momentum/stalled
// tool — the owner's project/goal/area progress intelligence, computed live.
func ProjectProgress() Meta {
	return Meta{
		Name:        "project_progress",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.7.0",
		Description: "Read-only PARA momentum/stalled intelligence for Koopa's projects, goals, and areas — computed LIVE at read time, nothing stored. No parameters: it always returns the owner's full PARA, not a caller-scoped view. projects[]: every candidate project (status in_progress|planned) with its expected_cadence, last_human_activity_at, days_since_human_activity, open_next_action (has an open todo OR an incomplete milestone), milestone_done/total, and a stalled flag. expected_cadence is optional — a project without one still appears, with expected_cadence \"\" and stalled always false (no threshold to exceed). stalled = days_since_human_activity > 2× the cadence period (daily=1, weekly=7, biweekly=14, monthly=30 days) AND there is an open next action — a project with no open next action is '待規劃' (to-plan), never stalled. goals[]: each active goal with milestone progress and a rollup of how many of its projects are stalled. areas[]: each active area with area_neglected (no human activity attributed to the area — via any project, goal, or milestone — for >14 days). HUMAN ACTIVITY ONLY: progress counts solely activity_events by the owner (actor='human'); agent/system actors (hermes, codex, …) never count as progress. Read this to ground a conversation in what has gone quiet, never to change anything.",
	}
}

// ListContent returns metadata for the read-only content-readback tool — an
// agent reads the disposition of the content it proposed, including the owner's
// review_note when a draft was sent back for changes.
func ListContent() Meta {
	return Meta{
		Name:        "list_content",
		Domain:      DomainContent,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.9.0",
		Description: "Read-only readback of content YOU submitted. It returns disposition, review_note, the exact source_vault_path/source_git_blob_sha binding, and published_at when live. Caller-scoped: it never exposes the owner's or another agent's content. Use the published fields as receipt ingredients for an optional external Vault writer; Koopa itself never writes the Vault.",
	}
}

// ReviseContent returns metadata for the caller-scoped content revision tool —
// an agent edits its own review/changes_requested content back into review.
func ReviseContent() Meta {
	return Meta{
		Name:        "revise_content",
		Domain:      DomainContent,
		Writability: Destructive,
		Stability:   StabilityStable,
		Since:       "1.9.0",
		Description: "Replace the complete publication snapshot YOU submitted after changing the Vault source first. Required: id, complete title/body/excerpt, source_vault_path, and a NEW source_git_blob_sha. Authored fields and provenance update atomically, the row returns to review, and review_note clears. Reusing the current SHA or targeting another caller/non-revisable row changes nothing. Publishing remains owner-only.",
	}
}

// ReviewPeriod returns metadata for the read-only windowed owner retrospective —
// what the owner got done across a date window, computed live.
func ReviewPeriod() Meta {
	return Meta{
		Name:        "review_period",
		Domain:      DomainQuery,
		Writability: ReadOnly,
		Stability:   StabilityStable,
		Since:       "1.9.0",
		Description: "Read-only windowed retrospective of what KOOPA got done over a date window — computed LIVE from the activity log at read time, nothing stored. Required: since (YYYY-MM-DD). Optional: until (YYYY-MM-DD, default today); the window is whole-day-inclusive in the owner's timezone. Returns completed_todos and completed_milestones (with project/area/goal context), goals[] (every active goal with milestone progress and an advanced flag for the window), areas[] (each active area's activity_count — of all activity attributed to it across project, goal, and milestone — and a neglected flag), published_content, and a counts headline (todos_completed/opened, milestones_completed, content_published, areas_active/neglected, active_days). Owner-scoped, NOT caller-scoped — it always returns the single owner's retrospective. HUMAN ACTIVITY ONLY for progress: counts solely activity by the owner (actor='human'); the one exception is todos_opened, which counts backlog inflow from all actors. Read this to ground a conversation in what the owner actually accomplished in a period, never to change anything.",
	}
}

// All returns every tool meta in stable registration order. The order
// mirrors the addTool call sequence in internal/mcp/server.go and is
// enforced by TestOpsCatalogDrift. Adding a new tool requires appending
// an accessor here and registering a handler in the mcp package.
func All() []Meta {
	return []Meta{
		Brief(),
		CaptureInbox(),
		PlanDay(),
		ProposeArea(),
		ProposeGoal(),
		ProposeProject(),
		ProposeContent(),
		ListTodos(),
		ResolveTodo(),
		SetTodoRecurrence(),
		ListInbox(),
		TriageTodo(),
		ProjectProgress(),
		ListContent(),
		ReviseContent(),
		ReviewPeriod(),
	}
}
