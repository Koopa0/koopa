# MCP Tool Reference

Authoritative source: `internal/mcp/ops/catalog.go::All()`. The inventory
below is GENERATED from it (`go generate ./internal/mcp/ops`); the per-domain
usage detail further down — params and coordination patterns —
is hand-maintained.

## Tool inventory

<!-- GENERATED:TOOL-INVENTORY START — run: go generate ./internal/mcp/ops -->

> Generated from `internal/mcp/ops/catalog.go::All()` — do NOT edit by hand.
> Run `go generate ./internal/mcp/ops` after any change to the tool surface;
> the drift test `TestToolInventoryDocInSync` fails CI if this is stale.

**16 tools** across 3 domains.

| Domain | Count |
|---|---|
| `query` | 3 |
| `daily` | 10 |
| `content` | 3 |
| **Total** | **16** |

| Tool | Domain | Writability | Purpose |
|---|---|---|---|
| `brief` | `query` | read_only | Read-only planning-state pull |
| `project_progress` | `query` | read_only | Read-only PARA momentum/stalled intelligence for Koopa's projects, goals, and areas |
| `review_period` | `query` | read_only | Read-only windowed retrospective of what KOOPA got done over a date window |
| `capture_inbox` | `daily` | additive | Quick todo capture to the inbox |
| `list_inbox` | `daily` | read_only | Read-only owner-triage queue: every todo in state=inbox regardless of who captured it |
| `list_todos` | `daily` | read_only | Read-only readback of the todos you created (created_by = your resolved caller identity) so you can learn their disposition |
| `plan_day` | `daily` | idempotent | Set the day's plan as one atomic replacement |
| `propose_area` | `daily` | additive | Propose a PARA area (ongoing domain of responsibility) as an INERT draft in status=proposed |
| `propose_goal` | `daily` | additive | Propose a goal (with optional ordered milestones) as an INERT draft in status=proposed |
| `propose_project` | `daily` | additive | Propose a NEW project (a short-term effort with a clear outcome) as an INERT draft in status=proposed |
| `resolve_todo` | `daily` | destructive | Move a todo YOU created to a terminal state: done (completed), archived (filed away), or dismissed (won't do) |
| `set_todo_recurrence` | `daily` | destructive | Set or clear the recurrence of a todo YOU created |
| `triage_todo` | `daily` | destructive | Execute the owner's triage verdict on a todo |
| `list_content` | `content` | read_only | Read-only readback of content YOU submitted |
| `propose_content` | `content` | additive | Submit a FINISHED publication snapshot (article, essay, build-log, til, or digest) into the editorial review queue |
| `revise_content` | `content` | destructive | Replace the complete publication snapshot YOU submitted after changing the Vault source first |
<!-- GENERATED:TOOL-INVENTORY END -->

---

## Query — read-only

| Tool | Key params | Returns |
|---|---|---|
| `brief` | `mode` (`morning` / `reflection`), `sections?` (morning only), `date?` | `morning` = single-call daily-planning briefing (overdue/today/active/recurring/committed/upcoming todos, active_goals, rss_highlights, content_pipeline, proposals_pending). `reflection` = end-of-day plan-vs-actual retrospective (planned_items + completed/deferred/planned counts + completion_rate). `mode` is required. Read-only; carries no agent memory. Scope is the target date (default today), not since-last-session. |
| `project_progress` | (none) | Live PARA momentum/stalled intelligence for Koopa's projects, goals, and areas, computed at read time. Returns the owner's full PARA (not caller-scoped): `projects[]` with expected_cadence, days_since_human_activity, open_next_action, milestone_done/total, and a `stalled` flag; `goals[]` with milestone progress + stalled-project rollup; `areas[]` with `area_neglected` (no owner activity attributed to the area via any project, goal, or milestone for >14 days). Progress counts owner activity only (`actor='human'`); agent/system actors never count. |

### `brief` modes and sections

`mode` is required. Two values:

- `morning` — daily-planning briefing.
- `reflection` — end-of-day plan-vs-actual retrospective. The `sections` parameter is ignored in this mode.

Morning mode is filterable via `sections` (omit or pass `[]` for all). Valid keys:

| Section | Returns |
|---|---|
| `todos` | overdue / today / active / recurring / committed / upcoming todos |
| `goals` | active_goals |
| `rss` | rss_highlights — feeds tagged `priority=high`, NOT relevance-ranked |
| `content_pipeline` | content_pipeline |
| `proposals` | proposals_pending — count of agent-proposed area/goal/project drafts awaiting owner triage |

Every caller gets all sections by default; pass an explicit `sections` list to narrow the briefing.

## Daily — personal work

| Tool | Key params | Annotation |
|---|---|---|
| `capture_inbox` | `title`, `description?`, `project?`, `energy?` (`high` / `medium` / `low`), `due?`, recurrence: `weekdays?` OR `interval?`+`unit?` | Additive. Only `title` is required. Status is always `inbox` (captured but not clarified). The owner clarifies and advances it in admin. Use when the user says "add a task", "remind me to", or expresses a concrete work item to capture. `project` may be the slug of an existing or a proposed project (the link survives activation). Optional recurrence captures a routine in one call (vs `capture_inbox` + `set_todo_recurrence`); like `due`/`energy` it is a captured attribute, so the recurring todo stays in `inbox` and dormant (not on the due-today surface) until the owner clarifies it. |
| `plan_day` | `date?`, `items[{todo_id, position?}]` | Idempotent. One atomic replacement (delete-existing + insert-new in one transaction). Each todo MUST already be in `state=todo` or `state=in_progress` — inbox/done/someday/archived/dismissed are rejected (clarify inbox todos via the admin UI first). The `items` list MUST be non-empty; to leave the day unplanned, do not call `plan_day` at all. No auto-carryover — yesterday's unfinished items surface in `brief(mode=morning)` but do not roll forward automatically. `items_removed` reports true displacements only (todos carried over with the same `todo_id` are not reported as removed). |
| `propose_area` | `name`, `proposal_rationale?` | Additive. Drafts a PARA area (ongoing domain of responsibility) as an INERT draft in `status=proposed` — invisible until the owner activates it (no area selector, backs no goal, surfaces only in admin proposals triage). Slug derived from name. Propose only to materialize a theme that surfaced in a conversation the owner was part of; activation (proposed→active) and rejection (hard delete) are owner actions in admin. |
| `propose_goal` | `name`, `milestones?[]`, `area?`, `proposal_rationale?` | Additive. Drafts a goal (with optional ordered milestones) as an INERT draft in `status=proposed` — feeds no list, no alignment, never appears in `brief` or any default goal listing; surfaces only in admin proposals triage. Optionally file under an existing active area's slug/name or a proposed (not-yet-active) area. Activation (proposed→in_progress, so it then appears in `brief`'s active_goals) and rejection (hard delete, milestones cascade) are owner actions in admin. |
| `propose_project` | `name`, `proposal_rationale?` | Additive. Drafts a NEW project (short-term effort with a clear outcome) as an INERT draft in `status=proposed` — invisible until the owner activates it (no project list, picker, or public portfolio; admin proposals triage only). Slug derived from name. `capture_inbox` can link a todo to the proposed project by slug before activation; the link survives activation, and a rejected project's todos are unlinked (not deleted). For an existing project, reference it via `capture_inbox.project` instead. Activation (proposed→in_progress) and rejection (hard delete) are owner actions in admin. |
| `list_todos` | (none) | Read-only. Readback of the todos YOU created (created_by = your resolved caller identity) so you can learn their disposition — accept = `state` todo/done, pending = inbox, reject = absent from the list (the owner triaged it away). Caller-scoped: returns only your own todos. Use to close the `capture_inbox` loop. |
| `resolve_todo` | `id`, `state` (`done` / `archived` / `dismissed`) | Destructive. Move a todo YOU created to a terminal state. Caller-scoped — resolving anyone else's todo returns not-found and changes nothing. The write half of the `capture_inbox`/`list_todos` readback loop: self-clear the todos you've finished processing instead of leaving them for the owner. |

Higher-commitment GTD transitions for the owner's own todos (clarify / start / complete / defer / drop) and inbox-to-todo promotion are admin-UI/HTTP only — off the MCP surface.

Proposals (`propose_area` / `propose_goal` / `propose_project`) only ever materialize a draft from a conversation the owner was part of — never from a scheduled or autonomous run.

---

## Content — propose for review

| Tool | Key params | Annotation |
|---|---|---|
| `propose_content` | `title`, `type` (`article` / `essay` / `build-log` / `til` / `digest`), `body`, `source_vault_path`, `source_git_blob_sha`, `excerpt?`, `slug?`, `topic_ids?[]`, `proposal_rationale?` | Additive. Submits a complete publication snapshot into the editorial review queue. The source path must be Vault-relative Markdown outside Diary; the SHA must be a lowercase 40- or 64-hex Git blob ID. Koopa records this coordinate but never reads the Vault. The row lands in `status=review` with `is_public=false`; only the owner can publish. |
| `list_content` | (none) | Read-only caller-scoped disposition readback. Returns each submitted row's status, review note, source path/blob SHA, and `published_at` when live. These fields are receipt ingredients for an optional external Vault writer; Koopa never writes the Vault. |
| `revise_content` | `id`, `title`, `body`, `excerpt`, `source_vault_path`, `source_git_blob_sha` | Destructive caller-scoped full snapshot replacement. Change the Vault first, then submit all authored fields plus a new blob SHA. The authored fields and provenance move atomically, the row returns to review, and the owner's review note clears. Reusing the existing SHA changes nothing. |

Publishing stays an owner action in admin, off the MCP surface.

---

## Cross-cutting rules

**Caller identity**: every tool accepts optional `as: "<agent_name>"`. There is **no tool-layer authorization** (Option B) — the MCP transport is the access boundary, and `as` only carries attribution + caller-scope (created_by / activity_events.actor / `*ByCreator` readback), resolved in `internal/mcp/server.go::callerIdentity` against the roster in `internal/agent/registry.go::BuiltinAgents()`. A fabricated `as` is rejected by the created_by FK. There is no synthetic fallback caller: the default comes from env `KOOPA_MCP_CALLER_AGENT`, and with none set an `as`-less write is refused at `withActorTx` — every recorded write carries a real, registered agent.

**Read-only forever**: `brief`, `list_todos`, `list_content`, `review_period`, and `project_progress` are read-only by design and will not gain write actions.

**Off the MCP surface**: high-commitment lifecycle steps stay in the admin UI / HTTP — milestone creation, proposal triage (area / goal / project activation + rejection), content publishing, feed curation, and the owner's own todo lifecycle transitions.

**Cross-references**: `docs/backend-semantic-contract.md` §2 (vocabulary), §3 (entity responsibilities), §4 (lifecycles). The canonical tool surface, intent routing, and multiplexer semantics live in `internal/mcp/ops/catalog.go::All()` and the per-tool handlers in `internal/mcp/`.
