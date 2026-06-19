# MCP Tool Reference

Authoritative source: `internal/mcp/ops/catalog.go::All()`. The inventory
below is GENERATED from it (`go generate ./internal/mcp/ops`); the per-domain
usage detail further down — params, search mechanics, coordination patterns —
is hand-maintained.

## Tool inventory

<!-- GENERATED:TOOL-INVENTORY START — run: go generate ./internal/mcp/ops -->

> Generated from `internal/mcp/ops/catalog.go::All()` — do NOT edit by hand.
> Run `go generate ./internal/mcp/ops` after any change to the tool surface;
> the drift test `TestToolInventoryDocInSync` fails CI if this is stale.

**16 tools** across 4 domains.

| Domain | Count |
|---|---|
| `query` | 2 |
| `daily` | 6 |
| `learning` | 6 |
| `content` | 2 |
| **Total** | **16** |

| Tool | Domain | Writability | Purpose |
|---|---|---|---|
| `brief` | `query` | read_only | Read-only planning-state pull |
| `search_knowledge` | `query` | read_only | Search across content (articles, build logs, TILs, etc.) and notes (Zettelkasten) |
| `capture_inbox` | `daily` | additive | Quick task capture to inbox |
| `list_tasks` | `daily` | read_only | Read-only readback of the todos you created (created_by = your resolved caller identity) so you can learn their disposition |
| `plan_day` | `daily` | idempotent | Set the day's plan as one atomic replacement |
| `propose_area` | `daily` | additive | Propose a PARA area (ongoing domain of responsibility) as an INERT draft in status=proposed |
| `propose_goal` | `daily` | additive | Propose a goal (with optional ordered milestones) as an INERT draft in status=proposed |
| `propose_project` | `daily` | additive | Propose a NEW project (a short-term effort with a clear outcome) as an INERT draft in status=proposed |
| `draft_hypothesis` | `learning` | additive | Draft a falsifiable learning hypothesis (claim + invalidation_condition) in state=draft |
| `end_session` | `learning` | additive | End the active learning session |
| `learning_read` | `learning` | read_only | Read-only learning analytics |
| `manage_plan` | `learning` | destructive | Learning plan lifecycle and entries |
| `record_attempt` | `learning` | additive | Record an attempt within the active learning session |
| `start_session` | `learning` | additive | Begin a learning session |
| `create_note` | `content` | additive | Create a Zettelkasten note (notes table) |
| `update_note` | `content` | additive | Update editable fields (slug / title / body / kind) on a note |
<!-- GENERATED:TOOL-INVENTORY END -->

---

## Query — read-only

| Tool | Key params | Returns |
|---|---|---|
| `brief` | `mode` (`morning` / `reflection`), `sections?` (morning only), `date?` | `morning` = single-call daily-planning briefing (overdue/today/committed/upcoming todos, active_goals, unverified_hypotheses, rss_highlights, content_pipeline). `reflection` = end-of-day plan-vs-actual retrospective (planned_items + completed/deferred/planned counts + completion_rate). `mode` is required. Read-only; carries no agent memory. Scope is the target date (default today), not since-last-session. |
| `search_knowledge` | `query`, `source_types?`, `content_type?`, `note_kind?`, `project?`, `after?`, `before?`, `limit?` | FTS retrieval over contents and notes. See Search section below. |

### `brief` modes and sections

`mode` is required. Two values:

- `morning` — daily-planning briefing.
- `reflection` — end-of-day plan-vs-actual retrospective. The `sections` parameter is ignored in this mode.

Morning mode is filterable via `sections` (omit or pass `[]` for all). Valid keys:

| Section | Returns |
|---|---|
| `tasks` | overdue / today / committed / upcoming todos |
| `goals` | active_goals |
| `hypotheses` | unverified_hypotheses |
| `rss` | rss_highlights — feeds tagged `priority=high`, NOT relevance-ranked; use `search_knowledge` for ranked retrieval |
| `content_pipeline` | content_pipeline |

Per-agent default sections: `learning-studio` defaults to `['tasks', 'hypotheses']`; every other caller (incl. `planner`) gets all sections. Explicit `sections` always wins.

### `search_knowledge` retrieval

CURRENT behavior is PostgreSQL full-text search only (lexical, tsvector + websearch syntax, GIN-indexed). There is no production document-embedding write path today, so the semantic / pgvector branch returns no rows for app-created content. Hybrid lexical + pgvector + RRF is PLANNED but not active — do not assume semantic recall.

- **FTS**: `websearch_to_tsquery('simple', query)` on the search vectors (GIN).
- Searches across content (articles, build logs, TILs, etc.) and notes (Zettelkasten).

Filters:

- `source_types` — default both (content + notes).
- `content_type` — implies content-only; mutually exclusive with `note_kind`.
- `note_kind` — implies note-only; mutually exclusive with `content_type`.
- `project`, `after`, `before`, `limit`.

Query syntax (websearch):

- Quoted phrases: `"value semantics"` — exact match.
- AND (default): `Go generics` — both words appear.
- OR: `goroutine OR channel`.
- Exclusion: `-draft`.

Visibility: `search_knowledge` sees all statuses including drafts and private — it is the internal-search surface, not the public-site search.

---

## Daily — personal work

| Tool | Key params | Annotation |
|---|---|---|
| `capture_inbox` | `title`, `due?`, `project?`, `priority?`, `energy?` (`high` / `medium` / `low`) | Additive. Only `title` is required. Status is always `inbox` (captured but not clarified). Use when the user says "add a task", "remind me to", or expresses a concrete work item to capture. |
| `plan_day` | `date?`, `items[{todo_id, reason?, position?}]` | Idempotent. One atomic replacement (delete-existing + insert-new in one transaction). Each todo MUST already be in `state=todo` — inbox/done/someday are rejected (clarify inbox todos to `state=todo` via the admin UI first). The `items` list MUST be non-empty; to leave the day unplanned, do not call `plan_day` at all. No auto-carryover — yesterday's unfinished items surface in `brief(mode=morning)` but do not roll forward automatically. `items_removed` reports true displacements only (todos carried over with the same `task_id` are not reported as removed). |

Higher-commitment GTD transitions (clarify / start / complete / defer / drop) and inbox-to-todo promotion are admin-UI/HTTP only — off the MCP surface.

---

## Learning

| Tool | Key params | Annotation |
|---|---|---|
| `start_session` | `domain`, `mode` (`retrieval` / `practice` / `mixed` / `review` / `reading`) | Additive. Validates no other active session exists (at most one globally). Use when the user wants to start a learning/practice session. |
| `record_attempt` | `target{title, external_id?, domain?}`, `outcome`, `time_spent_minutes?`, `stuck_at?`, `approach_used?`, `metadata?`, `observations?[]`, `related_targets?[]` | Additive. Requires an active session. Accepts semantic `outcome` values ("got it", "needed help", "gave up") mapped to schema enums by session mode; response echoes `canonical_outcome`. Auto-creates learning targets and concepts. See partial-write contract below. |
| `end_session` | `session_id`, `summary?` | Additive. Ends the active session; returns session summary with all attempts. |
| `learning_read` | `view` (`overview` / `next_target` / `attempts` / `session_progress`), view-specific fields | Read-only. See views below. |
| `manage_plan` | `action` (`add_entries` / `remove_entries` / `update_entry` / `reorder` / `progress`), `plan_id`, action-specific fields | Destructive. See actions + entry-completion below. |

### `record_attempt` outcomes and partial-write contract

`outcome` accepts canonical DB enums and semantic synonyms (mapped by session mode):

- Canonical: `solved_independent`, `solved_with_hint`, `solved_after_solution`, `completed`, `completed_with_support`, `incomplete`, `gave_up`.
- Synonyms (problem_solving): "got it", "solved it", "nailed it", "needed help", "needed a hint", "got help", "saw answer", "saw the answer", "saw the answer first", "didn't finish", "not done", "gave up", "stuck".
- Synonyms (immersive): "finished", "done", "needed support".

Partial-write contract: `observations` are validated per-element. `severity` is only valid for `signal='weakness'`; passing it on `mastery`/`improvement` rejects that observation only — siblings still try independently and the attempt row still persists. `observations_recorded < input length` is therefore legal; rejected indices are named in `observation_warnings`. Same per-element semantics apply to `related_targets` (`relations_linked < len(related_targets)` is legal; rejects land in `relation_warnings`). `attempt_number` is PER-TARGET (count of attempts on this `learning_target_id` across all sessions), not per-session — for session-scoped count use `learning_read(view=session_progress)`'s `attempt_count`.

### `learning_read` views

| view | Params | Returns |
|---|---|---|
| `overview` (default-style) | `domain?`, `window_days?` | Recent learning sessions list. |
| `next_target` | `session_id` (active), `count?`, `exclude_patterns?[]` | In-session next-problem recommendation combining weakness analysis with the untried-variation graph. |
| `attempts` | exactly one of `target{title+domain}` / `concept_slug(+domain?)` / `session_id` | Attempt history; each attempt carries its observation list with confidence labels. `concept_slug` mode adds `matched_observation_id`. `resolved=false` means the lookup target does not exist (a legal answer). |
| `session_progress` | (active session) | In-session aggregate: attempt count, elapsed time, paradigm/concept/category distributions. When no session is active returns `{active:false, last_ended_session_id}`. |

The former dashboard `mastery` / `weaknesses` / `timeline` / `variations` / `retrieval` views are NOT on the MCP surface — they remain HTTP-admin-only.

### `manage_plan` actions and entry completion

Actions: `add_entries` (accepts `learning_target_id` OR `title` for find-or-create using plan domain), `remove_entries` (draft plans only), `update_entry` (complete / skip / substitute), `reorder`, `progress` (read-only — returns aggregate counts plus a flat entry list with `plan_entry_id`, `learning_target_id`, `title`, `position`, `status`, `phase`; call it before `update_entry` to look up `plan_entry_id`).

Plan-status transitions (draft → active → completed/paused/abandoned) are admin-UI/HTTP only — `manage_plan` has no `update_plan` action.

Completing an entry (`status=completed`) requires:

- `completed_by_attempt_id` — policy-mandatory; the attempt's `learning_target` must match the entry's (mismatched IDs are rejected).
- `reason` — non-blank, includes attempt outcome.

Skipping an entry (`status=skipped`) also requires a non-blank `reason` (no force-mode escape hatch for skip). For completion only, use `force=true` with a `reason` starting with `manual override:` (≥60 chars) when no aligned attempt exists — the prefix is the audit signal for retroactive completions.

---

## Notes (Zettelkasten)

Separate entity, separate package. Notes are Koopa-private and mature in place; they do not publish.

| Tool | Key params | Annotation |
|---|---|---|
| `create_note` | `title`, `body`, `kind`, `slug?`, `concepts?`, `target_ids?` | Additive. Creates at `seed` maturity. `kind` one of `solve-note` / `concept-note` / `debug-postmortem` / `decision-log` / `reading-note` / `musing`. |
| `update_note` | `id`, `slug?` / `title?` / `body?` / `kind?` patches | Additive. Maturity is NOT editable via the MCP surface (maturity transitions are admin-UI/HTTP only). |

---

## Cross-cutting rules

**Caller identity**: every tool accepts optional `as: "<agent_name>"`. Server trusts the `as` value and authorizes by identity (platform / author / self) in `internal/mcp/authz.go`, against the roster in `internal/agent/registry.go::BuiltinAgents()`. Default caller is from env `KOOPA_MCP_CALLER_AGENT`.

**Read-only forever**: `brief` and `learning_read` are read-only by design and will not gain write actions.

**Off the MCP surface**: high-commitment entities (goals / projects / milestones / hypotheses, learning-plan activation, content authoring + publishing, note maturity, feed curation, todo lifecycle transitions) are admin-UI/HTTP only.

**Cross-references**: `docs/backend-semantic-contract.md` §2 (vocabulary), §3 (entity responsibilities), §4 (lifecycles). The canonical tool surface, intent routing, and multiplexer semantics live in `internal/mcp/ops/catalog.go::All()` and the per-tool handlers in `internal/mcp/`.
