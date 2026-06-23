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

**16 tools** across 3 domains.

| Domain | Count |
|---|---|
| `query` | 6 |
| `daily` | 7 |
| `content` | 3 |
| **Total** | **16** |

| Tool | Domain | Writability | Purpose |
|---|---|---|---|
| `brief` | `query` | read_only | Read-only planning-state pull |
| `get_reading` | `query` | read_only | Read-only fetch of one book by id, returning the reading (incl |
| `list_readings` | `query` | read_only | Read-only list of Koopa's reading shelf |
| `project_progress` | `query` | read_only | Read-only PARA momentum/stalled intelligence for Koopa's projects, goals, and areas |
| `review_period` | `query` | read_only | Read-only windowed retrospective of what KOOPA got done over a date window |
| `search_knowledge` | `query` | read_only | Read-only search across Koopa's corpus: content (articles, essays, build-logs, TILs, digests), the reading shelf (books + reading diary), and the ヨルシカ… |
| `capture_inbox` | `daily` | additive | Quick task capture to inbox |
| `list_tasks` | `daily` | read_only | Read-only readback of the todos you created (created_by = your resolved caller identity) so you can learn their disposition |
| `plan_day` | `daily` | idempotent | Set the day's plan as one atomic replacement |
| `propose_area` | `daily` | additive | Propose a PARA area (ongoing domain of responsibility) as an INERT draft in status=proposed |
| `propose_goal` | `daily` | additive | Propose a goal (with optional ordered milestones) as an INERT draft in status=proposed |
| `propose_project` | `daily` | additive | Propose a NEW project (a short-term effort with a clear outcome) as an INERT draft in status=proposed |
| `resolve_task` | `daily` | destructive | Move a todo YOU created to a terminal state: done (completed), archived (filed away), or dismissed (won't do) |
| `list_content` | `content` | read_only | Read-only readback of the content YOU proposed (created_by = your resolved caller identity) so you can learn its disposition |
| `propose_content` | `content` | additive | Propose a FINISHED content piece (article, essay, build-log, til, or digest) into the editorial review queue |
| `revise_content` | `content` | destructive | Revise content YOU created that is in review or changes_requested, returning it to the review queue and clearing the owner's review_note |
<!-- GENERATED:TOOL-INVENTORY END -->

---

## Query — read-only

| Tool | Key params | Returns |
|---|---|---|
| `brief` | `mode` (`morning` / `reflection`), `sections?` (morning only), `date?` | `morning` = single-call daily-planning briefing (overdue/today/committed/upcoming todos, active_goals, rss_highlights, content_pipeline). `reflection` = end-of-day plan-vs-actual retrospective (planned_items + completed/deferred/planned counts + completion_rate). `mode` is required. Read-only; carries no agent memory. Scope is the target date (default today), not since-last-session. |
| `search_knowledge` | `query`, `source_types?`, `content_type?`, `after?`, `before?`, `limit?` | Hybrid (FTS + pgvector) retrieval over content + the reading shelf + the ヨルシカ song shelf. See Search section below. |
| `list_readings` | `status?` (`want_to_read` / `reading` / `finished` / `abandoned`) | One entry per book on Koopa's reading shelf — title, author, status, started_on/finished_on, is_public, optional goal_id. Omit `status` for the whole shelf. Read access only; the shelf has no agent write path. |
| `get_reading` | `id` | One book plus its full reflection thread — dated diary entries in entry_date order (created_at tiebreak). Use after `list_readings` to read Koopa's notes on a specific book. Read access only. |
| `project_progress` | (none) | Live PARA momentum/stalled intelligence for Koopa's projects, goals, and areas, computed at read time. Returns the owner's full PARA (not caller-scoped): `projects[]` with expected_cadence, days_since_human_activity, open_next_action, milestone_done/total, and a `stalled` flag; `goals[]` with milestone progress + stalled-project rollup; `areas[]` with `area_neglected`. Progress counts owner activity only (`actor='human'`); agent/system actors never count. |

### `brief` modes and sections

`mode` is required. Two values:

- `morning` — daily-planning briefing.
- `reflection` — end-of-day plan-vs-actual retrospective. The `sections` parameter is ignored in this mode.

Morning mode is filterable via `sections` (omit or pass `[]` for all). Valid keys:

| Section | Returns |
|---|---|
| `tasks` | overdue / today / committed / upcoming todos |
| `goals` | active_goals |
| `rss` | rss_highlights — feeds tagged `priority=high`, NOT relevance-ranked; use `search_knowledge` for ranked retrieval |
| `content_pipeline` | content_pipeline |

Every caller gets all sections by default; pass an explicit `sections` list to narrow the briefing.

### `search_knowledge` retrieval

Read-only hybrid retrieval over three corpora, each searched independently and then interleaved by per-corpus rank:

- **content** — articles, essays, build-logs, TILs, digests.
- **reading** — the reading shelf (books) plus the reading diary. A diary-entry hit folds under its parent book (same `source_type=reading`), linking back via the book's id/title; the excerpt is the diary body (or the book title for a shelf hit). Use `get_reading` with the returned id to read the full thread.
- **song** — the ヨルシカ song shelf plus its reflection diary. A reflection hit folds under its parent song (`source_type=song`); the excerpt is the reflection body (or the song title for a shelf hit). This is the song shelf's only agent-visible surface, and it is read-only.

Each corpus runs FTS fused with pgvector semantic search via reciprocal-rank fusion (RRF):

- **FTS**: `websearch_to_tsquery('simple', query)` on the per-table generated `search_vector` (GIN).
- **Semantic**: query embedded once (gemini-embedding-2), cosine-ranked over the corpus's `embedding` column (HNSW). A background reconciler fills embeddings as rows land; without `GEMINI_API_KEY` the semantic branch is skipped and search degrades to FTS-only.

Reflections are NOT a separate source type — they always surface linked to their parent shelf row.

Filters:

- `source_types` — subset of `{content, reading, song}`; default is all three. Any other token is rejected.
- `content_type` — content only (narrows the corpus to content). Combining it with a `source_types` list that excludes `content` is rejected as `unsupported_filter`.
- `after`, `before`, `limit`.

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
| `capture_inbox` | `title`, `due?`, `project?`, `priority?`, `energy?` (`high` / `medium` / `low`) | Additive. Only `title` is required. Status is always `inbox` (captured but not clarified). The owner clarifies and advances it in admin. Use when the user says "add a task", "remind me to", or expresses a concrete work item to capture. `project` may be the slug of an existing or a proposed project (the link survives activation). |
| `plan_day` | `date?`, `items[{todo_id, reason?, position?}]` | Idempotent. One atomic replacement (delete-existing + insert-new in one transaction). Each todo MUST already be in `state=todo` — inbox/done/someday are rejected (clarify inbox todos to `state=todo` via the admin UI first). The `items` list MUST be non-empty; to leave the day unplanned, do not call `plan_day` at all. No auto-carryover — yesterday's unfinished items surface in `brief(mode=morning)` but do not roll forward automatically. `items_removed` reports true displacements only (todos carried over with the same `task_id` are not reported as removed). |
| `propose_area` | `name`, `proposal_rationale?` | Additive. Drafts a PARA area (ongoing domain of responsibility) as an INERT draft in `status=proposed` — invisible until the owner activates it (no area selector, backs no goal, surfaces only in admin proposals triage). Slug derived from name. Propose only to materialize a theme that surfaced in a conversation the owner was part of; activation (proposed→active) and rejection (hard delete) are owner actions in admin. |
| `propose_goal` | `name`, `milestones?[]`, `area?`, `proposal_rationale?` | Additive. Drafts a goal (with optional ordered milestones) as an INERT draft in `status=proposed` — feeds no list, no alignment, never appears in `brief` or any default goal listing; surfaces only in admin proposals triage. Optionally file under an existing active area's slug/name or a proposed (not-yet-active) area. Activation (proposed→in_progress, so it then appears in `brief`'s active_goals) and rejection (hard delete, milestones cascade) are owner actions in admin. |
| `propose_project` | `name`, `proposal_rationale?` | Additive. Drafts a NEW project (short-term effort with a clear outcome) as an INERT draft in `status=proposed` — invisible until the owner activates it (no project list, picker, or public portfolio; admin proposals triage only). Slug derived from name. `capture_inbox` can link a todo to the proposed project by slug before activation; the link survives activation, and a rejected project's todos are unlinked (not deleted). For an existing project, reference it via `capture_inbox.project` instead. Activation (proposed→in_progress) and rejection (hard delete) are owner actions in admin. |
| `list_tasks` | (none) | Read-only. Readback of the todos YOU created (created_by = your resolved caller identity) so you can learn their disposition — accept = `state` todo/done, pending = inbox, reject = absent from the list (the owner triaged it away). Caller-scoped: returns only your own todos. Use to close the `capture_inbox` loop. |
| `resolve_task` | `id`, `state` (`done` / `archived` / `dismissed`) | Destructive. Move a todo YOU created to a terminal state. Caller-scoped — resolving anyone else's todo returns not-found and changes nothing. The write half of the `capture_inbox`/`list_tasks` readback loop: self-clear the todos you've finished processing instead of leaving them for the owner. |

Higher-commitment GTD transitions for the owner's own todos (clarify / start / complete / defer / drop) and inbox-to-todo promotion are admin-UI/HTTP only — off the MCP surface.

Proposals (`propose_area` / `propose_goal` / `propose_project`) only ever materialize a draft from a conversation the owner was part of — never from a scheduled or autonomous run.

---

## Content — propose for review

| Tool | Key params | Annotation |
|---|---|---|
| `propose_content` | `title`, `type` (`article` / `essay` / `build-log` / `til` / `digest`), `body`, `excerpt?`, `slug?`, `topic_ids?[]`, `proposal_rationale?` | Additive. Pushes a FINISHED content piece into the editorial review queue. It always lands in `status=review` with `is_public=false` — an agent never publishes; the owner publishes or rejects it in the admin review queue. `body` is the finished Markdown draft (not a stub); `slug` is derived from title when omitted; `proposal_rationale` is the "why I propose this" note shown to the owner. The proposing agent is recorded as `created_by`. Use to push a finished draft (e.g. a completed Obsidian article) for the owner's review. |

Publishing stays an owner action in admin, off the MCP surface.

---

## Cross-cutting rules

**Caller identity**: every tool accepts optional `as: "<agent_name>"`. Server trusts the `as` value and authorizes by identity (platform / author / self) in `internal/mcp/authz.go`, against the roster in `internal/agent/registry.go::BuiltinAgents()`. Default caller is from env `KOOPA_MCP_CALLER_AGENT`.

**Read-only forever**: `brief`, `search_knowledge`, `list_tasks`, `list_readings`, `get_reading`, and `project_progress` are read-only by design and will not gain write actions.

**Off the MCP surface**: high-commitment lifecycle steps stay in the admin UI / HTTP — milestone creation, proposal triage (area / goal / project activation + rejection), content publishing, feed curation, and the owner's own todo lifecycle transitions. The reading shelf and ヨルシカ song shelf are written in admin too; the MCP surface only reads them.

**Cross-references**: `docs/backend-semantic-contract.md` §2 (vocabulary), §3 (entity responsibilities), §4 (lifecycles). The canonical tool surface, intent routing, and multiplexer semantics live in `internal/mcp/ops/catalog.go::All()` and the per-tool handlers in `internal/mcp/`.
