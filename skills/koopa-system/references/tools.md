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

**21 tools** across 7 domains.

| Domain | Count |
|---|---|
| `query` | 4 |
| `daily` | 2 |
| `a2a` | 0 |
| `meta` | 1 |
| `learning` | 5 |
| `content` | 9 |
| `system` | 0 |
| **Total** | **21** |

| Tool | Domain | Writability | Purpose |
|---|---|---|---|
| `morning_context` | `query` | read_only | Single-call daily-planning briefing |
| `query_agent_notes` | `query` | read_only | Recall prior agent notes |
| `reflection_context` | `query` | read_only | End-of-day retrospective: plan vs actual completion, daily plan item outcomes, today's agent notes |
| `search_knowledge` | `query` | read_only | Search across content (articles, build logs, TILs, etc.) and notes (Zettelkasten) |
| `capture_inbox` | `daily` | additive | Quick task capture to inbox |
| `plan_day` | `daily` | idempotent | Set the day's plan as one atomic replacement |
| `write_agent_note` | `meta` | additive | Create an agent note |
| `end_session` | `learning` | additive | End the active learning session |
| `learning_read` | `learning` | read_only | Read-only learning analytics |
| `manage_plan` | `learning` | destructive | Learning plan lifecycle and entries |
| `record_attempt` | `learning` | additive | Record an attempt within the active learning session |
| `start_session` | `learning` | additive | Begin a learning session |
| `archive_content` | `content` | destructive | Soft-delete a content row by archiving it |
| `create_content` | `content` | additive | Create a new content row in status=draft |
| `create_note` | `content` | additive | Create a Zettelkasten note (notes table) |
| `list_content` | `content` | read_only | List content rows with optional filters (type, status, project) |
| `publish_content` | `content` | destructive | HUMAN-ONLY |
| `read_content` | `content` | read_only | Fetch a single content row with full body by ID. |
| `set_content_review_state` | `content` | additive | Set a content row's review state |
| `update_content` | `content` | additive | Update editable fields (title/body/slug/type) on a content row |
| `update_note` | `content` | additive | Update editable fields (slug / title / body / kind) on a note |
<!-- GENERATED:TOOL-INVENTORY END -->

---

## Context suppliers (read-only)

| Tool | Key params | Returns |
|---|---|---|
| `morning_context` | `sections?`, `date?` | Session-start bundle: unacknowledged directives, today's plan, overdue todos, pending artifacts, RSS highlights, unverified hypotheses. When `sections` is omitted, server consults a per-agent allowlist (e.g. `learning-studio` defaults to `tasks` + `pending_tasks` + `hypotheses` + `plan_history`, skipping rss + content_pipeline); unlisted callers still get all sections. Explicit `sections` always wins. |
| `reflection_context` | `date?` | Session-end bundle: planned vs actual, agent notes written today |
| `session_delta` | `since?` | Activity snapshot since a point in time: todos created, todos completed, agent notes, learning session count. Not a session-to-session diff; not scoped to any learning_session. Default `since` is yesterday-midnight in Asia/Taipei (calendar-day aligned with `s.today()`); window width therefore varies with wall-clock (up to ~47h at TPE 23:00). Explicit ISO `since` overrides. |
| `weekly_summary` | `week_of?` | Week retrospective: todos completed, agent notes by kind, learning session count + domains, concept mastery. Defaults to current ISO week. |
| `system_status` | `scope?` | Pipeline health, feed health, process_runs by kind (`crawl` / `agent_schedule`). Response also carries `build: {sha, built_at, version}` so auditors can pin a response to the exact commit that produced it. |
| `search_knowledge` | `query`, `source_types?`, `content_type?`, `note_kind?`, `project?`, `after?`, `before?`, `limit?` | Hybrid retrieval over contents (FTS + pgvector) and notes (FTS). See Search section below. |

### `search_knowledge` hybrid retrieval

Content branch runs in parallel:

- **FTS**: `websearch_to_tsquery('simple', query)` on `contents.search_vector` (GIN).
- **Semantic**: query embedded via `gemini-embedding-2-preview` (1536d Matryoshka), cosine distance on `contents.embedding` (HNSW).
- **Merge**: Reciprocal rank fusion (k=60), top 30 per branch → top `limit` after merge.

Semantic branch auto-falls-back to FTS-only when embedder is unavailable, times out (>400ms), or errors. Notes branch is FTS-only.

Query syntax (both FTS paths use websearch):

- Quoted phrases: `"value semantics"` — exact match.
- AND (default): `Go generics` — both words appear.
- OR: `goroutine OR channel`.
- Exclusion: `-draft`.

Visibility: `search_knowledge` sees all statuses including drafts and private — it is the internal-search surface, not the public-site search.

---

## GTD — personal work

| Tool | Key params | Annotation |
|---|---|---|
| `capture_inbox` | `title`, `due?`, `project?`, `priority?` | Additive. Inbox state means captured but not clarified (no project / due / priority required). |
| `advance_work` | `todo_id`, `action` (`clarify` / `start` / `complete` / `defer` / `drop`) | Idempotent (repeat with same state is no-op). |
| `plan_day` | `date?`, `entries[{todo_id, reason?, position?}]` | Additive. No auto-carryover — yesterday's unfinished items surface in `morning_context` but do not roll forward automatically. |

---

## Commitment gateway

Two-step pattern. There is no single combined proposal tool — proposing was flat-split into seven typed `propose_*` tools (the old multiplexer's `type` discriminator selected fundamentally different entities; per `.claude/rules/mcp-decision-policy.md §10`, discriminator-by-entity → flat-split). Each typed tool produces a preview + signed proposal token and writes nothing to the DB. The signed token carries the type, so the single `commit_proposal` persists any of them — commit stayed unified.

The seven typed propose tools:

| Tool | Key params | Output entity | Notes |
|---|---|---|---|
| `propose_goal` | `title`, `area?`, `target_deadline?`, `quarter?` | `goals` row | Optional area, optional deadline, optional quarter. |
| `propose_project` | `title`, `goal_id?`, `area?` | `projects` row | Optional goal link. |
| `propose_milestone` | `title`, `goal_id`, `target_deadline?` | `milestones` row | Binary progress checkpoint; no `target_value` / `current_value`. |
| `propose_directive` | `target`, `request_parts`, `priority?` | `tasks` row (inter-agent) | `source` is caller auto-filled. `request_parts` is an a2a.Part array (`[{"text":"..."}]` or `[{"data":{...}}]`), first part MUST be text. At most 16 parts, ≤32 KB total. |
| `propose_hypothesis` | `claim`, `invalidation_condition`, `content` | `learning_hypotheses` row | LEARNING-domain only. |
| `propose_learning_plan` | `title`, `domain`, `goal_id?` | `learning_plans` row (draft) | Activate separately via `manage_plan(action=update_plan, status=active)`. |
| `propose_learning_domain` | `slug`, `name` | `learning_domains` row | `slug` is kebab-case (`^[a-z][a-z0-9-]*$`). |

| Tool | Key params | Annotation |
|---|---|---|
| `commit_proposal` | `proposal_token` | Additive on success. Commits the entity from any `propose_*` token. |
| `goal_progress` | `goal_id?`, `area?`, `status?` | Read-only. Goal progress = completed milestones / total milestones (advisory, not auto-derived goal status). |

---

## Agent notes

`agent_note` is self-directed narrative — plans, context snapshots, reflections. Never a channel for inter-agent communication; cross-agent reasoning goes through `task_messages` on a `task`.

| Tool | Key params | Annotation |
|---|---|---|
| `write_agent_note` | `kind` (`plan` / `context` / `reflection`), `content`, `metadata?` | Additive. |
| `query_agent_notes` | `query?`, `kind?`, `since?`, `until?`, `author?`, `limit?` | Read-only. |

### `query_agent_notes` search

- `query` runs `websearch_to_tsquery('simple', …)` on `agent_notes.search_vector` (GIN).
- Filters (kind, author, date window) compose with `query`.
- Ordering: `entry_date DESC, created_at DESC`. When `query` is set, `ts_rank` is the same-day tiebreaker.
- Defaults: 90-day window, limit 50, limit max 200.

---

## Coordination (a2a)

The inter-agent work triad: `task` + `task_message` + `artifact`. Completion requires ≥1 response message AND ≥1 artifact (trigger-enforced).

| Tool | Key params | Annotation |
|---|---|---|
| `acknowledge_directive` | `task_id` | Idempotent. Caller must be the target — validated via `agent.ActionAcceptTask`. |
| `file_report` | `in_response_to?`, `artifact_parts`, `response_message_parts?` | Idempotent. Task-bound (with `in_response_to`): response message + artifact + state transition atomic. Standalone (without): free artifact via `artifact.Store.Add`. **Part shape (HERMES F-15)**: each part in `artifact_parts` / `response_message_parts` is an a2a Part with EXACTLY ONE of `text` (string) / `raw` (base64) / `data` (any JSON) / `url` (string); optional siblings `filename`, `mediaType`, `metadata`. Top-level `type` and unknown keys are silently dropped by a2a-go — for structured payloads use `{"data":{...}}`, NOT `{"type":"observation","text":"..."}` (that stores as plain Text with no error). Rejection errors carry `valid keys: text, raw, data, url ...`. |
| `task_detail` | `task_id` | Read-only. Returns `{task, messages, artifacts}`. Caller must be source or target (else `not_found`). Artifacts are task-bound only; `agent_notes` are not exposed. |
| `list_my_tasks` | `limit?` | Read-only. Returns `{received, issued}` — your open tasks as assignee (inbox) and as creator (outbox), each covering `submitted` / `working` / `revision_requested`. Caller from `as`; no `task_id` needed (unlike `task_detail`, which cannot enumerate). |

---

## Hypotheses

| Tool | Key params | Annotation |
|---|---|---|
| `track_hypothesis` | `hypothesis_id`, `action` (`verify` / `invalidate` / `archive`), `evidence_attempt_id?`, `evidence_observation_id?`, `resolution_summary?` | Idempotent. Resolved states (`verified`, `invalidated`) require evidence FK or non-blank `resolution_summary` (schema CHECK). |

---

## Learning

| Tool | Key params | Annotation |
|---|---|---|
| `start_session` | `domain`, `mode` (`retrieval` / `practice` / `mixed` / `review` / `reading`) | Additive. At most one active session globally (partial unique index). Auto-ends the prior session if idle > 12h (returns `zombie_ended`). |
| `record_attempt` | `target{title, external_id, domain}`, `outcome`, `time_spent_minutes`, `stuck_at?`, `approach_used?`, `metadata?`, `fsrs_rating?`, `observations?[]`, `related_targets?[]` | Additive. Requires an active session. `outcome` values are paradigm-specific (see per-domain playbook). Response surfaces `concepts: [{slug, id}]` (one per resolved observation, deduped), `related_targets_resolved: [{id, title}]` (one per successfully-linked related target), and `fsrs_card: {id, due_at}` (touched review card; omitted entirely when `fsrs_review_failed=true` so callers gate on the flag, not on a null card). Chain follow-up reads without re-resolving slugs. |
| `end_session` | `session_id`, `summary?` | Idempotent. |
| `learning_dashboard` | `view` (`overview` / `mastery` / `weaknesses` / `retrieval` / `timeline` / `variations`), `domain?`, `window_days?`, `confidence_filter?`, `due_within_hours?` | Read-only. See views below. |
| `recommend_next_target` | `session_id`, `count?`, `domain?`, `exclude_patterns?[]` | Read-only. Returns candidates[], each with `source_concept` + `relation_type` + `anchor`. |
| `attempt_history` | exactly one of `target{title,domain?}` / `concept_slug(+domain?)` / `session_id`; `max_results?` | Read-only. `resolved: false` + empty attempts means "never attempted" — a legal answer, not an error. |
| `manage_plan` | `action` (`add_entries` / `remove_entries` / `update_entry` / `reorder` / `update_plan` / `progress`), `plan_id`, action-specific fields | Mixed (read for `progress`, write for others). |

### `learning_dashboard` views

| view | Returns |
|---|---|
| `overview` (default) | Recent sessions list |
| `mastery` | Per-concept signal counts + derived stage (`struggling` / `developing` / `solid`). Floor: <3 filtered observations → always `developing`. |
| `weaknesses` | Cross-concept weakness analysis by category + severity |
| `retrieval` | Due FSRS review items. `due_within_hours` (0..168, default 0) looks ahead. |
| `timeline` | Sessions + attempts by day. `window_days` (mastery 60, others 30, range 1..365). |
| `variations` | Target relation graph (easier / harder / prerequisite / follow-up) |

`confidence_filter` (default `"high"`) applies to `mastery` and `weaknesses` only. Set `"all"` to include coach-inferred low-confidence observations.

### `manage_plan` entry completion

Setting `update_entry status=completed` requires:

- `completed_by_attempt_id` — policy-mandatory (schema allows NULL for manual completion). Server validates the attempt's `learning_target_id` matches the entry's.
- `reason` — descriptive, includes attempt outcome.

---

## Content lifecycle

Flat per-intent CRUD. Status transitions: `draft → review → published → archived`.

| Tool | Key params | Annotation |
|---|---|---|
| `create_content` | `type`, `title`, `body`, `slug?`, `excerpt?`, `topics?`, `tags?`, `project_id?`, `ai_metadata?` | Additive. Creates in `draft`. |
| `update_content` | `id`, field patches | Additive. Edits any draft / review fields; cannot change `status`. |
| `set_content_review_state(state="review")` | `id` | Idempotent. `draft → review`. |
| `set_content_review_state(state="draft")` | `id` | Idempotent. `review → draft`. |
| `publish_content` | `id` | Destructive (human-only — agent with non-`human` `as` is rejected). Atomic: `status='published'`, `is_public=true`, `published_at=now()`. |
| `archive_content` | `id` | Idempotent. `published → archived` (or direct archive of review / draft). Demotes `is_public`. |
| `list_content` | `type?`, `status?`, `project?`, `limit?`, `after?`, `before?` | Read-only. Internal — sees all statuses. |
| `read_content` | `id` | Read-only. Returns full body + metadata. |

Content types: `article`, `essay`, `build-log`, `til`, `digest`. Bookmark creation is not in this surface — handled via admin UI.

---

## Notes (Zettelkasten)

Separate entity, separate package. Notes mature in place; they do not publish.

| Tool | Key params | Annotation |
|---|---|---|
| `create_note` | `title`, `body`, `kind`, `slug?`, `concepts?`, `target_ids?` | Additive. Creates at `seed` maturity. |
| `update_note` | `id`, field patches | Additive. Cannot change maturity (use `update_note_maturity`). |
| `update_note_maturity` | `id`, `maturity` (`seed` / `stub` / `evergreen` / `needs_revision` / `archived`) | Idempotent. Separate surface so maturity transitions have their own audit trail. |

Note sub-kinds: `solve-note`, `concept-note`, `debug-postmortem`, `decision-log`, `reading-note`, `musing`.

---

## Feeds / system

| Tool | Key params | Annotation |
|---|---|---|
| `manage_feeds` | `action` (`list` / `add` / `update` / `remove`), action-specific fields | Mixed (read for `list`, write for others). |

Feed schedule values: `hourly` / `daily` / `weekly` / `biweekly` / `monthly`. Auto-disables after consecutive fetch failures. `feed_entry` lifecycle: `unread → read → curated | ignored`; a curated entry becomes either a `content` row OR a bookmark, never both (trigger-enforced).

---

## Cross-cutting rules

**Caller identity**: every tool accepts optional `as: "<agent_name>"`. Server trusts the `as` value, validates via the Go `agent.Capability` registered in `BuiltinAgents()`. Default caller is from env `KOOPA_MCP_CALLER_AGENT` (default `"unknown"` — a zero-privilege fallback agent). Tools gated by `requireExplicitHuman` (publish_content, commit_proposal of high-commitment entities) refuse the default regardless of its value — the `as` field MUST be supplied explicitly.

**Proposal tokens**: HMAC-signed, ephemeral (lost on restart). Fields are fully validated at propose-time — missing required fields refuse to emit a token.

**Activity events**: every mutation to covered entity types writes one `activity_events` row via AFTER trigger. `entity_type` includes `todo`, `goal`, `milestone`, `project`, `content`, `bookmark`, `note`, `learning_attempt`, `task`, `learning_hypothesis`, `learning_plan_entry`, `learning_session`. `directive` is not a separate entity_type — directives are `task` rows.

**Cross-references**: `docs/backend-semantic-contract.md` §2 (vocabulary), §3 (entity responsibilities), §4 (lifecycles). `.claude/rules/mcp-decision-policy.md` §1 (intent classification), §10 (multiplexer rules), §14 (coordination layer).
