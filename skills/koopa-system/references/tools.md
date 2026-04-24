# MCP Tool Reference

37 tools. Authoritative source: `internal/mcp/ops/catalog.go::All()` (the
drift test in `ops_catalog_test.go` locks this file against the registered
handler sequence).

## Groups at a glance

| Group | Count | Nature |
|---|---|---|
| Context suppliers | 6 | Read-only situational awareness |
| GTD (todos + daily plan) | 3 | Personal work capture + execution |
| Commitment gateway | 3 | Proposal-first for goals / projects / milestones / directives / hypotheses / learning plans / learning domains |
| Agent notes | 2 | Self-directed narrative log (never A2A) |
| Coordination (a2a) | 3 | Inter-agent task / report / lineage |
| Hypothesis | 1 | Falsifiable claim lifecycle |
| Learning | 7 | Session / attempt / plan / analytics |
| Content lifecycle | 8 | Flat per-intent CRUD + editorial |
| Notes (Zettelkasten) | 3 | Maturity-based knowledge artifacts |
| Feeds / system | 1 | RSS subscription management |

---

## Context suppliers (read-only)

| Tool | Key params | Returns |
|---|---|---|
| `morning_context` | `sections?`, `date?` | Session-start bundle: unacknowledged directives, today's plan, overdue todos, pending artifacts, RSS highlights, unverified hypotheses |
| `reflection_context` | `date?` | Session-end bundle: planned vs actual, agent notes written today |
| `session_delta` | `since?` | Activity snapshot since a point in time: todos created, todos completed, agent notes, learning session count. Not a session-to-session diff; not scoped to any learning_session. Default lookback 24h. |
| `weekly_summary` | `week_of?` | Week retrospective: todos completed, agent notes by kind, learning session count + domains, concept mastery. Defaults to current ISO week. |
| `system_status` | `scope?` | Pipeline health, feed health, process_runs by kind (`crawl` / `agent_schedule`). |
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

Two-step pattern. `propose_commitment` produces a preview + signed token; `commit_proposal` persists it. Agents draft; the human (or delegated authority) confirms.

| Tool | Key params | Annotation |
|---|---|---|
| `propose_commitment` | `type`, `fields` | Read-only (no DB write). |
| `commit_proposal` | `proposal_token` | Additive on success. |
| `goal_progress` | `goal_id?`, `area?`, `status?` | Read-only. Goal progress = completed milestones / total milestones (advisory, not auto-derived goal status). |

### Valid `type` values for `propose_commitment`

| type | Output entity | Notes |
|---|---|---|
| `goal` | `goals` row | Optional area, optional deadline, optional quarter |
| `project` | `projects` row | Optional goal link |
| `milestone` | `milestones` row | Binary progress checkpoint; no `target_value` / `current_value` |
| `directive` | `tasks` row (inter-agent) | Requires `source` (caller auto-filled), `target` (assignee), `request_parts` (a2a.Part array: `[{"text":"..."}]` or `[{"data":{...}}]`). At most 16 parts, ≤32 KB total. |
| `hypothesis` | `learning_hypotheses` row | Requires `claim`, `invalidation_condition`, `content`. LEARNING-domain only. |
| `learning_plan` | `learning_plans` row (draft) | Activate separately via `manage_plan(action=update_plan, status=active)`. |
| `learning_domain` | `learning_domains` row | Requires `slug` (kebab-case), `name`. |

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
| `acknowledge_directive` | `directive_id` | Idempotent. Caller must be the target — validated via `agent.ActionAcceptTask`. |
| `file_report` | `in_response_to?`, `artifact_parts`, `response_message_parts?` | Idempotent. Task-bound (with `in_response_to`): response message + artifact + state transition atomic. Standalone (without): free artifact via `artifact.Store.Add`. |
| `task_detail` | `task_id` | Read-only. Returns `{task, messages, artifacts}`. Caller must be source or target (else `not_found`). Artifacts are task-bound only; `agent_notes` are not exposed. |

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
| `record_attempt` | `target{title, external_id, domain}`, `outcome`, `time_spent_minutes`, `stuck_at?`, `approach_used?`, `metadata?`, `fsrs_rating?`, `observations?[]`, `related_targets?[]` | Additive. Requires an active session. `outcome` values are paradigm-specific (see per-domain playbook). |
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
| `submit_content_for_review` | `id` | Idempotent. `draft → review`. |
| `revert_content_to_draft` | `id` | Idempotent. `review → draft`. |
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

**Caller identity**: every tool accepts optional `as: "<agent_name>"`. Server trusts the `as` value, validates via the Go `agent.Capability` registered in `BuiltinAgents()`. Default caller is from env `KOOPA_MCP_CALLER_AGENT` (commonly `"human"`).

**Proposal tokens**: HMAC-signed, ephemeral (lost on restart). Fields are fully validated at propose-time — missing required fields refuse to emit a token.

**Activity events**: every mutation to covered entity types writes one `activity_events` row via AFTER trigger. `entity_type` includes `todo`, `goal`, `milestone`, `project`, `content`, `bookmark`, `note`, `learning_attempt`, `task`, `learning_hypothesis`, `learning_plan_entry`, `learning_session`. `directive` is not a separate entity_type — directives are `task` rows.

**Cross-references**: `docs/backend-semantic-contract.md` §2 (vocabulary), §3 (entity responsibilities), §4 (lifecycles). `.claude/rules/mcp-decision-policy.md` §1 (intent classification), §10 (multiplexer rules), §14 (coordination layer).
