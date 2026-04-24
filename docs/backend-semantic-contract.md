# Backend Semantic Contract

Authoritative semantic baseline for all parties working on or around the
koopa backend: backend engineering, frontend / mission-control spec,
Claude Design UI/UX, and MCP agent authors.

**Contract authority order** (higher binds lower):

1. `migrations/001_initial.up.sql` — the schema. If this document
   contradicts the schema, the schema wins and this document must be
   updated.
2. Go code under `internal/` — the reference implementation of the
   schema.
3. `.claude/rules/mcp-decision-policy.md` — MCP behavior rules.
4. This document — the shared vocabulary and contract consumers see.
5. README / skill docs — consumer-facing narrative; never load-bearing.

Companion documents (do not duplicate their scope here):

- `docs/SYSTEM-SEMANTICS.md` — entity catalogue + cross-entity relationships.
- `docs/LEARNING-CONTRACT.md` — FSRS retention vs concept mastery split.
- `.claude/rules/mcp-decision-policy.md` — which tool fires when, proposal vs direct-commit.

---

## 1. System Semantic Summary

### What the system is

A private-by-default personal knowledge / learning / coordination OS.
One backend serves one human admin and multiple AI agents. All parties
read and write through the same semantic surface (the schema plus the
MCP tool layer on top of it).

### Architectural center

Three structural invariants define the backend:

- **`agents.name` as actor identity**. Every mutation is attributed to a
  known agent via FK: `created_by`, `curated_by`, `selected_by`, `actor`,
  `assignee`. The registry is projected from Go `BuiltinAgents()` at
  startup. Agents are retired, never deleted.
- **`activity_events` as canonical change log**. Written exclusively by
  `AFTER` triggers on covered tables. Application code MUST NOT INSERT
  into it directly. The `koopa.actor` Postgres GUC carries the actor
  identity from the request into the trigger.
- **Illegal states made structurally impossible**. Joint CHECKs, partial
  unique indexes, and narrow-scope triggers enforce invariants that
  cannot be expressed as a single constraint (e.g. task state ↔
  timestamp consistency, at-most-one-active learning session,
  completion-requires-outputs).

### Bounded contexts (subsystems)

Four concurrent axes. Each axis has its own vocabulary and its own
lifecycle semantics. Cross-axis links exist (see §4) but each axis is
independently meaningful.

| Axis | Entities | Subsystem purpose |
|---|---|---|
| **Commitment** | `areas`, `goals`, `milestones`, `projects`, `todos`, `daily_plan_items`, `todo_skips` | PARA + GTD — what the admin commits to, plans, and executes. |
| **Knowledge** | `contents`, `notes`, `bookmarks`, `topics`, `tags`, `tag_aliases`, `feeds`, `feed_entries` | Authored + curated + collected knowledge. Public output + private reference. |
| **Learning** | `learning_domains`, `concepts`, `learning_targets`, `learning_sessions`, `learning_attempts`, `learning_attempt_observations`, `observation_categories`, `learning_plans`, `learning_plan_entries`, `learning_hypotheses`, `learning_target_relations`, `review_cards`, `review_logs` | Deliberate-practice engine — what to learn, practice, diagnose, and review. |
| **Coordination** | `agents`, `tasks`, `task_messages`, `artifacts`, `agent_notes` | Inter-agent work (`tasks`) + intra-agent narrative (`agent_notes`). |

Cutting across all four:

| Cross-cutting | Entities |
|---|---|
| **Audit** | `activity_events` (trigger-only), `process_runs` (background run history). |
| **Identity** | `agents` (the actor registry), `users` + `refresh_tokens` (single-admin login). |

---

## 2. Core Vocabulary Glossary

Every term below has a precise definition. The "is not" and "differs from"
lines are load-bearing — getting them wrong is a semantic bug, not a
naming quibble.

### Identity / Actors

- **agent** — an actor that can write to the system (human, Cowork
  Claude instance, Claude Code, system bot). Source of truth is Go
  `BuiltinAgents()`; DB row is a projection. Used as FK target for every
  `created_by` / `selected_by` / `curated_by` / `actor` / `assignee`.
  - Is not: a user account (those live in `users`, separate).
  - Is not: a Cowork project. Cowork is a platform; agents can run on
    several platforms (`claude-cowork`, `claude-code`, `claude-web`,
    `human`, `system`).
- **user** — a login identity in `users`. Today there is exactly one
  admin user. The system does not use `user_id` as actor identity; all
  mutation attribution goes through `agents.name` (the admin logs in
  as agent name `human`).
- **actor** (column on `activity_events`) — the `agents.name` value
  attributed to a particular change. Set from the `koopa.actor` GUC
  inside the audit trigger.

### Coordination

- **task** — an inter-agent work unit. One agent asks another to do
  work. Lifecycle: `submitted → working → completed | canceled`, with
  a revision cycle (`completed → revision_requested → working →
  completed`). Completion requires ≥1 response message and ≥1 artifact
  (trigger-enforced).
  - Is not: a personal todo item (see `todo`).
  - Is not: a background job (see `process_run`).
- **directive** — **vocabulary label only, not a structural entity**. A
  task whose expected output is a report and whose target exercises
  autonomous judgment. At the MCP boundary the agent uses
  `propose_commitment(type=directive)` / `acknowledge_directive` /
  `file_report`; in the DB it is a plain `tasks` row. No `kind`
  discriminator today. If behavior diverges in the future, a
  `tasks.kind` column gets added then.
- **task_message** — an ordered request/response turn on a task
  (`role ∈ {request, response}`). Parts are a2a-go `Part` values in
  flattened JSON form. Hard size caps (16 parts, 32 KB) DB-enforced —
  anything larger belongs in an artifact.
- **artifact** — a structured deliverable. Either task-bound
  (`task_id` set; attached to a completed task) or standalone
  (`task_id` NULL; agent self-published). Looser size caps (32 parts,
  256 KB).
- **agent_note** — an agent's internal narrative log entry. Three kinds:
  `plan` (daily plan reasoning), `context` (session snapshot),
  `reflection` (retrospective). Self-directed; NOT a way to communicate
  with other agents.
  - Is not: a Zettelkasten note (see `note`). "A bare 'note' is
    ambiguous — say `agent_note` or `note`."
  - Is not: inter-agent coordination (see `task`).

### Commitment (PARA + GTD)

- **area** — a PARA Area of Responsibility. Persists indefinitely. Each
  area has a standard to maintain, not a goal to achieve.
  Human-managed only; never created via MCP.
- **goal** — an aspirational outcome, optionally tied to an area, with
  optional deadline / quarter. May have multiple milestones and
  projects under it. Status (`not_started → in_progress → done |
  abandoned | on_hold`) is manually managed; not auto-derived from
  milestones.
- **milestone** — a binary (done / not-done) progress checkpoint inside
  a goal. Goal progress = completed milestones / total milestones
  (advisory). Milestones are NOT OKR key results — no `target_value`,
  no `current_value`.
- **project** — a PARA execution vehicle: short-term effort with
  deliverables. May (but does not have to) serve a goal. Has its own
  status lifecycle separate from goal status.
- **project_profile** — a 1:1 public portfolio / case-study facet of a
  project. Independent lifecycle from the project itself (a profile
  can be edited months after the project completed). Existence of a
  row means the project has been curated for public display;
  `is_public=true` gates whether it actually renders.
- **todo** — a personal GTD work item. Lifecycle: `inbox → todo →
  in_progress → done`, plus `someday` as a parked branch. `inbox`
  means "captured, not yet clarified" (lacks project / due / priority).
  Recurring todos carry `recur_interval` + `recur_unit`.
  - Is not: a task (that's inter-agent). Vocabulary split is
    load-bearing.
- **daily_plan_item** — "today I commit to this todo" record. One row
  per (plan_date, todo). Lifecycle: `planned → done | deferred |
  dropped`. There is NO auto-carryover — yesterday's unfinished items
  surface in the morning briefing but do not roll forward
  automatically.
- **todo_skip** — a per-occurrence skip record for a recurring todo
  (the scheduled recurrence did not happen). Distinct from
  `daily_plan_items.status='dropped'` — skip = missed occurrence;
  dropped = explicitly removed from a specific day's plan. Mutual
  exclusion trigger-enforced.

### Knowledge

- **content** — a first-party publishable knowledge artifact going
  through an editorial lifecycle. Five types: `article`, `essay`,
  `build-log`, `til`, `digest`. Lifecycle: `draft → review →
  published → archived`. `review` is a two-actor handoff: Claude
  submits, human admin publishes (human-only at MCP boundary).
  Publishing atomically flips `status='published'`, `is_public=true`,
  `published_at=now()`.
  - Is not: a note (different lifecycle, separate table).
  - Is not: a bookmark (different curation model, separate table).
- **note** — a Zettelkasten knowledge artifact with a maturity-based
  lifecycle (`seed → stub → evergreen → needs_revision → archived`).
  Private (Koopa-only); notes do not "publish". Six sub-kinds:
  `solve-note`, `concept-note`, `debug-postmortem`, `decision-log`,
  `reading-note`, `musing`. A learning_target may accumulate multiple
  notes of different kinds over time.
- **bookmark** — an external URL + personal commentary. Curate =
  publish: creating a bookmark sets `is_public=true` and
  `published_at=now()` by default, no editorial review stage.
- **feed** — an RSS/Atom subscription with its own fetch schedule
  (`hourly | daily | weekly | biweekly | monthly`), priority, and
  topic associations. Auto-disables after consecutive fetch failures.
- **feed_entry** — a single article collected from a feed. Lifecycle:
  `unread → read → curated | ignored`. A curated feed_entry becomes
  EITHER a content row (`curated_content_id`) OR a bookmark
  (`source_feed_entry_id`); never both (trigger-enforced exclusion).
- **topic** — a curated high-level knowledge domain (~10-20 topics
  manually managed). Examples: `go`, `ai`, `system-design`.
- **tag** — a fine-grained content-classification label
  (e.g. `two-pointers`, `error-handling`). Raw tag strings flow
  through `tag_aliases` into the canonical `tags` table.
  - Is not: a concept. Tags classify content. Concepts diagnose
    learning. Namespaced slugs like `weakness:xxx` are no longer used.
- **tag_alias** — a row in the raw→canonical mapping pipeline for
  tags. A tag may be `unmapped`, `rejected`, or resolved via one of
  four paths (`auto-exact`, `auto-ci`, `auto-slug`, `admin`).

### Learning

- **learning_domain** — a closed lookup: one of the learning areas the
  system supports (seeded `leetcode`, `japanese`, `go`,
  `system-design`, `reading`). FK target for concepts / targets /
  sessions / plans.
- **concept** — a unit of learning ontology: `pattern` (e.g.
  `two-pointers`), `skill` (e.g. `edge-case-handling`), or `principle`
  (e.g. `amortized-analysis`). Concepts form a same-domain hierarchy
  (`parent_id` self-referencing, acyclicity trigger-enforced).
  Mastery is a DERIVED value over filtered observations, not stored
  on the concept.
  - Is not: a tag (concepts are diagnostic; tags are descriptive).
- **learning_target** — something to learn, practice, or revisit: a
  LeetCode problem, a book chapter, a grammar drill, a system-design
  scenario. Independent of notes (a target exists before any notes
  are written about it). Targets have a relation graph (easier /
  harder variants, prerequisites, follow-ups).
- **learning_session** — an orchestration boundary with explicit start
  / end, domain, mode (`retrieval | practice | mixed | review |
  reading`), and optional link to the `agent_notes(kind='reflection')`
  the session produced. **At most one active session** (partial unique
  index); `start_session` errors if one already exists.
- **learning_attempt** — a single attempt at one learning_target
  within a session. Append-only. Carries paradigm + outcome:
  - `paradigm='problem_solving'` ⇒ outcome ∈ {`solved_independent`,
    `solved_with_hint`, `solved_after_solution`, `incomplete`,
    `gave_up`}
  - `paradigm='immersive'` ⇒ outcome ∈ {`completed`,
    `completed_with_support`, `incomplete`, `gave_up`}
- **learning_attempt_observation** — a micro-cognitive signal tagged
  to an attempt and a concept. Fields: `signal_type ∈ {weakness,
  improvement, mastery}`, `category` (FK to `observation_categories`),
  `severity` (weakness only: `minor | moderate | critical`),
  `confidence ∈ {high, low}`. High-confidence signals are directly
  evidenced; low-confidence signals are coach-inferred. Mastery
  derivation defaults to `confidence='high'` only, with a 3-filtered-
  observation floor per concept.
- **observation_category** — the canonical registry of weakness /
  improvement / mastery category slugs. FK-enforced from observations
  so dashboard `GROUP BY category` never silently splits on typos.
  See §4 for the seeded list.
- **learning_plan** — an ordered curriculum. Status lifecycle:
  `draft → active → completed | paused | abandoned`. Optional goal
  link. `draft` is a workspace; only `active` is tracked in
  execution.
- **learning_plan_entry** — a plan's pointer to a specific learning_target,
  with ordering and per-entry lifecycle
  (`planned → completed | skipped | substituted`). Completion requires
  `completed_by_attempt_id` by POLICY (not schema) when Claude
  decides the entry is done.
- **learning_hypothesis** — a falsifiable claim in the LEARNING domain.
  Required fields: `claim` (one-line prediction), `invalidation_condition`
  (what evidence would disprove it), `content` (supporting narrative).
  Lifecycle: `unverified → verified | invalidated → archived`.
  Evidence FKs point only into learning structures (`learning_attempts`,
  `learning_attempt_observations`) — cross-domain hypotheses do not
  belong in this table.
- **review_card** — the FSRS spaced-repetition state for a single
  learning_target. **Exactly one card per target** (unique index).
  Review scheduling is per-target only; neither content-scoped nor
  concept-scoped review is modelled today.
- **review_log** — an append-only FSRS review-event record. Retained
  indefinitely (the algorithm needs history).

### Audit / Infrastructure

- **activity_event** — the canonical audit log row. Written by AFTER
  triggers on covered tables. Carries `entity_type`, `entity_id`,
  `entity_title` + `entity_slug` (write-time snapshots so a
  hard-deleted entity still renders), `change_kind`, `actor`,
  `payload` (typed per `(entity_type, change_kind)` pair),
  `occurred_at`. Covered entity types: `todo`, `goal`, `milestone`,
  `project`, `content`, `bookmark`, `note`, `learning_attempt`,
  `task`, `learning_hypothesis`, `learning_plan_entry`,
  `learning_session`. `directive` is NOT a separate entity_type.
- **process_run** — a background-run history row. Two kinds: `crawl`
  (internal fetch/collector runs, e.g. RSS feed fetch) and
  `agent_schedule` (external AI scheduler runs, e.g. claude-cowork).
  `subsystem` is the external scheduler identifier (only when
  `kind='agent_schedule'`).
  - Is not: a task (that's inter-agent). `process_run` is
    infrastructure telemetry.

---

## 3. Entity / Aggregate Responsibilities

For each entity: **role, ownership, responsibility boundary, adjacent
entities, lifecycle role, frontend relevance**.

Frontend relevance flags:
- `primary` — UI should surface this as a first-class object the user
  directly manipulates.
- `support` — UI needs to understand it but rarely exposes it
  directly (e.g. activity_events feeds timelines but is never
  "created" in UI).
- `internal` — UI does not need to model this as an independent
  object; it shows up inside other entities' displays.

| Entity | Role | Write path | Boundary | Adjacent | Lifecycle | Frontend |
|---|---|---|---|---|---|---|
| `agents` | Actor identity registry | Go literal → `SyncToTable` at startup. Never via MCP or admin UI. | Capability flags live in Go, NOT in DB. | All `created_by` / `actor` / `assignee` FKs. | Upsert at boot; retire on removal (status=`retired`). | support |
| `users` + `refresh_tokens` | Login identity | `internal/auth` handlers | Single admin today. RBAC is explicitly a future concern, not designed. | None (auth is its own island). | Create on first login; rotate refresh tokens. | internal |
| `areas` | PARA area lookup | Human-only (admin UI). Never via MCP. | Persistent; never "completes". | `goals.area_id`, `projects.area_id` (both SET NULL on delete). | Static. | primary |
| `goals` | Aspirational outcome | MCP `propose_commitment(type=goal)` → `commit_proposal`; admin UI. | Status is manual; not auto-derived. | 1:N milestones, 1:N projects, 0:N learning_plans. | not_started → in_progress → done / abandoned / on_hold. | primary |
| `milestones` | Goal progress checkpoint | MCP proposal; admin UI. | Binary completion (`completed_at`); no target/current values. | Belongs to exactly one goal (CASCADE). | One-shot: incomplete → completed (via `completed_at`). | primary |
| `projects` | PARA execution vehicle | MCP proposal; admin UI. | Separate lifecycle from goals. | Optional goal link; 1:1 project_profile; 0:N contents; 0:N todos. | planned → in_progress → completed \| archived, plus on_hold / maintained. | primary |
| `project_profiles` | Public portfolio facet | Admin UI only. | Existence ≠ visibility (`is_public` gates). | 1:1 project (CASCADE). | Independent edits; cannot be `is_public=true` when owning project is archived. | primary (public site); internal (admin) |
| `todos` | Personal GTD work item | MCP `capture_inbox` / `advance_work`; admin UI. | `inbox` lacks project/due/priority by design. | Optional project link; 0:N daily_plan_items; 0:N todo_skips. | inbox → todo → in_progress → done, + someday. Recurring: `recur_interval` + `recur_unit`. | primary |
| `daily_plan_items` | "Today I commit to X" | MCP `plan_day`; admin UI. | No auto-carryover. | Belongs to exactly one todo (CASCADE). | planned → done / deferred / dropped. | primary |
| `todo_skips` | Missed recurrence | Background cron (not MCP). | Mutually exclusive with `daily_plan_items.status='dropped'` for same (todo_id, date). | 1:1 todo (CASCADE). | Append-only. | support |
| `contents` | Public-facing published writing | MCP `create_content` / `update_content` / `submit_content_for_review` / `publish_content` (human-only) / `archive_content` / `revert_content_to_draft`; admin UI. | Publishing is atomic 3-field flip. | 0:N content_topics, 0:N content_tags, 0:N content_concepts, optional project link. | draft → review → published → archived, plus revert-to-draft from review. | primary |
| `notes` | Private knowledge artifact | MCP `create_note` / `update_note` / `update_note_maturity`; admin UI. | No publish state; matures in place. | 0:N note_concepts, 0:N learning_target_notes. | seed → stub → evergreen → needs_revision → archived (not terminal one-way). | primary |
| `bookmarks` | External URL + commentary | Admin UI (`internal/bookmark`). MCP does NOT create bookmarks — the `manage_content(bookmark_rss)` path was removed. | Curate = publish (default `is_public=true`). | Optional `source_feed_entry_id`. | Create only; mutual-exclusion with feed_entry→content curation. | primary |
| `feeds` | RSS subscription | Admin UI + MCP `manage_feeds`. | Schedule is a cadence label, not cron. | 0:N feed_topics, 0:N feed_entries. | Create → fetched repeatedly; auto-disable after consecutive failures. | primary (admin only) |
| `feed_entries` | Collected RSS item | Background fetch pipeline. Admin UI curates. | A given entry → content OR bookmark, never both. | Optional feed (`feed_id` SET NULL on feed delete). | unread → read → curated / ignored. | primary (admin only) |
| `topics` | Curated domain lookup | Admin UI. | ~10-20, manually managed. | Junction to contents, feeds, bookmarks. | Static. | support |
| `tags` | Fine-grained label | Admin UI. Raw tags resolved via `tag_aliases`. | Tags classify content only; NOT for learning diagnosis. | Self-referencing hierarchy; junctions to contents, bookmarks. | Static registry. | support |
| `tag_aliases` | raw→canonical mapping | Admin UI (manual) + auto-resolver (auto-*). | Unmapped/rejected rows are legitimate states. | Resolves to `tags.id`. | raw received → auto or admin resolution → confirmed. | internal |
| `learning_domains` | Closed lookup | Seed + `propose_commitment(type=learning_domain)`. | Bootstrap via migration 002. | FK target for concepts, targets, sessions, plans. | Static per domain. | support |
| `concepts` | Learning ontology node | MCP proposal for structural changes; `record_attempt` auto-creates leaf-only same-domain concepts. | Mastery is derived, not stored. | learning_target_concepts, note_concepts, content_concepts, observations. | Static hierarchy. | primary (mastery views) |
| `learning_targets` | What to learn | MCP `record_attempt` find-or-create; `manage_plan(add_entries)`; admin. | Independent of notes. | learning_target_concepts, learning_target_notes, learning_target_contents, learning_target_relations, review_cards, learning_attempts. | Static; `metadata` JSONB for domain-specific fields. | primary |
| `learning_sessions` | Orchestration boundary | MCP `start_session` / `end_session`. | At most one active. | 1:N attempts; optional agent_note(kind=reflection) link; optional daily_plan_item link. | started → ended. | primary |
| `learning_attempts` | Append-only attempt record | MCP `record_attempt` only. | Must live inside a session. | 0:N observations; optional review_card sync. | Append-only. | support |
| `learning_attempt_observations` | Concept signal | MCP `record_attempt` only. | Confidence is a label, not a filter gate at write. | Attached to an attempt and a concept. | Append-only. | support |
| `observation_categories` | Category slug registry | Seed. | FK enforces typo-free GROUP BY. | Referenced by observations. | Static. | internal |
| `learning_plans` | Ordered curriculum | MCP proposal. | Only `active` is tracked in execution. | 0:N learning_plan_entries; optional goal link. | draft → active → completed / paused / abandoned. | primary |
| `learning_plan_entries` | Plan ↔ target with order + lifecycle | MCP `manage_plan`. | Substitution forms a DAG (trigger-enforced). | Belongs to plan (CASCADE); target (RESTRICT). | planned → completed / skipped / substituted. | primary |
| `learning_hypotheses` | Falsifiable learning-domain claim | MCP `propose_commitment(type=hypothesis)` / `track_hypothesis`. | LEARNING-only; do not use for non-learning claims. | Optional evidence FKs into attempts / observations. | unverified → verified / invalidated → archived. | primary |
| `learning_target_relations` | Target relation graph | `record_attempt` side effect; MCP. | Same-domain only (trigger). Symmetric types auto-insert reverse edge. | N:N on learning_targets. | Append-only triples. | support |
| `review_cards` | FSRS state per target | System-managed (`internal/learning/fsrs`). Never via MCP. | Exactly one per target. | 1:1 target (CASCADE); 1:N review_logs. | FSRS-managed; drift markers (`last_sync_drift_at`) flag desync. | primary (review schedule) |
| `review_logs` | FSRS history | System-managed. Never via MCP. | Append-only; retained indefinitely. | 1:N card. | Append-only. | internal |
| `tasks` | Inter-agent work unit | MCP `propose_commitment(type=directive)` / `acknowledge_directive` / `file_report`; admin UI (Reply, RequestRevision). | Completion requires ≥1 response + ≥1 artifact (trigger). Source ≠ target. | 1:N task_messages; 1:N artifacts. | submitted → working → completed / canceled, plus revision cycle. | primary |
| `task_messages` | Request/response turn | Via `task.Store.Submit` + `Complete` + `Reply`. | Bounds: 16 parts, 32 KB (DB-enforced). | Belongs to a task (CASCADE). | Append-only. | support |
| `artifacts` | Structured deliverable | MCP `file_report`. | Bounds: 32 parts, 256 KB. Task-bound or standalone. | Optional task (CASCADE). | Append-only. | primary |
| `agent_notes` | Agent narrative log | MCP `write_agent_note`. | Self-directed; three kinds with enforced binding (plan → daily_plan_item, reflection → learning_session). | Optional link FROM daily_plan_item and learning_session (not the other way). | Append-only. | support |
| `activity_events` | Canonical audit log | AFTER triggers only. Never app INSERT. | Exposes `actor`, `entity_title`, `entity_slug` as write-time snapshots. | Polymorphic `entity_id` with no FK. | Append-only; retained indefinitely. | support (timelines) |
| `process_runs` | Background run history | Feed fetch pipeline (kind=crawl); agent scheduler (kind=agent_schedule). | RETENTION: 90 days for terminal rows. | Optional content_id (SET NULL). | pending → running → completed / failed / skipped. | support (ops dashboard) |

---

## 4. Lifecycle and State Semantics

All state machines below are either Postgres ENUMs or TEXT CHECKs. Values
are listed verbatim.

### Knowledge lifecycles

- **`content_status` (ENUM)**: `draft → review → published → archived`
  - Transition `review → published` is **human-only** (MCP
    `publish_content` enforces).
  - Transition `review → draft` via `revert_content_to_draft`.
  - Invariants: `status='published' ↔ published_at IS NOT NULL`;
    `is_public=true` requires `status='published'`.
- **`note_maturity` (ENUM)**: `seed → stub → evergreen →
  needs_revision → archived`
  - Archive is operationally terminal but recoverable via
    `update_note_maturity`.
- **`feed_entry_status` (ENUM)**: `unread → read → curated | ignored`
  - `status='curated'` requires `curated_content_id IS NOT NULL`.
  - Mutual exclusion: a feed_entry is either curated into content OR
    referenced by a bookmark (via `source_feed_entry_id`), never both.

### Commitment lifecycles

- **`goal_status` (ENUM)**: `not_started → in_progress → done |
  abandoned | on_hold`
  - `abandoned` is terminal.
  - `on_hold` is pausable; can return to `in_progress`.
- **`project_status` (ENUM)**: `planned → in_progress → completed |
  archived`, plus `on_hold` and `maintained` branches.
  - `maintained` = project is operational but past its active
    build-out phase.
  - `archived` demotes any linked project_profile from
    `is_public=true`.
- **`todo_state` (ENUM)**: `inbox → todo → in_progress → done`, plus
  `someday` branch from `todo` or `inbox`.
  - `state='done' ↔ completed_at IS NOT NULL`.
- **`daily_plan_items.status` (TEXT CHECK)**: `planned → done |
  deferred | dropped`.
- **`hypothesis_state` (ENUM)**: `unverified → verified | invalidated
  → archived`.
  - Resolved states (`verified`, `invalidated`) require either an
    evidence FK or a non-blank `resolution_summary`.

### Coordination lifecycles

- **`task_state` (ENUM)**: `submitted → working → completed |
  canceled`, plus revision cycle `completed → revision_requested →
  working → completed`.
  - Each state has a mandated timestamp profile (joint CHECK).
  - Completion requires ≥1 response message AND ≥1 artifact
    (trigger).
  - `created_by <> assignee` (CHECK — no self-assignment).

### Learning lifecycles

- **`learning_plans.status` (TEXT CHECK)**: `draft → active →
  completed | paused | abandoned`
  - Only `active` plans count as "committed curriculum".
- **`learning_plan_entries.status` (TEXT CHECK)**: `planned →
  completed | skipped | substituted`
  - `completed` requires `completed_by_attempt_id` (schema + policy).
  - `substituted` requires `substituted_by` pointing to another
    entry in the SAME plan. Substitution DAG is trigger-enforced
    acyclic.
- **Session lifecycle**: `started → ended` (driven by
  `ended_at IS NULL`).
  - At most one active session at a time.
  - Ending may produce an `agent_notes(kind='reflection')` entry;
    `learning_sessions.agent_note_id` is kind-bound via trigger.

### Content-generating lifecycles (FSRS)

FSRS state is opaque to the app except for the denormalized `due`. The
algorithm advances on every review. Review scope today is **per
`learning_target` only** — content-scoped and concept-scoped review
are NOT modelled.

### Audit lifecycle

All mutations to covered entities produce exactly one `activity_event`
row via AFTER triggers. Covered `entity_type` values:

`todo | goal | milestone | project | content | bookmark | note |
learning_attempt | task | learning_hypothesis | learning_plan_entry |
learning_session`

Change kinds: `created | updated | state_changed | published |
completed | archived`.

Application code MUST NOT insert into `activity_events`. Any write
that is not attributed via `koopa.actor` GUC falls back to
`actor='system'` — that is the catch-all for cron, migrations, and
anything bypassing the request path.

### Observation categories (seeded)

`observation_categories.slug` (global unique). Categories by domain:

| Domain | Categories |
|---|---|
| `leetcode` | pattern-recognition, constraint-analysis, edge-cases, implementation, complexity-analysis, approach-selection, state-transition |
| `japanese` | conjugation-accuracy, particle-selection, listening-comprehension, vocabulary-recall |
| `system-design` | tradeoff-analysis, bottleneck-diagnosis, capacity-estimation |

Frontend MUST render weakness labels from this registry, not from
free text.

---

## 5. Frontend-Relevant Semantics

### Primary objects (UI should surface as first-class)

Commitment: `goal`, `milestone`, `project`, `todo`, `daily_plan_item`,
`area`.
Knowledge: `content`, `note`, `bookmark`, `feed`, `feed_entry`,
`topic`.
Learning: `learning_target`, `learning_session`, `learning_plan`,
`learning_plan_entry`, `concept`, `learning_hypothesis`, `review_card`.
Coordination: `task`, `artifact`.

Public site:
`content`, `bookmark`, `project_profile`, `topic`.

### Support objects (UI uses but rarely surfaces as primary)

`agent` (shown as attribution, not as an editable object),
`activity_event` (shown as timeline entries), `agent_note` (shown
inline with the session or daily plan it belongs to, not as its own
tab), `tag`, `tag_alias` (admin triage view),
`learning_attempt` (shown inside a session detail),
`learning_attempt_observation` (shown inside attempt detail),
`process_run` (shown in ops dashboard), `todo_skip` (shown inside a
recurring todo's history).

### Internal-only objects (UI should not create independent editors for)

`users`, `refresh_tokens`, `review_logs`, `observation_categories`,
`learning_domains` (closed lookup; edited via Backend proposal tool,
not a direct editor), `task_messages` (shown as thread inside a task;
never "create message" as a top-level action).

### User-visible states

These states should appear as filters / badges / columns in
admin/mission-control UI:

- Content: `draft`, `review`, `published`, `archived`, plus `is_public`.
- Todo: `inbox`, `todo`, `in_progress`, `done`, `someday`.
- Daily plan item: `planned`, `done`, `deferred`, `dropped`.
- Task: `submitted`, `working`, `completed`, `canceled`,
  `revision_requested`.
- Learning plan: `draft`, `active`, `completed`, `paused`, `abandoned`.
- Learning plan entry: `planned`, `completed`, `skipped`,
  `substituted`.
- Hypothesis: `unverified`, `verified`, `invalidated`, `archived`.
- Goal: `not_started`, `in_progress`, `done`, `abandoned`, `on_hold`.
- Project: `planned`, `in_progress`, `on_hold`, `completed`,
  `maintained`, `archived`.
- Note: `seed`, `stub`, `evergreen`, `needs_revision`, `archived`.
- Feed entry: `unread`, `read`, `curated`, `ignored`.
- Agent: `active`, `retired` (attribution only; not a filter most
  users care about).

### Legal actions surface (UI ↔ backend)

For each primary object, the UI may invoke exactly the actions listed
via the corresponding backend route. Anything else (e.g. "change todo
created_at") is NOT supported.

- **goal**: propose / commit / update status / attach milestones /
  attach projects.
- **milestone**: propose / commit / mark complete (set
  `completed_at`).
- **project**: propose / commit / update status / edit project_profile
  facet / toggle `is_public` on profile.
- **todo**: capture / clarify → todo / start → in_progress / complete →
  done / defer → someday / drop.
- **daily_plan_item**: add to today / reorder / mark done / mark
  deferred / mark dropped. NO auto-carryover.
- **content**: create (draft) / update / submit for review / revert to
  draft / publish (human only) / archive / toggle `is_public` (only
  when published).
- **note**: create / update body-title / update maturity (separate
  action so maturity transitions have their own audit).
- **bookmark**: create (curate = publish) / delete. No edit workflow
  today.
- **feed**: create / update schedule-or-topics / enable / disable /
  fetch-now / delete.
- **feed_entry**: mark read / curate → content / curate → bookmark /
  ignore / submit feedback.
- **task**: submit (via propose_commitment directive) / accept
  (acknowledge_directive) / reply / request revision / file report
  (complete) / cancel.
- **learning_session**: start / end (carrying a reflection).
- **learning_plan**: propose / commit / update status / add entries /
  remove entries / reorder / update entry / progress read.
- **learning_hypothesis**: propose / commit / verify / invalidate /
  archive / add evidence.
- **tag**: create / update / delete / merge; map/confirm/reject
  aliases.

### Relationships the UI must not misrepresent

- `directive` is NOT a separate entity. The UI MUST render directives
  as tasks (same row, same status, same state machine). If a
  "Directives" tab exists, it is a filter on the `tasks` list
  (e.g. by an application-side heuristic), NOT a query against a
  separate table.
- `agent_note` is NOT a message channel between agents. It is
  self-directed narrative. There is no UI concept of "send
  agent_note to another agent".
- `task` is NOT a todo. UI surfaces for the two should be distinct:
  todos go in the GTD / daily plan pane; tasks go in the
  coordination pane.
- `note` (Zettelkasten) is NOT a `content`. Notes never publish; they
  mature. UI must not apply the same "Publish" verb to a note.
- `concept` mastery is DERIVED from observations. UI must not offer a
  "Set mastery level" control. To change a concept's mastery, the
  user records more attempts and observations.
- `review_card.due` is DENORMALIZED from FSRS internal state. UI
  must not offer a direct "Set next due date" control. Rescheduling
  happens by recording a review.
- `daily_plan_items` does NOT auto-carry yesterday's unfinished items.
  UI must NOT hide this; the confrontation is the point.
- `milestones` are NOT OKR key results. UI must not surface
  `target_value` / `current_value` / percent-complete fields on a
  milestone.
- `bookmarks` do NOT have a draft → review flow. Creating a bookmark
  is publishing it. UI must not offer "Publish bookmark" as a
  distinct action.

---

## 6. Naming and Vocabulary Rules

### Canonical vocabulary per layer

| Concept | DB column / table | Go type / field | MCP tool / JSON field | UI label (suggested) |
|---|---|---|---|---|
| Inter-agent work | `tasks` | `task.Task`; `Source` / `Target` fields map to `created_by` / `assignee` | `propose_commitment(type=directive)`, `acknowledge_directive`, `file_report` | "Task" (default) or "Directive" (when framed as autonomous-report) |
| Personal work item | `todos` | `todo.Item` | `capture_inbox`, `advance_work` | "Todo" |
| Today's commitment | `daily_plan_items` | `daily.PlanItem` | `plan_day` | "Daily plan" / "Today" |
| Agent narrative | `agent_notes` | `agent/note.Note` | `write_agent_note`, `query_agent_notes` | "Agent note" (never bare "note") |
| Zettelkasten note | `notes` | `note.Note` | `create_note`, `update_note`, `update_note_maturity` | "Note" |
| Actor identity | `agents` | `agent.Agent` | (implicit via `as` field) | "Agent" |
| Audit record | `activity_events` | `activity.Event` (wire-layer; see below) | (read-only via `session_delta` / `weekly_summary` / `morning_context`) | "Activity" |
| Change timestamp | `activity_events.occurred_at` | `activity.Event.Timestamp` | `timestamp` | "When" |
| Change author | `activity_events.actor` | `activity.Event.Actor` | `actor` | "By" |
| Event payload | `activity_events.payload` | `activity.Event.Metadata` | `metadata` | (inspector panel) |
| Background run | `process_runs` (kind=crawl) | (db-level only today) | `system_status` | "Pipeline run" / "Crawl run" |
| Session | `learning_sessions` | `learning.Session` | `start_session`, `end_session` | "Learning session" |
| Concept | `concepts` | `learning.Concept` (via store helpers) | — (referenced by slug) | "Concept" |
| Target | `learning_targets` | `learning.Target` | — (referenced by id) | "Learning target" / domain-specific: "Problem", "Chapter", etc. |
| Review card | `review_cards` | `fsrs.Card` | — (internal) | "Review" |
| Hypothesis | `learning_hypotheses` | `hypothesis.Hypothesis` | `propose_commitment(type=hypothesis)`, `track_hypothesis` | "Hypothesis" |
| Priority (task/todo) | `tasks.priority` / `todos.priority` CHECK `{high, medium, low}` | — | field value ∈ `{"high","medium","low"}` | Priority chip |

### Forbidden / retired vocabulary

Do not use these terms in new code, schema, API, or UI copy:

- **`flow`** — retired. Was residue from the removed genkit-flow
  subsystem. The `process_runs.kind` value for internal fetch runs is
  `crawl`.
- **`participant`** — retired. Was a pre-rebuild term for what is now
  `agents`.
- **`weakness:xxx` / `improvement:xxx`** — retired namespaced tag slugs.
  Weakness diagnosis runs through `concepts` + `learning_attempt_observations`,
  not tags.
- **`p0` / `p1` / `p2` priority scale** — retired. The single scale is
  `high | medium | low` to match the `tasks.priority` CHECK. The MCP
  boundary rejects anything else (no alias).
- **`resolve_directive=true`** — phantom parameter. Never existed in
  `FileReportInput`. `file_report` with `in_response_to` set already
  completes the task.
- **`bookmark_rss` MCP action** — removed from `manage_content`.
  Bookmarks are created via the admin UI, not via content tools.
- **`ErrCoordinationRebuildPending`** — sentinel that never existed.
  Do not cite "Phase 3b pending" in docs; the coordination layer is
  live.
- **`body` field on activity events** — removed. `activity.Event`
  does not carry a body; the `payload`/`Metadata` JSONB carries
  payload.

### Disambiguation rules

- When writing about a note, always qualify: `agent_note` (the
  narrative log) vs `note` (the Zettelkasten artifact).
- When writing about a task, clarify context: coordination `task`
  vs generic English "task". Avoid bare "task" when the audience
  may read it as "todo".
- `origin_system` (contents) and `capture_channel` (bookmarks) are
  different columns on different tables. Do not conflate.
- `learning_target` is the *thing* learned; `learning_plan_entry` is
  that thing's *membership in a specific plan*. Completing a plan
  entry is a plan-domain decision, not an attempt outcome.
- `review_card` answers "when next to review THIS target"; `concept`
  mastery answers "which patterns / skills do I understand".
  They are independent axes (see LEARNING-CONTRACT).

### Frontend copy alignment

UI should prefer short domain-accurate labels over clever ones:
- "Today" rather than "My Day" (aligns with `daily_plan_items`).
- "Submitted / Working / Completed" rather than "New / Active / Done"
  for tasks (aligns with `task_state`).
- "Draft / Review / Published" for content (verbatim from
  `content_status`).
- "Seed / Evergreen / Archived" for notes (verbatim from
  `note_maturity`). Keep the stem — do not re-translate.

---

## 7. Non-Goals / Forbidden Assumptions

Do not infer, design around, or build features assuming any of the
following — they are either explicitly out of scope today or would
violate the current semantics.

### Structural

1. **No `tasks.kind` discriminator**. Do not assume you can query
   "all directives" separately from tasks. If a UI tab labeled
   "Directives" exists, it is a presentation filter on the tasks list,
   not a separate query.
2. **No `bookmarks.status` lifecycle**. Do not design bookmark review
   queues. Creation IS publishing.
3. **No content-scoped or concept-scoped `review_card`**. Review cards
   are one-per-learning_target only. Do not design a "review concept"
   flow.
4. **No auto-carryover of daily plan items**. Yesterday's planned
   items that ended `deferred` or still `planned` do NOT automatically
   appear on today's plan. UI must force the user to choose.
5. **No RBAC**. `users` has one admin today. Do not design
   per-user permission matrices; capability gating is per-agent
   (`agent.Authorized`), not per-user.
6. **No quantitative milestones**. Do not model
   `target_value`/`current_value`/percentage on milestones. They are
   binary.
7. **No goal auto-status derivation**. Completing all milestones does
   NOT auto-mark a goal as `done`. Goal status is user-managed.
8. **No cross-domain `learning_hypotheses`**. The table is
   LEARNING-only. Pipeline / UX / system-design hypotheses would use
   a future sibling table; do not inject non-learning rows here.

### Coordination

9. **No self-directed tasks**. `created_by <> assignee` is CHECK-enforced.
10. **No hand-rolled a2a Parts**. `parts` columns hold a2a-go
    `Part` objects as JSONB. Clients pass `{"text": "..."}` or
    `{"data": {...}}`. Do not invent `{"code": ...}` or
    `{"markdown": ...}` variants.
11. **No direct INSERT into `activity_events`**. Only AFTER triggers
    write this table. UI actions that surface as activity items must
    be expressed as mutations on the underlying entity.
12. **No `agent_notes` to another agent**. Agent notes are
    self-directed. Inter-agent messaging is `task_messages` on a
    task.

### Learning

13. **No direct mastery edit**. `concept` mastery is derived from
    observations. There is no "Set mastery to Evergreen" action.
14. **No FSRS override knobs exposed**. `review_cards.card_state` is
    opaque. Do not design UI controls that edit FSRS internals; the
    only knobs are the review rating (Again / Hard / Good / Easy)
    and, optionally, an `fsrs_rating` override on `record_attempt`.
15. **No cross-domain concept parent**. `concepts.parent_id` must
    share the child's `domain` (trigger). Do not assume a Japanese
    concept can parent a LeetCode concept.
16. **No silent concept creation for non-leaf / cross-domain cases**.
    `record_attempt` auto-creates concepts only if leaf, same-domain,
    inferable kind. Structural changes go through
    `propose_commitment`.

### Vocabulary

17. **Do not name new things `service` / `repository` / `handler`
    packages**. The project is package-by-feature. Hooks enforce this
    at file creation.
18. **Do not invent new `process_runs.kind` values casually**. Adding
    one requires both the schema CHECK update and a coherent story
    for `subsystem` (required iff `kind='agent_schedule'`).
19. **Do not reintroduce `flow` / `bookmark_rss` /
    `resolve_directive` / `p0/p1/p2`** in any new code, query, or UI
    copy. These are explicitly retired (§6).

---

## 8. Open Ambiguities / Not Yet Finalized

Items below are known points where the code, docs, or schema do not yet
give a single authoritative answer. Mark any UI / implementation work
that touches them as needing explicit decision.

1. **Agent-scoped activity views** (`activity_events.actor` consumers)
   — the schema and read layer now expose `actor`, but the downstream
   Go types (`weekly.Summary`, `mcp.SessionDelta`, `mcp.MorningContext`
   outputs) do not yet propagate it into user-facing responses. UI
   work that wants to render "by hq / by claude-code / by human" will
   need those output types widened. *Status: backend-ready,
   not-yet-propagated.*

2. **`learning_domains` lifecycle**. New domains can be proposed at
   runtime via `propose_commitment(type=learning_domain)` but there
   is no retire / deactivate flow beyond the `active` flag. No UI
   for it today.

3. **`agent_notes.metadata` schema**. Per-kind metadata structure
   (e.g. `plan → {reasoning}`) is policy-mandatory, not
   schema-enforced. UI reading this JSON must tolerate missing
   fields gracefully and must not assume a closed schema.

4. **Frontend `actor` / `by` surfacing**. Whether admin UI should
   expose actor attribution on every entity list (goals created by
   hq vs by admin, etc.) is undecided. Backend data is there.

5. **`contents.ai_metadata` consumer contract**. Structure documented
   as `{summary, keywords, quality_score, review_notes}` but not
   type-checked. Admin UI should treat it as advisory; it is not a
   formal contract today.

6. **`project_aliases` surface**. Aliases exist to resolve fuzzy
   project references from activity-event resolution (GitHub repo
   name variants). Not currently exposed in the admin UI.

7. **Task `revision_requested` UX**. Backend lifecycle is clear (joint
   CHECK covers the state). UI treatment of "I, the reviewer, want
   changes — here is what I want" (request_revision request body
   shape, message vs full artifact vs free text) is not yet codified.
   Currently the Go handler exists (`task.RequestRevision`) but the
   payload contract is whatever the handler accepts.

8. **`directive` discriminator decision**. Status quo: directive is
   naming-only. The criteria for adding a real `tasks.kind` column
   are documented in `.claude/rules/mcp-decision-policy.md §14`
   (when behavior diverges). Not a current plan.

9. **Bookmark edit flow**. Bookmark creation is final today — there
   is no admin endpoint to update a bookmark's `note` or `title`
   after curation. If UI needs this, a backend edit endpoint and
   audit behavior need design first.

---

## 9. Change Discipline for This Document

This file is part of the contract consumers rely on. When changing it:

- Update it in the same commit as the underlying code/schema change
  that made the old text false.
- Do not log history or trade-offs here. Commit messages and
  git log carry those.
- If the schema changes in a way this doc cannot yet describe, add
  the item to §8 (Open Ambiguities) rather than guessing.
- If in doubt, run the check: does a backend engineer, a frontend
  engineer, and a UI designer all arrive at the same mental model
  from reading this? If not, the section is wrong.
