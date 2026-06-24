# Backend Semantic Contract

> The grounded semantic vocabulary for the koopa0.dev backend, organized as
> **seven numbered sections** (§1–§7). It is the shared-vocabulary layer below
> the code: the schema, the Go code, and the MCP ops catalog are authoritative;
> this contract names what they mean and flags what is not provable from them.
>
> Intended basis for: MCP tool contract tests, hybrid-search judgment tests,
> commitment-proposal lifecycle tests, frontend UI/UX golden flows, and the
> observability event taxonomy.

**Grounding discipline:**

- Every implementation-backed statement carries a `file:line` reference. Line
  numbers track `migrations/001_initial.up.sql` (1452 lines) and
  `migrations/002_seed.up.sql` (132 lines) as committed; re-ground them after a
  migration rewrite.
- Statements not provable from the repo are marked **Open Question** (§7) and
  resolved only by the human owner.
- The existence of a table, a doc, or a handler is **not** proof a feature
  works. §6 separates "implemented and wired" from "schema-supported only".

---

## 1. System purpose

### What koopa0.dev is

A **private-by-default personal knowledge / learning OS for a single human
owner and a small closed set of AI agents.** One Go backend serves one admin
(`users`, single row today) and a closed roster of registered agents
(`internal/agent/registry.go::BuiltinAgents()`). Every party reads and writes
through the same two surfaces: the PostgreSQL schema and the MCP tool layer on
top of it. A public Angular site is a read-only projection of the publishable
subset.

It is **all of the following, with explicit boundaries** (§4):

| Facet | What it covers | Backing |
|---|---|---|
| **Personal semantic infrastructure** | `agents.name` as universal actor identity; `activity_events` as the canonical change log written only by triggers | `internal/agent/`, `internal/activity/`, schema triggers `migrations/001_initial.up.sql:1049-1173` |
| **PARA / GTD / OKR-ish system** | areas, goals, milestones, projects, todos, daily plan | `internal/goal/`, `internal/project/`, `internal/todo/`, `internal/daily/` |
| **MCP tool surface** | **14 agent-facing tools** | `internal/mcp/ops/catalog.go::All()` (canonical list) |
| **Knowledge / search system** | content, topics, feeds; hybrid FTS + pgvector search | `internal/content/`, `internal/search/`, `internal/mcp/search.go` |

> **This is a closed single-owner + small-agent-roster knowledge OS.** The
> agent-facing MCP surface is **14 tools** (`internal/mcp/ops/catalog.go::All()`).
> Milestone creation, area/goal/project activation, and content publication are
> **admin-only HTTP forms** under `/api/admin/` (`cmd/app/routes.go`); agents
> draft area/goal/project as inert proposals and push finished content into the
> review queue. There is no inter-agent coordination layer in the backend. Agent
> memory is not a backend entity — each agent keeps its own `.md`. The schema is
> migrations **001 + 002**.

It is **NOT**: a multi-user product, an RBAC system, a public CMS with
arbitrary authorship, or a generic agent marketplace. The agent set is closed
and compiled into the binary (`internal/agent/registry.go::BuiltinAgents()`).

### Architectural invariants (the three load-bearing rules)

1. **`agents.name` is the only actor identity.** Every mutation is attributed
   via FK (`created_by` / `curated_by` / `selected_by` / `actor` / `assignee`).
   The registry is a projection of the Go `BuiltinAgents()` literal synced at
   startup (`registry.go:17-101`); an agent row persists and carries a status
   (`agent_status`, `migrations/001_initial.up.sql:31`), so a name stays a
   stable FK target for the life of the audit log.
2. **`activity_events` is written exclusively by AFTER triggers.** Application
   code must never INSERT (`migrations/001_initial.up.sql:952` table,
   `:975` "MUST NOT INSERT" comment; audit functions + triggers `:1049-1173`).
   Actor flows from the `koopa.actor` GUC via `current_actor()`
   (`:1049`), defaulting to `'system'`.
3. **Illegal states are made structurally impossible** through joint CHECKs,
   partial unique indexes, and narrow triggers — not application discipline
   alone. The publish CHECKs couple `status='published'` with `published_at`
   (`:481`) and gate `is_public` on `published` (`:483`); an inert proposal
   carries `status='proposed'`. There is no `tasks` entity, so the task
   state↔timestamp / completion-requires-outputs invariants do not exist.

---

## 2. Sources of truth

When two sources disagree about **what the system does**, the higher tier
wins and the lower MUST be updated. This authority order resolves
*descriptive* conflicts only — it does **not** settle *normative* questions
("is this behavior intended?"). Normative questions go to §7 Open Questions
and are resolved only by the human owner.

| Source | Path(s) | Status | Notes |
|---|---|---|---|
| **Schema + DB constraints** | `migrations/001_initial.up.sql`, `002_seed.up.sql` | **Authoritative** | CHECKs, triggers, FKs are the last word on legal states. |
| **Go code + tests** | `internal/`, `cmd/` | **Authoritative** (reference impl) | A passing test pins observable behavior. When prose disagrees with a green test, the test wins. |
| **MCP ops catalog** | `internal/mcp/ops/catalog.go` | **Authoritative** (tool surface) | The `All()` list (`:215-231`) is the canonical agent-facing tool surface; drift-tested against handler registration (`ops_catalog_test.go`). |
| **sqlc-generated code** | `internal/db/` | **Derived** | Generated from `query.sql` files; never hand-edited. |
| **This contract** | `docs/backend-semantic-contract.md` | **Derived** | Shared vocabulary; below schema/code/catalog. |
| **PARA usage contract** | `docs/para-semantic-contract.md` | **Derived** | The classification/usage layer (which real thing maps to which entity). Below the same three authorities. |
| **Cowork agent op docs** | `skills/koopa-system/` + each agent's own Cowork project `CLAUDE.md` | **Advisory** | Per-agent operational guidance; never structural truth. |
| **Frontend route/service code** | `frontend/src/app/**` | **Advisory / assumption** | Encodes the frontend's *assumed* backend contract. |

**Implementation-only (no doc is authoritative; read the code):**
`internal/mcp/search.go` (RRF merge constants and FTS/semantic fusion —
`mergeByRank:198`, `rrfMerge:295`, `rrfMergeResults:485`).

---

## 3. Core domain vocabulary

Format per term: **meaning** · *defined/implied at* · **enforced?** ·
*ambiguity / open question*. The "is not" lines are load-bearing — getting
them wrong is a semantic bug, not a naming quibble.

### Identity / actors

- **agent** — an actor that may write to the system (human, Cowork Claude
  instance, Claude Code, system bot). *Source of truth*
  `registry.go::BuiltinAgents()` (`:17-101`); DB row is an identity projection
  (name / platform / status). **Enforced**: FK target for every actor column.
  There is **no tool-layer authorization** (Option B, 2026-06): access is gated
  by the MCP transport, and `as` only carries attribution + caller-scope
  (`server.go::callerIdentity`). *Is not* a user account; *is not* a Cowork
  project (one platform an agent can run on).
- **user** — a login identity (`users` table) + `refresh_tokens`. Exactly one
  admin today; the admin logs in and acts as agent name `human`
  (`registry.go:63-67`). `user_id` is **not** used as actor identity.
- **actor** — the `agents.name` value attributed to one `activity_events` row;
  set from the `koopa.actor` GUC inside the audit trigger via `current_actor()`
  (`migrations/001_initial.up.sql:1049`).
- **planner / Koopa** — `planner` is the `claude-cowork` daily-driver agent:
  morning briefing, candidate day plans, inbox capture, search
  (`registry.go:20-31`). "Koopa" is the human owner (display name on the
  `human` agent) — the sole decision-maker and sole router.
- **Claude Cowork project** — a `claude-cowork` platform agent: `planner`
  (`registry.go:22`). A platform/identity, not a PARA `project` (§4).
- **Claude Code** — `claude-code` platform agents (`koopa0-dev`, `go-spec`,
  `hermes`), doing repo development and scheduled vault work. A Claude Code
  session is a dev runtime, not a coordination peer (§4).

### Commitment (PARA + GTD + goals)

> The classification/usage layer — which real-world thing maps to which entity
> and why — lives in `docs/para-semantic-contract.md`. This section defines the
> entities and their enforced lifecycle.

- **project (PARA)** — a PARA execution vehicle: a concrete effort with
  deliverables (`projects` table, `migrations/001_initial.up.sql:314`). Has
  nullable `area_id` and `goal_id` (`:317`); may be `maintained` (continuous).
  Its status lifecycle is `project_status` (`:23` — `proposed | planned |
  in_progress | on_hold | completed | maintained | archived`). An agent
  may draft an inert `status='proposed'` project via `propose_project` —
  invisible until the owner activates (proposed→in_progress) or rejects it;
  `capture_inbox` can link a todo to a proposed project by slug, and the link
  survives activation. *Is not* a Cowork project / agent identity (§4).
- **area (PARA)** — an ongoing domain of responsibility / sphere of life
  (`areas` table). Activation is an admin action; an agent may draft an inert
  proposal via `propose_area` (`status='proposed'`), and the owner activates
  (proposed→active) or rejects (hard delete, cascading to its proposed child
  goals) in admin triage (`cmd/app/routes.go:224-225`).
- **goal** — a finite objective, optionally area-scoped, with optional
  deadline/quarter. Status (`goal_status`, `:19`: `proposed | not_started →
  in_progress → done | abandoned | on_hold`) is **manually managed**, not
  auto-derived from milestones. The owner creates and re-statuses a goal via
  the admin forms (`cmd/app/routes.go:207,209`); an agent may draft an inert
  `status='proposed'` goal (with ordered milestones) via `propose_goal`, which
  the owner activates (proposed→in_progress) or rejects in admin triage.
- **milestone** — a binary done/not-done checkpoint inside a goal
  (`migrations/001_initial.up.sql:249`); `milestone.goal_id` is **NOT NULL**
  (`:253`) — a milestone only attaches to a goal, never a project. Completion is
  `completed_at IS NOT NULL` (`:255`), no status column. **Not** an OKR key
  result — no `target_value`/`current_value` (schema comment `:273-276`).
  Created via the admin milestone form (`cmd/app/routes.go:210`), or as part of
  a `propose_goal` proposal bundle that the owner activates.
- **todo** — a personal GTD work item (`:740`). `todo_state` (`:27`): `inbox →
  todo → in_progress → done`, plus `someday`, `archived`, `dismissed`. Optional
  `project_id` only — no `goal_id` / `area_id` edge. `completed_at` is coupled
  to `state='done'` by CHECK (`:758-760`). *Is not* a `task`.
- **daily_plan_item** — "today I commit to this todo" (`:802`). Status CHECK
  `planned | done | deferred | dropped` (`:810`). **No auto-carryover** — no
  trigger copies yesterday's items forward; `deferred` is a manual carry-over
  *candidate*, not an automatic one (comment `:837,857`).

### Knowledge

- **content** — first-party publishable artifact (`:447`). Five types:
  `article`, `essay`, `build-log`, `til`, `digest` (`content_type`, `:7`).
  `content_status` (`:11`): `draft → review → published → archived`. Publishing
  ties `status='published'` to `published_at` (`:481`) and gates `is_public` on
  `published` (`:483`). Content authoring / lifecycle is **admin HTTP** under
  `/api/admin/knowledge/content` (`cmd/app/routes.go:145-154`); the one agent
  path is `propose_content`, which inserts a finished piece at `status='review'`
  with `is_public=false` for the owner to publish or reject — an agent never
  publishes. Each row carries an `embedding vector(1536)` column (`:467`) that
  the reconciler fills (§6).
- **source / provenance** — attribution of where a knowledge row came from.
  Columns: `contents.origin_system`, `feed_entries → feeds`.
  `activity_events.actor` + entity-title/slug write-time snapshots give
  per-mutation provenance. **Ambiguity:** there is no single uniform
  "provenance" object; provenance is per-entity columns + the audit log.
- **feed / feed_entry** — RSS subscription + collected items. `feed_entry`
  lifecycle `unread → read → curated | ignored` (`feed_entry_status`, `:15`);
  a curated entry produces a content row.

### MCP / system

- **MCP tool** — a registered handler in the MCP server, described by an
  `ops.Meta` (`internal/mcp/ops/types.go:52`): name, domain, writability,
  stability, since, description, field enums. **14 tools**
  (`catalog.go::All()`, `:215-231`).
- **schedule** — a per-agent recurring trigger declared on the Go
  `agent.Agent` literal (`Schedule{Name, Trigger, Expr, Backend, Purpose}`).
  `planner` runs `morning-briefing` at `0 8 * * *` on `cowork_desktop`
  (`registry.go:24-30`) — the one scheduled agent. **Lives in Go, not the DB.**
  The schedule literal is metadata only; the backend has **no internal
  scheduler** — execution is driven by the external Cowork/Desktop runner. This
  repo owns the registry metadata, the schema, and the
  `process_runs(kind='agent_schedule')` audit row; it does not own scheduled
  execution.
- **schedule run** — a single execution of an external agent schedule,
  recorded in `process_runs` (`:644`) with `kind='agent_schedule'` and a
  non-null `subsystem` (`chk_process_runs_subsystem_iff_agent_schedule`,
  `:673-674`). The sibling kind `crawl` is for internal fetch/collector runs
  (RSS). *Is not* a `task`. Whether the external runner is actively writing
  these rows is **not yet observable from this repo** (§7 Open Question 5).

---

## 4. Domain boundaries

The named confusions and their resolutions, each grounded.

| Boundary | Term A | Term B | Rule | Grounding |
|---|---|---|---|---|
| **PARA project vs agent identity** | `projects` row (work vehicle) | Cowork "project" = a `claude-cowork` agent | A PARA project is data in `projects`; a Cowork project is an actor in `agents`. They never share a table or ID. | `projects` schema `:314`; `registry.go:20-31` |
| **todo is the only work-item entity** | `todos` (personal GTD) | (no `tasks` entity) | There is no inter-agent `tasks` triad, so there is no "task vs todo" boundary to police — a todo is the system's only work-item entity. | `todo_state` enum `:27` |
| **inert proposal vs active commitment** | `status='proposed'` area / goal / project (agent draft) | the activated row (owner action) | A proposed entity is fully inert — invisible to brief / Today / active listings / selectors — until the owner activates it in admin triage. The agent drafts; the owner commits. | `propose_*` handlers; `cmd/app/routes.go:220-227` |
| **MCP tool call vs semantic write** | a `tools/call` invocation | the resulting row + `activity_event` | A read-only tool call (`ReadOnly` writability — `brief`, `search_knowledge`, `list_tasks`, `list_content`, `review_period`, `project_progress`) produces no semantic write. Only Additive/Idempotent/Destructive tools write; the *write* is the row + its trigger-emitted audit event, not the call. | `ops/types.go:28-39` |
| **Cowork project vs agent identity** | `claude-cowork` agent | the live `agent` entity | A Cowork project IS an agent — a row in `agents` keyed by `name`, the universal actor identity. | `registry.go:20-31` |
| **Claude Code runtime vs Koopa identity** | `claude-code` agent (dev session) | `human` agent (Koopa) | Both attribute writes via `as`; there is no tool-layer override for either (Option B — no `requireAuthor`). The live distinction is actor-attribution identity (`actor='human'` is what `project_progress` / `review_period` count as owner momentum), not coordination authority. | `server.go::callerIdentity`; `registry.go` |
| **frontend page model vs backend domain model** | Angular admin pages (composed views) | backend entities | Page-level view-models are **not** backend entities. The Today page is now backed by a fully-wired backend aggregate (§6F). | `internal/today/handler.go`; §2 |

---

## 5. MCP tool semantics

The canonical tool inventory, each tool's per-tool writability (`ReadOnly |
Additive | Idempotent | Destructive` — `ops/types.go:28-39`), and its
description live in `internal/mcp/ops/catalog.go::All()` (`:215-231`),
drift-tested against handler registration in `ops_catalog_test.go`. The
read-only tools (`brief`, `search_knowledge`, `list_tasks`, `list_content`,
`review_period`, `project_progress`) are permanently read-only. This contract
points at the catalog rather than duplicating the per-tool table; read
`catalog.go::All()` for the authoritative surface.

The agent write surface is exactly: `capture_inbox` (Additive), `plan_day`
(Idempotent — atomic replacement), `propose_area` / `propose_goal` /
`propose_project` / `propose_content` (Additive — inert drafts / review-queue
push), `revise_content` (Destructive — caller-scoped revise of the agent's own
`review` / `changes_requested` content, resent to the review queue), and
`resolve_task` (Destructive — caller-scoped self-clear of a todo the agent
created).

---

## 6. Implementation status

What is actually wired and exercised, separated from what the schema merely
permits. Existence of a table, handler, or doc is not proof of a working path.

### A. Implemented and wired

| Capability | Reality | Evidence |
|---|---|---|
| Login + refresh-token rotation + token security | implemented, tested | `internal/auth/` (`auth_test.go`, `handler_test.go`) |
| Content draft→review→publish→archive lifecycle (admin HTTP; `propose_content` lands at `status=review`, `is_public=false`) | implemented; publish CHECKs enforce transitions | `internal/content/`; CHECKs `migrations/001_initial.up.sql:481,483`; routes `cmd/app/routes.go:145-154` |
| Feed fetch + scheduler cadence + auto-disable on failures | implemented, tested | `internal/feed/scheduler_test.go` (testcontainers) |
| **Document-embedding write path** | **Implemented (this is the current state, not a TODO).** `embedder.Embed` (`internal/embedder/embedder.go:67`) is driven by a background `Reconciler` (`internal/embedder/reconciler.go`) that drains every registered source — currently just `contents` (`cmd/app/main.go`) — embedding rows missing a vector. Two call sites: the `app` server runs a background `Run` loop, gated on `GEMINI_API_KEY` (`cmd/app/main.go:242-247`), and the `embed-backfill` subcommand runs a one-shot `RunOnce` (`runBackfill`, `cmd/app/main.go:83-102`, dispatched at `:64`); the `mcp` server also constructs one (`cmd/mcp/main.go:93-94`). Unset `GEMINI_API_KEY` → FTS-only (`cmd/mcp/main.go:101`). | `reconciler.go:121,139,236`; `content/embedding.go:21,27` |
| **Hybrid search (FTS + pgvector RRF)** | implemented; per-corpus FTS fused with pgvector semantic results via reciprocal-rank fusion, degrading to FTS-only when no embedder is configured | `internal/mcp/search.go` — `mergeByRank:198`, `EmbedQuery:273`, `rrfMerge:295`, `rrfMergeResults:485`; HNSW index `migrations/001_initial.up.sql:516` |
| Today aggregate (admin HTTP) | implemented + fully wired (§6F) | `cmd/app/main.go:290`; tests `internal/today/handler_test.go:94,128` |
| Agent-surface write tools (`propose_*`, `capture_inbox`, `resolve_task`) | implemented; handler-level input validation tested | `internal/mcp/handler_test.go` |
| Catalog ↔ handler registration parity | drift-tested (names) | `ops_catalog_test.go` — proves registration completeness, not per-tool contract behavior |

### B. Thinly covered (works; named edge / rejection paths under-tested)

| Claim | Gap |
|---|---|
| `propose_*` inert-draft visibility | the invariant that a `status=proposed` row stays out of brief / Today / active listings / selectors has thin coverage — assert it explicitly (§7) |
| Hybrid search semantic branch | the degradation path (embedder nil / timeout) and cross-corpus ranking lack an integration test against real pgvector |

### C. Schema-supported only (NOT implemented — do not assume it works)

| Feature | Reality | Evidence |
|---|---|---|
| **Feed AI relevance scoring** | not active — scoring pipeline not yet wired, items carry score=0; highlights are recency/priority-ordered, not relevance-ranked | `internal/feed/entry/query.sql`; `internal/mcp/brief.go:176-178` |
| **Admin global-search Kind taxonomy** | `internal/search/search.go` declares exactly `KindContent` (`:22`), wired; no other kinds | `internal/search/search.go:19-22` |
| **`contents.ai_metadata` consumer contract** | column exists with documented shape `{summary, keywords, quality_score, review_notes}` (schema comment `:493`); not type-checked — advisory only (§7) | `migrations/001_initial.up.sql:457,493` |

### F. Today surface — fully wired

The Today aggregate is now a complete backend surface (the earlier
"`WithSources` is not called anywhere" / "partially wired" caveat is obsolete):

| Endpoint | Status | Evidence |
|---|---|---|
| `GET /api/admin/commitment/today` | exists, fully wired | `cmd/app/routes.go:247` → `today.Handler.Today` |
| `GET /api/admin/system/health` | exists | `cmd/app/routes.go:301` → `stats.Handler.Health` |

- `today.NewHandler(dailyStore, logger)` requires only the plan reader; the
  cross-domain readers (overdue/today/upcoming todos, active goals, RSS
  highlights) are injected via `WithSources(...)`, which **is** called in
  production at `cmd/app/main.go:290`. Every section is populated.
- The handler models no `AwaitingJudgment` / `tasks` section — there is one
  work-item entity (`todos`) and no coordination triad
  (`internal/today/handler.go:49-82`).
- Tested for both empty-state and wired-sections behavior
  (`internal/today/handler_test.go:94,128`).
- Daily Plan is subsumed by this aggregate (`cmd/app/routes.go:318`).

### G. Carried-forward human-resolved decisions (do not re-litigate)

- **Search corpus** — `search_knowledge` covers the content corpus only
  (article / essay / build-log / til / digest); the reading and song shelves
  were removed (that material lives in Obsidian) (`catalog.go::SearchKnowledge`).
- **Embedding posture** — the owner decided to build the embedding write path;
  it is implemented (§6A) rather than deferred.

---

## 7. Testing implications & Open Questions

### What must be tested before each domain is trustworthy

| Domain | Must test before trusting |
|---|---|
| **MCP tools** | Catalog parity is already drift-tested (names only, `ops_catalog_test.go`) — that is not a contract test. Add claim-level contract tests for all **14**: the `brief.mode` discriminator rejects out-of-set values; each writability annotation matches the actual side effect; the read-only tools write nothing; each `propose_*` produces an inert `status=proposed` row that feeds no dashboard / brief / Today / active listing; `propose_content` lands at `status=review` with `is_public=false`; `resolve_task` is caller-scoped (another agent's todo returns not-found); per-tool authorization gate. |
| **Search** | Integration-test the hybrid path against real pgvector: FTS + pgvector fusion over the content corpus, RRF ranking judgment, and graceful degradation when the embedder is nil / times out. |
| **Embedding** | Integration-test the reconciler: a newly-inserted content row acquires an embedding on the next pass; an embed failure leaves the row retryable (still listed by `MissingEmbeddings`) rather than silently skipped; FTS-only path when `GEMINI_API_KEY` is unset. |
| **Commitment proposals** | Each `propose_*` writes an inert `status=proposed` row invisible to brief / Today / active listings / selectors; area-reject cascades its proposed child goals; goal-reject cascades its milestones; a `capture_inbox` link to a proposed project survives activation and is unlinked (not deleted) on reject; `resolve_task` caller-scoping. |
| **Frontend workflows** | A backend/frontend route compatibility matrix (every admin page: frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error behavior); then golden-flow each admin area; assert no UI affordance violates a forbidden assumption below. |
| **Observability** | Inventory `activity_events` producers (the audit triggers, `migrations/001_initial.up.sql:1049-1173`) and map each to `entity_type` × `change_kind` × actor attribution × write path × user-visible event. Confirm `koopa.actor` is set on every Go write path so `actor='system'` only appears for genuine cron/manual ops. |

### Forbidden assumptions (UI / impl must NOT build on these)

The system models one work-item entity (`todos`) and no inter-agent
coordination layer — build nothing on `tasks` / `task_messages` / `artifacts` /
`reports` / `research_assignments`. Agent memory is each agent's own `.md`, not
a backend table. The agent commitment write surface is exactly: `capture_inbox`
(raw todo), `propose_area` / `propose_goal` / `propose_project` (inert
`status=proposed` drafts — agents never activate or reject; that is admin HTTP,
and proposals materialize only from owner-present conversations, never from
scheduled runs), `propose_content` (finished piece into `status=review`, never
published by an agent), `revise_content` (caller-scoped revise of the agent's
own `review` / `changes_requested` content), `plan_day`, and `resolve_task`
(caller-scoped self-clear). Content publishing is admin HTTP only. Other structural guarantees: no daily-plan
auto-carryover; no RBAC; no quantitative milestones; no goal auto-status; no
direct `activity_events` INSERT. (Each is schema- or policy-enforced; see §3.)

### Open Questions (require human decision)

1. **`contents.ai_metadata` consumer contract** — the documented shape
   `{summary, keywords, quality_score, review_notes}` (`:493`) is not
   type-checked; treat as advisory. Keep, formalize, or drop?
2. **Feed AI relevance scoring** — implement (replace the score=0 placeholder)
   or formally drop?
3. **Actor attribution surfacing** — `activity_events.actor` exists but is not
   propagated into the aggregate-reader outputs (`brief`); widen those types?
4. **External `schedule` execution observability** — scheduled execution is
   owned by the external Cowork/Desktop runner; this repo provides the registry
   metadata, the schema, and the `process_runs(kind='agent_schedule')` row.
   Whether the runner is actively writing those rows is not observable from this
   repo. Add a read-side surface ("last schedule run per agent" on
   `/api/admin/system/health`)?
5. **`project_aliases` surface** — exists for fuzzy project resolution; not
   exposed in admin UI.
6. **"Blocked work" definition** — a blocked-work affordance, if ever wanted,
   would be a derived condition over `todos` (the system's one work-item
   entity), not a new entity.

### Known schema-comment drift (not this document's authority, flagged for cleanup)

- `migrations/001_initial.up.sql:486` (the `contents` table comment) still
  names retired MCP tools `set_content_review_state` / `publish_content` for the
  review handoff. The live agent path is `propose_content` (review push);
  publish is admin HTTP. The comment should be re-grounded to the current
  surface in a future migration-comment pass.
