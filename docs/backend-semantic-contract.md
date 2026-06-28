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

- Every implementation-backed statement carries a stable **symbol** reference —
  a table / type / enum / constraint / index / function / route name — rather
  than a line number, because symbols survive file restructuring while line
  numbers rot. Each cite names the file plus the symbol
  (e.g. `migrations/001_initial.up.sql` (`chk_content_publication`)).
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
| **Personal semantic infrastructure** | `agents.name` as universal actor identity; `activity_events` as the canonical change log written only by triggers | `internal/agent/`, `internal/activity/`, schema triggers `migrations/001_initial.up.sql` (`current_actor` + `audit_* triggers`) |
| **PARA / GTD / OKR-ish system** | areas, goals, milestones, projects, todos, daily plan | `internal/goal/`, `internal/project/`, `internal/todo/`, `internal/daily/` |
| **MCP tool surface** | **15 agent-facing tools** | `internal/mcp/ops/catalog.go::All()` (canonical list) |
| **Knowledge / search system** | content, topics, feeds; hybrid FTS + pgvector search | `internal/content/`, `internal/search/`, `internal/mcp/search.go` |

> **This is a closed single-owner + small-agent-roster knowledge OS.** The
> agent-facing MCP surface is **15 tools** (`internal/mcp/ops/catalog.go::All()`).
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
   startup (`registry.go::BuiltinAgents()`); an agent row persists and carries a status
   (`agent_status`, `migrations/001_initial.up.sql`), so a name stays a
   stable FK target for the life of the audit log.
2. **`activity_events` is written exclusively by AFTER triggers.** Application
   code must never INSERT (`migrations/001_initial.up.sql` — `activity_events`
   table, its "MUST NOT INSERT" table COMMENT; audit function + triggers
   `current_actor` + `audit_* triggers`).
   Actor flows from the `koopa.actor` GUC via `current_actor()`
   (`migrations/001_initial.up.sql`), defaulting to `'human'` — there is no synthetic `'system'` agent.
3. **Illegal states are made structurally impossible** through joint CHECKs,
   partial unique indexes, and narrow triggers — not application discipline
   alone. The publish CHECKs couple `status='published'` with `published_at`
   (`chk_content_publication`) and gate `is_public` on `published`
   (`chk_content_public_requires_published`); an inert proposal
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
| **MCP ops catalog** | `internal/mcp/ops/catalog.go` | **Authoritative** (tool surface) | The `All()` list is the canonical agent-facing tool surface; drift-tested against handler registration (`ops_catalog_test.go`). |
| **sqlc-generated code** | `internal/db/` | **Derived** | Generated from `query.sql` files; never hand-edited. |
| **This contract** | `docs/backend-semantic-contract.md` | **Derived** | Shared vocabulary; below schema/code/catalog. |
| **PARA usage contract** | `docs/para-semantic-contract.md` | **Derived** | The classification/usage layer (which real thing maps to which entity). Below the same three authorities. |
| **Cowork agent op docs** | `skills/koopa-system/` + each agent's own Cowork project `CLAUDE.md` | **Advisory** | Per-agent operational guidance; never structural truth. |
| **Frontend route/service code** | `frontend/src/app/**` | **Advisory / assumption** | Encodes the frontend's *assumed* backend contract. |

**Implementation-only (no doc is authoritative; read the code):**
`internal/mcp/search.go` (RRF merge constants and FTS/semantic fusion —
`rrfMerge`).

---

## 3. Core domain vocabulary

Format per term: **meaning** · *defined/implied at* · **enforced?** ·
*ambiguity / open question*. The "is not" lines are load-bearing — getting
them wrong is a semantic bug, not a naming quibble.

### Identity / actors

- **agent** — an actor that may write to the system (human, Cowork Claude
  instance, Claude Code, system bot). *Source of truth*
  `registry.go::BuiltinAgents()`; DB row is an identity projection
  (name / platform / status). **Enforced**: FK target for every actor column.
  There is **no tool-layer authorization** (Option B, 2026-06): access is gated
  by the MCP transport, and `as` only carries attribution + caller-scope
  (`server.go::callerIdentity`). *Is not* a user account; *is not* a Cowork
  project (one platform an agent can run on).
- **user** — a login identity (`users` table) + `refresh_tokens`. Exactly one
  admin today; the admin logs in and acts as agent name `human`
  (`registry.go::BuiltinAgents()` — `human` entry). `user_id` is **not** used as actor identity.
- **actor** — the `agents.name` value attributed to one `activity_events` row;
  set from the `koopa.actor` GUC inside the audit trigger via `current_actor()`
  (`migrations/001_initial.up.sql`).
- **Koopa** — the human owner (display name on the `human` agent) — the sole
  decision-maker and sole router.
- **Agents** — `claude` (`claude-code`) does repo development and agent-surface
  work; `codex` (`codex`) is a dev collaborator / cross-reviewer; `hermes`
  (`hermes`) does scheduled vault curation. An agent session is a runtime, not a
  coordination peer (§4). There are no synthetic agents: no `system` (the audit
  trigger falls back to `human`), no `unknown` (an `as`-less write is refused).

### Commitment (PARA + GTD + goals)

> The classification/usage layer — which real-world thing maps to which entity
> and why — lives in `docs/para-semantic-contract.md`. This section defines the
> entities and their enforced lifecycle.

- **project (PARA)** — a PARA execution vehicle: a concrete effort with
  deliverables (`projects` table, `migrations/001_initial.up.sql`). Has
  nullable `area_id` and `goal_id` (`projects.area_id` / `projects.goal_id`); may be `maintained` (continuous).
  Its status lifecycle is `project_status` (`proposed | planned |
  in_progress | on_hold | completed | maintained | archived`). An agent
  may draft an inert `status='proposed'` project via `propose_project` —
  invisible until the owner activates (proposed→in_progress) or rejects it;
  `capture_inbox` can link a todo to a proposed project by slug, and the link
  survives activation. *Is not* a Cowork project / agent identity (§4).
- **area (PARA)** — an ongoing domain of responsibility / sphere of life
  (`areas` table). Activation is an admin action; an agent may draft an inert
  proposal via `propose_area` (`status='proposed'`), and the owner activates
  (proposed→active) or rejects (hard delete, cascading to its proposed child
  goals) in admin triage (the `/api/admin/commitment/areas` routes).
- **goal** — a finite objective, optionally area-scoped, with optional
  deadline/quarter. Status (`goal_status`: `proposed | not_started →
  in_progress → done | abandoned | on_hold`) is **manually managed**, not
  auto-derived from milestones. The owner creates and re-statuses a goal via
  the admin forms (the `/api/admin/commitment/goals` routes); an agent may draft an inert
  `status='proposed'` goal (with ordered milestones) via `propose_goal`, which
  the owner activates (proposed→in_progress) or rejects in admin triage.
- **milestone** — a binary done/not-done checkpoint inside a goal
  (`milestones` table); `milestone.goal_id` is **NOT NULL**
  (`milestones.goal_id`) — a milestone only attaches to a goal, never a project. Completion is
  `completed_at IS NOT NULL` (`milestones.completed_at`), no status column. **Not** an OKR key
  result — no `target_value`/`current_value` (`milestones` table COMMENT).
  Created via the admin milestone form (the `/api/admin/commitment/goals/{id}/milestones` route), or as part of
  a `propose_goal` proposal bundle that the owner activates.
- **todo** — a personal GTD work item (`todos` table). `todo_state`: `inbox →
  todo → in_progress → done`, plus `someday`, `archived`, `dismissed`. Optional
  `project_id` only — no `goal_id` / `area_id` edge. `completed_at` is coupled
  to `state='done'` by CHECK (`chk_todo_completed_at_consistency`). *Is not* a `task`.
- **daily_plan_item** — "today I commit to this todo" (`daily_plan_items` table). Status CHECK
  `planned | done | deferred | dropped` (`daily_plan_items` status CHECK). **No auto-carryover** — no
  trigger copies yesterday's items forward; `deferred` is a manual carry-over
  *candidate*, not an automatic one (`daily_plan_items` table COMMENT).

### Knowledge

- **content** — first-party publishable artifact (`contents` table). Five types:
  `article`, `essay`, `build-log`, `til`, `digest` (`content_type`).
  `content_status`: `draft → review → published → archived`. The owner
  publishes a **draft directly** (`Store.Publish` promotes draft *or* review →
  published — the common path for Koopa's own finished work); review is the
  **agent** handoff, not a step the owner is forced through. Publishing ties
  `status='published'` to `published_at` (`chk_content_publication`) and gates `is_public` on
  `published` (`chk_content_public_requires_published`). Content authoring / lifecycle is **admin HTTP** under
  `/api/admin/knowledge/content` (the `/api/admin/knowledge/content` routes); the one agent
  path is `propose_content`, which inserts a finished piece at `status='review'`
  with `is_public=false` for the owner to publish or reject — an agent never
  publishes. Each row carries an `embedding vector(1536)` column (`contents.embedding`) that
  the reconciler fills (§6).
- **source / provenance** — attribution of where a knowledge row came from.
  Columns: `contents.origin_system`, `feed_entries → feeds`.
  `activity_events.actor` + entity-title/slug + `area_id` write-time snapshots
  give per-mutation provenance (the `area_id` snapshot is resolved by the audit
  triggers across all lineages — goal/project direct, milestone→goal,
  todo/content→project — and powers the all-lineage area rollups, not just
  project-scoped activity). **Ambiguity:** there is no single uniform
  "provenance" object; provenance is per-entity columns + the audit log.
- **feed / feed_entry** — RSS subscription + collected items. `feed_entry`
  lifecycle `unread → read → curated | ignored` (`feed_entry_status`);
  a curated entry produces a content row.

### MCP / system

- **MCP tool** — a registered handler in the MCP server, described by an
  `ops.Meta` (`internal/mcp/ops/types.go` — `Meta`): name, domain, writability,
  stability, since, description, field enums. **15 tools**
  (`catalog.go::All()`).
- **schedule** — a per-agent recurring trigger declared on the Go
  `agent.Agent` literal (`Schedule{Name, Trigger, Expr, Backend, Purpose}`).
  No agent currently declares one; when present it **lives in Go, not the DB.**
  The schedule literal is metadata only; the backend has **no internal
  scheduler** — execution is driven by the external Cowork/Desktop runner. This
  repo owns the registry metadata and the schema, but there is **no
  `process_runs` schema backing for schedules today**: the `process_runs.kind`
  CHECK allows only `'crawl'` — there is no `agent_schedule` kind and no
  `subsystem` column. The `schedule` concept lives only as Go `agent.Agent`
  metadata; the repo does not own scheduled execution.
- **schedule run** — a single execution of an external agent schedule. **No
  `process_runs` schema backs this today**: the `process_runs` table
  (`migrations/001_initial.up.sql`) has a `process_runs.kind` CHECK that allows
  only `'crawl'` (internal fetch/collector runs, RSS) — there is no
  `agent_schedule` kind, no `subsystem` column, and no
  `chk_process_runs_subsystem_iff_agent_schedule` constraint. *Is not* a `task`.
  This repo does not back schedule execution with `process_runs` and will not —
  schedule-run observability is out of scope here.

---

## 4. Domain boundaries

The named confusions and their resolutions, each grounded.

| Boundary | Term A | Term B | Rule | Grounding |
|---|---|---|---|---|
| **PARA project vs agent identity** | `projects` row (work vehicle) | an `agents` row (actor identity) | A PARA project is data in `projects`; an agent is an actor in `agents`. They never share a table or ID. | `projects` table; `registry.go` |
| **todo is the only work-item entity** | `todos` (personal GTD) | (no `tasks` entity) | There is no inter-agent `tasks` triad, so there is no "task vs todo" boundary to police — a todo is the system's only work-item entity. | `todo_state` enum |
| **inert proposal vs active commitment** | `status='proposed'` area / goal / project (agent draft) | the activated row (owner action) | A proposed entity is fully inert — invisible to brief / Today / active listings / selectors — until the owner activates it in admin triage. The agent drafts; the owner commits. | `propose_*` handlers; the `/api/admin/commitment/projects\|areas\|goals` routes |
| **MCP tool call vs semantic write** | a `tools/call` invocation | the resulting row + `activity_event` | A read-only tool call (`ReadOnly` writability — `brief`, `search_knowledge`, `list_todos`, `list_content`, `review_period`, `project_progress`) produces no semantic write. Only Additive/Idempotent/Destructive tools write; the *write* is the row + its trigger-emitted audit event, not the call. | `ops/types.go` (`Writability`) |
| **Claude Code runtime vs Koopa identity** | `claude` agent (dev session, `claude-code`) | `human` agent (Koopa) | Both attribute writes via `as`; there is no tool-layer override for either (Option B — no `requireAuthor`). The live distinction is actor-attribution identity (`actor='human'` is what `project_progress` / `review_period` count as owner momentum), not coordination authority. | `server.go::callerIdentity`; `registry.go` |
| **frontend page model vs backend domain model** | Angular admin pages (composed views) | backend entities | Page-level view-models are **not** backend entities. The Today page is now backed by a fully-wired backend aggregate (§6F). | `internal/today/handler.go`; §2 |

---

## 5. MCP tool semantics

The canonical tool inventory, each tool's per-tool writability (`ReadOnly |
Additive | Idempotent | Destructive` — `ops/types.go` (`Writability`)), and its
description live in `internal/mcp/ops/catalog.go::All()`,
drift-tested against handler registration in `ops_catalog_test.go`. The
read-only tools (`brief`, `search_knowledge`, `list_todos`, `list_content`,
`review_period`, `project_progress`) are permanently read-only. This contract
points at the catalog rather than duplicating the per-tool table; read
`catalog.go::All()` for the authoritative surface.

The agent write surface is exactly: `capture_inbox` (Additive), `plan_day`
(Idempotent — atomic replacement), `propose_area` / `propose_goal` /
`propose_project` / `propose_content` (Additive — inert drafts / review-queue
push), `revise_content` (Destructive — caller-scoped revise of the agent's own
`review` / `changes_requested` content, resent to the review queue),
`resolve_todo` (Destructive — caller-scoped self-clear of a todo the agent
created), and `set_todo_recurrence` (Destructive — caller-scoped recurrence
schedule for a todo the agent created).

---

## 6. Implementation status

What is actually wired and exercised, separated from what the schema merely
permits. Existence of a table, handler, or doc is not proof of a working path.

### A. Implemented and wired

| Capability | Reality | Evidence |
|---|---|---|
| Login + refresh-token rotation + token security | implemented, tested | `internal/auth/` (`auth_test.go`, `handler_test.go`) |
| Content lifecycle (admin HTTP; owner publishes a draft directly via `Store.Publish`, or a review row from the queue; `propose_content` lands an agent piece at `status=review`, `is_public=false`) | implemented; `Store.Publish` gates draft/review→published, publish CHECKs enforce the rest | `internal/content/publish.go`; CHECKs `migrations/001_initial.up.sql` (`chk_content_publication`, `chk_content_public_requires_published`); routes the `/api/admin/knowledge/content` routes |
| Feed fetch + scheduler cadence + auto-disable on failures | implemented, tested | `internal/feed/scheduler_test.go` (testcontainers) |
| **Document-embedding write path** | **Implemented (this is the current state, not a TODO).** `embedder.Embed` (`internal/embedder/embedder.go`) is driven by a background `Reconciler` (`internal/embedder/reconciler.go`) that drains every registered source — currently just `contents` (`cmd/app/main.go`) — embedding rows missing a vector. Two call sites: the `app` server runs a background `Run` loop, gated on `GEMINI_API_KEY` (`cmd/app/main.go`), and the `embed-backfill` subcommand runs a one-shot `RunOnce` (`runBackfill`, `cmd/app/main.go`, dispatched from `main`); the `mcp` server also constructs one (`cmd/mcp/main.go`). Unset `GEMINI_API_KEY` → FTS-only (`cmd/mcp/main.go`). | `reconciler.go` (`Reconciler`); `content/embedding.go` |
| **Hybrid search (FTS + pgvector RRF)** | implemented; per-corpus FTS fused with pgvector semantic results via reciprocal-rank fusion, degrading to FTS-only when no embedder is configured | `internal/mcp/search.go` — `rrfMerge`; HNSW index `migrations/001_initial.up.sql` (`idx_contents_embedding_hnsw`) |
| Today aggregate (admin HTTP) | implemented + fully wired (§6F) | `cmd/app/main.go` (`WithSources` wiring); tests `internal/today/handler_test.go` |
| Agent-surface write tools (`propose_*`, `capture_inbox`, `resolve_todo`) | implemented; handler-level input validation tested | `internal/mcp/handler_test.go` |
| Catalog ↔ handler registration parity | drift-tested (names) | `ops_catalog_test.go` — proves registration completeness, not per-tool contract behavior |

### B. Thinly covered (works; named edge / rejection paths under-tested)

| Claim | Gap |
|---|---|
| `propose_*` inert-draft visibility | the invariant that a `status=proposed` row stays out of brief / Today / active listings / selectors has thin coverage — assert it explicitly (§7) |
| Hybrid search semantic branch | the degradation path (embedder nil / timeout) and cross-corpus ranking lack an integration test against real pgvector |

### C. Schema-supported only (NOT implemented — do not assume it works)

| Feature | Reality | Evidence |
|---|---|---|
| **Feed highlight ordering** | no AI relevance scoring (a deliberate non-feature); highlights are recency/priority-ordered. The `score` field is vestigial | `internal/feed/entry/query.sql`; `internal/mcp/brief.go` |
| **Admin global-search Kind taxonomy** | `internal/search/search.go` declares exactly `KindContent`, wired; no other kinds | `internal/search/search.go` (`Kind` / `KindContent`) |
| **`contents.ai_metadata` consumer contract** | column exists with documented shape `{summary, keywords, quality_score, review_notes}` (schema comment on `contents.ai_metadata`); not type-checked — advisory only (§7) | `migrations/001_initial.up.sql` (`contents.ai_metadata`) |

### F. Today surface — fully wired

The Today aggregate is now a complete backend surface (the earlier
"`WithSources` is not called anywhere" / "partially wired" caveat is obsolete):

| Endpoint | Status | Evidence |
|---|---|---|
| `GET /api/admin/commitment/today` | exists, fully wired | `cmd/app/routes.go` → `today.Handler.Today` |
| `GET /api/admin/system/health` | exists | `cmd/app/routes.go` → `stats.Handler.Health` |

- `today.NewHandler(dailyStore, logger)` requires only the plan reader; the
  cross-domain readers (overdue/today/upcoming todos, active goals, RSS
  highlights) are injected via `WithSources(...)`, which **is** called in
  production at `cmd/app/main.go` (`WithSources`). Every section is populated.
- The handler models no `AwaitingJudgment` / `tasks` section — there is one
  work-item entity (`todos`) and no coordination triad
  (`internal/today/handler.go` — `Handler.Today`).
- Tested for both empty-state and wired-sections behavior
  (`internal/today/handler_test.go`).
- Daily Plan is subsumed by this aggregate (`cmd/app/routes.go` — `GET /api/admin/commitment/today`).

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
| **MCP tools** | Catalog parity is already drift-tested (names only, `ops_catalog_test.go`) — that is not a contract test. Add claim-level contract tests for all **15**: the `brief.mode` discriminator rejects out-of-set values; each writability annotation matches the actual side effect; the read-only tools write nothing; each `propose_*` produces an inert `status=proposed` row that feeds no dashboard / brief / Today / active listing; `propose_content` lands at `status=review` with `is_public=false`; `resolve_todo` is caller-scoped (another agent's todo returns not-found). There is NO per-tool authorization gate — Option B: `as` is attribution only, and access is bounded by the MCP transport (HTTP Bearer + admin-email OAuth, or the stdio process boundary), so a contract test must assert the absence of a caller-identity gate, not its presence. |
| **Search** | Integration-test the hybrid path against real pgvector: FTS + pgvector fusion over the content corpus, RRF ranking judgment, and graceful degradation when the embedder is nil / times out. |
| **Embedding** | Integration-test the reconciler: a newly-inserted content row acquires an embedding on the next pass; an embed failure leaves the row retryable (still listed by `MissingEmbeddings`) rather than silently skipped; FTS-only path when `GEMINI_API_KEY` is unset. |
| **Commitment proposals** | Each `propose_*` writes an inert `status=proposed` row invisible to brief / Today / active listings / selectors; area-reject cascades its proposed child goals; goal-reject cascades its milestones; a `capture_inbox` link to a proposed project survives activation and is unlinked (not deleted) on reject; `resolve_todo` caller-scoping. |
| **Frontend workflows** | A backend/frontend route compatibility matrix (every admin page: frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error behavior); then golden-flow each admin area; assert no UI affordance violates a forbidden assumption below. |
| **Observability** | Inventory `activity_events` producers (the audit triggers, `migrations/001_initial.up.sql` — `current_actor` + `audit_* triggers`) and map each to `entity_type` × `change_kind` × actor attribution × write path × user-visible event. Confirm `koopa.actor` is set on every Go write path so `actor='system'` only appears for genuine cron/manual ops. |

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
own `review` / `changes_requested` content), `plan_day`, and `resolve_todo`
(caller-scoped self-clear). Content publishing is admin HTTP only. Other structural guarantees: no daily-plan
auto-carryover; no RBAC; no quantitative milestones; no goal auto-status; no
direct `activity_events` INSERT. (Each is schema- or policy-enforced; see §3.)

### Open Questions (require human decision)

1. **`contents.ai_metadata` consumer contract** — the documented shape
   `{summary, keywords, quality_score, review_notes}` (the `contents.ai_metadata`
   COMMENT) is not type-checked; treat as advisory. Keep, formalize, or drop?
2. **Actor attribution surfacing** — `activity_events.actor` exists but is not
   propagated into the aggregate-reader outputs (`brief`); widen those types?
3. **"Blocked work" definition** — a blocked-work affordance, if ever wanted,
   would be a derived condition over `todos` (the system's one work-item
   entity), not a new entity.
