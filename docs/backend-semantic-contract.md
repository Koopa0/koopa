# Backend Semantic Contract

> **Track 0 closeout baseline (Track 0.1 corrected, 2026-05-21).** This is the
> grounded semantic contract for the koopa0.dev backend, organized as **seven
> numbered sections** (§1–§7). Change/audit discipline is NOT a content section
> of this contract.
>
> It is intended to become the basis for: MCP tool contract tests, hybrid
> search judgment tests, commitment-proposal lifecycle tests, frontend UI/UX
> golden flows, and the observability event taxonomy.
>
> Track 0.1 corrected the Today-surface claim (endpoints exist; the risk is
> fan-out vs partially-wired aggregate), tightened §6 to claim-level
> confidence, and reworded the search conclusion.

**Grounding discipline used in this rewrite:**

- Every implementation-backed statement carries a `file:line` reference.
- Statements not provable from the repo are marked **Open Question**.
- The existence of a table, a doc, or a handler is **not** treated as proof
  that a feature works. §6 separates "implemented and tested" from the rest.
- Where the prior contract recorded a human decision (e.g. FTS-only is the
  current `search_knowledge` production behavior, decided Phase 1D 2026-05-27),
  that decision is carried forward verbatim in §6 / §7 rather than re-derived.

---

## 1. System purpose

### What koopa0.dev is

A **private-by-default personal knowledge / learning OS for a single human
owner and a small closed set of AI agents.** One Go backend serves one admin
(`users`, single row today) and ≤10 registered agents
(`internal/agent/registry.go`). Every party reads and writes through the same
two surfaces: the PostgreSQL schema and the MCP tool layer on top of it. A
public Angular site is a read-only projection of the publishable subset.

It is **all of the following, with explicit boundaries** (§4):

| Facet | What it covers | Backing |
|---|---|---|
| **Personal semantic infrastructure** | `agents.name` as universal actor identity; `activity_events` as the canonical change log written only by triggers | `internal/agent/`, `internal/activity/`, schema triggers `migrations/001_initial.up.sql` |
| **PARA / GTD / OKR-ish system** | areas, goals, milestones, projects, todos, daily plan | `internal/goal/`, `internal/project/`, `internal/todo/`, `internal/daily/` |
| **MCP tool surface** | **13 agent-facing tools** | `internal/mcp/ops/catalog.go::All()` (canonical list) |
| **Knowledge / search system** | content, topics, tags, feeds, the reading shelf, the song shelf; hybrid search | `internal/content/`, `internal/search/`, `internal/mcp/search.go` |

> **This is a closed single-owner + ≤10-agent knowledge OS.** The
> agent-facing MCP surface is **13 tools** (`internal/mcp/ops/catalog.go::All()`).
> Milestone creation, area/goal/project activation, and content publication are
> **admin-only HTTP forms** under `/api/admin/` (`cmd/app/routes.go`); agents
> draft area/goal/project as inert proposals and push finished content into the
> review queue. There is no inter-agent coordination layer in the backend. Agent
> memory is not a backend entity — each agent keeps its own `.md`. The schema is
> migrations **001 + 002**.

It is **NOT**: a multi-user product, an RBAC system, a public CMS with
arbitrary authorship, or a generic agent marketplace. The agent set is closed
and compiled into the binary (`internal/agent/registry.go`).

### Architectural invariants (the three load-bearing rules)

1. **`agents.name` is the only actor identity.** Every mutation is attributed
   via FK (`created_by` / `curated_by` / `selected_by` / `actor` / `assignee`).
   The registry is a projection of the Go `BuiltinAgents()` literal synced at
   startup; an agent row persists and carries a status, so a name stays a stable
   FK target for the life of the audit log (`registry.go:8-14`).
2. **`activity_events` is written exclusively by AFTER triggers.** Application
   code must never INSERT (`migrations/001_initial.up.sql:1166` table comment;
   triggers `2646-2911`). Actor flows from the `koopa.actor` GUC via
   `current_actor()` (`2646-2656`), defaulting to `'system'`.
3. **Illegal states are made structurally impossible** through joint CHECKs,
   partial unique indexes, and narrow triggers — not application discipline
   alone (a curated feed-entry resolves to a content row; the publish CHECK
   couples `status='published'` / `is_public=true` / `published_at`; an inert
   proposal carries `status='proposed'`). There is no `tasks` entity, so the
   task state↔timestamp / completion-requires-outputs invariants do not exist.

---

## 2. Sources of truth

When two sources disagree about **what the system does**, the higher tier
wins and the lower MUST be updated. This authority order resolves
*descriptive* conflicts only — it does **not** settle *normative* questions
("is this behavior intended?"). Normative questions go to §7 Open Questions
and are resolved only by the human owner.

| Source | Path(s) | Status | Notes |
|---|---|---|---|
| **Schema + DB constraints** | `migrations/001_initial.up.sql`, `002_seed.up.sql` | **Authoritative** | CHECKs, triggers, FKs are the last word on legal states. 2920 + 13k lines. |
| **Go code + tests** | `internal/`, `cmd/` | **Authoritative** (reference impl) | A passing test pins observable behavior. When prose disagrees with a green test, the test wins. |
| **MCP ops catalog** | `internal/mcp/ops/catalog.go` | **Authoritative** (tool surface) | The `All()` list is the canonical agent-facing tool surface; drift-tested against handler registration (`ops/types.go:9-11`, `ops_catalog_test.go`). |
| **sqlc-generated code** | `internal/db/` | **Derived** | Generated from `query.sql` files; never hand-edited. |
| **This contract** | `docs/backend-semantic-contract.md` | **Derived** | Shared vocabulary; below schema/code/catalog. |
| **Cowork agent op docs** | `skills/koopa-system/` + each agent's own Cowork project `CLAUDE.md` | **Advisory** | Per-agent operational guidance; never structural truth. |
| **Frontend route/service code** | `frontend/src/app/**` | **Advisory / assumption** | Encodes the frontend's *assumed* backend contract. The endpoints it calls (incl. `/api/admin/commitment/today`, `/api/admin/learning/summary`, `/api/admin/system/health`) **do exist** (`cmd/app/routes.go:204,269,333`); the open risk is payload compatibility and the Today fan-out-vs-aggregate split — see §6. |
| **Audit reports** | `docs/audit/`, `docs/audit-prompts/` | **Stale / point-in-time** | Historical context only; NOT runtime truth. |

**Implementation-only (no doc is authoritative; read the code):**
`internal/mcp/execution.go::normalizePriority` (priority alias acceptance),
`internal/mcp/search.go` (RRF merge constants).

---

## 3. Core domain vocabulary

Format per term: **meaning** · *defined/implied at* · **enforced?** ·
*ambiguity / open question*. The "is not" lines are load-bearing — getting
them wrong is a semantic bug, not a naming quibble.

### Identity / actors

- **agent** — an actor that may write to the system (human, Cowork Claude
  instance, Claude Code, system bot). *Source of truth*
  `registry.go::BuiltinAgents()`; DB row is an identity projection (name /
  platform / status). **Enforced**: FK target for every actor column;
  authorization is identity-based at runtime (`internal/mcp/authz.go` —
  author allowlists, registration, human-only gates). *Is not* a user
  account; *is not* a Cowork project (one platform an agent can run on).
- **user** — a login identity (`users` table) + `refresh_tokens`. Exactly one
  admin today; the admin logs in and acts as agent name `human`
  (`registry.go:103-111`). `user_id` is **not** used as actor identity.
- **actor** — the `agents.name` value attributed to one `activity_events` row;
  set from the `koopa.actor` GUC inside the audit trigger
  (`migrations/001_initial.up.sql:2646-2656`).
- **planner / Koopa** — `planner` is the `claude-cowork` daily-driver agent:
  morning briefing, candidate day plans, inbox capture, search
  (`registry.go`). "Koopa" is the human owner (display name on
  the `human` agent) — the sole decision-maker and sole router.
- **Claude Cowork project** — a `claude-cowork` platform agent: `planner`
  (`registry.go`). A platform/identity, not a PARA `project` (§4).
- **Claude Code** — `claude-code` platform agents (`koopa0-dev`, `go-spec`,
  `hermes`), doing repo development and scheduled vault work. A Claude Code
  session is a dev runtime, not a coordination peer (§4).

### Commitment (PARA + GTD + goals)

- **project (PARA)** — a PARA execution vehicle: short-term effort with
  deliverables (`projects` table). May serve a goal; has its own status
  lifecycle (`project_status` enum, incl. `proposed`). 1:1 optional
  `project_profile` for public display. An agent may draft an inert
  `status='proposed'` project via `propose_project` — invisible until the owner
  activates (proposed→in_progress) or rejects it; `capture_inbox` can link a
  todo to a proposed project by slug, and the link survives activation. *Is
  not* a Cowork project / agent identity (§4).
- **area (PARA)** — an ongoing domain of responsibility (`areas` table).
  Activation is an admin action; an agent may draft an inert proposal via
  `propose_area` (`status='proposed'`), and the owner activates (proposed→active)
  or rejects (hard delete, cascading to its proposed child goals) in admin
  triage.
- **goal** — an aspirational outcome, optionally area-scoped, with optional
  deadline/quarter. Status (`goal_status`: `proposed | not_started →
  in_progress → done | abandoned | on_hold`) is **manually managed**, not
  auto-derived from milestones. The owner creates and re-statuses a goal via
  the admin form `POST /api/admin/commitment/goals` /
  `PUT /api/admin/commitment/goals/{id}/status`; an agent may draft an inert
  `status='proposed'` goal (with ordered milestones) via `propose_goal`, which
  the owner activates (proposed→in_progress) or rejects in admin triage.
- **milestone** — a binary done/not-done checkpoint inside a goal. **Not** an
  OKR key result — no `target_value`/`current_value` (§7 forbidden
  assumptions). Goal progress = completed/total (advisory). Created via
  `POST /api/admin/commitment/goals/{id}/milestones`, or as part of a
  `propose_goal` proposal bundle that the owner activates.
- **todo** — a personal GTD work item. `todo_state`: `inbox → todo →
  in_progress → done`, plus `someday`. *Is not* a `task`.
- **daily_plan_item** — "today I commit to this todo." Status CHECK `planned |
  done | deferred | dropped` (`970-971`). **No auto-carryover** — verified: no
  trigger copies yesterday's items forward (only structural triggers exist on
  the table).

### Knowledge

- **content** — first-party publishable artifact. Five types: `article`,
  `essay`, `build-log`, `til`, `digest`. `content_status`: `draft → review →
  published → archived`. Publishing atomically flips `status='published'`,
  `is_public=true`, `published_at=now()`. Content authoring / lifecycle is
  **admin HTTP** under `/api/admin/knowledge/content` (`cmd/app/routes.go:147-156`);
  the one agent path is `propose_content`, which inserts a finished piece at
  `status='review'` with `is_public=false` for the owner to publish or reject —
  an agent never publishes.
- **reading (shelf)** — Koopa's reading shelf: one row per book (`readings`),
  with status (`want_to_read | reading | finished | abandoned`), dates, an
  optional `goal_id` link, and a dated reflection diary thread. Written in
  admin; the MCP surface reads it through `list_readings` / `get_reading`
  (`source_type=reading` in search), never writes it.
- **song (shelf)** — Koopa's ヨルシカ song shelf: one row per song with a
  reflection diary. Written in admin; agent-visible only through
  `search_knowledge` (`source_type=song`), read-only.
- **source / provenance** — attribution of where a knowledge row came from.
  Columns: `contents.origin_system`, `feed_entries → feeds`.
  `activity_events.actor` + `entity_title`/`entity_slug` write-time snapshots
  give per-mutation provenance. **Ambiguity:** there is no single uniform
  "provenance" object; provenance is per-entity columns + the audit log.
- **feed / feed_entry** — RSS subscription + collected items. `feed_entry`
  lifecycle `unread → read → curated | ignored`; a curated entry produces a
  content row.

### MCP / system

- **MCP tool** — a registered handler in the MCP server, described by an
  `ops.Meta` (`ops/types.go:56-71`): name, domain, writability, stability,
  since, description, field enums. **13 tools** (`catalog.go::All()`).
- **schedule** — a per-agent recurring trigger declared on the Go
  `agent.Agent` literal (`Schedule{Name, Trigger, Expr, Backend, Purpose}`,
  `registry.go:24` etc.). `planner` runs `morning-briefing` at `0 8 * * *`
  on `cowork_desktop` — the one scheduled agent. **Lives in Go, not the DB.**
  **DECIDED (Phase 1D, 2026-05-27):** the schedule literal is metadata only and
  the backend has **no internal scheduler** — execution is driven by the
  external Cowork/Desktop runner. This repo owns the registry metadata, the
  schema, and the `process_runs(kind='agent_schedule')` audit row; it does not
  own scheduled execution.
- **schedule run** — a single execution of an external agent schedule,
  recorded in `process_runs` with `kind='agent_schedule'` and a non-null
  `subsystem` (`chk_process_runs_subsystem_iff_agent_schedule`, `798-799`).
  The sibling kind `crawl` is for internal fetch/collector runs (RSS).
  *Is not* a `task`. **Status (Phase 1D, 2026-05-27):** whether the external
  runner is actively writing these rows today is **not yet observable from
  this repo** — adding a read-side observability surface (e.g. "last
  schedule run per agent") is a follow-up task, separate from this decision.

---

## 4. Domain boundaries

The named confusions and their resolutions, each grounded.

| Boundary | Term A | Term B | Rule | Grounding |
|---|---|---|---|---|
| **PARA project vs agent identity** | `projects` row (work vehicle) | Cowork "project" = a `claude-cowork` agent | A PARA project is data in `projects`; a Cowork project is an actor in `agents`. They never share a table or ID. | `projects` schema; `registry.go:17-81` |
| **todo is the only work-item entity** | `todos` (personal GTD) | (no `tasks` entity) | There is no inter-agent `tasks` triad, so there is no "task vs todo" boundary to police — a todo is the system's only work-item entity. | `todo_state` enum |
| **inert proposal vs active commitment** | `status='proposed'` area / goal / project (agent draft) | the activated row (owner action) | A proposed entity is fully inert — invisible to brief / Today / active listings / selectors — until the owner activates it in admin triage. The agent drafts; the owner commits. | `propose_*` handlers; `cmd/app/routes.go` |
| **MCP tool call vs semantic write** | a `tools/call` invocation | the resulting row + `activity_event` | A read-only tool call (`ReadOnly` writability — `brief`, `search_knowledge`, `list_tasks`, `list_readings`, `get_reading`, `project_progress`) produces no semantic write. Only Additive/Idempotent/Destructive tools write; the *write* is the row + its trigger-emitted audit event, not the call. | `ops/types.go:32-42` |
| **Cowork project vs agent identity** | `claude-cowork` agent | the live `agent` entity | A Cowork project IS an agent — a row in `agents` keyed by `name`, the universal actor identity. | `registry.go` |
| **Claude Code runtime vs Koopa identity** | `claude-code` agent (dev session, no capability) | `human` agent (Koopa) | Claude Code agents attribute writes via `as` but hold no capability flags; Koopa (human) carries the platform-human override. No live MCP tool consumes a capability flag — the live distinction is actor-attribution identity, not coordination authority. | `registry.go` |
| **frontend page model vs backend domain model** | Angular admin pages (composed views) | backend entities | The frontend composes multiple backend reads into one page (e.g. the Today page forks 6 calls). Page-level view-models are **not** backend entities and may assume endpoints not yet verified to exist (§6). | frontend `today-page.component.ts`; §2 |

---

## 5. MCP tool semantics

The canonical tool inventory, each tool's per-tool writability (`ReadOnly |
Additive | Idempotent | Destructive`), and its description live in
`internal/mcp/ops/catalog.go::All()`, drift-tested against handler registration
in `ops_catalog_test.go`. The read-only tools (`brief`, `search_knowledge`,
`list_tasks`, `list_readings`, `get_reading`, `project_progress`) are permanently
read-only. This contract points at the catalog rather than duplicating the
per-tool table; read `catalog.go::All()` for the authoritative surface.

---

## 6. Current completion claims

Strict, **claim-level** separation. "An area has tests" is NOT the same as
"the claim is tested". Existence of a table, handler, or doc is not proof.
Each row is a *specific claim* mapped to a *specific test or its absence*.
Grounded in the Track-0 test-coverage audit + direct code reads.

Confidence levels used below:

- **claim-tested** — the exact named behavior has a test asserting it.
- **surface-tested** — only registration/parity/validation is tested, not the
  semantic behavior.
- **weakly tested** — happy path tested; named rejection/edge path untested.
- **schema-supported only** — schema/code exists; no working write/exec path.
- **documented only** — described in docs; no implementation found.
- **unclear / requires evidence** — needs a Track 1 read to classify.

### A. Implemented and CLAIM-tested (specific behavior asserted)

> The claims below describe the agent surface. The following are **not**
> agent-facing and are not listed here as live claims: any task/directive
> triad and inter-agent coordination layer. The agent commitment write paths
> are `capture_inbox`, `propose_area` / `propose_goal` / `propose_project`
> (inert drafts), `propose_content` (review-queue push), `plan_day`, and
> `resolve_task`. Content lifecycle exists behind admin HTTP, so the
> schema-level CHECK claim is retained.

| Claim | Confidence | Evidence |
|---|---|---|
| Login + refresh-token rotation + token security behave as specified | claim-tested | `internal/auth/` — 27 tests incl. `auth_security_test.go` |
| Content draft→review→publish→archive transitions enforce their CHECKs (admin-HTTP-driven; `propose_content` lands at `status=review`) | claim-tested | `internal/content/` integration (testcontainers) |
| Tag raw→canonical alias resolution (auto + admin paths) | claim-tested | `internal/tag/` integration |
| Feed fetch + scheduler cadence + auto-disable on failures | claim-tested | `internal/feed/scheduler_test.go` (testcontainers) |

### B. Implemented and only SURFACE-tested (parity/validation, not semantics)

| Claim | Confidence | Evidence |
|---|---|---|
| The catalog matches handler registration | surface-tested (**parity only**) | `ops_catalog_test.go` compares *names only* — proves registration completeness, **not** per-tool contract behavior |
| `search_knowledge` RRF merge + filter mutex logic | surface-tested (unit, no DB) | `search_test.go` — unit tests on the merge function; no end-to-end search |
| Agent-surface write tools (`propose_*`, `capture_inbox`, `resolve_task`) input validation | surface-tested | `handler_test.go` — validation only, limited business-logic integration |

### C. Implemented but WEAKLY tested (happy path only; rejection paths open)

| Claim | Gap (untested) | Evidence |
|---|---|---|
| `propose_*` inert-draft visibility | the invariant that a `status=proposed` row stays out of brief / Today / active listings has thin coverage | audit |
| Hybrid search semantic branch | no integration test against real pgvector; degradation path (embedder nil/timeout) untested | `search.go`; `search_knowledge` tool has no integration test |

(There are no task-completion / directive-revision / standalone-artifact /
a2a-cap gaps to list here: there is one work-item entity, `todos`, and no
coordination triad.)

### D. Schema-supported only (NOT implemented — do not assume it works)

| Feature | Reality | Evidence |
|---|---|---|
| **Document embedding write path** | **No automatic document-embedding write path exists — this is the current decision, not a TODO.** `embedder.Embed()` is defined (`embedder.go:65`) but has no production call site; app-created `content` rows therefore behave **FTS-only** unless embeddings are externally/backfill-populated. The vector-*read* path is real (`InternalSemanticSearch`, `content/public.go:104-115`) and *would* return rows if embeddings were backfilled — so "no write path" must not be conflated with "semantic branch can never return rows". **Decided (Phase 1D, 2026-05-27):** keep schema, indexes, and embedder package in place; do not implement write/backfill until agent recall ceilings on FTS are observed in practice. `search_knowledge` is documented as FTS-backed today. | `search.go:182-235` (only `EmbedQuery`); no `Embed()` call site; cols `migrations/001_initial.up.sql:495,573` |
| **Feed AI relevance scoring** | Not active — "scoring pipeline not yet active, all items have score=0"; highlights recency/priority-ordered | `internal/feed/entry/query.sql` |
| **Admin global-search Kind taxonomy** | `internal/search/search.go` declares **`KindContent` (wired)**. | `internal/search/search.go:22-25` |

### E. Untested entirely (no test files — confidence: unclear / requires evidence)

| Package / tool | Note |
|---|---|
| `internal/daily`, `internal/search`, `internal/today`, `internal/todo` | **No `*_test.go` files.** `internal/db` is sqlc-generated (acceptable). |
| MCP tools `brief` (morning + reflection modes), `project_progress` | No direct contract tests found — output shape unverified. These are the aggregate readers on the agent surface. |

### F. Today surface (CORRECTED in Track 0.1)

The endpoints exist — this is a wiring question, not an existence one.

This surface is **admin-only HTTP** (the frontend admin shell), not the MCP
agent surface. One of its sections has no data source (see below).

| Endpoint | Status | Evidence |
|---|---|---|
| `GET /api/admin/commitment/today` | exists (backend aggregate) | `cmd/app/routes.go:204` → `today.Handler.Today` |
| `GET /api/admin/system/health` | exists | `cmd/app/routes.go:269` → `stats.Handler.Health` |

**The real risk is a fan-out-vs-aggregate split, not endpoint existence:**

- The backend Today **aggregate exists but is only partially wired in
  production.** `today.NewHandler(planItems, logger)` requires only the plan
  reader; the warnings section comes from optional readers injected via
  `WithSources(...)`. **`WithSources` is not called anywhere in `cmd/`**, so in
  production the aggregate returns the plan section populated and the Warnings
  section **empty**.
- **The AwaitingJudgment section stays empty** — it would require a `tasks`
  triad, which the system does not model (the only work-item entity is
  `todos`). Reconciliation (below) should drop that section rather than wire
  it.
- The **frontend Today page fans out to per-entity endpoints** and assembles
  the envelope client-side
  (`frontend/src/app/admin/commitment/today/today.service.ts`).
- **Do NOT claim the Today aggregate is canonical.** Neither implementation
  wiring nor frontend usage supports that today.
- **Track 1 input: "Today surface reconciliation"** — decide whether golden
  tests target the frontend fan-out or the backend aggregate; then either wire
  `WithSources(...)` and switch the frontend to the aggregate, or mark the
  aggregate route as partial/scaffolded and exclude it from golden flows. This
  pass does **not** wire `WithSources` or switch the frontend.

### G. Carried-forward human-resolved decisions (do not re-litigate)

- **Search corpus** — `search_knowledge` covers content + the reading shelf +
  the ヨルシカ song shelf; `source_types` accepts `content` / `reading` / `song`.

---

## 7. Testing implications & Open Questions

### What must be tested before each domain is trustworthy

| Domain | Must test before trusting |
|---|---|
| **MCP tools** | Catalog parity is **already surface-tested** (names only, `ops_catalog_test.go`) — that is not a contract test. Add claim-level contract tests for all **13**: the multiplexer discriminator (`brief.mode`) rejects out-of-set values; writability annotation matches actual side effect; the read-only tools (`brief`, `search_knowledge`, `list_tasks`, `list_readings`, `get_reading`, `project_progress`) write nothing; each `propose_*` produces an inert `status=proposed` row that feeds no dashboard / brief / Today / active listing; `propose_content` lands at `status=review` with `is_public=false`; `resolve_task` is caller-scoped (another agent's todo returns not-found); per-tool authorization gate. |
| **Search** | Decide the search product contract (Open Question #1) THEN integration-test the hybrid path with real pgvector; until then, test and document FTS-only behavior + graceful degradation when embedder nil/timeout. Cover the three-corpus interleave (content / reading / song) and the diary-folds-under-parent behavior. Add ranking-judgment tests (Scenario 6). |
| **Commitment proposals** | Each `propose_*` writes an inert `status=proposed` row invisible to brief / Today / active listings / selectors; area-reject cascades its proposed child goals; goal-reject cascades its milestones; a `capture_inbox` link to a proposed project survives activation and is unlinked (not deleted) on reject; `resolve_task` caller-scoping. Needs a deterministic fixture matrix (see Scenario 4). The system has one work-item entity (`todos`) and no coordination triad. |
| **Frontend workflows** | **Today surface reconciliation first** (§6F): decide canonical surface (fan-out vs aggregate) before any Today golden flow. Then a backend/frontend **route compatibility matrix** (every admin page: frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error behavior); then golden-flow each admin area; assert no UI affordance violates a forbidden assumption below. |
| **Observability** | **Track 1 input: inventory `activity_events` producers** and map each to `entity_type` × `change_kind` × actor attribution × write path × user-visible event × observability category × alert/dashboard relevance (see §7 Track 1 inputs). Confirm `koopa.actor` GUC is set on every Go write path so `actor='system'` only appears for genuine cron/manual ops (`registry.go:112-125`). Do NOT design dashboards yet. |

### Forbidden assumptions (UI / impl must NOT build on these)

The system models one work-item entity (`todos`) and no inter-agent
coordination layer — build nothing on `tasks` / `task_messages` / `artifacts` /
`reports` / `research_assignments`. Agent memory is each agent's own `.md`, not
a backend table. The agent commitment write surface is exactly: `capture_inbox`
(raw todo), `propose_area` / `propose_goal` / `propose_project` (inert
`status=proposed` drafts — agents never activate or reject; that is admin HTTP,
and proposals materialize only from owner-present conversations, never from
scheduled runs), `propose_content` (finished piece into `status=review`, never
published by an agent), `plan_day`, and `resolve_task` (caller-scoped
self-clear). Content publishing is admin HTTP only. The reading and song
shelves are read-only on MCP. Other structural guarantees: no daily-plan
auto-carryover; no RBAC; no quantitative milestones; no goal auto-status; no
direct `activity_events` INSERT. (Each is schema- or policy-enforced; see §3.)

### Open Questions (require human decision)

1. **Search product contract** — **DECIDED (Phase 1D, 2026-05-27): FTS-only
   is the current production behavior** of `search_knowledge`. Hybrid
   pgvector + RRF is **planned**, deferred until the document-embedding
   write/backfill pipeline lands. Schema, HNSW indexes, embedder package,
   and the RRF merge code remain in place for future activation. Trigger
   for revisiting: observed agent recall ceilings on FTS (e.g. ≥3 incidents
   where a known-relevant document was not retrieved). Cross-source ranking
   (recency-final vs fused relevance) is part of the deferred design.
2. **`p0`/`p1`/`p2` priority aliases** — `normalizePriority` accepts them as
   input shorthand; keep or remove?
3. **Admin global-search Kind taxonomy** — **RESOLVED:** `internal/search/search.go`
   declares exactly `KindContent`, wired.
4. **Feed AI relevance scoring** — implement or formally drop?
5. **Actor attribution surfacing** — `activity_events.actor` exists but is not
   propagated into the aggregate-reader outputs (`brief`); widen those types?
6. **External `schedule` execution + `schedule run` recording** —
   **DECIDED (Phase 1D, 2026-05-27): scheduled execution is owned by the
   external Cowork/Desktop runner.** This repo provides the agent registry
   metadata, the schema, and the `process_runs(kind='agent_schedule')`
   audit row. **No internal scheduler is planned at this time.** Whether
   the external runner is actively writing those rows is not yet
   observable from this repo; adding a read-side observability surface
   (e.g. "last schedule run per agent" on the admin `/api/admin/system/health`
   surface) is a follow-up task, deliberately separate from this ownership
   decision.
7. **`contents.ai_metadata` consumer contract** — documented shape
   `{summary, keywords, quality_score, review_notes}` is not type-checked;
   treat as advisory. The column and its advisory shape persist alongside
   `propose_content` and the admin authoring path.
8. **`project_aliases` surface** — exist for fuzzy project resolution; not
   exposed in admin UI.
9. **"Blocked work" definition** — a blocked-work affordance, if ever wanted,
   would be a derived condition over `todos` (the system's one work-item
   entity).

### Track 1 inputs (carried out of Track 0; not started here)

1. **Today surface reconciliation** (§6F) — pick canonical surface before any
   Today golden flow.
2. **Backend/frontend route compatibility matrix** — every admin page:
   frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error
   behavior. Broader than the two already-confirmed endpoints.
3. **Observability event taxonomy from real producers** — inventory every
   `activity_events` producer (the audit triggers in migration 001) and map:
   `entity_type` · `change_kind` · actor attribution · write path ·
   user-visible event · observability category · alert/dashboard relevance.
   Build the taxonomy from producers, not from prose. Do NOT design dashboards
   yet.
