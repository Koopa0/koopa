# Backend Semantic Contract

> **Track 0 closeout baseline (Track 0.1 corrected, 2026-05-21).** This is the
> grounded semantic contract for the koopa0.dev backend, organized as **seven
> numbered sections** (§1–§7). Change/audit discipline is NOT a content section
> of this contract.
>
> It is intended to become the basis for: MCP tool contract tests, hybrid
> search judgment tests, multi-agent IPC tests, learning analytics
> correctness tests, frontend UI/UX golden flows, and the observability
> event taxonomy. The companion document
> `docs/usage-scenario-catalog.md` carries the user-centered scenarios.
>
> Track 0.1 corrected the Today-surface claim (endpoints exist; the risk is
> fan-out vs partially-wired aggregate), tightened §6 to claim-level
> confidence, and reworded the search conclusion. See
> `docs/reports/track-0-1-correction-report.md`.

**Grounding discipline used in this rewrite:**

- Every implementation-backed statement carries a `file:line` reference.
- Statements not provable from the repo are marked **Open Question**.
- The existence of a table, a doc, or a handler is **not** treated as proof
  that a feature works. §6 separates "implemented and tested" from the rest.
- Where the prior contract recorded a human decision (e.g. bookmark search
  exclusion, resolved 2026-05-21), that decision is carried forward verbatim
  in §6 / §7 rather than re-derived.

---

## 1. System purpose

### What koopa0.dev is

A **private-by-default personal knowledge / learning OS for a single human
owner and a small closed set of AI agents.** One Go backend serves one admin
(`users`, single row today) and ≤10 registered agents
(`internal/agent/registry.go`). Every party reads and writes through the same
two surfaces: the PostgreSQL schema and the MCP tool layer on top of it. A
public Angular site is a read-only projection of the publishable subset.
(Earlier revisions framed this as a "coordination OS" — the inter-agent
coordination layer was retired in MCP-v3; see the note after the facet table.)

It is **all of the following, with explicit boundaries** (§4):

| Facet | What it covers | Backing |
|---|---|---|
| **Personal semantic infrastructure** | `agents.name` as universal actor identity; `activity_events` as the canonical change log written only by triggers | `internal/agent/`, `internal/activity/`, schema triggers `migrations/001_initial.up.sql` |
| **PARA / GTD / OKR-ish system** | areas, goals, milestones, projects, todos, daily plan | `internal/goal/`, `internal/project/`, `internal/todo/`, `internal/daily/` |
| **Learning analytics engine** | domains, concepts, targets, sessions, attempts, observations | `internal/learning/` |
| **MCP tool surface** | **11 agent-facing tools** (post MCP-v3 semantic contraction) | `internal/mcp/ops/catalog.go::All()` (canonical list) |
| **Knowledge / search system** | content, notes, bookmarks, topics, tags, feeds; hybrid search | `internal/content/`, `internal/note/`, `internal/search/`, `internal/mcp/search.go` |

> **MCP-v3 semantic contraction (closed; ledger:
> `docs/decisions/mcp-v3-semantic-contraction.md`).** The agent-facing MCP
> surface is now **exactly 11 tools**. The former agent-coordination layer
> (the A2A task/task_message/artifact triad and `agent_notes`), the report
> lane, the FSRS spaced-repetition tools, the content write/lifecycle tools,
> the `propose_*`/`commit_proposal` flow, and the standalone aggregate readers
> were all removed from the agent surface. High-commitment entity creation
> (goal / milestone / learning plan / learning domain) and content
> publication moved to **admin-only HTTP forms** under `/api/admin/`
> (`cmd/app/routes.go`). Agent memory is no longer a backend entity — each
> agent keeps its own `.md`. The schema converged on migrations **001 + 002**
> (9 tables dropped). This contract describes the contracted state; the ledger
> is the historical record of how it got here.

It is **NOT**: a multi-user product, an RBAC system, a public CMS with
arbitrary authorship, or a generic agent marketplace. The agent set is closed
and compiled into the binary (`docs/authorization-matrix.md:269-289`).

### Architectural invariants (the three load-bearing rules)

1. **`agents.name` is the only actor identity.** Every mutation is attributed
   via FK (`created_by` / `curated_by` / `selected_by` / `actor` / `assignee`).
   The registry is a projection of the Go `BuiltinAgents()` literal synced at
   startup; agents are retired, never deleted (`registry.go:8-14`).
2. **`activity_events` is written exclusively by AFTER triggers.** Application
   code must never INSERT (`migrations/001_initial.up.sql:1166` table comment;
   triggers `2646-2911`). Actor flows from the `koopa.actor` GUC via
   `current_actor()` (`2646-2656`), defaulting to `'system'`.
3. **Illegal states are made structurally impossible** through joint CHECKs,
   partial unique indexes, and narrow triggers — not application discipline
   alone (at-most-one-active learning session `uq_learning_sessions_one_active`;
   curated feed-entry mutual-exclusion content-XOR-bookmark; learning-concept
   acyclicity triggers). The task state↔timestamp / completion-requires-outputs
   invariants cited in earlier revisions are gone with the retired `tasks` triad.

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
| **MCP ops catalog** | `internal/mcp/ops/catalog.go` | **Authoritative** (tool surface) | The 11-tool `All()` list is canonical; drift-tested against handler registration (`ops/types.go:9-11`, `ops_catalog_test.go`). |
| **MCP decision policy** | `.claude/rules/mcp-decision-policy.md` | **Advisory→Authoritative for routing** | Defines which tool fires when. Defers to schema. |
| **Authorization matrix** | `docs/authorization-matrix.md` | **Derived** | Projection of `internal/mcp/authz.go` + `agent/authorize.go`. Code wins on conflict (`authorization-matrix.md:10-13`). |
| **sqlc-generated code** | `internal/db/` | **Derived** | Generated from `query.sql` files; never hand-edited. |
| **This contract** | `docs/backend-semantic-contract.md` | **Derived** | Shared vocabulary; below schema/code/catalog. |
| **Learning contract** | `docs/LEARNING-CONTRACT.md` | **Derived** | Concept-mastery model. (The FSRS-retention half of the former split is retired — FSRS was removed in MCP-v3.) |
| **Cowork agent op docs** | `docs/Koopa-*.md` | **Advisory** | Per-agent operational guidance; never structural truth. |
| **Frontend route/service code** | `frontend/src/app/**` | **Advisory / assumption** | Encodes the frontend's *assumed* backend contract. The endpoints it calls (incl. `/api/admin/commitment/today`, `/api/admin/learning/summary`, `/api/admin/system/health`) **do exist** (`cmd/app/routes.go:204,269,333`); the open risk is payload compatibility and the Today fan-out-vs-aggregate split — see §6. |
| **Audit reports** | `docs/audit/`, `docs/audit-prompts/` | **Stale / point-in-time** | Historical context only; NOT runtime truth. |

**Implementation-only (no doc is authoritative; read the code):**
`internal/mcp/execution.go::normalizePriority` (priority alias acceptance),
`internal/mcp/search.go` (RRF merge constants). (The FSRS scheduler internals
cited in earlier revisions are gone — FSRS was retired in MCP-v3.)

---

## 3. Core domain vocabulary

Format per term: **meaning** · *defined/implied at* · **enforced?** ·
*ambiguity / open question*. The "is not" lines are load-bearing — getting
them wrong is a semantic bug, not a naming quibble.

### Identity / actors

- **agent** — an actor that may write to the system (human, Cowork Claude
  instance, Claude Code, system bot). *Source of truth* `registry.go:16-126`;
  DB row is a projection. **Enforced**: FK target for every actor column;
  capability gated at compile time via `agent.Authorized`. *Is not* a user
  account; *is not* a Cowork project (one platform an agent can run on).
- **participant** — **retired vocabulary.** Pre-rebuild term for what is now
  `agent`. Do not use in new code/schema/UI. (`mcp-decision-policy.md §4`.)
  **Open Question:** none — this is settled removal.
- **user** — a login identity (`users` table) + `refresh_tokens`. Exactly one
  admin today; the admin logs in and acts as agent name `human`
  (`registry.go:103-111`). `user_id` is **not** used as actor identity.
- **actor** — the `agents.name` value attributed to one `activity_events` row;
  set from the `koopa.actor` GUC inside the audit trigger
  (`migrations/001_initial.up.sql:2646-2656`).
- **HQ / Koopa** — `hq` is the `claude-cowork` agent acting as "CEO":
  decisions, delegation, the morning briefing (`registry.go:17-34`). "Koopa"
  is the human owner (display name on the `human` agent, `registry.go:106`).
  HQ holds `SubmitTasks + PublishArtifacts` but **not** `ReceiveTasks`.
- **Claude Cowork project** — a `claude-cowork` platform agent: `hq`,
  `content-studio`, `research-lab`, `learning-studio` (`registry.go:17-81`).
  A platform/identity, not a PARA `project` (§4).
- **Claude Code** — `claude-code` platform agents (`koopa0-dev`, `go-spec`),
  doing repo development work; **zero coordination capability**
  (`Capability{}`, `registry.go:82-95`). A Claude Code session is a dev
  runtime, not a coordination peer (§4).
- **capability** — one of three flags on `agent.Capability`: `SubmitTasks`,
  `ReceiveTasks`, `PublishArtifacts` (`internal/agent/agent.go:36-43`,
  `registry.go`). The *shape* of the check is **compile-time**
  (`agent.Authorize(...) → Authorized[Action]`; a method needing the capability
  cannot be called without the value). Capability lives in Go, **not** in the
  DB. **Post MCP-v3 these flags are vestigial relative to the agent tool
  surface:** they used to gate the A2A coordination tools, which are retired —
  no live MCP tool consumes a capability today. The literals remain on the
  registry rows but no longer gate any agent-facing call.

### Coordination / IPC — RETIRED (MCP-v3 contraction)

The entire inter-agent coordination layer was removed from the agent surface
in the MCP-v3 semantic contraction. The vocabulary below is preserved as a
**tombstone** so future readers do not re-derive removed terms as live.

- **task / task_message / artifact (A2A triad)** — **RETIRED.** The
  `tasks` / `task_messages` / `artifacts` tables and their MCP tools
  (`propose_directive`, `acknowledge_directive`, `file_report`,
  `task_detail`, `request_revision`, `reaccept`) are gone. Inter-agent
  coordination is no longer modeled in the backend; coordination, if any,
  happens out of band. *Was not* a `todo`; *was not* a `process_run`.
- **directive** — **RETIRED.** A naming-only label for a coordination task;
  removed with the triad. There is no `propose_directive` / `commit_proposal`
  path on the agent surface.
- **report (A2A) / report lane** — **RETIRED.** Both the artifact-bearing
  `file_report` completion and the `create_report` / `assign_research` corpus
  report lane (`research_assignments` / `reports` tables) were dropped. There
  is no agent-facing path that produces a searchable low-trust corpus SOURCE.
- **agent_note** — **RETIRED.** The `agent_notes` feature
  (`write_agent_note` / `query_agent_notes`, the three kinds plan / context /
  reflection) was removed. Agent runtime memory now lives in each agent's own
  `.md`, not in the backend. `brief` and `learning_read` are pure
  planning-state / analytics pulls and carry **no** agent memory.
  - *Consequence for the non-negotiable rules:* the old "agent_note is
    self-directed memory, never A2A" rule is now **moot** — both sides of the
    distinction (agent_note and the A2A triad) are gone. See §5.
- **session_note** — **RETIRED label.** Was always a loose label resolving to
  an `agent_note`; with `agent_notes` gone, "session note" no longer maps to
  any backend entity. `end_session` may still accept optional reflection text,
  but it no longer creates a persisted agent-note row (see §5 learning group).

### Commitment (PARA + GTD + goals)

- **project (PARA)** — a PARA execution vehicle: short-term effort with
  deliverables (`projects` table). May serve a goal; has its own status
  lifecycle (`project_status` enum). 1:1 optional `project_profile` for public
  display. *Is not* a Cowork project / agent identity (§4).
- **goal** — an aspirational outcome, optionally area-scoped, with optional
  deadline/quarter. Status (`goal_status`: `not_started → in_progress → done |
  abandoned | on_hold`) is **manually managed**, not auto-derived from
  milestones. **No MCP create path** after MCP-v3: goals are created via the
  admin form `POST /api/admin/commitment/goals` and status changes via
  `PUT /api/admin/commitment/goals/{id}/status` (`cmd/app/routes.go:186-187`).
- **milestone** — a binary done/not-done checkpoint inside a goal. **Not** an
  OKR key result — no `target_value`/`current_value` (§7 forbidden
  assumptions). Goal progress = completed/total (advisory). **No MCP create
  path**: created via `POST /api/admin/commitment/goals/{id}/milestones`
  (`cmd/app/routes.go:188`).
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
  `is_public=true`, `published_at=now()`. **No MCP path** after MCP-v3:
  content create / update / submit-for-review / revert-to-draft / publish /
  archive are **admin-only HTTP** under `/api/admin/knowledge/content`
  (`cmd/app/routes.go:147-156`); the write surface is the admin UI / human, not
  any agent tool.
- **note** — a Zettelkasten artifact (`notes` table), maturity lifecycle
  `seed → stub → evergreen → needs_revision → archived`. Private; **never
  publishes**. Six kinds: `solve-note`, `concept-note`, `debug-postmortem`,
  `decision-log`, `reading-note`, `musing` (`catalog.go::CreateNote`). Notes
  are the one knowledge entity still writable from the agent surface:
  `create_note` and `update_note` (field edits). Maturity transitions are
  **admin-only HTTP** (`POST /api/admin/knowledge/notes/{id}/maturity`,
  `routes.go:165`) — the MCP `update_note_maturity` tool was removed.
- **bookmark** — external URL + commentary. Curate = publish. Created via
  admin UI only (no MCP path). **Open Question** §7: a `PUT .../bookmarks/{id}`
  edit endpoint exists; whether bookmarks should be editable is undecided.
- **source / provenance** — attribution of where a knowledge row came from.
  Columns: `contents.origin_system`, `bookmarks.capture_channel`,
  `feed_entries → feeds`, `learning_attempts.metadata.recommended_by`.
  `activity_events.actor` + `entity_title`/`entity_slug` write-time snapshots
  give per-mutation provenance. **Ambiguity:** there is no single uniform
  "provenance" object; provenance is per-entity columns + the audit log.
- **feed / feed_entry** — RSS subscription + collected items. `feed_entry`
  lifecycle `unread → read → curated | ignored`; a curated entry becomes
  EITHER content OR a bookmark, never both (mutual-exclusion triggers
  `2586-2627`).

### Learning

- **learning item / learning_target** — something to learn/practice/revisit
  (LeetCode problem, chapter, drill). Independent of notes. **"Learning item"
  in the brief = `learning_targets`** (the schema name).
- **learning session** — orchestration boundary with start/end, domain, mode
  (`retrieval | practice | mixed | review | reading`). **At most one active**
  (`uq_learning_sessions_one_active`, `1895-1897`).
- **attempt** — a single try at one target within a session (`learning_attempts`,
  append-only). Carries paradigm + outcome.
- **attempt observation** — `learning_attempt_observation`: a micro-cognitive
  signal tagged to an attempt and a concept. `signal_type ∈ {weakness,
  improvement, mastery}`, `confidence ∈ {high, low}`. **Confidence is a label,
  not a write-time gate** — read-time filter (`mcp-decision-policy.md §5`).
- **concept** — learning ontology node (`pattern | skill | principle`),
  same-domain hierarchy (parent-domain + acyclicity triggers). Mastery is
  **derived** over filtered observations, never stored. *Is not* a tag.
- **review card / FSRS** — **RETIRED.** The FSRS spaced-repetition state
  (`review_cards`), its scheduler (`internal/learning/fsrs/`), and any
  due-review surface were dropped in the MCP-v3 contraction. There is no
  spaced-repetition mechanism today; `record_attempt` no longer writes an
  FSRS rating, and no tool reports "due reviews".

### MCP / system

- **MCP tool** — a registered handler in the MCP server, described by an
  `ops.Meta` (`ops/types.go:56-71`): name, domain, writability, stability,
  since, description, field enums. **11 tools** (`catalog.go::All()`).
- **schedule** — a per-agent recurring trigger declared on the Go
  `agent.Agent` literal (`Schedule{Name, Trigger, Expr, Backend, Purpose}`,
  `registry.go:27-33` etc.). E.g. `hq` runs `morning-briefing` at `0 8 * * *`
  on `cowork_desktop`. **Lives in Go, not the DB.** Only 4 of 9 agents carry a
  schedule. **DECIDED (Phase 1D, 2026-05-27):** the schedule literal is
  metadata only and the backend has **no internal scheduler** — execution is
  driven by the external Cowork/Desktop runner. This repo owns the registry
  metadata, the schema, and the `process_runs(kind='agent_schedule')` audit
  row; it does not own scheduled execution.
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
| **todo is the only work-item entity** | `todos` (personal GTD) | (`tasks` / directive — **RETIRED**) | The inter-agent `tasks` triad was removed in MCP-v3, so there is no longer a "task vs todo" boundary to police — a todo is the system's only work-item entity. | `todo_state` enum; MCP-v3 ledger |
| **learning observation vs knowledge note** | `learning_attempt_observation` (diagnostic signal on a concept) | `note` (Zettelkasten artifact) | Observations drive mastery diagnosis; notes are durable knowledge. Different tables, different lifecycles. | schema; §3 |
| **MCP tool call vs semantic write** | a `tools/call` invocation | the resulting row + `activity_event` | A read-only tool call (`ReadOnly` writability — `brief`, `learning_read`, `search_knowledge`) produces no semantic write. Only Additive/Idempotent/Destructive tools write; the *write* is the row + its trigger-emitted audit event, not the call. | `ops/types.go:32-42` |
| **Cowork project vs internal participant** | `claude-cowork` agent | (retired term "participant") | "Participant" is dead vocabulary; the live entity is `agent`. A Cowork project IS an agent. | `registry.go`; `mcp-decision-policy.md §4` |
| **Claude Code runtime vs Koopa identity** | `claude-code` agent (dev session, no capability) | `human` agent (Koopa) | Claude Code agents attribute writes via `as` but hold no capability flags; Koopa (human) carries the platform-human override. The capability difference is now vestigial (no live MCP tool consumes a capability post MCP-v3) — the live distinction is actor-attribution identity, not coordination authority. | `registry.go` |
| **frontend page model vs backend domain model** | Angular admin pages (composed views) | backend entities | The frontend composes multiple backend reads into one page (e.g. the Today page forks 6 calls). Page-level view-models are **not** backend entities and may assume endpoints not yet verified to exist (§6). | frontend `today-page.component.ts`; §2 |

---

## 5. MCP tool semantics

The canonical inventory is `internal/mcp/ops/catalog.go::All()` — **11 tools**
after the MCP-v3 semantic contraction. Each tool's `Writability` (`ReadOnly |
Additive | Idempotent | Destructive`) maps to MCP `ToolAnnotations` at
registration and is the machine-readable risk signal (`ops/types.go:28-42`).
Below, tools are grouped by their declared `Domain`.

The complete agent surface, by name and writability:

| # | Tool | Domain | Writability |
|---|---|---|---|
| 1 | `brief` (mode=morning\|reflection) | `DomainQuery` | ReadOnly |
| 2 | `search_knowledge` | `DomainQuery` | ReadOnly |
| 3 | `capture_inbox` | `DomainDaily` | Additive |
| 4 | `plan_day` | `DomainDaily` | Idempotent |
| 5 | `start_session` | `DomainLearning` | Additive |
| 6 | `record_attempt` | `DomainLearning` | Additive |
| 7 | `end_session` | `DomainLearning` | Additive |
| 8 | `learning_read` (view=overview\|next_target\|attempts\|session_progress) | `DomainLearning` | ReadOnly |
| 9 | `manage_plan` (5 actions) | `DomainLearning` | Destructive |
| 10 | `create_note` | `DomainContent` | Additive |
| 11 | `update_note` | `DomainContent` | Additive |

**`brief` and `learning_read` are READ-ONLY forever** — they are pure
planning-state / analytics pulls and carry no agent memory and no write path.

### Group: knowledge / search (`DomainQuery`, `DomainContent`)

| Tool | Writability | Caller | Side effect | Enforcement |
|---|---|---|---|---|
| `search_knowledge` | ReadOnly | any registered | none | FTS-backed today; hybrid pgvector + RRF is planned and gated on the embedder write/backfill pipeline (§6D, §7 #1) |
| `create_note` | Additive | any registered | note row (default maturity `seed`) | one of six `kind` values; notes are Koopa-private, no publication lifecycle |
| `update_note` | Additive | any registered | note field edit (slug / title / body / kind) | maturity transitions NOT here — admin-only HTTP (`update_note_maturity` tool removed) |

**Semantics for testing:** notes are the only knowledge entity writable from
the agent surface; their maturity lifecycle is admin-only. Search is read-only
and **FTS-only in production today** — the hybrid pgvector + RRF path is
planned, not active (§6D, §7 #1).

**Removed from this group (now admin-only HTTP or gone):** the content write /
lifecycle tools (`create_content`, `update_content`,
`set_content_review_state`, `publish_content`, `archive_content`,
`list_content`, `read_content`) moved to `/api/admin/knowledge/content`
(`routes.go:147-156`) — publication is a human act on the admin surface, not an
agent tool. `update_note_maturity` moved to
`POST /api/admin/knowledge/notes/{id}/maturity` (`routes.go:165`).
`manage_feeds` (feed CRUD) was removed from the agent surface; feeds are
managed via `/api/admin/knowledge/feeds` (`routes.go:241-245`).

### Group: PARA / GTD (`DomainDaily`)

| Tool | Writability | Caller | Side effect | Enforcement |
|---|---|---|---|---|
| `capture_inbox` | Additive | any | todo (state=inbox) | only `title` required; status is always inbox |
| `plan_day` | Idempotent | any | atomic daily-plan replacement | each todo MUST already be `state=todo`; items list MUST be non-empty; whole delete+insert runs in one tx |

**Semantics for testing:** `plan_day` is the one transactional contract here —
any per-item validation failure rolls the whole replacement back to the prior
plan; `items_removed` reports true displacements only (a carried-over todo with
the same `task_id` is not reported as removed). `capture_inbox` is the only
agent path that writes a todo; todo state transitions (inbox→todo→in_progress→
done) are no longer agent-driven — `advance_work` was removed and clarification
happens on the admin UI (todos `/api/admin/commitment/todos`, `routes.go:193-198`).

**Removed from this group (now admin-only HTTP or gone):** `advance_work`
(todo transitions → admin `POST .../todos/{id}/advance`). The entire
`propose_*` / `commit_proposal` flow (`propose_goal`, `propose_project`,
`propose_milestone`, `propose_hypothesis`, `propose_learning_plan`,
`propose_learning_domain`, `propose_directive`, `commit_proposal`) was removed:
high-commitment entities are now created on **admin HTTP forms** — goals
(`POST /api/admin/commitment/goals`), milestones
(`POST .../goals/{id}/milestones`), learning plans
(`POST /api/admin/learning/plans`), learning domains
(`POST /api/admin/learning/domains`) (`routes.go:186-188, 310, 316`).
`goal_progress` and `track_hypothesis` were removed from the agent surface
(hypothesis lifecycle is admin HTTP, `routes.go:289-295`).

### Group: learning (`DomainLearning`)

| Tool | Writability | Side effect | Enforcement |
|---|---|---|---|
| `start_session` | Additive | new session | rejects if an active session exists (`uq_learning_sessions_one_active`) |
| `record_attempt` | Additive | attempt + observations + targets/relations | **partial-write**: per-element validation; `observations_recorded < input` is legal; no FSRS rating (FSRS retired) |
| `end_session` | Additive | ends session; optional reflection text | reflection text is summary-only — no persisted agent-note row (agent_notes retired) |
| `learning_read` | ReadOnly | none | multiplexer; 4 views: `overview` / `next_target` / `attempts` / `session_progress` |
| `manage_plan` | Destructive | plan entries lifecycle (5 actions) | completion requires `completed_by_attempt_id` + reason, or `force=true` with `manual override:` prefix (`mcp-decision-policy.md §13`) |

**`learning_read` views** (`view` discriminator, ReadOnly): `overview` (recent
sessions; filter by domain + window_days), `next_target` (in-session
next-problem recommendation — requires the active `session_id`), `attempts`
(history by target/concept/session; each attempt carries its observation list),
`session_progress` (in-session aggregate; when no session is active returns
`{active:false, last_ended_session_id}`). The former dashboard mastery /
weaknesses / timeline / variations views are **admin-only HTTP**
(`/api/admin/learning/dashboard`, `routes.go:300`) — `learning_read` rejects
any view outside the four above.

**`manage_plan` actions** (5, ReadOnly `progress` intrinsic to the lifecycle):
`add_entries`, `remove_entries`, `update_entry`, `reorder`, `progress`. (The
former Wave-1 sixth action was dropped to the 5-action set in MCP-v3.)

**Semantics for testing:** `record_attempt` partial-write contract is the
single most test-worthy learning behavior — rejected observation indices must
surface in `observation_warnings` while siblings and the attempt row persist.
`attempt_number` is **per-target, not per-session**.

**Removed from this group (now admin-only HTTP or gone):**
`learning_dashboard` / `recommend_next_target` / `attempt_history` /
`session_progress` were folded into `learning_read` views; the full dashboard
views remain admin-only HTTP. `archive_learning_target` was removed from the
agent surface. All FSRS / review-card tools are gone (FSRS retired).

### Group: audit / provenance

There are **no write tools** in this group — provenance is a side effect.
Audit events are emitted only by triggers; the agent-facing read surface is
embedded in `brief` (morning/reflection) and `learning_read`. The richer
activity feed (`/api/admin/coordination/activity`, `routes.go:257`) is
admin-only HTTP (frontend-advisory, §2).

### Group: system / context bootstrap (`DomainQuery`)

| Tool | Writability | Side effect | Notes |
|---|---|---|---|
| `brief(mode=morning)` | ReadOnly | none | single-call daily-planning briefing (overdue/today/committed/upcoming todos, active_goals, unverified_hypotheses, rss_highlights, content_pipeline); `sections` filter; **today-scoped**, not since-last-session |
| `brief(mode=reflection)` | ReadOnly | none | end-of-day plan-vs-actual retrospective (planned_items + completed/deferred/planned counts + completion_rate); `sections` ignored |

**`brief` replaces the former `morning_context` + `reflection_context`** behind
a `mode` discriminator. Per-agent default sections: learning-studio defaults to
`['tasks', 'hypotheses']`; every other caller (incl. hq) gets all sections.
`rss_highlights` are feeds tagged priority=high, NOT relevance-ranked — use
`search_knowledge` for ranked retrieval.

**Removed from this group (gone):** `morning_context` and `reflection_context`
were merged into `brief`. `session_delta` (24h activity snapshot),
`weekly_summary` (Mon–Sun retrospective), and `system_status` (feeds health +
process_runs + counts) were removed from the agent surface entirely — system
observability is admin-only HTTP (`/api/admin/system/health`,
`/api/admin/system/stats`, `routes.go:261-269`).

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

> The claims below describe the **contracted** agent surface. Behaviors backed
> by tools removed in MCP-v3 (the task/directive triad, `propose_*` /
> `commit_proposal`, FSRS, `archive_learning_target`, agent_notes) are no
> longer agent-facing and are not listed here as live claims — see the
> ledger `docs/decisions/mcp-v3-semantic-contraction.md` for their history.
> Where the *underlying entity* (content lifecycle, learning sessions) still
> exists behind admin HTTP, the schema-level CHECK claim is retained.

| Claim | Confidence | Evidence |
|---|---|---|
| Login + refresh-token rotation + token security behave as specified | claim-tested | `internal/auth/` — 27 tests incl. `auth_security_test.go` |
| Content draft→review→publish→archive transitions enforce their CHECKs (now admin-HTTP-driven) | claim-tested | `internal/content/` integration (testcontainers) |
| Tag raw→canonical alias resolution (auto + admin paths) | claim-tested | `internal/tag/` integration |
| Feed fetch + scheduler cadence + auto-disable on failures | claim-tested | `internal/feed/scheduler_test.go` (testcontainers) |
| **At-most-one active learning session** rejects a second `start_session` | claim-tested | `TestIntegration_StartSession_*` |
| `record_attempt` **cold-start happy path** (attempt + observations + targets) | claim-tested | `TestIntegration_ColdStart_RecordAttempt` |
| Mastery floor (<3 filtered obs → `developing`) + confidence-filter invariant | claim-tested | `TestObservationConfidenceInvariant`; `internal/learning/mastery_test.go` |

### B. Implemented and only SURFACE-tested (parity/validation, not semantics)

| Claim | Confidence | Evidence |
|---|---|---|
| The 11-tool catalog matches handler registration | surface-tested (**parity only**) | `ops_catalog_test.go` compares *names only* — proves registration completeness, **not** per-tool contract behavior |
| `search_knowledge` RRF merge + filter mutex logic | surface-tested (unit, no DB) | `search_test.go` — unit tests on the merge function; no end-to-end search |
| Agent-surface note write tools (`create_note`, `update_note`, `manage_plan`) input validation | surface-tested | `handler_test.go` — validation only, limited business-logic integration |

### C. Implemented but WEAKLY tested (happy path only; rejection paths open)

| Claim | Gap (untested) | Evidence |
|---|---|---|
| `record_attempt` partial-write | **per-element rejection** (`observation_warnings`, `relation_warnings`) coverage thin | audit |
| Hybrid search semantic branch | no integration test against real pgvector; degradation path (embedder nil/timeout) untested | `search.go`; `search_knowledge` tool has no integration test |

(The task-completion / directive-revision / standalone-artifact / a2a-cap gaps
previously listed here are removed: the coordination triad was retired in
MCP-v3 and those tables/tools no longer exist.)

### D. Schema-supported only (NOT implemented — do not assume it works)

| Feature | Reality | Evidence |
|---|---|---|
| **Document embedding write path** | **No automatic document-embedding write path exists — this is the current decision, not a TODO.** `embedder.Embed()` is defined (`embedder.go:65`) but has no production call site; app-created `content`/`note` rows therefore behave **FTS-only** unless embeddings are externally/backfill-populated. The vector-*read* path is real (`InternalSemanticSearch`, `content/public.go:104-115`) and *would* return rows if embeddings were backfilled — so "no write path" must not be conflated with "semantic branch can never return rows". **Decided (Phase 1D, 2026-05-27):** keep schema, indexes, and embedder package in place; do not implement write/backfill until agent recall ceilings on FTS are observed in practice. `search_knowledge` is documented as FTS-backed today. | `search.go:182-235` (only `EmbedQuery`); no `Embed()` call site; cols `migrations/001_initial.up.sql:495,573` |
| **Feed AI relevance scoring** | Not active — "scoring pipeline not yet active, all items have score=0"; highlights recency/priority-ordered | `internal/feed/entry/query.sql` |
| **Admin global-search Kind taxonomy** | `internal/search/search.go` declares 9 Kinds; only `KindContent` + `KindNote` are wired; `KindBookmark/Hypothesis/Concept/Task/Goal/Todo/Project` declared-but-unwired | `internal/search/search.go` |

### E. Untested entirely (no test files — confidence: unclear / requires evidence)

| Package / tool | Note |
|---|---|
| `internal/daily`, `internal/note`, `internal/search`, `internal/today`, `internal/todo` | **No `*_test.go` files.** `internal/db` is sqlc-generated (acceptable). |
| MCP tools `brief` (morning + reflection modes), `learning_read` (4 views) | No direct contract tests found — output shape unverified. These are the surviving aggregate readers; the former `reflection_context` / `session_delta` / `weekly_summary` / `goal_progress` tools were removed. |

### F. Today surface (CORRECTED in Track 0.1)

The endpoints exist — this is no longer an open existence question:

This surface is **admin-only HTTP** (the frontend admin shell), not the MCP
agent surface — it is unaffected by the MCP-v3 contraction except that two of
its sections lost their data source (see below).

| Endpoint | Status | Evidence |
|---|---|---|
| `GET /api/admin/commitment/today` | exists (backend aggregate) | `cmd/app/routes.go:204` → `today.Handler.Today` |
| `GET /api/admin/system/health` | exists | `cmd/app/routes.go:269` → `stats.Handler.Health` |
| `GET /api/admin/learning/summary` | exists | `cmd/app/routes.go:333` → `learning.Handler.Summary` |

**The real risk is a fan-out-vs-aggregate split, not endpoint existence:**

- The backend Today **aggregate exists but is only partially wired in
  production.** `today.NewHandler(planItems, logger)` requires only the plan
  reader; the warnings section comes from optional readers injected via
  `WithSources(...)`. **`WithSources` is not called anywhere in `cmd/`**, so in
  production the aggregate returns the plan section populated and the Warnings
  section **empty**.
- **The AwaitingJudgment and DueReviews sections are now permanently empty** —
  AwaitingJudgment was sourced from the retired `tasks` triad and DueReviews
  from the retired FSRS review-cards. Reconciliation (below) should drop these
  two sections rather than wire them.
- The **frontend Today page bypasses the aggregate** and fans out to six
  per-entity endpoints, assembling the envelope client-side
  (`frontend/src/app/admin/commitment/today/today.service.ts` — the doc comment
  states the aggregate is not yet shipped).
- **Do NOT claim the Today aggregate is canonical.** Neither implementation
  wiring nor frontend usage supports that today.
- **Track 1 input: "Today surface reconciliation"** — decide whether golden
  tests target the frontend fan-out or the backend aggregate; then either wire
  `WithSources(...)` and switch the frontend to the aggregate, or mark the
  aggregate route as partial/scaffolded and exclude it from golden flows. This
  pass does **not** wire `WithSources` or switch the frontend.

### G. Carried-forward human-resolved decisions (do not re-litigate)

- **Bookmark is NOT a `search_knowledge` corpus member** — resolved
  2026-05-21 by Koopa; the dormant `bookmarks.embedding` column + HNSW index
  were removed.

---

## 7. Testing implications & Open Questions

### What must be tested before each domain is trustworthy

| Domain | Must test before trusting |
|---|---|
| **MCP tools** | Catalog parity is **already surface-tested** (names only, `ops_catalog_test.go`) — that is not a contract test. Add claim-level contract tests for all **11**: the multiplexer discriminators (`brief.mode`, `learning_read.view`, `manage_plan.action`) reject out-of-set values; writability annotation matches actual side effect; `brief` / `learning_read` are read-only (write nothing); per-tool authorization gate. |
| **Search** | Decide the search product contract (Open Question #1) THEN integration-test the hybrid path with real pgvector; until then, test and document FTS-only behavior + graceful degradation when embedder nil/timeout. Add ranking-judgment tests (Scenario 6). |
| **Learning analytics** | `record_attempt` partial-write per-element rejection; mastery floor (<3 filtered obs → `developing`); confidence-filter read semantics; concept auto-creation boundary (leaf, same-domain only; cross-domain → rejected by trigger); plan-entry completion audit-trail enforcement (`mcp-decision-policy.md §13`). Needs a deterministic fixture matrix (see Scenario 4). (Agent coordination as a test domain is gone — the task triad was retired in MCP-v3.) |
| **Frontend workflows** | **Today surface reconciliation first** (§6F): decide canonical surface (fan-out vs aggregate) before any Today golden flow. Then a backend/frontend **route compatibility matrix** (every admin page: frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error behavior); then golden-flow each admin area; assert no UI affordance violates a forbidden assumption below. |
| **Observability** | **Track 1 input: inventory `activity_events` producers** and map each to `entity_type` × `change_kind` × actor attribution × write path × user-visible event × observability category × alert/dashboard relevance (see §7 Track 1 inputs). Confirm `koopa.actor` GUC is set on every Go write path so `actor='system'` only appears for genuine cron/manual ops (`registry.go:112-125`). Do NOT design dashboards yet. |

### Forbidden assumptions (UI / impl must NOT build on these)

No `tasks` / `task_messages` / `artifacts` (the A2A triad was retired — do not
re-introduce a coordination layer assuming these tables exist); no `agent_notes`
(agent memory is each agent's own `.md`); no `reports` / `research_assignments`
(report lane retired); no review cards / FSRS state of any kind (retired); no
agent-facing `propose_*` / `commit_proposal` flow (high-commitment creation is
admin HTTP); no agent-facing content write/publish (admin HTTP only); no
`bookmarks.status` lifecycle; no daily-plan auto-carryover; no RBAC; no
quantitative milestones; no goal auto-status; no direct `activity_events`
INSERT; no direct mastery edit. (Each is schema- or policy-enforced or removed;
see §3/§5 and the MCP-v3 ledger.)

### Open Questions (require human decision)

1. **Search product contract** — **DECIDED (Phase 1D, 2026-05-27): FTS-only
   is the current production behavior** of `search_knowledge`. Hybrid
   pgvector + RRF is **planned**, deferred until the document-embedding
   write/backfill pipeline lands. Schema, HNSW indexes, embedder package,
   and the RRF merge code remain in place for future activation. Trigger
   for revisiting: observed agent recall ceilings on FTS (e.g. ≥3 incidents
   where a known-relevant document was not retrieved). Cross-source ranking
   (recency-final vs fused relevance) is part of the deferred design.
2. **Bookmark edit flow** — the `PUT /api/admin/knowledge/bookmarks/{id}`
   endpoint exists; are bookmarks Create-only/immutable or Create+edit? Must
   NOT be resolved by "the code exists" alone.
3. **`p0`/`p1`/`p2` priority aliases** — `normalizePriority` accepts them as
   input shorthand; keep or remove?
4. **`directive` discriminator** — **MOOT (MCP-v3): the `tasks` triad was
   retired.** There is no directive entity to discriminate.
5. **Admin global-search Kind taxonomy** — wire the unwired Kinds or remove
   the declarations? (Note: `KindTask` etc. are dead since the triad was
   retired; only `KindContent` + `KindNote` remain meaningful.)
6. **Feed AI relevance scoring** — implement or formally drop?
7. **Actor attribution surfacing** — `activity_events.actor` exists but is not
   propagated into the surviving aggregate-reader outputs (`brief`); widen
   those types? (The former `weekly.Summary` / `SessionDelta` / `MorningContext`
   tool outputs no longer exist.)
8. **`agent_notes.metadata` schema** — **MOOT (MCP-v3): `agent_notes` retired.**
9. **"session_note" as a first-class entity** — **MOOT (MCP-v3): the
   `agent_notes` backing entity is gone**; "session note" no longer maps to any
   backend entity.
10. **External `schedule` execution + `schedule run` recording** —
    **DECIDED (Phase 1D, 2026-05-27): scheduled execution is owned by the
    external Cowork/Desktop runner.** This repo provides the agent registry
    metadata, the schema, and the `process_runs(kind='agent_schedule')`
    audit row. **No internal scheduler is planned at this time.** Whether
    the external runner is actively writing those rows is not yet
    observable from this repo; adding a read-side observability surface
    (e.g. "last schedule run per agent" on the admin `/api/admin/system/health`
    surface — the agent `system_status` tool was removed in MCP-v3) is a
    follow-up task, deliberately separate from this ownership decision.
11. **Task `revision_requested` payload contract** — **MOOT (MCP-v3): the
    `tasks` triad and its revision cycle were retired.**
12. **`contents.ai_metadata` consumer contract** — documented shape
    `{summary, keywords, quality_score, review_notes}` is not type-checked;
    treat as advisory. (Content is now admin-HTTP-only, but the column and its
    advisory shape persist.)
13. **`learning_domains` lifecycle** — created via admin form
    `POST /api/admin/learning/domains` but no retire/deactivate flow.
14. **`project_aliases` surface** — exist for fuzzy project resolution; not
    exposed in admin UI.
15. **"Blocked task" definition** — **MOOT (MCP-v3): there is no `tasks` entity
    or Today "awaiting/blocked work" section to populate.** A blocked-work
    affordance, if ever wanted, would be a derived condition over `todos`.
16. **`learning_read(view=next_target)` ranking policy** — design-only, not
    implemented. Current ranker does not incorporate breadth cap or
    explainability (FSRS-due is gone with FSRS). Direction: mixed coaching
    recommendation by session mode. Do NOT patch the ranker until decisions
    land on session-mode source, `recommendation_type` taxonomy, breadth cap,
    backward-compatible response envelope, and fixture matrix. (audit memo: CF-01.)
17. **`record_attempt` observation `concept_kind`** — design-only, not
    implemented. Auto-created concepts default to `skill`; the
    pattern/skill/principle distinction is not persisted. Direction: optional
    `concept_kind` on `record_attempt` for **new-concept creation only**.
    Existing concept `kind` MUST NOT be overwritten; conflict policy is
    "warn but keep existing". `parent_id` / hierarchy stays admin-form-only —
    never direct-write via `record_attempt`. (audit memo: CF-03.)
18. **Directive `reject` / `defer` transitions** — **MOOT (MCP-v3): the
    directive/task lifecycle was retired.** (audit memo: CF-07.)
19. **`recommendation_acceptance_rate` self-audit metric** — **MOOT (MCP-v3):
    the `weekly_summary` tool and its `self_audit` block were removed from the
    agent surface.** Any equivalent now lives on admin HTTP stats, out of
    scope here. (audit memo: CF-08 remainder.)

### Track 1 inputs (carried out of Track 0; not started here)

1. **Today surface reconciliation** (§6F) — pick canonical surface before any
   Today golden flow.
2. **Backend/frontend route compatibility matrix** — every admin page:
   frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error
   behavior. Broader than the two already-confirmed endpoints.
3. **Observability event taxonomy from real producers** — inventory every
   `activity_events` producer (the audit triggers in migration 001, minus the
   triggers on the 9 tables dropped in MCP-v3) and map: `entity_type` ·
   `change_kind` · actor attribution · write path · user-visible event ·
   observability category · alert/dashboard relevance. Build the taxonomy from
   producers, not from prose. Do NOT design dashboards yet.
4. **Scenario→test-spec conversion** — turn each scenario in
   `usage-scenario-catalog.md` into a fixture-backed spec (the catalog now
   carries seed specs; Track 1 makes them executable).
