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

A **private-by-default personal knowledge / learning / coordination OS for a
single human owner and a small closed set of AI agents.** One Go backend
serves one admin (`users`, single row today) and ≤10 registered agents
(`internal/agent/registry.go:16-126`). Every party reads and writes through
the same two surfaces: the PostgreSQL schema and the MCP tool layer on top of
it. A public Angular site is a read-only projection of the publishable subset.

It is **all of the following, with explicit boundaries** (§4):

| Facet | What it covers | Backing |
|---|---|---|
| **Personal semantic infrastructure** | `agents.name` as universal actor identity; `activity_events` as the canonical change log written only by triggers | `internal/agent/`, `internal/activity/`, schema triggers `migrations/001_initial.up.sql:2646-2911` |
| **PARA / GTD / OKR-ish system** | areas, goals, milestones, projects, todos, daily plan | `internal/goal/`, `internal/project/`, `internal/todo/`, `internal/daily/` |
| **Learning analytics engine** | domains, concepts, targets, sessions, attempts, observations, FSRS review | `internal/learning/` (incl. `internal/learning/fsrs/`) |
| **Agent coordination layer (IPC)** | tasks, task_messages, artifacts, agent_notes | `internal/agent/task/`, `internal/agent/artifact/`, `internal/mcp/agent_note.go` |
| **MCP tool surface** | 45 tools across 7 domains | `internal/mcp/ops/catalog.go:633-681` (canonical list) |
| **Knowledge / search system** | content, notes, bookmarks, topics, tags, feeds; hybrid search | `internal/content/`, `internal/note/`, `internal/search/`, `internal/mcp/search.go` |

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
   alone (task state↔timestamp `1249-1255`; at-most-one-active session
   `1895-1897`; completion-requires-outputs `1366-1391`).

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
| **MCP ops catalog** | `internal/mcp/ops/catalog.go` | **Authoritative** (tool surface) | The 45-tool `All()` list (`catalog.go:633-681`) is canonical; drift-tested against handler registration (`ops/types.go:9-11`, `ops_catalog_test.go`). |
| **MCP decision policy** | `.claude/rules/mcp-decision-policy.md` | **Advisory→Authoritative for routing** | Defines which tool fires when. Defers to schema. |
| **Authorization matrix** | `docs/authorization-matrix.md` | **Derived** | Projection of `internal/mcp/authz.go` + `agent/authorize.go`. Code wins on conflict (`authorization-matrix.md:10-13`). |
| **sqlc-generated code** | `internal/db/` | **Derived** | Generated from `query.sql` files; never hand-edited. |
| **This contract** | `docs/backend-semantic-contract.md` | **Derived** | Shared vocabulary; below schema/code/catalog. |
| **Learning contract** | `docs/LEARNING-CONTRACT.md` | **Derived** | FSRS-retention vs concept-mastery split. |
| **Cowork agent op docs** | `docs/Koopa-*.md` | **Advisory** | Per-agent operational guidance; never structural truth. |
| **Frontend route/service code** | `frontend/src/app/**` | **Advisory / assumption** | Encodes the frontend's *assumed* backend contract. The endpoints it calls (incl. `/api/admin/commitment/today`, `/api/admin/learning/summary`, `/api/admin/system/health`) **do exist** (`cmd/app/routes.go:206,271,350`); the open risk is payload compatibility and the Today fan-out-vs-aggregate split — see §6. |
| **Audit reports** | `docs/audit/`, `docs/audit-prompts/` | **Stale / point-in-time** | Historical context only; NOT runtime truth. |

**Implementation-only (no doc is authoritative; read the code):**
`internal/mcp/execution.go::normalizePriority` (priority alias acceptance),
`internal/mcp/search.go` (RRF merge constants), the FSRS scheduler
internals (`internal/learning/fsrs/fsrs.go`).

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
  `ReceiveTasks`, `PublishArtifacts` (`authorization-matrix.md:22-37`).
  The *shape* of the check is **compile-time** (`agent.Authorize(...) →
  Authorized[Action]`; a method needing the capability cannot be called
  without the value), but the *subject* is resolved at **runtime** from the
  caller's `as` identity against the registry row — so functional tests must
  not over-read this as "purely compile-time": a wrong/unauthorized `as` is
  rejected at request time. Capability lives in Go, **not** in the DB.

### Coordination / IPC

- **task** — an inter-agent work unit (`tasks` table). Lifecycle
  `submitted → working → completed | canceled` plus the revision cycle
  `completed → revision_requested → working → completed`
  (`task_state` enum, `migrations/001_initial.up.sql:35-37`). **Enforced**:
  state↔timestamp joint CHECK `chk_tasks_state_timestamps` (`1249-1255`);
  no self-assignment `chk_tasks_no_self_assignment` (`1247-1248`); completion
  requires ≥1 response message AND ≥1 artifact
  (`trg_tasks_completion_requires_outputs`, `1366-1391`). *Is not* a `todo`;
  *is not* a `process_run`.
- **directive** — **vocabulary label only, not a structural entity.** A task
  whose expected output is a *report* and whose target exercises autonomous
  judgment. At the MCP boundary the agent uses `propose_directive` /
  `acknowledge_directive` / `file_report`; in the DB it is a plain `tasks`
  row with no `kind` discriminator. **Ambiguity:** "show all directives I
  issued" cannot be answered structurally. **Open Question** §7: whether to
  add `tasks.kind` (status quo: no).
- **report** — vocabulary for the artifact-bearing completion of a directive.
  Mechanically: a `file_report(in_response_to=task_id)` call that attaches a
  response `task_message` + an `artifact` and transitions the task to
  `completed` (`catalog.go:242-251`; `authorization-matrix.md:160`). Not a
  separate table.
- **task_message** — an ordered request/response turn on a task
  (`role ∈ {request, response}`). Parts are a2a-go `Part` JSON. **Enforced**
  caps: 1–16 parts (`chk_task_messages_parts_count`, `1307-1309`), ≤32 KB
  (`chk_task_messages_parts_size`, `1311-1313`); unique `(task_id, position)`
  (`1305`).
- **artifact** — a structured deliverable. Task-bound (`task_id` set) or
  standalone (`task_id` NULL). **Enforced** caps: 1–32 parts (`1341-1343`),
  ≤256 KB (`1345-1346`).
- **agent_note** — an agent's internal narrative log entry. Three kinds:
  `plan` (daily-plan reasoning), `context` (session snapshot), `reflection`
  (retrospective). **Self-directed; never inter-agent communication.** *Is
  not* a Zettelkasten `note`. Per-kind binding enforced by trigger
  (plan→daily_plan_item, reflection→learning_session). **Open Question** §7:
  `agent_notes.metadata` per-kind schema is policy, not schema-enforced.
- **session_note** — **NOT a backend entity.** The term appears in the task
  brief and in skill docs as a loose label; in the schema it resolves to
  `agent_notes(kind='context')` (a session snapshot) or to an
  `agent_notes(kind='reflection')` linked from a `learning_session`. **Open
  Question** §7: whether to formalize "session note" as distinct from
  `agent_note` — currently it is not.

### Commitment (PARA + GTD + goals)

- **project (PARA)** — a PARA execution vehicle: short-term effort with
  deliverables (`projects` table). May serve a goal; has its own status
  lifecycle (`project_status` enum). 1:1 optional `project_profile` for public
  display. *Is not* a Cowork project / agent identity (§4).
- **goal** — an aspirational outcome, optionally area-scoped, with optional
  deadline/quarter. Status (`goal_status`: `not_started → in_progress → done |
  abandoned | on_hold`) is **manually managed**, not auto-derived from
  milestones.
- **milestone** — a binary done/not-done checkpoint inside a goal. **Not** an
  OKR key result — no `target_value`/`current_value` (§7 forbidden
  assumptions). Goal progress = completed/total (advisory).
- **todo** — a personal GTD work item. `todo_state`: `inbox → todo →
  in_progress → done`, plus `someday`. *Is not* a `task`.
- **daily_plan_item** — "today I commit to this todo." Status CHECK `planned |
  done | deferred | dropped` (`970-971`). **No auto-carryover** — verified: no
  trigger copies yesterday's items forward (only structural triggers exist on
  the table).

### Knowledge

- **content** — first-party publishable artifact. Five types: `article`,
  `essay`, `build-log`, `til`, `digest`. `content_status`: `draft → review →
  published → archived`. **`review → published` is human-only**
  (`publish_content`, `authorization-matrix.md:126`). Publishing atomically
  flips `status='published'`, `is_public=true`, `published_at=now()`.
- **note** — a Zettelkasten artifact (`notes` table), maturity lifecycle
  `seed → stub → evergreen → needs_revision → archived`. Private; **never
  publishes**. Six kinds: `solve-note`, `concept-note`, `debug-postmortem`,
  `decision-log`, `reading-note`, `musing` (`catalog.go:547`).
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
  same-domain hierarchy (parent-domain + acyclicity triggers `2174-2217`).
  Mastery is **derived** over filtered observations, never stored. *Is not* a
  tag.
- **review card** — FSRS spaced-repetition state, **exactly one per
  learning_target** (`uq_review_cards_learning_target`, `1688`). System-managed
  (`internal/learning/fsrs/`); never via MCP. Review scope is per-target only.

### MCP / system

- **MCP tool** — a registered handler in the MCP server, described by an
  `ops.Meta` (`ops/types.go:56-71`): name, domain, writability, stability,
  since, description, field enums. 45 tools (`catalog.go:633-681`).
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
| **GTD task vs directive** | `todos` (personal) | `tasks` framed as directive | A todo is single-actor GTD; a directive is an inter-agent `tasks` row. No `tasks.kind` — directive is naming only. | `todo_state` vs `task_state` enums; `mcp-decision-policy.md §14` |
| **report vs session_note vs agent_note** | report = artifact-bearing task completion | session_note = loose label → `agent_notes(kind=context)` | agent_note = self-directed narrative | A report crosses agents (artifact); an agent_note never does. "session_note" is not its own entity. | `catalog.go:242-251`; `agent_note.go` |
| **learning observation vs knowledge note** | `learning_attempt_observation` (diagnostic signal on a concept) | `note` (Zettelkasten artifact) | Observations drive mastery diagnosis; notes are durable knowledge. Different tables, different lifecycles. | schema; §3 |
| **MCP tool call vs semantic write** | a `tools/call` invocation | the resulting row + `activity_event` | A read-only tool call (`ReadOnly` writability) produces no semantic write. Only Additive/Idempotent/Destructive tools write; the *write* is the row + its trigger-emitted audit event, not the call. | `ops/types.go:32-42` |
| **Cowork project vs internal participant** | `claude-cowork` agent | (retired term "participant") | "Participant" is dead vocabulary; the live entity is `agent`. A Cowork project IS an agent. | `registry.go`; `mcp-decision-policy.md §4` |
| **Claude Code runtime vs Koopa participant** | `claude-code` agent (dev session, no capability) | `human` agent (Koopa) | Claude Code agents can attribute writes but hold no coordination capability; Koopa (human) holds `SubmitTasks` + platform-human override. | `registry.go:82-111` |
| **frontend page model vs backend domain model** | Angular admin pages (composed views) | backend entities | The frontend composes multiple backend reads into one page (e.g. the Today page forks 6 calls). Page-level view-models are **not** backend entities and may assume endpoints not yet verified to exist (§6). | frontend `today-page.component.ts`; §2 |

---

## 5. MCP tool semantics

The canonical inventory is `internal/mcp/ops/catalog.go::All()` — **45 tools**.
Each tool's `Writability` (`ReadOnly | Additive | Idempotent | Destructive`)
maps to MCP `ToolAnnotations` at registration and is the machine-readable risk
signal (`ops/types.go:28-42`). Below, tools are grouped by their declared
`Domain` plus the authorization axes that gate them
(`docs/authorization-matrix.md §3`).

### Group: knowledge / search (`DomainQuery`, `DomainContent`)

| Tool | Writability | Caller | Side effect | Enforcement |
|---|---|---|---|---|
| `search_knowledge` | ReadOnly | any registered | none | FTS-backed today; hybrid pgvector + RRF is planned and gated on the embedder write/backfill pipeline (§6D, §7 #1) |
| `create_content` / `update_content` / `submit_content_for_review` / `revert_content_to_draft` / `archive_content` | Additive/Destructive | any registered | content row + state | **Open** authorship; lifecycle CHECKs in schema |
| `publish_content` | Destructive | **human only** | atomic publish flip | `requireExplicitHuman` (`authz.go`); explicit `as` + Platform=human (`authorization-matrix.md:126`) |
| `list_content` / `read_content` | ReadOnly | any | none | — |
| `create_note` / `update_note` / `update_note_maturity` | Additive | any registered | note row / maturity | Open (`authorization-matrix.md:113-116`) |
| `manage_feeds` | Destructive | any registered | feed CRUD (list/add/update/remove) | Open; returns stripped FeedSummary |

**Semantics for testing:** content publish is the one hard human gate in this
group; search is read-only and **FTS-only in production today** — the hybrid
pgvector + RRF path is planned, not active (§6D, §7 #1). `manage_feeds` is a
multiplexer (≤4 actions, one entity) — Destructive because it includes
update/remove.

### Group: PARA / GTD / OKR (`DomainDaily`, `DomainMeta`)

| Tool | Writability | Caller | Side effect | Enforcement |
|---|---|---|---|---|
| `capture_inbox` | Additive | any | todo (state=inbox) | Open (caller's own todo) |
| `advance_work` | Destructive | self | todo transition (+auto plan-item, +recur reset) | Self-bound `caller==created_by`; Platform=human override (`authorization-matrix.md:170`) |
| `plan_day` | Idempotent | **hq + human** | atomic daily-plan replacement | Author allowlist = `hq` (`authorization-matrix.md:168`) |
| `propose_goal` / `propose_project` / `propose_milestone` | ReadOnly | author allowlist | **none** — returns signed token only | `requireAuthor` (hq, content-studio, research-lab) |
| `propose_hypothesis` | ReadOnly | hq, learning-studio, research-lab | token only | `requireAuthor` |
| `propose_learning_plan` / `propose_learning_domain` | ReadOnly | learning-studio (+hq for domain) | token only | `requireAuthor` |
| `commit_proposal` | Additive | depends on type | creates the proposed entity | `directive`→capability; **other 6 types→human only** (`authorization-matrix.md:152-153`) |
| `track_hypothesis` | Idempotent | — | hypothesis state | per-handler |
| `goal_progress` | ReadOnly | any | none | — |

**Semantics for testing:** `propose_*` tools are **ReadOnly** — they sign a
preview token and write nothing; the write happens at `commit_proposal`. Token
expires 10 min after issuance and is invalidated by server restart (HMAC secret
regenerates) (`catalog.go:225`). High-commitment commits are human-gated.

### Group: learning (`DomainLearning`)

| Tool | Writability | Side effect | Enforcement |
|---|---|---|---|
| `start_session` | Additive | new session | rejects if an active session exists (`uq_learning_sessions_one_active`) |
| `record_attempt` | Additive | attempt + observations + targets/relations + FSRS rating | **partial-write**: per-element validation; `observations_recorded < input` is legal (`catalog.go:319`) |
| `end_session` | Additive | ends session, optional reflection note | reflection→agent_note link trigger-bound |
| `learning_dashboard` | ReadOnly | none | 6 views; mastery floor <3 obs → `developing` |
| `recommend_next_target` | ReadOnly | none | active-session scoped |
| `attempt_history` | ReadOnly | none | 3 lookup modes (target/concept/session) |
| `session_progress` | ReadOnly | none | active-session aggregate |
| `manage_plan` | Destructive | plan entries lifecycle (6 actions) | completion requires `completed_by_attempt_id` + reason, or `force=true` with `manual override:` prefix (`mcp-decision-policy.md §13`) |
| `manage_targets` | Destructive | archive target + cascade relations | self-bound U2; Platform=human override (`catalog.go:411-419`) |

**Semantics for testing:** `record_attempt` partial-write contract is the
single most test-worthy learning behavior — rejected observation indices must
surface in `observation_warnings` while siblings and the attempt row persist.
`attempt_number` is **per-target, not per-session** (`catalog.go:319, 392`).

### Group: agent coordination / IPC (`DomainA2A`, parts of `DomainMeta`)

| Tool | Writability | Caller | Side effect | Enforcement |
|---|---|---|---|---|
| `propose_directive` | ReadOnly | SubmitTasks cap | token only; first part must be text (becomes title) | capability pre-check at propose (`catalog.go:174`) |
| `commit_proposal(directive)` | Additive | SubmitTasks | creates `tasks` row via `task.Store.Submit` | capability in `commitDirective` |
| `acknowledge_directive` | Idempotent | ReceiveTasks + task target | `submitted→working`, stamps `accepted_at` | capability + self (target) |
| `file_report(in_response_to)` | Additive | PublishArtifacts + task target | response message + artifact + `→completed` (atomic) | capability + self |
| `file_report(standalone)` | Additive | PublishArtifacts; allowlist excludes hq | free-standing artifact | `requireAuthor` (content-studio, research-lab, learning-studio) |
| `task_detail` | ReadOnly | source or target only | none; returns not_found to non-parties | self (party check) |
| `write_agent_note` / `query_agent_notes` | Additive / ReadOnly | any | agent_note row / read | self-directed |

**Semantics for testing:** the directive lifecycle is the core IPC contract.
Completion is trigger-enforced to require both a response message and an
artifact (`1366-1391`); `acknowledge_directive` is Idempotent (re-accept of a
non-submitted task → ErrConflict, tested). `task_detail` must not leak tasks
the caller is not party to.

### Group: audit / provenance

There are **no write tools** in this group — provenance is a side effect.
Audit events are emitted only by triggers; the read surface is embedded in
`morning_context`, `session_delta`, `weekly_summary`, and the admin
`/api/admin/coordination/activity` endpoint (frontend-advisory, §2).

### Group: system / context bootstrap (`DomainSystem`, `DomainQuery`)

| Tool | Writability | Side effect | Notes |
|---|---|---|---|
| `morning_context` | ReadOnly | none | single-call daily briefing; `sections` filter; **today-scoped** |
| `reflection_context` | ReadOnly | none | end-of-day, today-scoped |
| `session_delta` | ReadOnly | none | 24h activity snapshot (not a two-session diff) |
| `weekly_summary` | ReadOnly | none | Mon–Sun retrospective |
| `system_status` | ReadOnly | none | feeds health + 24h process_runs + entity counts |

**Semantics for testing:** these aggregate read tools have overlapping scopes
by design (today vs 24h-window vs week); contract tests should pin the *scope*
of each, not just non-emptiness. Four of them are currently **untested** (§6).

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

| Claim | Confidence | Evidence |
|---|---|---|
| Login + refresh-token rotation + token security behave as specified | claim-tested | `internal/auth/` — 27 tests incl. `auth_security_test.go` |
| Content draft→review→publish→archive transitions enforce their CHECKs | claim-tested | `internal/content/` integration (testcontainers) |
| Tag raw→canonical alias resolution (auto + admin paths) | claim-tested | `internal/tag/` integration |
| Feed fetch + scheduler cadence + auto-disable on failures | claim-tested | `internal/feed/scheduler_test.go` (testcontainers) |
| Task **submit→accept→complete happy path** lands message+artifact+state atomically | claim-tested | `task/integration_test.go::TestCompletionRequiresOutputs` |
| Task **self-assignment rejected** (`created_by<>assignee`) | claim-tested | `TestSelfAssignmentRejected` |
| Task **accept-idempotency** (re-accept non-submitted → ErrConflict) | claim-tested | `TestAcceptNonSubmittedRejected` |
| Task **message ordering serialized** under concurrent appends | claim-tested | `TestAppendMessage_ConcurrentAssigns_SerializedPositions` |
| **At-most-one active learning session** rejects a second `start_session` | claim-tested | `TestIntegration_StartSession_*` |
| `record_attempt` **cold-start happy path** (attempt + observations + targets) | claim-tested | `TestIntegration_ColdStart_RecordAttempt` |
| Mastery floor (<3 filtered obs → `developing`) + confidence-filter invariant | claim-tested | `TestObservationConfidenceInvariant`; `internal/learning/mastery_test.go` |
| FSRS rating-from-outcome + scheduler first-review | claim-tested | `internal/learning/fsrs/fsrs_test.go` |
| `propose_*`→`commit_proposal` round-trip + proposal validation | claim-tested | `TestIntegration_ProposeGoal_CommitRoundTrip`, `TestIntegration_ProposalValidator` |
| `propose_directive` capability pre-check rejects non-`SubmitTasks` callers | claim-tested | `TestIntegration_ProposeDirective_CapabilityPreCheck` |
| `task_detail` returns not_found to non-parties (no existence leak) | claim-tested | `TestIntegration_TaskDetail_*` |
| `manage_targets` archive + cascade + self-bound auth | claim-tested | 4 integration tests |

### B. Implemented and only SURFACE-tested (parity/validation, not semantics)

| Claim | Confidence | Evidence |
|---|---|---|
| The 45-tool catalog matches handler registration | surface-tested (**parity only**) | `ops_catalog_test.go:22-33` compares *names only* — proves registration completeness, **not** per-tool contract behavior |
| `search_knowledge` RRF merge + filter mutex logic | surface-tested (unit, no DB) | `search_test.go` — 4 unit tests on the merge function; no end-to-end search |
| Content/note write tools (`archive_content`, `create_note`, `update_note`, `update_note_maturity`, `manage_plan`) input validation | surface-tested | `handler_test.go` — validation only, limited business-logic integration |

### C. Implemented but WEAKLY tested (happy path only; rejection paths open)

| Claim | Gap (untested) | Evidence |
|---|---|---|
| Task completion requires ≥1 message AND ≥1 artifact | the **rejection** path (complete *without* artifact → should fail) is untested | `task/integration_test.go` covers the satisfied case only |
| Directive revision cycle (`completed→revision_requested→working→completed`) | the **full round-trip is untested** | no test exercises `revision_requested` |
| Artifacts | **standalone** artifact lifecycle untested; no handler-level test; only exercised as a task-completion payload | `internal/agent/artifact/` has no `*_test.go` |
| `record_attempt` partial-write | **per-element rejection** (`observation_warnings`, `relation_warnings`) coverage thin | audit |
| a2a part size/count caps (16/32KB, 32/256KB) | cap-**rejection** path untested | schema CHECKs `1307-1346` exist; no test drives them |
| Hybrid search semantic branch | no integration test against real pgvector; degradation path (embedder nil/timeout) untested | `search.go:182-236`; `search_knowledge` tool has no integration test |

### D. Schema-supported only (NOT implemented — do not assume it works)

| Feature | Reality | Evidence |
|---|---|---|
| **Document embedding write path** | **No automatic document-embedding write path exists — this is the current decision, not a TODO.** `embedder.Embed()` is defined (`embedder.go:65`) but has no production call site; app-created `content`/`note` rows therefore behave **FTS-only** unless embeddings are externally/backfill-populated. The vector-*read* path is real (`InternalSemanticSearch`, `content/public.go:104-115`) and *would* return rows if embeddings were backfilled — so "no write path" must not be conflated with "semantic branch can never return rows". **Decided (Phase 1D, 2026-05-27):** keep schema, indexes, and embedder package in place; do not implement write/backfill until agent recall ceilings on FTS are observed in practice. `search_knowledge` is documented as FTS-backed today. | `search.go:182-235` (only `EmbedQuery`); no `Embed()` call site; cols `migrations/001_initial.up.sql:495,573` |
| **Feed AI relevance scoring** | Not active — "scoring pipeline not yet active, all items have score=0"; highlights recency/priority-ordered | `internal/feed/entry/query.sql` |
| **Admin global-search Kind taxonomy** | `internal/search/search.go` declares 9 Kinds; only `KindContent` + `KindNote` are wired; `KindBookmark/Hypothesis/Concept/Task/Goal/Todo/Project` declared-but-unwired | `internal/search/search.go` |

### E. Untested entirely (no test files — confidence: unclear / requires evidence)

| Package / tool | Note |
|---|---|
| `internal/daily`, `internal/note`, `internal/search`, `internal/today`, `internal/todo`, `internal/weekly` | **No `*_test.go` files.** `internal/db` is sqlc-generated (acceptable). |
| MCP tools `goal_progress`, `reflection_context`, `session_delta`, `weekly_summary` | No direct tests found — output shape unverified |

### F. Today surface (CORRECTED in Track 0.1)

The endpoints exist — this is no longer an open existence question:

| Endpoint | Status | Evidence |
|---|---|---|
| `GET /api/admin/commitment/today` | exists (backend aggregate) | `cmd/app/routes.go:206` → `today.Handler.Today` (`internal/today/handler.go:108-137`) |
| `GET /api/admin/system/health` | exists | `cmd/app/routes.go:271` → `stats.Handler.Health` |
| `GET /api/admin/learning/summary` | exists | `cmd/app/routes.go:350` → `learning.Handler.Summary` |

**The real risk is a fan-out-vs-aggregate split, not endpoint existence:**

- The backend Today **aggregate exists but is only partially wired in
  production.** `today.NewHandler(planItems, logger)` requires only the plan
  reader; the judgment / due-reviews / warnings sections come from optional
  readers injected via `WithSources(...)` (`handler.go:78-100`). **`WithSources`
  is not called anywhere in `cmd/`**, so in production the aggregate returns the
  plan section populated and the AwaitingJudgment / DueReviews / Warnings
  sections **empty** (`handler.go:121-160` initialize-then-fill-if-reader).
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
| **MCP tools** | Catalog parity is **already surface-tested** (names only, `ops_catalog_test.go`) — that is not a contract test. Add claim-level contract tests for all 45 (the 4 untested aggregate readers first); writability annotation matches actual side effect; `propose_*` writes nothing; token expiry + restart invalidation + tamper rejection; per-tool authorization gate (human-only publish, capability pre-checks, self-bound advance_work/manage_targets). |
| **Search** | Decide the search product contract (Open Question #1) THEN integration-test the hybrid path with real pgvector; until then, test and document FTS-only behavior + graceful degradation when embedder nil/timeout (`search.go:198-207`). Add ranking-judgment tests (Scenario 6). |
| **Agent coordination** | Directive full lifecycle incl. **revision cycle**; duplicate ack idempotency; **duplicate report** behavior; report-without-directive (standalone) authorization; completion-**without**-artifact rejection; `task_detail` non-party leak; a2a part size/count cap rejection (`1307-1346`). |
| **Learning analytics** | `record_attempt` partial-write per-element rejection; mastery floor (<3 filtered obs → `developing`); confidence-filter read semantics; concept auto-creation boundary (leaf, same-domain only; cross-domain → rejected by trigger `2190`); plan-entry completion audit-trail enforcement (`mcp-decision-policy.md §13`). Needs a deterministic fixture matrix (see Scenario 4). |
| **Frontend workflows** | **Today surface reconciliation first** (§6F): decide canonical surface (fan-out vs aggregate) before any Today golden flow. Then a backend/frontend **route compatibility matrix** (every admin page: frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error behavior); then golden-flow each admin area; assert no UI affordance violates a forbidden assumption below. |
| **Observability** | **Track 1 input: inventory `activity_events` producers** and map each to `entity_type` × `change_kind` × actor attribution × write path × user-visible event × observability category × alert/dashboard relevance (see §7 Track 1 inputs). Confirm `koopa.actor` GUC is set on every Go write path so `actor='system'` only appears for genuine cron/manual ops (`registry.go:112-125`). Do NOT design dashboards yet. |

### Forbidden assumptions (UI / impl must NOT build on these)

No `tasks.kind`; no `bookmarks.status` lifecycle; no content/concept-scoped
review cards (one-per-target only); no daily-plan auto-carryover; no RBAC; no
quantitative milestones; no goal auto-status; no cross-domain
`learning_hypotheses`; no self-directed tasks; no direct `activity_events`
INSERT; no direct mastery edit; no FSRS internal-state edit knobs. (Each is
schema- or policy-enforced; see the cited constraints in §3/§5.)

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
4. **`directive` discriminator** — add `tasks.kind` or keep naming-only?
5. **Admin global-search Kind taxonomy** — wire the 7 unwired Kinds or remove
   the declarations?
6. **Feed AI relevance scoring** — implement or formally drop?
7. **Actor attribution surfacing** — `activity_events.actor` exists but is not
   propagated into `weekly.Summary` / `SessionDelta` / `MorningContext`
   outputs; widen those types?
8. **`agent_notes.metadata` schema** — formalize per-kind structure or keep
   policy-only + tolerant readers?
9. **"session_note" as a first-class entity** — formalize, or keep as a label
   over `agent_notes(kind=context|reflection)`?
10. **External `schedule` execution + `schedule run` recording** —
    **DECIDED (Phase 1D, 2026-05-27): scheduled execution is owned by the
    external Cowork/Desktop runner.** This repo provides the agent registry
    metadata, the schema, and the `process_runs(kind='agent_schedule')`
    audit row. **No internal scheduler is planned at this time.** Whether
    the external runner is actively writing those rows is not yet
    observable from this repo; adding a read-side observability surface
    (e.g. "last schedule run per agent" in `system_status`) is a follow-up
    task, deliberately separate from this ownership decision.
11. **Task `revision_requested` payload contract** — request-revision body
    shape (message vs artifact vs free text) is not codified.
12. **`contents.ai_metadata` consumer contract** — documented shape
    `{summary, keywords, quality_score, review_notes}` is not type-checked;
    treat as advisory.
13. **`learning_domains` lifecycle** — proposable at runtime but no
    retire/deactivate flow.
14. **`project_aliases` surface** — exist for fuzzy project resolution; not
    exposed in admin UI.
15. **"Blocked task" definition** — Scenario 1 wants to show blocked work, but
    `task_state` has no `blocked` value. Remove from the Today view, define as
    a read-side derived condition, or add a structural state. Until decided,
    do NOT test it as implemented.

### Track 1 inputs (carried out of Track 0; not started here)

1. **Today surface reconciliation** (§6F) — pick canonical surface before any
   Today golden flow.
2. **Backend/frontend route compatibility matrix** — every admin page:
   frontend endpoint ↔ backend route ↔ response envelope ↔ empty/error
   behavior. Broader than the two already-confirmed endpoints.
3. **Observability event taxonomy from real producers** — inventory every
   `activity_events` producer (the 12 audit triggers `2646-2911`) and map:
   `entity_type` · `change_kind` · actor attribution · write path · user-visible
   event · observability category · alert/dashboard relevance. Build the
   taxonomy from producers, not from prose. Do NOT design dashboards yet.
4. **Scenario→test-spec conversion** — turn each scenario in
   `usage-scenario-catalog.md` into a fixture-backed spec (the catalog now
   carries seed specs; Track 1 makes them executable).
