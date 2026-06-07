# MCP v3 — Semantic Contraction (Owner Decision Ledger)

**Status:** ACCEPTED — Koopa (human owner), 2026-06-05.
**Authority:** This document is the single source of truth for the agent surface during the
MCP v3 contraction. If any older doc — `decision-policy.md`, `backend-semantic-contract.md`,
`authorization-matrix.md`, the generated `skills/koopa-system` manual, or Studio role manuals —
contradicts this ledger, **this ledger wins** until those are regenerated (W10). **No agent may
resurrect a retired tool by citing an older document.** Those docs are stale the moment this is
accepted; they are rewritten LAST, on purpose.

---

## 0. Core reframe — the actor axis is FLOW vs DECISION/VIEW (not human-vs-agent)

- **Cowork agents drive FLOWS via MCP**, in conversation with Koopa.
- **Admin UI = confirm / decide / view.** No operational flow.
- **Koopa = sole decision-maker AND sole router.** No agent→agent dispatch. No agent→agent status
  sharing. Agent memory lives in the agent's own readable `.md`, not a DB table.
- **Agents are redefined: PLANNER + LEARNING COACH + SEARCH + NOTE CO-AUTHOR.** Content,
  commitments, curation, publishing, and hypothesis verdicts all return to Koopa in the admin UI.

---

## 1. MCP v3 accepted agent surface (~11 tools)

> **Follow-on owner decision (2026-06-08):** the `hq` identity is renamed to **`planner`**;
> all surfaces (Go core, docs, skills, frontend) are updated. The name is the only change —
> the role and the tool surface are unchanged.

| Tool | Locked semantics | Notes |
|---|---|---|
| `plan_day` | **planner / human-facing agents ONLY.** Pulls data + forms today's **candidate** plan. NOT priority-deciding, NOT auto-scheduling, NOT commitment-system owner. | role-scoped |
| `search_knowledge` | Retrieval over Koopa's corpus — the agent's only window into content/notes. | read |
| `capture_inbox` | Agent drops a **raw** todo into inbox FOR Koopa. Clarification/advance is Koopa's (admin). | write (insert-only) |
| `start_session` / `record_attempt` / `end_session` | Learning session lifecycle, Cowork-coached. | mutation |
| `manage_plan` (5 actions: `add_entries`, `remove_entries`, `update_entry`, `reorder`, `progress`) | Learning-plan curriculum management. | `update_plan` REMOVED → admin |
| `learning_read` (`view = overview \| next_target \| attempts \| session_progress`) | **READ-ONLY multiplexer.** Session / attempt / weakness / plan-based. **No FSRS due queue.** | never mutates |
| `brief` (`mode = morning \| reflection`) | **READ-ONLY multiplexer.** Planning-state pull for planner. No `agent_notes` / FSRS sections. | never mutates |
| `create_note` / `update_note` | Cowork co-authors the Zettelkasten — body / links only. | **maturity NOT here** |

**Invariant (Correction 3):** `brief` and `learning_read` are **READ-ONLY forever** — they never
grow a write/mutation action. Mutation lives ONLY in `start/record/end_session`, `manage_plan`,
`capture_inbox`, `create_note/update_note`, and `plan_day` (candidate-plan only).

---

## 2. Admin-only surfaces (left MCP → Koopa stamps / views in Angular)

| Surface | Why admin | Build needed? |
|---|---|---|
| Create goal / project / milestone / learning_plan / learning_domain | Commitments are Koopa's decisions | **Yes** — new admin create forms (backend POST + Angular); projects half-exists |
| Content authoring + lifecycle (write/paste, set-review-state, publish, archive) | Koopa authors all koopa0.dev content himself | content admin mostly exists |
| Todo lifecycle `advance_work` (clarify/start/complete/defer/drop) | Koopa manages his own todos; a button ends it | exists |
| `update_note_maturity` (declare evergreen / accepted) | Curation verdict is Koopa's, not an agent's | exists/small |
| `manage_plan(update_plan)` — plan activation/status | Activation is a commitment | small |
| Hypothesis CRUD / evidence / verify / invalidate (`track_hypothesis` off MCP) | Agent may contribute material via `create_note` / `search_knowledge` **suggestions**, never mutate truth state | exists |
| `manage_feeds` | Feed curation is admin | exists |
| Dashboards: `goal_progress`, `learning_dashboard`, `system_status`, `weekly_summary`, `attempt_history`, `session_progress` | Koopa views these in Angular | exists |

---

## 3. Retired surfaces (deleted — NO backward compatibility, no deprecation shims)

**MCP tools cut entirely:** `assign_research`, `create_report`, `file_report`,
`propose_directive`, `acknowledge_directive`, `task_detail`, `list_my_tasks`, `request_revision`,
`reaccept`, `write_agent_note`, `query_agent_notes`, `session_delta`. Plus every tool listed in
§2 is removed from the MCP catalog (its admin/HTTP surface stays).

**Features fully retired (full vertical stack):**
- **report-lane** — `internal/research`, `assign_research`/`create_report`/`file_report`.
- **A2A / task coordination** — `tasks` / `task_messages` / `artifacts`, the dispatch tools,
  `internal/agent/task`, `internal/agent/artifact`, admin `coordination/tasks` page.
  **Keep** admin `activity` (system-of-record view) and `agents` (registry view) pages.
- **agent_notes** — `write_agent_note` / `query_agent_notes` + `agent_notes` table. Agent memory
  moves to the agent's own `.md`.
- **bookmark** — full feature: `bookmarks` (+ junctions), admin pages, public `/api/bookmarks`,
  public Angular page.
- **FSRS / review** — `review_cards` / `review_logs`, SRS scheduling / due queue / next-review
  machinery. **Learning is a coach / weakness-review / session-observation model — NOT an
  Anki/FSRS spaced-repetition product.** Kept: session, `record_attempt`, observations, concept /
  target / plan, mastery-lite / weakness signal.

---

## 4. Schema-retirement candidates (W7 — edit migration 001 in place)

Drop from `migrations/001` **in place**: `tasks`, `task_messages`, `artifacts`, `agent_notes`,
`review_cards`, `review_logs`, `bookmarks`, `bookmark_topics`, `bookmark_tags`, plus retired
columns. **Delete migrations `003_tasks_acknowledged` and `004_report_lane` entirely** — their
tables (`research_assignments`, `reports`) and the added `tasks` columns vanish with them.

**End state = clean `001` + `002`.** NO append-only "drop" migrations. Rationale: pre-production;
do not let these decisions iterate forward into an archaeological mental-model burden.

---

## 5. Execution waves

| Wave | Scope | Schema? |
|---|---|---|
| **W-1** | **This ledger** — the authority. | — |
| **W0** | Dead code: 11 orphan sqlc queries + dead todo-skip path. | — |
| **W1** | Retire report-lane (code). | schema → W7 |
| **W2** | Retire A2A/task coordination (code). Keep activity + agents admin pages. | schema → W7 |
| **W3** | Retire agent_notes (code); ensure `brief` no longer pulls it. | schema → W7 |
| **W4** | Retire bookmark feature (code + admin + public). | schema → W7 |
| **W5** | Retire FSRS — **Phase A** remove MCP/read deps; **Phase B** `learning_read` → session/attempt/weakness/plan-based. (Phase C tests/docs → W10; Phase D schema → W7.) | schema → W7 |
| **W6** | Contract MCP catalog: remove §2 tools + `session_delta` from the catalog. Backend/HTTP stays. | — |
| **W7** | **Schema converge into 001** (edit-in-place + delete 003/004 + `sqlc generate` + rebuild test DB + full build/test). | **yes** |
| **W8** | Build R1 admin create forms (goal/milestone/learning_plan/learning_domain); ensure admin covers maturity / update_plan / track_hypothesis / content-lifecycle stamps. | — |
| **W9** | Build READ-ONLY multiplexers `brief(mode)` + `learning_read(view)`. | — |
| **W10** | Doc cascade LAST: rewrite `decision-policy.md` / `backend-semantic-contract.md` / `authorization-matrix.md`; regenerate `skills/koopa-system`; delete Studio role-manuals. | — |

**Doc-cascade ordering rule:** this ledger FIRST → code/schema cleanup → regenerate generated
docs → delete old Studio manuals LAST. Never edit the descriptive docs into "future fantasy"
before the code matches them.

---

## 6. Execution rules (binding)

- **Schema converges into 001** (edit-in-place; delete 003/004; no append-only drop migrations).
- **No backward compatibility / no deprecation shims.**
- **Clean removal:** full vertical stack per feature; no orphans.
- **Per-wave gate:** `go build` → `go vet` → `golangci-lint` → `go test` + reviewers before the next wave.
- **Branch:** `refactor/mcp-v3-contraction`. Conventional commits; refactor (zero-behaviour) split from any semantic fix.

---

## 7. Why this ledger exists (anti-resurrection)

Retired tools must not be revived by citing older docs (`decision-policy §8/§14`, Studio manuals,
the old MCP catalog). Those become stale the instant this is accepted and are rewritten **last**
(W10). Until then, **this document is the single source of truth for the agent surface.**
