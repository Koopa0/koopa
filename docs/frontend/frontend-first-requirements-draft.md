# Frontend-First Requirements Draft — koopa admin UI (HYBRID rebuild)

> **Status:** DRAFT for owner revision (2026-06-07). This is the *frontend-first*
> deliverable: it states what each **page** does and what **data (read-models)** +
> **actions** it needs, so the API is shaped to serve real views — not the views
> bent to fit the API. Domain model stays backend SSOT; the frontend owns the
> view/read-model contracts. Revise freely; ✏️ marks the open owner decisions.

## 0. Principle & method

1. Design the **page** (what Koopa does there) → 2. derive its **data needs**
(the read-model it renders) + **actions** (mutations) → 3. that defines the
**API contract**; existing endpoints are reused, gaps become new
endpoints (the kept store API is the menu). Never prune the store API before
the views that would call it are designed.

**Audience:** one human (Koopa). It's a personal knowledge / GTD / PARA /
learning OS admin surface — not a multi-tenant product. Optimise for *Koopa's*
daily workflow, density, and keyboard speed over generic SaaS polish.

---

## 1. Information architecture (top-level nav)

Keep the existing 5 areas; one is retired by the contraction.

| Area | Purpose | Contraction delta |
|---|---|---|
| **Daily** (was part of *commitment*) | today, plan, GTD inbox/todos | promote to its own area — it's the daily driver |
| **Commitment** (PARA) | goals, projects, milestones, areas | **+ create forms** (W8 backend ready) |
| **Knowledge** | content, notes, feeds, tags/topics, search | bookmark surfaces removed; content/notes lifecycle stays |
| **Learning** | sessions, attempts, plans, concepts/mastery, hypotheses, domains | + domain/plan create forms |
| **System** | health, stats, activity, agents (read-only) | **remove `coordination/tasks` + `pipeline`** (A2A/tasks retired); agents read-only |
| ~~Coordination/tasks~~ | — | **RETIRED** (tasks/task_messages/artifacts dropped) |

✏️ **Decision N1 — nav grouping:** split *Daily* out of *Commitment*, or keep
commitment as one area? (I recommend split — Daily is the everyday entry point.)

---

## 2. Per-area page specs

### 2.1 Daily

**`/daily/today`** — the home screen.
- **Reads:** `GET /commitment/today` → `{ planned_items[], completion: {planned, completed, deferred}, overdue_todos[], active_session?, rss_highlights[] }`. (This is the human mirror of the agent `brief(morning)`.)
- **Actions:** advance a todo (`POST /commitment/todos/{id}/advance`), open capture, start a learning session.
- **Backend:** `GET /today` exists. ✅

**`/daily/plan`** — build/adjust today's plan.
- **Reads:** `GET /commitment/daily-plan?date=` → ordered plan items + the candidate todo pool (state=todo).
- **Actions:** set/reorder the plan (the human equivalent of `plan_day`; needs `PUT /commitment/daily-plan` ✏️ **gap — not yet wired**), drag-reorder.
- **Backend:** GET exists; **plan-write endpoint = new** (store has the daily logic).

**`/daily/inbox` + `/daily/todos`** — GTD.
- **Reads:** todo lists by state — **inbox**, **today**, **pending** (w/ project), **someday**, **recurring**, **done/history**. ← *this is where the "dormant" kept store API lives* (`InboxItems`, `PendingItems`, `PendingItemsWithProject`, recurring×6, history×3). Each is a view the page needs.
- **Actions:** capture (`POST /commitment/todos`), clarify inbox→todo, advance/complete/defer/drop (`POST .../advance`), edit, delete.
- **Backend:** basic `GET /todos` + `POST` + advance exist; **the rich inbox/pending/recurring/someday/history list endpoints = new** (store methods ready — this is the menu to wire). ✏️ **Decision N2 — recurring todos in v1?** (the recurring store API exists; is the recurring UI in scope now or later?)

### 2.2 Commitment (PARA)

**`/commitment/goals`** (list) + **`/goals/{id}`** (detail) + **✏️ NEW `goals/new` create form**.
- **Reads:** list `GET /commitment/goals`; detail `GET /goals/{id}` → `{ goal, milestones[], projects[], recent_activity[] }`.
- **Actions:** **create goal** (`POST /commitment/goals` ✅ W8), **add milestone** (`POST /goals/{id}/milestones` ✅ W8), update status (`PUT /goals/{id}/status` ✅), toggle milestone (store ready, ✏️ endpoint gap), filter by status (store `GoalsByOptionalStatus` ready).
- **Form fields (goal):** title*, description, area, quarter, deadline. **Status is server-set `not_started`** (transition via the status action, not create).
- **Form fields (milestone):** title*, description, target_deadline.

**`/commitment/projects`** list + detail + profile editor (exists). **Areas** = a small PARA admin (✏️ areas are "human-only" — a simple CRUD, low priority).

### 2.3 Knowledge

**`/knowledge/content`** — list + the **content editor** (exists; wire to `POST /content`, lifecycle: submit-for-review / publish / archive / revert / is-public toggle — all endpoints exist ✅). Content types: article / essay / build-log / til / digest.

**`/knowledge/notes`** — Zettelkasten. List + **note editor** (exists; `POST /notes`, maturity transition `POST /notes/{id}/maturity` ✅). kinds: solve-note / concept-note / debug-postmortem / decision-log / reading-note / musing; maturity seed→evergreen→archived.

**`/knowledge/feeds`** — RSS sources + **feed-entries curation** (curate / ignore / feedback — endpoints exist ✅). **Tags + tag-aliases + topics** admin (merge, confirm/map/reject aliases — endpoints exist ✅).

**`/knowledge/search`** — `GET /admin/search` over content + notes. ✅

### 2.4 Learning

**`/learning/dashboard`** — mastery/streak/recent-observations (`GET /learning/dashboard` ✅; degraded-partial by design).
**`/learning/sessions`** — list + detail (attempts timeline) + **start session** (`POST /sessions` ✅).
**`/learning/plans`** — list + detail (entries + progress) + **✏️ NEW plan create form** (`POST /plans` ✅ W8) + add/reorder entries (`POST /plans/{id}/entries` ✅) + update-entry (§13 audit gate — completed needs `completed_by_attempt_id` + `reason`).
**`/learning/concepts`** — concept list + detail (mastery, observations). `GET /concepts` ✅.
**`/learning/hypotheses`** — list + detail + lineage + verify/invalidate/archive/add-evidence (all endpoints exist ✅) + **✏️ create** (store ready, endpoint gap).
**`/learning/domains`** — **✏️ NEW domain create form** (`POST /domains` ✅ W8, kebab-slug + name).

### 2.5 System

**`/system/health`** + **`/system/stats`** (+ drift, learning) — read-only dashboards (✅). **`/system/activity`** — the audit-event feed (`GET /coordination/activity` ✅). **`/system/agents`** — read-only registry (`GET /coordination/agents` ✅). **Remove** `coordination/tasks` + `coordination/pipeline`.

---

## 3. Net-new this phase (the gaps)

| Item | Backend | Frontend |
|---|---|---|
| Goal / milestone create forms | ✅ POST exists (W8) | **build form pages** |
| Learning plan / domain create forms | ✅ POST exists (W8) | **build form pages** |
| Daily-plan write (reorder/set) | ✏️ **new endpoint** (store ready) | build the plan builder |
| GTD inbox/pending/recurring/someday/history views | ✏️ **new list endpoints** (store ready) | build the GTD views |
| Hypothesis / milestone-toggle create | ✏️ endpoint gaps (store ready) | forms |
| **Remove** stale surfaces | — | delete `coordination/tasks`, `pipeline`; audit any agent_notes/bookmark/morning-reflection/propose references; rewire removed endpoints |

---

## 4. Cross-cutting

- **Design system:** reuse the existing 9 shared components (data-table, modal, form-field, page-header, badge, loading-spinner, empty-state, hero-canvas) + Tailwind v4, **dark-mode default**. Extend, don't replace.
- **Angular v22** (released 2026-06-03): **Signal Forms (stable)** for every create/edit form (goal/milestone/plan/domain/content/note) — this is the headline win; **OnPush default**; **Vitest** (already aligned); **per-route render strategy** (SSR for public-ish read pages, CSR for editors); `debounced()` signals for search/filter inputs; zoneless. **Prereq: TypeScript v6 + Node 26** (drops Node 20) — do the toolchain bump first.
- **Accessibility:** WCAG 2.1 AA (semantic HTML, keyboard nav, focus, contrast) — there's an `accessibility` skill.
- **Performance:** OnPush + `@defer` for heavy panels, virtual scroll for long lists (todos, activity, content), bundle budgets.

---

## 5. Owner decisions — RESOLVED (2026-06-07)

1. **N1 — nav:** ✅ **SPLIT** Daily into its own top-level area.
2. **N2 — admin-creation model:** ✅ **both — but an architectural fact resolves it.** After the contraction, agents have **no MCP tool** to create the *high-commitment* entities — **goal, project, milestone, learning_plan (shell), learning_domain, hypothesis** (the `propose_*`/`commit` flow was removed; per ledger §2 these are **human-only via admin HTTP** — exactly why W8 shipped their POST endpoints). So the UI create **forms are mandatory, not optional — they are the *only* creation path for commitments.** Agents *can* still create **todo** (`capture_inbox`), **daily plan** (`plan_day`), **note** (`create_note`), **plan entries** (`manage_plan`) — for those, UI-create is convenience alongside the agent path. The UI is **not** read-mostly for commitments; it owns their creation. (Wanting agents to create commitments again = re-opening proposal-first → a new MCP surface, not a frontend change.)
3. **N3 — GTD depth:** ✅ **do all** — Inbox, Today, Pending, Someday, Recurring, History.
4. **N4 — sequence:** ✅ **do all**; suggested order: Daily + create-forms → Knowledge/Learning editors → System cleanup.
5. **N5 — visual:** ✅ **fresh visual**, but as **one cohesive new design system applied uniformly to rebuilt AND kept pages** (tokens + the 9 components re-skinned; keep structure + dark-mode default). Not page-by-page divergence. See the prompt.

---

## Appendix — Claude Design prompt

See `docs/frontend/claude-design-prompt.md`.
