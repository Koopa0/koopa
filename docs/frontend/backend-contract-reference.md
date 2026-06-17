# Backend contract reference — admin UI (real shapes)

> The **real** routes, request/response shapes, and enums from the Go backend
> (verified against source 2026-06-07). Bind the design + Angular build to *these*
> — don't invent field names. Domain model is backend SSOT; these are the
> read-model contracts the views consume. ⚠️ marks alignment points to decide.

All admin routes are under `/api/admin`. Mutations require `adminMid` (human-only);
reads require `authMid`. Envelope: `{ "data": ... }`; errors `{ "error": { code, message } }`.
Lists never return `null` — always `[]`. Timestamps are RFC3339.

---

## Commitment — Goal

**Create** `POST /commitment/goals` — body:
```json
{ "title": "…", "description": "…", "area_id"?: "uuid", "deadline"?: "RFC3339", "quarter"?: "2026-Q3" }
```
`status` is **NOT** accepted — the server always creates `not_started`. Transitions
go through `PUT /commitment/goals/{id}/status` `{ "status": "<enum>" }`.

**Status enum (5):** `not_started · in_progress · done · abandoned · on_hold`.

**Detail** `GET /commitment/goals/{id}` → `{ id, title, description, status, area_id?, area_name?, deadline?, quarter?, milestones[], projects[], recent_activity[], created_at, updated_at }`.
**List** `GET /commitment/goals?status=<enum>` (optional filter).
**Update** `PUT /commitment/goals/{id}` — partial: `{ title?, description?, quarter?, deadline?, area_id? }` (omitted = unchanged; `status` not accepted) → updated goal; 404 unknown.
**Milestone create** `POST /commitment/goals/{id}/milestones` `{ title, description, target_deadline? }`.
**Milestone update** `PUT /commitment/goals/{id}/milestones/{mid}` — partial: `{ title?, description?, target_deadline? }`; `mid` must belong to the goal (404 otherwise) → updated milestone.
**Milestone delete** `DELETE /commitment/goals/{id}/milestones/{mid}` → 204; same membership binding; completed milestones deletable; position gaps left as-is.
**Milestone toggle** `POST /commitment/goals/{id}/milestones/{mid}/toggle` → updated milestone (flips `completed_at`).
**Areas** `GET /commitment/areas` → `[{ id, slug, name, sort_order }]` — PARA areas for the goal area selector, ordered by `sort_order`.

---

## Learning — Plan

**Create** `POST /learning/plans` — body:
```json
{ "title": "…", "description": "…", "domain": "leetcode", "goal_id"?: "uuid", "target_count"?: 10 }
```
**Plan status enum (5):** `draft · active · completed · paused · abandoned`.

**List** `GET /learning/plans?domain=&status=` — no `domain` → management view (`draft`+`active`);
with `domain` → all statuses unless `status=` narrows. Rows = plan fields + **`entry_total`** +
**`entry_done`** (per-plan entry counts for the Entries/Progress columns).

**Detail** `GET /learning/plans/{id}` → ⚠️ **field-name decision (#9):**
```json
{ "plan": {…}, "goal_name": "…", "entries": [EntryDetail], "progress": { "total", "completed", "skipped", "substituted", "remaining" } }
```
`goal_name` = the linked goal's title for the meta strip (`""` when the plan has no goal — never a UUID).
The real field is **`progress`** (not `summary`). The detail response *also* currently
embeds the plan's fields (anti-pattern) — I'll switch it to the explicit `{ plan, entries, progress }`
above. **⚠️ Decide: keep `progress` or rename to `summary`?** I lean **`progress`**
(matches the entity); say the word and I rename the backend (one line) if the design prefers `summary`.

**EntryDetail:** `{ plan_entry_id, plan_id, learning_target_id, position, status, phase?, substituted_by?, completed_by_attempt_id?, reason? }`.

**Entries** `POST /learning/plans/{id}/entries` `{ entries: [{ learning_target_id, phase? }] }` (max 100).
**Update entry** (the **audit-gate** modal): marking `status=completed` REQUIRES
`completed_by_attempt_id` + non-blank `reason` (server rejects otherwise, 400 `AUDIT_REQUIRED`).
`status=substituted` requires `substituted_by` (400 otherwise). `skipped` has no extra gate.
**Attempt picker** `GET /learning/targets/{id}/attempts?limit=` (limit 1–100, default 20) →
newest-first attempts on one learning target:
`[{ id, outcome, duration_minutes?, attempted_at, created_at, session_id, attempt_number, paradigm, target_title, … }]`
— the candidate `completed_by_attempt_id` values for the audit-gate modal (replaces the raw UUID
field). Unknown target / no attempts → `[]` (never 404); out-of-range or non-numeric limit → 400.

---

## Learning — Domain & Hypothesis

**Domain create** `POST /learning/domains` `{ "slug": "kebab-case", "name": "…" }` (slug: `[a-z0-9-]`, no leading/trailing/double hyphen; both control-char validated).

**Hypothesis state enum (5):** `draft · unverified · verified · invalidated · archived`.
Machine: `draft → unverified → verified | invalidated → archived`. `draft` is the
agent-created pre-endorsement state (MCP `draft_hypothesis`, v3.1 inert drafts) —
inert: excluded from brief(morning), the Today aggregate, and every dashboard;
visible ONLY in the admin hypotheses list (render as a drafts/triage group).

**Hypothesis create** `POST /learning/hypotheses` `{ "claim": "…", "invalidation_condition": "…", "content"?: "…", "observed_date"?: "YYYY-MM-DD" }` → lands `state=unverified` (admin create IS the endorsement). (`created_by` from the session actor.)
**List** `GET /learning/hypotheses?state=<enum>&page=&per_page=` — optional state filter; `state=draft` is the triage view; bad value 400.
Lifecycle: `POST /learning/hypotheses/{id}/{verify|invalidate|archive|evidence}`.
**Endorse** `POST /learning/hypotheses/{id}/endorse` → `draft → unverified`; 200 + updated record; 409 `NOT_DRAFT` on a non-draft row; 404 unknown. *(new, v3.1)*
**Delete (draft-only)** `DELETE /learning/hypotheses/{id}` → 204; 409 `NOT_DRAFT` for any non-draft state — endorsed/resolved rows are permanent records. *(new, v3.1)*

---

## Daily & GTD — Todo

**Todo (Item) shape:** `{ id, title, state, due?, project_id?, completed_at?, energy?, priority?, recur_interval?, recur_unit?, description?, created_by, created_at, updated_at }`.
**State enum (5):** `inbox · todo · in_progress · done · someday`.

**List (state-filtered)** `GET /commitment/todos?state=&project=&priority=&energy=&q=&sort=&limit=` — serves Inbox / Today / Pending / Someday / Done. `state` accepts a single value or a comma-separated list (`state=inbox,todo,in_progress,someday` — the server-side done exclusion for the backlog); every element must be a valid state, else 400. List rows carry `created_by`.
**Create** `POST /commitment/todos` (`state` defaults to `inbox`; pass `state=todo` to skip clarify).
**Advance** `POST /commitment/todos/{id}/advance` (clarify / start / complete / defer / activate / drop). `activate` = someday → todo; wrong-state → 400 `INVALID_TRANSITION`.
**Recurring view** `GET /commitment/todos/recurring` → `{ "due_today": [Item], "overdue": [Item] }`. *(new)*
**History view** `GET /commitment/todos/history?since=YYYY-MM-DD&q=&project=&limit=` → completed/searched items. *(new)*

**Daily plan** `GET /commitment/daily-plan?date=` (read) · **`PUT /commitment/daily-plan`** *(new)* `{ date?, items: [{ todo_id, position? }] }` → atomic set/reorder; rejects empty + inbox-state todos; returns the new plan + `items_removed`.

---

## Learning — Dashboard & Summary

**Dashboard** `GET /learning/dashboard?view=&domain=&confidence_filter=` →
`{ streak_days, concepts: { count_total, counts_by_domain, rows[] }, recent_observations[], week_activity: [{ "date": "YYYY-MM-DD", "attempts": 0 }] }`.
`week_activity` = the last 7 UTC days of attempt logging (`learning_attempts.created_at`), zero-filled, today last.
**Summary** `GET /learning/summary` → `{ streak_days, domains: [DomainMastery] }` — the lightweight streak + per-domain mastery envelope (no due-review data).

---

## Knowledge — Content & Note (enums for the editors)

**Content** type: `article · essay · build-log · til · digest`; status: `draft · review · published · archived` (lifecycle via `submit-for-review / publish / archive / revert-to-draft`); `is_public` toggle via `PATCH …/is-public`.
**Note** kind: `solve-note · concept-note · debug-postmortem · decision-log · reading-note · musing`; maturity: `seed · stub · evergreen · needs_revision · archived` (via `POST /notes/{id}/maturity`).

---

## Knowledge — Readings

Literature shelf + reading diary. **Privacy boundary: no MCP tool, not in the
search corpus (no embeddings/tsvector) — this admin surface is the only access path.**
No rating field, ever — reflections are the only evaluation. DATE fields are `YYYY-MM-DD` strings.

**Reading shape:** `{ id, title, author, status, started_on?, finished_on?, is_public, created_at, updated_at }`. `author` is `""` when not recorded.
**Status enum (4):** `want_to_read · reading · finished · abandoned` (transitions free; not schema-enforced).

**List** `GET /knowledge/readings?status=<enum>` (optional filter; bad value 400) — ordered `updated_at` desc; status-group ordering is the frontend's call.
**Create** `POST /knowledge/readings` `{ title, author?, status?, started_on? }` — `status` defaults `want_to_read`; `finished_on` not accepted here (record it via update).
**Detail** `GET /knowledge/readings/{id}` → reading + `reflections[]` thread, ordered `entry_date` asc, `created_at` asc tiebreak.
**Update** `PUT /knowledge/readings/{id}` — partial: `{ title?, author?, status?, started_on?, finished_on?, is_public? }`. Convenience rule: transition to `finished` with no `finished_on` stamps today; an explicit date wins; an already-recorded date is never overwritten.
**Delete** `DELETE /knowledge/readings/{id}` → 204 — **cascades the diary**.

**Reflection shape:** `{ id, reading_id, entry_date, body, created_at, updated_at }`. Body is multi-line prose (newlines/tabs OK).
**Create** `POST /knowledge/readings/{id}/reflections` `{ body, entry_date? }` — `entry_date` defaults today.
**Update** `PUT /knowledge/readings/{id}/reflections/{rid}` — partial `{ body?, entry_date? }`; `rid` must belong to the reading (404 otherwise).
**Delete** `DELETE /knowledge/readings/{id}/reflections/{rid}` → 204; same membership binding.

---

## ✅ Alignment points — RESOLVED (2026-06-07)

1. **#9 plan-detail:** kept `progress` (matches `manage_plan(progress)` + the `Progress` type); de-embedded. Real wire shape: `{ "plan": {...}, "entries": [EntryDetail], "progress": { total, completed, skipped, substituted, remaining } }` — plan fields nest under `plan`, NOT flat. Same fix applied to session detail → `{ "session": {...}, "attempts": [...] }`.
2. **Today aggregate:** WIRED to the contracted brief(morning) shape (no longer a stub; stale task/agent_note fields dropped). Contract below.

## Daily — Today (real, wired)

`GET /api/admin/commitment/today` →
```json
{
  "date": "YYYY-MM-DD",
  "overdue_todos": [PendingDetail],
  "today_todos": [PendingDetail],
  "committed_todos": [Item],
  "upcoming_todos": [PendingDetail],
  "plan_completion": { "planned": 0, "completed": 0, "deferred": 0 },
  "active_goals": [ActiveGoalSummary],
  "unverified_hypotheses": [Hypothesis],
  "active_session": "Session | absent (omitempty)",
  "rss_highlights": [{ "title", "url", "feed_name", "created_at" }]
}
```
All list fields are `[]`, never `null`. `active_session` is omitted (not null) when no session is open. `PendingDetail` = a todo + its project; `Item` = a daily-plan item; `ActiveGoalSummary` / `Hypothesis` / `Session` match the goal/hypothesis/learning endpoints. `unverified_hypotheses` is state-scoped to `unverified` — `draft` hypotheses (v3.1 inert drafts) never appear here.
