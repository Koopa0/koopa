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
**Milestone create** `POST /commitment/goals/{id}/milestones` `{ title, description, target_deadline? }`.
**Milestone toggle** `POST /commitment/goals/{id}/milestones/{mid}/toggle` → updated milestone (flips `completed_at`).

---

## Learning — Plan

**Create** `POST /learning/plans` — body:
```json
{ "title": "…", "description": "…", "domain": "leetcode", "goal_id"?: "uuid", "target_count"?: 10 }
```
**Plan status enum (5):** `draft · active · completed · paused · abandoned`.

**Detail** `GET /learning/plans/{id}` → ⚠️ **field-name decision (#9):**
```json
{ "plan": {…}, "entries": [EntryDetail], "progress": { "total", "completed", "skipped", "substituted", "remaining" } }
```
The real field is **`progress`** (not `summary`). The detail response *also* currently
embeds the plan's fields (anti-pattern) — I'll switch it to the explicit `{ plan, entries, progress }`
above. **⚠️ Decide: keep `progress` or rename to `summary`?** I lean **`progress`**
(matches the entity); say the word and I rename the backend (one line) if the design prefers `summary`.

**EntryDetail:** `{ plan_entry_id, plan_id, learning_target_id, position, status, phase?, substituted_by?, completed_by_attempt_id?, reason? }`.

**Entries** `POST /learning/plans/{id}/entries` `{ entries: [{ learning_target_id, phase? }] }` (max 100).
**Update entry** (the **audit-gate** modal): marking `status=completed` REQUIRES
`completed_by_attempt_id` + non-blank `reason` (server rejects otherwise, 400 `AUDIT_REQUIRED`).
`status=skipped` requires a `reason`.

---

## Learning — Domain & Hypothesis

**Domain create** `POST /learning/domains` `{ "slug": "kebab-case", "name": "…" }` (slug: `[a-z0-9-]`, no leading/trailing/double hyphen; both control-char validated).

**Hypothesis create** `POST /learning/hypotheses` `{ "claim": "…", "invalidation_condition": "…", "content"?: "…", "observed_date"?: "YYYY-MM-DD" }` → lands `state=unverified`. (`created_by` from the session actor.)
Lifecycle: `POST /learning/hypotheses/{id}/{verify|invalidate|archive|evidence}`.

---

## Daily & GTD — Todo

**Todo (Item) shape:** `{ id, title, state, due?, project_id?, completed_at?, energy?, priority?, recur_interval?, recur_unit?, description?, created_by, created_at, updated_at }`.
**State enum (5):** `inbox · todo · in_progress · done · someday`.

**List (state-filtered)** `GET /commitment/todos?state=&project=&priority=&energy=&q=&sort=&limit=` — serves Inbox / Today / Pending / Someday / Done.
**Create** `POST /commitment/todos` (`state` defaults to `inbox`; pass `state=todo` to skip clarify).
**Advance** `POST /commitment/todos/{id}/advance` (clarify / start / complete / defer / drop).
**Recurring view** `GET /commitment/todos/recurring` → `{ "due_today": [Item], "overdue": [Item] }`. *(new)*
**History view** `GET /commitment/todos/history?since=YYYY-MM-DD&q=&project=&limit=` → completed/searched items. *(new)*

**Daily plan** `GET /commitment/daily-plan?date=` (read) · **`PUT /commitment/daily-plan`** *(new)* `{ date?, items: [{ todo_id, position? }] }` → atomic set/reorder; rejects empty + inbox-state todos; returns the new plan + `items_removed`.

---

## Knowledge — Content & Note (enums for the editors)

**Content** type: `article · essay · build-log · til · digest`; status: `draft · review · published · archived` (lifecycle via `submit-for-review / publish / archive / revert-to-draft`); `is_public` toggle via `PATCH …/is-public`.
**Note** kind: `solve-note · concept-note · debug-postmortem · decision-log · reading-note · musing`; maturity: `seed · stub · evergreen · needs_revision · archived` (via `POST /notes/{id}/maturity`).

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
All list fields are `[]`, never `null`. `active_session` is omitted (not null) when no session is open. `PendingDetail` = a todo + its project; `Item` = a daily-plan item; `ActiveGoalSummary` / `Hypothesis` / `Session` match the goal/hypothesis/learning endpoints.
