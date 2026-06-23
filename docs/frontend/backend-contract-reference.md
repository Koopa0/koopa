# Backend contract reference — admin UI (real shapes)

> The **real** routes, request/response shapes, and enums from the Go backend.
> Bind the design + Angular build to *these* — don't invent field names. Domain
> model is backend SSOT; these are the read-model contracts the views consume.
> ⚠️ marks alignment points to decide.

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

## Daily & GTD — Todo

**Todo (Item) shape:** `{ id, title, state, due?, project_id?, completed_at?, energy?, priority?, recur_interval?, recur_unit?, description?, created_by, created_at, updated_at }`.
**State enum (5):** `inbox · todo · in_progress · done · someday`.

**List (state-filtered)** `GET /commitment/todos?state=&project=&priority=&energy=&q=&sort=&limit=` — serves Inbox / Today / Pending / Someday / Done. `state` accepts a single value or a comma-separated list (`state=inbox,todo,in_progress,someday` — the server-side done exclusion for the backlog); every element must be a valid state, else 400. List rows carry `created_by`.
**Create** `POST /commitment/todos` (`state` defaults to `inbox`; pass `state=todo` to skip clarify).
**Advance** `POST /commitment/todos/{id}/advance` (clarify / start / complete / defer / activate / drop). `activate` = someday → todo; wrong-state → 400 `INVALID_TRANSITION`.
**Recurring view** `GET /commitment/todos/recurring` → `{ "due_today": [Item], "overdue": [Item] }`.
**History view** `GET /commitment/todos/history?since=YYYY-MM-DD&q=&project=&limit=` → completed/searched items.

**Daily plan** `GET /commitment/daily-plan?date=` (read) · **`PUT /commitment/daily-plan`** `{ date?, items: [{ todo_id, position? }] }` → atomic set/reorder; rejects empty + inbox-state todos; returns the new plan + `items_removed`.

---

## Knowledge — Content (enums for the editors)

**Content** type: `article · essay · build-log · til · digest`; status: `draft · review · published · archived` (lifecycle via `submit-for-review / publish / archive / revert-to-draft`); `is_public` toggle via `PATCH …/is-public`.

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

## Wire-shape notes

1. **Today aggregate** follows the contracted brief(morning) shape. Contract below.

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
  "rss_highlights": [{ "title", "url", "feed_name", "created_at" }]
}
```
All list fields are `[]`, never `null`. `PendingDetail` = a todo + its project; `Item` = a daily-plan item; `ActiveGoalSummary` matches the goal endpoints.
