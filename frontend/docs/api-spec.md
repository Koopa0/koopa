# API Spec — Mission Control Admin

> 前端對後端的 API 契約 — 這是 frontend ↔ backend 的唯一權威文件。
> 結構以 4 個 domain 為主軸（Commitment / Knowledge / Learning / Coordination），加上跨切面的 Activity / System / Auth / Search。
> 每個 endpoint 標：狀態（`✓ existing` / `🔨 new` / `🔧 extend`）、消費它的 UI surface。

**版本**：v2.1 — 2026-04-24
**語意來源**：`migrations/001_initial.up.sql`、`docs/backend-semantic-contract.md`
**base URL**：`/api/admin/*`（除 auth 與公開 API）
**認證**：所有 `/api/admin/*` 需 JWT via `Authorization: Bearer <token>`。mutation 路徑需 admin middleware（actor tx binding）。

---

## 1. Conventions

### 1.1 Request / Response 格式

- JSON only（`Content-Type: application/json`）
- 時間：RFC 3339（`2026-04-23T14:35:00Z`）
- ID：UUID string
- 分頁：`?page=N&per_page=M`（預設 `page=1, per_page=20, max per_page=100`）
- Pagination envelope：
  ```json
  { "data": [...], "total": 123, "page": 1, "per_page": 20 }
  ```
- 單一資源：直接回傳 object，`{ "id": ..., ... }`
- 204 No Content 用於 mutation 成功但無內容回傳（如 ignore、delete）
- Error envelope：
  ```json
  { "error": { "code": "NOT_FOUND", "message": "..." } }
  ```

### 1.2 Filter conventions

- 列表 filter 放 query params；**欄位名用 snake_case** 對齊 schema（`status=draft`、`actor=human`、`topic=go`）
- 多值用逗號：`?status=draft,review`
- 時間範圍：`?since=2026-04-22T00:00:00Z&until=2026-04-23T00:00:00Z`

### 1.3 Actor / caller identity

所有 mutation 路徑從 JWT 取得 agent name（`human`）並綁定到 per-request tx 的 `koopa.actor` GUC，audit trigger 自動寫入。前端不傳 actor field。

### 1.4 Cell-state envelope

後端 aggregate endpoint（如 `GET /system/health`）回傳含 `state` 欄位：
```json
{ "count": 23, "state": "ok" }
{ "count": 3, "state": "warn", "reason": "oldest 5d" }
{ "count": 1, "state": "error", "reason": "DNS resolution failed" }
```
前端只渲染，不推導 state。

### 1.5 Status badge mapping

| schema enum | CSS class | label |
|---|---|---|
| content_status | `.status-draft/.status-review/.status-published/.status-archived` | verbatim |
| task_state | `.status-submitted/.status-working/.status-revision_requested/.status-completed/.status-canceled` | verbatim |
| hypothesis_state | `.status-unverified/.status-verified/.status-invalidated/.status-archived` | verbatim |
| goal_status / project_status / todo_state / note_maturity | same pattern | verbatim |
| feed_entry_status | `.status-unread/.status-read/.status-curated/.status-ignored` | verbatim |
| process_run status | `.status-pending/.status-running/.status-completed/.status-failed/.status-skipped` | verbatim |

前端不得自創新 status 值。

---

## 2. Commitment domain

### 2.1 `GET /api/admin/commitment/today`  🔨 new

**Purpose**：Today Timeline route 主要資料來源。
**UI**：Today page（UX §5.3、design §5.1）
**Response**：
```json
{
  "date": "2026-04-23",
  "awaiting_judgment": {
    "content_review": [
      { "id": "...", "title": "...", "type": "til", "actor": "claude-cowork", "submitted_at": "..." }
    ],
    "unverified_hypotheses": [
      { "id": "...", "claim": "...", "actor": "learning-studio", "created_at": "..." }
    ],
    "completed_tasks_awaiting_approval": [
      { "id": "...", "title": "...", "source": "research-lab", "assignee": "human", "completed_at": "..." }
    ]
  },
  "plan": {
    "date": "2026-04-23",
    "planning_note": {
      "id": "...", "kind": "plan", "body_md": "...",
      "actor": "claude-cowork", "created_at": "..."
    },
    "items": [
      { "id": "...", "todo": { "id": "...", "title": "..." },
        "position": 1, "status": "done", "selected_by": "claude-cowork" }
    ],
    "summary": { "total": 8, "done": 4, "overdue": 1 }
  },
  "due_reviews": {
    "count": 3,
    "items": [
      { "card_id": "...", "target": { "id": "...", "title": "LC 76" },
        "domain": "leetcode", "retention": 0.62, "last_reviewed_at": "..." }
    ]
  },
  "warnings": [
    { "source": "feed", "severity": "warn", "message": "thoughtbot.com failing for 3d" },
    { "source": "goal", "severity": "warn", "message": "Koopa Studio launch stale 14d" }
  ]
}
```

### 2.2 `GET /api/admin/commitment/todos`  🔨 new

**Purpose**：Todos List route.
**UI**：UX §5.16
**Query**：`state=inbox|todo|in_progress|done|someday,project=<id>,priority=high|medium|low,due_before=<iso>,sort=due|priority|created_at`
**Response row**：
```json
{
  "id": "...", "title": "Wire content_status filter",
  "description": "...", "state": "in_progress",
  "priority": "medium", "due_date": "2026-04-25",
  "project_id": "...", "project_title": "Koopa admin v2",
  "created_at": "...", "created_by": "human",
  "updated_at": "...", "recurring": null
}
```

### 2.3 `POST /api/admin/commitment/todos`  🔨 new

**Purpose**：建 inbox todo（capture）或直接建 todo（if all fields present）。
**UI**：Todos list top `[+ New]` button.
**Body**：
```json
{ "title": "...", "state": "inbox" | "todo",
  "description": "?", "project_id": "?", "priority": "?", "due_date": "?" }
```
**Response**：201 + created todo.

### 2.4 `POST /api/admin/commitment/todos/:id/advance`  🔨 new

**Purpose**：wraps MCP `advance_work`. 推進 state machine.
**Body**：
```json
{ "action": "clarify" | "start" | "complete" | "defer" | "drop" }
```
**Response**：200 + updated todo；400 if illegal transition.

### 2.5 `PUT /api/admin/commitment/todos/:id`  🔨 new

更新欄位（title / description / project / priority / due_date）。不轉 state（state 走 advance）。

### 2.6 `DELETE /api/admin/commitment/todos/:id`  🔨 new

### 2.7 `GET /api/admin/commitment/todos/:id`  🔨 new

**Purpose**：Todo detail for the todo inspector / edit form. Returns the same shape as the list row plus full description, attached project, and full due_date/completed_at timestamps.

**Response**：`TodoDetail` — list-row fields plus `description`, `project` (full ref), `completed_at`, `last_state_change_at`.

### 2.8 `GET /api/admin/commitment/goals`  ✓ existing (rename)

**Purpose**：Goals list.
**UI**：`/admin/commitment/goals`.
**Note**：目前 backend 已有 `GET /api/admin/goals`；新路徑一律用 `/commitment/goals`，舊路徑不保留 alias（見 §10.1）. Response row shape 已對：`{id, title, area_name, status, quarter, deadline, milestones_total, milestones_done, ...}`.

### 2.9 `GET /api/admin/commitment/goals/:id`  ✓ existing (rename)

Goal profile detail. 既有 `GET /api/admin/goals/:id`.

### 2.10 `PUT /api/admin/commitment/goals/:id/status`  ✓ existing (rename)

既有 `PUT /api/admin/goals/:id/status`.

### 2.11 `GET/POST/PUT/DELETE /api/admin/commitment/projects[/:id]` + `/profile` variants  ✓ existing (rename)

既有 `/api/admin/projects/*` 系列（list / detail / create / update / delete / profile GET PUT DELETE）.

### 2.12 `GET /api/admin/commitment/daily-plan`  🔨 new

**Purpose**：Per-date plan envelope — the materialised `daily_plan_items` rows for the Today HERO + the legacy now-page dashboard. Distinct from §2.1 `/commitment/today`: `/today` is the full dashboard aggregate (judgment queue + plan summary + warnings); `/daily-plan` is just the plan list for a chosen date.

**UI**：Today HERO (as a sub-fetch of §2.1 until backend folds it in), now-page dashboard.

**Query**：`date=YYYY-MM-DD`（optional；缺省 = server today）.

**Response**：
```json
{
  "date": "2026-04-24",
  "items": [
    {
      "id": "<plan_item_id>",
      "todo_id": "<todo_id>",
      "title": "Draft the GDE essay outline",
      "priority": "high|medium|low",
      "state": "planned|done|deferred|dropped",
      "reason": "<plan-time note from the author>",
      "due_date": "2026-04-24",
      "completed_at": null,
      "selected_by": "hq"
    }
  ],
  "total": 3,
  "done": 1,
  "overdue_count": 0
}
```

**Note**：state/reason 由後端決定並寫入，前端只 render，不 derive（見 §10.8）.

---

## 3. Knowledge domain

### 3.1 Content

#### `GET /api/admin/knowledge/content`  ✓ existing (rename)

既有 `GET /api/admin/contents`（複數/單數不一致；建議 rename，但非阻塞）。
**UI**：Content List route.
**Query**：`type=article|essay|build-log|til|digest,status=draft|review|published|archived,topic=<slug>,actor=<agent_name>,is_public=true|false,q=<search>,sort=updated_at|created_at|published_at`
**Response row**：
```json
{
  "id": "...", "slug": "...", "title": "...",
  "type": "til", "status": "review", "is_public": false,
  "topic": { "slug": "system-design", "name": "System Design" },
  "tags": ["pg", "explain"],
  "actor": "claude-cowork",
  "project_id": null,
  "ai_metadata": { "summary": "...", "quality_score": 8.2 },
  "reading_time_min": 2,
  "created_at": "...", "updated_at": "...", "published_at": null
}
```

> ⚠ **移除** `review_level` / `maturity` / `note_kind` 欄位——contract 不支援，frontend 型別殘留。

#### `GET /api/admin/knowledge/content/:id`  ✓ existing (rename)

既有 `GET /api/admin/contents/:id`. 回傳同上 + `body: string`.

#### `POST /api/admin/knowledge/content`  ✓ existing (rename)

建 draft（status='draft'）。
**Body**：`{ "type": "til", "title": "...", "body": "...", "slug": "?", "topic_slug": "?", "tags": ["..."], "project_id": "?", "source": "?" }`
**Response**：201 + full content.

#### `PUT /api/admin/knowledge/content/:id`  ✓ existing (rename)

更新欄位（不轉 status）。

#### `POST /api/admin/knowledge/content/:id/submit-for-review`  🔨 new

Wraps MCP `submit_content_for_review`. draft → review 唯一路徑。
**Body**：`{}`（空）
**Response**：200 + updated content.
**Error**：400 if status != draft.
**UI**：Content Editor 頂部 action（作者自用；review queue 的來源）。

#### `POST /api/admin/knowledge/content/:id/revert-to-draft`  🔨 new

Wraps MCP `revert_content_to_draft`. review → draft，相當於 "reject".
**Body**：`{ "reviewer_notes": "?" }`（可選；若給則寫入 `ai_metadata.review_notes`）
**Response**：200 + updated content.
**Error**：400 if status != review.
**UI**：Content Editor 頂部 action；**取代現有 frontend `ContentService.reject()` 指向的 `/reject` URL**.

#### `POST /api/admin/knowledge/content/:id/publish`  ✓ existing (with human gate)

既有 `POST /api/admin/contents/:id/publish`. **僅 human caller 可用**（backend 雙重驗證；non-human 回 403）。
Atomic：`status=published + is_public=true + published_at=now()`.

#### `PATCH /api/admin/knowledge/content/:id/is-public`  ✓ existing (rename)

既有 `PATCH /api/admin/contents/:id/is-public`. 僅當 status=published 時可 toggle.

#### `POST /api/admin/knowledge/content/:id/archive`  🔨 new

Wraps MCP `archive_content`. 任何 status → archived.
**Body**：`{}`
**Response**：200 + updated content.
**UI**：Content Editor overflow menu.

#### `DELETE /api/admin/knowledge/content/:id`  ✓ existing (rename)

既有 `DELETE /api/admin/contents/:id`.

### 3.2 Notes (Zettelkasten, 獨立 entity)

#### `GET /api/admin/knowledge/notes`  🔨 new

**UI**：Notes List route / Concept profile linked notes.
**Query**：`kind=solve-note|concept-note|debug-postmortem|decision-log|reading-note|musing,maturity=seed|stub|evergreen|needs_revision|archived,concept_slug=<>,target_id=<>,q=<>`
**Response row**：
```json
{
  "id": "...", "slug": "...", "title": "...",
  "kind": "solve-note", "maturity": "seed",
  "actor": "human",
  "concepts": [{ "slug": "sliding-window", "name": "Sliding window" }],
  "targets": [{ "id": "...", "title": "LC 295" }],
  "created_at": "...", "updated_at": "..."
}
```

#### `GET /api/admin/knowledge/notes/:id`  🔨 new

Returns row + `body: string`.

#### `POST /api/admin/knowledge/notes`  🔨 new

Wraps MCP `create_note`.
**Body**：`{ "title": "...", "body": "...", "kind": "solve-note", "maturity": "seed", "slug": "?", "concept_slugs": [], "target_ids": [] }`
**Response**：201 + full note.

#### `PUT /api/admin/knowledge/notes/:id`  🔨 new

Wraps MCP `update_note`. 更新 title / body / kind / relations. **不**改 maturity.

#### `POST /api/admin/knowledge/notes/:id/maturity`  🔨 new

Wraps MCP `update_note_maturity`. 獨立 audit.
**Body**：`{ "maturity": "evergreen" }`
**Response**：200 + updated note.
**UI**：Note Editor maturity slider. 反向 transition（e.g. evergreen→stub）backend 可能 warn，前端二次確認。

#### `DELETE /api/admin/knowledge/notes/:id`  🔨 new

### 3.3 Bookmarks

#### `GET /api/admin/knowledge/bookmarks`  ✓ existing (rename)

既有 `GET /api/admin/bookmarks`.
**Response row**：
```json
{
  "id": "...", "slug": "...", "title": "...",
  "url": "https://...",
  "note": "Koopa's commentary in md",
  "topic": { "slug": "go", "name": "Go" },
  "tags": ["gotchas"],
  "source_feed_entry_id": null,
  "source_feed_name": null,
  "relevance_score": null,
  "is_public": true,
  "actor": "human",
  "published_at": "..."
}
```

#### `GET /api/admin/knowledge/bookmarks/:id`  ✓ existing (rename)

#### `POST /api/admin/knowledge/bookmarks`  ✓ existing (rename)

建立即發佈.
**Body**：`{ "title": "...", "url": "...", "note": "?", "topic_slug": "?", "tags": [] }`
Response: 201 + bookmark（預設 `is_public=true, published_at=now()`）.

#### `PUT /api/admin/knowledge/bookmarks/:id`  🔨 new

**Purpose**：更新 title / note / tags / topic. URL 不可改（URL 就是 identity）.
**Body**：`{ "title": "?", "note": "?", "topic_slug": "?", "tags": [] }`
**Response**：200 + updated bookmark.
**UI**：Bookmark List row side panel quick edit.

#### `DELETE /api/admin/knowledge/bookmarks/:id`  ✓ existing (rename)

### 3.4 Feeds

#### `GET /api/admin/knowledge/feeds`  ✓ existing (rename)

既有 `GET /api/admin/feeds`.
**Response row**：
```json
{
  "id": "...", "name": "thoughtbot.com",
  "url": "https://thoughtbot.com/rss",
  "schedule": "daily",
  "topic_slugs": ["dev", "ruby"],
  "enabled": true,
  "consecutive_failures": 0,
  "last_fetched_at": "...",
  "last_error": null,
  "priority": "normal"
}
```

#### `POST/PUT/DELETE /api/admin/knowledge/feeds[/:id]`  ✓ existing (rename)
#### `POST /api/admin/knowledge/feeds/:id/fetch`  ✓ existing (rename)

Force fetch now. Background job；200 回傳 `{ "status": "queued" }`.

### 3.5 Feed entries (Triage)

#### `GET /api/admin/knowledge/feed-entries`  ✓ existing (rename)

既有 `GET /api/admin/feed-entries`.
**UI**：Feeds Triage cards（UX §2.4、design §5.5）
**Query**：`status=unread|read|curated|ignored,feed_id=<>,topic_slug=<>,min_relevance=0.0-1.0,sort=relevance|collected_at`
**Response row**：
```json
{
  "id": "...", "title": "...", "excerpt": "...",
  "source_url": "https://...",
  "feed": { "id": "...", "name": "thoughtbot.com" },
  "topic_slugs": ["go"],
  "relevance_score": 0.92,
  "status": "unread",
  "collected_at": "...", "published_at": "...",
  "curated_content_id": null,
  "user_feedback": null
}
```

#### `POST /api/admin/knowledge/feed-entries/:id/curate`  ✓ existing (rename)

Link feed_entry → existing content row.
**Body**：`{ "content_id": "..." }`
**Response**：204.
**UI**：Triage `Draft` action 的 step 2（step 1 是 `POST /content` 建 draft）.

#### `POST /api/admin/knowledge/feed-entries/:id/ignore`  ✓ existing (rename)

**Body**：`{}`；**Response**：204.

#### `POST /api/admin/knowledge/feed-entries/:id/feedback`  ✓ existing (rename)

Relevance scoring feedback.
**Body**：`{ "feedback": "up" | "down" }`
**Response**：204.

### 3.6 Topics

#### `GET /api/admin/knowledge/topics`  🔧 extend

既有 `GET /api/topics`（公開）. Admin 版本若不存在需加；用於 Content Editor metadata picker.

#### `POST/PUT/DELETE /api/admin/knowledge/topics[/:id]`  ✓ existing (rename)

### 3.7 Tags / Tag aliases

#### `GET /api/admin/knowledge/tags` + CRUD + `/merge`  ✓ existing (rename)
#### `GET /api/admin/knowledge/tag-aliases*`  ✓ existing (rename)

優先度低（管理工具，非日常）.

---

## 4. Learning domain

### 4.1 `GET /api/admin/learning/dashboard`  🔨 new

**Purpose**：Learning Dashboard 3 card 資料來源. Wraps MCP `learning_dashboard`.
**UI**：UX §5.6、design §5.6.
**Query**：`view=overview|mastery|weaknesses|retrieval|timeline|variations,domain=<>,confidence_filter=high|all`
**Response (view=overview)**：
```json
{
  "concepts": {
    "count_total": 48,
    "counts_by_domain": { "leetcode": 22, "go": 9, "system-design": 12, "japanese": 3, "reading": 2 },
    "rows": [
      { "slug": "sliding-window", "kind": "pattern", "domain": "leetcode",
        "obs_count": 14, "mastery_value": 0.42, "mastery_stage": "developing",
        "next_due": "2026-04-25" }
    ]
  },
  "due_today": {
    "count": 3,
    "items": [
      { "card_id": "...", "target": { "id": "...", "title": "LC 76" },
        "domain": "leetcode", "retention": 0.62, "last_reviewed_at": "..." }
    ]
  },
  "recent_observations": [
    { "id": "...", "signal": "weakness", "category": "state-transition",
      "body": "...", "domain": "leetcode", "concept_slug": "dp",
      "confidence": "high", "created_at": "..." }
  ]
}
```
Other views 的 shape 見 MCP docs.

### 4.2 `GET /api/admin/learning/concepts`  🔨 new

**UI**：Concepts List.
**Query**：`domain=<>,kind=pattern|skill|principle,mastery_stage=struggling|developing|solid,q=<>`
**Response row**：
```json
{
  "slug": "sliding-window", "kind": "pattern", "domain": "leetcode",
  "mastery_stage": "developing",
  "mastery_counts": { "weakness": 5, "improvement": 2, "mastery": 7 },
  "obs_count": 14,
  "parent_slug": null,
  "next_due_target": { "id": "...", "title": "LC 76", "due_at": "..." }
}
```

### 4.3 `GET /api/admin/learning/concepts/:id`  🔨 new

Concept profile full detail. Path param is the concept **uuid**, not the slug — concept slugs are only unique within a `(domain, slug)` pair, so cross-domain routing uses the uuid.

**UI**：UX §5.7、design §5.7.
**Query**：`confidence_filter=high|all`（toggle low-confidence obs）
**Response**：
```json
{
  "slug": "sliding-window", "kind": "pattern", "domain": "leetcode",
  "mastery_stage": "developing",
  "mastery_counts": { "weakness": 5, "improvement": 2, "mastery": 7 },
  "low_confidence_counts": { "weakness": 2, "improvement": 0, "mastery": 1 },
  "parent": { "slug": "...", "name": "..." },
  "children": [ { "slug": "...", "name": "..." } ],
  "relations": [ { "type": "prerequisite", "concept": { "slug": "...", "name": "..." } } ],
  "linked_notes": [ { "id": "...", "title": "...", "kind": "solve-note", "maturity": "seed" } ],
  "linked_contents": [ { "id": "...", "title": "...", "type": "til" } ],
  "recent_attempts": [ { "id": "...", "target_title": "LC 295", "outcome": "solved_with_hint", "created_at": "..." } ],
  "recent_observations": [ /* …shape of §4.1 rows */ ]
}
```

### 4.4 `GET /api/admin/learning/sessions`  🔨 new

Sessions list.
**Query**：`domain=<>,mode=retrieval|practice|mixed|review|reading,ended=true|false,sort=started_at`
**Response row**：`{id, domain, mode, started_at, ended_at, attempt_count, solved_independent_count, observation_count, reflection_note_id?}`.

### 4.5 `GET /api/admin/learning/sessions/:id`  🔨 new

Session Timeline full data. Wraps MCP `learning_dashboard(view=overview, session_id=...)` + `attempt_history`.
**UI**：UX §5 Timeline route，design §5.9.
**Response**：
```json
{
  "id": "...", "domain": "leetcode", "mode": "practice",
  "started_at": "...", "ended_at": "...",
  "summary": { "attempts": 3, "solved_independent": 1, "solved_with_hint": 2, "observations": 3 },
  "attempts": [
    {
      "id": "...", "target": { "id": "...", "title": "LC 295" },
      "paradigm": "problem_solving", "outcome": "solved_with_hint",
      "duration_minutes": 24, "stuck_at": "state transition bound",
      "approach": "two heaps", "created_at": "...",
      "observations": [
        { "id": "...", "signal": "weakness", "category": "state-transition",
          "body": "...", "concept_slug": "dp", "severity": "critical", "confidence": "high" }
      ]
    }
  ],
  "reflection_note": {
    "id": "...", "kind": "reflection", "body_md": "...",
    "actor": "learning-studio", "created_at": "..."
  }
}
```

### 4.6 `POST /api/admin/learning/sessions`  🔨 new

Start a new session. Wraps MCP `start_session`.
**Body**：`{ "domain": "leetcode", "mode": "review" }`
**Response**：201 + session. 若已有 active session 回 409.
**UI**：Today `Start session` button、Dashboard Due reviews.

### 4.7 `POST /api/admin/learning/sessions/:id/end`  🔨 new

Wraps MCP `end_session`. 可選帶 reflection note body.
**Body**：`{ "reflection_md": "?" }`
**Response**：200 + updated session (含 agent_note_id if reflection provided).

### 4.8 `POST /api/admin/learning/sessions/:id/attempts`  🔨 new

Record an attempt. Wraps MCP `record_attempt`.
**Body**：schema per MCP（target_id/title, paradigm, outcome, stuck_at, approach, observations[]）
**Response**：201 + attempt with observations.

### 4.9 `GET /api/admin/learning/plans`  🔨 new

Plans list.

### 4.10 `GET /api/admin/learning/plans/:id`  🔨 new

Plan Timeline. Wraps MCP `manage_plan(progress)`.
**UI**：design §5.10.
**Response**：
```json
{
  "id": "...", "title": "...", "status": "active", "goal_id": null,
  "entries": [
    {
      "id": "...", "position": 1, "status": "completed",
      "target": { "id": "...", "title": "..." },
      "completed_at": "...",
      "completed_by_attempt_id": "...",
      "reason": "solved_independent on attempt #2, 8 min, clean implementation"
    }
  ],
  "summary": { "total": 10, "completed": 3, "skipped": 0, "substituted": 1 }
}
```

### 4.11 `POST /api/admin/learning/plans/:id/entries`  🔨 new

Wraps `manage_plan(add_entries)`.

### 4.12 `PUT /api/admin/learning/plans/:id/entries/:entry_id`  🔨 new

Wraps `manage_plan(update_entry)`. status 轉 completed 時 **policy-mandatory** 帶 `completed_by_attempt_id` + `reason`.

### 4.13 `GET /api/admin/learning/hypotheses`  ✓ existing (rename)

既有 `GET /api/admin/hypotheses`.
**Query**：`state=unverified|verified|invalidated|archived,actor=<>`

### 4.14 `GET /api/admin/learning/hypotheses/:id`  ✓ existing (rename)

### 4.15 `GET /api/admin/learning/hypotheses/:id/lineage`  🔨 new

**Purpose**：Hypothesis Profile Origin + Linked observations sections.
**UI**：UX §4.3、design §5.8.
**Response**：
```json
{
  "hypothesis": { "id": "...", "claim": "...", "invalidation_condition": "...", "state": "unverified", "actor": "...", "created_at": "..." },
  "origin": {
    "session": { "id": "...", "domain": "...", "mode": "...", "started_at": "...", "ended_at": "..." },
    "attempts": [ /* abbreviated per §4.5 */ ]
  },
  "observations": [ /* same shape as concept obs */ ],
  "evidence_log": [
    { "id": "...", "type": "supporting" | "counter", "body": "...",
      "linked_attempt_id": null, "linked_observation_id": null,
      "added_at": "...", "actor": "..." }
  ]
}
```

### 4.16 `POST /api/admin/learning/hypotheses/:id/verify`  ✓ existing (rename)
### 4.17 `POST /api/admin/learning/hypotheses/:id/invalidate`  ✓ existing (rename)
### 4.18 `POST /api/admin/learning/hypotheses/:id/archive`  ✓ existing (rename)
### 4.19 `POST /api/admin/learning/hypotheses/:id/evidence`  ✓ existing (rename)

Add evidence row.
**Body**：`{ "type": "supporting" | "counter", "body": "...", "linked_attempt_id": "?", "linked_observation_id": "?" }`

### 4.20 `POST /api/admin/learning/reviews/:card_id`  🔨 new

Record FSRS review.
**Body**：`{ "rating": "again" | "hard" | "good" | "easy", "attempt_id": "?" }`
**Response**：200 + updated review_card（含新 due）.
**UI**：Dashboard `Due today` card rating buttons.

### 4.21 `GET /api/admin/learning/summary`  🔨 new

**Purpose**：Lightweight 3-field cell-state envelope for surfaces that need the due-review count / streak without paying for the full §4.1 dashboard fan-out. Today HERO + now-page dashboard read this; Learning Dashboard reads §4.1 instead.

**UI**：Today HERO review-chip, legacy `/admin/now` dashboard.

**Response**：
```json
{
  "streak_days": 12,
  "due_reviews": 4,
  "domains": [
    { "slug": "leetcode", "name": "LeetCode", "mastered": 23, "developing": 8, "weak": 2 },
    { "slug": "japanese", "name": "Japanese", "mastered": 11, "developing": 5, "weak": 0 }
  ],
  "state": "ok|warn|error",
  "reason": null
}
```

**Note**：subset of §4.1 — do NOT re-implement the streak/due-review logic separately; §4.1 and §4.21 MUST share the same aggregation query so the two responses never disagree.

---

## 5. Coordination domain

### 5.1 Tasks

#### `GET /api/admin/coordination/tasks`  ✓ existing (rename)

既有 `GET /api/admin/tasks`.
**UI**：Tasks List（UX §2、design §5.11）.
**Query**：`state=submitted|working|revision_requested|completed|canceled,source=<agent>,assignee=<agent>,priority=high|medium|low,sort=updated_at`
**Response row**：
```json
{
  "id": "...", "title": "...",
  "source": "human", "assignee": "research-lab",
  "state": "completed", "priority": "high",
  "submitted_at": "...", "accepted_at": "...", "completed_at": "...",
  "message_count": 3, "artifact_count": 2
}
```

#### `GET /api/admin/coordination/tasks/open` | `/completed` | `/:id`  ✓ existing (rename)

Returns full task object including description.

#### `GET /api/admin/coordination/tasks/:id/messages`  ✓ existing (rename)
#### `GET /api/admin/coordination/tasks/:id/artifacts`  ✓ existing (rename)

**UI**：Task Timeline main + side rail（UX §5.4、design §5.12）.
Message parts: a2a shape `{"text": "..."} | {"data": {...}}`. **不得** 有 `{"code": ...}` / `{"markdown": ...}` 等非 a2a 變體.

#### `POST /api/admin/coordination/tasks`  🔨 new

**Purpose**：human 發起 task（`Submit directive` button）.
**Body**：
```json
{ "title": "...", "description": "...",
  "assignee": "research-lab", "priority": "medium",
  "parts": [{"text": "..."}] }
```
**Response**：201 + task. Source auto-set to caller agent name (`human`).

#### `POST /api/admin/coordination/tasks/:id/reply`  ✓ existing (rename)

既有. 回覆 task.
**Body**：`{ "parts": [{"text": "..."}] }`

#### `POST /api/admin/coordination/tasks/:id/request-revision`  ✓ existing (rename)

既有. 當 task 已 completed 但 human 不滿意.
**Body**：`{ "reason": "...", "parts": [{"text": "..."}] }`
**Response**：200 + task (state=revision_requested).

#### `POST /api/admin/coordination/tasks/:id/approve`  🔨 new

**Purpose**：human 接受一個 completed task.
**Body**：`{ "notes": "?" }`
**Response**：200 + task.
**UI**：Task Timeline `[Approve]` button.
**Note**：若 backend task lifecycle 無 `approved` state，此 endpoint 可以只寫一筆 `response` message + 無 state transition；前端 UI affordance 是「acknowledge 完成」的明確動作。

#### `POST /api/admin/coordination/tasks/:id/cancel`  🔨 new

**Purpose**：human 取消 submitted/working task.
**Body**：`{ "reason": "?" }`
**Response**：200 + task (state=canceled).

### 5.2 Agents

#### `GET /api/admin/coordination/agents`  ✓ existing (rename)

既有 `GET /api/admin/agents`.
**Response row**：
```json
{
  "name": "research-lab", "display_name": "Research Lab",
  "platform": "claude-cowork", "status": "active",
  "capabilities": ["task.accept", "task.complete", "content.create"],
  "as_creator_open": 2, "as_assignee_open": 1,
  "last_active_at": "..."
}
```

#### `GET /api/admin/coordination/agents/:name`  ✓ existing (rename)

Agent profile detail. row + recent artifacts + capability flags.

#### `GET /api/admin/coordination/agents/:name/tasks`  ✓ existing (rename)

Agent's task history.

#### `GET /api/admin/coordination/agents/:name/notes`  🔨 new

**Purpose**：Agent profile Context notes tab. Wraps MCP `query_agent_notes`.
**UI**：Agent Profile（UX §4.2、design §5.13）.
**Query**：`kind=plan|context|reflection,since=<iso>,until=<iso>`（kind 支援逗號分隔多值）.
**Response row**：
```json
{ "id": "...", "kind": "context", "body_md": "...", "metadata": {},
  "created_at": "...", "actor": "research-lab" }
```

### 5.3 Process runs

#### `GET /api/admin/coordination/process-runs`  🔨 new

**UI**：Process runs list（design §5.14）.
**Query**：`kind=crawl|agent_schedule,subsystem=<>,status=pending|running|completed|failed|skipped,since=<iso>`
**Response envelope with aggregate summary**：
```json
{
  "summary": {
    "success_rate_24h": { "value": 98.2, "state": "ok" },
    "avg_latency_seconds": 3.4,
    "in_retry": { "value": 2, "state": "warn" },
    "failed_last_hour": { "value": 1, "state": "error" }
  },
  "stages": [
    { "name": "crawl",    "status": "running", "pct_ok": 100,
      "rows": [["feeds polled", 14, null], ["items harvested", 274, null], ["rate-limited", 1, "error"]] },
    { "name": "classify", "status": "running", "pct_ok": 100, "rows": [ /* ... */ ] },
    { "name": "draft",    "status": "running", "pct_ok":  82, "rows": [ /* ... */ ] },
    { "name": "grade",    "status": "running", "pct_ok":  75, "rows": [ /* ... */ ] }
  ],
  "runs": [
    { "id": "r_4a1a", "when": "11:58", "kind": "crawl", "subsystem": null,
      "source": "hn-newest-api", "items": null, "duration": null,
      "status": "failed", "error": "429 Too Many Requests · retry-after 600s" }
  ],
  "total": 412
}
```

> 注意：stages 的 `name` 是 scheduler 活動 label（**不是** `process_runs.kind`）. backend 應在此 endpoint 內 compute aggregate；前端不推導.

### 5.4 Activity (cross-domain audit log)

#### `GET /api/admin/coordination/activity`  ✓ existing (rename)

既有 `GET /api/admin/activity/changelog`.
**UI**：Activity List（design §5.15）.
**Query**：
```
entity_type=todo|goal|milestone|project|content|bookmark|note|learning_attempt|task|learning_hypothesis|learning_plan_entry|learning_session
change_kind=created|updated|state_changed|published|completed|archived
since=<iso>,until=<iso>
```
**Response envelope** (group by day):
```json
{
  "days": [
    {
      "date": "2026-04-23",
      "event_count": 37,
      "events": [
        {
          "id": "...",
          "timestamp": "2026-04-23T14:23:00Z",
          "entity_type": "content",
          "entity_id": "...",
          "change_kind": "created",
          "title": "Draft Q2 review",
          "project": "koopa-admin",
          "actor": "claude-cowork"
        }
      ]
    }
  ]
}
```

#### 🔧 Phase 2 widen：`ChangelogEvent.actor`

目前 wire type 缺 `actor`（contract §8.1）. 加上後啟用前端 by-agent filter（query param `actor=<name>` 或 `actor=<name1>,<name2>`）.

#### `GET /api/admin/coordination/activity/sessions`  ✓ existing (rename)

既有 `GET /api/admin/activity/sessions`. GitHub push events 分組視圖.

---

## 6. Cross-cutting

### 6.1 `GET /api/admin/system/health`  🔧 extend

**Purpose**：nav count + Today warnings + 4-domain overview.
**UI**：Shell nav（all pages）、Today warnings section.
**Response envelope**：
```json
{
  "commitment": {
    "todos_open":       { "count": 23, "state": "ok" },
    "goals_active":     { "count":  6, "state": "warn", "reason": "1 stale >14d" },
    "today_plan_done":  { "count":  4, "total": 8, "state": "ok" }
  },
  "knowledge": {
    "contents_total":   { "count": 22 },
    "review_queue":     { "count":  3, "state": "warn", "reason": "oldest 5d" },
    "notes_total":      { "count": 84 },
    "bookmarks_total":  { "count": 37 },
    "feeds_active":     { "count": 14, "state": "error", "reason": "1 failing" }
  },
  "learning": {
    "concepts_total":   { "count": 48 },
    "weak_concepts":    { "count":  3, "state": "warn" },
    "due_reviews":      { "count": 12 },
    "hypotheses_unverified": { "count": 4 }
  },
  "coordination": {
    "tasks_awaiting_human":    { "count": 2, "state": "warn", "reason": "1 revision_requested" },
    "process_runs_24h_success_pct": { "value": 98.2, "state": "ok" },
    "agents_active":           { "count": 4 }
  }
}
```

**Note**：backend 目前 `/api/admin/system/health` shape 可能是舊 SystemHealth；此 spec 要求擴充到完整 4-domain envelope.

### 6.2 `GET /api/admin/system/stats*`  ✓ existing (keep)

既有 `/api/admin/stats` / `/stats/drift` / `/stats/learning`. Phase 3 再決定合併.

### 6.3 `GET /api/admin/search`  🔨 new

**Purpose**：全域 ⌘K search. Phase 2 lexical；Phase 3 semantic（wraps `search_knowledge` MCP）.
**UI**：Topbar ⌘K launcher.
**Query**：`q=<query>,types=content,note,bookmark,hypothesis,concept,task,goal,todo,project,limit=20,mode=lexical|semantic`
**Response**：
```json
{
  "results": [
    { "type": "content", "id": "...", "title": "...", "excerpt": "...", "score": 0.92 }
  ]
}
```

### 6.4 `POST /api/admin/upload`  ✓ existing

既有. cover image / note attachments. multipart form.

---

## 7. Auth

既有 Google OAuth flow：
- `GET /api/auth/google`
- `GET /api/auth/google/callback`
- `POST /api/auth/refresh`

Token in-memory signal + HttpOnly refresh cookie（security.md）. 無 `/logout` endpoint（clear memory + revoke refresh 在 frontend 處理）.

---

## 8. Phase 分層

### Phase 1（shell + list + content editor + todos + tasks basics）

| Endpoint | Status |
|---|---|
| `GET /commitment/today` | 🔨 |
| `GET /commitment/todos` | 🔨 |
| `POST /commitment/todos` | 🔨 |
| `POST /commitment/todos/:id/advance` | 🔨 |
| `PUT /commitment/todos/:id` | 🔨 |
| `DELETE /commitment/todos/:id` | 🔨 |
| `GET/POST/PUT/DELETE /knowledge/content` + `:id` | ✓ rename |
| `POST /knowledge/content/:id/submit-for-review` | 🔨 |
| `POST /knowledge/content/:id/revert-to-draft` | 🔨 |
| `POST /knowledge/content/:id/publish` | ✓ (human-gated) |
| `POST /knowledge/content/:id/archive` | 🔨 |
| `PATCH /knowledge/content/:id/is-public` | ✓ rename |
| `DELETE /knowledge/content/:id` | ✓ rename |
| `GET /knowledge/bookmarks` + CRUD | ✓ rename |
| `PUT /knowledge/bookmarks/:id` | 🔨 |
| `GET/POST/PUT/DELETE /knowledge/feeds[/:id]` | ✓ rename |
| `POST /knowledge/feeds/:id/fetch` | ✓ rename |
| `GET /knowledge/feed-entries` | ✓ rename |
| `POST /knowledge/feed-entries/:id/curate\|ignore\|feedback` | ✓ rename |
| `GET /commitment/goals` + `:id` + `:id/status` | ✓ rename |
| `GET /commitment/projects*` | ✓ rename |
| `GET /coordination/tasks*` + `messages` + `artifacts` | ✓ rename |
| `POST /coordination/tasks/:id/reply\|request-revision` | ✓ rename |
| `POST /coordination/tasks` | 🔨 |
| `POST /coordination/tasks/:id/approve\|cancel` | 🔨 |
| `GET /coordination/agents` + `:name` + `:name/tasks` | ✓ rename |
| `GET /coordination/activity` | ✓ rename |
| `GET /knowledge/topics*` | ✓ rename |
| `GET /system/health` (4-domain envelope) | 🔧 extend |
| Upload / Auth | ✓ existing |

### Phase 2（learning depth + hypothesis lineage + agent notes + ⌘K lexical）

| Endpoint | Status |
|---|---|
| `GET /learning/dashboard` | 🔨 |
| `GET /learning/concepts` + `:slug` | 🔨 |
| `GET /learning/sessions` + `:id` | 🔨 |
| `POST /learning/sessions` + `:id/end` + `:id/attempts` | 🔨 |
| `GET /learning/plans` + `:id` | 🔨 |
| `POST /learning/plans/:id/entries` + `PUT :entry_id` | 🔨 |
| `GET /learning/hypotheses*` | ✓ rename |
| `GET /learning/hypotheses/:id/lineage` | 🔨 |
| `POST /learning/hypotheses/:id/{verify,invalidate,archive,evidence}` | ✓ rename |
| `POST /learning/reviews/:card_id` | 🔨 |
| `GET /coordination/agents/:name/notes` | 🔨 |
| `GET /search?mode=lexical` | 🔨 |

### Phase 3（notes + process runs + activity widen + semantic search）

| Endpoint | Status |
|---|---|
| `GET /knowledge/notes` + `:id` | 🔨 |
| `POST/PUT/DELETE /knowledge/notes` | 🔨 |
| `POST /knowledge/notes/:id/maturity` | 🔨 |
| `GET /coordination/process-runs` | 🔨 |
| `ChangelogEvent.actor` widen + activity `actor` filter | 🔧 |
| `GET /search?mode=semantic` | 🔨 (wraps search_knowledge) |

---

## 9. 明確**不需要**的 API

v1 api-spec 曾列過、v2 移除：

| 不需要 | 原因 |
|---|---|
| `POST /api/admin/contents/:id/reject` | 被 `/revert-to-draft` 取代；frontend `ContentService.reject()` 要改 URL 或刪方法 |
| `POST /api/admin/feed-entries/:id/curate` 帶 `target=bookmark` | schema 已移除此路徑；curate 只接受 `content_id` |
| 任何 `bookmark_rss` action | MCP 已移除 |
| Commitment proposal 兩階段 REST（`POST /proposals` + `:token/commit`）| 走 Cowork chat，admin 不做（使用者決策）|
| `morning_context` / `reflection_context` / `session_delta` / `weekly_summary` REST wrap | Today endpoint §2.1 已 aggregate 需要的資料；其他 MCP 僅 Cowork 用 |
| `process_runs` 新 kind | 固定 `crawl \| agent_schedule`，新增需 schema CHECK 改 |
| `tasks.kind` 或 `directive_id` 欄位 | directive 是 naming convention，不是 entity |
| Concept mastery edit endpoint | derived，不可寫 |
| FSRS due 覆寫 endpoint | denormalized；只能靠 review 推進 |
| `daily_plan_items` auto-carryover API | 設計上不自動 carry；使用者手動 re-plan |
| Goal auto-status derivation API | 手動 status |
| Cross-domain `learning_hypotheses` | LEARNING-only（contract §7 item 8）|
| `review_level` 欄位 | schema 無，frontend 待清理 |
| `contents.maturity` / `contents.note_kind` | 屬於 notes 表 |
| Bookmark draft/review lifecycle | 建立即發佈 |
| Areas CRUD | human-only 管理，不走 admin UI（contract §3）|
| Agents registry CRUD | system-managed，不走 admin UI |

---

## 10. 給後端的筆記

1. **路徑命名 — 直接切換，不留 alias**：所有 admin REST endpoint 使用 `/api/admin/<domain>/<entity>` 形式（Commitment / Knowledge / Learning / Coordination）. 現有 `/api/admin/contents`、`/api/admin/goals`、`/api/admin/tasks`、`/api/admin/agents`、`/api/admin/hypotheses`、`/api/admin/concepts`、`/api/admin/bookmarks`、`/api/admin/feeds`、`/api/admin/feed-entries`、`/api/admin/projects`、`/api/admin/daily-plan`、`/api/admin/activity/changelog` 一律改為 domain-prefixed 新路徑，**不保留 alias**. 前端 service 在後端 ship 新路徑時同步替換 URL，一個 PR 原子完成. 理由：solo dev 單一消費者、沒有外部 client、尚未上線；alias 會變成永久雙路徑維護成本.
2. **Actor propagation**：`ChangelogEvent` 目前不含 `actor`（contract §8.1）. Phase 2 widen 解鎖 Activity by-agent filter + Agent Profile activity tab.
3. **Human gate**：`publish_content` REST 必須驗證 caller agent 的 `platform='human'`；non-human 回 403.
4. **MCP 與 REST 解耦（決定：(b) duplicated + decoupled）**：REST handler 直接打 store，不走 MCP 管線；MCP tool 走自己的 MCP 管線. 兩條路徑各自實作 handler，但為了不讓兩邊的 audit 資料 / 狀態機判定 drift，下面兩個 invariant 必須由共用 helper 實作（不是共用整個 service/handler）：
   - **`activity_events` 一律經 `changelog.Record(ctx, EventSpec)` helper 寫入**：REST 和 MCP 都呼叫同一個函式，保證 `actor` / `entity_type` / `event_type` / `payload` 形狀一致. Activity 頁 + Agent Profile activity tab 依賴這個不變量.
   - **狀態機合法轉移由 `<feature>/transitions.go` 定義，single source**：`Legal(from, action) bool` 和 `Apply(from, action) (to, error)` 由 REST handler 和 MCP tool 共同查詢. 包含 Todo / Content / Hypothesis / Goal / Task 五組 transition. 非法轉移一律 400（REST）/ Invalid Argument（MCP）.

   除上述兩個 invariant 外，handler 邏輯可以自由 duplicate，不強制共用 service 層.
5. **Aggregate endpoints**：Today (§2.1)、System health (§6.1)、Process runs (§5.3) 三個 aggregate 有多個 join. backend 可根據效能決定是否快取（前端不做）.
6. **Empty state**：list endpoint 在無資料時回 `{"data": [], "total": 0}`，不要 404.
7. **Filter validation**：enum 值錯誤回 400 with clear error code，不要 silent ignore.
8. **Status transitions are explicit**：不允許 `PUT` 改 status；必須走專屬 transition endpoint（publish / archive / submit-for-review / revert-to-draft / advance / verify / invalidate / ...）. 每次 transition 都是一個 audit event（經 §10.4 的 `changelog.Record`）.
9. **Pagination envelope 一律 `{data, total, page, per_page}`**（§1.2）：所有 list endpoint 包含 todos / content / bookmarks / notes / feeds / feed-entries / tasks / agents / hypotheses / concepts / plans / sessions / activity / search. 不允許回傳 raw array.

---

## 11. 版本歷史

- **v2.1 (2026-04-24)**：鎖 rename 策略為「直接切換，不留 alias」（§10.1）；鎖 MCP 與 REST 解耦策略為 (b) + 兩個共用 invariant（`changelog.Record` helper + `transitions.go` 狀態機）（§10.4）；補上 §2.7 todo detail、§2.12 daily-plan、§4.21 learning summary 三個原本前端在呼叫但 spec 未文件化的 endpoint.
- **v2 (2026-04-23)**：按 4-domain 重組；退場 v1 的 mode-based 章節（NOW/ATLAS/REWIND/STREAM/STUDIO）；明確列出不需要的 endpoint.
- v1：前一版本已歸檔（git history）.
