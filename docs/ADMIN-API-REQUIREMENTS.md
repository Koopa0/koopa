# Admin Frontend — Semantic API 需求文件

> **架構變更（2026-04-09）**：Admin frontend 已重新定義為**唯讀觀測介面**。
> 所有實質操作（capture、plan、advance task、start session、record attempt、write journal、propose goal、issue directive 等）由 **Claude Cowork / Claude Code 透過 MCP 完成**。
> Admin 的角色是**呈現系統狀態**讓使用者掃視、診斷、做不可委派的判斷（content publish 決定）。
>
> 這份文件記錄哪些 API：
> - ✅ **保留** — read endpoint，admin frontend 在用
> - ❌ **移除** — write endpoint，admin 不再需要（Claude/MCP 端的 MCP tool 已經有對應的寫入路徑）
> - ➕ **新增/修改** — 為了支撐新 admin 的觀測需求
> - 🟡 **保留但非 admin 用** — backend 仍可保留供 MCP 或其他 client 使用，但不歸 admin frontend 需求

---

## 設計原則（已調整）

1. **Read-only by default** — Admin frontend 預設只讀。任何 write endpoint 都需要明確的「為什麼必須在 admin UI 做」理由。
2. **Aggregate views** — 一個畫面對應一個 endpoint，backend 負責聚合。
3. **Workflow-aware naming** — 命名反映使用者觀測意圖（getOverview、getWeaknessMap、getDirectiveBoard），不是 CRUD（list / get / update）。
4. **Backend 計算衍生欄位** — `health`、`days_remaining`、`mastery_level`、`severity_score` 都由 backend 算好，前端不二次計算。
5. **單一寫入例外** — 整個 admin 只有 **content review/publish** 是允許的 write，因為這是人類本人必須親自判斷的事。

---

## ❌ Section A — 應該移除的 Endpoints

這些 endpoint 在 admin frontend 不再有對應 UI 觸發。建議：
- **方案 1（推薦）**：從 admin 路由樹中移除，避免未來誤用
- **方案 2**：標註 `// admin-deprecated`，但保留 handler 以利測試或其他 client

> 注意：這些操作的「語意對等物」**仍存在於 MCP tool 層**（例如 `capture_inbox`、`plan_day`、`advance_work`、`propose_commitment`、`commit_proposal`、`record_attempt`、`write_journal` 等）。移除 admin endpoint 不會破壞 Claude / Cowork 的功能。

### A.1 Today / Daily Plan Operations

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `POST` | `/api/admin/today/plan` | 規劃今日在 Claude 對話中完成（MCP `plan_day`） |
| `POST` | `/api/admin/today/items/{id}/resolve` | Plan item 推進在 Claude 完成（MCP `advance_work`） |

### A.2 Inbox

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `GET`  | `/api/admin/inbox` | 沒有獨立的 Inbox 頁面。Inbox count 已在 `GET /api/admin/today` 的 `needs_attention.inbox_count` 提供 |
| `POST` | `/api/admin/inbox/capture` | 捕獲在 Claude 完成（MCP `capture_inbox`） |
| `POST` | `/api/admin/inbox/{id}/clarify` | Clarify 在 Claude 完成（MCP `advance_work` action=clarify 或 polymorphic routing） |

### A.3 Goals — Write 操作

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `POST` | `/api/admin/plan/goals/propose` | Goal 提案在 Claude（MCP `propose_commitment` type=goal） |
| `POST` | `/api/admin/plan/goals/propose/{proposal_id}/commit` | Goal commit 在 Claude（MCP `commit_proposal`） |
| `POST` | `/api/admin/plan/goals/{id}/milestones` | Milestone 建立在 Claude |
| `POST` | `/api/admin/plan/goals/{id}/milestones/{ms_id}/toggle` | Milestone 完成切換在 Claude |

### A.4 Tasks

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `GET`  | `/api/admin/plan/tasks` | 沒有獨立的 Tasks Backlog 頁面。任務在 project detail 中顯示，由 `GET /api/admin/plan/projects/{id}` 提供 |
| `POST` | `/api/admin/plan/tasks/{id}/advance` | Task 推進在 Claude（MCP `advance_work`） |

### A.5 Learning — Session & Attempt 操作

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `POST` | `/api/admin/learn/sessions/start` | Session 開始在 Claude（MCP `start_session`） |
| `POST` | `/api/admin/learn/sessions/{id}/attempt` | Attempt 記錄在 Claude（MCP `record_attempt`） |
| `POST` | `/api/admin/learn/sessions/{id}/end` | Session 結束在 Claude（MCP `end_session`） |

### A.6 Learning Plans — Write 操作

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `POST`   | `/api/admin/learn/plans/{id}/items` | Plan item 新增在 Claude（MCP `manage_plan` action=add_items） |
| `DELETE` | `/api/admin/learn/plans/{id}/items/{item_id}` | Plan item 移除在 Claude |
| `POST`   | `/api/admin/learn/plans/{id}/items/{item_id}/update` | Plan item 狀態變更在 Claude |
| `POST`   | `/api/admin/learn/plans/{id}/reorder` | Plan item 重排在 Claude |
| `PATCH`  | `/api/admin/learn/plans/{id}` | Plan 狀態變更在 Claude |

### A.7 Reflect — Journal Write

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `POST` | `/api/admin/reflect/journal` | Journal 寫入在 Claude（MCP `write_journal`） |

### A.8 Studio — Directive Write

| Method | Endpoint | 移除理由 |
|--------|----------|---------|
| `POST` | `/api/admin/studio/directives/propose` | Directive 提案在 Claude（MCP `propose_commitment` type=directive） |

> 註：原本沒有 `commit` / `acknowledge` / `resolve` 的 admin endpoint，這些都在 MCP（`commit_proposal`, `acknowledge_directive`, `file_report`），不需要新增。

---

## ✅ Section B — 保留的 Read Endpoints

這些 endpoint admin frontend 在用，必須保留並按下方標註修改 response shape。

### B.1 Overview Page → `GET /api/admin/today`

> 前端已將「Today」頁面更名為「Overview」，但 endpoint path 暫不需要重新命名（為了避免破壞現有實作）。
> 如果之後要重命名，建議改為 `GET /api/admin/overview`。

**用途**：渲染 Overview 畫面。一次取得當天觀測所需的全部 context。

**Response**（修改後）：
```json
{
  "date": "2026-04-08",
  "context_line": "距離 GDE 申請還有 47 天。本週 focus: NATS integration。",
  "yesterday_unfinished": [
    {
      "id": "dpi_uuid",
      "task_id": "task_uuid",
      "title": "Review NATS JetStream docs",
      "area": "backend",
      "energy": "high",
      "status": "planned",
      "planned_date": "2026-04-07"
    }
  ],
  "today_plan": [
    {
      "id": "dpi_uuid",
      "task_id": "task_uuid",
      "title": "Design admin IA",
      "area": "studio",
      "energy": "high",
      "estimated_minutes": 60,
      "position": 1,
      "status": "planned"
    }
  ],
  "overdue_tasks": [
    {
      "id": "task_uuid",
      "title": "Write TIL about iteration",
      "due": "2026-04-06",
      "area": "learning",
      "priority": "medium"
    }
  ],
  "needs_attention": {
    "inbox_count": 4,
    "pending_directives": 1,
    "unread_reports": 1,
    "due_reviews": 3,
    "overdue_tasks": 1,
    "stale_someday_count": 5
  },
  "reflection_context": {
    "has_yesterday_reflection": true,
    "reflection_excerpt": "決定把重心放在 admin redesign..."
  },
  "goal_pulse": [
    {
      "id": "goal_uuid",
      "title": "GDE Application",
      "area": "career",
      "deadline": "2026-05-25",
      "days_remaining": 47,
      "milestones_total": 4,
      "milestones_done": 2,
      "next_milestone": "Submit application form",
      "status": "in-progress"
    }
  ]
}
```

**狀態**：✅ 保留，shape 不變。

---

### B.2 `GET /api/admin/dashboard/trends`

**用途**：Overview 畫面的趨勢區塊。週對週的 metrics。

**Response**：見原文件 §8 — shape 不變，✅ 保留。

---

### B.3 Goals — Read

#### `GET /api/admin/plan/goals`
✅ 保留。原 shape 不變。前端 `commitments/goals` 頁使用。

#### `GET /api/admin/plan/goals/{id}`
✅ 保留，但 **建議擴充 `recent_activity[].type`**（見 §C.4）。

---

### B.4 Projects — Read

#### `GET /api/admin/plan/projects`
✅ 保留。原 shape 不變。

#### `GET /api/admin/plan/projects/{id}`
✅ 保留。原 shape 不變。

---

### B.5 Library — Pipeline

#### `GET /api/admin/library/pipeline`
✅ 保留。原 shape 不變。

> 建議路徑搬遷到 `/api/admin/content/pipeline` 以對齊新的 admin 路由 `/admin/content/pipeline`，但**不阻塞**——前端 service 層已經 hardcode `/api/admin/library/pipeline`，可在 Phase 4 統一改名。

---

### B.6 Learn — Read

#### `GET /api/admin/learn/dashboard`
✅ 保留，但 **建議擴充 `weakness_spotlight[].severity_summary`**（見 §C.5）。

#### `GET /api/admin/learn/concepts/{slug}`
✅ 保留。原 shape 不變。

#### `GET /api/admin/learn/review-queue`
✅ 保留。原 shape 不變。

#### `GET /api/admin/learn/plans`
✅ 保留。原 shape 不變。

#### `GET /api/admin/learn/plans/{id}`
✅ 保留。原 shape 不變。

---

### B.7 Reflect — Read

#### `GET /api/admin/reflect/daily?date=YYYY-MM-DD`
✅ 保留。原 shape 不變。

#### `GET /api/admin/reflect/weekly?week_start=YYYY-MM-DD`
✅ 保留。原 shape 不變。

#### `GET /api/admin/reflect/journal`
✅ 保留，但 **必須補上 `source` 欄位**（見 §C.2）。

#### `GET /api/admin/reflect/insights`
✅ 保留，但 **必須補上 `invalidation_condition` 欄位**（見 §C.1）。

---

### B.8 Studio (Directives) — Read

#### `GET /api/admin/studio/overview`
✅ 保留，但 **建議擴充：**
- 加入 `?include_resolved=true` query param 支援（見 §C.3）
- `participants[]` 補上 capability flags 詳情（見 §C.6）

---

### B.9 System Health

#### `GET /api/admin/system/health`
✅ 保留。原 shape 不變。

> 注意：原文件未明確記載此 endpoint，但前端 SystemHealthComponent 在用，需要確認 backend 已實作。

---

## ➕ Section C — 需要新增 / 修改的部分

### C.1 [MODIFY] `GET /api/admin/reflect/insights` — 補上 `invalidation_condition`

**問題**：目前 response 只有 `id, hypothesis, status, age_days`。但 insight 的核心結構是 **hypothesis + invalidation_condition** — 沒有 invalidation_condition 就不是「可證偽的假設」，只是普通筆記。前端的 Insights 頁面語意核心被遮蔽。

**修改後 response**：
```json
{
  "insights": [
    {
      "id": "1",
      "hypothesis": "pgvector HNSW 在 100K 以上效能下降",
      "invalidation_condition": "benchmark 100K rows HNSW vs IVFFlat，如果 HNSW 仍然 <10ms 則推翻",
      "status": "unverified",
      "source": "human",
      "observed_date": "2026-03-25",
      "age_days": 14,
      "evidence_count": 2
    }
  ]
}
```

**Backend 邏輯**：
- `invalidation_condition`：直接從 `insights.invalidation_condition` 欄位取（schema 已有此欄位）
- `source`：直接從 `insights.source` 取
- `observed_date`：從 `insights.observed_date` 取
- `evidence_count`：`COALESCE(jsonb_array_length(metadata->'evidence'), 0)`

**Migration 影響**：無，schema 已有 `invalidation_condition` 欄位（`internal/insight/insight.go` 已定義）。只需要 handler 把欄位塞進 response。

---

### C.2 [MODIFY] `GET /api/admin/reflect/journal` — 補上 `source` 和 `id`

**問題**：目前 response 只有 `kind, body, date`。但 Journal 是 multi-participant 系統 — 不同 participant（human、claude-code、cowork、content-studio）寫的 journal 應該標明來源，否則使用者看不出哪些是自己寫的、哪些是 AI agent 自動產生的。

**修改後 response**：
```json
{
  "entries": [
    {
      "id": 123,
      "kind": "reflection",
      "body": "今天的 admin redesign 討論收穫很大...",
      "source": "human",
      "entry_date": "2026-04-08",
      "created_at": "2026-04-08T22:30:00+08:00"
    }
  ]
}
```

**Backend 邏輯**：所有欄位 schema 都已存在（`internal/journal/journal.go`），只需要 handler 把欄位帶出來。

---

### C.3 [MODIFY] `GET /api/admin/studio/overview` — 加 `?include_resolved` 查詢

**問題**：目前 response 只回 `open_directives`（unresolved）。前端的 Directive Board 頁面需要 **CEO 視角的歷史追蹤**：「我發出去的 directive 哪些已經完成、報告品質如何」。沒有歷史視圖，使用者無法做組織回顧。

**修改**：加入 query parameter。

```
GET /api/admin/studio/overview?include_resolved=true&limit=20
```

**修改後 response**（當 `include_resolved=true`）：
```json
{
  "open_directives": [...],          // 同原本
  "resolved_directives": [             // 新增
    {
      "id": 42,
      "content": "研究 NATS exactly-once",
      "source": "hq",
      "target": "research-lab",
      "priority": "p1",
      "lifecycle_status": "resolved",
      "issued_date": "2026-03-25",
      "acknowledged_at": "2026-03-25T10:00:00+08:00",
      "resolved_at": "2026-04-02T16:30:00+08:00",
      "resolution_report_id": 87,
      "days_to_resolution": 8
    }
  ],
  "unread_reports": [...],
  "participants": [...]
}
```

**Backend 邏輯**：
- 預設行為（不傳 query param）：只回 open（保持 backward compatible）
- `include_resolved=true`：額外回 `resolved_directives`，按 `resolved_at DESC` 排序，預設 `limit=20`

---

### C.4 [MODIFY] `GET /api/admin/plan/goals/{id}` — `recent_activity[].type` 改為 typed enum

**問題**：目前 `recent_activity[].type` 是 generic string。前端無法根據 type 給不同 icon / 顏色，只能展示成 grey badge。語意表達被壓平。

**修改後 type 列舉**（前後端共識）：
```typescript
type GoalActivityType =
  | 'task_completed'
  | 'milestone_completed'
  | 'project_status_changed'
  | 'content_published'    // related content (e.g., build-log) published
  | 'attempt_solved'       // learning attempt linked to this goal
  | 'directive_resolved';  // directive linked to this goal resolved
```

**修改後 response 範例**：
```json
{
  "recent_activity": [
    {
      "type": "milestone_completed",
      "title": "Set up pgvector extension",
      "ref_id": "ms_uuid",
      "timestamp": "2026-04-07T16:30:00+08:00"
    },
    {
      "type": "content_published",
      "title": "pgvector indexing guide",
      "ref_id": "content_uuid",
      "ref_slug": "pgvector-indexing-guide",
      "timestamp": "2026-04-06T20:00:00+08:00"
    }
  ]
}
```

**Backend 邏輯**：
- UNION 查詢多個 source：tasks (completed_at), milestones (completed_at), projects (status_changed_at if tracked), contents (published_at), attempts (joined to goal via project), directives (resolved_at)
- 按 timestamp DESC，limit 10

---

### C.5 [MODIFY] `GET /api/admin/learn/dashboard` — `weakness_spotlight` 補上 severity 聚合

**問題**：目前 `weakness_spotlight[]` 只有 `fail_count_30d`。但 schema 已經有 `attempt_observations.severity`（minor / moderate / critical），這個資訊是診斷弱點的關鍵——「3 次 critical 弱點」遠比「10 次 minor 弱點」嚴重。

**修改後 response 範例**：
```json
{
  "weakness_spotlight": [
    {
      "concept_slug": "channel-direction",
      "concept_name": "Channel Direction",
      "domain": "go",
      "fail_count_30d": 5,
      "severity_summary": {
        "critical": 1,
        "moderate": 3,
        "minor": 1
      },
      "severity_score": 8,
      "last_practiced": "2026-03-25",
      "days_since_practice": 14
    }
  ]
}
```

**Backend 邏輯**：
- `severity_summary`：`COUNT GROUP BY severity` 限制在最近 30 天 + 該 concept 的 weakness 觀察
- `severity_score`：`critical*5 + moderate*2 + minor*1`（讓前端可以單一數值排序）

---

### C.6 [MODIFY] `GET /api/admin/studio/overview` — `participants[]` 補 capability 細節

**問題**：目前 `participants[]` 只有 `name`、`active_directives`、`recent_reports`、`capabilities` array。前端 Directive Board 想顯示「這個 participant 能不能 issue / receive / write reports / 接 task」的 chip，但 generic string array 沒辦法明確區分。

**修改後 response 範例**：
```json
{
  "participants": [
    {
      "name": "research-lab",
      "platform": "claude-code",
      "active_directives": 2,
      "recent_reports": 1,
      "can_issue_directives": false,
      "can_receive_directives": true,
      "can_write_reports": true,
      "task_assignable": false,
      "has_schedule": true
    }
  ]
}
```

**Backend 邏輯**：直接 SELECT participants 表的 capability flag 欄位即可，schema 已存在。

---

### C.7 [ADD] Content Review — 新的 write endpoints（**唯一允許的 admin write**）

> 整個 admin 唯一保留的 write 路徑：content review。
> 因為「要不要把這篇東西公開發布」是 Koopa 本人必須親自做的判斷，無法委派給 Claude / AI。

#### 既有 endpoints — 確認用途

backend 目前有：
- `POST /api/admin/contents/{id}/publish` ✅ 用於 approve（status → published）
- `PATCH /api/admin/contents/{id}/is-public` ✅ 用於控制公開可見性

#### 缺的 endpoint — 需新增

**`POST /api/admin/contents/{id}/reject`**

**用途**：退回 draft 狀態，附帶 reviewer notes（給寫作者後續修改參考）。

**Request**：
```json
{
  "reviewer_notes": "結論段落需要更具體的數據支撐"
}
```

**Response**：更新後的 content（status=draft）。

**Backend 邏輯**：
- `UPDATE contents SET status='draft', updated_at=now() WHERE id=$1`
- 將 `reviewer_notes` 寫入 `contents.metadata->'review_notes'` JSONB（或新建欄位 `review_notes TEXT`，建議前者以避免 schema 變更）
- 同時 INSERT 一筆 `review_queue` 紀錄（若該表存在），記錄 reviewer + reason + timestamp，供之後 audit

#### 還需要的 read endpoint

**`GET /api/admin/contents/{id}`**

> 已存在於 backend (`h.content.AdminGet`)，✅ 保留。前端 ContentReviewWorkspace 用此取得單一 content 完整內容（含 body）。

---

### C.8 [REMOVE-OR-INTERNAL] 不歸 admin 的 endpoints

以下 endpoints 在 `cmd/app/routes.go` 還註冊著，但 admin frontend 完全不使用。建議**移到非 admin 路由** 或 **加註 `// internal-use`**：

| 路由 | 現況 | 建議 |
|------|------|------|
| `POST /api/admin/contents` (create) | CRUD 編輯器用 | 移到非 admin，或標 `// editor-only` — Obsidian sync 走別的路徑，不需要 admin 開放 |
| `PUT /api/admin/contents/{id}` (update) | 編輯器用 | 同上 |
| `DELETE /api/admin/contents/{id}` | 編輯器用 | 同上，admin 不刪內容 |
| `POST /api/admin/projects` / `PUT` / `DELETE` | Project editor 用 | 移到非 admin 或標 `// internal-use` |
| `PUT /api/admin/goals/{id}/status` | 舊 goal CRUD | 移除（操作走 MCP） |
| `POST /api/admin/topics` / `PUT` / `DELETE` | Topic CRUD | 移除或標 `// admin-internal` |
| `POST /api/admin/tags` / `PUT` / `DELETE` / `merge` / `backfill` | Tag CRUD | 移除或標 `// admin-internal` |
| `POST /api/admin/aliases/*` | Tag alias 管理 | 移除或標 `// admin-internal` |
| `POST /api/admin/feeds` / `PUT` / `DELETE` / `fetch` | Feed CRUD | 移除（操作走 MCP `manage_feeds`），保留 `GET /api/admin/feeds`（intelligence 頁面 read 用） |
| `POST /api/admin/collected/*` | Collected items 操作 | 移除（操作走 MCP `manage_content` action=bookmark_rss） |
| `GET /api/admin/notes` / `decisions` | Notes search | 評估，可能移到 search service |
| `GET /api/admin/activity/sessions` / `changelog` | Activity log | 評估是否融入 system health |
| `GET /api/admin/stats` / `drift` / `learning` | Old stats | 評估，與 dashboard/trends 重疊則移除 |
| `POST /api/admin/upload` | 編輯器附檔上傳 | 移除（admin 沒有編輯器） |
| `GET /api/admin/review` + `/approve` / `/reject` / `/edit` | 舊 review queue | **改用 §C.7 的新 endpoints**，或保留並讓 `POST /api/admin/contents/{id}/reject` 作為 alias |

---

## Section D — Frontend 對應頁面與 endpoint 清單

| 頁面 | Endpoints 用到 |
|------|---------------|
| `/admin/overview` | `GET /api/admin/today` + `GET /api/admin/dashboard/trends` |
| `/admin/learn/weaknesses` | `GET /api/admin/learn/dashboard` |
| `/admin/learn/concepts/:slug` | `GET /api/admin/learn/concepts/:slug` |
| `/admin/learn/sessions` | `GET /api/admin/learn/dashboard`（recent_sessions）— 未來可能單獨做 `GET /api/admin/learn/sessions` |
| `/admin/learn/plans` | `GET /api/admin/learn/plans` |
| `/admin/learn/plans/:id` | `GET /api/admin/learn/plans/:id` |
| `/admin/content/pipeline` | `GET /api/admin/library/pipeline` |
| `/admin/content/review/:id` | `GET /api/admin/contents/:id` + `POST /api/admin/contents/:id/publish` + `POST /api/admin/contents/:id/reject`（新） + `PATCH /api/admin/contents/:id/is-public` |
| `/admin/content/library` | `GET /api/admin/contents`（list） |
| `/admin/content/intelligence` | `GET /api/admin/feeds`（list） |
| `/admin/commitments/goals` | `GET /api/admin/plan/goals` |
| `/admin/commitments/goals/:id` | `GET /api/admin/plan/goals/:id` |
| `/admin/commitments/projects` | `GET /api/admin/plan/projects` |
| `/admin/commitments/projects/:id` | `GET /api/admin/plan/projects/:id` |
| `/admin/commitments/directives` | `GET /api/admin/studio/overview`（含 `?include_resolved=true` 選用） |
| `/admin/activity/daily` | `GET /api/admin/reflect/daily?date=` |
| `/admin/activity/weekly` | `GET /api/admin/reflect/weekly?week_start=` |
| `/admin/activity/insights` | `GET /api/admin/reflect/insights` |
| `/admin/activity/journal` | `GET /api/admin/reflect/journal` |
| `/admin/system` | `GET /api/admin/system/health` |

---

## Section E — 實作優先級

### P0 — 立刻做（解語意 bug）

這些是 admin frontend 已經部署但 response shape 缺欄位導致語意呈現不完整的：

1. **§C.1** — `GET /api/admin/reflect/insights` 補上 `invalidation_condition`、`source`、`observed_date`、`evidence_count`
2. **§C.2** — `GET /api/admin/reflect/journal` 補上 `id`、`source`、`entry_date`、`created_at`

> 這兩項 schema 都已支援，只是 handler 沒帶出來。改動量極小（每個約 5 行 Go），但語意修復顯著。

### P1 — 短期（前端已有 placeholder，等後端就能上）

3. **§C.3** — `GET /api/admin/studio/overview` 支援 `?include_resolved=true` 並回 `resolved_directives`
4. **§C.5** — `GET /api/admin/learn/dashboard` 補上 `weakness_spotlight[].severity_summary` 和 `severity_score`
5. **§C.6** — `GET /api/admin/studio/overview` 的 `participants[]` 補上 capability flag 細節
6. **§C.7** — 新增 `POST /api/admin/contents/{id}/reject`

### P2 — 中期（語意提升，但不阻塞）

7. **§C.4** — `GET /api/admin/plan/goals/{id}` 的 `recent_activity[].type` 改為 typed enum + 加上 `ref_id`、`ref_slug`

### P3 — 整理階段（清理技術債）

8. **§A** 的所有移除動作 — 可以一次清理或漸進
9. **§C.8** — 把不歸 admin 的 endpoints 移到別的命名空間

---

## Section F — Schema 對齊備註

> 以下記錄 API response 與 `migrations/001_initial.up.sql` 的欄位對應關係。

### 關鍵差異與決策

| API response 欄位 | Schema 欄位 | 說明 |
|---|---|---|
| `task.area` | tasks 表**沒有** area 欄位 | 透過 `tasks.project_id → projects.area_id → areas.name` JOIN 衍生 |
| `task.status` | `task_status` enum 5 值：`inbox, todo, in-progress, done, someday` | 前端 type 包含全部 5 值 |
| `goal.area_name` | `goals.area_id` UUID FK → `areas.name` | 回傳 denormalized `area_id` + `area_name` |
| `milestone.completed` | Schema 用 `completed_at TIMESTAMPTZ`（null = 未完成）| API 回 `completed: boolean` + 原始 `completed_at` |
| `daily_plan_item.title` | Schema 只有 `task_id` FK | API 回 denormalized `title`（JOIN tasks.title）|
| `daily_plan_item.area` | 同上 | API denormalize |
| `directive.title` | Schema 只有 `content TEXT` | 前端直接用 `content` 顯示 |
| `directive` lifecycle | Schema 有 `resolved_at` + `resolution_report_id` | lifecycle_status 從欄位計算（pending / acknowledged / resolved）|
| `insight.invalidation_condition` | Schema 有此欄位（但 admin handler 漏帶出來）| **§C.1 修復** |
| `insight.evidence` | Schema 用 `metadata JSONB` | evidence 存在 `metadata.evidence` 中 |
| `journal.source` | Schema 有此欄位 | **§C.2 修復**：admin handler 補帶出來 |
| `attempt.outcome` | 7 值 enum：`solved_independent, solved_with_hint, solved_after_solution, completed, completed_with_support, incomplete, gave_up` | 前端 type 7 值 |
| `session.mode` | `session_mode` 5 值：`retrieval, practice, mixed, review, reading` | |
| `observation.signal_type` | 3 值：`weakness, improvement, mastery` | 不是 `weakness, strength, misconception` |
| `observation.severity` | `minor, moderate, critical`，僅 weakness 有值 | `chk_severity_weakness_only` 約束 |
| `observation.severity_summary` | derived | **§C.5 新增**：handler 聚合計算 |
| `concept.kind` | 3 值：`pattern, skill, principle` | |
| `participant.has_schedule` | Schema 有此欄位 | **§C.6 補帶出來** |
| `areas` seed | 6 個：backend, learning, studio, frontend, career, ops | 前端 AREA_CLASSES 顏色映射覆蓋這 6 個 |

### Frontend TypeScript model 修正項目

1. `JournalEntry` 加入 `id, source, entry_date, created_at`
2. `InsightCheck` 加入 `invalidation_condition, source, observed_date, evidence_count`
3. `DirectiveSummary` lifecycle 維持 `pending | acknowledged | resolved`
4. `ParticipantSummary` 確認 capability boolean 欄位齊全（已對齊）
5. `ConceptWeakness` 加入 `severity_summary, severity_score`
6. `StudioOverview` 加入 `resolved_directives?: DirectiveSummary[]`
7. `ActivityItem` 的 `type` 改為 typed enum 而非 string
8. 新增 `RejectContentRequest { reviewer_notes: string }` 用於 §C.7
