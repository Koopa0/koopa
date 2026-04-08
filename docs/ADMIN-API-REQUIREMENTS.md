# Admin Frontend — Semantic API 需求文件

> 這份文件定義前端 admin 重新設計所需的後端 API。
> 每個 endpoint 從 **使用者工作流** 反推，不是 CRUD 包裝。
> 前端開發不阻塞——API 未就緒前使用 mock data。

---

## 設計原則

1. **Aggregate views** — 前端不應拼裝 5 個 endpoint 來渲染一個畫面。Backend 負責聚合。
2. **Semantic commands** — `advanceTask(id, "complete")` 而非 `PATCH /tasks/:id { status: "done" }`。
3. **Workflow-aware** — API 反映使用者意圖（clarify, propose, commit），不是資料表操作。
4. **Backend 決定 context** — `context_line`、`health` 等衍生欄位由 backend 計算。

---

## 1. Today — 每日操作面

### GET /api/admin/today

**用途**：渲染 Today 畫面。一次取得今日所需的全部 context。

**為什麼需要**：使用者每天第一個看到的畫面。不能讓前端打 6 個 API 拼起來。

**Response**：
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

> **⚠ Schema 對齊**：daily_plan_items 表沒有 estimated_minutes 欄位。此值需要從 tasks 表或 metadata 取得。建議：(a) 加欄位到 daily_plan_items，或 (b) JOIN tasks 取得估計時間，或 (c) 前端不顯示此欄位。

**Backend 邏輯**：
- `context_line`：根據最近 deadline 的 active goal 生成，或根據本週 journal(kind=plan) 提取 focus
- `yesterday_unfinished`：`daily_plan_items WHERE planned_date = yesterday AND status = 'planned'`
- `today_plan`：`daily_plan_items WHERE planned_date = today`
- `overdue_tasks`：`tasks WHERE due < today AND status NOT IN ('done', 'someday')`
- `needs_attention`：各 domain 的 count 聚合
  - `stale_someday_count`：`tasks WHERE status = 'someday' AND updated_at < now() - interval '30 days'`（GTD 要求定期審查 someday 項目，否則會無聲腐爛）
- `reflection_context`：昨晚是否有 reflection journal？如有，提取摘要。讓使用者規劃今天時有昨日反思的 context
  - `SELECT content FROM journal WHERE source = 'human' AND kind = 'reflection' AND created_at::date = yesterday ORDER BY created_at DESC LIMIT 1`
- `goal_pulse`：`goals WHERE status = 'in-progress'` + milestone count

---

### POST /api/admin/today/plan

**用途**：規劃今日。將 tasks 加入今日計劃。

**為什麼需要**：My Day planning 是一個 batch 操作，不是逐個 API call。

**Request**：
```json
{
  "items": [
    { "task_id": "task_uuid", "position": 1, "estimated_minutes": 30 },
    { "task_id": "task_uuid", "position": 2, "estimated_minutes": 60 }
  ]
}
```

**Response**：更新後的 `today_plan` 陣列。

**Backend 邏輯**：為每個 item 建立 `daily_plan_items` record (planned_date=today, status=planned)。

---

### POST /api/admin/today/items/{id}/resolve

**用途**：處理 daily plan item 的狀態轉換。

**為什麼需要**：前端不該直接 PATCH daily_plan_items 的 status — 這個操作有 side effects（complete 需要同步更新 task.status）。

**Request**：
```json
{ "action": "complete" | "defer" | "drop" }
```

**Backend 邏輯**：
- `complete`：daily_plan_item.status → done，如果 linked task 存在，task.status → done，task.completed_at → now
- `defer`：daily_plan_item.status → deferred。不自動建立明天的 plan item（使用者明天早上自己決定）
- `drop`：daily_plan_item.status → dropped

---

## 2. Inbox — GTD 捕獲與澄清

### GET /api/admin/inbox

**用途**：列出所有未澄清的 inbox items。

**為什麼需要**：Inbox 不只是 task.status=inbox — 它是一個 workflow queue。

**Query params**：`cursor`, `limit` (default 20)

**Response**：
```json
{
  "items": [
    {
      "id": "task_uuid",
      "text": "也許應該研究一下 pgvector indexing 策略",
      "source": "manual",
      "captured_at": "2026-04-08T09:30:00+08:00",
      "age_hours": 2.5
    }
  ],
  "stats": {
    "total": 4,
    "oldest_age_days": 3,
    "by_source": { "manual": 2, "mcp": 1, "rss": 1 }
  }
}
```

**Backend 邏輯**：`tasks WHERE status = 'inbox' ORDER BY created_at DESC`

---

### POST /api/admin/inbox/capture

**用途**：快速捕獲一個想法到 inbox。

**為什麼需要**：最低摩擦的 capture — 只要一段文字。不需要 type / area / priority。

**Request**：
```json
{ "text": "研究 NATS exactly-once delivery" }
```

**Response**：建立的 inbox item（`{ id, text, captured_at }`）

**Backend 邏輯**：`INSERT INTO tasks (title, status, created_by) VALUES ($text, 'inbox', 'human')`

---

### POST /api/admin/inbox/{id}/clarify

**用途**：將 inbox item 澄清為具體 entity。這是 GTD clarify 的 semantic command。

**為什麼需要**：Clarify 不是 `PATCH task.status` — 它可能 transform 成完全不同的 entity（journal, insight, goal direction）。

**Request** — polymorphic by `type`：
```json
// 澄清為 task
{
  "type": "task",
  "area_id": "area_uuid",
  "priority": "medium",
  "energy": "high",
  "due": "2026-04-15"
}

// 澄清為 journal entry
{
  "type": "journal",
  "kind": "reflection",
  "body": "決定不研究這個方向，因為..."
}

// 澄清為 insight proposal
{
  "type": "insight",
  "hypothesis": "pgvector HNSW 在 100K 以上效能會顯著下降",
  "invalidation_condition": "benchmark 100K rows HNSW vs IVFFlat，如果 HNSW 仍然 <10ms 則推翻",
  "initial_evidence": "看到 GitHub issue 討論"
}

// 刪除
{
  "type": "discard"
}
```

**Response**：
```json
{
  "result": "clarified",
  "entity_type": "task",
  "entity_id": "task_uuid"
}
```

**Backend 邏輯**：
- `task`：更新 task.status → todo，設定 area/priority/energy/due
- `journal`：建立 journal record，刪除原 inbox task
- `insight`：建立 insight（status=unverified），刪除原 inbox task
- `discard`：刪除 inbox task

---

## 3. Plan — Goals

### GET /api/admin/plan/goals

**用途**：Goals overview，按 area 分組。

**為什麼需要**：前端需要一次取得所有 goals + milestone 進度 + area grouping。

**Response**：
```json
{
  "by_area": [
    {
      "area_id": "area_uuid",
      "area_name": "Backend",
      "area_slug": "backend",
      "goals": [
        {
          "id": "goal_uuid",
          "title": "Master pgvector indexing",
          "status": "in-progress",
          "deadline": "2026-06-01",
          "days_remaining": 54,
          "milestones_total": 3,
          "milestones_done": 1,
          "next_milestone_title": "Benchmark IVFFlat vs HNSW",
          "projects_count": 1,
          "quarter": "2026-Q2"
        }
      ]
    }
  ]
}
```

**Backend 邏輯**：
- `goals` + `LEFT JOIN milestones` + `LEFT JOIN projects ON projects.goal_id = goals.id`
- ⚠ projects 和 milestones 都直接掛在 goal 下，是 siblings 關係，不是 parent-child
- 按 area 分組
- `days_remaining` = deadline - today（null if no deadline）
- `next_milestone_title` = 第一個未完成的 milestone
- `projects_count` = `COUNT(projects WHERE goal_id = goal.id)`

---

### GET /api/admin/plan/goals/{id}

**用途**：Goal detail — milestones, linked projects, recent activity。

**為什麼需要**：Goal detail 需要跨 entity 的聚合（milestones + projects + tasks + activity）。

**Response**：
```json
{
  "id": "goal_uuid",
  "title": "Master pgvector indexing",
  "description": "...",
  "status": "in-progress",
  "area_id": "area_uuid",
  "area_name": "Backend",
  "deadline": "2026-06-01",
  "quarter": "2026-Q2",
  "created_at": "2026-03-01",
  "health": "on-track",
  "milestones": [
    {
      "id": "ms_uuid",
      "title": "Benchmark IVFFlat vs HNSW",
      "completed": false,
      "completed_at": null,
      "position": 1
    }
  ],
  "projects": [
    {
      "id": "proj_uuid",
      "title": "pgvector PoC",
      "status": "in-progress",
      "task_progress": { "total": 5, "done": 2 }
    }
  ],
  "recent_activity": [
    {
      "type": "task_completed",
      "title": "Set up pgvector extension",
      "timestamp": "2026-04-07T16:30:00+08:00"
    }
  ]
}
```

> **⚠ Schema 對齊**：projects.goal_id 直接指向 goals.id，沒有經過 milestones。
> milestones 和 projects 是 goal 的兩個獨立面向（完成指標 vs 執行載體），不是 parent-child。
```

**Backend 邏輯**：
- `health`：on-track（有 milestone progress 且 deadline 未到）/ at-risk（deadline < 14 天且 progress < 50%）/ stalled（> 14 天沒有任何 related task completion）
- `recent_activity`：related task completions + commits + build logs，最近 10 筆

---

### POST /api/admin/plan/goals/propose

**用途**：提案建立 goal。返回 preview 而不立即建立。

**為什麼需要**：Goal 是 commitment-level entity — 必須 proposal-first。

**Request**：
```json
{
  "title": "Master pgvector indexing",
  "description": "...",
  "area_id": "area_uuid",
  "deadline": "2026-06-01",
  "quarter": "2026-Q2"
}
```

**Response**：
```json
{
  "proposal_id": "prop_uuid",
  "preview": {
    "title": "Master pgvector indexing",
    "area_name": "Backend",
    "deadline": "2026-06-01",
    "existing_goals_in_area": 2,
    "quarter": "2026-Q2"
  }
}
```

**Backend 邏輯**：儲存 proposal（可用 temp table 或 JSON field），不建立 goal。返回 context（同 area 有幾個 goal）幫助使用者判斷。

---

### POST /api/admin/plan/goals/propose/{proposal_id}/commit

**用途**：確認並建立 goal。

**Response**：建立的 goal。

---

### POST /api/admin/plan/goals/{id}/milestones

**用途**：為 goal 新增 milestone。

**Request**：
```json
{
  "title": "Benchmark IVFFlat vs HNSW on 100K rows",
  "position": 1
}
```

---

### POST /api/admin/plan/goals/{id}/milestones/{ms_id}/toggle

**用途**：Toggle milestone 完成狀態。

**Response**：更新後的 milestone。

---

## 4. Plan — Projects

### GET /api/admin/plan/projects

**用途**：Projects overview。

**Query params**：`status` (active / planned / on-hold / completed / all)

**Response**：
```json
{
  "projects": [
    {
      "id": "proj_uuid",
      "title": "koopa0.dev MCP v2",
      "slug": "koopa0-dev-mcp-v2",
      "status": "in-progress",
      "area": "backend",
      "goal_breadcrumb": {
        "goal_id": "goal_uuid",
        "goal_title": "Launch knowledge engine"
      },
      "task_progress": { "total": 12, "done": 5 },
      "staleness_days": 0,
      "last_activity_at": "2026-04-08T10:00:00+08:00"
    }
  ]
}
```

**Backend 邏輯**：
- `goal_breadcrumb`：project → goal 的直接 FK（可能為 null，schema 無 milestone FK）
- `task_progress`：`COUNT tasks WHERE project_id = X GROUP BY status`
- `staleness_days`：`EXTRACT(DAY FROM now() - last_activity_at)`

---

### GET /api/admin/plan/projects/{id}

**用途**：Project detail — tasks by status, milestone link, activity。

**Response**：
```json
{
  "id": "proj_uuid",
  "title": "koopa0.dev MCP v2",
  "description": "...",
  "problem": "...",
  "solution": "...",
  "architecture": "...",
  "status": "in-progress",
  "area": "backend",
  "goal_breadcrumb": { "goal_id": "...", "goal_title": "..." },
  "tasks_by_status": {
    "in_progress": [{ "id": "...", "title": "...", "priority": "...", "energy": "..." }],
    "todo": [],
    "done": [],
    "someday": []
  },
  "recent_activity": [],
  "related_content": [
    { "id": "...", "title": "...", "type": "build-log", "slug": "..." }
  ]
}
```

---

## 5. Plan — Tasks

### GET /api/admin/plan/tasks

**用途**：Task backlog — 所有已澄清的 tasks。

**Query params**：`status` (todo/in-progress/someday/all), `area_id`, `energy`, `priority`, `project_id`, `search`, `cursor`, `limit`

**Response**：
```json
{
  "tasks": [
    {
      "id": "task_uuid",
      "title": "Add rate limiting to auth middleware",
      "status": "todo",
      "area": "backend",
      "priority": "high",
      "energy": "high",
      "due": "2026-04-15",
      "project_title": "koopa0.dev",
      "is_in_today_plan": false
    }
  ],
  "meta": { "total": 42, "cursor": "..." }
}
```

---

### POST /api/admin/plan/tasks/{id}/advance

**用途**：推進 task 狀態。Semantic command。

**為什麼需要**：不是 PATCH status — advance 有 side effects（start 設定 started_at, complete 設定 completed_at + 更新 daily_plan_item）。

**Request**：
```json
{ "action": "start" | "complete" | "defer" | "drop" }
```

**Backend 邏輯**：
- `start`：task.status → in-progress
- `complete`：task.status → done, task.completed_at → now, if daily_plan_item exists → mark done
- `defer`：task.status → someday
- `drop`：只影響 daily_plan_item.status → dropped（不刪除 task 本身）。如果 task 不在今日計劃中，此 action 無效

---

## 6. Library — Contents

### GET /api/admin/library/pipeline

**用途**：Content pipeline view — 按 workflow stage 分組。

**為什麼需要**：使用者打開 Library 不是來看表格，是來回答「我該繼續寫哪個 draft？」

**Response**：
```json
{
  "drafts_needing_work": [
    { "id": "...", "title": "...", "type": "article", "updated_at": "...", "word_count": 1200 }
  ],
  "in_review": [
    { "id": "...", "title": "...", "type": "til", "submitted_at": "...", "review_level": "standard" }
  ],
  "ready_to_publish": [
    { "id": "...", "title": "...", "type": "article", "reviewed_at": "..." }
  ],
  "recently_published": [
    { "id": "...", "title": "...", "type": "article", "published_at": "..." }
  ]
}
```

**Backend 邏輯**：
- `drafts_needing_work`：`contents WHERE status = 'draft' ORDER BY updated_at DESC LIMIT 10`
- `in_review`：`contents WHERE status = 'review'` + join review_queue
- `ready_to_publish`：`review_queue WHERE status = 'approved'` + join contents
- `recently_published`：`contents WHERE status = 'published' ORDER BY published_at DESC LIMIT 5`

---

## 7. Learn — 學習引擎（Phase 2）

### GET /api/admin/learn/dashboard

**用途**：Learning overview — due reviews, weakness, recent sessions。

**Response**：
```json
{
  "due_reviews_count": 12,
  "due_reviews_today": 5,
  "recent_sessions": [
    {
      "id": "session_uuid",
      "domain": "leetcode",
      "started_at": "2026-04-07T20:00:00+08:00",
      "duration_minutes": 47,
      "attempts_count": 4,
      "solved_count": 2
    }
  ],
  "weakness_spotlight": [
    {
      "concept_slug": "channel-direction",
      "concept_name": "Channel Direction",
      "domain": "go",
      "fail_count_30d": 5,
      "last_practiced": "2026-03-25",
      "days_since_practice": 14
    }
  ],
  "mastery_by_domain": [
    {
      "domain": "go",
      "concepts_total": 24,
      "concepts_mastered": 8,
      "concepts_weak": 5,
      "concepts_untested": 11
    }
  ],
  "streak": { "current_days": 3, "longest": 14 }
}
```

> **⚠ Schema 對齊**：streak 是從 sessions 表聚合計算（consecutive days with ≥1 session），不是存儲的值。

---

### POST /api/admin/learn/sessions/start

**用途**：開始學習 session。

**Request**：
```json
{
  "domain": "leetcode",
  "session_mode": "practice"
}
```

> **⚠ Schema 對齊**：sessions 表沒有 focus_concept_slugs 欄位。
> focus 概念可放在 metadata JSONB 中，或作為 suggested_items 的篩選參數。
> session_mode 必須是 schema 定義的 5 值之一：retrieval / practice / mixed / review / reading。

**Response**：
```json
{
  "session_id": "session_uuid",
  "suggested_items": [
    {
      "id": "item_uuid",
      "title": "LeetCode 704: Binary Search",
      "difficulty": "easy",
      "concepts": ["binary-search"],
      "last_attempt_outcome": "solved",
      "fsrs_due": "2026-04-08"
    }
  ]
}
```

---

### POST /api/admin/learn/sessions/{id}/attempt

**用途**：記錄一次 attempt。

**Request**：
```json
{
  "item_id": "item_uuid",
  "outcome": "incomplete",
  "duration_minutes": 12,
  "stuck_at": "邊界條件處理",
  "approach_used": "binary search with left/right pointers",
  "observations": [
    { "concept_slug": "binary-search", "signal_type": "weakness", "category": "boundary-conditions", "confidence": "high" },
    { "concept_slug": "off-by-one", "signal_type": "weakness", "category": "indexing", "confidence": "low" }
  ]
}
```

> **⚠ Schema 對齊**：
> - outcome 必須是 7 值之一：solved_independent / solved_with_hint / solved_after_solution / completed / completed_with_support / incomplete / gave_up（沒有 "partial"）
> - 用 duration_minutes INT，不是 duration_seconds
> - 沒有 ease_rating（FSRS rating 在 review_logs，不在 attempts）
> - signal_type 必須是：weakness / improvement / mastery（沒有 "misconception"）
> - attempts 有 stuck_at TEXT 和 approach_used TEXT 欄位
```

**Response**：
```json
{
  "attempt_id": "attempt_uuid",
  "confirmed_observations": [
    { "concept_slug": "binary-search", "signal": "weakness" }
  ],
  "pending_observations": [
    { "concept_slug": "off-by-one", "signal_type": "weakness", "reason": "concept would be auto-created" }
  ]
}
```

---

### POST /api/admin/learn/sessions/{id}/end

**用途**：結束 session，取得 summary。

**Response**：
```json
{
  "session_id": "session_uuid",
  "duration_minutes": 47,
  "attempts_count": 4,
  "solved_count": 2,
  "concept_impact": [
    { "concept_slug": "binary-search", "signal_type": "weakness", "observation_count": 2, "direction": "declining" }
  ],
  "observations_summary": {
    "weaknesses": ["binary-search boundary conditions"],
    "improvements": ["basic iteration"],
    "masteries": []
  }
}
```

> **⚠ Schema 對齊**：mastery 不是存儲的數值——是從 attempt_observations 聚合計算的衍生狀態。
> concept_impact 應該基於本次 session 記錄的 observations，而非 mastery 分數差。
> observations_summary 的 key 用 schema 的 signal_type 名稱：weaknesses / improvements / masteries（不是 strengths / misconceptions）。
}
```

---

### GET /api/admin/learn/concepts/{slug}

**用途**：Concept drilldown — 歷史趨勢, attempts, related items。

**Response**：
```json
{
  "concept": { "slug": "binary-search", "name": "Binary Search", "domain": "leetcode", "kind": "pattern" },
  "observation_trend": [
    { "date": "2026-03-01", "weakness_count": 3, "improvement_count": 0, "mastery_count": 0 },
    { "date": "2026-03-15", "weakness_count": 1, "improvement_count": 2, "mastery_count": 0 },
    { "date": "2026-04-01", "weakness_count": 1, "improvement_count": 1, "mastery_count": 1 }
  ],
  "recent_attempts": [
    { "item_title": "LeetCode 704", "outcome": "solved_independent", "date": "2026-03-28" }
  ],
  "observations": [
    { "signal_type": "weakness", "category": "boundary-conditions", "date": "2026-04-07" }
  ],
  "related_items": [
    { "id": "...", "title": "LeetCode 704", "difficulty": "easy", "last_outcome": "solved" }
  ],
  "next_review": "2026-04-10"
}
```

---

### GET /api/admin/learn/review-queue

**用途**：取得今天到期的 review cards（具體 items，不只是 count）。

**Response**：
```json
{
  "due_today": [
    {
      "card_id": 1,
      "target_type": "learning_item",
      "target_id": "item_uuid",
      "title": "LeetCode 704: Binary Search",
      "domain": "leetcode",
      "due": "2026-04-08",
      "last_reviewed_at": "2026-04-01"
    }
  ],
  "due_this_week": 12,
  "overdue": 3
}
```

---

## 7.5 Learn — Learning Plans（Phase 2）

> Schema 表：`plans`（status lifecycle）+ `plan_items`（UNIQUE per plan+item）
> MCP 工具：`manage_plan`（6 actions: add_items, remove_items, update_item, reorder, update_plan, progress）

### GET /api/admin/learn/plans

**用途**：列出所有 learning plans。

**Response**：
```json
{
  "plans": [
    {
      "id": "plan_uuid",
      "title": "Google 200 題計劃",
      "domain": "leetcode",
      "status": "active",
      "items_total": 200,
      "items_completed": 45,
      "items_skipped": 3,
      "created_at": "2026-03-01",
      "updated_at": "2026-04-07"
    }
  ]
}
```

### GET /api/admin/learn/plans/{id}

**用途**：Plan detail — items with status, progress。

**Response**：
```json
{
  "id": "plan_uuid",
  "title": "Google 200 題計劃",
  "domain": "leetcode",
  "status": "active",
  "description": "...",
  "items": [
    {
      "id": "plan_item_uuid",
      "learning_item_id": "item_uuid",
      "title": "LeetCode 704: Binary Search",
      "difficulty": "easy",
      "position": 1,
      "status": "completed",
      "completed_at": "2026-03-28",
      "completion_reason": "solved_independent on attempt #2"
    }
  ],
  "progress": {
    "total": 200,
    "completed": 45,
    "skipped": 3,
    "substituted": 1,
    "planned": 151
  }
}
```

> **⚠ Schema 對齊**：
> - plan_items.status：planned / completed / skipped / substituted
> - plan_items 有 reason TEXT 欄位（記錄 completion/skip 理由）
> - UNIQUE(plan_id, learning_item_id) 確保不重複
> - 同一 item 在不同 plan 中的完成狀態獨立

### POST /api/admin/learn/plans/{id}/items/{item_id}/update

**用途**：更新 plan item 狀態。Semantic command。

**Request**：
```json
{
  "status": "completed",
  "reason": "solved_independent on attempt #2"
}
```

> **⚠ Policy**：reason 欄位對 completions 應該是必填（審計建議），記錄「為什麼認為完成了」。

### POST /api/admin/learn/plans/{id}/items

**用途**：批次新增 items 到 plan。

**Request**：
```json
{ "item_ids": ["item_uuid_1", "item_uuid_2"] }
```

### DELETE /api/admin/learn/plans/{id}/items/{item_id}

**用途**：從 plan 移除 item。

### POST /api/admin/learn/plans/{id}/reorder

**用途**：重排 plan items 順序。

**Request**：
```json
{ "item_ids": ["item_uuid_2", "item_uuid_1"] }
```

### PATCH /api/admin/learn/plans/{id}

**用途**：更新 plan 本身（title, status）。

**Request**：
```json
{ "status": "paused", "title": "..." }
```

---

## 8. Reflect — 回顧（Phase 2）

### GET /api/admin/reflect/daily?date=2026-04-08

**用途**：每日回顧 context 聚合。

**為什麼需要**：前端不應自己拼裝 tasks + sessions + commits — backend 一次聚合。

**Response**：
```json
{
  "date": "2026-04-08",
  "plan_vs_actual": { "planned": 6, "completed": 4, "deferred": 1, "dropped": 1 },
  "completed_tasks": [
    { "id": "...", "title": "Design admin IA", "area": "studio" }
  ],
  "learning_sessions": [
    { "domain": "go", "duration_minutes": 47, "solved": 2, "total": 4 }
  ],
  "content_changes": [
    { "title": "pgvector indexing guide", "type": "article", "action": "updated" }
  ],
  "commits_count": 5,
  "inbox_delta": { "captured": 3, "clarified": 1, "net": 2 }
}
```

---

### GET /api/admin/reflect/weekly?week_start=2026-04-01

**用途**：週回顧聚合。

**Response**：
```json
{
  "week_start": "2026-04-01",
  "week_end": "2026-04-07",
  "goal_progress": [
    { "goal_title": "GDE Application", "milestones_completed_this_week": 1, "total_done": 3, "total": 4 }
  ],
  "project_health": [
    { "title": "MCP v2", "status": "in-progress", "tasks_completed": 3, "stalled": false }
  ],
  "learning_summary": {
    "sessions_count": 4,
    "total_minutes": 180,
    "concepts_improved": ["mutex-usage", "goroutine-lifecycle"],
    "concepts_declined": ["channel-direction"]
  },
  "content_output": {
    "published": 1,
    "drafted": 2
  },
  "inbox_health": { "start_count": 8, "end_count": 5, "clarified": 6, "captured": 3 },
  "insights_needing_check": [
    { "id": "...", "hypothesis": "...", "status": "unverified", "age_days": 14 }
  ],
  "metrics": { "tasks_completed": 12, "commits": 23, "build_logs": 3 }
}
```

---

### POST /api/admin/reflect/journal

**用途**：寫 journal entry。

**Request**：
```json
{
  "kind": "reflection",
  "body": "今天的 admin redesign 討論收穫很大...",
  "date": "2026-04-08"
}
```

---

### GET /api/admin/reflect/journal

**用途**：取得 journal 條目列表。

**Query params**：`limit` (default 20), `kind` (optional filter)

**Response**：
```json
{
  "entries": [
    {
      "kind": "reflection",
      "body": "今天的 admin redesign 討論收穫很大...",
      "date": "2026-04-08"
    }
  ]
}
```

**Backend 邏輯**：`journal ORDER BY created_at DESC LIMIT $limit`，可選 `WHERE kind = $kind`

---

### GET /api/admin/reflect/insights

**用途**：取得 insights 列表。

**Response**：
```json
{
  "insights": [
    {
      "id": "1",
      "hypothesis": "pgvector HNSW 在 100K 以上效能下降",
      "status": "unverified",
      "age_days": 14
    }
  ]
}
```

**Backend 邏輯**：`insights ORDER BY created_at DESC`，`age_days = EXTRACT(DAY FROM now() - created_at)`

---

### GET /api/admin/dashboard/trends

**用途**：系統趨勢分析數據（Dashboard 頁）。所有值由 backend 聚合計算。

**Response**：
```json
{
  "period": "2026-04-01 ~ 2026-04-07",
  "execution": {
    "tasks_completed_this_week": 12,
    "tasks_completed_last_week": 10,
    "trend": "up"
  },
  "plan_adherence": {
    "completion_rate_this_week": 78,
    "completion_rate_last_week": 65
  },
  "goal_health": {
    "on_track": 3,
    "at_risk": 1,
    "stalled": 0
  },
  "learning": {
    "sessions_this_week": 4,
    "weakness_count": 8,
    "weakness_change": -4,
    "mastery_count": 8,
    "mastery_change": 3,
    "review_backlog": 5
  },
  "content": {
    "published_this_month": 4,
    "published_target": 12,
    "drafts_in_progress": 2
  },
  "inbox_health": {
    "current_count": 5,
    "week_start_count": 8,
    "clarified_this_week": 6,
    "captured_this_week": 3
  },
  "someday_health": {
    "total": 12,
    "stale_count": 5
  },
  "directive_health": {
    "open_count": 2,
    "avg_resolution_days": 3.5
  }
}
```

**Backend 邏輯**：
- `execution`：`COUNT tasks WHERE completed_at BETWEEN this_week/last_week`
- `plan_adherence`：`daily_plan_items WHERE status='done' / total WHERE plan_date BETWEEN`
- `goal_health`：計算每個 active goal 的 health（同 goal detail 的 health 邏輯）
- `learning`：`COUNT attempt_observations GROUP BY signal_type` 本週 vs 上週
- `content`：`COUNT contents WHERE published_at` 本月 + draft count
- `inbox_health`：`COUNT tasks WHERE status='inbox'` + 本週 capture/clarify delta
- `someday_health`：`COUNT tasks WHERE status='someday'`，stale = `updated_at < now() - 30d`
- `directive_health`：`COUNT directives WHERE resolved_at IS NULL`，avg = `AVG(resolved_at - created_at)`

---

## 9. Studio — IPC 協作（Phase 3）

> **Schema 已更新（2026-04-08）**：directives 表已有 `resolved_at TIMESTAMPTZ` + `resolution_report_id BIGINT FK reports(id)` + `chk_resolved_requires_ack` CHECK constraint。
> `lifecycle_status` 可直接從 schema 欄位計算：pending（unacked）/ acknowledged / resolved。

### GET /api/admin/studio/overview

**用途**：IPC 全局狀態。

**Response**：
```json
{
  "open_directives": [
    {
      "id": "...",
      "title": "...",
      "target": "research-lab",
      "created_at": "...",
      "lifecycle_status": "pending" | "acknowledged" | "resolved",
      "acknowledged_at": null,
      "has_report": false,
      "days_open": 3
    }
  ],
  "unread_reports": [
    { "id": "...", "title": "...", "source": "research-lab", "directive_title": "...", "filed_at": "..." }
  ],
  "participants": [
    { "name": "research-lab", "active_directives": 2, "recent_reports": 1, "capabilities": ["can_receive_directives"] }
  ]
}
```

**Backend 邏輯**（`lifecycle_status` 計算，3 值）：
- `pending`：`acknowledged_at IS NULL`
- `acknowledged`：`acknowledged_at IS NOT NULL AND resolved_at IS NULL`
- `resolved`：`resolved_at IS NOT NULL`

`has_report: boolean` 作為獨立欄位存在於 DirectiveSummary 上，不影響 lifecycle_status。

---

### POST /api/admin/studio/directives/propose

**用途**：提案 directive。

**Request**：
```json
{
  "target": "research-lab",
  "title": "研究 NATS exactly-once semantics",
  "description": "...",
  "context": "...",
  "deadline": "2026-04-15"
}
```

---

## 10. System（Phase 3）

### GET /api/admin/system/health

**用途**：系統健康總覽。

**Response**：
```json
{
  "feeds": { "total": 15, "healthy": 13, "failing": 2, "failing_feeds": [{ "name": "...", "error": "...", "since": "..." }] },
  "pipelines": { "recent_runs": 10, "failed": 0, "last_run_at": "..." },
  "ai_budget": { "today_tokens": 45000, "daily_limit": 100000 },
  "database": { "contents_count": 142, "tasks_count": 67, "notes_count": 320 }
}
```

---

## API 命名對照表

| 前端需求 | Endpoint | 語意 |
|---------|----------|------|
| Today 畫面 | `GET /api/admin/today` | 聚合今日 context |
| 規劃今日 | `POST /api/admin/today/plan` | Batch plan items |
| 處理 plan item | `POST /api/admin/today/items/:id/resolve` | Semantic transition |
| Inbox 列表 | `GET /api/admin/inbox` | GTD inbox queue |
| 快速捕獲 | `POST /api/admin/inbox/capture` | Frictionless capture |
| 澄清 inbox item | `POST /api/admin/inbox/:id/clarify` | Polymorphic clarify |
| Goals 總覽 | `GET /api/admin/plan/goals` | By-area grouped |
| Goal 詳情 | `GET /api/admin/plan/goals/:id` | Cross-entity aggregate |
| 提案 Goal | `POST /api/admin/plan/goals/propose` | Proposal-first |
| 確認 Goal | `POST /api/admin/plan/goals/propose/:id/commit` | Commit proposal |
| 新增 Milestone | `POST /api/admin/plan/goals/:id/milestones` | Direct create |
| Toggle Milestone | `POST /api/admin/plan/goals/:id/milestones/:ms_id/toggle` | Binary toggle |
| Projects 總覽 | `GET /api/admin/plan/projects` | With breadcrumbs |
| Project 詳情 | `GET /api/admin/plan/projects/:id` | Tasks + activity |
| Tasks Backlog | `GET /api/admin/plan/tasks` | Filtered list |
| 推進 Task | `POST /api/admin/plan/tasks/:id/advance` | Semantic command |
| Content Pipeline | `GET /api/admin/library/pipeline` | Workflow stages |
| Learning Dashboard | `GET /api/admin/learn/dashboard` | Phase 2 |
| Start Session | `POST /api/admin/learn/sessions/start` | Phase 2 |
| Record Attempt | `POST /api/admin/learn/sessions/:id/attempt` | Phase 2 |
| End Session | `POST /api/admin/learn/sessions/:id/end` | Phase 2 |
| Concept Drilldown | `GET /api/admin/learn/concepts/:slug` | Phase 2 |
| Daily Review | `GET /api/admin/reflect/daily` | Phase 2 |
| Weekly Review | `GET /api/admin/reflect/weekly` | Phase 2 |
| Write Journal | `POST /api/admin/reflect/journal` | Phase 2 |
| Journal 列表 | `GET /api/admin/reflect/journal` | Phase 2 |
| Insights 列表 | `GET /api/admin/reflect/insights` | Phase 2 |
| Dashboard 趨勢 | `GET /api/admin/dashboard/trends` | Phase 2 |
| Studio Overview | `GET /api/admin/studio/overview` | Phase 3 |
| Propose Directive | `POST /api/admin/studio/directives/propose` | Phase 3 |
| System Health | `GET /api/admin/system/health` | Phase 3 |

---

## 實作優先級

| Priority | Endpoints | 理由 |
|----------|-----------|------|
| **P0 — Day One** | today, inbox (3), plan/goals (5), plan/projects (2), plan/tasks (2), library/pipeline | 前端 Day One 必要 |
| **P1 — Phase 2** | learn (5), reflect (3) | 學習 + 回顧 workflow |
| **P2 — Phase 3** | studio (2), system (1) | IPC + 系統監控 |

**注意**：前端會先用 mock data 開發，API 準備好後切換。每個 service 都會有 `useMock` flag。

---

## Schema 對齊備註

> 以下記錄 API response 與 migrations/001_initial.up.sql 的欄位對應關係，
> 避免前後端 mapping 成本。

### 關鍵差異與決策

| API response 欄位 | Schema 欄位 | 說明 |
|---|---|---|
| `task.area` | tasks 表**沒有** area 欄位 | 需透過 `tasks.project_id → projects.area_id → areas.name` JOIN 衍生。無 project 的 task area 為 null |
| `task.status` | `task_status` 列舉含 5 值：`inbox, todo, in-progress, done, someday` | 前端 TaskStatus type 需包含全部 5 值 |
| `goal.area_name` | `goals.area_id` UUID FK → `areas.name` | API 回傳 denormalized 的 `area_id` + `area_name`，省去前端 JOIN |
| `milestone.completed` | Schema 用 `completed_at TIMESTAMPTZ`（null = 未完成）| API 回傳 `completed: boolean`（衍生自 `completed_at IS NOT NULL`）+ 原始 `completed_at` |
| `daily_plan_item.title` | Schema 只有 `task_id` FK | API 回傳 denormalized 的 `title`（JOIN tasks.title）|
| `daily_plan_item.area` | 同上，需 JOIN tasks → projects → areas | API denormalize |
| `directive.title` | Schema 只有 `content TEXT` | API 可從 `content` 前 N 字截取作 title，或前端直接用 `content` |
| `directive` lifecycle | Schema **已有** `resolved_at` + `resolution_report_id` | lifecycle_status 可直接從 schema 欄位計算，不需 JOIN 推斷 |
| `insight.evidence` | Schema 用 `metadata JSONB` | evidence 存在 metadata.evidence 中（如有） |
| `attempt.outcome` | 7 值列舉：`solved_independent, solved_with_hint, solved_after_solution, completed, completed_with_support, incomplete, gave_up` | 前端 type 需包含全部 7 值 |
| `session.mode` | `session_mode` CHECK 5 值：`retrieval, practice, mixed, review, reading` | 前端需定義對應 type |
| `observation.signal_type` | 3 值：`weakness, improvement, mastery` | 注意不是 `weakness, strength, misconception`——schema 用 `improvement` 和 `mastery` |
| `observation.severity` | `minor, moderate, critical`，且只有 `signal_type='weakness'` 時才有值 | `chk_severity_weakness_only` 約束 |
| `concept.kind` | 3 值：`pattern, skill, principle` | |
| `areas` seed | 6 個：backend, learning, studio, frontend, career, ops | 前端 AREA_CLASSES 顏色映射需覆蓋這 6 個 |

### 前端 TypeScript model 需修正

1. `TaskStatus` 改為 `'inbox' | 'todo' | 'in-progress' | 'done' | 'someday'`（目前缺 inbox 和 someday）
2. `MilestoneWithProjects.completed` 改為 `completed_at: string | null`（布林由前端 computed 衍生）
3. `AREA_CLASSES` 色彩映射加入 `ops`
4. `AttemptOutcome` 定義為 7 值 union type
5. `SessionMode` 定義為 5 值 union type
6. `ObservationSignal` 改為 `weakness | improvement | mastery`（不是 weakness/strength/misconception）
7. `DirectiveSummary` 的 `title` 改為 `content`（或在 API 層截取）
