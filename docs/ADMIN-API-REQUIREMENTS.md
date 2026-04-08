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
    "overdue_tasks": 1
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

**Backend 邏輯**：
- `context_line`：根據最近 deadline 的 active goal 生成，或根據本週 journal(kind=plan) 提取 focus
- `yesterday_unfinished`：`daily_plan_items WHERE planned_date = yesterday AND status = 'planned'`
- `today_plan`：`daily_plan_items WHERE planned_date = today`
- `overdue_tasks`：`tasks WHERE due < today AND status NOT IN ('done', 'someday')`
- `needs_attention`：各 domain 的 count 聚合
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
- `goals` + `LEFT JOIN milestones` + `LEFT JOIN projects ON projects.milestone_id`
- 按 area 分組
- `days_remaining` = deadline - today（null if no deadline）
- `next_milestone_title` = 第一個未完成的 milestone

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
      "position": 1,
      "projects": [
        {
          "id": "proj_uuid",
          "title": "pgvector PoC",
          "status": "in-progress",
          "task_progress": { "total": 5, "done": 2 }
        }
      ]
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
        "goal_title": "Launch knowledge engine",
        "milestone_title": "MCP redesign"
      },
      "task_progress": { "total": 12, "done": 5 },
      "staleness_days": 0,
      "last_activity_at": "2026-04-08T10:00:00+08:00"
    }
  ]
}
```

**Backend 邏輯**：
- `goal_breadcrumb`：project → milestone → goal 的 chain（可能為 null）
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
  "goal_breadcrumb": { "goal_id": "...", "goal_title": "...", "milestone_id": "...", "milestone_title": "..." },
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
- `drop`：soft delete or archive

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
      "domain": "algorithms",
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

---

### POST /api/admin/learn/sessions/start

**用途**：開始學習 session。

**Request**：
```json
{
  "domain": "algorithms",
  "focus_concept_slugs": ["binary-search", "two-pointers"]
}
```

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
  "outcome": "partial",
  "duration_seconds": 720,
  "ease_rating": 3,
  "notes": "差點解出來，卡在邊界條件",
  "observations": [
    { "concept_slug": "binary-search", "signal": "weakness", "category": "boundary-conditions", "confidence": "high" },
    { "concept_slug": "off-by-one", "signal": "misconception", "category": "indexing", "confidence": "low" }
  ]
}
```

**Response**：
```json
{
  "attempt_id": "attempt_uuid",
  "confirmed_observations": [
    { "concept_slug": "binary-search", "signal": "weakness" }
  ],
  "pending_observations": [
    { "concept_slug": "off-by-one", "signal": "misconception", "reason": "concept would be auto-created" }
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
    { "concept_slug": "binary-search", "mastery_before": 0.6, "mastery_after": 0.55, "direction": "down" }
  ],
  "observations_summary": {
    "weaknesses": ["binary-search boundary conditions"],
    "strengths": ["basic iteration"],
    "misconceptions": []
  }
}
```

---

### GET /api/admin/learn/concepts/{slug}

**用途**：Concept drilldown — 歷史趨勢, attempts, related items。

**Response**：
```json
{
  "concept": { "slug": "binary-search", "name": "Binary Search", "domain": "algorithms", "kind": "pattern" },
  "mastery_trend": [
    { "date": "2026-03-01", "mastery": 0.3 },
    { "date": "2026-03-15", "mastery": 0.5 },
    { "date": "2026-04-01", "mastery": 0.6 }
  ],
  "recent_attempts": [
    { "item_title": "LeetCode 704", "outcome": "solved", "date": "2026-03-28" }
  ],
  "observations": [
    { "signal": "weakness", "category": "boundary-conditions", "date": "2026-04-07" }
  ],
  "related_items": [
    { "id": "...", "title": "LeetCode 704", "difficulty": "easy", "last_outcome": "solved" }
  ],
  "next_review": "2026-04-10"
}
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

## 9. Studio — IPC 協作（Phase 3）

### GET /api/admin/studio/overview

**用途**：IPC 全局狀態。

**Response**：
```json
{
  "pending_directives": [
    { "id": "...", "title": "...", "target": "research-lab", "created_at": "...", "status": "pending" }
  ],
  "unread_reports": [
    { "id": "...", "title": "...", "source": "research-lab", "directive_title": "...", "filed_at": "..." }
  ],
  "participants": [
    { "name": "research-lab", "active_directives": 2, "recent_reports": 1, "capabilities": ["can_receive_directives"] }
  ]
}
```

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
