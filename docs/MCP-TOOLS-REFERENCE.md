# koopa0-knowledge MCP Tools Reference

> 52 tools across 10 functional domains. Last audit: 2026-03-31.
> Server: `koopa0-knowledge` v0.2.0 — Go binary (`cmd/mcp/`) + PostgreSQL (pgvector).
> Transport: Streamable HTTP on port 8081 (OAuth2 via Google OIDC).

---

## Quick Navigation

| Domain | Tools | Purpose |
|--------|-------|---------|
| [Daily Workflow](#1-daily-workflow-8-tools) | 8 | Morning/evening PDCA 循環：規劃、執行、回顧、調整 |
| [Task Management](#2-task-management-5-tools) | 5 | 任務 CRUD、批次 My Day、Notion 雙向同步 |
| [Knowledge Search](#3-knowledge-search-5-tools) | 5 | 跨源搜尋、內容詳情、主題合成、語意相似、決策日誌 |
| [Content Pipeline](#4-content-pipeline-5-tools) | 5 | 內容 CRUD、發佈、佇列、RSS 書籤 |
| [RSS / Feed Management](#5-rss--feed-management-6-tools) | 6 | 訂閱 CRUD、收集統計、RSS 摘要 |
| [Project & Goal](#6-project--goal-5-tools) | 5 | 專案上下文、目標進度、狀態更新 |
| [Learning Analytics](#7-learning-analytics-10-tools) | 10 | 開發/學習記錄、標籤統計、涵蓋矩陣、弱點趨勢、時間線、mastery map、concept gaps、variation map |
| [O'Reilly Integration](#8-oreilly-integration-3-tools) | 3 | 搜尋、書籍目錄、章節閱讀（條件啟用） |
| [System & Infrastructure](#9-system--infrastructure-3-tools) | 3 | 系統狀態、管線觸發、活動事件（部分條件啟用） |
| [Spaced Retrieval (FSRS)](#10-spaced-retrieval-fsrs-2-tools) | 2 | 間隔重複回測、到期佇列（條件啟用） |

### Annotation Legend

| 標記 | 意義 |
|------|------|
| `readOnly` | 唯讀，不修改任何資料 |
| `readOnly+openWorld` | 唯讀，但呼叫外部 API（O'Reilly） |
| `additive` | 新增資料，不破壞既有資料 |
| `additive+idempotent` | 更新/upsert，重複呼叫安全 |
| `destructive` | 不可逆操作（刪除、發佈、完成recurring task） |
| 🔒 | 條件啟用：需特定環境變數才註冊 |

---

## 1. Daily Workflow (8 tools)

每日 PDCA 循環的核心。Morning planning → execution → evening reflection → next morning。

### `morning_context`

> 早晨規劃一站式：一次拉回所有規劃所需資料。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/morning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `sections` | string[] | — | 限定回傳子集：tasks, activity, build_logs, projects, goals, insights, reflection, planning_history, rss, plan, completions, pipeline_health, rss_highlights, agent_tasks, content_pipeline |
| `activity_days` | int | — | activity lookback 天數（default 3） |
| `build_log_days` | int | — | build log lookback 天數（default 7） |

觸發情境：「早安」「good morning」「今天有什麼事」、session start、`/checkin`

---

### `reflection_context`

> 晚間回顧一站式：today's plan vs actual completions。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/reflection.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `date` | string | — | 回顧日期 YYYY-MM-DD（default today） |

---

### `session_delta`

> 上次 session 到現在的所有變化。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/delta.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `since` | string | — | ISO date YYYY-MM-DD（default: 上次 claude session note 日期） |

---

### `weekly_summary`

> 每週綜合摘要：任務完成、指標趨勢、專案健康、目標對齊。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/weekly.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `weeks_back` | int | — | 0=本週, 1=上週（default 0, max 4） |
| `compare_previous` | bool | — | 包含上週比較數據與 delta |

---

### `save_session_note`

> 儲存跨環境 session 筆記。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `note_type` | string | ✅ | plan, reflection, context, metrics, insight |
| `content` | string | ✅ | 筆記內容 |
| `source` | string | ✅ | claude, claude-code, manual |
| `date` | string | — | YYYY-MM-DD（default today） |
| `metadata` | object | — | insight: {hypothesis, invalidation_condition}; plan: {reasoning, committed_task_ids, committed_items}; metrics: {tasks_planned, tasks_completed, adjustments} |

---

### `session_notes`

> 取得 session 筆記（依日期/類型）。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `date` | string | — | YYYY-MM-DD（default today） |
| `note_type` | string | — | plan, reflection, context, metrics, insight |
| `days` | int | — | 回溯天數（default 1, max 30） |

---

### `active_insights`

> 取得追蹤中的 insights（假說/觀察）。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/insights.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `status` | string | — | unverified, verified, invalidated, all（default unverified） |
| `project` | string | — | 依專案過濾 |
| `limit` | int | — | 最大筆數（default 10） |

---

### `update_insight`

> 更新 insight 狀態或附加證據。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive+idempotent` |
| 實作 | `internal/mcp/insights.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `insight_id` | int64 | ✅ | session_note ID |
| `status` | string | — | unverified, verified, invalidated, archived |
| `append_evidence` | string | — | 新增支持證據 |
| `append_counter_evidence` | string | — | 新增反面證據 |
| `conclusion` | string | — | 驗證後結論 |

---

## 2. Task Management (5 tools)

任務管理，雙向同步 Notion。

### `search_tasks`

> 搜尋/列出任務，支援多條件過濾。取代了舊的 `get_pending_tasks`。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `query` | string | — | 模糊搜尋 title + description |
| `project` | string | — | 專案 slug/alias/title |
| `status` | string | — | pending, done, all（default all） |
| `assignee` | string | — | human, claude-code, cowork, all |
| `completed_after` | string | — | YYYY-MM-DD（inclusive） |
| `completed_before` | string | — | YYYY-MM-DD（inclusive） |
| `limit` | int | — | 最大筆數（default 20, max 100） |

---

### `create_task`

> 在 Notion 建立新任務。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `title` | string | ✅ | 任務標題 |
| `project` | string | — | 專案 slug/alias/title |
| `due` | string | — | YYYY-MM-DD |
| `priority` | string | — | Low, Medium, High |
| `energy` | string | — | Low, High |
| `my_day` | bool | — | 加入 My Day |
| `notes` | string | — | 描述文字 |
| `assignee` | string | — | human, claude-code, cowork（default human） |

---

### `complete_task`

> 標記任務完成。recurring task 會推進到下次 due date。

| 屬性 | 值 |
|------|-----|
| 標記 | `destructive`（recurring due date 推進不可逆） |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `task_id` | string | — | UUID 或 Notion page ID |
| `task_title` | string | — | 模糊匹配待辦任務標題（與 task_id 二擇一） |
| `notes` | string | — | 完成備註 |

---

### `update_task`

> 更新任務屬性。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive+idempotent` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `task_id` | string | — | UUID（與 task_title 二擇一） |
| `task_title` | string | — | 模糊匹配 |
| `new_title` | string | — | 重命名 |
| `status` | string | — | To Do, Doing, Done |
| `due` | string | — | YYYY-MM-DD |
| `priority` | string | — | Low, Medium, High |
| `energy` | string | — | Low, High |
| `my_day` | bool | — | 設定/清除 My Day |
| `project` | string | — | 專案 slug/alias/title |
| `notes` | string | — | 追加描述 |
| `assignee` | string | — | human, claude-code, cowork |

---

### `my_day`

> 批次設定 Notion My Day。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive+idempotent` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `task_ids` | string[] | ✅ | 要設為 My Day 的 task UUIDs |
| `clear` | bool | — | 是否先清除所有既有 My Day |

---

## 3. Knowledge Search (5 tools)

跨所有內容源的知識搜尋與合成。

### `search_knowledge`

> 跨所有內容類型搜尋：articles, build logs, TILs, notes, Obsidian notes。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/search.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `query` | string | ✅ | 搜尋關鍵字 |
| `project` | string | — | 專案 slug/alias/title |
| `after` | string | — | 排除此日期之前（YYYY-MM-DD, exclusive） |
| `before` | string | — | 排除此日期之後（YYYY-MM-DD, exclusive） |
| `content_type` | string | — | article, essay, build-log, til, note, bookmark, digest, obsidian-note |
| `source` | string | — | Obsidian 篩選：leetcode, book, course, discussion, practice, video |
| `context` | string | — | Obsidian 篩選：frontmatter 中的 project name |
| `book` | string | — | Obsidian 篩選：書名 |
| `limit` | int | — | 最大筆數（default 10, max 30） |

合併了舊的 `search_notes`。使用 `content_type="obsidian-note"` 搭配 source/context/book 來搜尋 Obsidian 筆記。

---

### `content_detail`

> 依 slug 取得完整內容。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/search.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `slug` | string | ✅ | 內容 slug |

---

### `decision_log`

> 取得 Obsidian 中 type=decision-log 的筆記。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/morning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | — | 依專案 context 過濾 |
| `limit` | int | — | 最大筆數（default 20, max 50） |

---

### `synthesize_topic`

> 跨所有內容源的主題合成 + gap analysis。Token 成本較高。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/search.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `query` | string | ✅ | 要合成的主題 |
| `max_sources` | int | — | 最大來源數（default 15, max 30） |
| `include_gap_analysis` | bool | — | 包含子主題涵蓋缺口（default true） |

---

### `find_similar_content`

> 基於 embedding cosine similarity 的語意相似搜尋。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/search.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `content_slug` | string | ✅ | 基準 TIL 的 slug |
| `limit` | int | — | 最大筆數（default 5, max 20） |

---

## 4. Content Pipeline (5 tools)

內容 CRUD 與發佈管線。

### `create_content`

> 建立內容草稿。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` |
| 實作 | `internal/mcp/content.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `title` | string | ✅ | 標題 |
| `body` | string | ✅ | Markdown 內容 |
| `content_type` | string | ✅ | article, essay, build-log, til, note, bookmark, digest |
| `tags` | string[] | — | 標籤 |
| `project` | string | — | 專案 slug/alias/title |

---

### `update_content`

> 更新草稿或審核中內容的屬性。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive+idempotent` |
| 實作 | `internal/mcp/content.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `content_id` | string | ✅ | 內容 UUID |
| `title` | string | — | 新標題 |
| `body` | string | — | 新內容 |
| `content_type` | string | — | 變更類型 |
| `tags` | string[] | — | 變更標籤 |
| `project` | string | — | 變更專案 |

---

### `publish_content`

> 發佈內容（不可逆）。

| 屬性 | 值 |
|------|-----|
| 標記 | `destructive` |
| 實作 | `internal/mcp/content.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `content_id` | string | ✅ | 內容 UUID |

---

### `list_content_queue`

> 查看內容佇列。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/content.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `view` | string | — | queue（default）, calendar, recent |
| `status` | string | — | draft, review, published, all |
| `content_type` | string | — | 內容類型過濾 |
| `limit` | int | — | 最大筆數（default 20） |

---

### `bookmark_rss_item`

> 將 RSS 項目存為書籤（建立 content record type=bookmark）。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` |
| 實作 | `internal/mcp/content.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `collected_id` | string | ✅ | collected_data 的 UUID |
| `notes` | string | — | 個人評語 |
| `tags` | string[] | — | 標籤 |

---

## 5. RSS / Feed Management (6 tools)

RSS 訂閱管理與收集統計。

### `rss_highlights`

> 取得最近收集的 RSS 文章。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/morning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `days` | int | — | 回溯天數（default 7, max 365） |
| `limit` | int | — | 最大筆數（default 20, max 100） |
| `sort_by` | string | — | relevance（default）或 recency |

---

### `list_feeds`

> 列出所有 RSS 訂閱。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` 🔒 |
| 實作 | `internal/mcp/feed.go` |

無參數。

---

### `add_feed`

> 新增 RSS 訂閱。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` 🔒 |
| 實作 | `internal/mcp/feed.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `url` | string | ✅ | Feed URL |
| `name` | string | ✅ | 顯示名稱 |
| `schedule` | string | — | daily（default）, weekly |
| `topics` | string[] | — | 主題標籤 |

---

### `update_feed`

> 啟用/停用 feed。合併了舊的 `disable_feed` + `enable_feed`。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive+idempotent` 🔒 |
| 實作 | `internal/mcp/feed.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `feed_id` | string | ✅ | Feed UUID |
| `enabled` | bool | ✅ | true 啟用 / false 停用 |

---

### `remove_feed`

> 永久刪除 feed。

| 屬性 | 值 |
|------|-----|
| 標記 | `destructive` 🔒 |
| 實作 | `internal/mcp/feed.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `feed_id` | string | ✅ | Feed UUID |

---

### `collection_stats`

> 收集管線統計：per-feed 數量、平均相關性、全域統計。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/feed.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `feed_id` | string | — | 特定 feed UUID |
| `days` | int | — | 回溯天數（default 30, max 90） |

---

## 6. Project & Goal (5 tools)

專案與目標管理。

### `list_projects`

> 列出所有進行中的專案。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/morning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `limit` | int | — | 最大筆數（default 20, max 50） |

---

### `project_context`

> 取得單一專案完整上下文：詳情、活動、相關筆記。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/morning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 name/slug/alias |

---

### `update_project_status`

> 更新專案狀態。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive+idempotent` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 name/slug/alias |
| `status` | string | ✅ | Planned, Doing, Ongoing, On Hold, Done |
| `review_notes` | string | — | 更新描述的備註 |
| `expected_cadence` | string | — | daily, weekly, biweekly, monthly, on_hold |

---

### `goal_progress`

> 目標進度追蹤 + optional drift analysis。取代了舊的 `get_goals` 和 `get_platform_stats` 的 drift 功能。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/goals.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `days` | int | — | 回溯天數（default 30, max 90） |
| `area` | string | — | 依 area 過濾 |
| `status` | string | — | not-started, in-progress, done, abandoned |
| `include_drift` | bool | — | 包含 goal-vs-activity drift 分析 |

---

### `update_goal_status`

> 更新目標狀態。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive+idempotent` |
| 實作 | `internal/mcp/goals.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `goal_title` | string | ✅ | 目標標題（case-insensitive match） |
| `status` | string | ✅ | not-started, in-progress, done, abandoned |

---

## 7. Learning Analytics (10 tools)

開發記錄、學習記錄、與學習分析。

### `log_dev_session`

> 記錄開發 session 為 build-log。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 name/slug/alias |
| `session_type` | string | ✅ | feature, refactor, bugfix, research, infra |
| `title` | string | ✅ | 簡短摘要 |
| `body` | string | ✅ | Markdown 內容 |
| `tags` | string[] | — | 標籤 |
| `plan_summary` | string | — | .claude/plans/ 摘要 |
| `review_summary` | string | — | reviewer 發現摘要 |
| `tier` | string | — | tier-1, tier-2, tier-3 |
| `diff_stats` | string | — | e.g. "+120 -30" |

---

### `log_learning_session`

> 記錄學習成果（LeetCode、書籍、課程、系統設計、語言學習）。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` |
| 實作 | `internal/mcp/write.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `topic` | string | ✅ | 學習主題 |
| `source` | string | ✅ | leetcode, hackerrank, oreilly, ardanlabs, article, discussion |
| `title` | string | ✅ | 簡短標題 |
| `body` | string | ✅ | Markdown 內容 |
| `project` | string | ✅ | 專案 slug/alias/title |
| `tags` | string[] | — | 標籤（topic tags + weakness:xxx + improvement:xxx） |
| `difficulty` | string | — | easy, medium, hard |
| `problem_url` | string | — | 題目連結 |
| `learning_type` | string | — | leetcode, book-reading, course, system-design, language |
| `metadata` | object | — | per-type structured data（見 server.go 完整 schema） |

---

### `learning_progress`

> 學習指標：筆記成長趨勢、每週活動比較、top 標籤。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/morning.go` |

無參數。

---

### `tag_summary`

> 專案 TIL 的標籤頻率統計。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 slug/alias/title |
| `tag_prefix` | string | — | 只回傳指定前綴的標籤 |
| `days` | int | — | 回溯天數（default 90, max 365） |

---

### `coverage_matrix`

> 主題涵蓋矩陣：各 topic 的練習次數、最近日期、結果分佈。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 slug/alias/title |
| `days` | int | — | 回溯天數（default 365, max 730） |

---

### `weakness_trend`

> 弱點標籤時間序列趨勢分析。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 slug/alias/title |
| `tag` | string | ✅ | 弱點標籤（e.g. weakness:pattern-recognition） |
| `days` | int | — | 回溯天數（default 30, max 180） |

---

### `learning_timeline`

> 學習項目按天分組 + 連續天數統計。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | — | 專案 slug/alias/title（省略=全部） |
| `days` | int | — | 回溯天數（default 14, max 90） |

### `mastery_map`

> 複合式 per-pattern 精熟度視圖。一次呼叫取代 coverage_matrix + tag_summary + weakness_trend。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 slug/alias/title |
| `patterns` | string[] | — | 只包含這些 pattern（省略=全部） |
| `days` | int | — | 回溯天數（default 30, max 365） |

回傳 per-pattern：stage（unexplored/struggling/developing/solid）、result 分佈、difficulty 分佈、concept mastery 計數、weak concepts、unexplored approaches、weakness tag 趨勢、variation coverage、regression signals、raw stage_signals。

---

### `concept_gaps`

> 跨 pattern concept 級弱點分析。找出跨多題出現 guided/told 的 systemic gaps。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 slug/alias/title |
| `mastery_filter` | string[] | — | 包含哪些 mastery 等級（default: guided, told） |
| `days` | int | — | 回溯天數（default 30, max 365） |

回傳 systemic_gaps（跨 2+ TIL 的弱點 concept）和 coaching_history（所有 coaching hints，按時間倒序）。

---

### `variation_map`

> 題目關係圖：從 variation_links metadata 建構 cluster。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | ✅ | 專案 slug/alias/title |
| `pattern` | string | — | pattern 過濾（省略=全部） |
| `include_unattempted` | bool | — | 包含尚未嘗試的 linked problems（default true） |
| `days` | int | — | 回溯天數（default 365, max 730） |

回傳 clusters（anchor problem + linked variations）和 isolated_problems（無 variation links 的題目）。

---

## 8. O'Reilly Integration (3 tools)

🔒 條件啟用：需要 `ORM_JWT` 環境變數。

### `search_oreilly_content`

> 搜尋 O'Reilly Learning 內容。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly+openWorld` |
| 實作 | `internal/mcp/oreilly_tools.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `query` | string | ✅ | 搜尋關鍵字 |
| `formats` | string[] | — | book, video, article, course, interactive, audiobook |
| `publishers` | string[] | — | 出版社過濾 |
| `authors` | string[] | — | 作者過濾 |
| `limit` | int | — | 最大筆數（default 10, max 50） |

---

### `oreilly_book_detail`

> 取得書籍 metadata 和完整目錄。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly+openWorld` |
| 實作 | `internal/mcp/oreilly_tools.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `archive_id` | string | ✅ | 書籍 identifier |

---

### `read_oreilly_chapter`

> 讀取書籍章節全文。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly+openWorld` |
| 實作 | `internal/mcp/oreilly_tools.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `archive_id` | string | ✅ | 書籍 identifier |
| `filename` | string | ✅ | 章節檔名（from book detail） |

---

## 9. System & Infrastructure (3 tools)

### `recent_activity`

> 最近的開發活動事件。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/morning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `days` | int | — | 回溯天數（default 7, max 30） |
| `source` | string | — | github, obsidian, notion |
| `project` | string | — | 專案名稱 |

---

### `system_status`

> 系統可觀測性：flow runs、feed health、pipeline 摘要。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` 🔒 |
| 實作 | `internal/mcp/status.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `scope` | string | — | summary（default）, pipelines, flows |
| `flow_name` | string | — | 依 flow 名稱過濾 |
| `status` | string | — | completed, failed, running |
| `hours` | int | — | 回溯小時數（default 24, max 168） |

---

### `trigger_pipeline`

> 手動觸發管線。限速每 5 分鐘一次。

| 屬性 | 值 |
|------|-----|
| 標記 | `destructive` 🔒 |
| 實作 | `internal/mcp/status.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `pipeline` | string | ✅ | rss_collector 或 notion_sync |

---

## 10. Spaced Retrieval / FSRS (2 tools)

🔒 條件啟用：需要 retrieval store（FSRS tables 存在且 store 非 nil）。

### `log_retrieval_attempt`

> 記錄 FSRS 間隔重複回測結果。

| 屬性 | 值 |
|------|-----|
| 標記 | `additive` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `content_slug` | string | ✅ | TIL slug |
| `rating` | int | ✅ | 1=Again, 2=Hard, 3=Good, 4=Easy |
| `tag` | string | — | 特定弱點/概念標籤 |

---

### `retrieval_queue`

> 取得到期的間隔重複佇列。

| 屬性 | 值 |
|------|-----|
| 標記 | `readOnly` |
| 實作 | `internal/mcp/learning.go` |

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `project` | string | — | 專案 slug/alias/title |
| `limit` | int | — | 最大筆數（default 10, max 50） |

---

## Removed / Merged Tools (Historical)

| 舊工具 | 處置 | 替代方式 |
|--------|------|---------|
| `search_notes` | 合併至 `search_knowledge` | 使用 `content_type="obsidian-note"` + source/context/book 參數 |
| `get_pending_tasks` | 合併至 `search_tasks` | 使用 `status="pending"` |
| `get_platform_stats` | 移除 | drift → `get_goal_progress(include_drift=true)`; overview → individual domain tools |
| `disable_feed` + `enable_feed` | 合併至 `update_feed` | 使用 `enabled` boolean |
| `generate_social_excerpt` | 移除（已 deprecated） | — |

---

## Conditional Registration Summary

| 環境變數 | 影響的工具 |
|----------|-----------|
| `ORM_JWT` | `search_oreilly_content`, `oreilly_book_detail`, `read_oreilly_chapter` |
| `ADMIN_API_URL` + `JWT_SECRET` + `ADMIN_EMAIL` | `system_status`, `trigger_pipeline` |
| `NOTION_API_KEY` | `create_task`, `complete_task`（Notion sync 功能） |
| retrieval store 非 nil | `log_retrieval_attempt`, `retrieval_queue` |
| feeds store 非 nil | `list_feeds`, `add_feed`, `update_feed`, `remove_feed` |
