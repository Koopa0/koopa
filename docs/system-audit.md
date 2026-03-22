# koopa0.dev 全系統盤點報告

> 產出日期：2026-03-22
> 掃描範圍：`/Users/koopa/blog/backend` + `/Users/koopa/blog/frontend`

---

## Part 1: Backend — MCP Tool 完整清單

共 **24 個 MCP Tools**，註冊於 `backend/internal/mcp/server.go`。

### Read Tools (14)

| Tool Name | 類型 | 用途說明 | 輸入參數 | 回傳的關鍵欄位 |
|---|---|---|---|---|
| `get_morning_context` | Read | 一次取得整天規劃所需的全部資訊：overdue/today/upcoming/my-day tasks、activity、build logs、projects、goals、reflection、planning metrics、insights、daily summary | `ActivityDays` (int, default 3), `BuildLogDays` (int, default 7) | `Date`, `OverdueTasks`, `TodayTasks`, `UpcomingTasks`, `MyDayTasks`, `RecentActivity` (by source/project), `RecentBuildLogs`, `Projects` (with health), `Goals`, `YesterdayReflection`, `PlanningHistory` (completion rate, capacity, trend), `ActiveInsights`, `TotalUnverified`, `DailySummary` |
| `get_pending_tasks` | Read | 列出待辦任務，按緊急度排序（deadline 優先，再按 least recently touched） | `Project` (string, optional), `Limit` (int, default 50) | `Tasks` (ID, Title, Status, Due, Priority, Energy, Project, IsRecurring, CreatedAt, UpdatedAt), `Total` |
| `get_active_insights` | Read | 取得追蹤中的 insights（假說/模式），自動 archive >14 天的 stale insights | `Status` (unverified/verified/invalidated/all), `Project` (optional), `Limit` (1-100, default 10) | `Insights` (ID, Content, Hypothesis, Status, Evidence[], SourceDates, Project, Tags, Conclusion), `Total`, `UnverifiedCount` |
| `get_goals` | Read | 從 Notion 同步的個人目標 | `Status` (optional), `Area` (optional), `Limit` (default 50) | `Goals` (ID, Title, Description, Status, Area, Quarter, Deadline) |
| `get_project_context` | Read | 單一專案的完整上下文（詳情 + 近期活動 + 相關筆記） | `Project` (required, name/slug/alias) | `Project` (全欄位), `RecentActivity`, `RelatedNotes` |
| `list_projects` | Read | 列出所有活躍專案 | `Limit` (default 50) | `Projects` (slug, title, status, area, tech_stack, URLs), `Total` |
| `get_recent_activity` | Read | 多來源開發活動摘要（GitHub、Obsidian、Notion） | `Days` (default 3), `Project` (optional), `Source` (optional) | `BySource`, `ByProject`, `TopEvents` |
| `search_knowledge` | Read | 跨內容類型搜尋（articles, build logs, TILs, notes），full-text + semantic | `Query` (required), `Limit` (default 10) | `Results` (type, slug, title, excerpt, source_type, published_at) |
| `search_notes` | Read | Obsidian 筆記搜尋，支援 frontmatter 過濾 | `Query`, `Type`, `Context`, `Source`, `Book`, `Limit` (all optional) | `Notes` (file_path, title, excerpt, type, context, source, book, tags) |
| `get_learning_progress` | Read | 學習指標（筆記成長趨勢、每週活躍度、top tags） | 無 | `TotalNotes`, `WeekGrowth`, `WeekVsLastWeek`, `TopTags`, `ActivityTrend` |
| `get_platform_stats` | Read | 平台健康總覽（content counts, projects, goals, activity drift） | `IncludeDrift` (bool), `DriftDays` (int) | `Contents` (by type/status), `Projects`, `Goals`, `ActivityTrend`, `GoalAlignmentDrift` |
| `get_session_notes` | Read | 取得 session notes（plan/reflection/metrics/context/insight） | `Date` (optional), `Days` (optional), `NoteType` (optional) | `Notes` (date, type, content, metadata, source) |
| `get_decision_log` | Read | 架構決策與設計理由 | `Project` (optional), `Limit` (default 50) | `Decisions` (obsidian notes from decision-log context) |
| `get_content_detail` | Read | 取得單一內容的完整 body | `Slug` (required) | `ID`, `Title`, `Body`, `Type`, `Status`, `Tags`, `Topics`, `PublishedAt` |

### Write Tools (10)

| Tool Name | 類型 | 用途說明 | 輸入參數 | 回傳的關鍵欄位 |
|---|---|---|---|---|
| `create_task` | Write | 建立任務（先寫 Notion 再寫 local） | `Title` (required), `Project`, `Due`, `Priority`, `Energy`, `MyDay`, `Notes` | `TaskID`, `Title`, `Due`, `Project`, `Warning` |
| `update_task` | Write | 更新任務屬性 | `TaskID`/`TaskTitle`, `Status`, `Due`, `Priority`, `Energy`, `MyDay`, `Project`, `Notes` | `TaskID`, `Title`, `Status`, `Due`, `UpdatedAt` |
| `complete_task` | Write | 完成任務，處理 recurrence，同步 Notion | `TaskID`/`TaskTitle`, `Notes` | `TaskID`, `Title`, `CompletedAt`, `IsRecurring`, `NextRecurrence` |
| `batch_my_day` | Write | 批次設定/清除 My Day 任務 | `TaskIDs` ([]string), `Clear` (bool) | `ClearedCount`, `SetCount` |
| `update_project_status` | Write | 更新專案狀態 | `Project` (required), `Status` (required), `ReviewNotes` | `Slug`, `Title`, `Status`, `UpdatedAt` |
| `update_goal_status` | Write | 更新目標狀態 | `GoalTitle` (required), `Status` (required) | `Title`, `Status`, `Area`, `UpdatedAt` |
| `save_session_note` | Write | 記錄 planning/reflection/metrics/context/insight | `NoteType` (required), `Content` (required), `Source` (required), `Date`, `Metadata` | `ID`, `NoteDate`, `NoteType`, `CreatedAt` |
| `update_insight` | Write | 更新 insight 狀態或補充 evidence | `InsightID` (required), `Status`, `AppendEvidence`, `Conclusion` | `ID`, `Status`, `EvidenceCount`, `Conclusion` |
| `log_learning_session` | Write | 記錄學習成果（LeetCode、書籍、課程） | `Topic`, `Source`, `Title`, `Body` (all required), `Tags`, `Project`, `Difficulty`, `ProblemURL` | `ContentID`, `Slug`, `Title`, `Status` |
| `log_dev_session` | Write | 記錄開發 session（build log） | `Title`, `Body` (required), `Project`, `Tags` | `ContentID`, `Slug`, `Title` |

---

## Part 2: Backend — Data Model 完整清單

### 2.1 所有 Tables（15 個）

#### `users`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | 使用者 ID |
| `email` | TEXT UNIQUE | 登入信箱 |
| `role` | TEXT (default 'admin') | 角色 |
| `created_at` | TIMESTAMPTZ | 建立時間 |
| `updated_at` | TIMESTAMPTZ | 更新時間 |

#### `refresh_tokens`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Token ID |
| `user_id` | UUID FK→users | 所屬使用者 |
| `token_hash` | TEXT UNIQUE | SHA256 hash |
| `expires_at` | TIMESTAMPTZ | 過期時間 |
| `created_at` | TIMESTAMPTZ | 建立時間 |

#### `contents`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | 內容 ID |
| `slug` | TEXT UNIQUE | URL 路徑 |
| `title` | TEXT | 標題 |
| `body` | TEXT | Markdown 全文 |
| `excerpt` | TEXT | 摘要 |
| `type` | ENUM (article/essay/build-log/til/note/bookmark/digest) | 內容類型 |
| `status` | ENUM (draft/review/published/archived) | 發佈狀態 |
| `tags` | TEXT[] | 標籤 |
| `source` | TEXT | 來源名稱 |
| `source_type` | ENUM (obsidian/notion/ai-generated/external/manual) | 來源類型 |
| `series_id` | UUID (optional) | 系列 ID |
| `series_order` | INT (optional) | 系列順序 |
| `review_level` | ENUM (auto/light/standard/strict) | 審核等級 |
| `ai_metadata` | JSONB | AI 工具輸出 |
| `reading_time` | INT | 閱讀時間（分鐘） |
| `cover_image` | TEXT | 封面圖 URL |
| `published_at` | TIMESTAMPTZ | 發佈時間 |
| `created_at` | TIMESTAMPTZ | 建立時間 |
| `updated_at` | TIMESTAMPTZ | 更新時間 |
| `embedding` | vector(768) | Gemini embedding（語意搜尋） |
| `search_text` | TEXT | 反正規化搜尋欄位 |
| `search_vector` | TSVECTOR (GENERATED) | 全文搜尋向量 |

#### `topics`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Topic ID |
| `slug` | TEXT UNIQUE | URL 路徑 |
| `name` | TEXT | 顯示名稱 |
| `description` | TEXT | 描述 |
| `icon` | TEXT | 圖示 |
| `sort_order` | INT | 排序 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `content_topics` (Join Table)
| 欄位 | 類型 | 用途 |
|------|------|------|
| `content_id` | UUID FK→contents | 內容 |
| `topic_id` | UUID FK→topics | 主題 |
| PK: (content_id, topic_id) | | |

#### `projects`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | 專案 ID |
| `slug` | TEXT UNIQUE | URL 路徑 |
| `title` | TEXT | 名稱 |
| `description` | TEXT | 簡述 |
| `long_description` | TEXT | 詳述 |
| `role` | TEXT | 擔任角色 |
| `tech_stack` | TEXT[] | 技術棧 |
| `highlights` | TEXT[] | 重點成就 |
| `problem` / `solution` / `architecture` / `results` | TEXT | 專案故事 |
| `github_url` / `live_url` | TEXT | 連結 |
| `featured` | BOOLEAN | 首頁置頂 |
| `public` | BOOLEAN | 公開展示 |
| `sort_order` | INT | 排序 |
| `status` | ENUM (planned/in-progress/on-hold/completed/maintained/archived) | 狀態 |
| `notion_page_id` | TEXT UNIQUE | Notion 同步 |
| `repo` | TEXT | Repository 識別 |
| `area` | TEXT | 分類 |
| `deadline` | TIMESTAMPTZ | 截止日 |
| `last_activity_at` | TIMESTAMPTZ | 最後活動 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `tasks`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | 任務 ID |
| `title` | TEXT | 任務標題 |
| `status` | ENUM (todo/in-progress/done) | 狀態 |
| `due` | DATE | 截止日 |
| `project_id` | UUID FK→projects (optional) | 所屬專案 |
| `notion_page_id` | TEXT UNIQUE | Notion 同步 |
| `completed_at` | TIMESTAMPTZ | 完成時間 |
| `energy` | TEXT | 所需精力 (low/high) |
| `priority` | TEXT | 優先級 (low/medium/high) |
| `recur_interval` | INT | 重複間隔 |
| `recur_unit` | TEXT | 重複單位 (day/week/month/year) |
| `my_day` | BOOLEAN | My Day 標記 |
| `description` | TEXT | 詳細說明 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `goals`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | 目標 ID |
| `title` | TEXT | 標題 |
| `description` | TEXT | 描述 |
| `status` | ENUM (not-started/in-progress/done/abandoned) | 狀態 |
| `area` | TEXT | 領域 |
| `quarter` | TEXT | 季度 (e.g., "Q1 2026") |
| `deadline` | TIMESTAMPTZ | 截止日 |
| `notion_page_id` | TEXT UNIQUE | Notion 同步 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `session_notes`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Note ID |
| `note_date` | DATE | Session 日期 |
| `note_type` | TEXT (plan/reflection/context/metrics/insight) | 類型 |
| `content` | TEXT | Markdown 內容 |
| `metadata` | JSONB | 任意結構化資料 |
| `source` | TEXT (claude/claude-code/manual) | 來源 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `obsidian_notes`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Note ID |
| `file_path` | TEXT UNIQUE | Vault 路徑 |
| `title` | TEXT | 標題 |
| `body` | TEXT | 內容 |
| `type` | TEXT | 筆記類型 |
| `source` | TEXT | 來源系統 |
| `context` | TEXT | Context tag |
| `book` | TEXT | 書籍 |
| `tags` | TEXT[] | 標籤 |
| `content_hash` | TEXT | 變更偵測 |
| `embedding` | vector(768) | 語意向量 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `activity_events`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Event ID |
| `source` | TEXT (github/obsidian/notion) | 來源 |
| `event_type` | TEXT (commit/file_change/page_update) | 事件類型 |
| `source_id` | TEXT | 去重用 ID |
| `project_id` | UUID FK→projects (optional) | 關聯專案 |
| `summary` | TEXT | 摘要 |
| `details` | JSONB | 詳細資料 |
| `occurred_at` | TIMESTAMPTZ | 發生時間 |
| `created_at` | TIMESTAMPTZ | 建立時間 |

#### `feeds`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Feed ID |
| `url` | TEXT UNIQUE | RSS URL |
| `name` | TEXT | 名稱 |
| `schedule` | TEXT (cron) | 排程 |
| `topics` | TEXT[] | 相關主題 |
| `enabled` | BOOLEAN | 啟用 |
| `etag` / `last_modified` | TEXT | HTTP 快取 |
| `last_fetched_at` | TIMESTAMPTZ | 最後抓取 |
| `consecutive_failures` | INT | 連續失敗 |
| `last_error` / `disabled_reason` | TEXT | 錯誤訊息 |
| `filter_config` | JSONB | 過濾設定 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `collected_data`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Item ID |
| `source_url` | TEXT | 原始 URL |
| `source_name` | TEXT | 來源名稱 |
| `title` | TEXT | 標題 |
| `original_content` | TEXT | 原始內容 |
| `relevance_score` | REAL | 相關性 (0-1) |
| `topics` | TEXT[] | 匹配主題 |
| `status` | ENUM (unread/read/curated/ignored) | 狀態 |
| `curated_content_id` | UUID FK→contents | 轉為內容 |
| `collected_at` | TIMESTAMPTZ | 收集時間 |
| `url_hash` | TEXT UNIQUE | 去重 |
| `user_feedback` | JSONB | 使用者回饋 |
| `feed_id` | UUID FK→feeds | 來源 feed |

#### `tracking_topics`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | ID |
| `name` | TEXT | 主題名稱 |
| `keywords` | TEXT[] | 搜尋關鍵字 |
| `sources` | TEXT[] | 追蹤來源 |
| `enabled` | BOOLEAN | 啟用 |
| `schedule` | TEXT (cron) | 排程 |
| `created_at` / `updated_at` | TIMESTAMPTZ | 時間戳 |

#### `review_queue`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Review ID |
| `content_id` | UUID FK→contents | 待審內容 |
| `review_level` | ENUM (auto/light/standard/strict) | 審核等級 |
| `status` | ENUM (pending/approved/rejected/edited) | 審核狀態 |
| `reviewer_notes` | TEXT | 審核意見 |
| `submitted_at` / `reviewed_at` | TIMESTAMPTZ | 時間戳 |

#### `flow_runs`
| 欄位 | 類型 | 用途 |
|------|------|------|
| `id` | UUID PK | Run ID |
| `flow_name` | TEXT | Flow 名稱 (polish/generate/digest) |
| `content_id` | UUID FK→contents | 關聯內容 |
| `input` / `output` | JSONB | 輸入/輸出 |
| `status` | ENUM (pending/running/completed/failed) | 執行狀態 |
| `error` | TEXT | 錯誤訊息 |
| `attempt` / `max_attempts` | INT | 重試 |
| `started_at` / `ended_at` / `created_at` | TIMESTAMPTZ | 時間戳 |

### 2.2 SQL Queries 總覽（99+ 個）

| Domain | Query 數量 | 關鍵 Queries |
|--------|-----------|-------------|
| **Task** | 18 | PendingTasks, CompletedTasksSince, DailySummaryHint, ClearAllMyDay, UpsertTaskByNotionPageID |
| **Content** | 26 | PublishedContents, SearchContents, SimilarContents (embedding), PublishedForRSS, AllPublishedSlugs |
| **Session** | 10 | CreateNote, NotesByDate, InsightsByStatus, ArchiveStaleInsights |
| **Project** | 19 | ActiveProjects, ProjectByAlias, UpdateProjectStatus, UpsertProjectByNotionPageID |
| **Goal** | 6 | UpsertGoalByNotionPageID, UpdateGoalStatus |
| **Activity** | 7 | CreateEvent, EventsByFilters, EventsByProject |
| **Note (Obsidian)** | 13 | UpsertNote, SearchNotesByText, SearchNotesBySimilarity, BulkUpsertNoteLinks |

### 2.3 資料關聯

```
users ──1:N──> refresh_tokens
contents ──M:N──> topics (via content_topics)
contents ──1:N──> review_queue
contents ──1:N──> flow_runs
contents <──1:1── collected_data.curated_content_id
projects ──1:N──> tasks
projects ──1:N──> activity_events
feeds ──1:N──> collected_data
```

---

## Part 3: Backend — HTTP Endpoints

共 **75+ endpoints**，位於 `backend/internal/server/routes.go`。

### 3.1 Public Routes（無需驗證）

| Method | Path | 用途 | 使用者 |
|--------|------|------|--------|
| GET | `/api/contents` | 列出已發佈內容（分頁、type/tag 過濾） | Frontend |
| GET | `/api/contents/{slug}` | 單一內容 | Frontend |
| GET | `/api/contents/by-type/{type}` | 按類型過濾 | Frontend |
| GET | `/api/contents/related/{slug}` | 相關內容 | Frontend |
| GET | `/api/topics` | 所有主題 | Frontend |
| GET | `/api/topics/{slug}` | 單一主題 | Frontend |
| GET | `/api/projects` | 公開專案 | Frontend |
| GET | `/api/projects/{slug}` | 單一專案 | Frontend |
| GET | `/api/search` | 全文搜尋 | Frontend |
| GET | `/api/knowledge-graph` | 語意知識圖譜（限流） | Frontend |
| GET | `/api/feed/rss` | RSS feed（10 分鐘快取） | External |
| GET | `/api/feed/sitemap` | XML sitemap（10 分鐘快取） | External/SEO |
| GET | `/api/auth/google` | Google OAuth 登入 | Frontend |
| GET | `/api/auth/google/callback` | OAuth callback | Google |
| POST | `/api/auth/refresh` | 刷新 access token（限流） | Frontend |

### 3.2 Admin Routes（需 JWT 驗證）

| Method | Path | 用途 | 使用者 |
|--------|------|------|--------|
| **Content CRUD** | | | |
| POST | `/api/admin/contents` | 建立草稿 | Frontend Admin |
| PUT | `/api/admin/contents/{id}` | 更新內容 | Frontend Admin |
| DELETE | `/api/admin/contents/{id}` | 刪除內容 | Frontend Admin |
| POST | `/api/admin/contents/{id}/publish` | 發佈 | Frontend Admin |
| **Review** | | | |
| GET | `/api/admin/review` | 待審清單 | Frontend Admin |
| POST | `/api/admin/review/{id}/approve` | 核准 | Frontend Admin |
| POST | `/api/admin/review/{id}/reject` | 退回 | Frontend Admin |
| PUT | `/api/admin/review/{id}/edit` | 要求修改 | Frontend Admin |
| **Collected Data** | | | |
| GET | `/api/admin/collected` | 收集內容列表 | Frontend Admin |
| POST | `/api/admin/collected/{id}/curate` | 轉為發佈內容 | Frontend Admin |
| POST | `/api/admin/collected/{id}/ignore` | 忽略 | Frontend Admin |
| POST | `/api/admin/collected/{id}/feedback` | 使用者回饋 | Frontend Admin |
| **Projects** | | | |
| GET | `/api/admin/projects` | 所有專案（含非公開） | Frontend Admin |
| POST | `/api/admin/projects` | 建立專案 | Frontend Admin |
| PUT | `/api/admin/projects/{id}` | 更新專案 | Frontend Admin |
| DELETE | `/api/admin/projects/{id}` | 刪除專案 | Frontend Admin |
| **Goals / Tasks** | | | |
| GET | `/api/admin/goals` | 目標列表 | Frontend Admin |
| GET | `/api/admin/tasks` | 任務列表 | Frontend Admin |
| GET | `/api/admin/tasks/pending` | 待辦任務 | Frontend Admin |
| **Topics** | | | |
| POST | `/api/admin/topics` | 建立主題 | Frontend Admin |
| PUT | `/api/admin/topics/{id}` | 更新主題 | Frontend Admin |
| DELETE | `/api/admin/topics/{id}` | 刪除主題 | Frontend Admin |
| **Tags** | | | |
| GET | `/api/admin/tags` | 標籤列表 | Frontend Admin |
| POST | `/api/admin/tags` | 建立標籤 | Frontend Admin |
| PUT | `/api/admin/tags/{id}` | 更新標籤 | Frontend Admin |
| DELETE | `/api/admin/tags/{id}` | 刪除標籤 | Frontend Admin |
| POST | `/api/admin/tags/backfill` | 自動補標籤 | Frontend Admin |
| POST | `/api/admin/tags/merge` | 合併標籤 | Frontend Admin |
| **Aliases** | | | |
| GET | `/api/admin/aliases` | 專案別名列表 | Frontend Admin |
| POST | `/api/admin/aliases/{id}/map` | 建立映射 | Frontend Admin |
| POST | `/api/admin/aliases/{id}/confirm` | 確認別名 | Frontend Admin |
| POST | `/api/admin/aliases/{id}/reject` | 拒絕別名 | Frontend Admin |
| DELETE | `/api/admin/aliases/{id}` | 刪除別名 | Frontend Admin |
| **Tracking** | | | |
| GET | `/api/admin/tracking` | 追蹤主題列表 | Frontend Admin |
| POST | `/api/admin/tracking` | 建立追蹤主題 | Frontend Admin |
| PUT | `/api/admin/tracking/{id}` | 更新 | Frontend Admin |
| DELETE | `/api/admin/tracking/{id}` | 刪除 | Frontend Admin |
| **Flow Runs** | | | |
| GET | `/api/admin/flow-runs` | AI pipeline 執行歷史 | Frontend Admin |
| GET | `/api/admin/flow-runs/{id}` | 單一執行詳情 | Frontend Admin |
| POST | `/api/admin/flow-runs/{id}/retry` | 重試失敗 flow | Frontend Admin |
| **Content Polish** | | | |
| POST | `/api/admin/flow/polish/{content_id}` | 觸發 AI polish | Frontend Admin |
| GET | `/api/admin/flow/polish/{content_id}/result` | Polish 結果 | Frontend Admin |
| POST | `/api/admin/flow/polish/{content_id}/approve` | 核准 polish | Frontend Admin |
| **Feeds** | | | |
| GET | `/api/admin/feeds` | RSS feed 列表 | Frontend Admin |
| POST | `/api/admin/feeds` | 建立 feed | Frontend Admin |
| PUT | `/api/admin/feeds/{id}` | 更新 feed | Frontend Admin |
| DELETE | `/api/admin/feeds/{id}` | 刪除 feed | Frontend Admin |
| POST | `/api/admin/feeds/{id}/fetch` | 手動抓取 | Frontend Admin |
| **Notion** | | | |
| GET | `/api/admin/notion-sources/discover` | 自動發現 Notion 資料庫 | Frontend Admin |
| GET | `/api/admin/notion-sources` | Notion 來源列表 | Frontend Admin |
| GET | `/api/admin/notion-sources/{id}` | 單一來源 | Frontend Admin |
| POST | `/api/admin/notion-sources` | 新增來源 | Frontend Admin |
| PUT | `/api/admin/notion-sources/{id}` | 更新來源 | Frontend Admin |
| DELETE | `/api/admin/notion-sources/{id}` | 刪除來源 | Frontend Admin |
| POST | `/api/admin/notion-sources/{id}/toggle` | 啟用/停用 | Frontend Admin |
| PUT | `/api/admin/notion-sources/{id}/role` | 變更角色 | Frontend Admin |
| **Activity** | | | |
| GET | `/api/admin/activity/sessions` | Session 列表 | Frontend Admin |
| GET | `/api/admin/activity/changelog` | 活動紀錄 | Frontend Admin |
| **Session Notes** | | | |
| GET | `/api/admin/session-notes` | Session notes | Frontend Admin |
| **Upload** | | | |
| POST | `/api/admin/upload` | 上傳檔案到 R2 | Frontend Admin |
| **Pipeline** | | | |
| POST | `/api/admin/pipeline/sync` | 同步 Obsidian + GitHub | Cron/Admin |
| POST | `/api/admin/pipeline/notion-sync` | 同步 Notion | Cron/Admin |
| POST | `/api/admin/pipeline/reconcile` | 調解 Notion-local 狀態 | Admin |
| POST | `/api/admin/pipeline/collect` | 從 feeds 收集內容 | Cron/Admin |
| POST | `/api/admin/pipeline/generate` | AI 生成內容 | Admin |
| POST | `/api/admin/pipeline/digest` | 生成週報/月報 | Admin |
| POST | `/api/admin/pipeline/bookmark` | 處理書籤 | Admin |
| **Stats** | | | |
| GET | `/api/admin/stats` | 平台總覽 | Frontend Admin |
| GET | `/api/admin/stats/drift` | 目標偏移報告 | Frontend Admin |
| GET | `/api/admin/stats/learning` | 學習指標 | Frontend Admin |

### 3.3 Webhooks（HMAC 驗證）

| Method | Path | 用途 | 來源 |
|--------|------|------|------|
| POST | `/api/webhook/github` | GitHub push/PR events | GitHub |
| POST | `/api/webhook/notion` | Notion 變更事件 | Notion |

---

## Part 4: Angular Frontend 完整清單

### 4.1 Route 定義

#### Public Routes（SSR）

| Path | Component | Lazy Load | Render Mode |
|------|-----------|-----------|-------------|
| `/` | HomeComponent | ✓ | Server |
| `/articles` | ArticlesComponent | ✓ | Server |
| `/articles/:id` | ArticleDetailComponent | ✓ | Server |
| `/projects` | ProjectsComponent | ✓ | Server |
| `/projects/:slug` | ProjectDetailComponent | ✓ | Server |
| `/tags/:tag` | TagComponent | ✓ | Server |
| `/til` | TilsComponent | ✓ | Server |
| `/til/:slug` | TilDetailComponent | ✓ | Server |
| `/notes` | NotesComponent | ✓ | Server |
| `/notes/:slug` | NoteDetailComponent | ✓ | Server |
| `/uses` | UsesComponent | ✓ | Prerender |
| `/about` | AboutComponent | ✓ | Prerender |
| `/privacy` | PrivacyComponent | ✓ | Server |
| `/terms` | TermsComponent | ✓ | Server |
| `/login` | LoginComponent | — | Client |
| `/error` | ErrorComponent | — | Client |
| `**` | NotFoundComponent | — | Client |

#### Admin Routes（需登入，Client render）

| Path | Component | Guard |
|------|-----------|-------|
| `/admin` | AdminLayoutComponent + DashboardComponent | authGuard |
| `/admin/today` | TodayComponent | authGuard |
| `/admin/flow-runs` | FlowRunsComponent | authGuard |
| `/admin/feeds` | FeedsComponent | authGuard |
| `/admin/collected` | CollectedComponent | authGuard |
| `/admin/review` | ReviewComponent | authGuard |
| `/admin/tags` | TagsComponent | authGuard |
| `/admin/notion-sources` | NotionSourcesComponent | authGuard |
| `/admin/activity` | ActivityComponent | authGuard |
| `/admin/projects` | AdminProjectsComponent | authGuard |
| `/admin/tasks` | TasksComponent | authGuard |
| `/admin/goals` | GoalsComponent | authGuard |
| `/admin/tracking` | TrackingComponent | authGuard |
| `/admin/build-logs` | BuildLogsComponent | authGuard |
| `/admin/build-logs/:slug` | BuildLogDetailComponent | authGuard |
| `/admin/editor` | ArticleEditorComponent | authGuard + unsavedChangesGuard |
| `/admin/editor/:id` | ArticleEditorComponent | authGuard |
| `/admin/project-editor` | ProjectEditorComponent | authGuard + unsavedChangesGuard |
| `/admin/project-editor/:id` | ProjectEditorComponent | authGuard |
| `/admin/oauth-callback` | OAuthCallbackComponent | — |

### 4.2 Page/Component 清單

#### Public Pages

| Component | 功能 | 呼叫的 API |
|-----------|------|-----------|
| HomeComponent | 首頁：Hero、Featured Projects、Tech Stack、Latest Feed、CTA | ProjectService, ContentService |
| ArticlesComponent | 文章列表 + 搜尋 + 分頁 | ArticleService.getArticles() |
| ArticleDetailComponent | 單一文章 + TOC + 相關文章 + 分享 | ArticleService.getArticleBySlug() |
| ProjectsComponent | 專案列表 + 狀態過濾 | ProjectService.getAllProjects() |
| ProjectDetailComponent | 專案詳情 | ProjectService.getProjectBySlug() |
| TagComponent | 標籤內容列表 | ContentService |
| TilsComponent / TilDetailComponent | TIL 列表 + 詳情 | ContentService (type=til) |
| NotesComponent / NoteDetailComponent | 技術筆記列表 + 詳情 | ContentService (type=note) |
| AboutComponent | 關於我（靜態） | — |
| UsesComponent | 工具清單（靜態） | — |
| LoginComponent | Google OAuth 登入 | `/bff/api/auth/google` |

#### Admin Pages

| Component | 功能 | 呼叫的 API |
|-----------|------|-----------|
| AdminLayoutComponent | Sidebar 導覽 shell | AuthService.logout() |
| DashboardComponent | 儀表板：stats cards、最近內容、drift、learning | StatsService, ArticleService, ProjectService |
| TodayComponent | 每日任務/目標/insights | TaskService, GoalService, SessionNoteService |
| ArticleEditorComponent | Markdown 編輯器 + 預覽 + AI polish + 上傳 | ContentService, FlowPolishService, UploadService |
| ProjectEditorComponent | 專案編輯器 | ProjectService |
| FlowRunsComponent | AI pipeline 執行歷史 | FlowRunService |
| FeedsComponent | RSS feed 管理 | FeedService |
| CollectedComponent | 收集內容管理 | CollectedService |
| ReviewComponent | 審核佇列 | ReviewService |
| TagsComponent | 標籤管理 | TagAdminService |
| NotionSourcesComponent | Notion 同步設定 | NotionSourceService |
| ActivityComponent | 活動紀錄 | ActivityService |
| AdminProjectsComponent | 專案管理（含非公開） | ProjectService.getAdminProjects() |
| TasksComponent | 任務列表 | TaskService |
| GoalsComponent | 目標列表 | GoalService |
| TrackingComponent | 追蹤主題管理 | TrackingService |
| BuildLogsComponent / BuildLogDetailComponent | Build logs 瀏覽 | ContentService (type=build-log) |

### 4.3 Services 清單（26+ 個）

| Service | 職責 | 對應 Backend Endpoint |
|---------|------|---------------------|
| ApiService | HTTP client（SSR-aware base URL） | — |
| AuthService | OAuth + JWT 狀態管理 | `/api/auth/*` |
| ContentService | 內容 CRUD | `/api/contents/*`, `/api/admin/contents/*` |
| ArticleService | 文章特化查詢 | 透過 ContentService |
| ProjectService | 專案 CRUD | `/api/projects/*`, `/api/admin/projects/*` |
| TopicService | 主題管理 | `/api/topics/*`, `/api/admin/topics/*` |
| TagService | 標籤查詢 | `/api/admin/tags` |
| TagAdminService | 標籤管理 | `/api/admin/tags/*` |
| SearchService | 全文搜尋 | `/api/search` |
| MarkdownService | Markdown → HTML（highlight.js + DOMPurify） | — |
| SeoService | Meta tags + JSON-LD | — |
| NotificationService | Toast 通知 | — |
| UploadService | 檔案上傳 R2 | `/api/admin/upload` |
| ThemeService | 暗色模式 | — |
| KeyboardShortcutsService | 快捷鍵 | — |
| CommandPaletteService | Cmd+K 導覽 | — |
| StatsService | 儀表板統計 | `/api/admin/stats/*` |
| FlowRunService | Pipeline 歷史 | `/api/admin/flow-runs` |
| FlowPolishService | AI 潤稿 | `/api/admin/flow/polish/*` |
| ReviewService | 審核流程 | `/api/admin/review/*` |
| FeedService | RSS feed 管理 | `/api/admin/feeds/*` |
| CollectedService | 收集內容 | `/api/admin/collected/*` |
| PipelineService | Pipeline 觸發 | `/api/admin/pipeline/*` |
| ActivityService | 活動紀錄 | `/api/admin/activity/*` |
| NotionSourceService | Notion 同步 | `/api/admin/notion-sources/*` |
| TaskService | 任務管理 | `/api/admin/tasks/*` |
| GoalService | 目標管理 | `/api/admin/goals/*` |
| SessionNoteService | Session notes | `/api/admin/session-notes` |
| TrackingService | 追蹤主題 | `/api/admin/tracking/*` |

### 4.4 UI Library

- **Tailwind CSS v4** — 唯一 styling 方案，全手刻 UI
- **Lucide Angular** — 圖標庫（577+ icons）
- **Angular CDK** — Layout/Overlay/A11y（非 Material）
- **highlight.js** — 程式碼高亮
- **marked** — Markdown 解析
- **isomorphic-dompurify** — XSS 防護
- **無 Angular Material、無 Bootstrap、無 PrimeNG**

### 4.5 Shared Components

| Component | 用途 |
|-----------|------|
| back-to-top | 回到頂部按鈕 |
| command-palette | Cmd+K 搜尋導覽 |
| search | 全文搜尋元件 |
| skeleton | Loading 骨架 |
| table-of-contents | 文章側邊 TOC |
| related-articles | 相關文章推薦 |
| theme-toggle | 主題切換（目前隱藏，固定暗色） |
| toast | Toast 通知顯示 |
| animations | fadeInUp 動畫 |

### 4.6 狀態管理

- **Angular Signals + Computed** — 全面使用，無 NgRx
- **RxJS** — 僅用於 HTTP 呼叫和 async 操作
- **takeUntilDestroyed()** — 自動 unsubscribe
- **OnPush** — 所有元件使用 OnPush change detection

---

## Part 5: Gap Analysis

### Tasks

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `get_pending_tasks` — 列出待辦任務 | `/admin/tasks` — 任務列表 | ⚠️ 部分覆蓋 | Frontend 只有基本列表，缺少按 urgency 排序、project 過濾 | P1 |
| `create_task` — 建立任務 | 無 | ❌ 完全沒有 | 只能透過 MCP/Notion 建立，Admin 無法直接建立 | P1 |
| `update_task` — 更新任務 | 無 | ❌ 完全沒有 | 無法在 Admin 修改任務屬性 | P1 |
| `complete_task` — 完成任務 | 無 | ❌ 完全沒有 | 無法在 Admin 標記完成 | P1 |
| `batch_my_day` — My Day 批次設定 | 無 | ❌ 完全沒有 | 無 My Day 介面 | P1 |
| Task recurring — 重複任務 | 無 | ❌ 完全沒有 | 無法查看/管理重複任務 | P2 |
| Task overdue — 逾期任務 | 無 | ❌ 完全沒有 | 無逾期提醒或顯示 | P1 |

### Projects

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `list_projects` / HTTP GET | `/projects` + `/admin/projects` | ✅ 已覆蓋 | 公開和管理列表都有 | — |
| `get_project_context` — 專案上下文 | `/projects/:slug` | ⚠️ 部分覆蓋 | 有基本詳情，但缺少 RecentActivity 和 RelatedNotes | P2 |
| `update_project_status` — 狀態更新 | `/admin/project-editor` | ⚠️ 部分覆蓋 | 編輯器有 status 欄位，但缺少 ReviewNotes 和快速狀態切換 | P3 |
| Project health — 專案健康度 | 無 | ❌ 完全沒有 | `PendingTasks`, `DaysSinceActivity` 等健康指標無顯示 | P2 |

### Goals

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `get_goals` — 目標列表 | `/admin/goals` | ⚠️ 部分覆蓋 | 有列表但缺少 area/quarter 過濾 | P2 |
| `update_goal_status` — 狀態更新 | 無 | ❌ 完全沒有 | 無法在 Frontend 更新目標狀態 | P1 |
| Goal alignment drift | Dashboard drift card | ✅ 已覆蓋 | StatsService.getDrift() | — |

### Session Notes

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `save_session_note` (plan/reflection/metrics/context/insight) | `/admin/today` | ⚠️ 部分覆蓋 | Today 頁面有部分呈現，但無法建立/編輯 session notes | P1 |
| `get_session_notes` — 歷史 notes | API 連接有 | ⚠️ 部分覆蓋 | 可能缺少完整的歷史瀏覽 UI | P2 |
| Session reflection — 回顧 | 無 | ❌ 完全沒有 | 無法在 Frontend 撰寫回顧 | P2 |
| Planning metrics — 規劃指標 | 無 | ❌ 完全沒有 | completion rate, capacity, trend 無視覺化 | P1 |

### Insights

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `get_active_insights` — 活躍 insights | `/admin/today` (部分) | ⚠️ 部分覆蓋 | Today 可能顯示部分 insights | P2 |
| `update_insight` — 更新狀態/evidence | 無 | ❌ 完全沒有 | 無法在 Frontend verify/invalidate/archive insights | P2 |
| Insight creation — 建立 insight | 無（透過 save_session_note） | ❌ 完全沒有 | 無直接建立介面 | P3 |

### Build Logs

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `log_dev_session` — 記錄開發 session | 無 | ❌ 完全沒有 | 只能透過 MCP 記錄，Admin 無法建立 | P2 |
| Build log 瀏覽 | `/admin/build-logs` + `/admin/build-logs/:slug` | ✅ 已覆蓋 | 列表和詳情都有 | — |
| Build log 搜尋 | 無 | ❌ 完全沒有 | 無搜尋功能 | P3 |

### Activity

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `get_recent_activity` — 多來源活動 | `/admin/activity` | ⚠️ 部分覆蓋 | 有 activity 頁面但缺少 by-source/by-project 分組 | P2 |
| GitHub commits 詳情 | 無 | ❌ 完全沒有 | 無 commit 詳情或 diff 瀏覽 | P3 |
| Notion events | 無 | ❌ 完全沒有 | Notion 變更無獨立呈現 | P3 |
| Activity timeline — 時間軸視覺化 | 無 | ❌ 完全沒有 | 無跨來源統一時間軸 | P3 |

### Knowledge

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `search_knowledge` — 全域搜尋 | `/api/search` + Search component | ✅ 已覆蓋 | 公開搜尋有 | — |
| `search_notes` — Obsidian 筆記搜尋 | 無 | ❌ 完全沒有 | 無 Obsidian 筆記的專屬搜尋介面 | P2 |
| `get_content_detail` — 內容詳情 | 各 detail pages | ✅ 已覆蓋 | article/til/note 都有 | — |
| Knowledge graph — 知識圖譜 | API endpoint 有 | ⚠️ 部分覆蓋 | API 有但前端未確認是否有視覺化 | P2 |
| Semantic search — 語意搜尋 | 無 | ❌ 完全沒有 | pgvector embedding 搜尋無前端介面 | P3 |
| `get_decision_log` — 決策日誌 | 無 | ❌ 完全沒有 | 無專門的決策日誌瀏覽頁 | P3 |

### Learning

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `get_learning_progress` — 學習指標 | Dashboard learning card | ✅ 已覆蓋 | StatsService.getLearning() | — |
| `log_learning_session` — 記錄學習 | 無 | ❌ 完全沒有 | 只能透過 MCP 記錄 LeetCode/書籍學習 | P2 |
| Learning history — 學習歷史 | 無 | ❌ 完全沒有 | 無學習紀錄瀏覽（按 topic/source/difficulty） | P2 |

### RSS

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| Feed 管理 (CRUD) | `/admin/feeds` | ✅ 已覆蓋 | | — |
| Collected items 管理 | `/admin/collected` | ✅ 已覆蓋 | curate/ignore/feedback 都有 | — |
| `get_rss_highlights` — 高相關性內容 | 無 | ❌ 完全沒有 | 無 RSS highlights 的獨立呈現 | P2 |
| Relevance scoring 視覺化 | 無 | ❌ 完全沒有 | 無專門的分析視圖 | P3 |

### Planning

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| `get_morning_context` — 每日全景 | `/admin/today` | ⚠️ 部分覆蓋 | Today 有基本架構但無法呈現 morning context 的完整資訊 | P1 |
| Planning history — 規劃歷史 | 無 | ❌ 完全沒有 | 無法查看過往規劃 | P2 |
| Capacity metrics — 容量指標 | 無 | ❌ 完全沒有 | weekday/weekend avg, trend 無呈現 | P2 |
| Daily summary — 每日摘要 | 無 | ❌ 完全沒有 | my-day completion, total completed 無呈現 | P1 |

### Admin 其他

| Backend 能力 | 對應 Frontend 功能 | 狀態 | Gap 說明 | 優先級建議 |
|---|---|---|---|---|
| Pipeline triggers (sync/notion-sync/collect/generate/digest/bookmark) | 無專門 UI | ❌ 完全沒有 | Pipeline 觸發只能透過 API/curl | P2 |
| Flow runs retry | `/admin/flow-runs` | ✅ 已覆蓋 | | — |
| Content polish flow | Article Editor | ✅ 已覆蓋 | | — |
| Upload to R2 | Article Editor | ✅ 已覆蓋 | | — |
| Notion sources 管理 | `/admin/notion-sources` | ✅ 已覆蓋 | | — |
| Stats overview | Dashboard | ✅ 已覆蓋 | | — |

---

## Part 6: Frontend Architecture 觀察

### 6.1 程式碼組織

- **Standalone Components** — 全面使用，無 NgModule
- **Feature-based** — `pages/`（公開）、`admin/`（管理）、`shared/`（共用）、`core/`（服務）
- **Lazy loading** — 所有 routes 都 lazy load
- **服務分離** — 26+ 個 service 各司其職，部分 service 職責有重疊（如 ContentService vs ArticleService）

### 6.2 Design System

- **無正式 Design System** — 全用 Tailwind CSS 手刻
- **一致性尚可** — 暗色主題統一，spacing/typography 靠 Tailwind utility class 維持
- **Lucide icons** — 統一圖標庫
- **缺少**：設計 tokens、共用 button/card/form 元件、spacing 規範

### 6.3 響應式設計

- **Mobile-first** — Tailwind 斷點
- **Admin sidebar** — CDK BreakpointObserver 自適應
- **各頁面** — 都有基本的 responsive 處理

### 6.4 效能考量

- **SSR** — 動態內容用 Server rendering，靜態頁面 prerender
- **OnPush** — 所有元件
- **Signals** — 取代 BehaviorSubject，減少 memory leak
- **Bundle budget** — 500kB warning / 1MB error
- **Code splitting** — standalone components 自動 tree-shake
- **待改善**：大文章的 markdown parsing 可能影響效能，related articles client-side fetch

### 6.5 可維護性

**優點：**
- 清晰的目錄結構
- Signal-based 狀態管理一致
- TypeScript strict mode
- SSR/Client 清楚分離

**待改善：**
- Admin 頁面多為基本 CRUD 列表，深度功能不足
- 缺少共用的表單元件（每個 editor 各自實作）
- 部分 admin pages 可能只是 placeholder（功能未深化）
- 缺少 E2E test 覆蓋
- 無 error boundary 或 global error handling（除 interceptor）

### 6.6 安全性

**優點：**
- Token in memory（非 localStorage）
- DOMPurify XSS 防護
- OAuth fragment token 傳遞
- Open redirect 防護

**待注意：**
- 無 CSP headers（依賴部署層）
- 無 refresh token rotation

---

## Part 7: 建議 Frontend Roadmap

### Tier 1 — 本週：填補最關鍵 Gap，讓 Backend 能力可被使用

#### 1.1 `/admin/today` 升級為「每日駕駛艙」
- 呼叫 morning context equivalent API，一次取得：
  - Overdue tasks（紅色警示）
  - Today tasks + My Day tasks（可勾選完成）
  - 每日摘要（已完成數、completion rate）
  - 活躍 insights（可 verify/invalidate）
  - 昨日回顧
- **Task 互動**：勾選完成、加入/移出 My Day、快速建立任務
- 這是最高優先級，因為整個 MCP 的 planning 能力都依賴這些資料

#### 1.2 Task 完整 CRUD
- 在 `/admin/tasks` 加入：
  - **建立任務**表單（title, due, priority, energy, project, my_day）
  - **編輯任務**（inline 或 modal）
  - **完成任務**（勾選 checkbox）
  - **My Day 批次管理**
  - **過期任務**高亮
  - **按 project/priority/due 排序和過濾**

#### 1.3 Goal 狀態更新
- 在 `/admin/goals` 加入狀態切換（dropdown 或 button group）

### Tier 2 — 本月：補齊核心功能

#### 2.1 Planning Metrics Dashboard
- 新增 `/admin/planning` 或嵌入 Dashboard：
  - Completion rate 趨勢圖
  - Capacity metrics（weekday/weekend 平均值）
  - Planning history 時間軸

#### 2.2 Session Notes 管理
- 擴充 `/admin/today` 或新增 `/admin/sessions`：
  - 查看歷史 session notes（plan/reflection/metrics）
  - 撰寫回顧
  - Planning metrics 對照 actual

#### 2.3 Insight Tracker
- 新增 `/admin/insights` 或嵌入 Today：
  - 列出 unverified insights
  - 操作：verify、invalidate、archive
  - 補充 evidence

#### 2.4 Project Context 增強
- `/admin/projects/:slug` 顯示：
  - 近期活動（commits, Notion 更新）
  - 關聯筆記
  - 專案健康度（pending tasks, days since activity）

#### 2.5 Pipeline Control Panel
- 新增 `/admin/pipeline` 或嵌入 Dashboard：
  - 一鍵觸發各 pipeline（sync, notion-sync, collect, generate, digest）
  - 顯示上次執行時間和狀態

#### 2.6 RSS Highlights
- 在 `/admin/collected` 或新頁面顯示高相關性 RSS 收集

#### 2.7 Activity 增強
- `/admin/activity` 加入：
  - 按 source 分群（GitHub / Obsidian / Notion）
  - 按 project 分群
  - 時間篩選

### Tier 3 — 未來：UX 改進、視覺化、Design System

#### 3.1 Design System
- 建立共用元件庫：
  - Button (primary/secondary/danger/ghost)
  - Card (content card, stat card, task card)
  - Form controls (input, select, textarea, checkbox)
  - Modal/Dialog
  - Badge/Status chip
  - Empty state
- 定義 design tokens（spacing, colors, typography）

#### 3.2 Knowledge Graph 視覺化
- 用 D3.js 或 Cytoscape.js 呈現知識圖譜
- 連接 `/api/knowledge-graph` endpoint

#### 3.3 Semantic Search UI
- 進階搜尋模式：語意搜尋 + 全文搜尋
- 搜尋結果依相關性排序

#### 3.4 Learning Dashboard
- 專門的學習追蹤頁面：
  - LeetCode 進度
  - 書籍閱讀進度
  - 技術成長圖表
  - 按 topic/source/difficulty 瀏覽

#### 3.5 Decision Log 瀏覽
- `/admin/decisions` — 架構決策索引
- 按 project 過濾

#### 3.6 Obsidian Notes 瀏覽
- `/admin/notes` — Obsidian 筆記搜尋 + 瀏覽
- Frontmatter 過濾（type, context, source, book）

#### 3.7 Build Log 建立
- 在 admin 直接記錄開發 session
- Markdown 編輯器 + project 關聯

#### 3.8 Public Content 增強
- Essay 頁面（目前無獨立 route）
- Bookmark 頁面（推薦資源）
- Digest 頁面（週報/月報）
- Series 瀏覽（系列文章）

#### 3.9 效能優化
- Related articles server-side 預計算
- 大文章 markdown 增量 parsing
- Image lazy loading + CDN 優化

---

## 總結

### 數字摘要

| 指標 | 數量 |
|------|------|
| MCP Tools | 24 (14 Read + 10 Write) |
| Database Tables | 15 |
| SQL Queries | 99+ |
| HTTP Endpoints | 75+ |
| Frontend Routes | 35+ |
| Frontend Services | 26+ |
| Frontend Components | 40+ |

### 覆蓋率評估

| Domain | Backend 完整度 | Frontend 覆蓋 | Gap 嚴重度 |
|--------|---------------|--------------|-----------|
| Content CRUD | 🟢 完整 | 🟢 完整 | — |
| Projects | 🟢 完整 | 🟡 基本覆蓋 | 中 |
| Tasks | 🟢 完整 | 🔴 僅列表 | **高** |
| Goals | 🟢 完整 | 🔴 僅列表 | **高** |
| Session/Planning | 🟢 完整 | 🔴 幾乎沒有 | **高** |
| Insights | 🟢 完整 | 🔴 幾乎沒有 | 中 |
| Activity | 🟢 完整 | 🟡 基本列表 | 中 |
| Knowledge Search | 🟢 完整 | 🟡 公開搜尋有 | 中 |
| RSS/Feeds | 🟢 完整 | 🟡 管理有 | 低 |
| Learning | 🟢 完整 | 🟡 Dashboard 有 | 中 |
| Review/Polish | 🟢 完整 | 🟢 完整 | — |
| Pipeline | 🟢 完整 | 🔴 無 UI | 中 |

### 最大 Gap

**Task management、Goal updates、Session/Planning** — 這三塊是「每日使用」的核心功能，Backend 和 MCP 都已就緒，但 Frontend 幾乎只有 read-only 列表，無法互動操作。
