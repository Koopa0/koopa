# koopa0.dev 架構摘要

> 目的：讓另一個 Claude instance 理解系統全貌，以便規劃 Cowork plugin 和 MCP 擴展。
> 產出日期：2026-03-24

---

## 1. 前台 vs Admin Panel

### 1.1 技術邊界

**同一個 Angular 21 App，透過路由和 Guard 分離。** 不是獨立部署。

- 前台路由：`/`, `/articles`, `/projects`, `/til`, `/notes`, `/about`, `/uses`, `/tags/*` 等
- Admin 路由：`/admin/*`（15 個子路由），受 `authGuard` 保護
- 認證：Google OAuth → `/bff/api/auth/google` → JWT（存在 memory Signal，不用 localStorage）
- Admin 身份：後端 email allowlist 驗證
- SSR 策略：
  - **Server render**：動態內容頁（articles, projects, til, notes, tags）
  - **Prerender**：靜態頁（uses, about）
  - **Client render**：Admin 路由、login、oauth-callback
- BFF Proxy：Angular SSR server 攔截 `/bff/*` → 轉發到 `http://backend:8080`，帶 authorization/cookie/x-forwarded-for headers，上傳限制 10MB

### 1.2 前台頁面

| 路由 | 功能 |
|------|------|
| `/` | Landing page — 個人品牌首頁 |
| `/articles` | 文章列表（深度技術文章） |
| `/articles/:slug` | 文章詳情 |
| `/projects` | Portfolio — 專案展示 |
| `/projects/:slug` | 專案詳情（problem/solution/architecture/results） |
| `/til` | Today I Learned 列表 |
| `/til/:slug` | TIL 詳情 |
| `/notes` | 技術筆記列表 |
| `/notes/:slug` | 筆記詳情 |
| `/about` | 關於我（prerender） |
| `/uses` | 使用工具清單（prerender） |
| `/tags` | 標籤總覽 |
| `/tags/:slug` | 按標籤篩選內容 |
| `/privacy` | 隱私政策 |
| `/terms` | 服務條款 |
| `/login` | 登入頁（client render） |
| `/oauth-callback` | OAuth 回調（client render） |

### 1.3 Admin Panel 功能

| 路由 | 功能 |
|------|------|
| `/admin` | Dashboard（平台統計概覽） |
| `/admin/contents` | 內容列表管理（篩選、搜尋） |
| `/admin/contents/new` | 建立新內容 |
| `/admin/contents/:id/edit` | 編輯內容 |
| `/admin/projects` | 專案管理 |
| `/admin/projects/new` | 新增專案 |
| `/admin/projects/:id/edit` | 編輯專案 |
| `/admin/topics` | 主題管理 |
| `/admin/feeds` | RSS Feed 來源管理 |
| `/admin/collected` | 收集的外部資料審核 |
| `/admin/tracking` | 追蹤主題 + 關鍵字管理 |
| `/admin/tags` | 標籤管理（canonical + alias） |
| `/admin/notes` | Obsidian 筆記瀏覽 |
| `/admin/flow-runs` | AI Pipeline 執行紀錄 |
| `/admin/upload` | 檔案上傳（→ R2） |

### 1.4 API 權限分離

```
公開 API（無需認證）：
  GET /api/contents, /api/contents/search, /api/contents/{type}, /api/contents/{slug}
  GET /api/contents/{id}/related, /api/contents/graph
  GET /api/feed.xml, /sitemap.xml

Admin API（需 JWT + allowlist）：
  POST/PUT/DELETE /api/admin/contents/*
  POST /api/admin/contents/{id}/publish
  POST /api/admin/pipeline/sync
  POST /api/admin/cache-clear
  POST /api/admin/upload

Webhook（簽名驗證）：
  POST /api/webhooks/github   — X-Hub-Signature-256
  POST /api/webhooks/notion   — X-Notion-Signature (HMAC-SHA256)
```

---

## 2. MCP Server 完整 Tool 清單

MCP Server 位於 `internal/mcp/`，共 **29 個 tools**（21 讀取 / 8 寫入）。
分佈在 8 個檔案：`server.go`, `goal_tools.go`, `write_tools.go`, `delta_tools.go`, `insight_tools.go`, `weekly_tools.go`, `morning_context.go`, `reflection_context.go`。

### 2.1 讀取型 Tools（21 個）

| # | Tool | 用途 | 輸入參數 | 內部操作 |
|---|------|------|----------|----------|
| 1 | `search_notes` | 搜尋 Obsidian 筆記（文字 + frontmatter） | Query, Limit, Book, Context, Source, Type | notes.SearchByQuery + SearchByFrontmatter → RRF merge |
| 2 | `get_project_context` | 取得單一專案完整上下文 | Project (name/slug/alias) | projects.ProjectByName, activity.ByProject, notes.ByProject |
| 3 | `get_recent_activity` | 近期開發活動事件 | Days, Project, Source | activity.SinceWithFilter |
| 4 | `get_decision_log` | 架構決策紀錄 | Project, Limit | notes.DecisionLogByProject |
| 5 | `get_rss_highlights` | RSS 收集的文章 | Days, Limit | rss.RecentArticles |
| 6 | `get_platform_stats` | 平台全局統計快照 | DriftDays, IncludeDrift | contents.Stats, projects.Stats, activity.Stats, goals.Stats, learning.Stats |
| 7 | `get_pending_tasks` | 待辦任務（按緊急度排序） | Project, Limit | tasks.Pending |
| 8 | `search_knowledge` | 跨所有內容類型語義搜尋 | Query (required), Limit | contents.SemanticSearch + notes.SearchByQuery → RRF merge |
| 9 | `get_content_detail` | 取得完整文章/build-log/TIL 內容 | Slug (required) | contents.ContentBySlug |
| 10 | `list_projects` | 列出所有活躍專案 | Limit | projects.ActiveProjects |
| 11 | `get_goals` | 個人目標（從 Notion 同步） | Status, Area, Limit | goals.Goals / ByStatus / ByArea |
| 12 | `get_learning_progress` | 學習指標：筆記成長趨勢、top tags | (none) | learning.Progress, notes.StatsBy |
| 13 | `get_morning_context` | 每日規劃所需全部資訊（一次呼叫） | ActivityDays (default 3), BuildLogDays (default 7) | tasks.TodayAndOverdue, activity.SinceWithFilter, contents.RecentByType, projects.ActiveProjects, goals.Active, sessions.YesterdayReflection |
| 14 | `get_session_delta` | 上次 Claude session 後的變更差異 | Since (ISO date, default 上次 session) | tasks.CompletedSince, CreatedSince, activity.Since, contents.Since, insights.ChangedSince, sessions.NotesOfType |
| 15 | `get_weekly_summary` | 週報：任務完成、趨勢、專案健康度 | WeeksBack (0=current, max 4) | tasks.CompletedInWeek, projects.HealthInWeek, insights.ActivityInWeek, goals.AlignmentInWeek |
| 16 | `get_goal_progress` | 各目標進度：相關專案、完成率、是否 on-track | Days (default 30, max 90) | goals.Goals, projects.ActiveProjects, tasks.CompletedByProjectSince |
| 17 | `get_session_notes` | 取得 session notes（按日期/類型） | Date, Days, NoteType | sessions.NotesFor / NotesOfType |
| 18 | `get_reflection_context` | 晚間回顧所需資訊 | Date (default today) | sessions.PlanFor, tasks.CompletedOn, insights.UnverifiedFor |
| 19 | `get_active_insights` | 追蹤中的 insights（假設 + 觀察） | Status (default "unverified"), Project, Limit | insights.ActiveByStatus / ByProject |

### 2.2 寫入型 Tools（8 個）

| # | Tool | 用途 | 輸入參數 | 內部操作 | 寫入目標 |
|---|------|------|----------|----------|----------|
| 20 | `log_dev_session` | 記錄開發 session 為 build-log | Project (req), SessionType (req), Title (req), Body (req), Tags | contents.CreateDraft (source="build-log") | `contents` table (status=draft) |
| 21 | `complete_task` | 標記任務完成 | TaskID, TaskTitle, Notes | tasks.Complete, activity.RecordEvent, tasks.NextRecurrence | `tasks` + `activity_events` |
| 22 | `create_task` | 在 Notion 建立新任務 | Title (req), Project, Due, Priority, Energy, MyDay, Notes | tasks.Create, activity.RecordEvent | `tasks` + `activity_events` → Notion write-back |
| 23 | `update_task` | 更新任務屬性 | TaskID, TaskTitle, Status, Due, Priority, Energy, MyDay, Project, Notes | tasks.Update, activity.RecordEvent | `tasks` + `activity_events` → Notion write-back |
| 24 | `batch_my_day` | 設定今日 My Day 任務 | TaskIDs (req), Clear | tasks.SetMyDay / ClearMyDay, activity.RecordEvent | `tasks` (my_day flag) |
| 25 | `log_learning_session` | 記錄學習成果 | Topic (req), Source (req), Title (req), Body (req), Tags, Project, Difficulty, ProblemURL | contents.CreateDraft (source="learning"), activity.RecordEvent | `contents` + `activity_events` |
| 26 | `update_project_status` | 更新專案狀態（review 用） | Project (req), Status (req), ReviewNotes, ExpectedCadence | projects.UpdateStatus, activity.RecordEvent | `projects` + `activity_events` → Notion write-back |
| 27 | `update_goal_status` | 更新目標狀態 | GoalTitle (req), Status (req) | goals.UpdateStatus, activity.RecordEvent | `goals` + `activity_events` → Notion write-back |
| 28 | `save_session_note` | 儲存跨環境 session note | NoteType (req), Content (req), Source (req), Date, Metadata | sessions.SaveNote, activity.RecordEvent | `session_notes` + `activity_events` |
| 29 | `update_insight` | 更新 insight 狀態或追加證據 | InsightID (req), Status, AppendEvidence, AppendCounterEvidence, Conclusion | insights.Update, activity.RecordEvent | `session_notes` (insight metadata) + `activity_events` |

### 2.3 MCP 連接端點

MCP Server 同時註冊在兩個 MCP provider：
- `koopa0-knowledge`（Claude Code 本地連接）
- `claude_ai_koopa0_dev`（Claude.ai 遠端連接）

兩者 tool 清單完全一致，共用同一個 backend。

---

## 3. 內容發佈管線

### 3.1 內容生命週期

```
                    ┌─────────────────────────────────────┐
                    │           內容來源                    │
                    ├─────────────────────────────────────┤
                    │ 1. Admin Panel 手動建立              │
                    │ 2. Obsidian → GitHub webhook 同步    │
                    │ 3. MCP tool (log_dev_session 等)     │
                    │ 4. RSS 收集 → 人工 curate            │
                    └──────────────┬──────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │   contents (status=draft)  │
                    │   review_level=standard     │
                    └──────────────┬──────────────┘
                                   │
                        ┌──────────┴──────────┐
                        │  AI Pipeline (可選)   │
                        │  Genkit Flows:        │
                        │  - content analysis   │
                        │  - tag generation     │
                        │  - excerpt generation │
                        │  - proofreading       │
                        │  - polishing          │
                        └──────────┬──────────┘
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │  review_queue (可選)       │
                    │  status: pending/approved  │
                    └──────────────┬──────────────┘
                                   │
                          Admin 點擊 Publish
                    POST /api/admin/contents/{id}/publish
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │  contents (status=published) │
                    │  + 生成 embedding (pgvector)  │
                    │  + 設定 published_at          │
                    │  + 清除 RSS/Sitemap cache     │
                    └──────────────────────────────┘
```

### 3.2 各內容類型的建立方式

| 類型 | Enum 值 | 主要建立方式 | 說明 |
|------|---------|-------------|------|
| 深度文章 | `article` | Admin Panel 或 Obsidian 同步 | 需要完整 review |
| 個人隨筆 | `essay` | Admin Panel | 非技術反思 |
| Build Log | `build-log` | MCP `log_dev_session` 或 Admin | 開發 session 後自動記錄 |
| TIL | `til` | Admin Panel 或 Obsidian | 每日學習短文 |
| 技術筆記 | `note` | Obsidian → GitHub webhook | 自動同步 |
| 書籤 | `bookmark` | RSS 收集 → curate，或 Admin | 推薦資源 + 評語 |
| 週報/月報 | `digest` | AI Pipeline `digest_generate` flow | 自動生成 |

### 3.3 狀態管理

```
content_status enum: 'draft' → 'review' → 'published' → 'archived'
```

- **draft**：預設狀態，前台不可見
- **review**：進入審核佇列（review_queue table）
- **published**：前台可見，出現在 RSS/Sitemap
- **archived**：軟刪除

Review Level 決定審核嚴格程度：
- `auto`：AI 自動通過
- `light`：快速人工掃一眼
- `standard`：預設，標準審核
- `strict`：重要內容，完整審核

### 3.4 RSS Feed

- Endpoint：`GET /api/feed.xml`
- 內容：最新 20 篇 `status=published` 的內容
- Cache：Ristretto in-memory，10 分鐘 TTL
- Invalidation：PublishContent 時自動清除

### 3.5 Sitemap

- Endpoint：`GET /sitemap.xml`
- 內容：所有 `status=published` 的 slug
- Cache：30 分鐘 TTL

---

## 4. PostgreSQL 核心 Table Schema

### 4.1 Extensions

- `pgvector`：768 維向量嵌入

### 4.2 Enum Types

| Enum | 值 |
|------|----|
| `content_type` | article, essay, build-log, til, note, bookmark, digest |
| `content_status` | draft, review, published, archived |
| `source_type` | obsidian, notion, ai-generated, external, manual |
| `review_level` | auto, light, standard, strict |
| `review_status` | pending, approved, rejected, edited |
| `collected_status` | unread, read, curated, ignored |
| `project_status` | planned, in-progress, on-hold, completed, maintained, archived |
| `flow_status` | pending, running, completed, failed |
| `goal_status` | not-started, in-progress, done, abandoned |
| `task_status` | todo, in-progress, done |

### 4.3 Content 相關

#### `contents`
```sql
id              UUID PRIMARY KEY
slug            TEXT NOT NULL UNIQUE
title           TEXT
body            TEXT
excerpt         TEXT
type            content_type NOT NULL
status          content_status NOT NULL DEFAULT 'draft'
tags            TEXT[]                              -- 原始標籤陣列
source          TEXT                                -- 來源識別
source_type     source_type
series_id       TEXT                                -- 系列文章
series_order    INT
review_level    review_level NOT NULL DEFAULT 'standard'
ai_metadata     JSONB                               -- AI 處理結果
reading_time    INT                                 -- 預估閱讀時間（分鐘）
cover_image     TEXT
published_at    TIMESTAMPTZ
created_at      TIMESTAMPTZ
updated_at      TIMESTAMPTZ
embedding       vector(768)                         -- pgvector 語義嵌入
search_text     TEXT
search_vector   TSVECTOR GENERATED ALWAYS           -- 全文搜尋索引
-- Indexes: status, type, published_at, tags(GIN), search_vector(GIN), series, embedding(HNSW)
```

#### `content_topics`（junction）
```sql
content_id  UUID FK → contents(id) ON DELETE CASCADE
topic_id    UUID FK → topics(id) ON DELETE CASCADE
PRIMARY KEY (content_id, topic_id)
```

#### `topics`
```sql
id          UUID PRIMARY KEY
slug        TEXT NOT NULL UNIQUE
name        TEXT NOT NULL
description TEXT
icon        TEXT
sort_order  INT
```

#### `review_queue`
```sql
id              UUID PRIMARY KEY
content_id      UUID FK → contents(id) ON DELETE CASCADE
review_level    review_level NOT NULL
status          review_status NOT NULL DEFAULT 'pending'
reviewer_notes  TEXT
submitted_at    TIMESTAMPTZ
reviewed_at     TIMESTAMPTZ
-- Unique: 每個 content 只能有一個 pending review
```

#### `tags`（canonical 標籤）
```sql
id          UUID PRIMARY KEY
slug        TEXT NOT NULL UNIQUE
name        TEXT NOT NULL
parent_id   UUID FK → tags(id)              -- 階層式標籤
description TEXT
```

#### `tag_aliases`（原始標籤 → canonical 映射）
```sql
id           UUID PRIMARY KEY
raw_tag      TEXT NOT NULL UNIQUE
tag_id       UUID FK → tags(id)
match_method TEXT NOT NULL DEFAULT 'manual'  -- manual/fuzzy/exact
confirmed    BOOLEAN NOT NULL DEFAULT false
```

### 4.4 Activity 相關

#### `activity_events`
```sql
id          BIGSERIAL PRIMARY KEY
source_id   TEXT                            -- 外部系統 ID（dedup 用）
timestamp   TIMESTAMPTZ NOT NULL
event_type  TEXT NOT NULL                   -- e.g. "commit", "task.complete", "content.publish"
source      TEXT NOT NULL                   -- "github", "notion", "mcp", "manual"
project     TEXT                            -- 關聯專案名（非 FK，用 alias 解析）
repo        TEXT
ref         TEXT                            -- git ref
title       TEXT
body        TEXT
metadata    JSONB
created_at  TIMESTAMPTZ
-- Indexes: timestamp DESC, project, event_type
-- Unique: (source, event_type, source_id) 防重複
```

#### `activity_event_tags`（junction）
```sql
event_id  BIGINT FK → activity_events(id) ON DELETE CASCADE
tag_id    UUID FK → tags(id) ON DELETE CASCADE
```

### 4.5 Notion 同步相關

#### `projects`
```sql
id                UUID PRIMARY KEY
slug              TEXT NOT NULL UNIQUE
title             TEXT
description       TEXT
long_description  TEXT
role              TEXT                        -- 角色定位
area              TEXT                        -- 所屬領域
tech_stack        TEXT[]
highlights        TEXT[]
problem           TEXT                        -- Portfolio 展示用
solution          TEXT
architecture      TEXT
results           TEXT
github_url        TEXT
live_url          TEXT
repo              TEXT
featured          BOOLEAN
public            BOOLEAN
sort_order        INT
status            project_status NOT NULL DEFAULT 'in-progress'
notion_page_id    TEXT UNIQUE                 -- Notion 雙向同步 key
goal_id           UUID FK → goals(id) ON DELETE SET NULL
deadline          TIMESTAMPTZ
last_activity_at  TIMESTAMPTZ
expected_cadence  TEXT
```

#### `goals`
```sql
id              UUID PRIMARY KEY
title           TEXT
description     TEXT
status          goal_status NOT NULL DEFAULT 'not-started'
area            TEXT
quarter         TEXT                          -- e.g. "2026-Q1"
deadline        TIMESTAMPTZ
notion_page_id  TEXT UNIQUE                   -- Notion 雙向同步 key
```

#### `tasks`
```sql
id              UUID PRIMARY KEY
title           TEXT NOT NULL
status          task_status NOT NULL DEFAULT 'todo'
due             DATE
project_id      UUID FK → projects(id) ON DELETE SET NULL
notion_page_id  TEXT UNIQUE                   -- Notion 雙向同步 key
completed_at    TIMESTAMPTZ
energy          TEXT                          -- 能量等級
priority        TEXT
recur_interval  INT                           -- 重複任務間隔
recur_unit      TEXT                          -- day/week/month
my_day          BOOLEAN NOT NULL DEFAULT false
description     TEXT
```

#### `notion_sources`（Notion Database 註冊表）
```sql
id              UUID PRIMARY KEY
database_id     TEXT NOT NULL UNIQUE           -- Notion database ID
name            TEXT
description     TEXT
role            TEXT CHECK (IN 'projects','tasks','books','goals')
sync_mode       TEXT NOT NULL DEFAULT 'full'
property_map    JSONB NOT NULL DEFAULT '{}'    -- Notion property → DB column 映射
poll_interval   TEXT NOT NULL DEFAULT '15 minutes'
enabled         BOOLEAN NOT NULL DEFAULT true
last_synced_at  TIMESTAMPTZ
-- Unique: 每個 role 只能有一個 database
```

### 4.6 Obsidian 筆記

#### `obsidian_notes`
```sql
id              BIGSERIAL PRIMARY KEY
file_path       TEXT UNIQUE NOT NULL           -- Obsidian vault 內路徑
title           TEXT
type            TEXT                           -- frontmatter type
source          TEXT                           -- frontmatter source
context         TEXT
status          TEXT DEFAULT 'seed'
tags            JSONB
difficulty      TEXT
leetcode_id     INT
book            TEXT
chapter         TEXT
notion_task_id  TEXT                           -- 關聯 Notion task
content_text    TEXT
search_text     TEXT
content_hash    TEXT                           -- 內容 SHA → 判斷是否需更新
embedding       vector(768)
search_vector   TSVECTOR GENERATED ALWAYS
git_created_at  TIMESTAMPTZ
git_updated_at  TIMESTAMPTZ
synced_at       TIMESTAMPTZ DEFAULT now()
```

#### `note_links`（Obsidian wikilink 圖譜）
```sql
id              BIGSERIAL PRIMARY KEY
source_note_id  BIGINT FK → obsidian_notes(id) ON DELETE CASCADE
target_path     TEXT NOT NULL
link_text       TEXT
-- Unique: (source_note_id, target_path)
```

### 4.7 其他重要 Tables

#### `session_notes`（跨環境 context 橋樑）
```sql
id          BIGSERIAL PRIMARY KEY
note_date   DATE NOT NULL
note_type   TEXT NOT NULL                     -- plan/reflection/context/metrics/insight
source      TEXT NOT NULL                     -- claude/claude-code/manual
content     TEXT NOT NULL
metadata    JSONB                             -- insight 用：status, evidence 等
created_at  TIMESTAMPTZ
```

#### `collected_data`（RSS 收集的外部資料）
```sql
id                  UUID PRIMARY KEY
source_url          TEXT NOT NULL
source_name         TEXT
title               TEXT
original_content    TEXT
relevance_score     REAL                      -- 關鍵字匹配分數
topics              TEXT[]
status              collected_status DEFAULT 'unread'
curated_content_id  UUID FK → contents(id)    -- curate 後關聯的 content
url_hash            TEXT                      -- SHA-256 dedup
feed_id             UUID FK → feeds(id)
```

#### `feeds`（RSS 來源管理）
```sql
id                      UUID PRIMARY KEY
url                     TEXT NOT NULL UNIQUE
name                    TEXT NOT NULL
schedule                TEXT NOT NULL           -- cron expression
topics                  TEXT[]
enabled                 BOOLEAN DEFAULT true
etag                    TEXT                    -- HTTP conditional request
last_modified           TEXT
last_fetched_at         TIMESTAMPTZ
consecutive_failures    INT
last_error              TEXT
disabled_reason         TEXT
filter_config           JSONB DEFAULT '{}'
```

#### `flow_runs`（AI Pipeline 執行紀錄）
```sql
id            UUID PRIMARY KEY
flow_name     TEXT NOT NULL                   -- Genkit flow 名稱
content_id    UUID FK → contents(id)
input         JSONB NOT NULL
output        JSONB
status        flow_status DEFAULT 'pending'   -- pending/running/completed/failed
error         TEXT
attempt       INT
max_attempts  INT DEFAULT 3
started_at    TIMESTAMPTZ
ended_at      TIMESTAMPTZ
```

---

## 5. Notion 同步機制

### 5.1 同步範圍

| Notion Database | Role | 同步方向 | 對應 Table |
|-----------------|------|----------|------------|
| Projects DB | `projects` | 雙向 | `projects` |
| Tasks DB | `tasks` | 雙向 | `tasks` |
| Goals DB | `goals` | 雙向 | `goals` |
| Books DB | `books` | Notion → Backend | (book-related notes) |

### 5.2 同步機制

**觸發方式：**
1. Notion Webhook（`POST /api/webhooks/notion`）→ 即時同步
2. Admin 手動觸發（`POST /api/admin/pipeline/sync`）→ 全量同步
3. 定時 polling（`notion_sources.poll_interval`，預設 15 分鐘）

**安全保護：**
- Webhook 簽名驗證：HMAC-SHA256（X-Notion-Signature）
- Replay 防護：timestamp ±5 分鐘 + entity-level dedup
- 併發防護：`syncInFlight` map 防止同時多次同步
- Database list cache：10 分鐘 TTL

**同步流程：**
1. Webhook 進來 → 簽名驗證 → timestamp 檢查
2. 根據 `notion_sources.role` 判斷同步到哪個 table
3. Upsert：用 `notion_page_id` 做 match key
4. 寫回 Notion：MCP write tools（create_task, update_task, update_project_status, update_goal_status）會同時寫回 Notion
5. Orphan 處理：Notion 端刪除的 entity → 後端 archive

### 5.3 Property Mapping

`notion_sources.property_map`（JSONB）定義 Notion property name → DB column 的映射。每個 database 的 property 結構不同，透過這個 map 做轉換。

---

## 6. AI Pipeline（Genkit Flows）

位於 `internal/flow/`，共 18+ 個 flow 實作。

| Flow | 用途 | 觸發時機 |
|------|------|----------|
| `content` | 分析分類內容 | 建立/更新 content |
| `content_excerpt` | 生成摘要 | Publish 前 |
| `content_proofread` | 校對文法 | Review 階段 |
| `content_polish` | 潤飾文筆 | Review 階段 |
| `content_tags` | 生成語義標籤 | 建立 content |
| `content_strategy` | 內容策略建議 | 手動觸發 |
| `morning` | 晨間 briefing | 排程 |
| `daily_dev_log` | 每日開發日誌 | Session 結束 |
| `weekly` | 週報摘要 | 每週排程 |
| `digest_generate` | 生成完整 digest | 週/月排程 |
| `build_log` | 分析 build session | log_dev_session 後 |
| `bookmark` | 處理書籤 + 標註 | 收集 RSS 後 |
| `project_track` | 追蹤專案進度 | 定期 |

**執行紀錄**存在 `flow_runs` table，支援：
- 最多 3 次自動重試（`max_attempts`）
- `ErrContentBlocked` 永久失敗（不重試）
- Token budget 控制

---

## 7. Caching 策略

| 資源 | TTL | Invalidation |
|------|-----|--------------|
| RSS Feed | 10 min | PublishContent 時 |
| Sitemap | 30 min | PublishContent 時 |
| Knowledge Graph | 5 min | PublishContent + singleflight |
| Notion DB list | 10 min | Sync 完成時 |
| 手動清除 | — | `POST /api/admin/cache-clear` |

Cache 技術：Ristretto（in-memory, probabilistic eviction, single-machine）

---

## 8. 技術棧總覽

| 層 | 技術 |
|----|------|
| Frontend | Angular 21, Tailwind CSS v4, SSR, Signals |
| Backend | Go (net/http 1.22+ routing, 無框架) |
| Database | PostgreSQL + pgvector (pgx/v5) |
| Query Gen | sqlc |
| AI | Genkit Go |
| Cache | Ristretto |
| Messaging | NATS Core + JetStream |
| Logging | log/slog |
| Tracing | OpenTelemetry |
| Storage | Cloudflare R2 (上傳) |
| Auth | Google OAuth + JWT + refresh token |
| Integrations | GitHub webhooks, Notion API, RSS |
| Deploy | Docker, VPS |
