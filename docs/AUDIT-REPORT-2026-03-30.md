# koopa0.dev 專案現況審計報告

**掃描日期**: 2026-03-30
**Repo 路徑**: `/Users/koopa/koopa0.dev`
**產出方式**: Claude Code 自動掃描，所有數字來自實際命令執行結果

---

## 1. 系統拓撲概覽

### 目錄結構（2 層深度）

```
.
├── cmd/
│   ├── app/          → Go API entry point, cron jobs, config, wiring
│   └── mcp/          → MCP server entry point, config
├── internal/
│   ├── activity/     → Activity event tracking (GitHub, Obsidian, Notion events)
│   ├── ai/           → Genkit AI flows + exec runner + report sub-packages
│   │   ├── exec/     → Flow job runner, store, alerter
│   │   ├── prompts/  → System prompt text files (embedded via //go:embed)
│   │   └── report/   → Digest, morning, weekly, daily report flows
│   ├── api/          → Shared API response helpers
│   ├── auth/         → Google OAuth, JWT, refresh tokens
│   ├── budget/       → Daily AI token budget tracking
│   ├── content/      → Content CRUD, search, embeddings, RSS/sitemap generation
│   ├── db/           → sqlc-generated code (DO NOT EDIT)
│   ├── event/        → In-process event bus
│   ├── feed/         → RSS feed store + schedule definitions
│   │   ├── collector/→ Feed fetcher with concurrent collection
│   │   └── entry/    → Collected data (RSS items) store
│   ├── github/       → GitHub REST API client (contents, commits, compare)
│   ├── goal/         → Goal CRUD + Notion sync
│   ├── learning/     → Learning analytics (coverage matrix, weakness trends, timeline)
│   ├── mcp/          → MCP server: 54 tools across all domains│   ├── mcpauth/      → MCP OAuth2 authentication (Google OIDC)
│   ├── monitor/      → Tracking topics CRUD
│   ├── note/         → Obsidian note store, embedder, wikilink parsing
│   ├── notify/       → Notification providers (LINE, Telegram, multi, noop)
│   ├── notion/       → Notion API client, webhook handler, source registry, sync
│   ├── obsidian/     → Obsidian vault parsing (frontmatter, markdown)
│   ├── oreilly/      → O'Reilly Learning API client (search, book detail, chapter read)
│   ├── pipeline/     → Content sync, webhook router, manual triggers
│   ├── project/      → Project CRUD, Notion sync, alias resolution
│   ├── reconcile/    → Weekly Obsidian + Notion consistency check
│   ├── retrieval/    → FSRS spaced retrieval (cards, review logs, queue)
│   ├── review/       → Content review queue
│   ├── server/       → HTTP server, routes, middleware, metrics, log sanitizer
│   ├── session/      → Session notes (plan, reflection, insight, metrics)
│   ├── stats/        → Platform statistics (overview, drift, learning)
│   ├── tag/          → Canonical tag registry, aliases, backfill, merge
│   ├── task/         → Task CRUD, Notion sync, My Day, daily summary
│   ├── testdb/       → Shared testcontainers-go PostgreSQL setup
│   ├── topic/        → Topic CRUD
│   ├── upload/       → S3/R2 file upload
│   └── webhook/      → Webhook deduplication cache
├── migrations/       → SQL migration files
├── frontend/         → Angular 21 SSR application
├── scripts/          → Utility scripts
├── docs/             → Design documents
└── .claude/          → Claude Code configuration (agents, rules, skills, hooks)
```

### 量化指標

| 指標 | 數值 |
|------|------|
| Go 檔案總數 | 259 |
| Go 程式碼總行數 | 77,090 |
| 測試檔案數 | 103 |
| 測試程式碼行數 | 35,496 |
| 測試 : 產品碼比例 | 46% |
| Go 版本 | 1.26.1 |
| Module path | `github.com/Koopa0/koopa0.dev` |
| 直接依賴數量 | 24 |
| `internal/` 子 package 數 | 34（含子目錄 `ai/exec`, `ai/report`, `ai/prompts`, `feed/collector`, `feed/entry`） |
| sqlc query 檔案數 | 18 |
| sqlc 生成碼行數 | 8,294（`internal/db/query.sql.go`） |

### 直接依賴清單

| 依賴 | 用途 |
|------|------|
| `aws/aws-sdk-go-v2` + `s3` | Cloudflare R2 object storage |
| `dgraph-io/ristretto/v2` | In-memory cache (Notion source cache) |
| `firebase/genkit/go` | AI flow framework |
| `golang-jwt/jwt/v5` | JWT authentication |
| `golang-migrate/migrate/v4` | Database migrations |
| `google/go-cmp` | Test comparisons |
| `google/uuid` | UUID generation |
| `jackc/pgerrcode` | PostgreSQL error codes |
| `jackc/pgx/v5` | PostgreSQL driver |
| `mmcdole/gofeed` | RSS/Atom feed parsing |
| `modelcontextprotocol/go-sdk` | MCP server SDK |
| `open-spaced-repetition/go-fsrs/v4` | FSRS spaced repetition algorithm |
| `pgvector/pgvector-go` | pgvector Go bindings |
| `prometheus/client_golang` | Prometheus metrics |
| `robfig/cron/v3` | Cron scheduler |
| `testcontainers/testcontainers-go` + postgres module | Integration test DB |
| `golang.org/x/oauth2` | Google OAuth2 |
| `golang.org/x/sync` | errgroup, singleflight |
| `golang.org/x/time` | Rate limiter (Notion client) |
| `google.golang.org/genai` | Google Generative AI SDK |
| `gopkg.in/yaml.v3` | YAML parsing |

---

## 2. MCP Server — 工具盤點

### 已註冊工具列表（54 個）
MCP server name: `koopa0-knowledge`。所有工具最後修改日期：2026-03-30。

| # | 工具名稱 | 功能描述 | 有測試 |
|---|---------|---------|--------|
| 1 | `project_context` | 依名稱/slug/alias 取得單一專案完整上下文 | 間接（morning_test） |
| 2 | `recent_activity` | 取得最近開發活動事件，可依 source/project 過濾 | 間接 |
| 3 | `decision_log` | 取得 Obsidian 中 type=decision-log 的筆記 | 間接 |
| 4 | `rss_highlights` | 取得最近收集的 RSS 文章 | 間接 |
| 5 | `search_tasks` | 搜尋/列出任務，支援多條件過濾 | 間接 |
| 6 | `search_knowledge` | 跨所有內容類型搜尋 | ✅ search_test.go (5) |
| 7 | `content_detail` | 依 slug 取得完整內容 | ✅ content_test.go |
| 8 | `list_projects` | 列出所有進行中的專案 | 間接 |
| 9 | `learning_progress` | 學習指標：筆記成長、每週活動、標籤統計 | 間接 |
| 10 | `log_dev_session` | 記錄開發 session 為 build-log | ✅ write_test.go |
| 11 | `complete_task` | 標記任務完成 | ✅ write_test.go |
| 12 | `create_task` | 在 Notion 建立新任務 | ✅ write_test.go |
| 13 | `update_task` | 更新任務屬性 | ✅ write_test.go |
| 14 | `my_day` | 批次設定 Notion My Day | ✅ write_test.go |
| 15 | `log_learning_session` | 記錄學習成果（LeetCode 等） | ✅ write_test.go |
| 16 | `update_project_status` | 更新專案狀態 | ✅ write_test.go |
| 17 | `update_goal_status` | 更新目標狀態 | ✅ goals_test.go |
| 18 | `morning_context` | 每日規劃所需的完整上下文（一次呼叫） | ✅ morning_test.go (12) |
| 19 | `session_delta` | 上次 session 以來的變化 | ✅ delta_test.go (2) |
| 20 | `weekly_summary` | 每週綜合摘要 | ✅ weekly_test.go (3) |
| 21 | `goal_progress` | 目標進度追蹤 | ✅ goals_test.go |
| 22 | `save_session_note` | 儲存跨環境 session 筆記 | ✅ write_test.go |
| 23 | `session_notes` | 取得 session 筆記（依日期/類型） | 間接 |
| 24 | `reflection_context` | 晚間反思所需完整上下文 | 間接 |
| 25 | `active_insights` | 取得追蹤中的 insights（假說/觀察） | ✅ insights_test.go (6) |
| 26 | `update_insight` | 更新 insight 狀態或附加證據 | ✅ insights_test.go |
| 27 | `search_oreilly_content` | 搜尋 O'Reilly Learning 內容 | 無（條件註冊） |
| 28 | `oreilly_book_detail` | 取得 O'Reilly 書籍目錄 | 無（條件註冊） |
| 29 | `read_oreilly_chapter` | 讀取 O'Reilly 書籍章節 | 無（條件註冊） |
| 30 | `bookmark_rss_item` | 將 RSS 項目存為書籤 | ✅ content_test.go |
| 31 | `create_content` | 建立內容草稿 | ✅ content_test.go |
| 32 | `update_content` | 更新內容屬性 | ✅ content_test.go |
| 33 | `publish_content` | 發佈內容 | ✅ content_test.go |
| 34 | `list_content_queue` | 查看內容佇列 | ✅ content_test.go |
| 35 | `list_feeds` | 列出 RSS 訂閱 | ✅ feed_test.go (3) |
| 36 | `add_feed` | 新增 RSS 訂閱 | ✅ feed_test.go |
| 37 | `update_feed` | 更新 RSS 訂閱（啟用/停用） | ✅ feed_test.go |
| 38 | `remove_feed` | 刪除 RSS 訂閱 | ✅ feed_test.go |
| 39 | `collection_stats` | 收集管線統計 | 間接 |
| 40 | `system_status` | 系統可觀測性：flow runs、feed health | 間接（條件註冊） |
| 41 | `trigger_pipeline` | 手動觸發管線（rss_collector / notion_sync） | 間接（條件註冊） |
| 42 | `tag_summary` | 專案 TIL 的標籤頻率統計 | 間接 |
| 43 | `coverage_matrix` | 主題涵蓋矩陣（各 topic 練習次數/結果分佈） | 間接 |
| 44 | `weakness_trend` | 弱點標籤時間序列趨勢 | 間接 |
| 45 | `learning_timeline` | 學習項目按天分組 + 連續天數統計 | 間接 |
| 46 | `synthesize_topic` | 跨所有內容源的主題合成 | ✅ search_test.go |
| 47 | `find_similar_content` | 基於 embedding 的相似內容搜尋 | ✅ search_test.go |
| 48 | `log_retrieval_attempt` | 記錄 FSRS 間隔重複回測結果 | 間接（條件註冊） |
| 49 | `retrieval_queue` | 取得到期的間隔重複佇列 | 間接（條件註冊） |

備註：「條件註冊」表示該工具僅在特定環境變數存在時才註冊（O'Reilly: `ORM_JWT`; system_status/trigger_pipeline: `ADMIN_API_URL` + `JWT_SECRET` + `ADMIN_EMAIL`; retrieval: `retrieval != nil`）。

### MCP 測試檔案統計

| 測試檔案 | 測試函式數 |
|----------|-----------|
| `content_test.go` | 5 |
| `delta_test.go` | 2 |
| `feed_test.go` | 3 |
| `goals_test.go` | 1 |
| `insights_test.go` | 6 |
| `morning_test.go` | 12 |
| `search_test.go` | 5 |
| `security_test.go` | 17 |
| `server_test.go` | 7 |
| `weekly_test.go` | 3 |
| `write_test.go` | 7 |
| **合計** | **68 個測試函式** |

### 按功能域分群

| 功能域 | 工具數 | 工具名稱 |
|--------|--------|---------|
| 日常工作流 (Morning/Evening/Session) | 8 | `morning_context`, `session_delta`, `reflection_context`, `weekly_summary`, `save_session_note`, `session_notes`, `active_insights`, `update_insight` |
| 任務管理 | 5 | `search_tasks`, `create_task`, `complete_task`, `update_task`, `my_day` |
| 知識搜尋 | 5 | `search_knowledge`, `content_detail`, `synthesize_topic`, `find_similar_content`, `decision_log` |
| 內容管線 | 5 | `create_content`, `update_content`, `publish_content`, `list_content_queue`, `bookmark_rss_item` |
| RSS/Feed 管理 | 6 | `list_feeds`, `add_feed`, `update_feed`, `remove_feed`, `rss_highlights`, `collection_stats` |
| 專案/目標 | 5 | `list_projects`, `project_context`, `update_project_status`, `goal_progress`, `update_goal_status` |
| 學習分析 | 7 | `learning_progress`, `log_learning_session`, `tag_summary`, `coverage_matrix`, `weakness_trend`, `learning_timeline`, `log_dev_session` |
| O'Reilly 整合 | 3 | `search_oreilly_content`, `oreilly_book_detail`, `read_oreilly_chapter` |
| 系統運維 | 3 | `system_status`, `trigger_pipeline`, `recent_activity` |
| 間隔重複 (FSRS) | 2 | `log_retrieval_attempt`, `retrieval_queue` |

---

## 3. 資料層

### 資料庫物件統計

| 物件類型 | 數量 |
|----------|------|
| Tables | 27 |
| Indexes | 62 |
| Views | 2 |
| Enums | 10 |
| Migration 檔案 | 1（`001_initial.up.sql`，單一大檔案） |

### 所有 Table

| Table | 欄位數 | 說明 |
|-------|--------|------|
| `users` | 5 | 使用者帳號（email, role） |
| `refresh_tokens` | 5 | JWT refresh token |
| `topics` | 7 | 主題分類 |
| `contents` | 23 | 核心內容表（article, build-log, til, note 等） |
| `content_topics` | 2 | 內容↔主題多對多 |
| `projects` | 22 | 專案管理 |
| `review_queue` | 6 | 內容審核佇列 |
| `feeds` | 14 | RSS 訂閱設定 |
| `collected_data` | 12 | RSS 收集的原始資料 |
| `tracking_topics` | 7 | 追蹤主題設定 |
| `flow_runs` | 11 | AI flow 執行紀錄 |
| `goals` | 9 | 目標管理 |
| `tasks` | 16 | 任務管理（同步自 Notion） |
| `activity_events` | 11 | 統一活動事件日誌 |
| `obsidian_notes` | 18 | Obsidian 知識筆記 |
| `tags` | 6 | 正規化標籤系統 |
| `tag_aliases` | 6 | 標籤別名對應 |
| `obsidian_note_tags` | 2 | 筆記↔標籤多對多 |
| `activity_event_tags` | 2 | 活動↔標籤多對多 |
| `project_aliases` | 5 | 專案名稱別名 |
| `notion_sources` | 10 | Notion 資料來源設定 |
| `note_links` | 5 | Wikilink 連結圖 |
| `session_notes` | 6 | 跨環境 session 筆記 |
| `tool_call_logs` | 7 | MCP 工具呼叫遙測 |
| `reconcile_runs` | 12 | 每週一致性檢查歷史 |
| `fsrs_cards` | 7 | FSRS 間隔重複卡片狀態 |
| `fsrs_review_logs` | 7 | FSRS 回測歷史 |

### pgvector 使用

| Table | 欄位 | 維度 | Index 類型 |
|-------|------|------|-----------|
| `contents` | `embedding` | vector(768) | HNSW (vector_cosine_ops, m=16, ef_construction=64) |
| `obsidian_notes` | `embedding` | vector(768) | HNSW (vector_cosine_ops, m=16, ef_construction=64) |

### tsvector / Full-Text Search 使用

| Table | 欄位 | 生成方式 | Index |
|-------|------|---------|-------|
| `contents` | `search_vector` | GENERATED ALWAYS AS (title weight A + search_text weight C) STORED | GIN |
| `obsidian_notes` | `search_vector` | GENERATED ALWAYS AS (title weight A + search_text weight C) STORED | GIN |

### Views

| View | 用途 |
|------|------|
| `tool_usage_summary` | MCP 工具使用統計聚合（calls, avg_ms, p95, error_rate） |
| `tool_daily_trend` | 每日工具呼叫量趨勢 |

### Stored Procedures / Materialized Views

無。

---

## 4. Pipeline / Background Jobs

### Cron 排程（Asia/Taipei 時區）

| 排程 | Job 名稱 | 說明 | 觸發方式 |
|------|---------|------|---------|
| `@every 2m` | `retry-flows` | 重試失敗的 AI flow | Cron |
| `0 */4 * * *` | `feed-hourly_4` | 每 4 小時收集 RSS（hourly_4 schedule） | Cron |
| `0 6 * * *` | `feed-daily` | 每日 06:00 收集 daily schedule feeds | Cron |
| `0 6 * * 1` | `feed-weekly` | 每週一 06:00 收集 weekly schedule feeds | Cron |
| `0 0 * * *` | `budget-reset` | 重設每日 AI token 預算 | Cron |
| `0 1 * * *` | `token-cleanup` | 清理過期 refresh tokens | Cron |
| `0 3 * * *` | `retention-events` | 刪除 12 個月前的 activity events | Cron |
| `15 3 * * *` | `retention-ignored` | 刪除 30 天前的 ignored collected data | Cron |
| `30 3 * * *` | `retention-flowruns` | 刪除 90 天前的 completed flow runs | Cron |
| `45 3 * * *` | `retention-session-notes` | 刪除過期 session notes（plan/reflection 30 天; metrics/insight 365 天） | Cron |
| `30 7 * * *` | `morning-brief` | 早安摘要 AI flow | Cron → flow submit |
| `0 23 * * *` | `daily-dev-log` | 每日開發日誌 AI flow | Cron → flow submit |
| `0 3 * * 1` | `content-strategy` | 內容策略 AI flow | Cron → flow submit |
| `0 9 * * 1` | `weekly-review` | 週回顧 AI flow（含健康資料） | Cron → flow submit |
| `0 10 * * 1` | `build-log-generate` | 專案 build-log 生成 | Cron → flow submit |
| `0 4 * * 0` | `reconciliation` | 週日 Obsidian + Notion 一致性檢查 | Cron |
| `15 * * * *` | `hourly-sync` | 每小時 GitHub + Notion 全同步 | Cron（overlap guarded） |
| `30 * * * *` | `note-embedding` | 生成缺失的 Obsidian note embeddings（每次上限 20） | Cron（非 mock mode 才啟用） |
| `35 * * * *` | `content-embedding` | 生成缺失的 content embeddings（每次上限 20） | Cron（非 mock mode 才啟用） |

### 手動觸發管線

| 管線 | 觸發方式 |
|------|---------|
| `rss_collector` | MCP `trigger_pipeline` / HTTP `POST /api/admin/pipeline/collect` |
| `notion_sync` | MCP `trigger_pipeline` / HTTP `POST /api/admin/pipeline/notion-sync` |
| `obsidian_sync` | HTTP `POST /api/admin/pipeline/sync` |
| `reconcile` | HTTP `POST /api/admin/pipeline/reconcile` |
| `content_generate` | HTTP `POST /api/admin/pipeline/generate` |
| `digest` | HTTP `POST /api/admin/pipeline/digest` |
| `bookmark` | HTTP `POST /api/admin/pipeline/bookmark` |

### Startup Sync

啟動時自動執行 `contentSync.SyncAllFromGitHub` + `notionHandler.SyncAll`，timeout 5 分鐘。

---

## 5. 外部整合

| 整合 | 模式 | 程式碼位置 | 說明 |
|------|------|-----------|------|
| **Notion API** | Read-Write | `internal/notion/client.go` | Rate-limited (3 req/s)。讀取/同步 projects, tasks, goals, books。Webhook 接收 page updates。 |
| **GitHub REST API** | Read-only | `internal/github/github.go` | 讀取 repo contents (Obsidian vault), commits, compare diffs。max response 10MB。 |
| **GitHub Webhooks** | Read-only (inbound) | `internal/pipeline/webhook.go` | 接收 push events 觸發 Obsidian 同步 |
| **Google OAuth2** | Read-only | `internal/auth/handler.go` | Google login for admin auth |
| **Google Generative AI (Gemini)** | Read-only | `internal/ai/pipeline.go` | 透過 Genkit plugin: `googlegenai.GoogleAI` |
| **Anthropic (Claude)** | Read-only | `internal/ai/pipeline.go` | 透過 Genkit plugin: `anthropic.Anthropic` |
| **Cloudflare R2 (S3-compatible)** | Read-Write | `internal/upload/` | 圖片/檔案上傳至 R2 bucket |
| **O'Reilly Learning API** | Read-only | `internal/oreilly/oreilly.go` | 搜尋書籍、取得目錄、讀取章節。需 `ORM_JWT`。Max response 5MB。 |
| **LINE Messaging API** | Write-only | `internal/notify/line.go` | 推送通知（morning brief, alerts） |
| **Telegram Bot API** | Write-only | `internal/notify/telegram.go` | 推送通知（morning brief, alerts） |
| **RSS/Atom Feeds** | Read-only | `internal/feed/collector/collector.go` | 透過 `gofeed` 解析。19 個 seed feeds（schema 中定義）。 |

---

## 6. Content Pipeline

### 內容類型

已定義的 `content_type` enum（7 種）：

| 類型 | SQL 定義 | 說明 |
|------|---------|------|
| `article` | ✅ | 深度技術文章 |
| `essay` | ✅ | 個人想法/非技術反思 |
| `build-log` | ✅ | 專案開發紀錄 |
| `til` | ✅ | 每日學習（短） |
| `note` | ✅ | 技術筆記片段 |
| `bookmark` | ✅ | 推薦資源 + 個人評語 |
| `digest` | ✅ | 週報/月報 |

### Content Lifecycle Stages

`content_status` enum（4 階段）：

```
draft → review → published → archived
```

- `draft`: 初始狀態，來自 MCP `create_content` / Obsidian sync / `bookmark_rss_item`
- `review`: 進入 `review_queue` 等待審核
- `published`: 發佈後可被公開 API 取得
- `archived`: 歸檔

### 審核分級

`review_level` enum（4 級）：`auto`, `light`, `standard`, `strict`

`review_status` enum（4 種）：`pending`, `approved`, `rejected`, `edited`

### AI-assisted 環節

14 個已定義的 Genkit flows 組成 AI 管線：

| Flow 名稱 | 功能 | 觸發方式 |
|-----------|------|---------|
| `content-review` | 內容品質審查 | Pipeline 自動 |
| `content-proofread` | 校對 | Pipeline 自動 |
| `content-excerpt` | 生成摘要 | Pipeline 自動 |
| `content-tags` | 自動標籤 | Pipeline 自動 |
| `content-polish` | 內容潤色 | Admin 手動觸發 |
| `bookmark-generate` | 從 RSS item 生成書籤內容 | MCP/Admin 觸發 |
| `content-strategy` | 每週內容策略 | Cron (每週一 03:00) |
| `project-track` | 專案追蹤報告 | Pipeline 觸發 |
| `build-log-generate` | 自動生成 build log | Cron (每週一 10:00) |
| `digest-generate` | 週報/月報生成 | Admin 手動觸發 |
| `morning-brief` | 每日早安摘要 | Cron (每日 07:30) |
| `weekly-review` | 每週回顧 | Cron (每週一 09:00) |
| `daily-dev-log` | 每日開發日誌 | Cron (每日 23:00) |

### 發佈目標

- Angular 21 SSR 前端（透過 REST API 取得內容）
- 公開 API endpoints: `GET /api/contents`, `GET /api/contents/{slug}`, `GET /api/feed/rss`, `GET /api/feed/sitemap`

---

## 7. Genkit / AI Flows

### 模型設定

| 設定 | 預設值 | 來源 |
|------|--------|------|
| `GEMINI_MODEL` | `gemini-3-flash-preview` | 環境變數 |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | 環境變數 |
| `MOCK_MODE` | `false` | 環境變數（`true` 時所有 flow 回傳 canned responses） |

### Genkit Plugins

- `googlegenai.GoogleAI` (Gemini)
- `anthropic.Anthropic` (Claude)

### Embedder

由 Genkit googlegenai plugin 提供（非 mock mode）。用於 `obsidian_notes.embedding` 和 `contents.embedding`，維度 768。

### Flow 清單（14 個）

| Flow | 定義位置 | 輸入 | 輸出 | 使用模型 |
|------|---------|------|------|---------|
| `content-review` | `ai/content.go` | Content JSON | Review result JSON | Gemini |
| `content-proofread` | `ai/proofread.go` | Content JSON | Proofread result JSON | Gemini |
| `content-excerpt` | `ai/excerpt.go` | Content JSON | Excerpt JSON | Gemini |
| `content-tags` | `ai/tags.go` | Content JSON | Tags JSON | Gemini |
| `content-polish` | `ai/polish.go` | Content JSON | Polished content JSON | Gemini |
| `bookmark-generate` | `ai/bookmark.go` | RSS item JSON | Bookmark content JSON | Gemini |
| `content-strategy` | `ai/content_strategy.go` | (no input) | Strategy JSON | Gemini |
| `project-track` | `ai/project_track.go` | Project JSON | Track result JSON | Gemini |
| `build-log-generate` | `ai/build_log.go` | Build data JSON | Build log JSON | Claude |
| `digest-generate` | `ai/report/digest.go` | (configurable input) | Digest JSON | Gemini |
| `morning-brief` | `ai/report/morning.go` | (no input) | Morning brief text | —（無 LLM，純 data aggregation） |
| `weekly-review` | `ai/report/weekly.go` | (configurable input) | Weekly review JSON | Gemini |
| `daily-dev-log` | `ai/report/daily.go` | (configurable input) | Daily dev log JSON | Gemini |

### System Prompt 模板（12 個 .txt 檔案）

所有 prompts 透過 `//go:embed prompts/<name>.txt` 嵌入。

| 檔案 | 對應 Flow |
|------|----------|
| `review.txt` | `content-review` |
| `excerpt.txt` | `content-excerpt` |
| `tags.txt` | `content-tags` |
| `polish.txt` | `content-polish` |
| `digest.txt` | `digest-generate` |
| `bookmark.txt` | `bookmark-generate` |
| `weekly_review.txt` | `weekly-review` |
| `project_track.txt` | `project-track` |
| `content_strategy.txt` | `content-strategy` |
| `build_log.txt` | `build-log-generate` |
| `daily_dev_log.txt` | `daily-dev-log` |
| `morning_brief.txt` | `morning-brief`（但該 flow 不使用 LLM） |

### Token Budget

每日 AI token 預算上限：500,000（在 `cmd/app/main.go` 中 hardcoded: `budget.New(500_000)`）。每日 00:00 (Asia/Taipei) 重設。

---

## 8. 前端 / 展示層

### 技術

- **框架**: Angular 21
- **CSS**: Tailwind CSS v4
- **渲染**: SSR (Server-Side Rendering) via `@angular/ssr`
- **Runtime**: Node.js 22 Alpine
- **Port**: 4000

### 前端規模

| 指標 | 數值 |
|------|------|
| TypeScript + HTML 檔案數（不含 node_modules/dist） | 256 |
| Component 檔案數（*.component.ts） | 18 |

### 公開頁面（26 個 page 目錄）

`home`, `about`, `articles`, `article-detail`, `bookmarks`, `build-logs`, `build-log-detail`, `essays`, `essay-detail`, `notes`, `note-detail`, `tils`, `til-detail`, `projects`, `project-detail`, `topics`, `topic-detail`, `tag`, `search`, `login`, `uses`, `privacy`, `terms`, `error`, `not-found`

### Admin 頁面（27 個目錄）

`dashboard`, `today`, `planning`, `contents`, `article-editor`, `project-editor`, `projects`, `review`, `collected`, `feeds`, `flow-runs`, `goals`, `tasks`, `tags`, `tracking`, `notion-sources`, `knowledge-metrics`, `insights`, `session-notes`, `journal`, `activity`, `pipeline`, `inbox`, `oauth-callback`, `admin-layout`, `shared`

### 部署

透過 `docker-compose.yml` 的 `frontend` service，反向代理至 backend。

### 公開 URL

⚠️ 無法從 code 確認。domain `koopa0.dev` 在 Dockerfile 和 docker-compose 中被引用。

---

## 9. 部署與基礎設施

### 部署目標

- **VPS** (self-hosted)，透過 SSH 部署
- Domain: `koopa0.dev`

### Docker 設定

| Container | Base Image | Multi-stage | Port |
|-----------|-----------|-------------|------|
| `backend` | `golang:1.26.1-alpine3.23` → `alpine:3.21` | ✅ 2-stage | 8080 |
| `mcp` | `golang:1.26.1-alpine3.23` → `alpine:3.21` | ✅ 2-stage | 8081 |
| `frontend` | `node:22-alpine` (build) → `node:22-alpine` (runtime) | ✅ 2-stage | 4000 |
| `postgres` | `pgvector/pgvector:pg17` | — | 5432 (internal) |

### Docker Compose 網路

- `frontend` network: frontend + backend
- `backend` network: backend + postgres + mcp

### 安全加固

所有 container 設定：`read_only: true`, `no-new-privileges: true`, `cap_drop: ALL`, memory limits。
Backend/frontend 使用 non-root `app` user。

### CI/CD

- **GitHub Actions**: `.github/workflows/deploy.yml`
- **觸發**: push to `main`
- **方式**: SSH 至 VPS → `git pull` → `docker compose up -d --build`
- **Health check**: 部署後逐一檢查 backend (`/healthz`) 和 mcp (`/healthz`)，30s timeout
- **Grafana 靜默**: 部署期間自動靜默 Grafana alerts（5 分鐘窗口）

### 環境變數（Backend，28 個）

**Required**: `DATABASE_URL`, `JWT_SECRET`, `GITHUB_WEBHOOK_SECRET`, `R2_ENDPOINT`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_PUBLIC_URL`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`, `ADMIN_EMAIL`, `GEMINI_API_KEY`（非 mock mode）, `ANTHROPIC_API_KEY`（非 mock mode）

**Optional**: `NOTION_API_KEY`, `NOTION_WEBHOOK_SECRET`, `GITHUB_TOKEN`, `GITHUB_REPO`, `GITHUB_BOT_LOGIN`, `LINE_CHANNEL_TOKEN`, `LINE_USER_ID`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `MOCK_MODE`, `GEMINI_MODEL`, `CLAUDE_MODEL`, `SERVER_PORT`, `CORS_ORIGIN`, `SITE_URL`, `R2_BUCKET`

### MCP Server 環境變數

`DATABASE_URL`, `MCP_TOKEN`, `MCP_TRANSPORT`, `MCP_PORT`, `NOTION_API_KEY`, `ORM_JWT`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `ADMIN_EMAIL`, `ADMIN_API_URL`, `JWT_SECRET`

---

## 10. 測試與品質

### 測試概覽

| 指標 | 數值 |
|------|------|
| 測試檔案數 | 103 |
| 測試程式碼行數 | 35,496 |
| Integration test 檔案數（`//go:build integration` tag） | 8 |
| Integration test 位置 | `note`, `reconcile`, `content`, `server`, `notion`, `ai/exec`, `task`, `tag` |
| Shared test helper | `internal/testdb/testdb.go`（testcontainers-go PostgreSQL） |

### Integration vs Unit Test 區分

- Integration tests 使用 `//go:build integration` build tag
- 需要 PostgreSQL 的測試使用 `testcontainers-go` 自動啟動容器
- Unit tests 無 build tag，直接 `go test ./...`

### Linter 設定

`golangci-lint` v2 設定檔：`.golangci.yaml`

**啟用的 linters（23 個）**：
`errcheck`, `errorlint`, `errname`, `staticcheck`, `govet`, `gocritic`, `gosec`, `ineffassign`, `unused`, `unconvert`, `unparam`, `wastedassign`, `misspell`, `whitespace`, `copyloopvar`, `intrange`, `gocyclo`, `gocognit`, `nestif`, `exhaustive`, `prealloc`, `nolintlint`

**複雜度閾值**：
- `gocyclo`: min 15
- `gocognit`: min 20
- `nestif`: min 4

**排除規則**：
- `_test.go` 檔案排除 `gocyclo`, `gocognit`, `errcheck`, `unparam`
- `internal/db/` 排除所有 linters（generated code）

### 每 package 測試覆蓋

| Package | Go 檔案 | 測試檔案 | 有測試 |
|---------|---------|---------|--------|
| activity | 7 | 2 | ✅ |
| ai | 15 | 2 | ✅ |
| api | 4 | 3 | ✅ |
| auth | 6 | 2 | ✅ |
| budget | 2 | 1 | ✅ |
| content | 11 | 5 | ✅ |
| db | 4 | 0 | — (generated) |
| event | 2 | 1 | ✅ |
| feed | 5 | 2 | ✅ |
| github | 2 | 1 | ✅ |
| goal | 6 | 2 | ✅ |
| learning | 11 | 6 | ✅ |
| mcp | 26 | 11 | ✅ |
| mcpauth | 4 | 3 | ✅ |
| monitor | 4 | 1 | ✅ |
| note | 8 | 3 | ✅ |
| notify | 4 | 1 | ✅ |
| notion | 14 | 5 | ✅ |
| obsidian | 9 | 5 | ✅ |
| oreilly | 2 | 1 | ✅ |
| pipeline | 10 | 4 | ✅ |
| project | 5 | 1 | ✅ |
| reconcile | 7 | 4 | ✅ |
| retrieval | 4 | 1 | ✅ |
| review | 5 | 2 | ✅ |
| server | 9 | 4 | ✅ |
| session | 5 | 2 | ✅ |
| stats | 4 | 1 | ✅ |
| tag | 6 | 3 | ✅ |
| task | 6 | 2 | ✅ |
| testdb | 1 | 0 | — (helper) |
| topic | 4 | 1 | ✅ |
| upload | 5 | 2 | ✅ |
| webhook | 7 | 5 | ✅ |

所有非 generated、非 helper package 都有測試檔案。

---

## 11. 程式碼健康度指標

### 最大的 5 個 .go 檔案

| 檔案 | 行數 |
|------|------|
| `internal/db/query.sql.go` | 8,294（generated，不可手動編輯） |
| `internal/mcp/morning_test.go` | 1,337 |
| `internal/feed/schedule_test.go` | 1,235 |
| `internal/mcp/search.go` | 1,186 |
| `internal/mcp/morning.go` | 1,170 |

### TODO / FIXME / HACK 標記

**0 個**。grep 搜尋 `TODO`, `FIXME`, `HACK`, `XXX` 在所有 `.go` 和 `.sql` 檔案中未發現任何結果。

### Hardcoded 值

| 位置 | 值 | 說明 |
|------|---|------|
| `cmd/app/main.go:140` | `budget.New(500_000)` | 每日 AI token 預算上限 hardcoded 為 500,000 |
| `docker-compose.yml` | `POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}` | 有 env var fallback，但預設值為 `changeme` |
| `docker-compose.yml` | `JWT_SECRET: ${JWT_SECRET:-change-me-in-production}` | 有 env var fallback，但預設值為 `change-me-in-production` |

### Hardcoded Credentials

未在 Go source code 中發現 hardcoded API keys 或 secrets。所有 credentials 透過環境變數注入。

### Dead Code 跡象

⚠️ 未執行完整的 dead code 分析（需 `go vet` + `unused` linter 實際執行）。Linter 設定中已啟用 `unused` linter。

---

## 12. 功能完成度矩陣

| 功能 | 狀態 | 證據 |
|------|------|------|
| **內容管理 CRUD** | ✅ 完整 | `internal/content/` 11 files, 5 test files; 6 HTTP endpoints; MCP tools |
| **內容審核佇列** | ✅ 完整 | `internal/review/` 5 files, 2 test files; 4 HTTP endpoints |
| **Topic 分類** | ✅ 完整 | `internal/topic/` 4 files, 1 test file; CRUD endpoints; 24 seed topics |
| **Tag 系統（正規化+別名）** | ✅ 完整 | `internal/tag/` 6 files, 3 test files; backfill + merge + alias endpoints |
| **專案管理** | ✅ 完整 | `internal/project/` 5 files, 1 test file; Notion sync; alias resolution |
| **目標管理** | ✅ 完整 | `internal/goal/` 6 files, 2 test files; Notion sync |
| **任務管理** | ✅ 完整 | `internal/task/` 6 files, 2 test files; Notion sync; My Day; daily summary |
| **Google OAuth 登入** | ✅ 完整 | `internal/auth/` 6 files, 2 test files; JWT + refresh tokens |
| **RSS/Atom 收集** | ✅ 完整 | `internal/feed/` + `collector/` + `entry/`; 19 seed feeds; schedule-based collection |
| **Obsidian 同步** | ✅ 完整 | `internal/obsidian/` 9 files, 5 test files; `pipeline/content_sync.go`; wikilink parsing; note embeddings |
| **Notion 雙向同步** | ✅ 完整 | `internal/notion/` 14 files, 5 test files; webhook handler; source registry; project/task/goal sync |
| **GitHub Webhook** | ✅ 完整 | `internal/pipeline/webhook.go`; push event → Obsidian sync; deduplication |
| **AI Content Pipeline** | ✅ 完整 | `internal/ai/` 15 files; 14 flows; mock mode; token budget; structured output |
| **Flow 執行引擎** | ✅ 完整 | `internal/ai/exec/` 7 files; runner with retry; alerter; Prometheus metrics observer |
| **MCP Server** | ✅ 完整 | `internal/mcp/` 26 files, 11 test files; 54 tools; HTTP transport; OAuth2 auth || **MCP OAuth2 認證** | ✅ 完整 | `internal/mcpauth/` 4 files, 3 test files |
| **Session Notes 跨環境** | ✅ 完整 | `internal/session/` 5 files, 2 test files; plan/reflection/insight/metrics types |
| **活動事件追蹤** | ✅ 完整 | `internal/activity/` 7 files, 2 test files; multi-source event log |
| **學習分析** | ✅ 完整 | `internal/learning/` 11 files, 6 test files; coverage matrix, tag summary, weakness trend, timeline |
| **O'Reilly 整合** | ✅ 完整 | `internal/oreilly/` 2 files, 1 test file; search, book detail, chapter read |
| **S3/R2 上傳** | ✅ 完整 | `internal/upload/` 5 files, 2 test files |
| **通知系統** | ✅ 完整 | `internal/notify/` 4 files, 1 test file; LINE + Telegram + multi + noop |
| **每週一致性檢查** | ✅ 完整 | `internal/reconcile/` 7 files, 4 test files; Obsidian + Notion drift detection |
| **FSRS 間隔重複** | ✅ 完整 | `internal/retrieval/` 4 files, 1 test file; fsrs_cards + review_logs tables; MCP tools |
| **Prometheus Metrics** | ✅ 完整 | `internal/server/metrics.go`; `GET /metrics` endpoint; flow duration observer |
| **Platform Stats** | ✅ 完整 | `internal/stats/` 4 files, 1 test file; overview + drift + learning endpoints |
| **Tracking Topics** | ✅ 完整 | `internal/monitor/` 4 files, 1 test file; CRUD endpoints |
| **Event Bus** | ✅ 完整 | `internal/event/` 2 files, 1 test file; in-process pub/sub |
| **Webhook Deduplication** | ✅ 完整 | `internal/webhook/` 7 files, 5 test files; TTL-based dedup cache |
| **Token Budget** | ✅ 完整 | `internal/budget/` 2 files, 1 test file; daily reset via cron |
| **Tool Call Telemetry** | ✅ 完整 | `tool_call_logs` table + 2 views; MCP server records per-call metrics |
| **Angular 前端 (Public)** | ✅ 完整 | 26 public pages; SSR; Tailwind v4 |
| **Angular 前端 (Admin)** | ✅ 完整 | 27 admin sections; authenticated |
| **知識圖譜** | ⚠️ 部分 | `GET /api/knowledge-graph` endpoint exists; `note_links` table for wikilinks; 前端 page 未見獨立 knowledge-graph page |
| **Full-Text Search** | ✅ 完整 | tsvector on `contents` + `obsidian_notes`; GIN indexes; `GET /api/search` endpoint; MCP `search_knowledge` |
| **Semantic Search (Vector)** | ✅ 完整 | pgvector HNSW on both tables; `find_similar_content` MCP tool; hourly embedding generation |
| **Data Retention** | ✅ 完整 | 4 cron jobs for cleanup: events (12mo), ignored items (30d), flow runs (90d), session notes (30d/365d) |
| **Graceful Shutdown** | ✅ 完整 | Signal handling; 5-minute hard deadline; pipeline drain; cron stop; pool close |
| **Wikilink Graph** | ✅ 完整 | `note_links` table; `obsidian/parser.go` extracts [[links]]; bidirectional resolution |

### HTTP API 統計

| 類別 | Endpoint 數 |
|------|------------|
| Public API | 12 |
| Auth | 3 |
| Admin | 91 |
| Webhooks | 2 |
| **Total** | **108** |

---

## 附錄：Per-Package 檔案明細

34 個 `internal/` packages（含子 package），全部遵循 package-by-feature 結構。
每個 feature package 包含：types (`<feature>.go`), handler (`handler.go`), store (`store.go`), queries (`query.sql`), tests (`<feature>_test.go`)。
無 `services/`, `repositories/`, `models/`, `domain/`, `util/` 等被禁止的目錄名稱。
