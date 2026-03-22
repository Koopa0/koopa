# koopa0.dev — 系統架構

## System Overview

koopa0.dev 是一個 Personal Operating System——整合 Notion（tasks/projects/goals）、GitHub（commits/activity）、Obsidian（knowledge notes）三個事件源的個人知識引擎。不是 Information Management System，因為它不只存放資訊，而是主動處理、聚合、生成洞察，形成完整的 Plan → Execute → Reflect → Learn 閉環。

核心身份：**Obsidian 是大腦，AI Pipeline 是編輯團隊，Angular 網站是出版物，RSS/API 收集工具是耳目，MCP 是 Claude 的操作介面。**

---

## Data Flow

```
┌─────────────────── Event Sources ───────────────────┐
│                                                      │
│  Notion (API + Webhook)     GitHub (Webhook)         │
│  ├── tasks                  ├── commits              │
│  ├── projects               ├── push events          │
│  └── goals                  └── diff stats           │
│                                                      │
│  Obsidian (Git push → webhook)   RSS Feeds (Cron)    │
│  ├── knowledge notes             ├── tech articles   │
│  ├── wikilinks                   └── relevance score │
│  └── embeddings                                      │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌────────────── PostgreSQL (Storage) ──────────────────┐
│                                                      │
│  Event Store          Content Store                  │
│  ├── activity_events  ├── contents (+ embeddings)    │
│  └── session_notes    ├── review_queue               │
│     (plan/reflect/    ├── collected_data              │
│      metrics/insight) └── obsidian_notes (+ embeddings)│
│                                                      │
│  Knowledge Store      Entity Store                   │
│  ├── tags + aliases   ├── tasks                      │
│  ├── note_links       ├── goals                      │
│  ├── topics           ├── projects                   │
│  └── tracking_topics  └── notion_sources             │
└──────────────────────┬───────────────────────────────┘
                       │
              ┌────────┴────────┐
              ▼                 ▼
┌──── MCP Server ────┐  ┌── HTTP API ──────┐
│  (Claude 操作介面)  │  │  (Angular 前端)   │
│                     │  │                   │
│  Read Tools:        │  │  Public:          │
│  - morning_context  │  │  - contents       │
│  - pending_tasks    │  │  - topics         │
│  - search_knowledge │  │  - projects       │
│  - active_insights  │  │  - rss/sitemap    │
│  - project_context  │  │  - search         │
│                     │  │                   │
│  Write Tools:       │  │  Admin:           │
│  - complete_task    │  │  - content CRUD   │
│  - save_session_note│  │  - review queue   │
│  - update_insight   │  │  - collected data │
│  - create_task      │  │  - task/goal mgmt │
│  - batch_my_day     │  │  - flow runs      │
└─────────────────────┘  └───────────────────┘
              │                 │
              ▼                 ▼
┌──── Write-Back Paths ───────────────────────┐
│                                              │
│  Claude sessions:                            │
│  - session_notes (plan/reflection/metrics)   │
│  - task status updates → Notion API          │
│  - insight tracking (hypothesis lifecycle)   │
│                                              │
│  Angular admin:                              │
│  - content publish/edit                      │
│  - review approve/reject                     │
│  - collected data curation                   │
│  - task/goal/project status                  │
└──────────────────────────────────────────────┘
```

### Source of Truth 分工

| Domain | Source of Truth | PostgreSQL 角色 |
|--------|----------------|-----------------|
| Tasks, Projects, Goals | Notion | 同步副本 + 本地擴充欄位（my_day, energy, priority） |
| Knowledge Notes | Obsidian vault (via Git) | 同步副本 + embeddings + search index |
| Metrics, Insights | PostgreSQL (session_notes) | 原生儲存，Claude 寫入 |
| Published Content | PostgreSQL (contents) | 原生儲存，前端和 admin 消費 |
| Activity Events | PostgreSQL (activity_events) | 原生儲存，多源聚合 |
| RSS Articles | PostgreSQL (collected_data) | 原生儲存，feed collector 寫入 |

---

## Component Boundaries

### Domain 劃分與職責

```
internal/
├── task/         Tasks（Notion 同步，My Day 管理，recurrence）
├── session/      Session Notes（plan/reflection/metrics/insight 跨環境上下文橋）
├── activity/     Activity Events（GitHub/Obsidian/manual 事件聚合，session 重建）
├── content/      Published Content（文章/TIL/bookmark，knowledge graph，semantic search）
├── goal/         Goals（Notion 同步，status lifecycle）
├── project/      Projects（portfolio case studies，Notion 同步，aliases）
├── note/         Obsidian Notes（vault sync，wikilinks，embeddings，full-text search）
├── tag/          Tag System（canonical tags，4-step alias resolution，hierarchy）
├── topic/        Content Topics（分類 taxonomy，seed data）
├── collected/    Collected Data（RSS 文章，relevance scoring，curation）
├── feed/         Feed Sources（RSS 訂閱，schedule，filter config）
├── collector/    Feed Collector（fetch engine，rate limiting，scoring）
├── flow/         AI Flows（Genkit pipelines：review/polish/digest/morning-brief/weekly-review）
├── flowrun/      Flow Execution（run tracking，retry，alerting）
├── review/       Review Queue（content approval workflow）
├── notion/       Notion Integration（API client，webhook，property schema，sync）
├── pipeline/     Pipeline Orchestrator（GitHub webhook routing，Obsidian sync，feed collection）
├── auth/         Authentication（JWT，Google OAuth，middleware）
├── server/       HTTP Server（routes，middleware chain，graceful shutdown）
├── mcp/          MCP Server（Claude tool definitions，read/write tools）
├── api/          API Utilities（Encode/Decode/Error，pagination）
├── stats/        Statistics（platform overview，goal drift，learning dashboard）
├── notify/       Notifications（LINE，Telegram）
├── obsidian/     Obsidian Parser（vault file parsing，wikilink extraction，camelCase handling）
├── budget/       Token Budget（daily LLM usage tracking，atomic counter）
├── tracking/     Content Tracking（topic tracking config for data collection）
├── upload/       File Upload（S3/R2 client）
├── webhook/      Webhook Verification（HMAC-SHA256 signature）
├── reconcile/    Data Reconciliation（Notion consistency checks）
└── db/           Generated Code（sqlc output，NEVER edit by hand）
```

### 依賴方向

**Infrastructure（零 internal imports）：**
- `db` — sqlc generated, DBTX interface
- `api` — response helpers (Encode, Decode, Error, ParsePagination)
- `webhook` — signature verification
- `obsidian` — vault file parser
- `notify` — LINE/Telegram clients
- `upload` — R2 client
- `budget` — atomic token counter

**Feature Packages（import db + api only）：**
- `content`, `task`, `goal`, `project`, `note`, `tag`, `topic`, `session`, `activity`, `collected`, `feed`, `tracking`, `review`, `flowrun`, `stats`, `auth`, `notion`
- 各自包含 types + handler + store + query，彼此不直接 import

**Orchestrators（跨 feature 協調）：**
- `pipeline` → imports: activity, content, feed, note, obsidian, project, tag, webhook
- `notion` → imports: activity, goal, project, task, tag, webhook
- `flow` → imports: activity, collected, content, pipeline, project, review, topic
- `collector` → imports: collected, feed

**Server Wiring（最外層）：**
- `server` → imports 幾乎所有 feature packages，負責 route registration
- `mcp` → imports read/write 相關 features（activity, content, goal, note, project, session, stats, tag, task, collected）
- `cmd/app/main.go` → creates all stores/handlers, wires everything

### Cross-Feature 解耦方式

Feature packages 之間不直接 import。需要跨 feature 操作時，使用 consumer-defined interfaces：

```go
// pipeline/handler.go — consumer 定義需要的介面
type ContentReader interface {
    ContentBySlug(ctx context.Context, slug string) (*content.Content, error)
}

type EventRecorder interface {
    CreateEvent(ctx context.Context, p activity.RecordParams) (int64, error)
}
```

唯一例外：feature packages 可以 import 其他 feature 的 domain types（structs），但不能 import store 或 handler。

---

## Design Principles（從 codebase 歸納）

### 1. MCP 和 HTTP 共用 Store，各自定義 Handler

MCP server 和 HTTP server 是兩個獨立 binary（`cmd/app/` 和 `cmd/mcp/`），但共用同一套 `*Store` structs。各自在 handler 層定義自己需要的 interface slice。

**Evidence：**
- `internal/mcp/mcp.go` 定義 20+ 個 reader/writer interfaces（`TaskReader`, `GoalReader`, `SessionNoteWriter` 等）
- `internal/task/handler.go` 定義 HTTP-specific handlers
- 兩者都依賴 `internal/task/Store`，但透過 interface 而非直接引用

### 2. Consumer-Defined Interfaces 解耦 Domain

每個 orchestrator（pipeline, mcp, flow）在自己的 handler 檔案裡定義自己需要的 interfaces，粒度小（通常 1-3 methods）。不存在 god interface。

**Evidence：**
- `pipeline/handler.go` 定義 16 個 interfaces（ContentReader, JobSubmitter, FeedCollector 等）
- `mcp/mcp.go` 定義 20+ 個 interfaces
- 每個 interface 只包含 caller 實際使用的 methods

### 3. Notion Sync 是 Best-Effort，不阻塞 Local Operation

Task/Goal/Project 在本地有獨立的 store 和 lifecycle。Notion 同步失敗不影響本地操作。寫回 Notion 也是 best-effort（MCP `complete_task` 嘗試更新 Notion，失敗時只標記本地完成）。

**Evidence：**
- `mcp/write_tools.go` `completeTask`: 先更新本地 status → 嘗試 Notion update → Notion 失敗不 rollback 本地
- `task/store.go` 的 CRUD 操作不依賴 Notion API
- `notion/sync.go` 是獨立的 sync 邏輯，由 webhook 或 cron 觸發

### 4. Session Notes 是跨環境上下文橋

`session_notes` 表用 `note_type` 區分用途（plan/reflection/metrics/insight），用 `source` 區分來源（claude/claude-code/manual）。這是唯一一個跨 MCP 和 HTTP API 共享即時上下文的機制。

**Evidence：**
- MCP `save_session_note` 和 `get_morning_context` 直接讀寫 session_notes
- Session notes 的 metadata 用 JSONB 存放結構化資料（metrics 的 completion_rate、insight 的 hypothesis/status/evidence）
- `get_morning_context` 聚合 tasks + goals + session_notes + activity 提供 Claude 完整早晨規劃上下文

### 5. AI Pipeline 用 Genkit Flows，不是 Raw API Calls

所有 AI 操作封裝在 `internal/flow/` 的 Genkit flows 中，每個 flow 是獨立的處理單元，透過 `flowrun.Runner` 統一執行和追蹤。

**Evidence：**
- `internal/flow/` 有 18 個檔案，每個 flow 對應一個具體任務（review, polish, excerpt, digest, morning-brief, weekly-review, build-log, dev-log 等）
- `flowrun/` 負責 run tracking（status: pending → running → completed/failed）、retry、alerting
- `budget.Budget` 用 atomic counter 追蹤每日 token 用量，`ErrOverBudget` 阻止超額呼叫
- 支援 mock mode（`MockMode` config flag），開發時不實際呼叫 AI

### 6. Feed Collection 用 Relevance Scoring 而非全部收錄

RSS feed 收集不是簡單的「抓下來存起來」。每篇文章計算 relevance score，只有高相關性的進入 review queue。

**Evidence：**
- `collector/` 包含 scoring 邏輯，基於 topic match、keyword match
- `collected_data` 有 `relevance_score` 和 `status`（unread/read/curated/ignored）
- `feed.FilterConfig` 支援 per-feed 的 URL/title/tag 過濾規則（deny_paths, deny_title_patterns, deny_tags）

### 7. Tag Resolution 是 4-Step Pipeline

Tag 不是簡單的字串比對。有一套 resolution pipeline 把 raw tag normalize 到 canonical tag。

**Evidence：**
- `tag/store.go` 的 `ResolveTag`：exact match → case-insensitive → slug match → unmapped alias
- `tag.Resolved` 記錄 match method（"exact", "case_insensitive", "slug", "unmapped"）
- `tag_aliases` 表存放 raw_tag → canonical mapping，支援 confirmed/unconfirmed/rejected 狀態

---

## Technology Choices

### 為什麼 Go + PostgreSQL + pgvector + Genkit

| 選擇 | 原因 |
|------|------|
| **Go** | Koopa 的主力後端語言；Genkit 原生支援；單一 binary 部署適合 VPS；高併發適合 webhook + cron + AI pipeline |
| **PostgreSQL** | 一個 DB 覆蓋 relational + full-text search + vector search（pgvector）；不需要額外的 Elasticsearch 或 Pinecone |
| **pgvector** | 768-dim embeddings，HNSW index，cosine similarity；與 PostgreSQL 同一個 transaction，不需要外部向量 DB |
| **Genkit** | Firebase AI SDK for Go；flow 抽象適合多步驟 AI pipeline；支援 Gemini + Claude；內建 prompt 模板管理 |
| **pgx/v5** | 原生 PostgreSQL driver（不用 database/sql 的 generic interface）；支援 COPY、LISTEN/NOTIFY、custom types |
| **sqlc** | SQL-first：寫 SQL，生成 type-safe Go code；不是 ORM，不隱藏 SQL semantics |

### 為什麼 Angular + Tailwind（不用 React、不用 Material）

| 選擇 | 原因 |
|------|------|
| **Angular 21** | Koopa 的前端主力框架；SSR 內建支援；強型別（TypeScript-first） |
| **Tailwind CSS v4** | 不需要 component library 的設計限制；完全自訂設計語言；dark mode 原生支援 |
| **不用 Material** | 避免「所有 Angular 專案看起來都一樣」的問題；個人品牌需要獨特視覺 |
| **不用 React** | 技術選擇一致性；Angular 的 DI + module system 適合這種中型 SPA |

### 為什麼 MCP 作為 Primary Interface

MCP（Model Context Protocol）讓 Claude 直接操作知識引擎，而不需要透過 HTTP API 的 UI layer。這使得 Claude 成為 koopa0.dev 的第一級使用者。

| 使用場景 | MCP Tool |
|---------|----------|
| 早晨規劃 | `get_morning_context` → `batch_my_day` → `create_task` |
| 晚間反思 | `save_session_note(type=reflection)` → `update_insight` |
| 知識檢索 | `search_knowledge` → `semantic_search` |
| 任務完成 | `complete_task`（同時更新本地 + Notion） |
| 洞察追蹤 | `get_active_insights` → `update_insight`（hypothesis lifecycle） |

兩個 transport：
- **Stdio**：Claude Code CLI 本地使用，無 auth
- **HTTP + OAuth 2.0**：Claude.ai 遠端使用，bearer token 或 OAuth flow

---

## Runtime Architecture

### Binary 分佈

| Binary | Port | 用途 |
|--------|------|------|
| `cmd/app` | 8080 | HTTP API server + cron daemon |
| `cmd/mcp` | 8081 (HTTP) or stdio | MCP server for Claude |
| `cmd/calibrate` | — | One-off data calibration utility |

### Middleware Chain（outermost first）

```
Prometheus metrics → Request ID → Logging (slog) → Security Headers
→ CORS → CSRF (Go 1.25+ CrossOriginProtection) → Route Mux
→ [Admin routes: Auth Middleware (JWT)] → Handler
```

### Caching Strategy

| Cache | Backend | TTL | Invalidation |
|-------|---------|-----|-------------|
| Knowledge Graph | Ristretto (count-based) | 10 min | Eventual consistency |
| RSS Feed | Ristretto (byte-based, 1MB) | 10 min | Eventual consistency |
| Sitemap | Ristretto (byte-based) | 30 min | Eventual consistency |
| Topics | Ristretto (count-based) | 10 min | Eventual consistency |
| Notion Source Roles | Ristretto (~4 entries) | — | On sync |

所有 cache 都是 eventual consistency，不做 active invalidation。對個人知識引擎來說，10 分鐘延遲可以接受。

### Scheduled Jobs（cron, Asia/Taipei timezone）

定義在 `cmd/app/cron.go`：
- Feed collection（per schedule: hourly, daily, weekly）
- Flow run retry（stuck/failed runs）
- Monitoring/cleanup tasks
