# koopa0.dev — 完整專案功能介紹與使用情境

> **最後更新**: 2026-03-18
> **專案類型**: 個人知識引擎平台 (Personal Knowledge Engine)
> **技術棧**: Go 1.26 + Angular 21 SSR + PostgreSQL 17 + Firebase Genkit
> **使用者**: Koopa (單一管理者) + 公開訪客

---

## 一、專案定位

koopa0.dev **不是部落格**。它是一個可輸入、可輸出的個人知識系統。

三個面向：
- **輸入** — 從 Obsidian、Notion、GitHub、RSS 自動收集工作痕跡和學習資料
- **處理** — 13 個 AI flow 自動整理、分類、摘要、審核、生成內容
- **輸出** — Angular SSR 網站展示知識作品 + Admin Dashboard 管理一切

核心哲學：
> 「Go code 做 LLM 做不好的事，LLM 做 Go code 做不好的事。」
> 「寧可少一個 data source，也不要多一層 integration complexity。」

---

## 二、系統架構

```
┌─ 資料來源 ─────────────────────────────────────────────┐
│  Obsidian Vault → GitHub Push → Webhook                │
│  Notion UB3.0 → Webhook + Hourly Polling               │
│  GitHub Activity → Push/PR Webhooks                     │
│  RSS Feeds (14源) → Cron (hourly/daily/weekly)          │
└────────────────────┬───────────────────────────────────┘
                     ▼
┌─ Go Backend (:8080) ───────────────────────────────────┐
│  Pipeline Handler → route events → upsert data          │
│  13 Genkit AI Flows → content review/summary/polish     │
│  14 Cron Jobs → 自動收集/分析/推送                       │
│  PostgreSQL 17 → 22 tables + pgvector embeddings        │
│  MCP Server (stdio) → Claude Code 整合                  │
└────────────────────┬───────────────────────────────────┘
                     ▼
┌─ Angular SSR Frontend (:4000) ─────────────────────────┐
│  公開網站 → 文章/專案/筆記/搜尋/知識圖譜               │
│  Admin Dashboard → 內容管理/標籤/RSS/AI/分析           │
│  BFF Proxy → /bff/* → backend:8080                     │
│  SSR → sitemap.xml + feed.xml 動態生成                 │
└────────────────────┬───────────────────────────────────┘
                     ▼
         Cloudflare Tunnel → 瀏覽器
```

---

## 三、公開功能（訪客看到的）

### 3.1 首頁

**URL**: `/`
**呈現**: Hero section + Mixed Feed (最新文章/build-log/TIL 混合排序) + Featured Projects + Tech Stack 展示 + Contact CTA

**使用情境**: 訪客第一次來到 koopa0.dev → 立刻看到 Koopa 是誰、最近在做什麼、技術棧有哪些、代表作品是什麼。

---

### 3.2 技術文章

**URL**: `/articles` (列表), `/articles/:slug` (詳情)
**呈現**: 文章列表 (分頁、按發佈日排序) → 點進去看完整 Markdown 渲染 (syntax highlighting + mermaid 圖表) + Table of Contents + Related Articles (embedding cosine similarity) + Series 導覽

**使用情境**: 訪客搜尋 "Go concurrency patterns" → 找到文章 → 看到相關文章推薦 → 進入 series "Go 深入系列" 繼續閱讀。

**內容類型** (共 7 種，同一個 content pipeline):

| Type | 說明 | URL |
|------|------|-----|
| `article` | 深度技術文章 (2000+ 字) | `/articles/:slug` |
| `essay` | 個人想法、非技術反思 | `/essays/:slug` |
| `build-log` | 專案開發紀錄 | `/build-logs/:slug` |
| `til` | 每日學習 (300-500 字) | `/til/:slug` |
| `note` | 技術筆記片段 | `/notes/:slug` |
| `bookmark` | 推薦資源 + 個人評語 | (via content list) |
| `digest` | 週報/月報 | (via content list) |

---

### 3.3 專案作品集

**URL**: `/projects` (列表), `/projects/:slug` (詳情)
**呈現**: Project Cards (featured 優先) → Case Study 格式詳情頁 (Problem → Solution → Architecture → Results) + Tech Stack 標籤 + GitHub/Live 連結

**使用情境**: 潛在合作者或僱主 → 看到 koopa0.dev 本身就是 showcase → 點進其他專案看完整 case study。

---

### 3.4 搜尋

**URL**: `/search?q=...`
**呈現**: 搜尋框 + 即時結果列表 (highlighted matches)
**後端**: PostgreSQL tsvector (simple config) full-text search + CamelCase splitting

**使用情境**: 訪客想找 "goroutine leak" 相關內容 → 搜尋 → tsvector 匹配 title (weight A) + body text (weight C) → 按 rank 排序返回。

---

### 3.5 RSS Feed + Sitemap

**URL**: `/feed.xml`, `/sitemap.xml`
**呈現**: 標準 RSS 2.0 XML + sitemap XML (動態生成, 10 分鐘快取)

**使用情境**: 讀者在 RSS reader 訂閱 koopa0.dev → 每次發佈新文章自動推送到 reader。搜尋引擎定期爬取 sitemap 更新索引。

---

### 3.6 知識圖譜

**URL**: `/knowledge-graph` (public API, 前端尚未完全整合)
**後端**: 所有已發佈 content 的 embedding + topic membership → 計算 cosine similarity → 產生 nodes (contents + topics) + edges (similarity + topic links)

**使用情境**: 視覺化展示 Koopa 的知識結構 — 哪些主題之間有關聯、知識如何串連。

---

### 3.7 SEO

**實作**: 每個頁面都有:
- `<meta>` tags (title, description, og:image)
- JSON-LD structured data (WebSite schema)
- Angular SSR server-side rendering (搜尋引擎直接讀取 HTML)
- Dynamic sitemap + RSS

---

## 四、Admin Dashboard（Koopa 使用的）

### 4.1 總覽儀表板

**URL**: `/admin`
**呈現**: 11 個統計卡片 (contents by status/type, collected by status, feeds, flow runs, projects, reviews, notes, activity 24h/7d, spaced rep, notion sources, tags) + 最近文章 + 最近專案 + Pipeline 觸發按鈕

**使用情境**: Koopa 每天早上打開 Dashboard → 一眼看到系統狀態：多少篇文章待審、多少 RSS 未讀、AI flow 有沒有失敗、有多少筆記要複習。

**Pipeline 一鍵觸發**:
| 按鈕 | 功能 |
|------|------|
| Sync | 手動觸發 GitHub Obsidian 同步 |
| Collect | 手動收集 RSS feeds |
| Notion Sync | 手動觸發 Notion 全量同步 |
| Reconcile | 手動觸發 Obsidian↔Notion 比對 |
| Digest | 手動生成週報 |
| Bookmark | 手動生成 bookmark 文章 |

---

### 4.2 內容編輯器

**URL**: `/admin/editor` (新建), `/admin/editor/:id` (編輯)
**呈現**: 左側 Markdown 編輯器 + 右側 Frontmatter 面板 (slug, title, type, status, tags, topics, cover image, series, review level)

**使用情境**:
1. **手動創作**: Koopa 直接在 editor 寫文章 → 存為 draft → 發佈
2. **AI 輔助**: Obsidian 筆記自動同步 → content-review flow 自動校對 + 生成摘要 + 建議標籤 → 進入 review queue → Koopa 在 editor 審核修改 → 發佈
3. **AI 潤稿**: 選擇一篇文章 → 觸發 content-polish (Claude) → 看 diff → approve/reject

---

### 4.3 Review Queue

**URL**: `/admin/review`
**呈現**: 待審核列表 (content title + type + review level + submitted time) + Approve/Reject 按鈕

**使用情境**: AI content-review flow 處理完一篇文章 → 自動進入 review queue → Koopa 審核 AI 校對結果 → approve (套用修改) 或 reject (保留原文)。

---

### 4.4 標籤管理

**URL**: `/admin/tags`
**呈現**: 兩個 Tab:
- **Tab 1: Canonical Tags** — 標籤樹 (支援 parent-child 層級) + CRUD + 合併 + 回填
- **Tab 2: Tag Aliases** — 未映射的 raw tags 列表 → 映射到 canonical tag / 確認 / 拒絕

**使用情境**:
1. Obsidian 筆記帶有 `tags: [go, Go, golang, Golang]` → B1 sync 自動 normalize → `tag_aliases` 記錄對應關係
2. Admin 打開 aliases tab → 看到未映射的 raw tags → 批次映射到 canonical tag "go"
3. 點擊 "Backfill" → 系統掃描所有筆記 → 補寫 junction table
4. 發現兩個 canonical tag "golang" 和 "go" → 用 Merge 合併

---

### 4.5 RSS Feed 管理

**URL**: `/admin/feeds`
**呈現**: Feed 列表 (name, URL, schedule, enabled, last fetched, error count) + CRUD + Filter by schedule + 手動 Fetch 按鈕

**使用情境**: Koopa 想追蹤新的技術 blog → 新增 RSS feed → 設定 schedule (daily) + filter config (deny_title_patterns: ["(?i)sponsored"]) → 系統自動按排程收集 → AI 評分 → 出現在 Collected 頁面。

**Collected Items** (`/admin/collected`):
- 列表: title + source + AI score + status (unread/read/curated/ignored)
- 操作: 👍/👎 feedback, Ignore, Curate (轉成 bookmark 文章)

---

### 4.6 AI Flow 管理

**URL**: `/admin/flow-runs`
**呈現**: Flow run 歷史 (flow name, status, attempt, started/ended time, error) + Filter by status/flow name + Retry 按鈕

**使用情境**: 某個 content-review flow 失敗 → 看到 error message (e.g., "token budget exceeded") → 等 budget 隔天重置 → 手動 Retry。

---

### 4.7 Spaced Repetition 複習

**URL**: `/admin/spaced`
**呈現**: 到期筆記 card stack → 翻轉看答案 → Quality 按鈕 (0-5)

**使用情境**:
1. Koopa 每天 09:00 收到 LINE: "📚 你有 4 個筆記要複習"
2. 打開 `/admin/spaced` → 看到 4 張到期卡片
3. 每張卡片: 筆記標題 + type + context → 回想內容 → 評分
4. SM-2 算法計算下次複習日期 (quality ≥ 3: 間隔加長, quality < 3: 重頭開始)

---

### 4.8 Notion Source 管理

**URL**: `/admin/notion-sources`
**呈現**: Notion database 列表 (name, database_id, sync_mode, poll_interval, enabled, last synced) + CRUD + Toggle

**使用情境**: Koopa 在 Notion 新增一個 "Reading List" database → 在 admin 註冊 → 設定 sync_mode: events, poll_interval: 30 minutes → 系統自動追蹤。

---

### 4.9 Activity 分析

**URL**: `/admin/activity`

**Sessions** — 工作 session 重建:
- 呈現: 時間軸，每個 session 顯示 start/end/duration + 涉及的 projects + sources
- 使用情境: 看到今天有 3 個 work sessions — 早上 2h 做 backend, 下午 1.5h 寫筆記, 晚上 30min 看 RSS

**Changelog** — 每日活動時間線:
- 呈現: 日曆式，每天展開看 events (source, type, project, title, time)
- 使用情境: 回顧過去 30 天每天做了什麼 — 哪天 push 最多、哪天寫了最多筆記

---

### 4.10 Drift Detection

**URL**: `/admin/stats/drift`
**呈現**: Bar chart — 每個 area 的 goal% vs activity%, drift% (正值=過度投入, 負值=投入不足)

**使用情境**: Koopa 設定了 "learning" 目標佔 40% → 實際 activity 只有 10% 在 learning → drift = -30% → 意識到需要增加讀書/練題時間。

---

### 4.11 Learning Dashboard

**URL**: `/admin/stats/learning`
**呈現**: Spaced rep 統計 (enrolled/due) + 筆記成長 (本週/本月/total) + 活動趨勢 (up/down/stable) + Top 10 tags

**使用情境**: 看到本週新增 5 個筆記 (比上週多 2 個, trend: up) → 最多的 tag 是 "go" (32 notes) → spaced rep 還有 3 個 due。

---

## 五、自動化系統（無需手動操作）

### 5.1 Webhook Pipeline

| 事件 | 觸發 | 處理 | 結果 |
|------|------|------|------|
| Obsidian push | GitHub webhook | B1: parse frontmatter → upsert note → tags → wikilinks → activity event | 知識筆記自動同步 |
| Public content push | GitHub webhook | A1: parse → upsert content → content-review AI flow | 文章自動校對+摘要+標籤 |
| PR merge | GitHub webhook | B4: scan PR body for Notion links → update task status | Notion task 自動完成 |
| Non-Obsidian push | GitHub webhook | project-track: record activity + AI project summary | 專案活動自動追蹤 |
| Notion page change | Notion webhook | Route to project/goal/task/book sync | 專案/目標自動同步 |

### 5.2 Cron Jobs (14 個自動任務)

| 時間 | 功能 | 推送 |
|------|------|------|
| 每 2 分鐘 | 重試失敗的 AI flow | — |
| 每 4 小時 | 收集 hourly RSS feeds | — |
| 每日 06:00 | 收集 daily RSS feeds | — |
| 每週一 06:00 | 收集 weekly RSS feeds | — |
| 每日 00:00 | 重置 AI token budget (500k/day) | — |
| 每日 01:00 | 清除過期 refresh tokens | — |
| **每日 07:30** | **Morning Brief** | **📱 LINE/Telegram** |
| **每日 09:00** | **Spaced Rep 到期提醒** | **📱 LINE/Telegram** |
| 每週一 09:00 | Weekly Review | 📱 LINE/Telegram |
| 每週一 03:00 | Content Strategy 分析 | — |
| **每週一 10:00** | **Build-log per project** | — |
| **每日 23:00** | **Daily Dev Log** | **📱 LINE/Telegram** |
| 每週日 04:00 | Reconciliation (Obsidian↔Notion 比對) | — |
| 每小時 :15 | Hourly sync safety net | — |

### 5.3 AI Flow Pipeline (13 個 Genkit Flow)

| Flow | 觸發 | 輸入 | 輸出 | Model |
|------|------|------|------|-------|
| content-review | Webhook (公開文章 push) | article body | 校對 + 摘要 + 標籤 + embedding | Gemini |
| content-proofread | Sub-flow | text | grammar/structure review | Gemini |
| content-excerpt | Sub-flow | text | 160 字 SEO 摘要 | Gemini |
| content-tags | Sub-flow | text + topic list | 建議標籤 (filtered by allowlist) | Gemini |
| content-polish | Admin 手動 | article body | 潤稿後全文 (Claude) | Claude |
| digest-generate | Admin 手動 | recent contents + collected | 週報全文 | Gemini |
| bookmark-generate | Admin 手動 | collected item | bookmark 文章 (推薦 + 評語) | Gemini |
| morning-brief | Cron 07:30 | Notion tasks + recent data | 每日早安簡報 | Gemini |
| weekly-review | Cron 09:00 Mon | all activity + goals | 週回顧 + 建議 | Gemini |
| content-strategy | Cron 03:00 Mon | contents + collected + projects | 內容策略建議 | Gemini |
| project-track | GitHub push webhook | commits + project info | 專案活動摘要 | Gemini |
| build-log-generate | Cron 10:00 Mon | project commits (7 days) | 週 build log | Gemini |
| daily-dev-log | Cron 23:00 | today's activity events | 每日開發摘要 | Gemini |

---

## 六、MCP Server (Claude Code 整合)

**獨立 binary**: `cmd/mcp/main.go` (stdio transport, 直連 DB)

| Tool | 使用情境 |
|------|---------|
| `search_notes` | Koopa 在 IDE 用 Claude Code → "搜尋我關於 goroutine 的筆記" → hybrid search (tsvector + frontmatter filter + RRF merge) |
| `get_project_context` | "koopa0.dev 這個專案目前的狀況" → project details + recent activity + related notes |
| `get_recent_activity` | "最近一週做了什麼" → activity events filtered by source/project |
| `get_decision_log` | "查一下之前關於 SSE broker 的設計決策" → decision-log type notes |

---

## 七、Database Schema (22 表)

### 核心內容
- `contents` — 7 types × 4 statuses + embedding + search_vector
- `topics` — 主題分類 (24 seed)
- `content_topics` — 內容↔主題 junction

### 知識筆記
- `obsidian_notes` — Obsidian vault 筆記 + frontmatter + embedding + search_vector
- `note_links` — wikilink 邊 (source_note → target_path)

### 標籤系統
- `tags` — canonical tags (hierarchical via parent_id)
- `tag_aliases` — raw tag → canonical mapping (4-step normalization)
- `obsidian_note_tags` — 筆記↔標籤 junction
- `activity_event_tags` — 事件↔標籤 junction

### 活動追蹤
- `activity_events` — 統一事件日誌 (GitHub + Obsidian + Notion)
- `project_aliases` — 專案名稱映射

### 專案/目標
- `projects` — 6 statuses + Notion sync
- `goals` — 4 statuses + area + quarter

### RSS 收集
- `feeds` — 14 RSS 源 + schedule + filter config
- `collected_data` — 收集的文章 + AI 評分

### AI Pipeline
- `flow_runs` — AI flow 執行記錄 + retry
- `review_queue` — 待審核內容

### Spaced Repetition
- `spaced_intervals` — SM-2 排程 (EF + interval + repetitions)

### Notion 整合
- `notion_sources` — Notion database 註冊表

### Auth
- `users` — 使用者 (admin only)
- `refresh_tokens` — JWT refresh token hash

### 追蹤
- `tracking_topics` — 主題追蹤配置

---

## 八、技術特點

| 特點 | 實作 |
|------|------|
| **Package-by-feature** | 28 個 internal packages，無 services/repositories 反模式 |
| **Consumer-defined interfaces** | 61 個 interface 全部定義在消費端，打破 import cycle |
| **Transactional note sync** | UpsertNote + SyncNoteTags + SyncNoteLinks 在同一個 pgx transaction |
| **SM-2 算法** | Pure function，10 個 table-driven tests |
| **CamelCase splitting** | `HTTPSRedirect` → `HTTPS Redirect`，保護 `[[wikilinks]]` |
| **4-step tag normalization** | exact → case-insensitive → slug → unmapped |
| **Ristretto cache** | Knowledge graph (10min), RSS/Sitemap (10min), Topics (10min) |
| **Overlap protection** | Cron jobs 用 `atomic.Bool` 防止併發執行 |
| **Token budget** | 500k daily limit + midnight reset |
| **Mock mode** | `MOCK_MODE=true` 切換全部 13 個 AI flow 為 mock，不需 API key |

---

## 九、量化數據

| 指標 | 後端 | 前端 |
|------|------|------|
| 程式語言 | Go 1.26 (22,128 LOC) | TypeScript/Angular 21 |
| 檔案數 | 122 .go files | 84 .ts files |
| Packages/Components | 28 internal + 3 cmd | 25+ pages + 25 services |
| HTTP Endpoints | ~60 | ~37 routes |
| DB Tables | 22 | — |
| DB Indexes | 46 | — |
| Cron Jobs | 14 | — |
| AI Flows | 13 | — |
| Test Functions | 68 (13 packages) | Angular test specs |
| External Dependencies | 131 (go.mod) | Angular + Tailwind + Lucide |

---

## 十、驗證狀態

| 檢查 | 結果 |
|------|------|
| `go build ./...` | ✅ PASS |
| `go vet ./...` | ✅ PASS |
| `golangci-lint run ./...` | ✅ 0 issues |
| `go test ./...` | ✅ 13/13 test packages pass |
| Security review | ✅ 0 CRITICAL |
| Go idioms review | ✅ All BLOCKING fixed |
| DB review | ✅ All BLOCKING fixed |
| Devil's Advocate | ✅ 8 findings evaluated + addressed |
| Independent code review | ✅ 3 pre-deploy fixes applied |

---

## 十一、完成度

| Phase | 完成 | 狀態 |
|-------|------|------|
| Phase 1: Core Pipeline | 16/16 | ✅ 100% |
| Phase 1.5: Source Decoupling | 1/3 | ⚠️ 2 blocked (infra) |
| Phase 2: Knowledge Backbone | 3/4 | ⚠️ 1 blocked (signals) |
| Phase 3: Intelligence Layer | 4/5 | ⚠️ 1 blocked (bidirectional writes) |
| Phase 4: Public & Portfolio | 2/2 | ✅ 100% |
| **Total** | **31/35** | **89%** |

4 個 blocked 項目全部是非程式碼因素（需要真實資料觀察、VPS infra 設定、前端實作、bidirectional writes 機制）。
