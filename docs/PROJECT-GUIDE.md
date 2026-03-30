# koopa0.dev — 專案完整導覽

> 寫給任何第一次接觸這個 codebase 的人（包括未來的自己和 Claude Code session）

---

## 一句話版本

**一個「可以輸入、可以處理、可以輸出」的個人知識引擎。**

不是部落格。部落格是「你寫文章 → 發布」。這個系統是：

- 你的 Obsidian 筆記自動同步進來
- 外部 RSS 文章自動收集進來
- AI 幫你整理、分類、潤色、生成摘要
- 你審核後發布到網站
- 同時還幫你管理 task、追蹤 goal、記錄 insight

```
輸入                    處理                     輸出
─────────────          ─────────────            ─────────────
Obsidian vault    →    AI Pipeline         →    公開網站
RSS feeds         →    審核佇列            →    articles, TILs
Notion tasks      →    Tag/Topic 分類      →    projects, notes
手動撰寫          →    潤色、生成摘要      →    build-logs, digests
```

---

## 技術棧

| 層 | 技術 | 備註 |
|----|------|------|
| 前端 | Angular 21 + Tailwind v4 + SSR | 公開頁面 + Admin dashboard |
| 後端 | Go + net/http (std lib) | 99 個 API endpoints |
| 資料庫 | PostgreSQL + pgvector | 全文搜尋 + 語義相似度 |
| AI | Genkit Go + Claude | 13 個 AI flow |
| 訊息 | NATS (JetStream) | AI job queue |
| 快取 | Ristretto | 單機 in-memory |
| 儲存 | Cloudflare R2 | 圖片上傳 |
| 外部整合 | Notion API + GitHub Webhook | 雙向同步 |

---

## 核心概念

在看任何功能之前，先搞懂這五個東西。系統的一切都圍繞它們。

### 1. Content — 成品

**Content 是這個平台的核心單位。任何最終會出現在網站上讓訪客看到的東西，都是一筆 content。**

它有 7 種 type：

| Type | 是什麼 | 典型場景 |
|------|--------|---------|
| `article` | 深度技術文章（1000-5000 字） | 你花幾天寫的「Go error handling 完整指南」 |
| `essay` | 個人想法、非技術反思 | 「為什麼我離開大公司」 |
| `build-log` | 專案開發紀錄 | 「koopa0.dev Week 3: 搞定 RSS pipeline」 |
| `til` | Today I Learned（100-500 字） | 「TIL: psql 的 \watch 可以自動重跑 query」 |
| `note` | 技術筆記片段 | 「PostgreSQL JSONB 常用操作速查」 |
| `bookmark` | 推薦外部文章 + 你的評語 | 「這篇 Uber 的 Go style guide 值得看，因為...」 |
| `digest` | 週報/月報，彙整一段時間的精華 | 「2026 第 12 週：完成了 RSS pipeline...」 |

所有 type 共用同一張 `contents` 表，有共同的生命週期：

```
draft → review → published → (archived)
                     ↑
              可以隨時設為 private（只有 admin 看得到）
```

**一句話：content = 你願意掛上名字、讓別人看到的東西。**

### 2. Note — 原始素材（跟 content type=note 不同！）

系統裡有**兩種 note**，這是最容易搞混的地方：

| | Obsidian notes | Content type `note` |
|---|---|---|
| 是什麼 | 你在 Obsidian vault 裡隨手寫的筆記 | 你整理好、發布到網站的技術筆記 |
| 存在哪 | `notes` 表 | `contents` 表 |
| 誰看得到 | 只有 admin | published 後訪客可見 |
| 有多少 | 可能幾百上千筆 | 精選過的，可能幾十筆 |
| API | `/api/admin/notes` | `/api/contents/by-type/note` |

**關係**：Obsidian note（原始素材）→ 你覺得值得分享 → 整理成 content type=note（成品）→ publish。

Obsidian notes 還有一個重要功能：**知識圖譜**。每篇 note 有 embedding (vector)，系統可以找語義相似的 content，也可以建立 note-to-note 的連結關係。

### 3. Topic & Tag — 知識組織

**Topic** 是**高層級的知識領域**，例如「Go」「系統設計」「AI」「前端」。
一個 content 可以屬於多個 topic。Topic 由 admin 手動管理（CRUD），數量通常在 10-20 個。

**Tag** 是**細粒度的標籤**，例如「pgvector」「error-handling」「concurrency」。
一個 content 可以有很多 tag。Tag 會從 Obsidian notes 自動提取。

Tag 有一個 **alias 系統**：
```
raw tag (來自 Obsidian)    →    canonical tag (系統標準)
"golang"                   →    "go"
"JS"                       →    "javascript"
"PostgreSQL"               →    "postgres"
```

AI 或同步過程中遇到未知的 raw tag，會建立一筆 unmapped alias，等 admin 決定：
- **Map**：映射到已有的 canonical tag
- **Confirm**：確認這個映射是對的
- **Reject**：這個 tag 不要

### 4. Session Note — AI 的工作日誌

**Session note 不是你寫的，是 AI flow 自動產生的。不對外公開。**

存在 `session_notes` 表，有 5 種 type：

| Type | 什麼時候產生 | 例子 |
|------|------------|------|
| `plan` | 每天早上 (MorningBrief flow) | 「今天計畫：完成 RSS scoring、review 3 篇收集文章」 |
| `reflection` | 每週日 (WeeklyReview flow) | 「這週完成 12 個 task，主要集中在 content pipeline」 |
| `context` | 開發 session 結束時 | 「這次 session 改了 feed handler 的 error handling」 |
| `metrics` | 定期 | `{tasks_planned: 5, tasks_completed: 3, completion_rate: 0.6}` |
| `insight` | AI 發現 pattern 時 | 見下面 ↓ |

### 5. Insight — 假說追蹤

**Insight 是 session note 的特殊子類型，多了「假說 → 驗證」的結構。**

普通 session note 只有 content（一段文字）。Insight 多了：

```json
{
  "content": "發現 relevance score < 0.3 的收集文章 90% 會被 ignore",
  "hypothesis": "門檻應該從 0.2 調到 0.3",
  "evidence": [
    "2026-03-20: 15/17 low-score items ignored",
    "2026-03-25: 12/14 ignored"
  ],
  "status": "unverified",
  "conclusion": null
}
```

Status 流轉：`unverified` → `verified`（假說成立） / `invalidated`（假說不成立） → `archived`

**一句話：insight = AI 提出的假說，等你蒐集證據確認對不對。**

---

## 三大資料流

整個系統可以拆成三條資料流。理解這三條，就理解了 80% 的系統。

### 資料流 1：Obsidian → 網站

```
Obsidian vault (你的電腦)
    ↓ git push
GitHub repo
    ↓ webhook 通知 or 手動 sync
Backend: pipeline/sync
    ↓ 比對 content hash，只處理有變更的
notes 表 (原始素材)
    ↓ AI: 自動打 tag、生成 embedding
    ↓ 你決定哪些值得發布
contents 表 (成品)
    ↓ 審核 (如果 review_level 不是 auto)
published → 網站
```

**觸發方式**：
- 自動：GitHub webhook 在你 push 時觸發
- 手動：Admin pipeline 頁面按「Obsidian + GitHub Sync」
- 排程：cron job 定期跑

**前端呈現**：
- Public `/notes` 頁面 = 已發布的 content type=note
- Admin 暫時看不到 Obsidian 原始 notes（Phase 2 功能）

### 資料流 2：RSS → 網站

```
RSS feeds (你訂閱的技術 blog)
    ↓ 排程抓取 (4hourly / daily / weekly)
collector: 抓取 + TF-IDF 評分
    ↓
collected_data 表 (候選清單)
    ↓ Admin 審核：
    ├── Curate → 建立 bookmark content → publish
    ├── Feedback (up/down) → 訓練評分模型
    └── Ignore → 丟棄
```

**每筆 collected item 有 relevance score**，是 TF-IDF 根據你的 topic 興趣算出來的。分數越高，越可能是你想看的。

**Feed 有 filter config**：可以設定 deny path、deny title pattern、allow/deny tags，在抓取階段就過濾掉不要的。

**前端呈現**：
- `/admin/feeds`：管理 RSS 來源（增刪改 + 手動抓取）
- `/admin/collected`：審核收集到的文章（目前缺 curate 按鈕 ← BUG）
- Public 不會直接看到 collected items，只有被 curate 成 bookmark 後才會出現

### 資料流 3：Notion → 系統

```
Notion workspace
    ↓ webhook 通知 or 手動 sync
Backend: notion/handler
    ↓ 根據 source 的 role 分流
    ├── role=task   → tasks 表（你的 todo）
    ├── role=goal   → goals 表（你的目標）
    ├── role=project → projects 表（你的專案）
    └── role=note   → (未來) notes 表
```

**雙向同步**：
- Notion → Backend：webhook 或 cron 觸發，upsert 本地資料
- Backend → Notion：例如你在前端 complete 一個 task，Backend 會回寫 Notion

**Notion Source 管理**：
Admin 先 discover Notion workspace 裡的 database，然後 connect + 設定 role。每個 database 只能有一個 role。

**前端呈現**：
- `/admin/notion-sources`：連接和管理 Notion database
- `/admin/tasks`：管理 todo（有 My Day 功能，可以 batch 設定今日任務）
- `/admin/goals`：追蹤目標進度（唯讀 + status 切換）
- `/admin/projects`：管理專案（完整 CRUD，含 case study 欄位）

---

## AI Pipeline

系統有 13 個 Genkit flow，全部用 Claude 作為 LLM backend。分三類：

### 內容處理 Flow

| Flow | 觸發方式 | 做什麼 |
|------|---------|--------|
| ContentPolish | Admin 在 editor 按按鈕 | 改善文筆、修正語法。三步驟：trigger → poll → approve |
| ContentTags | 自動 | 分析內容，推薦 tag |
| ContentExcerpt | 自動 | 從文章生成 1-2 句摘要 |
| ContentProofread | 自動 | 語法和風格檢查，回傳問題列表 |
| ContentStrategy | 手動 | 策略建議（這篇文章的定位、目標讀者） |
| ContentReview | 自動 | AI 審核品質，給分數和回饋 |
| BookmarkGenerate | 收集時 | 從 bookmark 文章提取重點 + 推薦 tag |
| BuildLog | 開發後 | 從 dev session 整理出結構化 lesson learned |

### 定期報告 Flow

| Flow | 排程 | 產出 |
|------|------|------|
| MorningBrief | 每天早上 | session note (type=plan)：今日計畫 |
| DailyDevLog | 每天 | session note (type=context)：昨日開發摘要 |
| WeeklyReview | 每週日 | session note (type=reflection)：週回顧 |
| DigestGenerate | 手動觸發 | content (type=digest)：週報/月報 |

### 專案追蹤 Flow

| Flow | 觸發 | 做什麼 |
|------|------|--------|
| ProjectTrack | 定期 | 分析 project 的最近 activity，更新狀態和下一步 |

**所有 flow 的執行記錄存在 `flow_runs` 表**，Admin 可以在 `/admin/flow-runs` 監控狀態、重試失敗的 job。

---

## 審核系統

Content 不一定直接 publish，可以先進審核：

```
建立 content (status=draft)
    ↓ 提交審核
review_queue (status=pending)
    ↓ Admin 在 /admin/review 頁面
    ├── Approve → content status=published, published_at=now
    ├── Reject + notes → content status=draft（退回修改）
    └── Edit → 同 approve
```

有 4 種 review level，決定審核嚴格度：
- `auto`：AI 自動通過（TIL、bookmark 等低風險內容）
- `light`：快速看一眼
- `standard`：正常審核（article 預設）
- `strict`：仔細審核（essay、對外公開的重要內容）

**前端呈現**：`/admin/review` — 列出待審核項目，每項有 approve/reject/edit 三個按鈕。

---

## 認證

只有一種登入方式：**Google OAuth**。

```
1. 前端 /login 頁面 → 按「Google 登入」
2. Frontend call GET /api/auth/google → 拿到 Google OAuth URL
3. Redirect 到 Google 登入
4. Google callback → Backend 驗證
5. Backend redirect 到 /admin/oauth-callback#access_token=...&refresh_token=...
6. Frontend 從 URL fragment (#) 取 token → 存起來 → redirect 到 /admin
```

Token 規則：
- Access token：JWT (HS256)，24 小時過期
- Refresh token：隨機 base64，7 天過期，**一次性使用**（用過就換新的）
- Token 放在 URL fragment (`#`) 不是 query (`?`) — 防止 server log 和 Referer header 洩漏

**Email allowlist 制** — 不是任何 Google 帳號都能登入，只有白名單內的 email。

---

## 監控與分析

Admin 有多個角度看系統狀態：

### Dashboard (`/admin`)
**系統全局視角 —「我的平台整體狀態如何？」**

上方 4 張卡片：
1. Today's Progress — My Day task 完成率
2. Active Insights — 未驗證的 insight 數量
3. Weekly Capacity — 過去 7 天的平均 task/day + 趨勢
4. Quick Sync — 一鍵觸發 Notion/Obsidian/RSS 同步

下方統計網格：content 數量 (by status/type)、collected、feeds、flow runs、projects、reviews、notes、activity、sources、tags — 每張卡片顯示 icon + 數字 + 子分類。

再下方：
- **Drift Report** — 你的目標 vs 實際活動的偏差（堆疊長條圖）
- **Learning Dashboard** — 本週筆記數、趨勢、top tags
- **Recently Updated** — 最近更新的 5 篇文章

### Today (`/admin/today`)
**個人每日視角 —「我今天要做什麼？」**

左欄：
- My Day 任務清單（可 checkbox 完成、inline 新增）
- 逾期任務（紅色標記，可加入 My Day）
- 今天到期的任務

右欄：
- 未驗證的 Insights（可 verify/invalidate/加 evidence）
- 7 天 Planning 完成率 heatmap
- 昨日 session notes

### Activity (`/admin/activity`)
**變更紀錄** — 兩種視角：按 Session 分組 / 按時間 Timeline

### Planning (`/admin/planning`)
**計畫歷史分析** — 14 天趨勢、每週各天的平均產能 heatmap

### Stats API 提供三種報表：
| API | 用途 | 顯示位置 |
|-----|------|---------|
| `GET /api/admin/stats` | 系統全局數據快照 | Dashboard 統計網格 |
| `GET /api/admin/stats/drift` | 目標 vs 實際偏差 | Dashboard drift report |
| `GET /api/admin/stats/learning` | 學習進度指標 | Dashboard learning section |

---

## 前端頁面一覽

### 公開頁面（訪客可見）

| Route | 頁面 | 資料來源 |
|-------|------|---------|
| `/` | 首頁：hero + featured projects + tech stack + 最新 6 篇 feed + CTA | contents + projects |
| `/articles` | 文章列表：3 欄 grid、inline 搜尋 (debounce 300ms)、tag 過濾、分頁 | contents (type=article) |
| `/articles/:slug` | 文章詳情：TOC 側邊欄、syntax highlight、copy code button、related articles | content + related |
| `/projects` | 專案列表：status filter | projects (public=true) |
| `/projects/:slug` | 專案詳情：case study (problem/solution/architecture/results)、tech stack badges、GitHub/Live 連結 | project |
| `/til` | TIL 列表 | contents (type=til) |
| `/til/:slug` | TIL 詳情 | content |
| `/notes` | 技術筆記列表 | contents (type=note) |
| `/notes/:slug` | 筆記詳情 | content |
| `/tags/:tag` | 某 tag 下的所有 content（混合 type） | contents (tag filter) |
| `/about` | 關於頁面（靜態） | — |
| `/privacy` | 隱私政策（靜態） | — |
| `/terms` | 使用條款（靜態） | — |
| `/login` | Google OAuth 登入 | auth |

導航列：Home, Writing (Articles / TIL), Projects, About, ⌘K 搜尋

### Admin 頁面（需登入）

| Route | 頁面 | 主要功能 |
|-------|------|---------|
| `/admin` | Dashboard | 系統全局概覽、quick sync、drift report、learning dashboard |
| `/admin/today` | 今日工作 | My Day tasks、insights、planning heatmap、昨日 notes |
| `/admin/contents` | 內容管理 | 全 status/type/visibility 過濾、CRUD 操作 |
| `/admin/editor` | 文章編輯器 | Markdown 編輯 (edit/preview/split)、AI polish、image upload、metadata sidebar |
| `/admin/project-editor` | 專案編輯器 | 基本資訊 + case study 欄位 + flags (public/featured) |
| `/admin/review` | 審核佇列 | approve / reject / edit |
| `/admin/feeds` | RSS 管理 | CRUD + filter config + 手動 fetch |
| `/admin/collected` | 收集審核 | status filter、feedback（缺 curate） |
| `/admin/tasks` | 任務管理 | All/My Day 視圖、create/edit/complete、priority/energy/due filter |
| `/admin/goals` | 目標追蹤 | 唯讀 + status 切換 |
| `/admin/projects` | 專案管理 | 列表 + 連結到 project-editor |
| `/admin/tags` | Tag 管理 | 兩 tab：Canonical Tags (CRUD + merge + backfill) / Aliases (map/confirm/reject) |
| `/admin/notion-sources` | Notion 整合 | discover + connect + role 設定 + toggle |
| `/admin/flow-runs` | AI Flow 監控 | status/name filter、詳情、retry |
| `/admin/activity` | 活動紀錄 | session 視圖 + timeline 視圖 |
| `/admin/insights` | Insight 管理 | status filter、verify/invalidate、add evidence |
| `/admin/planning` | 計畫分析 | 14 天趨勢 + day-of-week heatmap |
| `/admin/tracking` | 追蹤主題 | CRUD（只有 metadata，無 data points） |
| `/admin/pipeline` | Pipeline 觸發 | 7 個手動操作按鈕 |

Admin sidebar 導航分組：
- 概覽：Dashboard, Today
- 內容：Contents, Review, Collected, Feeds
- 組織：Tags, Notion Sources
- 追蹤：Tasks, Goals, Projects, Insights, Tracking
- 系統：Flow Runs, Activity, Planning, Pipeline

---

## 已知問題和半成品

### Bug

| 問題 | 影響 |
|------|------|
| Pipeline 頁面打 `/api/pipeline/{action}`，Backend 路由是 `/api/admin/pipeline/{action}` | 所有 pipeline 操作 404 |
| Collected 頁面沒有 curate 按鈕 | 收集的文章無法轉為正式 bookmark content |

### 缺的東西

| 項目 | 狀態 |
|------|------|
| Knowledge Graph 視覺化 | Backend API 有、Frontend service 有、**頁面沒有** |
| 獨立 Search 頁面 | Backend 搜全站所有 type，Frontend 搜尋只嵌在 articles 頁面 |
| Build logs public route | Backend API 是 public 的，Frontend route 放在 admin children |
| Essay / Bookmark / Digest 公開頁面 | Backend 支援，Frontend 沒有獨立頁面 |
| Obsidian notes admin 管理 | Backend API 有 (`/api/admin/notes`)，Frontend 完全沒頁面 |
| Topic admin CRUD | Backend API 有，Frontend 沒有獨立管理頁面（topic 選擇只在 editor 裡） |

### 半成品

| 項目 | 現狀 |
|------|------|
| Tracking | 只有 topic metadata CRUD，沒有 data point 記錄和 visualization |
| Feed manual fetch | Backend 有，Frontend 不確定有沒有做在 UI 上 |
| Batch My Day | Backend 有 batch API，Frontend 的 batch 操作不明確 |

---

## 資料庫概覽

21 張表，按功能分：

```
內容系統
├── contents          主內容（7 types, embedding, full-text search）
├── content_topics    content ↔ topic 多對多
├── topics            知識主題
├── tags              canonical tags
├── tag_aliases       raw tag → canonical tag 映射
├── note_tags         note ↔ tag 多對多
├── review_queue      待審核佇列
└── collected_data    RSS 收集的候選文章

知識庫
├── notes             Obsidian 筆記（embedding, full-text）
└── note_links        note ↔ note 關聯（知識圖譜）

外部整合
├── feeds             RSS feed 設定
├── notion_sources    Notion database 連接
├── tasks             Notion 同步的 todo
├── goals             Notion 同步的目標
└── projects          專案（Notion 同步 + 手動）

AI & 監控
├── flow_runs         AI flow 執行紀錄
├── session_notes     AI 產生的工作日誌 + insights
├── activity_events   系統活動紀錄
└── tracking_topics   追蹤主題設定

認證
├── users             使用者
└── refresh_tokens    JWT refresh token
```

關鍵索引：
- `contents.search_vector` — GIN index (全文搜尋)
- `contents.embedding` — HNSW index (語義相似度，pgvector)
- 所有 `slug`、`notion_page_id`、`url` 都有 UNIQUE constraint

---

## API 組織

```
/api/                          公開（無需 auth）
├── contents                   內容瀏覽
├── contents/{slug}            內容詳情
├── contents/by-type/{type}    按類型瀏覽
├── contents/related/{slug}    相關推薦
├── topics                     主題列表
├── projects                   公開專案
├── search                     全站搜尋
├── knowledge-graph            知識圖譜
├── feed/rss                   RSS 輸出
├── feed/sitemap               Sitemap
└── auth/                      OAuth 認證

/api/admin/                    需 JWT auth
├── contents                   內容 CRUD + publish + visibility
├── review                     審核佇列
├── flow/polish                AI 潤色
├── collected                  收集審核
├── feeds                      RSS 管理
├── tasks                      任務管理
├── goals                      目標管理
├── projects                   專案 CRUD
├── topics                     主題 CRUD
├── tags + aliases             標籤管理
├── notion-sources             Notion 整合
├── flow-runs                  AI 監控
├── activity                   活動紀錄
├── session-notes              Session notes
├── insights                   Insight 管理
├── tracking                   追蹤主題
├── stats                      統計報表
├── today/summary              每日摘要
├── pipeline/                  Pipeline 手動觸發
├── upload                     檔案上傳
└── notes + decisions          Obsidian 筆記（admin only）

/api/webhook/                  HMAC 驗證（外部服務呼叫）
├── github                     GitHub push/PR 事件
└── notion                     Notion database 變更
```

---

## MCP Server（Claude 整合）

除了 Web API，Backend 還暴露了一個 MCP (Model Context Protocol) server，讓 Claude Code 直接操作系統。

這是「AI 幫你管系統」的入口：Claude 可以透過 MCP tools 建立 content、管理 task、搜尋知識庫、觸發 pipeline — 不需要開瀏覽器。

MCP 大約有 45 個 tool（曾經 47 個，經過整理縮減），分組：
- 內容讀寫
- 任務管理
- RSS 管理
- 系統診斷
- 學習追蹤
- Morning/Evening context

---

## 開發分工

| 角色 | 負責範圍 |
|------|---------|
| Koopa | Go API、AI Pipeline、Obsidian 整合、資料收集、MCP server |
| Claude Code (Frontend) | Angular 前端、API 對接、Admin UI、設計調整 |
| Claude Code (Backend) | Go 開發輔助、code review、test writing |
