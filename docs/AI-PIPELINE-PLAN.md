# AI Pipeline 實施計劃 v3.4

> koopa0.dev AI Pipeline 的完整規劃文件。
> 包含專案上下文、已完成的工作、預計要做的事情、技術決策記錄。
> 適合與人討論、自己回顧、或新加入者理解全貌。

---

## 目錄

1. [專案上下文](#專案上下文)
2. [已完成的工作](#已完成的工作)
3. [AI Pipeline 總覽](#ai-pipeline-總覽)
4. [系統架構](#系統架構)
5. [Phase 分期](#phase-分期)
6. [RSS 來源清單](#rss-來源清單)
7. [技術決策記錄](#技術決策記錄)
8. [資源控制](#資源控制)
9. [前端開發時間線](#前端開發時間線)
10. [總時間線](#總時間線)

---

## 專案上下文

### koopa0.dev 是什麼

koopa0.dev 不是一個部落格，是一個**個人知識引擎平台**。它有三個面向：

1. **輸入** — Obsidian 知識庫同步、外部資料主動收集（RSS/API）
2. **處理** — Go Genkit AI Pipeline：校對、分類、生成草稿、審核分級
3. **輸出** — Angular SSR 網站：主題式內容呈現、個人品牌展示

```
學習 (Obsidian) → 整理 (AI 審核 + 潤色) → 發佈 (Blog)
     ↑                                         ↓
規劃 (建議下一步) ← 分析 (知識缺口) ← 追蹤 (產出頻率)
```

AI 的角色是**處理層**——自動化人類不想手動做的重複工作，浮現人類看不到的模式。

### 技術棧

| 層   | 技術                                                                                                                                     |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 前端 | Angular 21, Tailwind CSS v4, SSR                                                                                                         |
| 後端 | Go 1.26+, net/http (std lib), PostgreSQL 17 (pgx/v5), sqlc                                                                               |
| AI   | Genkit Go 1.0 (DefineFlow + GenerateData + multi-provider plugins), Gemini 3 Flash (content-review) + Claude Sonnet 4.6 (content-polish) |
| 儲存 | Cloudflare R2 (S3-compatible)                                                                                                            |
| 部署 | Docker, VPS (Hostinger), Cloudflare Tunnel                                                                                               |

### 部署架構

```
瀏覽器 → Cloudflare Tunnel → SSR Server (:4000) → Go Backend (:8080) → PostgreSQL (:5432)
                                  ↑ BFF proxy /bff/*                        ↓
                                  └── 後端零暴露，不對外                Cloudflare R2
```

- **VPS**: Hostinger KVM 2 (2 vCPU / 8GB RAM / 96GB), Ubuntu 24.04
- **流量入口**: Cloudflare Tunnel，只有 SSH port 對外
- **後端**: Go API (port 8080)，只在 Docker 內網可達
- **資料庫**: PostgreSQL 17 (Docker)，只在 Docker 內網可達

### 內容類型

| 類型        | 說明                 | 來源                   |
| ----------- | -------------------- | ---------------------- |
| `article`   | 深度技術文章         | Obsidian / AI 潤色     |
| `essay`     | 個人想法、非技術反思 | Obsidian               |
| `build-log` | 專案開發紀錄         | 手動 → Phase 4 AI 彙整 |
| `til`       | 每日學習（短）       | Obsidian               |
| `note`      | 技術筆記片段         | Obsidian               |
| `bookmark`  | 推薦資源 + 個人評語  | RSS 收集 → AI 摘要     |
| `digest`    | 週報/月報            | AI 自動生成            |

### Monorepo 結構

```
/Users/koopa/blog/
├── frontend/     # Angular 21 前端（SSR + Tailwind v4）
├── ./      # Go API + AI Pipeline
├── docs/         # 共用設計文件
│   ├── PLATFORM-VISION.md   ← 完整平台設計
│   ├── API.md               ← API 規格
│   ├── AI-PIPELINE-SCENARIOS.md  ← 35+ AI 情境列表
│   └── AI-PIPELINE-PLAN.md  ← 你正在讀的這份
└── CLAUDE.md
```

---

## 已完成的工作

### 後端核心（Phase A：API 基礎）— ✅ 已完成

所有基礎 CRUD API 和認證系統已實作完成，可對外運作。

**認證系統 (`internal/auth/`)**

- JWT access token (15min) + refresh token (7天) rotation
- bcrypt 密碼雜湊
- `POST /api/auth/login`, `POST /api/auth/refresh`

**內容管理 (`internal/content/`)**

- 完整 CRUD：建立、更新、發佈、歸檔
- 7 種內容類型（article, essay, build-log, til, note, bookmark, digest）
- 4 種狀態（draft → review → published → archived）
- Full-text search（PostgreSQL TSVECTOR）
- RSS feed + sitemap 生成
- Topic 多對多關聯

**主題分類 (`internal/topic/`)**

- Topic CRUD + 自動計算每個 topic 的已發佈 content 數量

**專案作品集 (`internal/project/`)**

- Portfolio 展示 CRUD，支援 featured 排序

**審核佇列 (`internal/review/`)**

- Review queue：pending → approved / rejected
- 支援 review level（auto, light, standard, strict）

**外部資料收集 (`internal/collected/`)**

- Collected data CRUD + 狀態流（unread → read → curated/ignored）
- 可連結到 Content（curated → content_id）

**追蹤設定 (`internal/tracking/`)**

- Tracking topic 設定 CRUD（keywords, sources, schedule）

### Phase B：Obsidian Sync（GitHub Webhook）— ✅ 已完成

**Obsidian 同步 (`internal/pipeline/` + `internal/obsidian/`)**

- GitHub push webhook → HMAC-SHA256 簽名驗證
- 過濾 `10-Public-Content/*.md` 檔案
- 呼叫 GitHub Contents API 取得 base64 內容
- YAML frontmatter 解析：title, tags, published, created, updated
- 階層式 tag 分類：`type/article` → content_type, `golang/memory` → topic slug
- 建立或更新 content，自動發佈（如果 `published: true`）
- 非阻塞：回傳 202 Accepted，背景 goroutine 同步

**Consumer-defined interfaces**

- `ContentWriter`: pipeline 操作 content 的介面
- `TopicLookup`: pipeline 查詢 topic slug → UUID 的介面
- `GitHubFetcher`: pipeline 取得 GitHub 檔案的介面

**測試**

- 13 個 table-driven tests：VerifySignature (6), ChangedFiles (3), FilterPublicMarkdown (4), SlugFromPath (3)

### Phase C：R2 圖片上傳 — ✅ 已完成

**上傳 (`internal/upload/`)**

- `POST /api/admin/upload` — multipart file upload → Cloudflare R2
- 限制 5MB，僅允許 image/jpeg, image/png, image/webp, image/gif
- MIME type 由 `http.DetectContentType` 偵測（magic bytes，非副檔名）
- UUID-based key：`uploads/<uuid>.<ext>`
- R2 public URL: `https://pub-804a8da954f04c0d905575452865f416.r2.dev`

### 資料庫 Schema — ✅ 已完成

所有 schema 在 `migrations/001_initial.up.sql`（Pre-release 階段直接改這個檔案，不新增 migration）。

| 表                | 用途                                 |
| ----------------- | ------------------------------------ |
| `users`           | Admin 使用者                         |
| `refresh_tokens`  | JWT refresh token（hash 儲存）       |
| `topics`          | 內容分類                             |
| `contents`        | 所有內容（7 種類型）                 |
| `content_topics`  | 多對多關聯                           |
| `projects`        | 作品集                               |
| `review_queue`    | 審核佇列                             |
| `collected_data`  | 外部收集資料                         |
| `tracking_topics` | 收集追蹤設定                         |
| `flow_runs`       | Flow 執行歷史 + 重試（Phase 1 新增） |

### 現有 API 端點 — 34 個（13 public + 21 admin）

**Public (無需認證)**

```
GET  /api/contents                 # 分頁列表
GET  /api/contents/{slug}          # 單篇
GET  /api/contents/type/{type}     # 依類型
GET  /api/search?q=...             # 全文搜尋
GET  /api/feed/rss                 # RSS feed
GET  /api/feed/sitemap             # Sitemap
POST /api/auth/login               # 登入
POST /api/auth/refresh             # Token 刷新
GET  /api/topics                   # 所有主題
GET  /api/topics/{slug}            # 單一主題 + 內容
GET  /api/projects                 # 所有專案
GET  /api/projects/{slug}          # 單一專案
POST /api/webhook/github           # GitHub webhook（HMAC 驗證）
```

**Admin (JWT 保護)**

```
POST|PUT|DELETE /api/admin/contents/*     # Content CRUD + Publish
GET|POST /api/admin/review/*              # Review Queue 操作
GET|POST /api/admin/collected/*           # Collected Data 操作
POST|PUT|DELETE /api/admin/projects/*     # Project CRUD
POST|PUT|DELETE /api/admin/topics/*       # Topic CRUD
GET|POST|PUT|DELETE /api/admin/tracking/* # Tracking CRUD
POST /api/admin/upload                    # R2 上傳
```

**Pipeline Stubs (已註冊但回 501)**

```
POST /api/pipeline/sync       # 手動觸發同步
POST /api/pipeline/collect    # 手動觸發收集
POST /api/pipeline/generate   # 手動觸發生成
POST /api/pipeline/digest     # 手動觸發 digest
POST /api/webhook/obsidian    # Obsidian webhook
POST /api/webhook/notion      # Notion webhook（Phase 3 實作，HMAC-SHA256 驗簽）
```

### Phase 1 進行中

**已完成：**

- `internal/flow/` — Genkit Flow 定義（content-review flow：proofread + excerpt + tags + reading time + embedding stub）
- `internal/flowrun/` — in-process worker pool + flow_runs 表 + Cron 重試（Runner unit tests + Store integration tests 12/12 PASS）
- `prompts/` — review.txt, excerpt.txt, tags.txt（system prompt，非 dotprompt 格式）
- Calibration 通過 — 7 篇 Obsidian 文章全部成功（gemini-3-flash-preview）
- flow_runs migration（含 retry 三分支：failed + stuck-pending + stuck-running）

**尚未實作：**

- `content-polish` flow（A5，Phase 1 後半）
- `internal/collector/`（RSS 收集器，Phase 2）
- `internal/notion/`（Notion webhook handler + API client，Phase 3）
- `internal/webhook/`（共用 HMAC-SHA256 驗簽，Phase 3）
- OpenTelemetry（import 已加但未 wiring）

---

## AI Pipeline 總覽

### 確定要做的

| 情境                       | 說明                                                                      | Phase |
| -------------------------- | ------------------------------------------------------------------------- | ----- |
| **A1 文章審核**            | AI 校對 + 決定直接發佈 or review queue                                    | 1     |
| **A2 Excerpt 生成**        | 自動產出 2-3 句摘要                                                       | 1     |
| **A3 Reading Time**        | `字數 / 250` + 程式碼區塊權重（純計算）                                   | 1     |
| **A4 Tag/Topic 建議**      | Constrained classification 到現有 topics                                  | 1     |
| **A5 筆記→文章潤色**       | system prompt 定義風格規範，不塞 few-shot                                 | 1     |
| **B1 Build Log（輕量版）** | 手動寫 markdown，走 content-review 同流程                                 | 1     |
| **Embedding 生成**         | content-review 最後一步，為 Phase 5 累積向量                              | 1     |
| **D1 RSS 收集**            | 自建 gofeed + 條件請求 + 去重                                             | 2     |
| **D2 AI 篩選評分**         | 四維度評分 + feedback loop 校準                                           | 2     |
| **D3 自動摘要**            | 繁體中文摘要 + 標題翻譯                                                   | 2     |
| **B2 週報/月報**           | 自動彙整一段時間的 contents                                               | 2     |
| **B3 Bookmark 生成**       | 從收集文章生成摘要 + 個人評語                                             | 2     |
| **Feedback loop**          | thumbs up/down 校準評分權重                                               | 2     |
| **C1 Projects 同步**       | Notion → Blog 單向同步                                                    | 3     |
| **C2 Tasks 狀態變更**      | Notion webhook → project last_activity 更新 + build-log 素材累積，不需 AI | 3     |
| **C5 Reading List**        | 讀完觸發 B3 bookmark 生成                                                 | 3     |
| ~~**C6 回顧提醒**~~        | ~~獨立 Cron + 模板文字~~ → `planning` flow 的 I3 週五回顧涵蓋（TDR #17）  | ~~3~~ |
| **B1 Build Log（完整版）** | Notion tasks + GitHub commits → AI 彙整                                   | 4     |
| **H1 Commit 追蹤**         | GitHub push → 更新 project 進度                                           | 4     |
| **C4 執行率分析**          | 計劃 vs 實際完成                                                          | 4     |
| **I1 Morning Brief**       | 每日摘要，透過 Telegram Bot 送達                                          | 4     |
| **I3 週五回顧**            | 自動生成本週做了什麼                                                      | 4     |
| **G1 內容策略**            | 「你的 X 系列缺一篇 Y」                                                   | 4     |
| **G2 系列文規劃**          | 分析 topic 筆記群，建議系列文大綱                                         | 4     |
| **G3 發佈節奏**            | analytics dashboard 的一個 widget                                         | 4     |

### 確定不做的

| 情境              | 理由                   |
| ----------------- | ---------------------- |
| G4 讀者視角審核   | 低價值，直接用 ChatGPT |
| C3 AI 安排任務    | AI 不了解精力狀態      |
| E1 每日任務建議   | 跟 C3 重疊             |
| I2 Context Switch | 缺乏追蹤數據           |
| B4 TIL 生成       | 自動生成沒有靈魂       |
| A6 SEO 建議       | 流量不夠時 ROI 太低    |
| F2 刻意練習       | 判斷標準不明           |
| F3 費曼檢測       | 直接用 ChatGPT         |

### 長期（需資料累積 + Phase 1 embedding 數據）

| 情境              | 前置條件                           |
| ----------------- | ---------------------------------- |
| F1 知識圖譜視覺化 | pgvector + D3.js + ≥100 篇 content |
| F4 跨領域連結發現 | pgvector embeddings                |
| E3 知識缺口分析   | ≥50 篇 + ≥3 個月追蹤資料           |
| C1 雙向同步       | 觀察單向是否足夠                   |

> 完整 35+ 情境列表見 `docs/AI-PIPELINE-SCENARIOS.md`

---

## 系統架構

### 整體架構圖

```
觸發層                      執行層                         儲存層
──────                      ──────                         ──────
GitHub Webhook ──┐
Notion Webhook ──┤          In-process worker pool        PostgreSQL
Cron (robfig) ───┤          channel + goroutine            ├─ flow_runs（歷史 + 重試）
Manual API ──────┘          max 3 concurrent flows        ├─ contents
                                    │                      ├─ feeds
                            Genkit Flows (8 個)            └─ collected_data
                            ├─ content-review
                            ├─ content-polish
                            ├─ content-generate           LLM Providers
                            ├─ collect-and-score          ├─ Gemini 3 Flash（批量：review, RSS）
                            ├─ notion-sync                ├─ Claude Sonnet 4.6（對外發佈：polish）
                            ├─ analytics                  └─ Embedding model（向量累積）
                            ├─ planning
                            └─ project-track              Telegram Bot API
                                                          └─ Morning Brief 送達
```

### 為什麼 in-process，不用 NATS

所有 consumer 跑在同一個 process，NATS 解決的核心問題（多 consumer group、跨 service 投遞）用不到。這是一個人的 side project。

| 需求         | In-process 方案                                     |
| ------------ | --------------------------------------------------- |
| 非同步處理   | `chan FlowJob` + goroutine pool                     |
| 重試         | `flow_runs` 表 status + attempt + Cron 掃描失敗任務 |
| 並發控制     | semaphore（`chan struct{}`，cap=3）                 |
| 歷史查詢     | `flow_runs` 表                                      |
| 一事件多下游 | handler 裡 submit 多個 job                          |
| 持久化       | `flow_runs` 表（PostgreSQL WAL 保證，比 NATS 更強） |

如果未來需要跨 service 通訊，再加 NATS。不要預先解決不存在的問題。

### In-process Worker Pool 設計

```go
// internal/flowrun/

type Runner struct {
    store    runnerStore       // consumer-defined interface（5 methods）
    registry *flow.Registry   // flow name → Flow implementation
    jobs     chan uuid.UUID    // 非阻塞提交（run ID，不是 Job struct）
    sem      chan struct{}     // 並發控制，cap=3
    logger   *slog.Logger
    cancel   context.CancelFunc
    wg       sync.WaitGroup
}

// Submit: 寫入 flow_runs 表 + 送入 channel（非阻塞，滿了靠 Cron 重試）
// Start:  啟動 dispatch loop，semaphore 控制並發，30s hard timeout 防 shutdown 死鎖
// Requeue: Cron 掃描後把 run ID 送回 channel
// RetryableFlowRuns: UPDATE...SET status='pending'
//   WHERE (failed AND attempt < max)
//      OR (stuck-pending > 5min AND attempt < max)
//      OR (stuck-running > 10min AND attempt < max)
//   RETURNING * — PostgreSQL row-level lock 防重複執行

// Worker pool 為 FIFO，不設優先級。實務上觸發時間錯開（RSS cron vs webhook push），衝突機率低。
```

### 新增 Package（Phase 1-4）

```
internal/
├── flowrun/        in-process worker pool + flow_runs 表操作（✅ 已完成）
├── flow/           Genkit Flow 定義 + embed.FS prompt 載入（✅ content-review 完成）
│   └── prompts/    system prompt 文字檔（*.txt，go:embed 載入）
├── collector/      RSS 收集：fetcher、dedup、store（Phase 2）
├── notion/         Notion webhook handler + API client（Phase 3，讀 UB 3.0 databases）
├── webhook/        共用 HMAC-SHA256 驗簽（Phase 3）
├── pipeline/       保留：webhook handlers（已有）
├── obsidian/       保留：frontmatter parser（已有）

internal/flow/prompts/    # embed.FS 載入，不用 dotprompt
├── review.txt            # 校對 + auto_publish 決策
├── excerpt.txt           # 摘要生成
├── tags.txt              # 標籤建議
└── polish.txt            # 潤色（Phase 1 後半）
```

### 新增 DB 表（加入 001_initial.up.sql）

```sql
-- flow_status enum
CREATE TYPE flow_status AS ENUM ('pending', 'running', 'completed', 'failed');

-- flow_runs — Flow 執行歷史 + 重試
flow_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_name TEXT NOT NULL,
  input JSONB NOT NULL,
  status flow_status NOT NULL DEFAULT 'pending',
  output JSONB,
  error TEXT,
  attempt INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ    -- 注意：不是 completed_at
)

-- feeds — RSS 來源設定（含 error tracking）
feeds (
  id UUID PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  schedule TEXT NOT NULL,            -- 'hourly_4', 'daily', 'weekly'
  topics TEXT[] NOT NULL DEFAULT '{}',
  enabled BOOLEAN NOT NULL DEFAULT true,
  etag TEXT NOT NULL DEFAULT '',
  last_modified TEXT NOT NULL DEFAULT '',
  last_fetched_at TIMESTAMPTZ,
  consecutive_failures INT NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  disabled_reason TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)

-- collected_data 擴充欄位
-- + url_hash TEXT NOT NULL UNIQUE  -- hex-encoded SHA-256, 不用 BYTEA（psql debug 可讀性）
-- + ai_score SMALLINT
-- + ai_score_reason TEXT
-- + ai_summary_zh TEXT
-- + ai_title_zh TEXT
-- + user_feedback TEXT  -- 'up', 'down', NULL
-- + feedback_at TIMESTAMPTZ

-- notion_webhook_events — TBD：Phase 3 實作時決定是否需要獨立表
-- 可能直接用 flow_runs 的 input JSONB 做冪等檢查（event_id as dedup key）
-- 如果 webhook volume 高或需要獨立查詢，再建此表
```

### Genkit Flow 對應

| Flow              | 涵蓋情境                   | LLM 模型                   | 觸發                                       |
| ----------------- | -------------------------- | -------------------------- | ------------------------------------------ |
| content-review    | A1, A2, A3, A4 + embedding | Gemini 3 Flash + embedding | Webhook sync 後自動                        |
| content-polish    | A5                         | Claude Sonnet 4.6          | 手動觸發                                   |
| content-generate  | B1(完整版), B2, B3         | TBD（Phase 2 決定）        | Cron / 手動                                |
| collect-and-score | D1, D2, D3                 | Gemini 3 Flash             | Cron                                       |
| notion-sync       | C1, C2, C5                 | 無 LLM                     | Notion webhook 觸發                        |
| analytics         | C4, E2-E4, G1, G3          | Gemini 3 Flash             | 週期性 / 手動                              |
| planning          | I1, I3, G2                 | Gemini 3 Flash             | Cron（直接讀 UB databases via Notion API） |
| project-track     | H1                         | Gemini 3 Flash             | GitHub webhook / 手動                      |

---

## Phase 分期

### Phase 0：內容引導（Phase 1 前提）

> **前提：koopa0.dev 上需要有實際內容，AI pipeline 才有東西可跑。**

目前已發佈內容數量：**0 篇**。

在開始 Phase 1 之前，先手動從 Obsidian 同步 3-5 篇已完成的筆記到 koopa0.dev。這些文章是：

- content-review flow 的第一批測試輸入
- A5 content-polish 的「什麼品質算好」的基準參考
- 讓網站不是空的

**做法：**

- 從 Obsidian `10-Public-Content/` 挑 3-5 篇已經寫好的筆記
- 設定好 frontmatter（type, tags, published: true）
- Push 到 GitHub repo → 觸發現有的 webhook sync
- 確認 content 正確出現在 koopa0.dev

**這不是 AI pipeline 的工作，是人的工作。** 但不做這步，Phase 1 上線後跑 0 篇文章 = 0 價值。

### Phase 1：核心 Content Pipeline（3-4 週）

> 目標：**Obsidian 筆記同步後，自動審核 + 摘要 + 標籤 + embedding + 可手動潤色**
> 前提：Phase 0 完成，至少有 3 篇已發佈 content

**基礎設施：**

- [x] `internal/flowrun/` — in-process worker pool + flow_runs 表 + Cron 重試
- [x] `internal/flow/` — Genkit 架構 + embed.FS prompt 載入
- [x] `flow_runs` migration（加入 001_initial.up.sql，含 flow_status enum）
- [x] Cron 排程框架（robfig/cron，@every 2m 掃描 retryable runs）

**Flows：**

- [x] `content-review` flow（A1 + A2 + A4 + A3 + embedding stub）
  - Step 1: 校對（錯字、語法）→ 決定 auto_publish or needs_review（sequential，後續步驟依賴此結果）
  - Step 2-5 **並行**（errgroup）：excerpt、tags、reading time、embedding 彼此無依賴
    - Step 2: 生成 excerpt
    - Step 3: 建議 tags/topics（constrained to existing topics）
    - Step 4: 計算 reading time（純計算）
    - Step 5: embedding stub（Phase 5 接入 embedding model）
  - Calibration 7/7 篇通過（gemini-3-flash-preview，~10-15s/篇）
- [ ] `content-polish` flow（A5）
  - Claude Sonnet 4.6 via Genkit Anthropic plugin
  - system prompt 定義風格規範（語氣、結構、禁忌詞）
  - 不塞 few-shot，等累積滿意文章再加

**Prompts：**

- [x] `internal/flow/prompts/review.txt` — 校對 + auto_publish 決策
- [x] `internal/flow/prompts/excerpt.txt` — 摘要生成
- [x] `internal/flow/prompts/tags.txt` — 標籤建議
- [ ] `internal/flow/prompts/polish.txt` — 潤色（system prompt 風格定義）

**Pipeline 修改：**

- [x] webhook sync 完成後 → Submit content-review job
- [ ] content-review dedup — `flow_runs` 表用 `content_id + flow_name + status` 防止同一篇文章重複 submit（Obsidian Git auto-push 或手動連續 push 會觸發多個 webhook）
- [ ] Admin API: `POST /api/admin/flow/polish/{content_id}` 手動觸發潤色
- [x] Admin API: `GET /api/admin/flow-runs` flow 執行歷史

**B1 輕量版：**

- [x] Build Log = content_type `build-log` 的文章，手動寫 markdown
- [x] 走 content-review 同流程（校對 + excerpt + tags）

**前端配合（optional，不阻擋 Phase 1 後端完成）：**

- Review Queue 顯示 AI 審核結果（校對問題、建議 tags、excerpt 預覽）
- Content 編輯頁新增「AI 潤色」按鈕（before/after diff）

**成功指標：**

- 同步一篇筆記後 10 秒內完成審核（測量：`flow_runs.ended_at - created_at`）
- Excerpt 品質：10 篇中 ≥7 篇不需人工修改（測量：人工抽檢 review queue）
- Tags 準確率 ≥80%（測量：calibration script 比對 frontmatter 原始 tags）
- Embedding 向量成功寫入（Phase 1 為 stub — 此指標延後到接入 embedding model 後驗證）

### Phase 2：RSS 自建收集 + Digest 生成（4-5 週）

> 目標：**自建 RSS 收集，AI 篩選評分 + feedback loop，自動生成週報/月報**

**RSS 收集：**

- [ ] `internal/collector/` — gofeed 抓取、URL hash 去重、條件請求（ETag/Last-Modified）
- [ ] `feeds` migration — 含 error tracking（consecutive_failures, last_error, disabled_reason）
- [ ] `collected_data` 擴充 — url_hash, ai_score, ai_summary_zh, user_feedback
- [ ] 三級排程 — 每 4 小時 / 每日 / 每週
- [ ] 連續失敗 5 次自動 disable + slog 告警
- [ ] Admin API — RSS 來源 CRUD、手動觸發抓取

**AI 篩選（collect-and-score flow）：**

- [ ] 四維度評分：relevance × 0.35 + depth × 0.30 + freshness × 0.15 + quality × 0.20
- [ ] 閾值：≥7.0 自動推薦、≥5.0 存檔、<5.0 跳過
- [ ] 繁體中文摘要 + 標題翻譯

**Feedback loop：**

- [ ] 前端收集文章列表加 thumbs up/down（icon button）
- [ ] 記到 `collected_data.user_feedback` + `feedback_at`
- [ ] 累積 100+ 筆 feedback 後手動分析調權重

**內容生成：**

- [ ] `content-generate` flow — B2 週報/月報 Digest
- [ ] B3 Bookmark 生成 — 從收集文章 → AI 摘要 + 個人評語 → content

**成功指標：**

- RSS 來源 ≥50 個，涵蓋 ≥5 個分類
- 每日收集 ≥20 篇新文章
- AI 評分與人工判斷一致率 ≥75%（用 feedback 數據驗證）
- 連續失敗的 feed 自動 disable

### Phase 3：Notion UB 3.0 整合（3-4 週）

> 目標：**透過 Notion Integration Webhooks 接收 UB 3.0 工作流事件，同步 Projects + Tasks + Reading List**
> 前提：Notion Integration 已建立並連接到 UB 3.0 的 databases

**職責邊界（硬規則）：**

- Obsidian = 所有筆記和知識內容（技術筆記、隨手記、學習筆記、文章草稿）
- Notion UB 3.0 = 工作流和行動（Tasks、Projects 進度、Books/Reading List 狀態）
- Notion Notes database = 僅限 task/project 綁定的 context（會議記錄、task 補充說明），不進 pipeline 的內容流

**Webhook 基礎設施：**

- [ ] `internal/webhook/` — 共用 HMAC-SHA256 驗簽（從 `pipeline.VerifySignature` 抽出，GitHub + Notion 共用）
  - 遷移步驟：先抽出 → 改 `pipeline` import 新 package → 跑 `/verify` 確認 GitHub webhook 不 regress → 再加 Notion
- [ ] `internal/notion/` — Notion webhook handler + Notion API client
- [ ] Notion Integration 設定 — 建立 webhook subscription，訂閱 page.content_updated + page.created events
  - 先驗證 Free plan 是否支援 Integration Webhooks（如不支援，需 Plus ~$10/month）
- [ ] `POST /api/webhook/notion` — 實作（目前 stub 回 501）

**Flows：**

- [ ] `notion-sync` flow — 收到 webhook event 後:
  - 用 entity.id call Notion API 拉 page content
  - 判斷來源 database（Projects / Tasks / Reading List）
  - C1: Projects → 更新 `projects` 表
  - C2: Tasks → 狀態變更 webhook → 更新 project `last_activity` + 累積 build-log 素材（Phase 4 B1 完整版用）
  - C5: Books database status=Done → 觸發 B3 bookmark 生成（UB 3.0 Books 是獨立 database，直接讀）
- ~~C6 週期回顧提醒~~ → `planning` flow 自建（見 TDR #17）

**成功指標：**

- Notion webhook → pipeline 處理延遲 < 2 分鐘（含 Notion 的 aggregation delay）
- 連續 7 天零同步錯誤
- Reading List 讀完 → bookmark draft 成功率 ≥90%

### Phase 4：Build Log 完整版 + 分析與規劃（4-5 週）

> 目標：**Build Log 自動彙整 + 知識飛輪回饋 + Telegram 送達**

- [ ] B1 Build Log 完整版（Notion tasks + GitHub commits → AI 彙整）
- [ ] `project-track` flow — H1 Commit → 進度更新
- [ ] `analytics` flow — C4 執行率、內容分佈、G3 發佈節奏（dashboard widget）
- [ ] `planning` flow:
  - I1 Morning Brief: Cron 每天 07:30 → 讀 UB Tasks（今日 due + overdue）+ 昨日 RSS highlights → Gemini Flash 生成摘要 → Telegram 送達
  - I3 週五回顧: Cron 每週五 17:00 → 讀本週 completed Tasks（UB 3.0 Task History 原生支援，不需自建追蹤）+ GitHub commits + published contents + RSS highlights → 生成回顧
  - G2 系列文規劃: 手動觸發 → 讀 contents 的 topic 分佈 + embedding 相似度 → 建議系列文大綱
- [ ] G1 內容策略建議
- [ ] I1 Morning Brief 透過 Telegram Bot 送達

**成功指標：**

- Build Log 草稿「想發佈」比例 ≥60%
- Morning Brief 每天 08:00 前 Telegram 送達
- Analytics 能識別「最近寫太多 X，Y 已 N 週沒更新」

### Phase 5：進階功能（長期）

> 需要 3-6 個月內容累積。Embedding 從 Phase 1 開始累積，到這裡直接可用。

- [ ] F1 知識圖譜視覺化（pgvector + D3.js）
- [ ] F4 跨領域連結發現（embedding 相似度）
- [ ] E3 知識缺口分析
- [ ] C1 雙向同步（觀察單向是否足夠）

---

## RSS 來源清單

### Go 生態（13 個）

| 來源                | RSS URL                                            | 頻率                                          |
| ------------------- | -------------------------------------------------- | --------------------------------------------- |
| Go Blog             | `https://go.dev/blog/feed.atom`                    | 每週                                          |
| Ardan Labs          | `https://www.ardanlabs.com/blog/index.xml`         | 每月 2-4 篇                                   |
| Eli Bendersky       | `https://eli.thegreenplace.net/feeds/all.atom.xml` | 每月 1-3 篇                                   |
| Dave Cheney         | `https://dave.cheney.net/feed`                     | 不定期（⚠️ 已長期未更新，Phase 2 啟用前驗證） |
| Golang Weekly       | `https://golangweekly.com/rss/`                    | 每週                                          |
| Three Dots Labs     | `https://threedots.tech/index.xml`                 | 每月 1-2 篇                                   |
| Bitfield Consulting | `https://bitfieldconsulting.com/posts?format=rss`  | 每月                                          |
| Go Time Podcast     | `https://changelog.com/gotime/feed`                | 每週                                          |
| r/golang            | `https://www.reddit.com/r/golang/top/.rss?t=week`  | 持續                                          |
| Brandur             | `https://brandur.org/articles.atom`                | 不定期                                        |
| Filippo Valsorda    | `https://words.filippo.io/rss/`                    | 不定期                                        |
| Xe Iaso             | `https://xeiaso.net/blog.rss`                      | 每月數篇                                      |
| Thorsten Ball       | `https://registerspill.thorstenball.com/feed`      | 每週                                          |

### 系統設計/後端（10 個）

| 來源                   | RSS URL                                         | 頻率        |
| ---------------------- | ----------------------------------------------- | ----------- |
| Hacker News Best       | `https://hnrss.org/best?points=100`             | 持續        |
| The Pragmatic Engineer | `https://newsletter.pragmaticengineer.com/feed` | 每週        |
| ByteByteGo             | `https://blog.bytebytego.com/feed`              | 每週        |
| Martin Fowler          | `https://martinfowler.com/feed.atom`            | 不定期      |
| Architecture Notes     | `https://architecturenotes.co/rss/`             | 每月        |
| InfoQ                  | `https://feed.infoq.com/`                       | 每日        |
| Fly.io Blog            | `https://fly.io/blog/feed.xml`                  | 每週        |
| Julia Evans            | `https://jvns.ca/atom.xml`                      | 每月 2-4 篇 |
| Oxide Computer         | `https://oxide.computer/blog/feed`              | 不定期      |
| Changelog              | `https://changelog.com/feed`                    | 每日        |

### PostgreSQL（6 個）

| 來源              | RSS URL                                    | 頻率 |
| ----------------- | ------------------------------------------ | ---- |
| PostgreSQL Weekly | `https://postgresweekly.com/rss/`          | 每週 |
| Citus Blog        | `https://www.citusdata.com/blog/rss.xml`   | 每月 |
| pganalyze         | `https://pganalyze.com/blog.rss`           | 每月 |
| Neon Blog         | `https://neon.tech/blog/rss.xml`           | 每週 |
| CrunchyData       | `https://www.crunchydata.com/blog/rss.xml` | 每月 |
| Supabase          | `https://supabase.com/blog/rss.xml`        | 每週 |

### AI/趨勢（4 個）

| 來源                  | RSS URL                                       | 頻率 |
| --------------------- | --------------------------------------------- | ---- |
| Simon Willison        | `https://simonwillison.net/atom/everything/`  | 每日 |
| Lilian Weng           | `https://lilianweng.github.io/index.xml`      | 每月 |
| The Batch (Andrew Ng) | `https://www.deeplearning.ai/the-batch/feed/` | 每週 |
| Stratechery           | `https://stratechery.com/feed/`               | 每週 |

### 獨立開發/創業（5 個）

| 來源            | RSS URL                             | 頻率   |
| --------------- | ----------------------------------- | ------ |
| Indie Hackers   | `https://feed.indiehackers.com/`    | 每日   |
| Pieter Levels   | `https://levels.io/rss`             | 不定期 |
| Signal v. Noise | `https://m.signalvnoise.com/feed/`  | 不定期 |
| Justin Jackson  | `https://justinjackson.ca/feed`     | 每月   |
| Herman Martinus | `https://herman.bearblog.dev/feed/` | 不定期 |

### 生產力/知識管理（5 個）

| 來源        | RSS URL                            | 頻率   |
| ----------- | ---------------------------------- | ------ |
| Ness Labs   | `https://nesslabs.com/feed`        | 每週   |
| Forte Labs  | `https://fortelabs.com/feed/`      | 每月   |
| Cal Newport | `https://calnewport.com/feed/`     | 每週   |
| James Clear | `https://jamesclear.com/feed`      | 每週   |
| Nat Eliason | `https://blog.nateliason.com/feed` | 不定期 |

### 設計/產品（3 個）

| 來源               | RSS URL                                 | 頻率   |
| ------------------ | --------------------------------------- | ------ |
| Intercom Blog      | `https://www.intercom.com/blog/feed/`   | 每週   |
| Lenny's Newsletter | `https://www.lennysnewsletter.com/feed` | 每週   |
| Julie Zhuo         | `https://lg.substack.com/feed`          | 不定期 |

### 思考/寫作（6 個）

| 來源            | RSS URL                                | 頻率                                              |
| --------------- | -------------------------------------- | ------------------------------------------------- |
| The Marginalian | `https://www.themarginalian.org/feed/` | 每週                                              |
| Wait But Why    | `https://waitbutwhy.com/feed`          | 非常不定期（⚠️ 已多年未更新，Phase 2 啟用前驗證） |
| Seth Godin      | `https://seths.blog/feed/`             | 每日                                              |
| Morgan Housel   | `https://collabfund.com/blog/feed/`    | 每月                                              |
| Austin Kleon    | `https://austinkleon.com/feed/`        | 每週                                              |
| Farnam Street   | `https://fs.blog/feed/`                | 每週                                              |

### 抓取排程

| Tier | 頻率      | 來源類型                                                   |
| ---- | --------- | ---------------------------------------------------------- |
| 1    | 每 4 小時 | 高流量混合來源（HN, r/golang, Simon Willison, Seth Godin） |
| 2    | 每日 1 次 | 大多數個人博客和技術部落格                                 |
| 3    | 每週 1 次 | 週刊類（Golang Weekly, PostgreSQL Weekly, The Batch）      |

### AI 評分維度

```
final_score = relevance × 0.35    # 與技術棧和興趣的匹配度
            + depth     × 0.30    # 原創洞見 vs 表面教學
            + freshness × 0.15    # 新觀點 vs 已知常識
            + quality   × 0.20    # 寫作品質、程式碼範例、可操作性

≥ 7.0 → 自動推薦到前端
≥ 5.0 → 存檔
< 5.0 → 跳過（僅記錄 URL 做去重）

權重是初始值，透過 feedback loop（thumbs up/down）累積 100+ 筆後校準。
```

---

## 技術決策記錄

| #   | 決策                        | 選項                                                                         | 選擇                                                                 | 原因                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --- | --------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | 事件佇列                    | NATS JetStream vs in-process                                                 | **in-process**                                                       | 單 process side project，NATS 是 over-engineering。channel + flow_runs 表夠用。                                                                                                                                                                                                                                                                                                                                                                       |
| 2   | A5 prompt 策略              | few-shot examples vs system prompt                                           | **system prompt**                                                    | 目前沒有 10 篇 gold standard 文章。few-shot 塞 prompt 裡 token 成本高（8-15K/call）。等累積滿意文章再加。                                                                                                                                                                                                                                                                                                                                             |
| 3   | B1 Build Log 時機           | Phase 4 完整版 vs Phase 1 開始                                               | **Phase 1 輕量版 + Phase 4 完整版**                                  | 不讓完美版擋住開始寫。輕量版就是手動寫 markdown，走 content-review 同流程。                                                                                                                                                                                                                                                                                                                                                                           |
| 4   | G3 發佈節奏                 | 獨立情境 vs dashboard widget                                                 | **dashboard widget**                                                 | 就是一個 SQL query + 圖表，不需要獨立 flow。                                                                                                                                                                                                                                                                                                                                                                                                          |
| 5   | Embedding 時機              | Phase 5 才開始 vs Phase 1 開始                                               | **Phase 1 開始**                                                     | embedding model 便宜（~$0.0001/篇），從第一天累積，Phase 5 直接有數百篇向量可用。                                                                                                                                                                                                                                                                                                                                                                     |
| 6   | RSS 評分校準                | 固定權重 vs feedback loop                                                    | **feedback loop**                                                    | 沒有 loop 的評分永遠是猜的。前端加 thumbs up/down，100+ 筆後調權重。                                                                                                                                                                                                                                                                                                                                                                                  |
| 7   | feeds error handling        | 基本欄位 vs error tracking                                                   | **error tracking**                                                   | RSS feed 會死/搬家/403。consecutive_failures + 自動 disable + 通知。                                                                                                                                                                                                                                                                                                                                                                                  |
| 8   | I1 Morning Brief 送達       | 寫進 DB vs Telegram Bot                                                      | **Telegram Bot**                                                     | 寫進 DB 等自己看 = 不會看 = 沒做。                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 9   | G4 讀者視角審核             | 合併到 A5 vs 移除                                                            | **移除**                                                             | 低價值，直接用 ChatGPT 問就好。                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 10  | RSS 收集                    | Feedly vs 自建                                                               | **自建**                                                             | 完整控制：AI 評分、去重、自動 bookmark 生成、與 content 系統整合。gofeed + goquery 足夠。                                                                                                                                                                                                                                                                                                                                                             |
| 11  | url_hash 型別               | BYTEA vs TEXT                                                                | **TEXT**                                                             | BYTEA 在 psql 裡顯示 hex escape 很難讀。TEXT 存 hex string，去重效能差異在此資料量可忽略，debug 可讀性差很多。                                                                                                                                                                                                                                                                                                                                        |
| 12  | prompts 格式                | dotprompt vs plain text + embed.FS                                           | **plain text + embed.FS**                                            | dotprompt 的 YAML header（model config, input schema）跟 Go 的型別系統重複。plain `.txt` + `go:embed` 更簡單，model config 在 Go code 裡管理，編譯期就能抓到問題。                                                                                                                                                                                                                                                                                    |
| 13  | content-review steps        | sequential vs partial parallel                                               | **Step 1 sequential → Step 2-5 errgroup**                            | Step 1 校對結果影響 auto_publish 決策，但 excerpt/tags/reading-time/embedding 彼此無依賴。並行化 ~8-10s → ~3-4s。                                                                                                                                                                                                                                                                                                                                     |
| 14  | flow_runs Cron 重試         | SELECT then UPDATE vs atomic UPDATE RETURNING                                | **UPDATE...SET status='pending' WHERE status='failed' RETURNING \*** | 防止 Cron 間隔內同一筆被掃到兩次重複執行。PostgreSQL row-level lock 一行 SQL 解決。                                                                                                                                                                                                                                                                                                                                                                   |
| 15  | Gemini 模型選擇             | gemini-2.0-flash vs gemini-3-flash-preview                                   | **gemini-3-flash-preview**                                           | 2.0 已 deprecated。3-flash-preview 是目前可用的最新 Flash，calibration 7/7 通過。GA 後切 stable。                                                                                                                                                                                                                                                                                                                                                     |
| 16  | Proofread token limit       | 1024 vs 4096                                                                 | **4096**                                                             | 長文（>5000 字）校對結果被截斷。Calibration 時 3/7 篇因 1024 上限 JSON 不完整。                                                                                                                                                                                                                                                                                                                                                                       |
| 17  | Notion 整合策略             | Notion Custom Agent + polling vs Notion Integration Webhooks + pipeline 自建 | **Webhooks + pipeline 自建**                                         | Notion 已推出原生 Integration Webhooks（HMAC-SHA256 驗簽，與 GitHub webhook 對稱）。Pipeline 已有 LLM 能力（Gemini Flash + Claude Sonnet），Morning Brief / Weekly Review / Content Planner 全部可在 `planning` flow 自建，prompt 可 version control、model 可選擇。Notion Agent 的 prompt 和 model 不可控，月費 $12-24 買一個無法控制的中間層不合理。Notion 付費方案（Plus ~$10/month）仍可考慮用於 Database Automations，但 Custom Agent 不採用。   |
| 18  | AI framework                | direct SDK calls vs Genkit Go 1.0                                            | **Genkit Go 1.0**                                                    | Runner 管 scheduling/retry/persistence，Genkit 管 LLM interaction/structured output/tracing。分工明確：flowrun.Runner 是 job orchestrator，Genkit 是 AI interaction framework。自建 LLM layer 的 edge case（streaming, retry, structured output parsing, multi-provider）多且維護成本被低估。Genkit 的 DefineFlow + GenerateData[T] + plugin system 解決這些問題。                                                                                    |
| 19  | content-polish model        | Gemini Pro vs Claude Sonnet 4.6                                              | **Claude Sonnet 4.6**                                                | 繁體中文寫作品質 Claude 明顯優於 Gemini Pro（語感、用詞精準度、段落結構）。Genkit Anthropic plugin（v1.4.0）已驗證可用，multi-provider 無額外架構成本。content-review 用 Gemini Flash（便宜 + 批量），content-polish 用 Claude（品質優先），各取所長。                                                                                                                                                                                                |
| 20  | Notion trigger 機制         | Cron polling vs Integration Webhooks                                         | **Integration Webhooks**                                             | Notion 原生支援 webhook（page.content_updated, page.created 等），payload 含 metadata（page ID + event type + timestamp），收到後 call Notion API 拉 content。驗簽邏輯（HMAC-SHA256）與 GitHub webhook 共用，可抽出 `internal/webhook/`。已預留 `POST /api/webhook/notion` stub。比 Cron polling 更即時、更省 API calls、架構更乾淨。若 Free plan 不支援 Integration Webhooks，fallback 為 Cron polling + `last_edited_time` filter，不影響整體架構。 |
| 21  | Obsidian vs Notion 職責邊界 | 混合使用 vs 硬切                                                             | **硬切**                                                             | Obsidian = 所有筆記和知識內容（技術筆記、隨手記、學習筆記、文章草稿）。Notion UB 3.0 = 工作流和行動（Tasks、Projects、Reading List）。Notion Notes database 僅限 task/project context。消除同一筆記在兩個系統的重複問題，確保 Obsidian → koopa0.dev 是唯一的內容流，Notion → koopa0.dev 是純粹的 metadata/狀態流。                                                                                                                                    |
| 22  | Embedding model             | text-embedding-004 vs voyage-3-lite                                          | **text-embedding-004**                                               | 768 維，Genkit Google AI plugin 原生支援，不需額外 dependency。Phase 1-4 只累積不查詢，Phase 5 才建 index（HNSW or IVFFlat）。cost ~$0.0001/篇，年累積 < $1。voyage-3-lite（512 維）更便宜但需額外 plugin 或 HTTP client，與 Genkit 生態整合成本高於效益。                                                                                                                                                                                            |
| 23  | content-generate model      | Gemini Flash vs Claude Sonnet                                                | **Gemini Flash**                                                     | digest 和 bookmark 是批量生成、非對外展示的 draft（status: review，人工 approve 才發佈）。Flash 的品質足夠，成本是 Claude 的 1/10。如果 review 時發現品質不夠，可以對個別 draft 手動觸發 content-polish（Claude Sonnet）做二次潤色。                                                                                                                                                                                                                  |

---

## 資源控制

### LLM 成本

| 策略        | 做法                                                                                                                         |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 模型選擇    | Gemini 3 Flash 處理批量（審核、RSS 評分），Claude Sonnet 4.6 處理對外發佈（潤色）。content-generate 模型 TBD（Phase 2 決定） |
| Token 預算  | 每日上限 500K tokens，超過拒絕新 LLM 呼叫（Phase 1 無 enforcement，Phase 2 實作 middleware 計量）                            |
| Prompt 設計 | `GenerateContentConfig.MaxOutputTokens` 限制每次呼叫（review 4096, excerpt 256, tags 512）                                   |
| A5 潤色     | system prompt 定義風格，不塞 few-shot 省 token                                                                               |
| Embedding   | embedding model 極便宜，每篇 ~$0.0001                                                                                        |

**預估月成本：全平台 < $5（以 Flash 為主力）**

### 並發控制

| 策略              | 做法                                                                   |
| ----------------- | ---------------------------------------------------------------------- |
| Worker pool       | semaphore cap=3，同時最多 3 個 flow                                    |
| Cron 錯開         | RSS 每 4h 整點、Digest 週日 20:00、Analytics 週一 03:00                |
| Notion rate limit | API client 層 `rate.Limiter` 3 req/s（webhook event 觸發後拉 content） |
| RSS per-domain    | 同一 domain 最少間隔 2 秒                                              |
| Feed error        | 連續失敗 5 次自動 disable                                              |

### 可觀測性

| 層級      | 工具                                                    |
| --------- | ------------------------------------------------------- |
| 日誌      | slog + flow_name + content_id attributes                |
| 歷史      | `flow_runs` 表（status, input, output, error, attempt） |
| Admin API | `GET /api/admin/flow-runs` — 查看/重試失敗的 flow       |
| 告警      | 失敗率 > 20%、LLM 連續失敗、feed 自動 disable           |

---

## 前端開發時間線

| 前端工作                      | 可開始       | 必須完成       | 備註                 |
| ----------------------------- | ------------ | -------------- | -------------------- |
| Review Queue UI               | Phase 1 開始 | Phase 1 完成前 | 先用 mock data       |
| Content 編輯頁 AI 按鈕        | Phase 1 中期 | Phase 1 完成前 | 等 API schema        |
| Admin Dashboard（flow-runs）  | Phase 1 中期 | Phase 2 前     |                      |
| Build Log 展示頁              | Phase 1      | Phase 1 完成前 | 輕量版就是一般文章頁 |
| RSS 管理頁                    | Phase 1 後期 | Phase 2 中期   | 純 CRUD              |
| 收集文章列表 + thumbs up/down | Phase 1 後期 | Phase 2 完成前 | feedback loop        |
| Projects 展示頁               | Phase 2      | Phase 3 完成前 | 先做靜態版           |
| Analytics Dashboard（含 G3）  | Phase 3      | Phase 4 完成前 |                      |

---

## 總時間線

```
已完成                                    待實作
──────                                    ──────

Phase A: API 基礎 ─────── ✅ 完成
Phase B: Obsidian Sync ─── ✅ 完成
Phase C: R2 上傳 ────────── ✅ 完成

     Phase 0
      ├─┤
月份    1              2              3              4
        ├──Phase 1───┤
                      ├───Phase 2────┤
                                     ├──Phase 3───┤
                                                  ├───Phase 4────┤

Phase 0: 內容引導 ─────────────────── 1-2 天（手動發 3-5 篇）
Phase 1: Content Pipeline + 基礎設施 ─ 3-4 週
Phase 2: RSS 收集 + Digest ──────────── 4-5 週
Phase 3: Notion 整合 ───────────────── 3-4 週
Phase 4: Build Log 完整版 + 分析 ───── 4-5 週
Phase 5: 進階功能 ─────────────────── 持續

Phase 1-4 合計：14-18 週（3.5-4.5 個月）
```

---

## 相關文件

| 文件                            | 用途                                         |
| ------------------------------- | -------------------------------------------- |
| `docs/PLATFORM-VISION.md`       | 完整平台設計（系統架構、API spec、資料模型） |
| `docs/API.md`                   | API 規格文件                                 |
| `docs/AI-PIPELINE-SCENARIOS.md` | 35+ AI 情境完整列表（9 大類）                |
| `CLAUDE.md`             | Go 後端開發規範                              |
| `frontend/CLAUDE.md`            | Angular 前端開發規範                         |

---

_最後更新：2026-03-10_
_v3.4：修正 C2 描述（poll → webhook 一致）、移除 notion_webhook_events 假 schema（TBD 註解保留）、webhook 遷移步驟、成功指標加測量方式、token 預算標註 Phase 1 無 enforcement、embedding 指標修正、Notion Free plan 驗證提醒、標記疑似停更 RSS、前端標為 optional_
_v3.3：砍掉 Notion Custom Agent、改用 Notion Integration Webhooks（TDR #17 改寫 + #20 #21 新增）、Obsidian/Notion 職責硬切、Phase 3 完全改寫、Phase 4 planning flow 自建_
_v3.2：Genkit 架構決策（TDR #18）、Claude Sonnet 4.6 for polish（TDR #19）、C6 砍掉、gemini-3-flash-preview（TDR #15）、proofread 4096（TDR #16）、dotprompt → embed.FS（TDR #12 更新）、Phase 1 checklist 更新、flow_runs schema 修正_
_v3.1：Phase 0 內容引導、flow_runs Cron lock、url_hash TEXT、content-review 並行化、prompts 扁平化_
_v3：加入完整專案上下文、已完成工作、技術決策記錄_
_v2 → v3 關鍵變更：砍掉 NATS、in-process worker pool、feedback loop、embedding from day 1_
