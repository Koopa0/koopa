# koopa0.dev Phase 1 — 完整決策與實作指導文件

> **Version**: 2.0 (Final)  
> **Date**: 2026-03-17  
> **產出方式**: Koopa × Claude Opus 多輪交叉討論，經 Claude Code 三輪獨立 review 後修正  
> **用途**: 交給 Claude Code 實作，作為 source of truth  
> **Embedding**: 768 維（`internal/flow/content.go:251`，gemini-embedding-2-preview）  
> **Contents table**: 目前 0 筆資料（schema migration 可直接 recreate）

---

## 目錄

1. 系統現狀
2. 這次要解決的問題
3. Phase 1 完整工項清單與執行順序
4. 每個工項的技術設計與決策推理
5. 後續 Phase 預覽
6. 明確不做的事情與理由
7. 需要 Claude Code 獨立判斷的問題
8. 設計哲學（不可協商）
9. Reference Documents

---

## 1. 系統現狀

### 1.1 架構概覽

koopa0.dev 是 Koopa 的個人知識引擎，用 Go 建構。三個系統各司其職：

Notion UB3.0 管「做了什麼」（結構化資料：Tasks、Projects、Goals、Books、Tags、People）。Obsidian vault 管「學了什麼」（非結構化資料：解題筆記、讀書筆記、AI 討論記錄、技術深潛、decision log）。koopa0.dev 坐在中間做「整合 + 歸納 + 展示 + 推送」。

資料流是單向的——Notion 和 Obsidian 是 source of truth，koopa0.dev 只做 ingestion、analysis、display。唯一的「寫回」是 Genkit 產出的 review/report，走 git commit（Obsidian）或 Notion API create page（Notion Notes），都是 append 行為而非 mutation。

### 1.2 技術棧

Go backend、PostgreSQL + pgvector（`vector(768)`，gemini-embedding-2-preview）、Firebase Genkit（AI flow）、Angular frontend（含 BFF service）、LINE/Telegram 通知推送、Cloudflare Tunnel + WAF/DDoS/SSL、Prometheus + Grafana + Loki（可觀測性）。

### 1.3 已上線的基礎設施

Notion API sync（polling + webhook）。Obsidian vault → git push → GitHub → GitHub webhook 呼叫 koopa0.dev API（目前透過 Angular BFF service proxy 到 Go backend）。GitHub activity webhook。LINE Bot / Telegram Bot。Genkit flows（content-review、content-polish、build-log-generate、bookmark-generate、morning-brief、weekly-review、content-strategy、content-embed、content-proofread）含 persistent runner、token budget、retry、alert、mock mode。Blog 系統。RSS feed 收集與 AI 評分管線。

### 1.4 現有 Database Schema 重點

`contents` table 是目前的核心（**目前 0 筆資料**）。有 `embedding vector(768)` + HNSW index、有 `search_vector` tsvector generated column（目前用 `english` configuration，本次要修）。`topics` table 做 blog topic 分類（24 筆 seed data）。`feeds` + `collected_data` 做 RSS 收集。`flow_runs` 追蹤 Genkit flow 執行（含 persistent runner）。`projects` 和 `goals` table 存在但 Notion sync 深度有待加強。

現有 schema 裡**不存在**的（本次新建）：`activity_events`、`activity_event_tags`、`obsidian_notes`、`obsidian_note_tags`、`tags`、`tag_aliases`、`project_aliases`。`notion_sources` 留到 Phase 1.5。

### 1.5 Obsidian Sync 現有流程

Obsidian vault → git push → GitHub → webhook → 目前經 Angular BFF proxy → Go backend。koopa0.dev 透過 GitHub API 取 file content（webhook payload 只有 commit metadata + changed files list）。Server 上沒有 vault local clone。

**架構備註**：webhook 經 BFF 是為了不暴露 Go port。Cloudflare Tunnel 本身就是安全層——可按 path 分流讓 `/api/webhook/*` 直連 Go backend。Phase 1 維持現狀，Phase 1.5 評估 Tunnel path-based routing。Phase 1 必須確認 webhook handler 有 `X-Hub-Signature-256` HMAC 驗證（見 §7.7）。

---

## 2. 這次要解決的問題

### 2.1 核心 Loop 缺失

缺少「Notion + Obsidian + GitHub 工作痕跡統一匯入 → Genkit 分析 → 推送 insight」的核心 loop。`activity_events` 不存在，三源資料無法 join。

### 2.2 Source Flexibility 不足

Notion sync 硬編碼 database 結構，改動需改 Go code + redeploy。Phase 1.5 解決。

### 2.3 Tag 混亂

Free-form tags diverge（`go` / `golang` / `Go`）。下游全依賴 tag 一致性。

### 2.4 搜尋品質

tsvector `english` stemming 破壞技術術語。CamelCase/snake_case 無法有效 index。

### 2.5 Genkit Flow 品質

交叉審查發現 P0/P1 問題：temperature 錯誤、缺 JSON 容錯 parser、content policy block 被 retry、prompt 缺 negative examples。

### 2.6 Data Integrity 風險

拒絕 Linear 後，PR merge 不會自動更新 Notion Task。v3.0 標記必須 Phase 1 實作。

---

## 3. Phase 1 完整工項清單與執行順序

### 3.1 執行順序（有 dependency chain）

**Stage 0 — Audit**

B5. Frontmatter migration audit — 掃 vault，產出 frontmatter 差距報告。結果決定 B1 策略是否足夠。

**Stage 1 — Schema + Genkit Audit（可平行）**

A1-A6 全部 schema migration。C1 Genkit P0 修復。C2 Genkit P1 改善。G1 Health check metrics。

**Stage 2 — Backend + Admin UI（E1 必須在 B1 之前或同時）**

E1 Admin UI Tag 管理（B1 會產生 unmapped tags，需要 UI 管理）。A2 CamelCase splitting（B1 依賴）。B2 自迴圈防護。B1 Obsidian sync pipeline（依賴 A2、A3、A4、A6 + E1）。B3 GitHub diff stats。B4 PR → Notion Task 更新。

**Stage 3 — 驗證**

手動觸發 B1/B3，確認 activity_events 有真實資料。D1 Genkit flow pilot（**precondition**: activity_events 至少一天真實資料）。

### 3.2 完整項目 Table

#### Claude Code 負責

| ID | 項目 | 分類 | Stage | 來源 |
|----|------|------|-------|------|
| A1 | tsvector `simple` + `search_text`（recreate） | Schema | 1 | 決策報告 §5 |
| A2 | CamelCase splitting Go 邏輯 + tests | Backend | 2 | 決策報告 §5 |
| A3 | `tags` + `tag_aliases` + `obsidian_note_tags` + `activity_event_tags` | Schema | 1 | 決策報告 §4 + review |
| A4 | `activity_events`（含 `source_id` dedup） | Schema | 1 | v3.0 §3.1 + review |
| A5 | `project_aliases` table | Schema | 1 | 討論 |
| A6 | `obsidian_notes`（含 HNSW） | Schema | 1 | v3.0 §3.3 + 修正 |
| B1 | Obsidian sync pipeline（mutex + transaction） | Backend | 2 | v3.0 + review |
| B2 | 自迴圈防護（Git identity） | Backend | 2 | v3.0 §13.1 |
| B3 | GitHub diff stats extraction | Backend | 2 | v3.0 §17.1 |
| B4 | PR merge → Notion Task（PR description Notion link） | Backend | 2 | v3.0 §17.3 + review |
| B5 | Frontmatter audit script | Backend | 0 | 討論 |
| C1 | Genkit P0 修復（四項） | Genkit | 1 | v3.0 §19.2 |
| C2 | Genkit P1 改善（三項 prompt） | Genkit | 1 | v3.0 §19.2 |
| D1 | Genkit flow pilot | Genkit | 3 | v3.0 Phase 1 |
| E1 | Admin UI — Tag 管理 | Frontend | 2 | 決策報告 §4, §6 |
| G1 | Health check metrics | Infra | 1 | 討論 |

#### Koopa 自己負責

| ID | 項目 | 來源 |
|----|------|------|
| F1 | Notion LeetCode Practice Project | v3.0 §4.2 |
| F2 | Obsidian Bases（四個） | v3.0 §11.1 |
| F3 | Obsidian 插件配置（Git、Linter、Templater） | v3.0 §11.3 |
| F4 | Templater templates | v3.0 §3.2 |
| F5 | Notion unique ID property 評估 | review |
| F6 | Notion Agent 試驗性測試 | v3.0 §4.5 |

---

## 4. 每個工項的技術設計與決策推理

### A1. tsvector Configuration 修正

**現狀**：`contents.search_vector` 用 `english`。0 筆資料，直接 recreate。

**決策**：改 `simple`。新增 `search_text` 存 preprocessed 文字。原始 `body` 不動。

**否決**：dual configuration（simple + english）。Embedding 已覆蓋語意匹配，第四路 RRF 成本 > 收益。

```sql
ALTER TABLE contents DROP COLUMN search_vector;
ALTER TABLE contents ADD COLUMN search_text TEXT;
ALTER TABLE contents ADD COLUMN search_vector TSVECTOR GENERATED ALWAYS AS (
    setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
    setweight(to_tsvector('simple', coalesce(search_text, '')), 'C')
) STORED;
CREATE INDEX idx_contents_search ON contents USING GIN(search_vector);
```

### A2. CamelCase/snake_case Splitting

Go 層實作。連續大寫 = 一個 token（`HTTP` → `http`）。數字跟前 token（`OAuth2` → `oauth2`）。Dot 拆開（`io.Reader` → `io reader`）。Snake_case 拆開。

Table-driven test：`HTTPSRedirect`、`OAuth2Client`、`DDIA_Ch8`、`io.Reader`、`[]string`、`map[string]interface{}`、`pgxpool.Pool`、`genkit.Generate`、`ErrRedisConnectionTimeout`。

### A3. Tag Normalization 系統

四張 table + ingestion-time normalization + Admin UI。Obsidian 端零摩擦。

**為什麼四張 table**：`tags` + `tag_aliases` 做 normalization 邏輯。`obsidian_note_tags` + `activity_event_tags` 持久化結果。沒有 junction table，查「所有 go-concurrency 筆記」要先查 aliases 再 JSONB containment——繞過 normalization 初衷。Activity events 用 junction table 而非 JSONB，因為 tag merge 時 junction table = 一條 `UPDATE`，JSONB = O(n) parse+rewrite。Phase 1 初期 tag merge 頻繁。

```sql
CREATE TABLE tags (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    parent_id   UUID REFERENCES tags(id),
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tags_parent ON tags(parent_id);

CREATE TABLE tag_aliases (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_tag       TEXT NOT NULL UNIQUE,
    tag_id        UUID REFERENCES tags(id),  -- nullable vs sentinel 見 §7.2
    match_method  TEXT NOT NULL DEFAULT 'manual',
    confirmed     BOOLEAN NOT NULL DEFAULT false,
    confirmed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tag_aliases_tag ON tag_aliases(tag_id);
CREATE INDEX idx_tag_aliases_confirmed ON tag_aliases(confirmed);

CREATE TABLE obsidian_note_tags (
    note_id  BIGINT NOT NULL REFERENCES obsidian_notes(id) ON DELETE CASCADE,
    tag_id   UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (note_id, tag_id)
);
CREATE INDEX idx_obsidian_note_tags_tag ON obsidian_note_tags(tag_id);

CREATE TABLE activity_event_tags (
    event_id  BIGINT NOT NULL REFERENCES activity_events(id) ON DELETE CASCADE,
    tag_id    UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (event_id, tag_id)
);
CREATE INDEX idx_activity_event_tags_tag ON activity_event_tags(tag_id);
```

**Tag seed data：不 seed。** Pipeline 自然積累 + Admin UI 整理。理由：migration 裡預測不了所有 canonical tags，第一次大量 sync 的集中整理強迫在真實 data 面前做 taxonomy 設計。**E1 必須在 B1 之前或同時上線**，否則 unmapped tags 堆積無處管理。

**Slug 規則**：lowercase + hyphens。碰撞時後綴 `-2`。

**四步 pipeline**：1) Exact match → 用 canonical。2) Case-insensitive → auto-confirm。3) Slug match → `confirmed=false`（先生效不 block）。4) No match → unmapped pool。

**`obsidian_notes.tags` JSONB 保留**作 audit trail，下游走 junction table。

**層級聚合**：recursive CTE on `tags.parent_id`。

### A4. activity_events Table

```sql
CREATE TABLE activity_events (
    id          BIGSERIAL PRIMARY KEY,
    source_id   TEXT,
    timestamp   TIMESTAMPTZ NOT NULL,
    event_type  TEXT NOT NULL,
    source      TEXT NOT NULL,
    project     TEXT,
    repo        TEXT,
    ref         TEXT,
    title       TEXT,
    body        TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_activity_events_timestamp ON activity_events (timestamp DESC);
CREATE INDEX idx_activity_events_project ON activity_events (project);
CREATE INDEX idx_activity_events_type ON activity_events (event_type);

CREATE UNIQUE INDEX idx_activity_events_dedup
    ON activity_events (source, event_type, source_id)
    WHERE source_id IS NOT NULL;
```

**Dedup index 含 `event_type`**：Notion 同一 Task 同一分鐘改 status 和 title 時，`source_id = page_id+edited_time` 會碰撞。加 `event_type` 防 false dedup，成本零。

**source_id**：GitHub 用 delivery ID。Notion 用 `page_id+edited_time+property`。Obsidian 用 `file_path+content_hash`。Nullable。

**metadata 消費者**：Go SQL aggregation（churn ratio 等），幾百筆 seq scan 微秒級，不需 functional index。

### A5. project_aliases Table

直接用 table（不用 Go map）。Admin UI 管理。Go map 每次改 code+deploy 摩擦不合理。管理放 Admin UI settings 區塊。

```sql
CREATE TABLE project_aliases (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alias          TEXT NOT NULL UNIQUE,
    canonical_name TEXT NOT NULL,
    source         TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### A6. obsidian_notes Table

修正：`vector(768)`（v3.0 寫的 1536 是錯的）。HNSW 保留——空 table 上 CREATE INDEX 成本零，為 Phase 2 MCP Server 預建。`content_hash` 用 SHA-256。`content_text` 等價於 `contents.body`（加 comment 標註）。

```sql
CREATE TABLE obsidian_notes (
    id              BIGSERIAL PRIMARY KEY,
    file_path       TEXT UNIQUE NOT NULL,
    title           TEXT,
    type            TEXT,
    source          TEXT,
    context         TEXT,
    status          TEXT DEFAULT 'seed',
    tags            JSONB,           -- raw audit trail, 下游走 junction
    difficulty      TEXT,
    leetcode_id     INT,
    book            TEXT,
    chapter         TEXT,
    notion_task_id  TEXT,
    content_text    TEXT,            -- 等價 contents.body
    search_text     TEXT,
    content_hash    TEXT,            -- SHA-256
    embedding       vector(768),
    search_vector   TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(search_text, '')), 'C')
    ) STORED,
    git_created_at  TIMESTAMPTZ,
    git_updated_at  TIMESTAMPTZ,
    synced_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_obsidian_notes_type ON obsidian_notes (type);
CREATE INDEX idx_obsidian_notes_context ON obsidian_notes (context);
CREATE INDEX idx_obsidian_notes_search ON obsidian_notes USING GIN(search_vector);
CREATE INDEX idx_obsidian_notes_embedding ON obsidian_notes
    USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
```

### B1. Obsidian Sync Pipeline

```
Webhook 進來
  → B2: Git identity 檢查 → 自己的 push → skip
  → Mutex lock
  → Parse changed files
  → 每個 .md：
      → GitHub API 取 content
      → Parse frontmatter
      → 沒有 `type` → Prometheus counter, skip
      → 有 `type` → Tier 1:
          → BEGIN TRANSACTION
          → Tag normalization（四步）
          → CamelCase → search_text
          → SHA-256 content_hash 比對
          → Upsert obsidian_notes
          → Write obsidian_note_tags
          → Insert activity_events
          → Write activity_event_tags
          → COMMIT
          → 排隊 embedding（tx 之外，見 §7.6）
  → Mutex unlock
```

**Transaction boundary（四輪 review 關鍵決策）**：upsert + junction tables + activity_events 同一個 pgx tx。原因：如果 activity_events 寫入失敗但 notes 成功，下次 content_hash 匹配會 skip——activity_events 永遠補不上，silent data loss。Embedding 放 commit 後——失敗不影響 integrity，獨立 retry。

**Mutex**：連續 push 時防 GitHub API race condition。一人 vault，throughput 不是瓶頸。

**`type` 是唯一 hard required field。** 其他 graceful degrade。

**Cron 以 `Asia/Taipei` 為準。**

### B2. 自迴圈防護

專用 Git identity 做寫回。Webhook 檢查 sender → skip。見 §7.7 確認現有 identity。

### B3. GitHub Diff Stats

Push event → `activity_events.metadata`: `{"lines_added": N, "lines_removed": N, "files_changed": N}`。Go aggregation 算 churn ratio。

### B4. PR Merge → Notion Task

Phase 1：regex 掃 PR body 找 Notion URL → 提取 page ID → Notion API 更新 status。沒有 link → log warning。Phase 1.5 候選：Notion unique ID property。Parse 細節見 §7.8。

### B5. Frontmatter Audit

Stage 0，B1 之前跑。掃 vault，按 type 分組產出差距報告。結果決定 B1 skip 策略是否足夠。

### C1. Genkit P0

C1-a. Temperature：`build-log-generate` 0.6→0.3、`bookmark-generate` 0.5→0.3。C1-b+c. `GenerateData[T]()` vs `RobustUnmarshal`——見 §7.9，先查 SDK。C1-d. FinishReason SAFETY/RECITATION/OTHER → permanent failure。

### C2. Genkit P1

C2-a. `review.txt`（Level 標準 + negative examples）。C2-b. `tags.txt`（選擇策略 + negative rules）。C2-c. `excerpt.txt`（吸引非總結、160 字 SEO）。

### D1. Genkit Flow Pilot

**Precondition**：activity_events 至少一天真實資料。建議 Daily Dev Log（v3.0 §5.1.1），23:00 Asia/Taipei。

### E1. Admin UI — Tag 管理

**必須在 B1 之前或同時上線。** Unmapped pool、tag tree、pending confirmation、merge 操作。Angular lazy-loaded admin module `/admin/tags`。Project alias 管理放同 module settings 區塊。

### G1. Health Check Metrics

`koopa0dev_notion_last_sync_timestamp`、`koopa0dev_obsidian_last_sync_timestamp`、`koopa0dev_activity_events_today_total`、`koopa0dev_genkit_flow_runs_total`、`koopa0dev_obsidian_notes_missing_frontmatter_total`。

---

## 5. 後續 Phase 預覽（Big Picture）

Phase 1 的每個設計決策都需要考慮後續 Phase 的需求。以下是每個 Phase 的完整內容、它依賴 Phase 1 的哪些產出、以及它對 Phase 1 設計的 implicit 約束。

### Phase 1.5 — Source 解耦

**Notion Source Registry。** 建 `notion_sources` table + Admin UI（`/admin/sources`），讓 Notion database 的 sync 行為變成宣告式配置。核心欄位：`database_id`、`name`、`description`（自然語言語意，給 Genkit 和 MCP 用）、`sync_mode`（`full` / `events` / `disabled`）、`property_map`（Notion property name → canonical name + type + extract path 的 JSONB mapping）、`poll_interval`、`enabled`。

現有四個 full mode databases（Tasks、Projects、Goals、Books）在 table 裡建記錄但 sync 邏輯不動（Phase 2 才遷移）。新的 database 用 events-only generic sync——變更只寫入 `activity_events`，不維護獨立 table。Admin UI 的 onboard workflow：填 database ID → 後端調 Notion API 拉 schema → 前端顯示 property 列表 → 選擇 sync 的 property、填 canonical name → 保存。

**Phase 1 的 implicit 約束**：Phase 1 的 `activity_events.metadata` JSONB 結構需要足夠 generic，讓 Phase 1.5 的 events-only sync 可以把任意 Notion property 塞進去。Phase 1 的 Notion polling code 如果 hardcode 了 property extraction 邏輯，Phase 1.5 要能漸進替換（feature flag），而不是 big bang 重寫。

**Obsidian Tier 2 決策。** 根據 Phase 1 的 `obsidian_notes_missing_frontmatter_total` Prometheus counter 數據，如果超過筆記總量 10%，建 `obsidian_raw` table（UNIQUE on file_path，只存 path + title + content_hash + git timestamps）做 Tier 2 ingestion。如果低於 10%，不投資。

**Notion unique ID property 評估。** Notion 2024 年加的原生 unique ID property，database-scoped 遞增 + 自訂前綴。如果可行，B4 的 PR → Task matching 從「parse PR description Notion link」升級到「branch name 帶 TASK-42」。

**Cloudflare Tunnel path-based routing。** `/api/webhook/*` 直連 Go backend，其他走 Angular SSR。消除 webhook delivery 對 Node.js process 的依賴。

### Phase 2 — Knowledge Backbone

Phase 2 把 Phase 1 建好的資料基礎變成可查詢、可推送的知識系統。

**MCP Server（最高優先級）。** koopa0.dev 暴露 MCP server，讓 Claude Code 即時存取 knowledge base。四個 tool：

`search_notes(query, type?, context?)` — 語意搜尋 Obsidian 筆記，基於 hybrid search。`get_project_context(project_name)` — 返回 project 的 recent activity、related notes、open tasks、recent PRs。`get_recent_activity(project?, days?)` — 返回最近 N 天的 activity events。`get_decision_log(topic)` — 搜尋 `type: decision-log` 的筆記。

**Hybrid search 是三路 RRF（Reciprocal Rank Fusion）**：pgvector embedding（語意匹配）+ tsvector `simple`（精確關鍵字匹配）+ frontmatter exact match（結構化過濾）。如果 query 包含 frontmatter 的 known field value（如 `type:leetcode`），SQL WHERE clause 過濾，權重比 vector 和 keyword 都高。

**Phase 1 的 implicit 約束**：Phase 1 的 `obsidian_notes` 的 `search_text` + tsvector + embedding 就是為 Phase 2 hybrid search 預建的。如果 Phase 1 的 tsvector 設計有問題（例如 CamelCase splitting 不夠好），Phase 2 的搜尋品質直接受影響。Phase 1 的 `tags` 層級結構也被 MCP 的 `search_notes` 用到——按 type/context 過濾走 frontmatter exact match，按 tag 過濾走 `obsidian_note_tags` junction table。

**Genkit Audit P2。** `content-review` 拆為三個獨立 flow：`content-proofread`（Gemini Flash，語法校對）、`content-metadata`（Claude Sonnet，excerpt + tags + reading time）、`content-embed`（不走 Genkit flow，Go 層直接呼叫 Embedding API）。每個可獨立重試、獨立選 model。Prompt template injection：`polish.txt` 和 `review.txt` 共用的規則抽為 `{{PRESERVATION_BLOCK}}`。Token usage logging：讀取 `resp.Usage()` log 實際消耗。`content-strategy` 分工：Go 做數值分析（月產量、tag 頻率），Genkit 做語意分析（「最近 Go 內容太偏實踐缺理論」）。

**Phase 1 的 implicit 約束**：C1/C2 的 prompt 改善是 P2 flow 拆分的基礎——先確保單體 flow 的品質，再拆分。如果 C1-b/C1-c 的 JSON 處理路徑選擇影響了 flow 的 API contract，P2 拆分時要 follow 同樣的 pattern。

**Notion full mode sync 遷移到 property_map。** Phase 1.5 建好 `notion_sources` table 並填好 property_map 後，Phase 2 把現有 hardcoded sync code 改為從 `notion_sources.property_map` 讀取 field mapping。用 feature flag 漸進切換。

**Spaced Repetition Pipeline。** 建 `review_schedule` table（SM-2 演算法：next_review_at、interval_days、easiness_factor、review_count）。每日 cron 推送該複習的 Obsidian 筆記到 LINE。LINE 上推核心問題（Genkit 從筆記抽取），回覆 "ok" / "again" 更新排程。Schema 預留 `response_text` 和 `quality_score` column，Phase 3 做 AI-graded recall。

**Phase 1 的 implicit 約束**：`obsidian_notes` 的 `type` field 是 spaced repetition 的 routing key——不同 type 的筆記可能有不同的複習策略（LeetCode 需要 active recall，book-note 可能只需 passive review）。Phase 1 的 frontmatter 標準化決定了 Phase 2 spaced repetition 的覆蓋範圍。

**Content Maturity Pipeline。** 四階段 status（seed → sapling → tree → published）。Genkit weekly flow 掃 seed/sapling 筆記，找素材累積到臨界點的 topic（「你最近連續寫了 4 篇 Go error handling 的 seed 筆記，合併整理的素材夠了」）。`status: published` 的筆記自動 sync 到 blog。

**Phase 1 的 implicit 約束**：`obsidian_notes.status` field 就是 content maturity 的 carrier。Phase 1 的 frontmatter schema 裡 `status` 默認值是 `seed`，這跟 content maturity model 對齊。

### Phase 3 — Intelligence Layer

Phase 3 把 Phase 1-2 的資料和搜尋能力轉化為主動式的智慧分析。

**統一週報。** 每週日 cron，資料源是全部——Notion Tasks/Projects/Goals/Books + Obsidian notes + GitHub activity（全部從 `activity_events` + `obsidian_notes` 讀取）。內容結構：Task 完成摘要（按 Project 分組）、LeetCode 進度（本週完成數、難度分佈、topic 覆蓋率）、閱讀進度（頁數、目前在讀的書）、知識產出（新增/更新 Obsidian 筆記數量和分類）、GitHub 活動（commits、PRs merged）、Goals 對齊度（各 Goal 關聯的 Project 活動佔比）。輸出到 LINE digest + Notion Note + Obsidian note（`type: weekly-review`）。

**Phase 1 的 implicit 約束**：週報的 aggregation 完全依賴 `activity_events` 的 `project` 欄位正確 normalized（A5 的 project_aliases）和 tag 正確 resolved（A3 的 junction tables）。如果 Phase 1 的 normalization 品質差，週報的分類就會不準。`activity_events.metadata` 裡的 diff stats（B3）也被週報用到——計算每個 project 的 code churn ratio。

**Drift Detection。** 跟週報一起跑。計算各 Project/Tag 的 activity 佔比，跟 Goals 的 priority 比對。推送格式：「本週 Resonance 佔 activity 的 23%，但在 Goals 裡是 #1 priority。上週是 41%。」只在偵測到偏差時推送。

**Phase 1 的 implicit 約束**：Drift detection 需要 Goals → Projects → Tasks 的完整 relation 鏈。Phase 1 的 `activity_events.project` 必須能跟 Notion 的 Projects 和 Goals join。如果 project_aliases 沒有覆蓋所有 source 的 project name，drift detection 會漏算。`activity_event_tags` junction table 讓 drift detection 也能按 tag 維度分析（「Go concurrency 相關活動佔比下降」）。

**Session Reconstruction。** 每日 Genkit flow，用時間窗口（2 小時內）+ project matching + Obsidian `context` field，把相關 events 聚合成 work session。建 `work_sessions` table（project、started_at、ended_at、duration_minutes、event_ids、Genkit generated summary）。Genkit 做初步聚合後讓 Koopa 在 Admin UI 確認/調整，不完全自動化。

**Phase 1 的 implicit 約束**：Session reconstruction 直接讀 `activity_events`，按 timestamp + project 做 time window aggregation。Phase 1 的 `activity_events.timestamp` 精度和 `project` 正確性直接決定 session boundary 的品質。

**Knowledge Graph 分析。** Parse Obsidian wikilinks（`[[target]]`）建 `obsidian_links` table（from_note, to_note）。分析：孤島偵測（沒有 inbound link 的筆記）、cluster 分析（connected component 找知識群組）、筆記 action item 偵測（掃 "TODO"、"待驗證" pattern → 建議轉成 Notion Task）。

**Phase 1 的 implicit 約束**：`obsidian_notes.content_text` 需要保留原始 wikilink syntax（不要在 CamelCase splitting 時破壞 `[[...]]` 結構）。A2 的 splitting 邏輯要確保 wikilink 內的文字不被拆碎。

**Genkit Audit P3。** Eval 框架（LLM-as-Judge，prompt 變更前後 before/after 比較）。`content-strategy` 加 trending topic search。Flow composition（content-review + content-polish 自動鏈）。Model fallback（utility flow：Gemini Pro → Flash → 放棄）。

**月度 Flows。** Retrospective Intelligence（本月 vs 上月 pattern detection：coding activity 在哪些 project 轉移、LeetCode 刷題頻率趨勢、Obsidian 筆記長度變化、PR cycle time 趨勢、重大技術決策摘要）。Goals 對齊度報告（所有 active Goals 的 Tasks 完成率和 Time Tracked）。Books 閱讀分析（月閱讀量趨勢、讀書完成度 × 筆記覆蓋度比對）。Personal Changelog 自動生成（從 activity_events 聚合，零維護成本，同時作為 portfolio 和 freelance 信用背書）。

### Phase 4 — Public & Portfolio

Phase 4 把內部系統的分析結果轉化為公開展示。

**Learning Dashboard。** koopa0.dev 公開頁面：LeetCode 每日打卡 heatmap（從 `activity_events` event_type = 'notion_task_done' + context = 'leetcode' 聚合）、閱讀進度條（Books database sync）、active projects 列表帶 progress bar（Projects sync）、tech stack radar（從 Obsidian 筆記和 GitHub commit 的 language/framework 分佈自動算，用 `tags` 的層級結構聚合）。全部自動生成，零維護。對 freelance 品牌價值極大——客戶看到持續學習、持續 ship 的可驗證記錄。

**Phase 1 的 implicit 約束**：Dashboard 的 heatmap 讀 `activity_events`，tech stack radar 讀 `tags` 的 parent-child 層級。如果 Phase 1 的 tag hierarchy 設計不夠乾淨（例如 subtopic 太多層），radar 的呈現會混亂。

**Monthly Changelog。** 從 activity_events 全量聚合，自動生成 `/changelog` 頁面。格式：按月分組，每個月按 project 列出 key changes（PRs merged、筆記產出、LeetCode 題數）。同時作為 Obsidian note（`type: monthly-review`）寫回 vault。

**Cross-Project Knowledge Transfer Detection。** 用 embedding similarity 找跨 project 的高相似度 pair。推遲到 Phase 4 最後的原因：non-obvious connection 的 precision 低，false positive 多。先讓其他 flow 穩定運行後再評估。

**Retrospective Intelligence。** 月度 trend 分析——不只是「做了什麼」的計數，而是 pattern detection across time：coding activity 在哪些 project 之間轉移、PR cycle time 趨勢、筆記長度變化（是否偷懶不寫詳細筆記）。

### 對 Phase 1 設計決策的 Big Picture 影響摘要

Phase 1 的幾個設計決策會被後續 Phase 大量使用，如果 Phase 1 做錯，後面修的成本很高：

`activity_events` 的 `project` 正確性（Phase 2 MCP、Phase 3 drift detection、週報、session reconstruction、Phase 4 dashboard 全部依賴）。`tags` 的層級結構品質（Phase 2 MCP search filter、Phase 3 drift detection tag 維度、Phase 4 tech stack radar）。`obsidian_notes` 的 `search_text` + tsvector + embedding（Phase 2 MCP hybrid search 直接消費）。`obsidian_notes.content_text` 保持原始格式不被 preprocessing 破壞（Phase 3 knowledge graph 需要 parse wikilinks）。`activity_events.metadata` JSONB 的 generic 結構（Phase 1.5 events-only sync 需要塞任意 Notion property）。Genkit flow 的 JSON 處理 pattern（Phase 2 flow 拆分要 follow 同樣 pattern）。

---

## 6. 明確不做的事情與理由

### 6.1 工具選型

**不用 ActivityWatch / WakaTime。** 產出導向。緩解：B3 churn ratio。**不用 Readwise。** 手動高 SNR。Phase 2 Spaced Repetition 覆蓋。**不用 Linear。** Notion 覆蓋 100%。代價由 B4 緩解。

### 6.2 技術提案

**Delta Map-Reduce Filter/Compress 不做。** LLM filtering。**Rust Worker 不做。** Go 跑幾秒，CI/CD 成本遠超。

### 6.3 Source Flexibility

**Generic Notion page API 不做。** 自然語言 description 夠。**Obsidian folder-based sync 不做。** Frontmatter 更穩定。**Obsidian tag controlled vocabulary / Linter 不做。** 摩擦太大。

### 6.4 其他

**CLI 不做。** Admin UI + HTTP API。**Dual tsvector 不做。** Embedding 覆蓋。**sync_mode snapshot 不做。** poll_interval 調整。**Cross-Project Transfer 推遲 Phase 4。** False positive 高。**People CRM 推遲。** Client 不足。**Session Reconstruction 推遲 Phase 3。** Threshold 難調。**Notion Agent critical path 不做。** 定價不明。**Tag seed data 不做。** Pipeline 自然積累。

---

## 7. 需要 Claude Code 獨立判斷的問題

### 7.1 B1 transaction 內的 tag lookup batch 策略

Upsert + junction + activity_events 確定同一 tx。但 50 個 .md 每篇都查 `tag_aliases` 會大量 round trip。是否 tx 前 batch preload？根據 pgx/v5 batch pattern 判斷。

### 7.2 `tag_aliases.tag_id` nullable vs sentinel

NULL = unmapped vs `__unmapped__` sentinel。根據 pgx/v5 nullable FK handling 決定。

### 7.3 `tags` 和 `topics` 是否合併

重疊存在。合併可能更乾淨但影響 blog。根據 `topics.id` 依賴深度判斷。

### 7.4 CamelCase splitting 邊界

A2 列了原則和 edge case，需要測試驗證。

### 7.5 Admin UI Angular module 結構

現有專案有無 admin module？有則 follow。

### 7.6 Embedding 排隊

傾向寫入 `flow_runs` 讓 persistent runner 消費。確認現有 runner 是否可用。

### 7.7 Webhook HMAC + Git identity + 路徑

確認 webhook handler 有無 `X-Hub-Signature-256` 驗證。確認 webhook 實際路徑（直連 vs BFF proxy）。確認寫回 vault 的 Git identity（Koopa 帳號 vs 專用 bot）。

### 7.8 PR description Notion link parse

Regex 掃全文找 Notion URL。多個 link 時取第一個、全部嘗試、還是要求特定格式？

### 7.9 `GenerateData[T]()` vs `RobustUnmarshal`

查 Genkit Go SDK source。暴露 raw response → 共存。不暴露 → `genkit.Generate()` + `RobustUnmarshal`。

### 7.10 Migration 順序

統一 script vs 獨立 files。根據現有 migration 管理方式。

### 7.11 Genkit flow pilot 選擇

建議 daily dev log。更適合的現有 flow 可以提出。

---

## 8. 設計哲學（不可協商）

**「能用一個 SQL query 解決的就不要建 pipeline，能用 Go 標準庫解決的就不要引入新語言。」**

**「Go code 做 LLM 做不好的事（aggregation、dedup、time windowing），LLM 做 Go code 做不好的事（判斷什麼有價值、語意理解、cross-source correlation）。」**

**「寧可少一個 data source，也不要多一層 integration complexity。」**

---

## 9. Reference Documents

**現有 PostgreSQL Schema**：Migration baseline。Contents 0 筆。

**v3.0 整合策略與功能規劃**：按需查閱 §3.1、§3.2、§3.3、§4.2、§4.5、§5.1.1、§11.1、§11.3、§13.1、§16、§17、§19。

**Source Flexibility 技術決策報告**：Notion/Obsidian/Tag 完整決策。如需 property_map 設計、`extractValue` pseudo-code，查對應 Section。
