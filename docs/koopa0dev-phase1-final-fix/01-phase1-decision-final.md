# koopa0.dev Phase 1 — 完整決策與實作指導文件

> **Version**: 3.0 (Final)  
> **Date**: 2026-03-17  
> **產出方式**: Koopa × Claude Opus 多輪交叉討論，經 Claude Code audit + 兩輪獨立 review 修正  
> **Embedding**: 768 維（`internal/flow/content.go:251`，gemini-embedding-2-preview）  
> **Contents table**: 0 筆（migration 可 recreate）  
> **Repo 結構**: Obsidian vault 和 blog content 是同一個 repo

---

## 目錄

1. 系統現狀
2. 這次要解決的問題
3. Phase 1 完整工項清單與執行順序
4. 每個工項的技術設計與決策推理
5. 後續 Phase 預覽（Big Picture）
6. 明確不做的事情與理由
7. 需要 Claude Code 獨立判斷的問題
8. 設計哲學（不可協商）
9. Reference Documents

---

## 1. 系統現狀

### 1.1 架構概覽

koopa0.dev 是 Koopa 的個人知識引擎，Go 建構。Notion UB3.0 管「做了什麼」（Tasks、Projects、Goals、Books）。Obsidian vault 管「學了什麼」（解題筆記、讀書筆記、decision log）。koopa0.dev 做「整合 + 歸納 + 展示 + 推送」。資料流單向——Notion/Obsidian 是 source of truth，koopa0.dev 只做 ingestion/analysis/display。唯一寫回是 Genkit 產出的 review/report，走 git commit 或 Notion API create page，append 行為。

### 1.2 技術棧

Go backend、PostgreSQL + pgvector（`vector(768)`）、Firebase Genkit、Angular frontend（含 BFF service）、LINE/Telegram、Cloudflare Tunnel + WAF、Prometheus + Grafana + Loki。

### 1.3 已上線基礎設施（Claude Code audit 確認）

Notion API sync（polling + webhook）。GitHub webhook（含 `X-Hub-Signature-256` HMAC 驗證 ✅）。GitHub API client（FileContent、ListDirectory、RecentCommits）。Obsidian frontmatter parser（存在但欄位不足，需擴充）。Webhook replay protection（DeduplicationCache）。Genkit flows 含 persistent runner、token budget、retry。Blog 系統。RSS feed + AI 評分。前端已有 dashboard、article-editor、project-editor、review、feeds、flow-runs、collected 等 admin 頁面。

### 1.4 現有 Database Schema

`contents`（0 筆，有 `embedding vector(768)` + HNSW，`search_vector` 用 `english` config 需修正）。`topics`（24 筆 seed）。`feeds` + `collected_data`。`flow_runs`（persistent runner）。`projects` + `goals`。Migration 用 golang-migrate，目前只有 `001_initial.up.sql`。

不存在的（本次新建）：`activity_events`、`activity_event_tags`、`obsidian_notes`、`obsidian_note_tags`、`tags`、`tag_aliases`、`project_aliases`。

### 1.5 Repo 結構與 Sync 流程

**Obsidian vault 和 blog content 在同一個 repo。** `10-Public-Content/` 目錄是 blog 文章，走現有 pipeline → contents table。其他目錄是知識筆記，走新的 B1 pipeline → obsidian_notes table。Webhook handler 用 file path 分流。

現有的 Obsidian sync（`pipeline/handler.go`）用 `event.Repository.FullName` 判斷 repo，再用 path prefix 區分 blog content vs 其他。webhook 目前經 Angular BFF proxy 到 Go backend。Phase 1 維持現狀，Phase 1.5 評估 Cloudflare Tunnel path-based routing。

### 1.6 現有 Frontmatter Parser 差距

`internal/obsidian/obsidian.go` 目前只有 title/tags/published/created/updated。Phase 1 需要擴充：type/source/context/status/difficulty/leetcode_id/book/chapter/notion_task_id。

**兩條 pipeline 共存，不統一遷移。** `10-Public-Content/` 繼續用現有 parser + contents table。新 B1 用擴充後的 parser + obsidian_notes table。兩條路徑在 webhook handler 層用 file path 分流，互不干擾。

---

## 2. 這次要解決的問題

### 2.1 核心 Loop 缺失

缺少「Notion + Obsidian + GitHub 工作痕跡統一匯入 → Genkit 分析 → 推送 insight」的核心 loop。

### 2.2 Tag 混亂

Free-form tags diverge。下游全依賴 tag 一致性。

### 2.3 搜尋品質

tsvector `english` stemming 破壞技術術語。CamelCase/snake_case 無法有效 index。

### 2.4 Genkit Flow 品質

P0：temperature 錯誤（含 weekly review）、缺 JSON 容錯、content policy 被 retry。P1：prompt 缺 negative examples。

### 2.5 Data Integrity

拒絕 Linear 後，PR merge 不自動更新 Notion Task。

---

## 3. Phase 1 完整工項清單與執行順序

### 3.1 執行順序

**Stage 0 — Audit + Gate**

B5 Frontmatter audit script。結果是 gate：缺少 `type` 的比例超過 70% → 先做 F4 批次補 frontmatter 再上線 B1。低於 70% → B1 直接上線。

**Stage 1 — Schema + Genkit Audit（可平行）**

A1-A6 全部 schema migration。C1 Genkit P0 修復（含 weekly temperature）。C2 Genkit P1 改善。G1 Health check metrics。

**Stage 2 — Backend 實作（依賴 Stage 1 schema）**

A2 CamelCase splitting（B1 依賴）。B2 自迴圈防護。B1 Obsidian sync pipeline（依賴 A2、A3、A4、A6）。B3 GitHub diff stats。B4 PR → Notion Task。

**Stage 3 — 驗證 + Admin UI**

手動觸發 B1/B3，確認 activity_events 有真實資料。D1 Genkit flow pilot（precondition: activity_events 至少一天真實資料）。E1 Admin UI Tag 管理（在 B1 上線後，用真實 unmapped tags 資料設計 UI）。

**執行順序修正說明**：E1 排在 B1 之後（不是之前）。Tag seed data 不做 migration 硬編碼，讓 B1 pipeline 自然積累。B1 上線後 unmapped tags 堆積，E1 上線後整理。B1 到 E1 之間 unmapped tags 的 tag_id 是 NULL，junction table 不寫入（FK constraint 擋住），不影響 data integrity。E1 mapping 完成後跑 backfill 補寫 junction table。

### 3.2 完整項目 Table

#### Claude Code 負責

| ID | 項目 | Stage | 來源 |
|----|------|-------|------|
| A1 | tsvector `simple` + `search_text`（recreate） | 1 | 決策報告 §5 |
| A2 | CamelCase splitting Go 邏輯 + tests | 2 | 決策報告 §5 |
| A3 | `tags` + `tag_aliases` + `obsidian_note_tags` + `activity_event_tags` | 1 | 決策報告 §4 + review |
| A4 | `activity_events`（含 `source_id` dedup） | 1 | v3.0 §3.1 + review |
| A5 | `project_aliases` table | 1 | 討論 |
| A6 | `obsidian_notes`（含 HNSW） | 1 | v3.0 §3.3 + 修正 |
| B1 | Obsidian sync pipeline（mutex + transaction + path 分流） | 2 | v3.0 + review |
| B2 | 自迴圈防護（sender 檢查，config placeholder） | 2 | v3.0 §13.1 |
| B3 | GitHub diff stats extraction | 2 | v3.0 §17.1 |
| B4 | PR merge → Notion Task（PR description Notion link） | 2 | v3.0 §17.3 + review |
| B5 | Frontmatter audit script | 0 | 討論 |
| C1 | Genkit P0 修復（五項，含 weekly temperature） | 1 | v3.0 §19.2 + review |
| C2 | Genkit P1 改善（三項 prompt） | 1 | v3.0 §19.2 |
| D1 | Genkit flow pilot | 3 | v3.0 Phase 1 |
| E1 | Admin UI — Tag 管理 | 3 | 決策報告 §4 |
| G1 | Health check metrics | 1 | 討論 |

#### Koopa 負責

| ID | 項目 |
|----|------|
| F1 | Notion LeetCode Practice Project |
| F2 | Obsidian Bases（四個） |
| F3 | Obsidian 插件配置（Git、Linter、Templater） |
| F4 | Templater templates + 批次補 frontmatter（如 B5 audit > 70%） |
| F5 | Notion unique ID property 評估（Phase 1.5 候選） |
| F6 | Notion Agent 試驗性測試 |

---

## 4. 每個工項的技術設計與決策推理

### A1. tsvector Configuration 修正

`contents.search_vector` 從 `english` 改 `simple`。新增 `search_text` column。Contents 0 筆，直接 recreate。

不加回 excerpt weight B。`simple` config 下 excerpt 的 token 是 search_text 的嚴格子集，weight B 的 marginal value 接近零。三路 RRF 裡排序由 pgvector embedding 負責，tsvector 只負責精確匹配。兩位獨立 reviewer 得出相同結論。

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

Go 層。連續大寫 = 一個 token。數字跟前 token。Dot/snake_case 拆開。**不能破壞 `[[wikilink]]` syntax**（Phase 3 Knowledge Graph 需要 parse wikilinks，見 §5 Big Picture）。

Table-driven test：`HTTPSRedirect`、`OAuth2Client`、`DDIA_Ch8`、`io.Reader`、`[]string`、`map[string]interface{}`、`pgxpool.Pool`、`ErrRedisConnectionTimeout`、`[[some-note]]`（不應被拆）。

### A3. Tag Normalization 系統

四張 table + ingestion-time normalization。Tag seed data 不做——pipeline 自然積累 + E1 Admin UI 整理。

**已確定的決策（從 §7 移出）**：`tag_aliases.tag_id` 用 nullable（NULL = unmapped）。`tags` 和 `topics` 不合併（語意不同，topics 是 blog 展示分類，tags 是知識標籤）。

**`activity_event_tags` scope 限縮**：Phase 1 只由 B1（Obsidian sync）寫入。GitHub 和 Notion events 在 ingestion 時不打 tags（commit 和 task 沒有天然的 tag 概念）。GitHub/Notion events 的 tag 關聯由 Phase 3 的 Genkit weekly flow 在 analysis 時透過 `project` + `event_type` + 語意理解推斷，不在 ingestion 時持久化。這符合設計哲學第二條（LLM 做語意理解，Go 做 aggregation）。

**B1 到 E1 之間的 unmapped tag 處理**：Step 4（no match）→ 只寫 `tag_aliases` with tag_id = NULL → 不寫 `obsidian_note_tags`（FK constraint 會擋）。E1 上線後 mapping 完成，跑 backfill：掃 `tag_aliases WHERE tag_id IS NOT NULL AND confirmed_at > last_backfill_time`，找引用這些 raw tags 的 obsidian_notes，補寫 junction table。

```sql
CREATE TABLE tags (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,  -- lowercase + hyphens, 碰撞時後綴 -2
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
    tag_id        UUID REFERENCES tags(id),  -- NULL = unmapped
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

四步 normalization pipeline：1) Exact match。2) Case-insensitive（auto-confirm）。3) Slug match（`confirmed=false`，先生效）。4) No match（unmapped pool）。

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

Dedup index 含 `event_type`（防 Notion same-minute 多 property 變更的 false dedup）。source_id：GitHub = delivery ID，Notion = `page_id+edited_time+property`，Obsidian = `file_path+content_hash`。Nullable。metadata 消費者是 Go SQL aggregation，不需 functional index。

### A5. project_aliases Table

直接用 table（已確定，從 §7 移出）。Admin UI settings 區塊管理。

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

`vector(768)`。HNSW 保留（空 table 建 index 成本零，Phase 2 MCP 預建）。`content_hash` 用 SHA-256，**只對 frontmatter 以下的 markdown body 算**，不含 frontmatter block。frontmatter 變更觸發 metadata upsert 但不觸發 re-embedding（body 沒變，embedding 結果相同）。

```sql
CREATE TABLE obsidian_notes (
    id              BIGSERIAL PRIMARY KEY,
    file_path       TEXT UNIQUE NOT NULL,
    title           TEXT,
    type            TEXT,            -- hard required for Tier 1
    source          TEXT,
    context         TEXT,
    status          TEXT DEFAULT 'seed',
    tags            JSONB,           -- raw audit trail
    difficulty      TEXT,
    leetcode_id     INT,
    book            TEXT,
    chapter         TEXT,
    notion_task_id  TEXT,
    content_text    TEXT,            -- 原始 body（等價 contents.body）
    search_text     TEXT,            -- CamelCase preprocessed
    content_hash    TEXT,            -- SHA-256 of body only (excludes frontmatter)
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
Webhook 進來（同一個 repo）
  → File path 分流：
      10-Public-Content/* → 現有 blog pipeline → contents table（不動）
      其他 .md → 新 B1 pipeline ↓
  → B2: Sender 檢查 → 自己的 push → skip
  → Mutex lock
  → Parse changed files（git diff --diff-filter=A/M）
  → 每個 .md：
      → GitHub API 取 file content
      → Parse frontmatter + body 分離
      → body SHA-256 → content_hash
      → 檢查 `type` field
          → 沒有 → Prometheus counter, skip
          → 有 → Tier 1:
              → BEGIN TRANSACTION
              → Tag normalization（四步）
                  → mapped tags → 寫 obsidian_note_tags
                  → unmapped tags → 只寫 tag_aliases (tag_id=NULL), 不寫 junction
              → CamelCase splitting → search_text
              → content_hash 比對 DB：
                  → hash 相同 + frontmatter 變了 → metadata upsert only, skip embedding
                  → hash 不同 → full upsert + 排隊 embedding
              → Upsert obsidian_notes
              → Insert activity_events + activity_event_tags（只寫 mapped tags）
              → COMMIT
              → 排隊 embedding via flowrun.Submit（tx 之外，follow pipeline/handler.go:593-604 pattern）
  → Mutex unlock
```

**Transaction boundary**：upsert + junction tables + activity_events 同一個 pgx tx。Embedding 放 commit 後。原因：activity_events 寫入失敗但 notes 成功時，content_hash 匹配會 skip → silent data loss。

**content_hash 只算 body 不含 frontmatter**：避免 frontmatter 變更觸發無意義的 re-embedding。

所有 cron 以 `Asia/Taipei` 為準。

### B2. 自迴圈防護

Webhook handler 按 sender/author 檢查（config 項 `GitBotUsername`，Phase 1 留 placeholder，D1 實作寫回時啟用）。不需要現在建專用 Git identity。

### B3. GitHub Diff Stats

Push event → `activity_events.metadata`: `{"lines_added": N, "lines_removed": N, "files_changed": N}`。**不在 ingestion 時打 tags**（見 A3 scope 限縮）。

### B4. PR Merge → Notion Task

Regex 掃 PR body **所有** Notion URL（`https://(www\.)?notion\.so/...`），page ID = URL 末段 32 hex chars。全部嘗試更新 Task status → Done。個別失敗 log warning 繼續。沒有 link → log warning。Phase 1.5 候選：Notion unique ID property。

### B5. Frontmatter Audit（Stage 0 Gate）

掃 vault 全部 .md（透過 GitHub API），按 type 分組產出差距報告。**Gate threshold**：缺少 `type` > 70% → 先做 F4 批次補 frontmatter 再上線 B1。< 70% → B1 直接上線。

### C1. Genkit P0 修復（五項）

**C1-a. Temperature。** `build-log-generate` 0.6→0.3。`bookmark-generate` 0.5→0.3。**`weekly-review` 0.6→0.3**（output 是 JSON envelope `{"text": "..."}`，需要 JSON parse 精確度）。

**C1-b + C1-c.** `GenerateData[T]()` vs `RobustUnmarshal`：見 §7.1，先查 Genkit Go SDK。

**C1-d.** FinishReason SAFETY/RECITATION/OTHER → permanent failure。

### C2. Genkit P1

`review.txt`（Level 標準 + negative examples）。`tags.txt`（選擇策略 + negative rules）。`excerpt.txt`（吸引非總結、160 字 SEO）。

### D1. Genkit Flow Pilot

**Precondition**: activity_events 至少一天真實資料。Daily Dev Log（23:00 Asia/Taipei），掃當天 events → Obsidian vault + LINE 摘要。

### E1. Admin UI — Tag 管理（Stage 3，B1 之後）

Unmapped pool、tag tree、pending confirmation、merge。Angular lazy-loaded `/admin/tags`。Project alias 管理放 settings 區塊。

**Backfill 功能**：E1 做完 tag mapping 後，提供「backfill junction tables」按鈕——掃 `obsidian_notes.tags` JSONB 裡的 raw tags，對照新建的 `tag_aliases` mapping，補寫 `obsidian_note_tags` 和 `activity_event_tags`。

API Endpoints（Claude Code 後端實作）：`GET/POST/PUT/DELETE /api/admin/tags`、`GET/PUT /api/admin/tag-aliases`、`POST /api/admin/tags/merge`、`POST /api/admin/tags/backfill`、`GET/POST/PUT/DELETE /api/admin/project-aliases`。

### G1. Health Check Metrics

`koopa0dev_activity_events_total`（**counter**，monotonically increasing，Grafana 用 `increase(...[24h])` 算日增量，alert 檢測 24h 零增量）。`koopa0dev_notion_last_sync_timestamp`（gauge）。`koopa0dev_obsidian_last_sync_timestamp`（gauge）。`koopa0dev_genkit_flow_runs_total`（counter，label: flow_name, status）。`koopa0dev_obsidian_notes_missing_frontmatter_total`（counter）。

---

## 5. 後續 Phase 預覽（Big Picture）

Phase 1 的設計決策會被後續 Phase 大量消費。以下標注每個 Phase 對 Phase 1 的 implicit 約束。

### Phase 1.5 — Source 解耦

**Notion Source Registry。** `notion_sources` table + Admin UI（`/admin/sources`）。`property_map` JSONB 映射 Notion property → canonical name + type + extract path。`sync_mode`（full/events/disabled）。`description`（自然語言，給 Genkit 和 MCP 用）。現有 full mode databases（Tasks、Projects、Goals、Books）建記錄但 sync 不動。新 database 用 events-only generic sync。

→ Phase 1 約束：`activity_events.metadata` JSONB 結構要夠 generic，讓 events-only sync 能塞任意 Notion property。

**Obsidian Tier 2 決策。** 根據 `missing_frontmatter` counter。> 10% 建 `obsidian_raw` table。

**Cloudflare Tunnel path-based routing。** `/api/webhook/*` 直連 Go backend。

### Phase 2 — Knowledge Backbone

**MCP Server（最高優先級）。** 四個 tool：`search_notes`（hybrid search）、`get_project_context`、`get_recent_activity`、`get_decision_log`。三路 RRF：pgvector + tsvector simple + frontmatter exact match。

→ Phase 1 約束：`obsidian_notes` 的 search_text + tsvector + embedding 是 MCP hybrid search 的基礎。CamelCase splitting 品質直接影響搜尋品質。

**Genkit Audit P2。** content-review 拆為 content-proofread（Flash）/ content-metadata（Sonnet）/ content-embed（Go 直呼叫）。Prompt template injection。Token usage logging。

→ Phase 1 約束：C1 的 JSON 處理路徑（GenerateData vs RobustUnmarshal）決定 P2 拆分時的 API contract。

**Spaced Repetition。** `review_schedule` table + SM-2 + LINE 推送。

→ Phase 1 約束：`obsidian_notes.type` 是複習策略的 routing key。

**Content Maturity。** seed → sapling → tree → published。`status: published` 自動 sync 到 blog。

→ Phase 1 約束：`obsidian_notes.status` 默認 `seed`，對齊 content maturity model。

### Phase 3 — Intelligence Layer

**統一週報。** 全源 activity_events aggregation → LINE + Notion + Obsidian。

→ Phase 1 約束：`activity_events.project` 正確性（project_aliases）和 `activity_event_tags` junction（但 GitHub/Notion events 的 tag 由 Genkit 在此階段推斷，不在 Phase 1 ingestion）。

**Drift Detection。** Activity 佔比 vs Goals priority。

→ Phase 1 約束：Goals → Projects → Tasks relation 鏈需要 project_aliases 正確 join。

**Session Reconstruction。** 時間窗口 + project matching → work_sessions table。Genkit 初步聚合 + Admin UI 確認。

**Knowledge Graph。** Parse wikilinks → `obsidian_links` table → 孤島/cluster 分析。

→ Phase 1 約束：`obsidian_notes.content_text` 保留原始 wikilink syntax。A2 CamelCase splitting 不能破壞 `[[...]]`。

**月度 Flows。** Retrospective、Goals 對齊、Books 分析、Personal Changelog。

### Phase 4 — Public & Portfolio

**Learning Dashboard。** LeetCode heatmap、閱讀進度、tech stack radar（用 `tags` parent-child 聚合）。

→ Phase 1 約束：tags 層級結構品質影響 radar 呈現。

**Changelog / Cross-Project Transfer / Retrospective Intelligence。**

### Big Picture 影響摘要

Phase 1 高風險決策（做錯後面修成本高）：`activity_events.project` normalization 正確性。`tags` 層級結構品質。`search_text` + tsvector + embedding 品質。`content_text` 保持原始格式（wikilinks）。`metadata` JSONB 的 generic 結構。Genkit JSON 處理 pattern 一致性。

---

## 6. 明確不做的事情與理由

**工具**：不用 ActivityWatch/WakaTime（產出導向）、Readwise（手動高 SNR）、Linear（Notion 覆蓋 100%）。

**技術**：不做 Delta Map-Reduce Filter/Compress（LLM filtering）、Rust Worker（Go 夠快）、dual tsvector（embedding 覆蓋）、excerpt weight B（simple config 下 marginal value 零）。

**Source Flexibility**：不做 generic Notion API、folder-based sync、tag controlled vocabulary、Linter API。

**其他**：不做 CLI（Admin UI + HTTP API）、sync_mode snapshot（poll_interval）、description drift detection（手動）、Cross-Project Transfer（Phase 4，false positive 高）、People CRM（client 不足）、Session Reconstruction（Phase 3）、Notion Agent critical path（定價不明）、tag seed data migration（pipeline 自然積累）。

**GitHub/Notion events 的 ingestion-time tag extraction 不做。** Commit 和 task 沒有天然 tag 概念，硬寫 inference 邏輯是「用 heuristic 做 LLM 該做的事」。Phase 3 Genkit 在 analysis 時推斷。

---

## 7. 需要 Claude Code 獨立判斷的問題

（已解決的項目已移出：nullable ✅、不合併 ✅、table ✅、flowrun.Submit ✅、全部 Notion URL ✅、獨立 migration files ✅）

### 7.1 `GenerateData[T]()` vs `RobustUnmarshal`

查 Genkit Go SDK source。暴露 raw response → 共存。不暴露 → `genkit.Generate()` + `RobustUnmarshal`。

### 7.2 B1 transaction 內的 tag lookup batch 策略

50 個 .md 每篇都查 tag_aliases → 大量 round trip。是否 tx 前 batch preload？

### 7.3 CamelCase splitting 邊界

A2 指導原則 + edge case 列表，需測試驗證。特別注意 `[[wikilink]]` 不被拆。

### 7.4 Webhook 路由細節

確認 webhook 實際路徑（BFF 有無 transformation/buffering）。確認 koopa0.dev 寫回 vault 的 Git identity（Koopa 帳號 vs 專用 bot，決定 B2 的 config 值）。

### 7.5 Admin UI Angular module 結構

現有專案有無 admin module？有則 follow。

### 7.6 Frontmatter parser 擴充策略

現有 `internal/obsidian/obsidian.go` parser 擴充 vs 新建獨立 parser for B1。考慮兩條 pipeline 共存（blog vs knowledge）的 frontmatter 差異。

---

## 8. 設計哲學（不可協商）

**「能用一個 SQL query 解決的就不要建 pipeline，能用 Go 標準庫解決的就不要引入新語言。」**

**「Go code 做 LLM 做不好的事，LLM 做 Go code 做不好的事。」**

**「寧可少一個 data source，也不要多一層 integration complexity。」**

---

## 9. Reference Documents

**02-existing-schema-baseline.sql**：Migration baseline。

**03-v3-integration-strategy.md**：完整系統設計。按需查閱 §3.1-3.3、§4.2-4.5、§5.1.1、§11.1-11.3、§13.1、§16-17、§19。

**04-source-flexibility-decision-report.md**：property_map 設計、extractValue pseudo-code。
