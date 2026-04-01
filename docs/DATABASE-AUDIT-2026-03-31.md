# koopa0.dev Database Audit Report

**日期**: 2026-03-31
**審查者**: Claude (Opus 4.6)
**資料庫版本**: PostgreSQL 17
**Schema 來源**: `migrations/001_initial.up.sql` (739 lines, single migration)
**審查範圍**: 24 tables, 2 views, ~250 sqlc queries, 18 feature packages, 1 migration file

---

## Executive Summary

### 審查範圍

| 項目 | 數量 |
|------|------|
| Tables | 24 |
| Views | 2 |
| Enum types | 10 |
| sqlc query files | 18 |
| Named queries | ~250 |
| Raw SQL queries (stats) | ~15 |
| Migration files | 1 (monolithic initial) |

### 發現問題統計

| 嚴重度 | 數量 | 說明 |
|--------|------|------|
| 🔴 Critical | 4 | N+1 效能問題、語意歧義、資料完整性風險 |
| 🟡 Major | 12 | 型別選擇、缺少索引、命名不一致、正規化問題 |
| 🟢 Minor | 18 | 命名風格、可選優化、COMMENT 缺失 |

### 最高優先級問題摘要（前 5 項）

1. **🔴 content `Search()` 系列方法不填充 Topics** — 5 個 search/list 方法回傳的 Content 物件 Topics 欄位為空，呼叫端若需 topics 會觸發 N+1
2. **🔴 `obsidian_notes` 使用 `TEXT` + `CHECK` 模擬 enum，但 CHECK 允許 NULL 且值域與 `content_status` 不同** — `status` 欄位語意模糊，'seed'/'evergreen'/'stub' 與 content 系統的 'draft'/'published' 完全不同卻共用 "status" 概念
3. **🔴 `collected_data` 缺少 `NOT NULL` 約束** — `original_content`、`source_url` 等核心欄位允許 NULL 但業務上不應為空
4. **🟡 `contents.tags TEXT[]` 與正規化 tag 系統平行存在** — tags 同時存在於 `contents.tags[]` 陣列和 `tags` + `tag_aliases` 正規化系統中，兩套系統未整合
5. **🟡 `projects` 表欄位過多（22 欄）** — 混合了展示用途（`highlights`、`problem`、`solution`）、管理用途（`status`、`deadline`）和同步用途（`notion_page_id`），職責過於龐大

---

## Table-by-Table Audit

### users

**用途**: 系統管理員帳戶。目前只有 admin 角色，CHECK 約束硬限 `role = 'admin'`。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 命名 | 表名 `users` 正確使用複數 ✓ | — | 無需修改 | — |
| 2 | 🟢 | 約束 | `role CHECK (role = 'admin')` — 目前只有單一角色，CHECK 合理但可考慮直接移除 role 欄位 | `role TEXT NOT NULL DEFAULT 'admin'` | 若永遠只有 admin，可移除 role 欄位以簡化；若未來有多角色需求則保留 | auth 相關 query |

**相關 Queries 問題**: 無。`UserByEmail`、`UserByID`、`UpsertUserByEmail` 皆正確。

---

### refresh_tokens

**用途**: JWT refresh token 存儲，使用 token hash 而非明文。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | Schema 設計良好：hash 存儲 ✓、CASCADE 刪除 ✓、過期索引 ✓ | — | 無需修改 | — |

**相關 Queries 問題**: 無。`ConsumeRefreshToken` 使用 `DELETE...RETURNING` 實現原子消費，正確。

---

### topics

**用途**: 內容分類標籤（如 Go、Rust、AI 等），用於 content 的多對多分類。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 命名 | `icon TEXT` — nullable 且無 COMMENT，語意不明（是 emoji？URL？icon class？） | 允許 NULL | 加 COMMENT 說明用途和格式 | topic 展示相關 |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `RelatedTagsForTopic` | 🟢 效能 | 對 `contents.tags[]` 做 `unnest` + `GROUP BY` — 對大量 content 可能較慢 | 目前資料量小可接受，長期考慮物化視圖 |

---

### contents

**用途**: 核心內容表，存儲所有類型的內容（article、essay、build-log、til、note、bookmark、digest）。系統最重要的表。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟡 | 正規化 | `tags TEXT[]` 與正規化 tag 系統（`tags` + `tag_aliases` + `obsidian_note_tags`）平行存在。content 的 tags 存在陣列中，obsidian notes 的 tags 走正規化系統。兩套系統在 learning analytics 中同時被使用，增加複雜度 | `tags TEXT[] NOT NULL DEFAULT '{}'` | 長期應統一：content 也走 content_tags 正規化表（類似 content_topics），消除 `TEXT[]`。短期可接受但須記錄為技術債 | `ContentTagsByTypeAndProject`、`ContentRichTagEntries`、learning analytics、stats 的 `learningTopTags` |
| 2 | 🟡 | 型別 | `visibility TEXT CHECK (IN ('public', 'private'))` — 只有兩個值，適合用 `BOOLEAN` (`is_public`)，語意更清晰 | `TEXT NOT NULL DEFAULT 'public'` | 改為 `is_public BOOLEAN NOT NULL DEFAULT true`。但影響範圍大（~20 queries），ROI 偏低 | 所有有 visibility 過濾的 query |
| 3 | 🟡 | 型別 | `reading_time INT` — 沒有 COMMENT 說明單位（分鐘？秒？） | `INT NOT NULL DEFAULT 0` | 改名為 `reading_time_min` 或加 COMMENT `'Estimated reading time in minutes'` | 前端展示 |
| 4 | 🟢 | 約束 | `project_id UUID` 允許 NULL — 合理，不是所有 content 都屬於 project | FK 已在 ALTER TABLE 定義 ✓ | 無需修改 | — |
| 5 | 🟢 | 索引 | `idx_contents_embedding_hnsw` 使用 HNSW 索引，參數合理 (m=16, ef_construction=64) ✓ | — | 無需修改 | — |
| 6 | 🟢 | 約束 | `series_id` 和 `series_order` 沒有一致性約束 — 可能出現 `series_order` 有值但 `series_id` 為 NULL 的情況 | 兩者皆 nullable | 加 CHECK: `CHECK ((series_id IS NULL AND series_order IS NULL) OR (series_id IS NOT NULL AND series_order IS NOT NULL))` | content 系列功能 |
| 7 | 🟢 | COMMENT | 多數欄位缺少 COMMENT — 雖然型別和命名已足夠清晰，但 `ai_metadata JSONB` 的結構完全不明 | 無 COMMENT | 至少為 `ai_metadata` 加 COMMENT 說明 JSON 結構 | AI pipeline |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `SearchContents` + 4 others | 🔴 N+1 風險 | Search 系列 query 回傳完整 content 列但不含 topics。Go store 層的 `Search()`、`SearchOR()`、`InternalSearch()`、`InternalSearchOR()`、`ContentsByTopicID()` 都不呼叫 `topicsForContents()` 來批量填充 topics | 在 store 層加上 batch topic load，與 `Contents()` 方法一致 |
| 2 | `SearchContentsOR` | 🟡 正確性 | Go store 的 `SearchOR()` 回傳 `len(contents)` 作為 count 而非實際查詢總數。分頁時 count 不正確 | 新增對應的 `SearchContentsORCount` query，或加 window function `COUNT(*) OVER()` |
| 3 | `PublishedContentsByDateRange` | 🟡 效能 | 無 LIMIT — 如果日期範圍很大可能回傳大量結果 | 加 LIMIT 參數或在 Go 層設硬上限 |
| 4 | `ContentsWithoutEmbedding` | 🟢 效能 | 只檢查 `embedding IS NULL` 但不檢查 `status`（包含 draft、archived） — 可能為不需要 embedding 的 draft 生成 embedding | 加 `AND status IN ('published', 'review')` 過濾 |

---

### content_topics

**用途**: contents ↔ topics 多對多關聯表。

**Schema 問題**: 無。設計正確：複合 PK ✓、雙向 CASCADE ✓、topic_id 索引 ✓。

---

### projects

**用途**: 專案管理，包含展示資訊（portfolio）、管理狀態（進度追蹤）、和外部同步（Notion）。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟡 | 正規化 | 22 個欄位，職責過於龐大。混合了：展示 (`long_description`, `problem`, `solution`, `architecture`, `results`, `highlights`, `cover_image` — 但 cover_image 不存在)、管理 (`status`, `deadline`, `goal_id`, `expected_cadence`)、外部同步 (`notion_page_id`, `repo`, `last_activity_at`) | 單一表 | 可考慮拆為 `projects`（核心 + 管理）和 `project_profiles`（展示用途的長文本欄位）。但目前欄位間無明確的一對多關係，拆分收益有限。記錄為觀察項 | 大量 project query |
| 2 | 🟡 | 約束 | `goal_id UUID` FK 到 `goals(id)` ON DELETE SET NULL — 合理，但沒有檢查 goal 是否 archived/abandoned。可能關聯到已廢棄的 goal | FK 存在 ✓ | 業務邏輯層處理即可，不需 DB 約束 | project-goal 關聯 |
| 3 | 🟡 | 型別 | `public BOOLEAN` — PostgreSQL 保留字，雖然不加引號也能用但容易在 raw SQL 中造成歧義 | `public BOOLEAN NOT NULL DEFAULT false` | 改名為 `is_public`，與 PostgreSQL 慣例和 Go 的命名更一致 | ~10 queries, 前端 |
| 4 | 🟢 | 命名 | `expected_cadence TEXT CHECK (...)` — 語意清晰但 CHECK 包含空字串 `''` 作為「未設定」的語意，這比 NULL 更不慣用 | `DEFAULT '' CHECK (IN ('', 'daily', ...))` | 改為 nullable，NULL 代表未設定。或保持現狀（空字串在 Go 中更好處理） | cadence 相關邏輯 |
| 5 | 🟢 | 索引 | `idx_projects_public` 使用 `WHERE public = true` 的 partial index ✓ | — | 無需修改 | — |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `UpsertProjectByNotionPageID` | 🟢 正確性 | 正確使用 ON CONFLICT，但更新時不處理 `goal_id` 和 `last_activity_at` | 確認這是否為刻意設計（Notion 不同步這些欄位） |

---

### review_queue

**用途**: 內容發布前的審核佇列。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | `idx_review_queue_pending_content` UNIQUE partial index 防止 TOCTOU — 優秀設計 ✓ | — | 無需修改 | — |
| 2 | 🟢 | 約束 | `reviewed_at` nullable — 合理，pending 時為 NULL | — | 無需修改 | — |

---

### feeds

**用途**: RSS/Atom feed 訂閱管理，含健康追蹤和條件式抓取（ETag/Last-Modified）。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 型別 | `filter_config JSONB` — 用於動態過濾規則（deny_paths、deny_title_patterns、deny_tags），JSONB 在此場景合理因為不同 feed 有不同過濾需求 | `JSONB NOT NULL DEFAULT '{}'` | 加 COMMENT 說明 JSON 結構 | feed collection |
| 2 | 🟢 | 設計 | `consecutive_failures INT` + `last_error TEXT` + `disabled_reason TEXT` — 故障追蹤設計完整 ✓ | — | 無需修改 | — |

---

### collected_data

**用途**: RSS 收集到的文章，經過 relevance 評分後進入 curated/ignored 狀態。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🔴 | 約束 | `source_url TEXT NOT NULL` 但 `original_content TEXT` 允許 NULL — 對 RSS 收集的文章，原文應該是必要的。如果抓不到原文應記錄為空字串而非 NULL | `original_content TEXT` (nullable) | 改為 `TEXT NOT NULL DEFAULT ''` 或加 COMMENT 說明何時為 NULL（例如：僅存標題的來源） | entry store |
| 2 | 🟡 | 命名 | `source_name` 語意與 `feeds.name` 重複 — collected_data 已有 `feed_id` FK，`source_name` 是反正規化冗餘 | 同時存 feed_id 和 source_name | 如果是刻意冗餘（feed 被刪後仍需知道來源名稱），加 COMMENT 說明。否則移除 `source_name`，改為 JOIN `feeds` | entry query, MCP display |
| 3 | 🟡 | 索引 | `url_hash` 有 UNIQUE partial index (`WHERE url_hash != ''`)，但 `url_hash` 的 DEFAULT 是空字串。新增 collected_data 時如果忘記計算 hash 就會插入 `url_hash = ''`，繞過 dedup | `url_hash TEXT NOT NULL DEFAULT ''` | 考慮改為 `url_hash TEXT` (nullable)，UNIQUE index 不用 WHERE 條件（NULL 自然不衝突），或在 Go 層確保永遠填入 hash | 資料去重 |
| 4 | 🟢 | 型別 | `relevance_score REAL` — REAL (float4) 對 0-1 的分數足夠精確 ✓ | — | 無需修改 | — |

---

### tracking_topics

**用途**: 自動化主題追蹤配置（用於 content collection pipeline）。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 命名 | 表名 `tracking_topics` — 但 Go 套件名是 `monitor`，API 路徑可能也不一致 | — | 確認 API 路徑是否也叫 monitor。名稱不一致會造成混淆 | monitor 套件 |

---

### flow_runs

**用途**: AI pipeline flow 的執行紀錄，含重試邏輯和狀態機。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | `idx_flow_runs_dedup` partial index 防止重複 pending/running 執行 — 良好設計 ✓ | — | 無需修改 | — |
| 2 | 🟢 | 約束 | `attempt INT NOT NULL DEFAULT 0` + `max_attempts INT NOT NULL DEFAULT 3` — 重試邏輯合理 ✓ | — | 無需修改 | — |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `RetryableFlowRuns` | 🟢 正確性 | 正確檢查 `attempt < max_attempts` 和 age-based stale detection ✓ | 無需修改 |
| 2 | `DeleteOldCompletedRuns` | 🟢 效能 | 有 cutoff date 和 LIMIT ✓ | 無需修改 |

---

### goals

**用途**: OKR 風格的目標追蹤，與 Notion 雙向同步。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | 表結構簡潔，enum 狀態機清晰 ✓ | — | 無需修改 | — |
| 2 | 🟢 | 索引 | `idx_goals_lower_title` 支援 case-insensitive 查詢 ✓ | — | 無需修改 | — |

---

### tasks

**用途**: Notion 同步的任務管理，含 recurring task 系統和 My Day 功能。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟡 | 約束 | `energy` 和 `priority` 使用 `TEXT CHECK (IN ('', 'High', 'Medium', 'Low'))` — 空字串代表「未設定」不慣用，且值用大寫開頭（與 Go 的 string constant 慣例不一致） | `energy TEXT NOT NULL DEFAULT ''` | 改為 lowercase（'high', 'medium', 'low'）並保持空字串慣例（或改 nullable）。這是 Notion 同步的產物，改動需同步更新 Notion 欄位映射 | task CRUD, Notion sync |
| 2 | 🟡 | 約束 | `recur_unit TEXT CHECK (IN ('', 'Day(s)', 'Week(s)', 'Month(s)', 'Year(s)'))` — 括號在值中是 Notion 的顯示格式，不應作為資料庫的 canonical 值 | 含括號的 enum 值 | 如果這些值直接從 Notion API 來，可以在 Go 層做映射（`Day(s)` → `day`），DB 存正規化的值。但改動影響 Notion sync 邏輯，ROI 需評估 | recurring task system |
| 3 | 🟢 | 設計 | `recur_interval INT` nullable — NULL 代表非 recurring，合理 ✓ | — | 無需修改 | — |
| 4 | 🟢 | 索引 | 4 個 partial index 設計精準，覆蓋主要 query pattern ✓ | — | 無需修改 | — |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `UpsertTaskByNotionPageID` | 🟢 正確性 | 複雜的 CASE 邏輯處理 recurring task due date 保護 — 正確防止 sync 覆蓋 cron 的 due date advance ✓ | 有良好的 SQL 註解 |
| 2 | `SearchTasks` | 🟡 效能 | `ILIKE '%' \|\| query \|\| '%'` — 前後模糊匹配無法使用 trigram 或 full-text 索引 | 資料量小可接受。若任務增多考慮加 FTS search_vector |
| 3 | `PendingTasksByTitle` | 🟡 安全 | `ILIKE '%' \|\| @search_title \|\| '%'` — sqlc 參數化安全 ✓，但 ILIKE 的 `%` 和 `_` 是 pattern 字元。若使用者輸入含這些字元，行為可能非預期 | 在 Go 層 escape `%` 和 `_` 字元 |
| 4 | `UpdateTask` | 🟢 設計 | 使用 `COALESCE(sqlc.narg(...), column)` 實現 sparse update — 正確 pattern ✓ | 無需修改 |

---

### activity_events

**用途**: 統一的活動事件日誌，記錄來自 GitHub、Notion、手動等來源的開發活動。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟡 | 型別 | PK 使用 `BIGSERIAL` 而非 UUID — 與其他所有表不一致。其他表全用 UUID | `BIGSERIAL PRIMARY KEY` | 此表作為 append-only log 使用 BIGSERIAL 合理（高頻寫入、不需分散式 ID），但與專案慣例不一致。保持現狀，加 COMMENT 說明選擇原因 | activity query, event_tags junction |
| 2 | 🟡 | 約束 | `event_type TEXT NOT NULL` 和 `source TEXT NOT NULL` — 無 CHECK 約束，允許任意字串。已知值域包括 `task_completed`、`task_status_change`、`commit` 等 | 無 CHECK | 考慮加 CHECK 或至少加 COMMENT 列舉已知值。但因為 event_type 可能隨新來源增加，不加 CHECK 可能是刻意的 | event 相關 query |
| 3 | 🟢 | 索引 | `idx_activity_events_dedup` UNIQUE partial index 正確處理 dedup ✓ | — | 無需修改 | — |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `EventsByTimeRange` | 🟢 效能 | 硬上限 5000 rows ✓ | 無需修改 |
| 2 | `CountEventsBySourcePrefix` | 🟡 效能 | `source_id LIKE @prefix \|\| '%'` — 前綴匹配可利用 B-tree 索引但 source_id 無索引 | 加 `CREATE INDEX idx_activity_events_source_id ON activity_events (source_id) WHERE source_id IS NOT NULL` |
| 3 | `CompletionEventsByProjectSince` | 🟢 正確性 | 使用 `DISTINCT ON (title, timestamp::date)` 正確去重 ✓ | 無需修改 |

---

### obsidian_notes

**用途**: Obsidian vault 的筆記同步，含全文搜尋和 embedding 語意搜尋。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🔴 | 語意 | `status TEXT CHECK (IN ('seed', 'evergreen', 'stub', 'archived'))` — 這與 content 的 `content_status` enum 語意完全不同。'seed'/'evergreen'/'stub' 是 Zettelkasten 筆記成熟度概念，但欄位名 `status` 容易與 content 的生命週期 status 混淆 | 允許 NULL | 考慮改名為 `maturity` 以區分。加 COMMENT 解釋這是 Zettelkasten maturity level，非生命週期狀態 | note search, archive |
| 2 | 🟡 | 型別 | PK 使用 `BIGSERIAL` — 與 `activity_events` 一致但與其他表的 UUID 不一致。作為 append-heavy 表合理 | `BIGSERIAL PRIMARY KEY` | 保持現狀，理由同 activity_events | note_tags, note_links junction |
| 3 | 🟡 | 約束 | `tags JSONB` — 存放 raw tags 陣列，但也有正規化的 `obsidian_note_tags` junction table。兩者功能重疊 | 同時有 JSONB tags 和正規化 tags | JSONB tags 是原始 frontmatter 數據，junction table 是正規化後的結果。加 COMMENT 說明：`'Raw frontmatter tags array. Canonical mapping is in obsidian_note_tags via tag resolution.'` | tag system |
| 4 | 🟢 | 設計 | `content_hash TEXT` — 用於變更偵測，避免無意義的更新。良好設計 ✓ | — | 無需修改 | — |
| 5 | 🟢 | 欄位 | `leetcode_id INT`、`difficulty TEXT`、`book TEXT`、`chapter TEXT`、`notion_task_id TEXT` — 這些是 frontmatter metadata，不是所有筆記都有 | 全部 nullable | 設計合理：nullable 欄位代表「不適用」。但數量偏多，若未來增加更多 frontmatter 欄位，考慮用 JSONB `frontmatter` 欄位統一存放 | note upsert |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `SearchNotesByFilters` | 🟢 正確性 | 正確使用 `sqlc.narg()` 處理 optional filters ✓ | 無需修改 |
| 2 | `BulkUpsertNoteLinks` | 🟢 效能 | 使用 `unnest` 批量 upsert — 優秀 pattern ✓ | 無需修改 |

---

### tags

**用途**: 正規化的 canonical tag 註冊表，支援階層結構（parent_id 自引用）。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | `parent_id` 自引用 FK with ON DELETE SET NULL — 合理，父 tag 刪除不級聯 ✓ | — | 無需修改 | — |
| 2 | 🟢 | 索引 | `idx_tags_parent` 索引 parent_id ✓ | — | 無需修改 | — |

---

### tag_aliases

**用途**: 將 raw tag（Obsidian frontmatter 原始值）映射到 canonical tag。含 4 步解析邏輯。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | `match_method` CHECK 含 'rejected' 狀態 — 完整覆蓋解析流程 ✓ | — | 無需修改 | — |
| 2 | 🟢 | 索引 | `idx_tag_aliases_lower_raw_tag` 支援 case-insensitive 查詢 ✓ | — | 無需修改 | — |

---

### obsidian_note_tags

**用途**: obsidian_notes ↔ tags 多對多關聯。

**Schema 問題**: 無。設計正確。

---

### activity_event_tags

**用途**: activity_events ↔ tags 多對多關聯。

**Schema 問題**: 無。設計正確。

---

### project_aliases

**用途**: 專案名稱別名映射（如 GitHub repo name → canonical project name）。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | `canonical_name TEXT` 欄位 — 同時有 `project_id UUID FK` 和 `canonical_name TEXT`。`project_id` 可能為 NULL（alias 先建立，project 後建立的情況） | 兩者共存 | 合理設計。加 COMMENT 說明：`'project_id may be NULL when alias is registered before the project exists'` | project resolution |

---

### notion_sources

**用途**: Notion database 同步設定，每個 database 有一個 role（projects、tasks、books、goals）。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | `idx_notion_sources_role` UNIQUE partial index 確保每個 role 只有一個 source — 精確設計 ✓ | — | 無需修改 | — |
| 2 | 🟢 | 型別 | `property_map JSONB` — 用於映射 Notion 的 property 到本地欄位，JSONB 合理 | — | 加 COMMENT 說明 JSON 結構 | Notion sync |

---

### note_links

**用途**: Obsidian 筆記間的 wikilink 邊，構建知識圖譜。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟡 | 完整性 | `target_path TEXT NOT NULL` — 指向的路徑可能不存在於 `obsidian_notes.file_path`（筆記尚未同步、或連結到不存在的筆記）。無 FK | TEXT 欄位 | 這是刻意設計（wikilink 可指向不存在的筆記），但應加 COMMENT 說明 | knowledge graph |
| 2 | 🟢 | 索引 | `idx_note_links_dedup` UNIQUE(source_note_id, target_path) 防重複 ✓ | — | 無需修改 | — |

---

### session_notes

**用途**: 跨環境的 context bridge — 儲存每日計劃、反思、metrics、insights。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟡 | 設計 | `metadata JSONB` 被用來存放 insight 的結構化欄位（status、category、project）— 這些對 insight 類型是「必要欄位」但對其他類型是不需要的。用 JSONB 存放必要欄位意味著 DB 無法強制約束 | `metadata JSONB` nullable | 對於 insight 類型，status/category/project 是查詢條件且有 partial index。但因為 session_notes 是多態表（5 種 note_type），用 JSONB 存放 type-specific metadata 是合理的妥協 | insight queries |
| 2 | 🟢 | 索引 | `idx_session_notes_insight_status` — 使用 JSONB 路徑的 partial index，正確 ✓ | — | 無需修改 | — |

**相關 Queries 問題**:

| # | Query 名稱 | 問題類型 | 描述 | 建議 |
|---|-----------|----------|------|------|
| 1 | `InsightsByStatus` | 🟢 正確性 | 正確處理 backward compatibility（NULL/empty status treated as 'unverified'）✓ | 無需修改 |
| 2 | `DeleteOldNotes` | 🟢 設計 | 分層刪除策略（短期: plan/reflection、長期: metrics/insights）✓ | 無需修改 |

---

### tool_call_logs

**用途**: MCP 工具呼叫的遙測記錄。

**Schema 問題**: 無。設計良好，COMMENT 完整 ✓。

---

### reconcile_runs

**用途**: 每週 Obsidian↔Notion 調和的歷史記錄。

**Schema 問題**: 無。設計良好，COMMENT 完整 ✓。

---

### fsrs_cards

**用途**: FSRS 間隔重複學習卡片狀態。

**Schema 問題**:

| # | 嚴重度 | 類別 | 問題描述 | 當前狀態 | 建議改法 | 影響範圍 |
|---|--------|------|----------|----------|----------|----------|
| 1 | 🟢 | 設計 | `COALESCE(tag, '')` unique index 正確處理 NULL 唯一性 — 優秀 pattern ✓ | — | 無需修改 | — |
| 2 | 🟢 | COMMENT | 完整的 COMMENT 覆蓋所有欄位 ✓ | — | 無需修改 | — |

---

### fsrs_review_logs

**用途**: FSRS 學習記錄（append-only）。

**Schema 問題**: 無。設計良好，COMMENT 完整 ✓。

---

### task_skip_log

**用途**: Recurring task 的跳過記錄。

**Schema 問題**: 無。設計良好，COMMENT 完整 ✓，UNIQUE 約束正確 ✓。

---

## Cross-Table Issues

### 1. 🟡 Tag 系統的雙軌制

**問題**: 系統中存在兩套平行的 tag 機制：

- **正規化 tag 系統**: `tags` → `tag_aliases` → `obsidian_note_tags` / `activity_event_tags` — 用於 Obsidian notes 和 activity events
- **TEXT[] 陣列**: `contents.tags` — 用於 content 的 tags

兩套系統在 learning analytics（`learningTopTags`、`ContentTagsByTypeAndProject`）中需要 UNION 合併，增加了查詢複雜度和維護成本。

**影響**: stats 的 `learningTopTags()` 做了 `UNION ALL` 合併兩個來源的 tags；`ContentRichTagEntries` 回傳 `TEXT[]` tags 需在 Go 層做 unnest 和計數。

**建議**: 長期建立 `content_tags` junction table（類似 `obsidian_note_tags`），將 `contents.tags` 遷移過去。短期記錄為技術債。

### 2. 🟡 PK 型別不一致

**問題**: 大多數表使用 `UUID` 作為 PK，但有 3 張表使用 `BIGSERIAL`：

| 表 | PK 型別 | 理由 |
|----|---------|------|
| activity_events | BIGSERIAL | 高頻 append-only log |
| obsidian_notes | BIGSERIAL | 大量筆記，sequential insert |
| session_notes | BIGSERIAL | Append-only session log |
| note_links | BIGSERIAL | Graph edge, high volume |
| fsrs_cards | BIGSERIAL | High-frequency updates |
| fsrs_review_logs | BIGSERIAL | Append-only log |
| reconcile_runs | BIGINT GENERATED ALWAYS AS IDENTITY | Append-only log |

**影響**: Junction tables 需要正確的 FK 型別（`BIGINT` 而非 `UUID`），已正確處理 ✓。

**建議**: 這是合理的設計選擇。BIGSERIAL 用於高頻寫入的 log 類型表，UUID 用於需要分散式 ID 的 entity 類型表。加 COMMENT 說明即可。

### 3. 🟡 命名慣例不一致

| 模式 | 使用情況 | 說明 |
|------|---------|------|
| `created_at` / `updated_at` | 所有表 ✓ | 一致 |
| Boolean 欄位 | `enabled` (feeds, tracking_topics, notion_sources), `featured` (projects), `public` (projects), `my_day` (tasks), `confirmed` (tag_aliases) | 未使用 `is_` / `has_` 前綴，但 Go 中 bool 欄位通常不需要前綴。`public` 是唯一有問題的（PostgreSQL 保留字） |
| `notion_page_id` | projects, goals, tasks | 一致 ✓ |
| 表名 | 全部 snake_case 複數 ✓ | 除了 `collected_data`（不可數名詞，單複數相同）和 junction tables（`content_topics` 等） |

### 4. 🟢 FK 完整性

所有跨表關聯都有明確的 FK 定義 ✓。ON DELETE 行為設計合理：
- Junction tables: CASCADE
- Optional 關聯: SET NULL
- 核心關聯: CASCADE

---

## N+1 and Performance Issues

### 🔴 Critical: Content Search 系列方法不填充 Topics

**位置**: `internal/content/store.go`

**問題**: 以下 5 個方法回傳 `[]Content` 但不填充 `Topics` 欄位：

| 方法 | 行數 | 說明 |
|------|------|------|
| `Search()` | ~265-299 | Full-text search (AND) |
| `SearchOR()` | ~303-328 | Full-text search (OR) |
| `InternalSearch()` | ~332-360 | Internal search (no visibility) |
| `InternalSearchOR()` | ~365-388 | Internal OR search |
| `ContentsByTopicID()` | ~233-261 | By topic |

**對比**: `Contents()` 方法（~109-157）正確使用 batch loading：
```go
topicMap, err := s.topicsForContents(ctx, ids)
for i := range contents {
    contents[i].Topics = topicMap[contents[i].ID]
}
```

**影響**: 如果任何呼叫端（handler、MCP tool）需要 search 結果的 topics，它必須個別查詢每個 content 的 topics，產生 N+1。目前 handler 似乎不需要 search 結果的 topics（API response 不含），但 MCP 的 `search_knowledge` 可能期望 topics。

**修復建議**: 在所有 5 個方法中加入 `topicsForContents()` batch call，與 `Contents()` 保持一致。即使目前不需要，統一行為可防止未來的 N+1 bug。

### 🟡 SearchOR Count 不正確

**位置**: `internal/content/store.go:~327`

**問題**: `SearchOR()` 回傳 `len(contents)` 作為 total count，而非查詢資料庫的實際總數。當結果超過一頁時，分頁的 total 計算不正確。

**修復建議**: 新增 `SearchContentsORCount` sqlc query，或使用 `COUNT(*) OVER()` window function。

### 🟡 CountEventsBySourcePrefix 缺少索引

**位置**: `internal/activity/query.sql`

**問題**: `source_id LIKE @prefix || '%'` — 前綴匹配可利用 B-tree 索引，但 `source_id` 欄位無索引。

**修復建議**:
```sql
CREATE INDEX idx_activity_events_source_id ON activity_events (source_id) WHERE source_id IS NOT NULL;
```

### 🟡 PublishedContentsByDateRange 無 LIMIT

**位置**: `internal/content/query.sql:180-187`

**問題**: `SELECT ... FROM contents WHERE ... AND published_at >= $1 AND published_at < $2 ORDER BY published_at DESC` — 無 LIMIT 約束。

**修復建議**: 加 LIMIT 參數或在 Go 層設定硬上限（類似 EventsByTimeRange 的 5000）。

### 🟢 Stats 的 Raw SQL

**位置**: `internal/stats/store.go`

**評估**: Stats 使用 raw SQL 而非 sqlc 是合理的 — 跨表聚合查詢無法由 sqlc 表達。所有查詢使用 `$N` 參數化，無 SQL injection 風險 ✓。使用 `errgroup` 並行執行 10 個獨立查詢是正確的效能最佳化 ✓。

---

## Migration Cleanup Plan

### 3.1 Migration 歷史分析

目前只有 **1 個 monolithic migration** (`001_initial.up.sql`)，739 行。這代表：

- ✅ 無歷史技術債（沒有來回修改、沒有 ALTER 鏈）
- ✅ Schema 的「最終態」就是 `001_initial.up.sql` 本身
- ⚠️ 但這也意味著無法部分 rollback — 如果 down migration 執行，會刪除所有表
- ⚠️ 隨著系統演進，新的 migration 會逐步累積在 `001` 之上

### 3.2 理想化 Schema vs 現狀差異

由於只有一個 migration，「理想化 schema」與現狀差異不大。以下是建議的改進：

| 改動 | 類型 | 描述 | Migration 策略 |
|------|------|------|----------------|
| `obsidian_notes.status` → `maturity` | 改名 | 避免與 content status 混淆 | `ALTER TABLE obsidian_notes RENAME COLUMN status TO maturity;` |
| `projects.public` → `is_public` | 改名 | 避免 PostgreSQL 保留字 | `ALTER TABLE projects RENAME COLUMN public TO is_public;` + 更新所有 queries |
| `contents` 加 series CHECK | 新約束 | 確保 series_id 和 series_order 一致 | `ALTER TABLE contents ADD CONSTRAINT chk_series CHECK (...)` |
| `collected_data.original_content` | 加 DEFAULT | NOT NULL DEFAULT '' 或加 COMMENT | 取決於業務決策 |
| 各 JSONB 欄位加 COMMENT | 文檔 | 說明 JSON 結構 | `COMMENT ON COLUMN ...` |
| `contents.reading_time` | 加 COMMENT | 說明單位 | `COMMENT ON COLUMN contents.reading_time IS '...'` |

### 3.3 建議的下一個 Migration

```sql
-- 002_schema_refinements.up.sql

-- 1. Rename obsidian_notes.status to maturity (Zettelkasten concept, not lifecycle)
ALTER TABLE obsidian_notes RENAME COLUMN status TO maturity;

-- 2. Rename projects.public to is_public (avoid PostgreSQL reserved word)
ALTER TABLE projects RENAME COLUMN public TO is_public;

-- 3. Add series consistency constraint
ALTER TABLE contents ADD CONSTRAINT chk_contents_series
    CHECK ((series_id IS NULL AND series_order IS NULL) OR
           (series_id IS NOT NULL AND series_order IS NOT NULL));

-- 4. Add missing index for source_id prefix queries
CREATE INDEX idx_activity_events_source_id
    ON activity_events (source_id)
    WHERE source_id IS NOT NULL;

-- 5. Documentation: COMMENT additions
COMMENT ON COLUMN contents.reading_time IS
    'Estimated reading time in minutes. Computed from body word count. Always >= 0.';

COMMENT ON COLUMN contents.ai_metadata IS
    'AI pipeline metadata (JSONB). Structure: {summary: string, keywords: string[], quality_score: float, review_notes: string}. Set by Genkit flows.';

COMMENT ON COLUMN contents.tags IS
    'Raw tag strings from Obsidian frontmatter or manual entry. Not normalized — for canonical tags use content_topics junction. Kept for backward compatibility and learning analytics unnest.';

COMMENT ON COLUMN obsidian_notes.maturity IS
    'Zettelkasten note maturity level: seed (new idea), stub (incomplete), evergreen (mature, reliable), archived (no longer relevant). NULL = not yet classified.';

COMMENT ON COLUMN obsidian_notes.tags IS
    'Raw frontmatter tags array (JSONB). Canonical mapping is in obsidian_note_tags via tag resolution pipeline. Kept as source-of-truth for raw values.';

COMMENT ON COLUMN feeds.filter_config IS
    'Feed-specific content filter rules (JSONB). Structure: {deny_paths: string[], deny_title_patterns: string[], deny_tags: string[]}. Empty {} means no filtering.';

COMMENT ON COLUMN notion_sources.property_map IS
    'Maps Notion database properties to local fields (JSONB). Structure: {notion_property_name: local_field_name, ...}. Empty {} means default mapping.';

COMMENT ON COLUMN note_links.target_path IS
    'Wikilink target file path. May reference notes not yet synced or non-existent files — this is expected for forward/broken links in the knowledge graph.';

COMMENT ON COLUMN project_aliases.canonical_name IS
    'Human-readable canonical project name. project_id may be NULL when alias is registered before the project entity exists.';

COMMENT ON COLUMN projects.is_public IS
    'Whether this project appears on the public portfolio page. Private projects are admin-only.';
```

```sql
-- 002_schema_refinements.down.sql

ALTER TABLE obsidian_notes RENAME COLUMN maturity TO status;
ALTER TABLE projects RENAME COLUMN is_public TO public;
ALTER TABLE contents DROP CONSTRAINT IF EXISTS chk_contents_series;
DROP INDEX IF EXISTS idx_activity_events_source_id;
-- COMMENTs don't need rollback (they're additive documentation)
```

---

## Appendix: Ideal Schema

如果今天從零開始，每張表的 DDL 應如下（僅列出與現狀有差異的表）：

### contents（理想態差異）

```sql
CREATE TABLE contents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          TEXT NOT NULL UNIQUE,
    title         TEXT NOT NULL,
    body          TEXT NOT NULL DEFAULT '',
    excerpt       TEXT NOT NULL DEFAULT '',
    type          content_type NOT NULL,
    status        content_status NOT NULL DEFAULT 'draft',
    tags          TEXT[] NOT NULL DEFAULT '{}',  -- 技術債：長期應遷移到 content_tags junction
    source        TEXT,
    source_type   source_type,
    series_id     TEXT,
    series_order  INT,
    review_level  review_level NOT NULL DEFAULT 'standard',
    ai_metadata   JSONB,
    reading_time_min INT NOT NULL DEFAULT 0,     -- 改名：明確單位
    cover_image   TEXT,
    is_public     BOOLEAN NOT NULL DEFAULT true,  -- 替代 visibility TEXT
    project_id    UUID REFERENCES projects(id) ON DELETE SET NULL,
    published_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    embedding     vector(768),
    search_vector TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(left(body, 10000), '')), 'C')
    ) STORED,
    CONSTRAINT chk_contents_series CHECK (
        (series_id IS NULL AND series_order IS NULL) OR
        (series_id IS NOT NULL AND series_order IS NOT NULL)
    )
);

COMMENT ON COLUMN contents.reading_time_min IS 'Estimated reading time in minutes.';
COMMENT ON COLUMN contents.ai_metadata IS 'AI pipeline metadata: {summary, keywords[], quality_score, review_notes}.';
COMMENT ON COLUMN contents.tags IS 'Raw tags. Canonical mapping via content_topics. Kept for analytics unnest.';
```

### projects（理想態差異）

```sql
CREATE TABLE projects (
    -- ... 所有現有欄位 ...
    is_public    BOOLEAN NOT NULL DEFAULT false,  -- 替代 public
    -- ... 其餘不變 ...
);

COMMENT ON COLUMN projects.is_public IS 'Whether visible on public portfolio.';
```

### obsidian_notes（理想態差異）

```sql
CREATE TABLE obsidian_notes (
    -- ... 所有現有欄位 ...
    maturity     TEXT DEFAULT 'seed'              -- 替代 status
                 CHECK (maturity IS NULL OR maturity IN ('seed', 'evergreen', 'stub', 'archived')),
    -- ... 其餘不變 ...
);

COMMENT ON COLUMN obsidian_notes.maturity IS 'Zettelkasten maturity: seed → stub → evergreen. archived = no longer relevant.';
COMMENT ON COLUMN obsidian_notes.tags IS 'Raw frontmatter JSONB. Canonical mapping in obsidian_note_tags.';
```

### collected_data（理想態差異）

```sql
CREATE TABLE collected_data (
    -- ... 所有現有欄位 ...
    original_content TEXT NOT NULL DEFAULT '',     -- 改為 NOT NULL
    -- ... 其餘不變 ...
);

COMMENT ON COLUMN collected_data.source_name IS 'Denormalized feed name. Preserved when feed_id FK target is deleted (ON DELETE SET NULL).';
```

---

## 總結

### 整體評價

koopa0.dev 的資料庫設計**品質良好**。作為一個單人專案，schema 展現了以下優點：

1. **索引策略精準** — partial indexes 大量使用，覆蓋實際 query pattern
2. **dedup 設計嚴謹** — UNIQUE partial indexes 用於防止重複（flow_runs、review_queue、activity_events、collected_data、note_links）
3. **FK 完整性佳** — 所有關聯都有 FK，ON DELETE 行為合理
4. **COMMENT 部分完整** — fsrs_cards、fsrs_review_logs、reconcile_runs、tool_call_logs、task_skip_log 有完整 COMMENT；其他表缺失
5. **sqlc 使用正確** — 參數化查詢、型別映射、emit_empty_slices 都配置正確
6. **安全性無虞** — 無 SQL injection 風險（包括 stats 的 raw SQL 也用參數化）

### 需要行動的項目

| 優先級 | 項目 | 預估工作量 |
|--------|------|-----------|
| 🔴 High | 修復 Content search 5 個方法的 topic batch loading | 2h（Go 層改動） |
| 🔴 High | 修復 SearchOR count 不正確的問題 | 30min |
| 🟡 Medium | 建立 `002_schema_refinements` migration（改名 + 約束 + COMMENT） | 2h（含 Go 層配合改動） |
| 🟡 Medium | 加 `idx_activity_events_source_id` 索引 | 5min |
| 🟡 Medium | Go 層 escape ILIKE pattern 字元 | 30min |
| 🟢 Low | 長期規劃 content tags 正規化遷移 | 記錄為技術債即可 |
| 🟢 Low | 各 JSONB 欄位加 COMMENT | 30min |
