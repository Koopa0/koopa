# Koopa Studio — Cowork System

> 4 個 Cowork Project 組成的虛擬工作室。跨 project 通訊透過 koopa0.dev MCP 的 `session_notes` 機制。

---

## 系統架構

```
┌─────────────────────────────────────────────────────────┐
│                   Claude Desktop (Cowork)                 │
│                                                           │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────┐  │
│  │ Studio HQ │  │ Content Studio│  │  Research Lab     │  │
│  │ (CEO)     │  │ (內容)        │  │  (研究)           │  │
│  └─────┬─────┘  └──────┬────────┘  └────────┬─────────┘  │
│        │               │                     │            │
│  ┌─────┴───────────────┴─────────────────────┴─────────┐ │
│  │              koopa0.dev MCP Server                    │ │
│  │         session_notes = message bus                   │ │
│  └──────────────────────┬────────────────────────────────┘│
│                         │                                 │
│  ┌──────────────────────┴────────────────────────────────┐│
│  │                  Learning Studio                       ││
│  │                  (學習教練)                             ││
│  └────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │  PostgreSQL          │
               │  session_notes table │
               └─────────────────────┘
```

## 各 Project 職責

| Project | 角色 | 做什麼 | 不做什麼 |
|---------|------|--------|----------|
| **Studio HQ** | CEO / 指揮中心 | 看全局、做決策、分配任務 | 不寫內容、不寫 code、不做研究 |
| **Content Studio** | 內容策略 + 編輯 | 選題、寫稿、潤稿、發佈管理 | 不做學習、不做營運決策 |
| **Research Lab** | 研究分析師 | 深度研究、結構化報告 | 不寫內容、不寫 code |
| **Learning** | 學習教練 | LeetCode coaching、FSRS 複習、知識建構 | 不做營運、不發佈內容 |

## Instructions 位置

| Project | 檔案 |
|---------|------|
| Studio HQ | `docs/Koopa-HQ.md` |
| Content Studio | `docs/Koopa-Content-Studio.md` |
| Research Lab | `docs/Koopa-Research-Lab.md` |
| Learning | `docs/Koopa-Learning.md` |

---

## 通訊協議

### 核心機制

所有跨 project 通訊透過 MCP 的 `save_session_note` / `session_notes` 完成。這是 Cowork 系統的 **IPC 協議**。

### note_type 定義（嚴格 enum）

後端 validation 只接受以下 7 種 `note_type`。任何其他值會被 **reject**。

| note_type | 用途 | 寫入者 | 讀取者 | 持久策略 |
|-----------|------|--------|--------|----------|
| `directive` | HQ 下達的跨部門指令 | HQ | Content Studio, Research Lab, Learning | 長期保留 |
| `report` | 各部門向 HQ 回報的 session 產出 | Content Studio, Research Lab, Learning | HQ | 長期保留 |
| `plan` | HQ 制定的每日/每週計劃 | HQ | Learning, Content Studio | 長期保留 |
| `context` | Session 結束時的上下文摘要 | 所有 | 同 project 下次 session | 短期保留 |
| `reflection` | Evening reflection / 回顧 | 所有 | HQ, 同 project | 短期保留 |
| `metrics` | 量化指標（任務完成數等） | HQ, Learning | HQ | 長期保留 |
| `insight` | 假說、觀察、pattern 辨識 | 所有 | HQ | 長期保留 |

**重要**：`ceo-directive` 和 `department-output` **不是合法的 note_type**，會被後端 reject。

### source 定義（嚴格 enum）

後端 validation 只接受以下 7 種 `source`。

| source | 代表 |
|--------|------|
| `hq` | Studio HQ project |
| `content-studio` | Content Studio project |
| `research-lab` | Research Lab project |
| `learning-studio` | Learning project |
| `claude-code` | Claude Code CLI（開發任務） |
| `claude` | Claude web / general |
| `manual` | Koopa 手動建立 |

### 通訊矩陣

```
            寫入 →   directive   report   plan   context   reflection   metrics   insight
寫入者 ↓
HQ                    ✅          ❌       ✅      ✅        ✅           ✅         ✅
Content Studio        ❌          ✅       ❌      ✅        ✅           ❌         ✅
Research Lab          ❌          ✅       ❌      ✅        ✅           ❌         ✅
Learning              ❌          ✅       ❌      ✅        ✅           ✅         ✅
Claude Code           ❌          ❌       ❌      ✅        ❌           ❌         ❌
```

```
            讀取 →   directive   report   plan   context   reflection   metrics   insight
讀取者 ↓
HQ                    ✅(自己的)   ✅       ✅      ✅        ✅           ✅         ✅
Content Studio        ✅          ❌       ✅      ✅(自己)   ❌           ❌         ❌
Research Lab          ✅          ❌       ❌      ✅(自己)   ❌           ❌         ❌
Learning              ❌          ❌       ✅      ✅(自己)   ❌           ❌         ❌
```

### Directive 格式（HQ → 部門）

```
save_session_note(
  note_type="directive",
  source="hq",
  content="""
  ## HQ Directive — [YYYY-MM-DD]
  **目標部門**: Content Studio | Research Lab | Learning | Claude Code
  **優先級**: P0 立即 | P1 今天 | P2 本週
  **指令**: [具體要做什麼]
  **背景**: [為什麼要做這個]
  **期望產出**: [交付什麼、什麼格式]
  """
)
```

### Report 格式（部門 → HQ）

```
save_session_note(
  note_type="report",
  source="content-studio",   # 或 "research-lab" 或 "learning-studio"
  content="""
  ## [部門名] Report — [YYYY-MM-DD]
  **工作內容**: [做了什麼]
  **產出**: [具體產出列表]
  **狀態**: [管道/專案狀態]
  **下次建議**: [下一步行動]
  """
)
```

---

## 排程配置

### Cloud Schedule（推薦，跑在 Anthropic 雲端）

| 任務 | 歸屬 | Cron | 說明 |
|------|------|------|------|
| Morning Briefing | HQ | `0 8 * * *` | `morning_context` → briefing → 寫 directive |
| Content Pipeline Check | Content Studio | `0 14 * * *` | 讀 directive → `list_content_queue` → RSS → 寫 report |
| 產業掃描 | Research Lab | `0 9 * * 1` | RSS + web search → 產業動態 → 寫 report |
| Weekly Review | HQ | `0 17 * * 5` | `weekly_summary` + 各部門 report → 週報 |

### 已知限制

- Cloud Schedule 最短間隔 1 小時
- 每次 run 是獨立 session（無跨 session memory，但透過 MCP 讀寫狀態）
- Desktop Schedule 必須桌面 app 開啟且聚焦 Cowork view（[已知 bug #36131](https://github.com/anthropics/claude-code/issues/36131)）

---

## Session 生命週期

### 每個 Project 的 Session 開始

```
Step 0: 讀 directive（如果是 HQ 以外的 project）
        session_notes(note_type="directive", days=3)
        
Step 1: 讀自己上次的 context
        session_notes(note_type="context", days=3)
        
Step 2: 執行 project 特定的啟動流程（見各 project instructions）
```

### 每個 Project 的 Session 結束

```
Step 1: 寫 report（回報給 HQ）
        save_session_note(note_type="report", source="[project-source]", content="...")
        
Step 2: 寫 context（留給自己下次 session）
        save_session_note(note_type="context", source="[project-source]", content="...")
```

---

## 工具鏈整合

### IDE 環境（Zed 唯一）

```
Zed IDE
├── Edit Prediction: GitHub Copilot（inline completion）
├── Agent Panel
│   ├── Claude（AI assistant）
│   ├── koopa0.dev MCP（知識引擎）
│   ├── Augment Context Engine MCP（codebase context）
│   └── GitHub Copilot ACP Agent
├── Terminal
│   └── Claude Code CLI
│       ├── go-spec agents（comprehend, planner, reviewer...）
│       ├── koopa0.dev MCP
│       └── Auggie MCP
└── Chrome DevTools MCP（前端 debug 用）
```

### 分工原則

| 工具 | 負責 | 不負責 |
|------|------|--------|
| **Claude Code** | 深度 code gen, review, refactor, MCP 互動 | Git workflow 自動化 |
| **GitHub Copilot Coding Agent** | Issue → branch → PR, agentic review | 深度架構決策 |
| **Copilot (Zed inline)** | 日常 code completion | 複雜邏輯 generation |
| **Auggie MCP** | Codebase semantic search, context | Code generation |
| **Claude Chrome Extension** | 前端 debug（console, network, DOM） | 後端 |

---

## 協議穩固化 — 判斷、優化、驗證

### 如何判斷協議是否健康

| 指標 | 健康 | 不健康 | 檢查方式 |
|------|------|--------|----------|
| Directive 被讀取 | 部門 report 引用了 directive 內容 | Report 與 directive 無關 | 比對 directive 和後續 report |
| Report 被 HQ 消費 | HQ briefing 引用了 report 摘要 | Report 石沉大海 | 檢查 HQ morning briefing 是否拉 report |
| note_type 使用正確 | 100% 命中 enum | 出現 reject 或誤用 | 查 DB 的 note_type 分布 |
| Source 標示正確 | 每個 note 可追溯到來源 project | 混用 source 或用 `claude` 代替 | 查 DB 的 source 分布 |
| 回應延遲 | < 24 小時 | 指令發出 3 天無回應 | `directive 日期` vs `report 日期` 的 delta |

### 如何優化

**短期（不改 code）：**

1. **統一 Instructions 裡的 note_type** — 修正 Content Studio 的 `"ceo-directive"` → `"directive"`，`"department-output"` → `"report"`
2. **每個 Project 明確列出讀/寫的 note_type + source** — 不靠記憶，寫在 instructions 裡
3. **Directive 加結構化 metadata** — 目標部門、優先級用固定格式，方便 filter

**中期（需改 code，排定下週實施）：**

見下方「IPC 協議補強計劃」。

### 如何驗證（定期健檢）

```sql
-- 1. note_type 分布（是否有異常值）
SELECT note_type, count(*) FROM session_notes GROUP BY note_type ORDER BY count DESC;

-- 2. source 分布（每個 project 是否都在寫）
SELECT source, note_type, count(*) FROM session_notes
WHERE note_date >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY source, note_type ORDER BY source, note_type;

-- 3. 未回應的 directive（超過 48 小時無對應 report）
SELECT d.id, d.note_date, d.content
FROM session_notes d
WHERE d.note_type = 'directive'
  AND d.note_date >= CURRENT_DATE - INTERVAL '7 days'
  AND NOT EXISTS (
    SELECT 1 FROM session_notes r
    WHERE r.note_type = 'report'
      AND r.note_date >= d.note_date
      AND r.note_date <= d.note_date + INTERVAL '2 days'
  );

-- 4. 最近 7 天各 project 活躍度
SELECT source, count(*), max(note_date) as last_active
FROM session_notes
WHERE note_date >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY source;
```

---

## IPC 協議補強計劃

> 研究日期：2026-04-02。排定下週實施。

### 為什麼不是微服務問題

這個系統**不是分散式系統**。4 個 Cowork project 透過同一個 MCP server 寫入同一個 PostgreSQL — 沒有多 DB、沒有網路分區、不會同時執行。CAP 三選二、2PC、saga pattern 全部不適用。

真正的問題是 **contract enforcement + delivery guarantee**，是 message queue 設計問題。

### 現狀分析（from codebase audit）

**Schema（DDL）**：`migrations/001_initial.up.sql:668-682`
- 7 note_type + 7 source 有 CHECK constraint（DB 層強制）
- `metadata` JSONB nullable，無 DB 層 schema 驗證
- 無 unique constraint — append-only，允許重複

**Application 層 validation（`internal/mcp/write.go:786-853`）**：

| note_type | 必填 metadata | 可選 | 問題 |
|-----------|--------------|------|------|
| `insight` | `hypothesis`, `invalidation_condition` | `status`(default unverified), `category`, `project`, evidence arrays | ✅ 最嚴格 |
| `plan` | `reasoning`, `committed_task_ids` or `committed_items` | `buffer_task_ids` | ✅ 有要求 |
| `metrics` | `tasks_planned`, `tasks_completed`, `adjustments` | — | ✅ 有要求 |
| **`directive`** | **無** | `from`, `to`, `priority` | ❌ **完全自由** |
| **`report`** | **無** | `from`, `to` | ❌ **完全自由** |
| `context` | 無 | — | ⚠️ 可接受（內部用） |
| `reflection` | 無 | — | ⚠️ 可接受（內部用） |

**索引**：3 個 — `(note_date DESC)`, `(note_date, note_type)`, partial functional `(metadata->>'status') WHERE note_type='insight'`。**無 JSONB GIN index**。

**Retention**：每日 3:45 AM 清理。短期 30 天（plan, reflection, context）、長期 365 天（metrics, insight, directive, report）。

### 四個問題 → 四個解法

| # | 問題 | 解法 | 機制 | 影響範圍 |
|---|------|------|------|----------|
| 1 | Directive metadata 無 schema | **強制 `target` + `priority`** | Go validation + DB CHECK constraint | `write.go` + migration |
| 2 | 無 delivery confirmation | **加 `consumed_at` + `consumed_by` 欄位** | `ALTER TABLE ADD COLUMN` | migration + query.sql |
| 3 | Report 無因果鏈 | **強制 `in_response_to` metadata** | Go validation + DB CHECK | `write.go` + migration |
| 4 | 無 targeting query | **expression index on `metadata->>'target'`** | `CREATE INDEX` | migration only |

### 實施方案

#### Migration（一個 migration file）

```sql
-- 1. Delivery confirmation columns
ALTER TABLE session_notes ADD COLUMN consumed_at TIMESTAMPTZ;
ALTER TABLE session_notes ADD COLUMN consumed_by TEXT;

-- 2. Directive schema enforcement (DB safety net)
ALTER TABLE session_notes ADD CONSTRAINT chk_directive_metadata
  CHECK (note_type != 'directive' OR (
    metadata IS NOT NULL
    AND metadata ? 'target'
    AND metadata ? 'priority'
    AND metadata->>'target' IN ('content-studio', 'research-lab', 'learning-studio', 'claude-code')
    AND metadata->>'priority' IN ('p0', 'p1', 'p2')
  ));

-- 3. Report causal link enforcement
ALTER TABLE session_notes ADD CONSTRAINT chk_report_metadata
  CHECK (note_type != 'report' OR (
    metadata IS NOT NULL
    AND metadata ? 'in_response_to'
  ));

-- 4. Expression index for targeting query
CREATE INDEX idx_session_notes_directive_target
  ON session_notes ((metadata->>'target'))
  WHERE note_type = 'directive';

-- 5. Index for unconsumed directives query
CREATE INDEX idx_session_notes_unconsumed
  ON session_notes (note_type, consumed_at)
  WHERE consumed_at IS NULL;
```

#### Go validation 補強（`internal/mcp/write.go`）

```go
// validateSessionNoteMetadata — add cases for directive and report

case "directive":
    target, _ := metadata["target"].(string)
    priority, _ := metadata["priority"].(string)
    if target == "" {
        return fmt.Errorf("directive metadata requires 'target' (content-studio|research-lab|learning-studio|claude-code)")
    }
    validTargets := map[string]bool{"content-studio": true, "research-lab": true, "learning-studio": true, "claude-code": true}
    if !validTargets[target] {
        return fmt.Errorf("invalid directive target %q", target)
    }
    if priority == "" {
        return fmt.Errorf("directive metadata requires 'priority' (p0|p1|p2)")
    }

case "report":
    if metadata["in_response_to"] == nil {
        return fmt.Errorf("report metadata requires 'in_response_to' (directive session_note ID)")
    }
```

#### Consumption query（`internal/session/query.sql`）

```sql
-- name: ConsumeDirective :one
UPDATE session_notes
SET consumed_at = now(), consumed_by = @consumer
WHERE id = @id
  AND consumed_at IS NULL
RETURNING id, note_date, note_type, source, content, metadata, consumed_at, consumed_by, created_at;

-- name: UnconsumedDirectives :many
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_type = 'directive'
  AND consumed_at IS NULL
  AND (sqlc.narg('target')::text IS NULL OR metadata->>'target' = sqlc.narg('target'))
ORDER BY created_at ASC;
```

#### MCP tool 更新

| Tool | 改動 |
|------|------|
| `save_session_note` | directive/report 加必填 metadata 欄位 |
| `session_notes` | directive query 加 `target` filter；返回 `consumed_at` |
| **新增** `consume_directive` | 部門標記 directive 為已讀 | 

#### Instructions 更新

所有 Cowork project 的 session 啟動流程改為：

```
Step 0: 讀取未消費的 directive
        session_notes(note_type="directive", target="content-studio", unconsumed=true)
        
Step 0.5: 標記為已讀
        consume_directive(id=<directive_id>)
```

### 設計決策記錄

| 決策 | 選擇 | 排除 | 原因 |
|------|------|------|------|
| Delivery confirmation | `consumed_at` + `consumed_by` columns | Outbox pattern relay | 單一 DB，不需要 relay process |
| Schema validation | DB CHECK + Go validation 雙層 | pg_jsonschema extension | 不加部署依賴；CHECK 做 safety net，Go 做 UX |
| Targeting | JSONB metadata `target` field + expression index | 新增 top-level `target` column | 不改 table schema，用 JSONB + index 達成相同效果 |
| Causal linking | `in_response_to` in report metadata | `parent_id` column | 同上，JSONB 裡做 |
| Concurrent safety | 暫不需要 SKIP LOCKED | FOR UPDATE SKIP LOCKED | 目前不會同時執行，但 migration 加了 `consumed_at` 後未來可防禦性加入 |
| CloudEvents spec | 不採用 | 採用完整 spec | 過度正式化，但借用 envelope 概念（routing 和 payload 分離） |
| LISTEN/NOTIFY | 不採用 | — | Agent 是異步 session，不是長駐 listener |
| GIN index on metadata | 不加 | 全 metadata GIN index | 只需要 `target` 的 expression index，GIN 太重 |

### 影響評估

| 維度 | 影響 |
|------|------|
| **Migration** | 1 個 migration file，加 2 column + 2 CHECK + 2 index |
| **Go 改動** | `write.go`（validation）+ `query.sql`（新 query）+ `search.go`（filter）+ `server.go`（新 tool） |
| **Instructions** | 4 個 Cowork project instructions 更新 session 啟動流程 |
| **Breaking change** | ⚠️ 現有 directive/report 沒有 metadata → 需要 data migration 或 CHECK constraint 只對新資料生效 |
| **向後相容** | CHECK constraint 用 `note_type != 'directive' OR (...)` 格式 — 不影響其他 note_type |

### 向後相容策略

現有的 directive/report 沒有 metadata。兩個選擇：

**選項 A（推薦）**：CHECK constraint 只對新資料生效 — 加 `AND created_at > '2026-04-07'` 條件
```sql
ALTER TABLE session_notes ADD CONSTRAINT chk_directive_metadata
  CHECK (note_type != 'directive' OR created_at <= '2026-04-07' OR (
    metadata IS NOT NULL AND metadata ? 'target' AND metadata ? 'priority'
  ));
```

**選項 B**：data migration — 為現有 directive 補上 metadata（但現有 directive 的 target 在 content 文字裡，需要解析）

### 研究來源

- [Transactional Outbox Pattern](https://microservices.io/patterns/data/transactional-outbox.html)
- [PostgreSQL SKIP LOCKED as Message Queue](https://www.inferable.ai/blog/posts/postgres-skip-locked)
- [Event Sourcing with PostgreSQL JSONB](https://softwaremill.com/implementing-event-sourcing-using-a-relational-database/)
- [JSONB Schema Validation with CHECK constraints](https://www.enterprisedb.com/blog/validating-shape-your-json-data)
- [pg_jsonschema (Supabase)](https://supabase.com/docs/guides/database/extensions/pg_jsonschema)
- [CloudEvents Spec](https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md)
- [PostgreSQL JSONB Indexing Best Practices (AWS)](https://aws.amazon.com/blogs/database/postgresql-as-a-json-database-advanced-patterns-and-best-practices/)

---

## 已知問題

| 問題 | 嚴重度 | 狀態 | 解法 |
|------|--------|------|------|
| Content Studio 用 `"ceo-directive"` 讀 directive | **P0** | ✅ 已修正 (2026-04-02) | 改為 `"directive"` |
| Content Studio 用 `"department-output"` 寫 report | **P0** | ✅ 已修正 (2026-04-02) | 改為 `"report"` |
| MCP-TOOLS-REFERENCE.md 的 note_type/source enum 過時 | P1 | ✅ 已修正 (2026-04-02) | 對齊後端 `write.go:797-808` |
| Directive metadata 無 schema（target, priority 不強制） | **P1** | 排定下週 | CHECK constraint + Go validation |
| Report 無因果鏈（不知回應哪個 directive） | **P1** | 排定下週 | `in_response_to` metadata |
| 無 delivery confirmation | P1 | 排定下週 | `consumed_at` + `consumed_by` columns |
| 無 targeting query（不能 filter by 目標部門） | P2 | 排定下週 | expression index on `metadata->>'target'` |
| Desktop Schedule 需聚焦 Cowork view 才觸發 | P2 | Anthropic 已知 bug | 改用 Cloud Schedule |

---

## 參考文件

| 文件 | 內容 |
|------|------|
| `docs/TOOLCHAIN-INTEGRATION-REPORT-2026-04-02.md` | 完整工具鏈研究報告 |
| `docs/MCP-TOOLS-REFERENCE.md` | MCP 49 工具完整參考 |
| `docs/AUDIT-REPORT-2026-03-30.md` | 系統現況審計報告 |
| `internal/mcp/write.go:786-809` | `save_session_note` validation（enum 權威來源） |
| `internal/mcp/search.go:1014` | `session_notes` query validation |
