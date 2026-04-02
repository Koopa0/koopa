# Decision Doc: Session Notes IPC Protocol Hardening

**Date**: 2026-04-02
**Author**: Koopa (koopa0.dev)
**Status**: Decided
**Review Process**: Design Review Board — 4 AI reviewers (2× Claude Web, Gemini, OpenAI), 6 review reports, cross-examination by Claude Web coordinator

---

## Context

koopa0.dev 的 `session_notes` 表是四個 Cowork 部門（HQ、Content Studio、Research Lab、Learning Studio）之間的唯一通訊管道。目前所有 cross-project 通訊都是 free-form prose，沒有結構化的 routing、acknowledgment、或 causal linking。

系統約束：單一 PostgreSQL、單一 Go server（pgx/v5 + sqlc）、順序執行的非同步 session、幾百行資料、自訂 MCP server 只在本地 Desktop/Cowork 可用（cloud scheduled tasks 無法存取）。

## Problem Statement

四個具體問題：

1. Directive 沒有結構化的 target / priority，routing 資訊埋在 prose 裡
2. 沒有 delivery confirmation——HQ 無法確認某部門是否已接手 directive
3. Report 和 directive 之間沒有結構化的因果連結
4. 無法用 SQL 查詢特定部門的 directive

## Decision Summary

| #   | Decision                        | Chose                                                          | Rejected                                                             | Rationale                                                                                                      |
| --- | ------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| 1   | Routing fields                  | First-class columns (`target`, `priority`)                     | JSONB metadata keys                                                  | 6/6 reviewers 共識——routing fields 不是 metadata，是 protocol 骨架。JSONB 用於非核心附加資訊。                 |
| 2   | Causal linking                  | `in_response_to BIGINT REFERENCES session_notes(id)` column    | JSONB `in_response_to` key                                           | FK 提供 referential integrity；JSONB 裡無法做 foreign key                                                      |
| 3   | Delivery confirmation           | `acknowledged_at TIMESTAMPTZ` + `acknowledged_by TEXT` columns | `consumed_at`（命名）、boolean、state machine、不加                  | 語義更準確：ack = picked up，report = completed。State machine 對當前場景太重。                                |
| 4   | `acknowledged_by`               | 保留                                                           | 砍掉（OpenAI Devil's Advocate 主張）                                 | 成本極低；FYI 型 directive 不產出 report 時有獨立價值；paired constraint 增加資料完整性                        |
| 5   | Conversation threading          | `correlation_id UUID` in JSONB metadata，規範 agent 寫入       | 不加 / 升格為 column                                                 | 避免未來 recursive CTE 追溯因果鏈。目前放 metadata 足夠，頻繁使用時再考慮升格。                                |
| 6   | Backward compatibility          | `NOT VALID` constraint                                         | `created_at <= '2026-04-07'` date hack / backfill / `schema_version` | 6/6 reviewers 共識拒絕日期 hack。`NOT VALID` 是最 PostgreSQL-native 的做法——新資料立刻受約束，舊資料先不追殺。 |
| 7   | Actor vocabulary management     | Lookup table `actor(name TEXT PRIMARY KEY)` + FK               | 在多個 CHECK 裡重複字串                                              | 單一 source of truth；新增部門只需 INSERT，不需改 DDL                                                          |
| 8   | Indexes                         | 暫不建立                                                       | Expression indexes on JSONB / partial indexes                        | 幾百行資料，seq scan 比 index lookup 快。未來有需要再加。                                                      |
| 9   | Multi-target directives         | Fan-out：一個 target 一筆 directive                            | Array targets / junction table                                       | 保持 ack model 簡單；每筆 directive 獨立追蹤 acknowledged_at                                                   |
| 10  | Directive-to-report cardinality | 每個 directive 最多一份 terminal report per department         | 不定義                                                               | 防止 duplicate completion；考慮加 unique partial index 擋重複                                                  |

## Detailed Rationale

### Why columns over JSONB for routing fields

這是整個 review 最核心的共識。六份 review 一致認為：當一個 JSONB key 決定了「誰讀這個 message」或「這個 message 回應的是什麼」，它就不再是 metadata——它是 protocol 的骨架。

具體好處包括：type safety（`BIGINT` vs. 任意 JSON value）、query clarity（`WHERE target = 'content-studio'` vs. `WHERE metadata->>'target' = ...`）、referential integrity（`in_response_to` 可以加 FK）、NULL semantics 更清楚、sqlc codegen 更乾淨。

RFC 原本說「避免 schema change」，但 RFC 本身已經在做 schema change（加 consumed_at/consumed_by + CHECK + index），所以這個論點不成立。既然要動 migration，就把重要的欄位一次扶正。

Mental model：**骨架進欄位，肉留 JSONB。**

- First-class columns：`target`, `priority`, `in_response_to`, `acknowledged_at`, `acknowledged_by`
- JSONB metadata：`deadline`, `tags`, `context_refs`, `artifacts`, `summary`, `correlation_id`, `session_id`, prompt hints, 任何還不穩定的附加資訊

### Why `acknowledged_at` instead of `consumed_at`

`consumed_at` 暗示「已消費完畢」，但實際語義是「agent 剛看到、準備處理」。拆成兩層更清楚：

- `acknowledged_at` / `acknowledged_by` = picked up（資料庫層）
- Report row with `in_response_to` = completed / responded（業務層）

HQ 判斷完成，看的是是否存在對應 report，不是看 `acknowledged_at`。

### Why keep `acknowledged_by`

OpenAI Devil's Advocate 主張砍掉，理由是 report 的 `source` 已經隱含消費者身份。但這忽略了一個場景：FYI 型 directive 不產出 report，但仍需確認對方看到了。保留 `acknowledged_by` 的 downside 幾乎為零（一個 TEXT 欄位 + FK），upside 是完整的審計軌跡和 paired constraint。

### Why `NOT VALID` over date hack

`NOT VALID` 是 PostgreSQL 原生機制：constraint 立刻對新 INSERT 生效，但不回頭檢查現有資料。之後可以 backfill 舊資料再 `VALIDATE CONSTRAINT`。相比 `created_at <= '2026-04-07'`：

- 不會在 schema 裡留下無業務意義的 magic date
- dump/restore 不會出問題
- 不會因為手動修改 `created_at` 而破壞語義
- 未來的 schema 演進不需要再塞更多日期

### Why `correlation_id` in metadata (not column)

`correlation_id` 用於串聯整個對話線程（directive → report → follow-up directive → report）。目前放在 JSONB metadata 就夠了，因為它不是 routing key（不決定誰讀），也不需要 FK。但它需要被規範——agent 在寫第一個 directive 時產生 UUID，後續所有回覆都帶同一個 `correlation_id`。

如果 multi-hop 對話頻繁且需要快速查詢，未來考慮升格為 column + index。

### Why lookup table for actors

`source`、`target`、`acknowledged_by` 三個欄位共享同一組 actor 名單（`hq`, `content-studio`, `research-lab`, `learning-studio`, `claude-code`, `claude`, `manual`）。用 lookup table + FK 取代在多個 CHECK 裡重複字串：

- 新增部門只需 `INSERT INTO actor`，不需要改 CHECK + DDL
- 單一 source of truth
- FK 自動阻止非法 actor

### What the Devil's Advocate taught us

兩份 Devil's Advocate review 提出的核心論點是：AI agent 能 parse prose，project instructions 就能解決大部分問題，不需要 database-level enforcement。

這個論點有力的地方在於：它正確指出 AI consumer 跟 dumb parser 不同，protocol 可以比傳統 IPC 更寬鬆。

但這個論點忽略了：protocol 不只是給 agent 讀的，也是給 operator（Koopa）查詢和審計用的。structured data 讓 morning briefing 的查詢更精確、讓 debug 更快、讓系統可觀測性更高。而且先做好結構再考慮刪減，比先 lazy 設計再堆疊技術債更健康——堆疊的技術債更難修復和發現問題。

最終決策：**Go 層 validation + DB constraint 雙層防護，不依賴 prompt engineering 作為唯一保障。**

## Deferred Decisions

| Item                                                  | Defer Until                    | Reason                                                 |
| ----------------------------------------------------- | ------------------------------ | ------------------------------------------------------ |
| `FOR UPDATE SKIP LOCKED`                              | 實際 concurrent sessions       | 目前順序執行，不需要                                   |
| LISTEN/NOTIFY                                         | 長執行 agent process           | Cowork 是 ephemeral session，不適用                    |
| State machine (`pending/processing/completed/failed`) | 有副作用型 directive           | 當前 directive 都是內容/研究任務，poison pill 風險極低 |
| `correlation_id` 升格為 column                        | Multi-hop 對話頻繁             | 目前放 metadata 足夠                                   |
| `schema_version` / protocol versioning                | 真正的 v2 envelope             | 不用來替代 migration hygiene                           |
| Dead letter handling / `expires_at`                   | Directive 長期未被處理成為問題 | Morning briefing 已能非正式地發現 stale directives     |
| Directive-to-report unique index                      | 觀察是否有重複 report 問題     | 先定義 cardinality 規則，觀察 agent 遵循度             |

## Migration Plan (Final — incorporates Claude Code validation feedback)

```sql
-- Step 0: Actor lookup table
CREATE TABLE actor (
  name TEXT PRIMARY KEY
);

INSERT INTO actor(name) VALUES
  ('claude'), ('claude-code'), ('manual'),
  ('hq'), ('content-studio'), ('research-lab'), ('learning-studio');

-- Step 1: Drop redundant CHECK constraint (before adding FK)
ALTER TABLE session_notes DROP CONSTRAINT session_notes_source_check;
-- note_type CHECK 保留不動

-- Step 2: Add first-class columns
ALTER TABLE session_notes ADD COLUMN target TEXT;
ALTER TABLE session_notes ADD COLUMN priority TEXT;
ALTER TABLE session_notes ADD COLUMN in_response_to BIGINT;
ALTER TABLE session_notes ADD COLUMN acknowledged_at TIMESTAMPTZ;
ALTER TABLE session_notes ADD COLUMN acknowledged_by TEXT;

-- Step 3: Foreign keys
ALTER TABLE session_notes
  ADD CONSTRAINT fk_source_actor FOREIGN KEY (source) REFERENCES actor(name);
ALTER TABLE session_notes
  ADD CONSTRAINT fk_target_actor FOREIGN KEY (target) REFERENCES actor(name);
ALTER TABLE session_notes
  ADD CONSTRAINT fk_acknowledged_by_actor FOREIGN KEY (acknowledged_by) REFERENCES actor(name);
ALTER TABLE session_notes
  ADD CONSTRAINT fk_in_response_to FOREIGN KEY (in_response_to) REFERENCES session_notes(id);

-- Step 4: Domain validation
ALTER TABLE session_notes ADD CONSTRAINT chk_priority_values
  CHECK (priority IS NULL OR priority IN ('p0', 'p1', 'p2'))
  NOT VALID;

-- Step 5: Structural enforcement — directive only
-- Report 不加 constraint — in_response_to nullable, Go 層 soft validate
ALTER TABLE session_notes ADD CONSTRAINT chk_directive_fields
  CHECK (note_type <> 'directive' OR (target IS NOT NULL AND priority IS NOT NULL))
  NOT VALID;

-- Step 6: Paired constraint for acknowledgment
ALTER TABLE session_notes ADD CONSTRAINT chk_ack_pair
  CHECK (
    (acknowledged_at IS NULL AND acknowledged_by IS NULL)
    OR (acknowledged_at IS NOT NULL AND acknowledged_by IS NOT NULL)
  ) NOT VALID;

-- No indexes at current scale. Add when warranted.
-- No chk_report_fields — report's in_response_to is soft-validated in Go only.
```

## Go Validation Layer (Final — incorporates Claude Code validation feedback)

```go
// write.go — validateSessionNoteFields()
case "directive":
    if target == "" {
        return fmt.Errorf("directive requires target")
    }
    if priority == "" {
        return fmt.Errorf("directive requires priority (p0/p1/p2)")
    }
    // correlation_id: server auto-generates UUID if not in metadata
    if metadata["correlation_id"] == nil {
        metadata["correlation_id"] = uuid.NewString()
    }

case "report":
    // in_response_to: soft validate — warn but don't reject
    if inResponseTo == 0 {
        slog.Warn("report without in_response_to", "source", source)
    }
    // correlation_id: if in_response_to is set, auto-copy from directive
    if inResponseTo != 0 {
        directive, _ := store.NoteByID(ctx, inResponseTo)
        if cid := directive.Metadata["correlation_id"]; cid != nil {
            metadata["correlation_id"] = cid  // override agent value
        }
    }
```

## Acknowledge Directive Query

```sql
-- acknowledge_directive.sql (sqlc)
UPDATE session_notes
SET acknowledged_at = now(), acknowledged_by = @acknowledged_by
WHERE id = @id AND acknowledged_at IS NULL
RETURNING *;
```

## Agent Communication Protocol (for Cowork Project Instructions)

Each department's project instructions should include:

> **Communication Protocol v2**
>
> When writing a directive: set `target` (department name), `priority` (p0/p1/p2). The server auto-generates `correlation_id` — you don't need to manage it.
>
> When writing a report in response to a directive: set `in_response_to` (the directive's session_note ID). The server auto-copies `correlation_id` from the directive.
>
> When writing a self-initiated report (no directive): `in_response_to` is optional. Omit it if the report is not responding to a specific directive.
>
> When starting a session: query for unacknowledged directives targeting you. After reading, acknowledge each one. Then process and write reports.

## JSONB metadata conventions (post-migration)

Metadata is now for **non-routing, non-structural** information only:

```jsonc
// Directive metadata example
{
  "correlation_id": "a1b2c3d4-...",  // server auto-generated, do not set manually
  "session_id": "x9y8z7w6-...",      // which session wrote this (optional)
  "deadline": "2026-04-10",           // soft deadline (optional)
  "context_refs": ["build-log-42"],   // related resources (optional)
  "tags": ["content", "blog"]         // categorization (optional)
}

// Report metadata example (directive-driven)
{
  "correlation_id": "a1b2c3d4-...",  // server auto-copied from directive, do not set manually
  "session_id": "q1w2e3r4-...",
  "artifacts": ["blog-post-slug"],    // produced outputs (optional)
  "follow_up_needed": true            // flag for HQ (optional)
}

// Report metadata example (self-initiated, no directive)
{
  "session_id": "q1w2e3r4-...",
  "artifacts": ["rss-scan-results"],
  "follow_up_needed": false
  // no correlation_id — server doesn't generate one for self-initiated reports
}

// Insight metadata (unchanged)
{
  "hypothesis": "...",
  "invalidation_condition": "..."
}
```

## Review Process Record

This decision was produced through a Design Review Board with four AI reviewers:

- **Claude Web #1 (Coordinator + System Architect)**: Orchestrated the review, synthesized disagreements, provided system-level architectural judgment.
- **Claude Web #2 (PostgreSQL DBA)**: Two sessions — focused on CHECK constraints, JSONB vs. columns, expression indexes, backward compatibility, PostgreSQL-specific patterns.
- **Gemini (Event Architecture)**: Two sessions covering message envelope design, acknowledgment model, causal linking, correlation IDs, actor mailbox patterns, future concurrency.
- **OpenAI (Devil's Advocate)**: Two sessions challenging necessity of each change, arguing for minimal intervention and project-instruction-based solutions.

Key consensus (6/6): Promote routing fields to columns. Reject date hack. Use NOT VALID.

Key resolved disagreement: Devil's Advocate argued the RFC is premature. Decision: the protocol serves operator queryability and auditability, not just agent comprehension. "先做好再刪減" over "先 lazy 再堆疊".

## Post-Review: Claude Code Implementation Validation (2026-04-02)

Decision Doc 交回 Claude Code 做 implementation-level review，發現三個 design-time 遺漏。以下為回應和最終決策。

### 疑慮 1：Report 強制 `in_response_to` 太嚴格

**問題**：不是所有 report 都回應 directive。Content Studio 排程 RSS 監測、Research Lab 自主產業掃描、Learning Studio session summary — 這些沒有對應的 directive。

**決策**：**選項 A — 放寬**。`in_response_to` nullable，不加 DB CHECK constraint。Go 層 soft validate：`in_response_to` 為空時 log warning 但不 reject。

**排除**：
- 選項 B（standing directive）：人為製造因果關係，稀釋 `in_response_to` 語義。
- 選項 C（拆 `report` / `status`）：方向對但時機不對，改動面太大。

**Migration 影響**：移除 `chk_report_fields` constraint。

### 疑慮 2：既有 CHECK constraint 衝突

**問題**：`session_notes` DDL 已有 `CHECK (source IN ('claude','claude-code',...))` — 加 `fk_source_actor` 後冗餘，且未來加 actor 需改兩處。

**決策**：Migration 中先 `DROP CONSTRAINT session_notes_source_check`，再加 FK。`note_type` CHECK 暫時不動 — 沒有 lookup table 化的 ROI。

### 疑慮 3：`correlation_id` 生成責任

**問題**：依賴 agent 在 instructions 中手動產生 UUID 不可靠。

**決策**：**Server 自動生成**。

- **寫 directive**：Go 層檢查 metadata，沒有 `correlation_id` 則自動生成 UUID 塞入。有則保留（follow-up directive 從上文複製）。
- **寫 report（有 `in_response_to`）**：Go 層從 referenced directive 的 metadata 自動複製 `correlation_id`，覆蓋 agent 提供的值。
- **寫 report（無 `in_response_to`，自發性）**：`correlation_id` 可選。Agent 提供就用，不提供不塞。

Agent 不需要管 `correlation_id` 傳遞邏輯。
