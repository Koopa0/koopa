# Decision Doc: Session Notes IPC Protocol Hardening

**Date**: 2026-04-02
**Author**: Koopa (koopa0.dev)
**Status**: Decided
**Review Process**: Design Review Board — 4 AI reviewers (2× Claude Web, Gemini, OpenAI), 6 review reports, cross-examination by Claude Web coordinator, Claude Code implementation validation

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

| #   | Decision                        | Chose                                                          | Rejected                                                | Rationale                                                                                                          |
| --- | ------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| 1   | Routing fields                  | First-class columns (`target`, `priority`)                     | JSONB metadata keys                                     | 6/6 reviewers 共識——routing fields 不是 metadata，是 protocol 骨架。JSONB 用於非核心附加資訊。                     |
| 2   | Causal linking                  | `in_response_to BIGINT REFERENCES session_notes(id)` column    | JSONB `in_response_to` key                              | FK 提供 referential integrity；JSONB 裡無法做 foreign key。**Nullable**——不是所有 report 都回應 directive。        |
| 3   | Delivery confirmation           | `acknowledged_at TIMESTAMPTZ` + `acknowledged_by TEXT` columns | `consumed_at`（命名）、boolean、state machine、不加     | 語義更準確：ack = picked up，report = completed。State machine 對當前場景太重。**僅 directive 可被 acknowledge。** |
| 4   | `acknowledged_by`               | 保留                                                           | 砍掉（OpenAI Devil's Advocate 主張）                    | 成本極低；FYI 型 directive 不產出 report 時有獨立價值；paired constraint 增加資料完整性                            |
| 5   | Conversation threading          | `correlation_id UUID` in JSONB metadata，server 自動生成       | 不加 / 升格為 column / agent 手動管理                   | 語義定義為 **thread-level**（整條工作線程），不是 pair-level。Server 負責生成和傳遞，agent 不需管理。              |
| 6   | Backward compatibility          | Backfill 舊資料 + 完整 constraint                              | `NOT VALID` / `created_at` date hack / `schema_version` | 幾百行資料、單一使用者、無 production traffic。`NOT VALID` 解決的問題（大表 lock）不存在。Backfill 更乾淨。        |
| 7   | Actor vocabulary management     | Lookup table `actor(name, role)` + FK                          | Flat `actor(name)` / 在多個 CHECK 裡重複字串            | `role` 區分 department vs executor，解決語義混用。Go 層 validate target 只接受 department。                        |
| 8   | Indexes                         | 暫不建立                                                       | Expression indexes on JSONB / partial indexes           | 幾百行資料，seq scan 比 index lookup 快。未來有需要再加。                                                          |
| 9   | Multi-target directives         | Fan-out：一個 target 一筆 directive                            | Array targets / junction table                          | 保持 ack model 簡單；每筆 directive 獨立追蹤 acknowledged_at                                                       |
| 10  | Directive-to-report cardinality | 每個 directive 最多一份 terminal report per department         | 不定義                                                  | 防止 duplicate completion；考慮加 unique partial index 擋重複                                                      |

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

Acknowledge 行為僅限 directive——其他 note_type（plan、reflection、context、metrics、insight）不需要 ack 機制。DB 層透過 `chk_ack_only_directive` constraint 強制這個語義邊界。

### Why keep `acknowledged_by`

OpenAI Devil's Advocate 主張砍掉，理由是 report 的 `source` 已經隱含消費者身份。但這忽略了一個場景：FYI 型 directive 不產出 report，但仍需確認對方看到了。保留 `acknowledged_by` 的 downside 幾乎為零（一個 TEXT 欄位 + FK），upside 是完整的審計軌跡和 paired constraint。

### Why backfill over `NOT VALID`

Review Board 原本選 `NOT VALID`，但 Claude Code 二次審查指出：**`NOT VALID` 解決的問題（大表 ACCESS EXCLUSIVE lock 造成 downtime）在這個場景不存在。** 表只有幾百行，掃描是毫秒級，單一使用者沒有 production traffic。

`NOT VALID` 會引入不必要的中間態：constraint 只保護新資料，舊資料處於「不確定」狀態，你還需要記得之後 backfill + `VALIDATE CONSTRAINT`。這是三步流程。

Backfill + 完整 constraint 是兩步流程：先 UPDATE 補齊舊資料，再加完整 CHECK。Migration 結束後 schema 就是乾淨的，沒有懸而未決的 `NOT VALID` constraint。

### Why report `in_response_to` is nullable (no DB constraint)

Claude Code implementation review 發現：不是所有 report 都回應 directive。Content Studio 排程跑 RSS 監測、Research Lab 自主產業掃描、Learning Studio 寫 session summary — 這些沒有對應的 directive。

三個選項的評估：

- **選項 A（放寬，最終選擇）**：`in_response_to` nullable，不加 DB CHECK。Go 層 soft validate：空值時 log warning 但不 reject。
- **選項 B（standing directive）**：人為製造因果關係（HQ 每天自動產出 directive），會稀釋 `in_response_to` 語義。Correlation 的價值在於精準，不在於覆蓋率。排除。
- **選項 C（拆 report / status）**：方向對但時機不對。先觀察自發性 report 比例，超過 30% 時再考慮正式化。列入 deferred decisions。

### Why `correlation_id` in metadata, server-managed, thread-level

`correlation_id` 用於串聯整個對話線程（directive → report → follow-up directive → report）。

**語義定義（寫死）**：`correlation_id` 代表**整條工作線程（thread）**，不是單輪 directive-report pair。Follow-up directive 延用同一個 `correlation_id`。這讓你可以用一個 UUID 查出一整條工作鏈的所有 notes。

**生成責任**：Server 自動處理，agent 不需管理。

- 寫 directive：metadata 沒有 `correlation_id` → server 自動生成 UUID
- 寫 directive（follow-up）：agent 從上文複製 `correlation_id` → server 保留
- 寫 report（有 `in_response_to`）：server 從 referenced note 自動複製 `correlation_id`，覆蓋 agent 值。如果 referenced note 的 metadata 缺少 `correlation_id`（老資料），log warning 但不 reject。
- 寫 report（自發性，無 `in_response_to`）：不塞 `correlation_id`

目前放 JSONB metadata — 不是 routing key，不需要 FK。Multi-hop 對話頻繁時再考慮升格為 column + index。

### Why lookup table with `role` for actors

原始設計是 flat `actor(name PRIMARY KEY)`。Claude Code 二次審查指出 **bad smell**：表裡混了兩種語義不同的東西。

- `hq`, `content-studio`, `research-lab`, `learning-studio` 是**部門（department）** — directive 的 target、report 的 source、acknowledge 的主體。
- `claude`, `claude-code`, `manual` 是**執行身份（executor）** — 描述「誰在操作」，不是「哪個部門在工作」。

混用場景：Claude Code 幫 Content Studio 執行任務，`source` 應該是 `content-studio` 還是 `claude-code`？以前被字串 CHECK 掩蓋，正規化成 lookup table 後問題浮出。

加 `role` 欄位區分。Go 層 validate：`target` 和 `acknowledged_by` 只接受 `role = 'department'`。`source` 兩種都接受（保持現狀相容）。FK 暫時指向整個 `actor` 表，不在 DB 層強制 role 區分——避免 partial unique index 或拆表的複雜度。

### What the Devil's Advocate taught us

兩份 Devil's Advocate review 提出的核心論點是：AI agent 能 parse prose，project instructions 就能解決大部分問題，不需要 database-level enforcement。

這個論點有力的地方在於：它正確指出 AI consumer 跟 dumb parser 不同，protocol 可以比傳統 IPC 更寬鬆。

但這個論點忽略了：protocol 不只是給 agent 讀的，也是給 operator（Koopa）查詢和審計用的。structured data 讓 morning briefing 的查詢更精確、讓 debug 更快、讓系統可觀測性更高。而且先做好結構再考慮刪減，比先 lazy 設計再堆疊技術債更健康——堆疊的技術債更難修復和發現問題。

最終決策：**Go 層 validation + DB constraint 雙層防護，不依賴 prompt engineering 作為唯一保障。**

## Deferred Decisions

| Item                                                            | Defer Until                      | Reason                                                               |
| --------------------------------------------------------------- | -------------------------------- | -------------------------------------------------------------------- |
| `FOR UPDATE SKIP LOCKED`                                        | 實際 concurrent sessions         | 目前順序執行，不需要                                                 |
| LISTEN/NOTIFY                                                   | 長執行 agent process             | Cowork 是 ephemeral session，不適用                                  |
| State machine (`pending/processing/completed/failed`)           | 有副作用型 directive             | 當前 directive 都是內容/研究任務，poison pill 風險極低               |
| `correlation_id` 升格為 column                                  | Multi-hop 對話頻繁               | 目前放 metadata 足夠                                                 |
| `schema_version` / protocol versioning                          | 真正的 v2 envelope               | 不用來替代 migration hygiene                                         |
| Dead letter handling / `expires_at`                             | Directive 長期未被處理成為問題   | Morning briefing 已能非正式地發現 stale directives                   |
| Directive-to-report unique index                                | 觀察是否有重複 report 問題       | 先定義 cardinality 規則，觀察 agent 遵循度                           |
| 拆 `session_notes` 為 journal + workflow 表                     | 出現 retry/stalled/reassign 需求 | `session_notes` 正從 journal 長成 workflow message table，但目前不拆 |
| Report `report_kind` 區分（directive-driven vs self-initiated） | 自發性 report 超過 30%           | 先在 metadata 裡鼓勵填寫，觀察比例後再決定是否正式化                 |
| Actor FK 層面強制 role 區分（target 只接受 department）         | Go 層 validation 不夠用時        | 需要 partial unique index 或拆表，目前 Go 層 soft validate 足夠      |
| `note_type` lookup table 化                                     | `note_type` 開始頻繁增加時       | 目前 7 個固定值，CHECK constraint ROI 更高                           |

## Migration Plan (Final — incorporates all review rounds)

```sql
-- Step 0: Actor lookup table with role distinction
CREATE TABLE actor (
  name TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('department', 'executor'))
);

INSERT INTO actor(name, role) VALUES
  ('hq', 'department'),
  ('content-studio', 'department'),
  ('research-lab', 'department'),
  ('learning-studio', 'department'),
  ('claude', 'executor'),
  ('claude-code', 'executor'),
  ('manual', 'executor');

-- Step 1: Safety check — verify all existing source values exist in actor table
-- If this returns rows, fix data or add missing actors before proceeding
-- SELECT DISTINCT source FROM session_notes WHERE source NOT IN (SELECT name FROM actor);

-- Step 2: Drop redundant source CHECK (before adding FK)
ALTER TABLE session_notes DROP CONSTRAINT session_notes_source_check;
-- note_type CHECK 保留不動

-- Step 3: Add first-class columns
ALTER TABLE session_notes ADD COLUMN target TEXT;
ALTER TABLE session_notes ADD COLUMN priority TEXT;
ALTER TABLE session_notes ADD COLUMN in_response_to BIGINT;
ALTER TABLE session_notes ADD COLUMN acknowledged_at TIMESTAMPTZ;
ALTER TABLE session_notes ADD COLUMN acknowledged_by TEXT;

-- Step 4: Backfill existing directives (before adding constraints)
-- 幾百行，手動可查，default routing 不影響系統行為
UPDATE session_notes
SET target = 'hq', priority = 'p2'
WHERE note_type = 'directive' AND target IS NULL;

-- Step 5: Foreign keys
ALTER TABLE session_notes
  ADD CONSTRAINT fk_source_actor FOREIGN KEY (source) REFERENCES actor(name);
ALTER TABLE session_notes
  ADD CONSTRAINT fk_target_actor FOREIGN KEY (target) REFERENCES actor(name);
ALTER TABLE session_notes
  ADD CONSTRAINT fk_acknowledged_by_actor FOREIGN KEY (acknowledged_by) REFERENCES actor(name);
ALTER TABLE session_notes
  ADD CONSTRAINT fk_in_response_to FOREIGN KEY (in_response_to) REFERENCES session_notes(id);

-- Step 6: Domain validation (完整 constraint，backfill 後不需要 NOT VALID)
ALTER TABLE session_notes ADD CONSTRAINT chk_priority_values
  CHECK (priority IS NULL OR priority IN ('p0', 'p1', 'p2'));

-- Step 7: Structural enforcement — directive only (完整，backfill 後不需要 NOT VALID)
ALTER TABLE session_notes ADD CONSTRAINT chk_directive_fields
  CHECK (note_type <> 'directive' OR (target IS NOT NULL AND priority IS NOT NULL));

-- Step 8: Paired constraint for acknowledgment
ALTER TABLE session_notes ADD CONSTRAINT chk_ack_pair
  CHECK (
    (acknowledged_at IS NULL AND acknowledged_by IS NULL)
    OR (acknowledged_at IS NOT NULL AND acknowledged_by IS NOT NULL)
  );

-- Step 9: Acknowledgment is directive-only (semantic boundary)
ALTER TABLE session_notes ADD CONSTRAINT chk_ack_only_directive
  CHECK (acknowledged_at IS NULL OR note_type = 'directive');

-- No chk_report_fields — report in_response_to nullable, Go 層 soft validate
-- No indexes — 幾百行 seq scan 比 index 快
-- No NOT VALID — 幾百行無 production traffic，backfill 更乾淨
```

## Go Validation Layer (Final — incorporates all review rounds)

```go
// write.go — validateSessionNoteFields()

// Actor role validation (applies to all note types)
// target and acknowledged_by must be department actors
if target != "" {
    actor, err := store.GetActor(ctx, target)
    if err != nil {
        return fmt.Errorf("unknown target actor: %s", target)
    }
    if actor.Role != "department" {
        return fmt.Errorf("target must be a department, got executor %q", target)
    }
}

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
        slog.Warn("report without in_response_to",
            "source", source,
            "note_date", noteDate,
        )
    }
    // correlation_id: if in_response_to is set, auto-copy from referenced note
    if inResponseTo != 0 {
        referenced, err := store.NoteByID(ctx, inResponseTo)
        if err != nil {
            slog.Warn("in_response_to references non-existent note",
                "id", inResponseTo,
            )
        } else if cid := referenced.Metadata["correlation_id"]; cid != nil {
            metadata["correlation_id"] = cid // override agent value
        } else {
            slog.Warn("referenced note missing correlation_id, report will lack thread context",
                "referenced_id", inResponseTo,
            )
        }
    }
```

## Acknowledge Directive Query

```sql
-- acknowledge_directive.sql (sqlc)
UPDATE session_notes
SET acknowledged_at = now(), acknowledged_by = @acknowledged_by
WHERE id = @id
  AND note_type = 'directive'
  AND acknowledged_at IS NULL
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

This decision was produced through a Design Review Board with four AI reviewers, followed by implementation-level validation:

- **Claude Web #1 (Coordinator + System Architect)**: Orchestrated the review, synthesized disagreements, provided system-level architectural judgment. Coordinated cross-examination across all reviewers.
- **Claude Web #2 (PostgreSQL DBA)**: Two sessions — focused on CHECK constraints, JSONB vs. columns, expression indexes, backward compatibility, PostgreSQL-specific patterns. Key contribution: `NOT VALID` mechanism, FK for `in_response_to`, actor lookup table.
- **Gemini (Event Architecture)**: Two sessions covering message envelope design, acknowledgment model, causal linking, correlation IDs, actor mailbox patterns, future concurrency. Key contribution: `correlation_id` for thread-level conversation tracking, state machine analysis (deferred), priority-based selective receive pattern.
- **OpenAI (Devil's Advocate)**: Two sessions challenging necessity of each change, arguing for minimal intervention and project-instruction-based solutions. Key contribution: forced justification for every change, validated that `consumed_at` is the minimum viable addition, challenged over-engineering risk.
- **Claude Code (Implementation Validator)**: Post-decision review. Key contributions: (1) Report `in_response_to` too strict — led to nullable decision; (2) Source CHECK → FK migration ordering; (3) `correlation_id` server-managed — eliminated agent dependency.

Key consensus (6/6): Promote routing fields to columns. Reject date hack.

Key resolved disagreement: Devil's Advocate argued the RFC is premature. Decision: the protocol serves operator queryability and auditability, not just agent comprehension. 「先做好再刪減」over「先 lazy 再堆疊」.

Post-review corrections (Coordinator final pass): (1) Added source FK safety check step; (2) Added `chk_ack_only_directive` constraint for semantic boundary; (3) Added nil-check logging for `correlation_id` auto-copy from old notes.

## Post-Review: Claude Code Implementation Validation (2026-04-02)

Decision Doc 交回 Claude Code 做 implementation-level review，發現三個 design-time 遺漏。以下為回應和最終決策。

### 疑慮 1：Report 強制 `in_response_to` 太嚴格

**問題**：不是所有 report 都回應 directive。Content Studio 排程 RSS 監測、Research Lab 自主產業掃描、Learning Studio session summary — 這些沒有對應的 directive。

**決策**：**選項 A — 放寬**。`in_response_to` nullable，不加 DB CHECK constraint。Go 層 soft validate：`in_response_to` 為空時 log warning 但不 reject。

**排除**：

- 選項 B（standing directive）：人為製造因果關係，稀釋 `in_response_to` 語義。
- 選項 C（拆 `report` / `status`）：方向對但時機不對，改動面太大。

### 疑慮 2：既有 CHECK constraint 衝突

**問題**：`session_notes` DDL 已有 `CHECK (source IN ('claude','claude-code',...))` — 加 `fk_source_actor` 後冗餘，且未來加 actor 需改兩處。

**決策**：Migration 中先 `DROP CONSTRAINT session_notes_source_check`，再加 FK。`note_type` CHECK 暫時不動 — 沒有 lookup table 化的 ROI。Migration Step 1 包含 safety check 確認所有既有 `source` 值都存在於 `actor` 表。

### 疑慮 3：`correlation_id` 生成責任

**問題**：依賴 agent 在 instructions 中手動產生 UUID 不可靠。

**決策**：**Server 自動生成**。

- **寫 directive**：Go 層檢查 metadata，沒有 `correlation_id` 則自動生成 UUID 塞入。有則保留（follow-up directive 從上文複製）。
- **寫 report（有 `in_response_to`）**：Go 層從 referenced note 的 metadata 自動複製 `correlation_id`，覆蓋 agent 提供的值。如果 referenced note 缺少 `correlation_id`（老資料），log warning。
- **寫 report（無 `in_response_to`，自發性）**：`correlation_id` 可選。Agent 提供就用，不提供不塞。

Agent 不需要管 `correlation_id` 傳遞邏輯。

### Coordinator 最終修正（三項補充）

1. **Source FK safety check**：Migration Step 1 加入 `SELECT DISTINCT source ... WHERE source NOT IN (SELECT name FROM actor)` 檢查。如果回傳資料，必須先修正再繼續 migration，否則 FK 會失敗。

2. **`chk_ack_only_directive` constraint**：只有 directive 才能被 acknowledge。防止其他 note_type 被意外寫入 `acknowledged_at`。DB 層強制語義邊界。

3. **`correlation_id` nil-check logging**：自動複製邏輯中，如果 referenced note 的 metadata 缺少 `correlation_id`（backfill 前的老 directive），Go 層 log warning 而非 silent fail。確保資料品質問題可被觀察到。
