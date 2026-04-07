# Schema v2 Migration — Go / MCP Impact Analysis

> 從 schema v1 到 v2 的所有 Go code 和 MCP tool 改動清單。

---

## 1. 表改名 → Go package / sqlc 改動

### 1.1 `session_notes` → `directives` + `reports` + `journal` + `insights`

| 層 | 改動 |
|----|------|
| **sqlc** | `internal/session/query.sql` 拆成多個 query file（或拆 package） |
| **Go package** | `internal/session/` → 考慮拆為 `internal/directive/`, `internal/report/`, `internal/journal/`, `internal/insight/`。或保持 `internal/session/` 但 store 方法分組 |
| **MCP tools** | 見 §2 |
| **Types** | `session.Note` → 拆為 `directive.Directive`, `report.Report`, `journal.Entry`, `insight.Insight` |
| **Store** | `session.Store` 的方法拆分到對應 package |
| **Retention cron** | `cmd/app/main.go` retention job 改為分表 DELETE |

**建議**：拆 package。每張表一個 package 符合 package-by-feature 原則。`internal/session/` 變成 4 個：

```
internal/directive/   — directive.go, store.go, query.sql, handler.go
internal/report/      — report.go, store.go, query.sql
internal/journal/     — journal.go, store.go, query.sql
internal/insight/     — insight.go, store.go, query.sql
```

### 1.2 `collected_data` → `feed_entries`

| 層 | 改動 |
|----|------|
| **sqlc** | `internal/feed/entry/query.sql` — 表名 `collected_data` → `feed_entries` |
| **Go types** | 檢查是否有 `CollectedData` type name 需要改為 `Entry` |
| **MCP tools** | `bookmark_rss_item` 的 store 呼叫 |
| **AI flows** | `internal/ai/bookmark.go`, `content_strategy.go` |

### 1.3 `tracking_topics` → `topic_monitors`

| 層 | 改動 |
|----|------|
| **sqlc** | `internal/monitor/query.sql` — 表名改 |
| **Go package** | `internal/monitor/` — Store 方法 + Handler |
| **Routes** | `/api/admin/tracking` — 可以保持 URL 不變，只改內部 |

### 1.4 `obsidian_notes` → `notes`

| 層 | 改動 |
|----|------|
| **sqlc** | `internal/note/query.sql` — 表名改 |
| **Go types** | 如有 `ObsidianNote` → `Note` |
| **Column** | `tags` → `raw_tags` — 所有讀寫 `tags` 的地方改名 |
| **Pipeline** | `internal/pipeline/sync_note.go` — Obsidian sync 邏輯 |

### 1.5 `notion_sources` → `sources`

| 層 | 改動 |
|----|------|
| **sqlc** | query 表名改 |
| **Column** | `database_id` → `external_id` — 所有讀寫改名 |
| **新 column** | `provider` — 需要設定 default 或 insert 時指定 |
| **Go types** | 如有 `NotionSource` → `Source` |
| **Notion sync** | `internal/notion/sync.go` — 查 source 的 query 改用 `external_id` |

### 1.6 `activity_events` → `events`

| 層 | 改動 |
|----|------|
| **sqlc** | `internal/activity/query.sql` — 表名改 |
| **Go types** | `event_type` 從 `string` → sqlc 生成的 enum type |
| **Column** | `event_type TEXT` → `event_type event_type` (PostgreSQL ENUM) |

### 1.7 `fsrs_cards` → `review_cards`, `fsrs_review_logs` → `review_logs`

| 層 | 改動 |
|----|------|
| **sqlc** | query 表名改 |
| **Column** | `tag TEXT` → `tag_id UUID` — FSRS card lookup 邏輯全改 |
| **Go types** | `FsrsCard` → `ReviewCard` 等 |
| **MCP tools** | `retrieval_queue`, `log_retrieval_attempt` 的 store 呼叫 |
| **Learning** | `internal/learning/` — mastery_map, concept_gaps 等 query |

### 1.8 `task_skip_log` → `task_skips`

| 層 | 改動 |
|----|------|
| **sqlc** | query 表名改 |
| **Go types** | 如有 `TaskSkipLog` → `TaskSkip` |

### 1.9 `tasks` 欄位改動

| 欄位 | 改動 | Go 影響 |
|------|------|---------|
| `energy` | `NOT NULL DEFAULT ''` → nullable | `string` → `*string` |
| `priority` | 同上 | `string` → `*string` |
| `recur_unit` | 同上 | `string` → `*string` |
| `assignee` | CHECK → FK to participant | 驗證邏輯可能需要查 participant 表 |
| 新 CHECK | `chk_completed_at_consistency`, `chk_recurrence_pair` | Go 層 insert/update 要保證一致性（不然 DB reject） |

### 1.10 `projects` 欄位改動

| 欄位 | 改動 | Go 影響 |
|------|------|---------|
| `expected_cadence` | `NOT NULL DEFAULT ''` → nullable | `string` → `*string` |
| `role` | `NOT NULL DEFAULT ''` → nullable | `string` → `*string` |
| `area` | `NOT NULL DEFAULT ''` → nullable | `string` → `*string` |

### 1.11 `goals` 欄位改動

| 欄位 | 改動 | Go 影響 |
|------|------|---------|
| `area` | `NOT NULL DEFAULT ''` → nullable | `string` → `*string` |
| `quarter` | `NOT NULL DEFAULT ''` → nullable | `string` → `*string` |

### 1.12 `feeds` 欄位改動

| 欄位 | 改動 | Go 影響 |
|------|------|---------|
| `etag` | `NOT NULL DEFAULT ''` → nullable | `string` → `*string` |
| `last_modified` | 同上 | `string` → `*string` |
| `last_error` | 同上 | `string` → `*string` |
| `disabled_reason` | 同上 | `string` → `*string` |
| `topics TEXT[]` | 欄位刪除，改為 `feed_topics` junction | query 全改：`ANY(topics)` → `JOIN feed_topics` |

---

## 2. MCP Tool 改動

### 2.1 Session note tools → 拆分

| 現有 Tool | 新 Tool | 寫入表 |
|-----------|---------|--------|
| `save_session_note(note_type="directive", ...)` | `send_directive(target, priority, content, ...)` | `directives` |
| `save_session_note(note_type="report", ...)` | `send_report(content, in_response_to?, ...)` | `reports` |
| `save_session_note(note_type="plan/context/reflection/metrics", ...)` | `save_journal(kind, content, ...)` | `journal` |
| `save_session_note(note_type="insight", ...)` | `save_insight(hypothesis, invalidation_condition, content, ...)` | `insights` |

**或者**：保持 `save_session_note` 作為 routing facade，Go 層根據 `note_type` 分發到正確的表。對 agent 來說 API 不變。

**建議**：拆 tool。理由：
- Tool name 本身就是語義。`send_directive` 比 `save_session_note(note_type="directive")` 更清楚。
- 每個 tool 的 validation 更乾淨 — `send_directive` 只需要 validate target + priority。
- 減少 MCP tool description 的 cognitive load。

### 2.2 Session note query tools → 拆分

| 現有 Tool | 新 Tool | 讀取表 |
|-----------|---------|--------|
| `session_notes(note_type="directive", ...)` | `inbox(target?, unacknowledged?)` | `directives` |
| `session_notes(note_type="report", ...)` | `outbox()` 或 `reports(source?, days?)` | `reports` |
| `session_notes(note_type="plan/context/...", ...)` | `journal(kind?, days?)` | `journal` |
| `active_insights(...)` | 保持（已獨立） | `insights` |

### 2.3 新增 Tool

| Tool | 功能 | 表 |
|------|------|-----|
| `acknowledge_directive(id)` | 標記 directive 為已讀 | `directives` UPDATE |

### 2.4 Correlation ID 自動化

| 場景 | Go 層行為 |
|------|-----------|
| 寫 directive | metadata 沒有 `correlation_id` → 自動生成 UUID |
| 寫 directive（follow-up） | agent 複製 `correlation_id` → 保留 |
| 寫 report（有 `in_response_to`） | 從 directive 自動複製 `correlation_id`，覆蓋 agent 值 |
| 寫 report（自發性） | 不塞 `correlation_id` |

### 2.5 MCP Tool 完整對照表

| # | 現有 Tool 名 | 新 Tool 名 | 改動類型 |
|---|-------------|-----------|----------|
| 1 | `save_session_note` | `send_directive` / `send_report` / `save_journal` / `save_insight` | 拆分 |
| 2 | `session_notes` | `inbox` / `reports` / `journal` | 拆分 |
| 3 | `active_insights` | 保持 | query 改表名 |
| 4 | `update_insight` | 保持 | query 改表名 |
| 5 | — | `acknowledge_directive` | 新增 |
| 6 | `morning_context` | 保持 | 內部 query 改：從 4 張表分別拉 |
| 7 | `reflection_context` | 保持 | 同上 |
| 8 | `session_delta` | 保持 | 同上 |
| 9 | `weekly_summary` | 保持 | 同上 |
| 10 | `bookmark_rss_item` | 保持 | query 改表名 `feed_entries` |
| 11 | `rss_highlights` | 保持 | query 改表名 + JOIN `feed_topics` |
| 12 | `collection_stats` | 保持 | query 改表名 |
| 13 | `list_feeds` | 保持 | query 改：`topics TEXT[]` → JOIN `feed_topics` |
| 14 | `add_feed` | 保持 | INSERT feeds + INSERT feed_topics |
| 15 | `update_feed` | 保持 | 可能需要 UPDATE feed_topics |
| 16 | `remove_feed` | 保持 | CASCADE 自動刪 feed_topics |
| 17 | `search_knowledge` | 保持 | query 改表名 `notes` |
| 18 | `retrieval_queue` | 保持 | query 改表名 `review_cards` + `tag_id` |
| 19 | `log_retrieval_attempt` | 保持 | query 改表名 `review_cards` / `review_logs` + `tag_id` |
| 20 | `mastery_map` | 保持 | query 改表名 + `tag_id` |
| 21 | `concept_gaps` | 保持 | 同上 |
| 22 | `variation_map` | 保持 | 同上 |
| 23 | `log_learning_session` | 保持 | query 改表名 |
| 24 | `log_dev_session` | 保持 | query 改表名 |
| 25 | `system_status` | 保持 | query 改表名 |

---

## 3. Cowork Project Instructions 改動

所有 4 個 Cowork project instructions 需要更新：

### 3.1 Tool name 更新

```
舊：save_session_note(note_type="directive", source="hq", ...)
新：send_directive(target="content-studio", priority="p1", content="...")

舊：session_notes(note_type="directive", days=3)
新：inbox(target="content-studio", unacknowledged=true)

舊：save_session_note(note_type="report", source="content-studio", ...)
新：send_report(content="...", in_response_to=42)

舊：save_session_note(note_type="context", ...)
新：save_journal(kind="context", content="...")
```

### 3.2 Session 啟動流程更新

```
Step 0: 讀取未確認的 directive
        inbox(target="content-studio", unacknowledged=true)

Step 0.5: 確認收到
        acknowledge_directive(id=<directive_id>)

Step 1: 讀自己上次的 context
        journal(kind="context", days=3)
```

### 3.3 Session 結束流程更新

```
Step 1: 寫 report（如果有 directive 要回報）
        send_report(content="...", in_response_to=<directive_id>)

Step 2: 寫 context
        save_journal(kind="context", content="...")
```

### 3.4 各 Project 需更新的文件

| 文件 | 改動 |
|------|------|
| `docs/Koopa-HQ.md` | Tool 名稱、session 流程、常用 tool 速查 |
| `docs/Koopa-Content-Studio.md` | Tool 名稱、session 流程 |
| `docs/Koopa-Research-Lab.md` | Tool 名稱、session 流程 |
| `docs/Koopa-Learning.md` | Tool 名稱、session 流程 |
| `docs/COWORK-SYSTEM.md` | Removed (04-04) — superseded by role-specific docs |
| `docs/MCP-TOOLS-REFERENCE.md` | Tool 列表全部更新 |
| `README.md` / `README.zh-TW.md` | Session Note 描述、IPC 流程 |

---

## 4. 新增 Go Package

| Package | 內容 |
|---------|------|
| `internal/directive/` | Directive type, Store, Handler, query.sql |
| `internal/report/` | Report type, Store, query.sql |
| `internal/journal/` | Journal entry type, Store, query.sql |
| `internal/platform/` | Platform + Participant types, Store（如果需要 query） |

`internal/insight/` 可能不需要獨立 package — 目前 insight 的 CRUD 都在 `internal/mcp/insights.go` 裡直接用 session store。但拆表後如果 query 夠多，可以獨立。

---

## 5. sqlc 改動摘要

`sqlc generate` 後所有 generated code 會自動更新。需要手動改的是 query.sql 文件：

| 現有 query file | 改動 |
|-----------------|------|
| `internal/session/query.sql` | 拆為 `directive/query.sql`, `report/query.sql`, `journal/query.sql`, `insight/query.sql` |
| `internal/feed/entry/query.sql` | 表名 `collected_data` → `feed_entries`；移除 `topics` 欄位相關 query |
| `internal/monitor/query.sql` | 表名 `tracking_topics` → `topic_monitors`；JOIN `topics` |
| `internal/note/query.sql` | 表名 `obsidian_notes` → `notes`；`tags` → `raw_tags` |
| `internal/activity/query.sql` | 表名 `activity_events` → `events` |
| 新增 | `internal/feed/topic/query.sql`（feed_topics junction CRUD） |

---

## 6. Retention Cron 改動

| 現在 | 之後 |
|------|------|
| `DELETE FROM session_notes WHERE note_type NOT IN (...) AND note_date < short` | `DELETE FROM journal WHERE note_date < 30d` |
| `DELETE FROM session_notes WHERE note_type IN (...) AND note_date < long` | `DELETE FROM directives WHERE note_date < 365d` |
| | `DELETE FROM reports WHERE note_date < 365d` |
| | Insights: `UPDATE SET status='archived'`（已有） |

每張表 = 一個 retention boundary。不需要排除式 WHERE。

---

## 7. 新增表（2026-04-04 signed off）

### 7.1 `milestones`

| 層 | 改動 |
|----|------|
| **新 package** | `internal/milestone/` — milestone.go, store.go, query.sql |
| **MCP tools** | `goal_progress` 增加 milestone 完成率；`weekly_summary` 增加 milestone deadline 分析 |
| **Notion sync** | 延後 — schema 預留 `notion_page_id`，sync 邏輯以後加 |

### 7.2 `daily_plan_items`

| 層 | 改動 |
|----|------|
| **新 package** | `internal/dailyplan/` — dailyplan.go, store.go, query.sql, handler.go |
| **取代** | `tasks.my_day` 欄位（已刪除）、`journal.metadata.committed_task_ids`（已廢除） |
| **MCP tools** | `my_day` → 改為 UPSERT daily_plan_items；`morning_context` / `reflection_context` 讀 daily_plan_items |
| **Cron** | 4-step pipeline 全面重寫：auto-defer incomplete → auto-populate recurring → Notion sync |
| **Go coordination** | task completion handler 需同步 UPDATE daily_plan_items.status = 'done' |

### 7.3 `tasks` 改動

| 欄位 | 改動 | Go 影響 |
|------|------|---------|
| `my_day` | 移除 | 所有 `MyDay bool` 從 struct 移除，`UpdateMyDay` / `ClearAllMyDay` / `MyDayTasks` 等 store 方法移除 |

### 7.4 `event_type` enum 改動

| 值 | 改動 | Go 影響 |
|-----|------|---------|
| `my_day_incomplete` | 移除 | `stepLogIncomplete` cron step 移除，由 daily_plan_items.status = 'deferred' 取代 |

### 7.5 `journal.metadata` comment 更新

| 改動 | 說明 |
|------|------|
| `committed_task_ids` 廢除 | plan metadata 只保留 `{reasoning}`；task selection tracked in daily_plan_items |

---

## 8. 實施順序建議

| 步驟 | 內容 | 阻擋 |
|------|------|------|
| 1 | 在 VPS 上 run `001_initial.down.sql`（DROP 全部） | 確認可接受資料清零 |
| 2 | Run `001_initial.up.sql`（新 schema） | — |
| 3 | Run `002_seed.up.sql`（seed data） | — |
| 4 | `sqlc generate` | 需要先改所有 query.sql |
| 5 | Go code 改動（type rename, store 方法, handler） | 依 sqlc generated code |
| 6 | MCP server 改動（tool 拆分/改名 + daily plan tools） | 依 store 層完成 |
| 7 | Cron pipeline 重寫（daily plan rollover） | 依 daily plan store 完成 |
| 8 | Cowork instructions 更新 | 依 MCP tool 定案 |
| 9 | README / docs 更新 | 最後 |
