# Schema Audit — 2026-04-02

> 全表語義審查。趁資料接近零，一次處理所有命名和結構問題。

---

## 審查範圍

Migration：`migrations/001_initial.up.sql`（唯一 migration file）
表數量：20 tables + 2 views + 8 enums

---

## P0：結構性拆分（已決策）

### `session_notes` → `messages` + `journal` + `insights`

見 `docs/Ipc protocol decision doc final.md`。三表設計已確定，不重複。

---

## P1：表改名

### `collected_data` → `feed_entries`

| 項目 | 說明 |
|------|------|
| **問題** | `collected_data` 是 generic 名詞，不表達這是 RSS feed 收集的文章 |
| **Go code** | package 已經叫 `internal/feed/entry/`，Go 層已用 `entry` 語義 |
| **業界慣例** | Miniflux（Go + PostgreSQL）用 `entries`，Atom spec 用 `entry`，RSS spec 用 `item` |
| **決定** | `feed_entries` — 加 `feed_` prefix 因為 `entries` 太 generic |
| **影響** | `internal/feed/entry/query.sql` 裡的表名、sqlc generated code、migrations |

### `tracking_topics` → 保留但加 COMMENT

| 項目 | 說明 |
|------|------|
| **問題** | 和 `topics` 表容易混淆，零 COMMENT |
| **Go code** | `internal/monitor/` 有完整 CRUD，routes 掛在 `/api/admin/tracking`，main.go 有 wiring。**在用，不能 DROP** |
| **語義區分** | `topics` = 靜態的知識領域分類（Go, AI, System Design）。`tracking_topics` = 主動監測的關鍵字組合，驅動 web scraping/API 收集 |
| **決定** | 保留表名（改名影響 routes + monitor package），但加完整 COMMENT |

---

## P2：統一身份模型

### 現狀：3 套獨立的 actor vocabulary

| 位置 | 值 | 語義 |
|------|-----|------|
| `session_notes.source` CHECK | `claude, claude-code, manual, hq, content-studio, research-lab, learning-studio` | 「誰寫了這筆 note」 |
| `tasks.assignee` CHECK | `human, claude-code, cowork` | 「誰來做這個 task」 |
| `contents.source_type` ENUM | `obsidian, notion, ai-generated, external, manual` | 「內容從哪來」 |

三套各自定義，沒有共享。`claude-code` 出現在兩個地方但 CHECK 不同。

### 統一身份層次

```
participant (lookup table)
├── role: 'human'
│   └── human
├── role: 'department'
│   ├── hq
│   ├── content-studio
│   ├── research-lab
│   └── learning-studio
└── role: 'agent'
    ├── claude-code
    ├── claude-web
    ├── claude-cowork
    └── claude（generic fallback）
```

**注意**：原本的 `role` 值 `executor` 改為 `agent` — 更準確描述 AI 執行者身份，不和 human 混淆。`manual` 合併到 `human`（手動操作就是人類操作）。

### 各表如何引用

| 表 | 欄位 | FK 到 participant | 限制 |
|----|------|-------------------|------|
| `messages` | `source` | FK | 所有 role |
| `messages` | `target` | FK | 僅 `role = 'department'`（Go 層 validate） |
| `messages` | `acknowledged_by` | FK | 僅 `role = 'department'` |
| `journal` | `source` | FK | 所有 role |
| `insights` | `source` | FK | 所有 role |
| `tasks` | `assignee` | FK | 所有 role（human, agent, department 都可能是 assignee） |

### `contents.source_type` 不整合

`source_type` 的語義是「內容來源系統」（obsidian, notion），不是「誰」。跟 participant 是不同維度。保持獨立 ENUM。

---

## P3：空字串 → NULL

### 現狀

```sql
-- tasks
energy   TEXT NOT NULL DEFAULT '' CHECK (energy IN ('', 'high', 'medium', 'low')),
priority TEXT NOT NULL DEFAULT '' CHECK (priority IN ('', 'high', 'medium', 'low')),
recur_unit TEXT NOT NULL DEFAULT '' CHECK (recur_unit IN ('', 'days', 'weeks', ...)),
assignee TEXT NOT NULL DEFAULT 'human' CHECK (assignee IN ('human', 'claude-code', 'cowork')),

-- projects
expected_cadence TEXT NOT NULL DEFAULT 'weekly' CHECK (expected_cadence IN ('', 'daily', ...)),
```

### 問題

`''`（空字串）和 `NULL` 語義不同：
- `NULL` = 「未設定」「不適用」
- `''` = 「我刻意選了空」

用 `''` 做 default 是 Go zero-value 的便利性推動的，但語義錯誤。

### 改法

```sql
-- 改為 nullable，去掉空字串
energy   TEXT CHECK (energy IN ('high', 'medium', 'low')),     -- NULL = 未設定
priority TEXT CHECK (priority IN ('high', 'medium', 'low')),   -- NULL = 未設定
recur_unit TEXT CHECK (recur_unit IN ('days', 'weeks', 'months', 'years')), -- NULL = 不循環

-- Go 層：string → *string（sqlc 自動處理 nullable）
```

`expected_cadence` 類似處理。`assignee` 保持 NOT NULL DEFAULT 'human' — 每個 task 必須有 assignee。

### Go 影響

sqlc 會生成 `*string` 代替 `string`。所有讀寫這些欄位的 Go code 需要處理 nil。影響範圍：
- `internal/task/task.go`（struct 定義）
- `internal/task/store.go`（type conversion）
- `internal/task/handler.go`（API response）
- `internal/mcp/write.go`、`search.go`（MCP tools）

成本不低但你說不管成本。既然資料可以 DROP 重建，就做。

---

## P4：欄位命名和 COMMENT 補充

### `projects` — PARA 模型

| 欄位 | 問題 | 修正 |
|------|------|------|
| `role` | 使用者在專案中扮演的角色？完全沒 COMMENT | 加 COMMENT：`使用者在此專案中的角色（如 Lead Engineer, Sole Developer）` |
| `area` | PARA 的 Area？沒 COMMENT | 加 COMMENT：`PARA methodology Area — 長期持續的責任領域（如 Backend, Learning, Studio）` |

### `obsidian_notes` — 多欄位缺 CHECK 和 COMMENT

| 欄位 | 問題 | 修正 |
|------|------|------|
| `type` | 無 CHECK，有效值是什麼？ | 需要你確認有效值，加 CHECK |
| `source` | 第 N 個 `source` 欄位，和其他表語義不同 | 加 COMMENT 說明這是「Obsidian 筆記的來源上下文」（如 book, course, project） |
| `context` | 什麼 context？ | 加 COMMENT |
| `difficulty` | LeetCode difficulty？無 CHECK | 如果是 LeetCode，加 CHECK IN ('easy', 'medium', 'hard') |
| `tags` JSONB | 為什麼不用 junction table？ | 已有 COMMENT 說明是 raw frontmatter，mapping 在 `obsidian_note_tags`。保持 |

### `activity_events` — 缺 CHECK 和 COMMENT

| 欄位 | 問題 | 修正 |
|------|------|------|
| `event_type` | 無 CHECK。有效值？ | 需要你確認：github-push, github-pr, notion-update, obsidian-sync...? |
| `source` | 另一個 `source`，語義是「事件來源系統」 | 加 COMMENT 區分：這是 event source（github, notion），不是 participant |
| `project` | TEXT，應該是 FK 到 projects？ | 檢查是否可以加 FK |
| `repo` | 什麼 repo？ | 加 COMMENT |
| `ref` | Git ref？ | 加 COMMENT |

### `tracking_topics`

| 欄位 | 問題 | 修正 |
|------|------|------|
| 整張表 | 0 個 COMMENT | 加 TABLE COMMENT + 每個欄位 COMMENT |
| 和 `topics` 關係 | 無文件 | COMMENT 說明：tracking_topics 驅動主動監測，topics 是知識分類 |

---

## P5：Enum 整理

### 現有 enum 類型（CREATE TYPE ... AS ENUM）

| Enum | 值 | 用在 |
|------|-----|------|
| `content_type` | article, essay, build-log, til, note, bookmark, digest | contents.type |
| `content_status` | draft, review, published, archived | contents.status |
| `source_type` | obsidian, notion, ai-generated, external, manual | contents.source_type |
| `review_level` | auto, light, standard, strict | contents.review_level, review_queue.review_level |
| `review_status` | pending, approved, rejected, edited | review_queue.status |
| `collected_status` | unread, read, curated, ignored | collected_data.status |
| `flow_status` | pending, running, completed, failed | flow_runs.status |
| `goal_status` | not-started, in-progress, done, abandoned | goals.status |
| `project_status` | planned, in-progress, on-hold, completed, maintained, archived | projects.status |
| `task_status` | todo, in-progress, done | tasks.status |

### 問題

`collected_status` → 如果表改名為 `feed_entries`，enum 應改名為 `feed_entry_status`。

其他 enum 命名合理，不改。

---

## P6：`contents.source` 欄位混淆

| 欄位 | 語義 |
|------|------|
| `contents.source` | 原始來源的 identifier（如 Obsidian file path, URL） |
| `contents.source_type` | 原始來源的系統分類（obsidian, notion, manual） |

兩個欄位語義接近，名字容易混淆。更好的命名：
- `source` → `origin`（原始來源 identifier）
- `source_type` → 保持（或 `origin_type`）

**但改名成本高**（影響所有 content 相關 query + MCP tools），且不會造成 bug。**記錄但不在這次改。**

---

## 改動清單（按優先序）

### 必做（結構性）

| # | 改動 | 影響 |
|---|------|------|
| 1 | `session_notes` 拆為 `messages` + `journal` + `insights` | 新表 + 資料遷移 + DROP 舊表 |
| 2 | `participant` lookup table（含 `role`） | 新表 + FK |
| 3 | `collected_data` → `feed_entries` | ALTER TABLE RENAME |
| 4 | `collected_status` enum → `feed_entry_status` | ALTER TYPE RENAME |
| 5 | `tasks.assignee` → FK 到 `participant` | DROP CHECK + ADD FK |
| 6 | 空字串 → NULL（tasks: energy, priority, recur_unit; projects: expected_cadence） | ALTER COLUMN + DROP CHECK + 新 CHECK |

### 應做（語義完善）

| # | 改動 | 影響 |
|---|------|------|
| 7 | `tracking_topics` 加完整 COMMENT | COMMENT ON TABLE/COLUMN |
| 8 | `projects.role`, `projects.area` 加 COMMENT | COMMENT ON COLUMN |
| 9 | `obsidian_notes` 多欄位加 CHECK + COMMENT | 需確認有效值 |
| 10 | `activity_events` 多欄位加 COMMENT | COMMENT ON COLUMN |

---

## 待你確認

| # | 問題 | 需要你回答 |
|---|------|-----------|
| 1 | `obsidian_notes.type` 的有效值是什麼？ | 看 Go code 或 Obsidian frontmatter |
| 2 | `obsidian_notes.source` 的語義是什麼？ | book name? course name? |
| 3 | `obsidian_notes.context` 的語義是什麼？ | 什麼 context? |
| 4 | `obsidian_notes.difficulty` 是否只用於 LeetCode？ | 加 CHECK? |
| 5 | `activity_events.event_type` 的有效值？ | 需要列出 |
| 6 | `activity_events.project` 是否應該 FK 到 `projects`？ | 或者是 free text 因為可能不在 projects 表？ |
| 7 | `participant` 的 `role` 用 `agent` 還是 `executor`？ | 我建議 `agent` |
| 8 | `manual` 是否合併到 `human`？ | 或保持為獨立 participant？ |

---

## 資料來源

- [Miniflux — Go RSS Reader, uses `entries` table](https://github.com/miniflux/v2)
- [FreshRSS — uses `entry` table](https://deepwiki.com/FreshRSS/FreshRSS/5.1-database-schema)
- [Atom spec — `entry` element](https://www.rfc-editor.org/rfc/rfc4287#section-4.1.2)
- [Google Reader API — `items` concept](https://www.davd.io/posts/2025-02-05-reimplementing-google-reader-api-in-2025/)
