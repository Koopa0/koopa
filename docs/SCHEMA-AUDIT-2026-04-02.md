# Schema Audit — 2026-04-02

> 全表語義審查。資料接近零，一次處理所有命名、結構和正規化問題。

---

## 審查範圍

Migration：`migrations/001_initial.up.sql`（唯一 migration file）
表數量：20 tables + 2 views + 8 enums

---

## 1. 結構性拆分

### 1.1 `session_notes` → `messages` + `journal` + `insights`

已決策。見 `docs/Ipc protocol decision doc final.md`。

- `messages`：directive, report（IPC 層，有 target/priority/acknowledged_at/in_response_to）
- `journal`：plan, context, reflection, metrics（session 日誌層）
- `insights`：insight（知識層，hypothesis/status 升格為 column）

---

## 2. Topic 正規化

### 2.1 現狀：5 個地方各自定義 "topic"

```
topics                   → 正規 table（UUID, slug, name）           ✅ canonical
content_topics           → junction table（content ↔ topics）       ✅ 正確
feeds.topics             → TEXT[] 陣列，"must match topics.slug"    ❌ 沒 FK
collected_data.topics    → TEXT[] 陣列，同上                        ❌ 沒 FK
tracking_topics          → 完全獨立的表                              ❌ 沒關聯到 topics
```

### 2.2 正規化設計

```
topics (single source of truth)
│
├── content_topics     (junction: content ↔ topic)     ✅ 已有，不動
├── feed_topics        (junction: feed ↔ topic)        ← 取代 feeds.topics TEXT[]
└── topic_monitors     (1:1 monitoring config)         ← 取代 tracking_topics
```

**`feed_entry_topics` 不建** — entry 透過 `feed_entries.feed_id` JOIN `feed_topics` 繼承 feed 的 topics。一層就夠，不需要多一層 junction。如果未來需要 entry-level 精細度，放 `feed_entries.metadata` JSONB。

### 2.3 改動明細

#### `feeds.topics TEXT[]` → `feed_topics` junction

```sql
CREATE TABLE feed_topics (
    feed_id  UUID NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    topic_id UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (feed_id, topic_id)
);
CREATE INDEX idx_feed_topics_topic ON feed_topics(topic_id);
```

刪除 `feeds.topics` 欄位。現有資料 backfill：用 `topics.slug` 做 lookup。

#### `collected_data.topics TEXT[]` → 刪除

Entry 透過 feed 繼承 topics，不需要自己的 topics 欄位。Relevance scoring 的 topic 匹配結果放 `feed_entries.metadata` 的 `matched_topics` key（如有需要）。

#### `tracking_topics` → `topic_monitors`

```sql
CREATE TABLE topic_monitors (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    topic_id   UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    keywords   TEXT[] NOT NULL DEFAULT '{}',
    sources    TEXT[] NOT NULL DEFAULT '{}',
    schedule   TEXT NOT NULL DEFAULT '0 */6 * * *',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(topic_id)
);

COMMENT ON TABLE topic_monitors IS '針對特定 topic 的主動監測規則。keywords 驅動 web search，schedule 控制頻率。一個 topic 最多一個 monitor。';
```

`tracking_topics.name` 消失 — name 就是 `topics.name`，不重複儲存。

Go 影響：`internal/monitor/` package 的 Store/Handler 需要改 query（JOIN topics）。Routes 可以保持 `/api/admin/tracking`。

---

## 3. 表改名

### 3.1 `collected_data` → `feed_entries`

| 項目 | 說明 |
|------|------|
| **問題** | `collected_data` generic，不表達這是 RSS feed 收集的文章 |
| **Go code** | package 已叫 `internal/feed/entry/`，Go 層已用 `entry` 語義 |
| **業界慣例** | Miniflux（Go + PostgreSQL）：`entries`；Atom spec：`entry`；RSS spec：`item` |
| **決定** | `feed_entries` — 加 `feed_` prefix 避免 `entries` 太 generic |

### 3.2 `collected_status` enum → `feed_entry_status`

配合表改名，enum 也正名。

---

## 4. 統一身份模型

### 4.1 現狀：3 套獨立的 actor vocabulary

| 位置 | 值 | 語義 |
|------|-----|------|
| `session_notes.source` CHECK | claude, claude-code, manual, hq, content-studio, research-lab, learning-studio | 「誰寫了這筆 note」 |
| `tasks.assignee` CHECK | human, claude-code, cowork | 「誰來做這個 task」 |
| `contents.source_type` ENUM | obsidian, notion, ai-generated, external, manual | 「內容從哪來」 |

三套各自定義，`claude-code` 出現在兩處但 CHECK 不同。

### 4.2 設計：`participant` lookup table

```sql
CREATE TABLE participant (
    name TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('human', 'department', 'agent'))
);

INSERT INTO participant(name, role) VALUES
    ('human', 'human'),
    ('hq', 'department'),
    ('content-studio', 'department'),
    ('research-lab', 'department'),
    ('learning-studio', 'department'),
    ('claude', 'agent'),
    ('claude-code', 'agent'),
    ('claude-web', 'agent'),
    ('claude-cowork', 'agent');
```

- `role = 'human'`：人類操作者（合併原本的 `manual`）
- `role = 'department'`：Cowork 部門（directive target / report source / acknowledge 主體）
- `role = 'agent'`：AI 執行者（描述「誰在操作」）

### 4.3 各表引用

| 表 | 欄位 | FK 到 participant | Go 層限制 |
|----|------|-------------------|-----------|
| `messages` | `source` | FK | 所有 role |
| `messages` | `target` | FK | 僅 department |
| `messages` | `acknowledged_by` | FK | 僅 department |
| `journal` | `source` | FK | 所有 role |
| `insights` | `source` | FK | 所有 role |
| `tasks` | `assignee` | FK | 所有 role |

### 4.4 不整合的：`contents.source_type`

`source_type` ENUM（obsidian, notion, ai-generated, external, manual）的語義是「內容來源系統」，不是「誰」。和 participant 是不同維度。保持獨立 ENUM。

---

## 5. 空字串 → NULL

### 5.1 現狀

4 個欄位用 `''` 代替 `NULL` 表示「未設定」：

```sql
-- tasks
energy     TEXT NOT NULL DEFAULT '' CHECK (energy IN ('', 'high', 'medium', 'low'))
priority   TEXT NOT NULL DEFAULT '' CHECK (priority IN ('', 'high', 'medium', 'low'))
recur_unit TEXT NOT NULL DEFAULT '' CHECK (recur_unit IN ('', 'days', 'weeks', 'months', 'years'))

-- projects
expected_cadence TEXT NOT NULL DEFAULT 'weekly' CHECK (expected_cadence IN ('', 'daily', 'weekly', 'biweekly', 'monthly'))
```

### 5.2 問題

`NULL` = 未設定。`''` = 刻意選了空。Go zero-value 便利性推動的語義錯誤。

### 5.3 改法

```sql
energy           TEXT CHECK (energy IN ('high', 'medium', 'low')),
priority         TEXT CHECK (priority IN ('high', 'medium', 'low')),
recur_unit       TEXT CHECK (recur_unit IN ('days', 'weeks', 'months', 'years')),
expected_cadence TEXT CHECK (expected_cadence IN ('daily', 'weekly', 'biweekly', 'monthly')),
```

全部 nullable，NULL = 未設定。`assignee` 保持 NOT NULL DEFAULT 'human'（task 必須有 assignee），改 FK 到 `participant`。

Go 影響：`string` → `*string`（sqlc nullable handling）。影響 `internal/task/`、`internal/mcp/`。

---

## 6. 欄位 COMMENT 補充

### 6.1 `projects`（PARA 模型）

```sql
COMMENT ON COLUMN projects.role IS '使用者在此專案中扮演的角色（如 Lead Engineer, Sole Developer）。';
COMMENT ON COLUMN projects.area IS 'PARA methodology Area — 長期持續的責任領域（如 Backend, Learning, Studio）。';
```

### 6.2 `obsidian_notes`

| 欄位 | 修正 |
|------|------|
| `type` | 需確認有效值後加 CHECK + COMMENT |
| `source` | 加 COMMENT：筆記的來源上下文（book title, course name），不是 participant |
| `context` | 加 COMMENT（需確認語義） |
| `difficulty` | 若僅 LeetCode 用，加 CHECK IN ('easy', 'medium', 'hard') + COMMENT |

### 6.3 `activity_events`

| 欄位 | 修正 |
|------|------|
| `event_type` | 需確認有效值後加 CHECK + COMMENT |
| `source` | 加 COMMENT：事件來源系統（github, notion），不是 participant |
| `project` | 加 COMMENT。考慮是否改為 FK（可能是 free text，Notion project 名可能不在 projects 表） |
| `repo` | 加 COMMENT：GitHub repository full name（如 Koopa0/koopa0.dev） |
| `ref` | 加 COMMENT：Git ref（branch name or tag） |

### 6.4 `topic_monitors`（取代 `tracking_topics`）

新表自帶完整 COMMENT（見 §2.3）。

---

## 7. Enum 整理

| 現有 Enum | 改動 |
|-----------|------|
| `collected_status` | → `feed_entry_status`（配合表改名） |
| 其他 9 個 enum | 命名合理，不改 |

---

## 8. 記錄但不改

| 項目 | 原因 |
|------|------|
| `contents.source` 欄位名混淆（vs `source_type`） | 改名成本高，不造成 bug |
| `projects.tech_stack TEXT[]` | 原子值，不是 FK reference，array 合理 |
| `projects.highlights TEXT[]` | 同上 |
| `topic_monitors.keywords TEXT[]` | 搜尋關鍵字，原子值 |
| `topic_monitors.sources TEXT[]` | 來源 URL，原子值 |

---

## 9. 全部改動清單

### 結構性改動

| # | 改動 | 類型 |
|---|------|------|
| 1 | `session_notes` 拆為 `messages` + `journal` + `insights` | 拆表 |
| 2 | 建 `participant` lookup table（name, role） | 新表 |
| 3 | 建 `feed_topics` junction table | 新表 |
| 4 | 建 `topic_monitors`（取代 `tracking_topics`） | 新表 + DROP 舊表 |
| 5 | `collected_data` → `feed_entries` | 改名 |
| 6 | `collected_status` → `feed_entry_status` | 改名 |
| 7 | 刪除 `feeds.topics TEXT[]` 欄位 | DROP COLUMN |
| 8 | 刪除 `feed_entries.topics TEXT[]` 欄位（原 `collected_data.topics`） | DROP COLUMN |
| 9 | `tasks.assignee` CHECK → FK 到 `participant` | DROP CHECK + ADD FK |
| 10 | DROP `session_notes.source` CHECK → FK 到 `participant` | DROP CHECK + ADD FK |
| 11 | 空字串 → nullable（tasks: energy/priority/recur_unit; projects: expected_cadence） | ALTER COLUMN |

### 語義完善

| # | 改動 | 類型 |
|---|------|------|
| 12 | `projects.role`, `projects.area` 加 COMMENT | COMMENT |
| 13 | `obsidian_notes` 多欄位加 CHECK + COMMENT | COMMENT + CHECK |
| 14 | `activity_events` 多欄位加 COMMENT | COMMENT |

### 資料遷移

| # | 步驟 |
|---|------|
| 15 | `session_notes` → INSERT INTO messages/journal/insights → DROP session_notes |
| 16 | `feeds.topics TEXT[]` → INSERT INTO feed_topics → DROP feeds.topics |
| 17 | `tracking_topics` → INSERT INTO topic_monitors（JOIN topics by name/slug）→ DROP tracking_topics |
| 18 | Backfill: tasks/projects 空字串 → NULL |
| 19 | Backfill: messages (directive) 補 target + priority |

---

## 10. 待確認

| # | 問題 |
|---|------|
| 1 | `obsidian_notes.type` 有效值？ |
| 2 | `obsidian_notes.source` 語義？（book name? course name?） |
| 3 | `obsidian_notes.context` 語義？ |
| 4 | `obsidian_notes.difficulty` 僅 LeetCode 用？ |
| 5 | `activity_events.event_type` 有效值？ |
| 6 | `activity_events.project` 是否改 FK 到 `projects`？（可能有不在 projects 表的值） |
| 7 | `participant.role` 用 `agent` 還是 `executor`？（建議 `agent`） |
| 8 | `manual` 合併到 `human` 還是保持獨立？（建議合併） |
| 9 | `tracking_topics` 的現有資料能否對應到 `topics` 表？（需確認 name 是否 match） |

---

## 資料來源

- [Miniflux — Go RSS Reader, `entries` table](https://github.com/miniflux/v2)
- [FreshRSS — `entry` table](https://deepwiki.com/FreshRSS/FreshRSS/5.1-database-schema)
- [Atom spec — `entry` element](https://www.rfc-editor.org/rfc/rfc4287#section-4.1.2)
- [Google Reader API — `items` concept](https://www.davd.io/posts/2025-02-05-reimplementing-google-reader-api-in-2025/)
