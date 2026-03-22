# koopa0.dev — 數據框架

## Three-Layer Data Architecture

```
Layer 3: Insight Layer
  "我們發現了什麼？我們在驗證什麼假設？"
  ├── session_notes (type=insight)
  └── metadata: {hypothesis, status, evidence}

Layer 2: Metrics Layer
  "Events aggregate 成可比較的指標"
  ├── session_notes (type=metrics)
  └── auto-computed: daily_summary_hint

Layer 1: Event Layer
  "發生了什麼？"
  ├── activity_events (GitHub, Obsidian, manual)
  ├── session_notes (type=plan, type=reflection)
  └── flow_runs (AI pipeline executions)
```

---

### Layer 1: Event Layer（已有，穩定）

**目的**：記錄「發生了什麼」——raw events from all sources。

**來源與儲存**：

| 來源 | Event Type | 儲存 | 範例 |
|------|-----------|------|------|
| GitHub | push, commit | `activity_events` | "Pushed 3 commits to koopa0/blog-backend" |
| Obsidian | note_created, note_updated | `activity_events` | "Updated learning/go-concurrency.md" |
| Manual | session_start, session_end | `activity_events` | "Started work on MCP write tools" |
| Claude | plan, reflection | `session_notes` | Morning plan, evening reflection |
| AI Pipeline | flow execution | `flow_runs` | "content-review completed for article X" |

**Retention**: 永久保留。Events 是 immutable append-only log。

**消費者**：
- `get_recent_activity` MCP tool — Claude 查看最近活動
- `get_morning_context` — 聚合昨天/本週的 activity
- Activity timeline in admin dashboard
- `activity.GroupSessions()` — 用 30 分鐘 gap threshold 重建 work sessions

**Dedup 策略**：
```sql
UNIQUE(source, event_type, source_id) WHERE source_id IS NOT NULL
```

**Key 設計**：
- `metadata` (JSONB) 存放 source-specific 資料（GitHub: lines_added, files_changed; Obsidian: file_path, tags）
- `activity.DiffStats` 解析 GitHub push 的 diff 統計
- Events 可以 tag（`activity_event_tags` M:M → `tags`）

---

### Layer 2: Metrics Layer（補強中）

**目的**：把 Layer 1 的 events aggregate 成可比較的指標。

**來源**：
1. **Claude evening reflection** 寫入 `session_notes(type=metrics)`，包含當日 completion_rate、committed_completion_rate、trend
2. **Auto-computed** `daily_summary_hint`：系統自動算 committed/pulled task 數量，不靠 Claude 手動數

**儲存**：`session_notes` table，`note_type = 'metrics'`

```json
// session_notes.metadata for type=metrics
{
  "planning_history": {
    "committed": 5,
    "pulled_in": 2,
    "completed": 6,
    "completion_rate": 0.86,
    "committed_completion_rate": 1.0
  },
  "capacity_by_day_type": {
    "workday": {"avg_completed": 5.2, "sample_size": 12},
    "weekend": {"avg_completed": 3.1, "sample_size": 6}
  },
  "trend": "stable"
}
```

**Retention**: 永久保留。Metrics 是歷史記錄的一部分。

**消費者**：
- `get_morning_context.planning_history` — Claude 早晨規劃時參考歷史完成率
- Admin dashboard `/admin/planning` — 視覺化趨勢
- `session.MetricsHistory()` — 查詢多天的 metrics 數據

**關鍵指標**：

| 指標 | 計算方式 | 用途 |
|------|---------|------|
| `completion_rate` | completed / (committed + pulled_in) | 整體任務完成率 |
| `committed_completion_rate` | completed_from_committed / committed | 計畫內完成率（排除臨時任務） |
| `capacity_by_day_type` | 按 workday/weekend 分組的平均完成數 | 規劃時估算今天能做多少 |
| `trend` | 近 7 天 vs 前 7 天 | stable / improving / declining |

**Auto-Computed vs Claude-Estimated**：
- `daily_summary_hint`（auto-computed）：系統自動算 committed/pulled task 數量
- `completion_rate`（Claude-computed）：Claude 在 evening reflection 時根據實際結果計算
- 原則：能自動算的就自動算，減少 Claude 手動數的 error

---

### Layer 3: Insight Layer（新增）

**目的**：記錄「我們發現了什麼」和「我們在驗證什麼假設」。

**來源**：Claude morning planning 或 evening reflection 寫入 `session_notes(type=insight)`。

**儲存**：`session_notes` table，`note_type = 'insight'`

```json
// session_notes.metadata for type=insight
{
  "status": "unverified",        // unverified → verified / invalidated → archived
  "hypothesis": "週末的 deep work sessions 比平日長 40%",
  "project": "productivity-tracking",
  "evidence": [
    "2026-03-15: 週六 session 平均 3.2hr vs 平日 1.8hr",
    "2026-03-22: 再次確認，週六 session 3.5hr"
  ]
}
```

**Lifecycle**：

```
         Claude 提出假設
              │
              ▼
        ┌─────────────┐
        │  unverified  │
        └──────┬──────┘
               │  Claude 收集 evidence
          ┌────┴────┐
          ▼         ▼
   ┌──────────┐ ┌─────────────┐
   │ verified │ │ invalidated │
   └────┬─────┘ └──────┬──────┘
        │              │
        │   14 天後     │   14 天後
        ▼              ▼
   ┌──────────────────────┐
   │      archived        │
   └──────────────────────┘
```

**Retention**: verified/invalidated 14 天後自動 archive（`ArchiveStaleInsights` query）。

**消費者**：
- `get_active_insights` MCP tool — Claude 查看當前追蹤的 insights
- `update_insight` MCP tool — Claude 更新 status 和 evidence
- `get_morning_context.active_insights` — 早晨規劃時提醒 Claude 有哪些待驗證假設
- Admin dashboard insight page

**設計考量**：
- 沒有用獨立的 `insights` table——insight 本質上是一種 session note，只是 lifecycle 不同
- JSONB metadata 讓 schema 保持彈性，不同 note_type 有不同 metadata 結構
- Auto-archive 避免 insights 無限累積

---

## Data Quality Principles

### 1. System-Computed > Claude-Estimated > Manual

優先用系統能自動算的數據：

```
最可靠   ← daily_summary_hint（系統算 committed/pulled 數量）
中等可靠 ← completion_rate（Claude 根據結果算，但人工步驟可能遺漏）
最不可靠 ← 手動輸入的 metrics
```

**教訓**（F3 修復）：
- 早期 `get_morning_context` 的 planning_history 讀取邏輯跟 metrics 的寫入 schema 不對齊，導致 null/undefined fields
- 修復：確保 metrics 的 JSONB schema 跟 `get_morning_context` 的讀取邏輯完全對齊
- 原則：**寫入 schema 和讀取邏輯必須同步設計**，不能分開演化

### 2. Closed Loop Integrity

Plan-Execute-Reflect 閉環的每個環節的輸入和輸出必須 match：

| 環節 | 輸入 | 輸出 | 儲存 |
|------|------|------|------|
| Plan (morning) | morning_context（tasks + goals + metrics + insights） | session_note(type=plan) | session_notes |
| Execute (day) | Notion tasks, code, learning | activity_events, completed tasks | activity_events, tasks |
| Reflect (evening) | 今天的 activity + completed tasks + plan | session_note(type=reflection) | session_notes |
| Metrics (evening) | 今天的 completed vs committed | session_note(type=metrics) | session_notes |
| Context (next morning) | 昨天的 metrics + active insights + pending tasks | morning_context tool output | — (computed on read) |

### 3. Event-Sourced Aggregation

Metrics 不是 mutable state——是 events 的 aggregate。如果 metrics 看起來不對，問題在 events 層，不是 metrics 層。

```
activity_events (immutable)  →  session_notes(type=metrics) (immutable snapshot)
                                      ↓
                              get_morning_context (computed on read)
```

---

## Obsidian's Role

### 定位

Obsidian 是**長期知識沉澱**——learning notes, decision logs, technical insights, study notes。

Session notes 是**短期操作紀錄**——today's plan, reflection, metrics, insights。

```
Short-term (session_notes)              Long-term (Obsidian)
├── plan: 今天要做什麼                  ├── go-concurrency.md
├── reflection: 今天做了什麼            ├── decision-log/...
├── metrics: 完成率數據                 ├── system-design/...
└── insight: 正在驗證的假設             └── project-notes/...
```

### 連接

- Verified insights 可以被 promote 成 Obsidian notes（目前手動，未來可自動化）
- Obsidian notes 透過 Git push → webhook → `pipeline/obsidian-sync` 同步到 PostgreSQL
- `obsidian_notes` table 存 metadata + content_hash + embeddings
- `note_links` 表存 wikilink edges，支援 knowledge graph visualization
- Semantic search（pgvector cosine similarity）讓 Claude 檢索 Obsidian 的知識

### 知識流動

```
Obsidian vault (source of truth)
     │
     │ git push → webhook
     ▼
obsidian_notes (PostgreSQL)
     │
     ├── full-text search (TSVECTOR)
     ├── semantic search (pgvector embeddings)
     ├── wikilink graph (note_links)
     └── tag resolution (tag_aliases pipeline)
           │
           ▼
    MCP tools: search_knowledge, semantic_search
           │
           ▼
    Claude retrieves relevant knowledge during sessions
```

---

## Data Model Overview

### Core Tables 一覽

| Table | Layer | 用途 | Key Fields |
|-------|-------|------|-----------|
| `activity_events` | Event | 跨源事件聚合 | source, event_type, metadata(JSONB) |
| `session_notes` | Event/Metrics/Insight | 跨環境上下文橋 | note_type, source, metadata(JSONB) |
| `flow_runs` | Event | AI pipeline 執行紀錄 | flow_name, status, input/output(JSONB) |
| `contents` | Content | 發布的文章/筆記 | slug, type, status, embedding(vector) |
| `obsidian_notes` | Knowledge | Obsidian 同步副本 | file_path, embedding(vector), search_vector |
| `tasks` | Entity | Notion 同步任務 | notion_page_id, status, my_day, recurrence |
| `goals` | Entity | 季度/年度目標 | notion_page_id, status, area, quarter |
| `projects` | Entity | Portfolio 專案 | slug, status, notion_page_id, tech_stack[] |
| `collected_data` | Collection | RSS 收集文章 | relevance_score, status, url_hash |
| `feeds` | Config | RSS 訂閱源 | schedule, filter_config(JSONB), enabled |
| `tags` | Taxonomy | Canonical tag registry | slug, parent_id(hierarchy) |
| `tag_aliases` | Taxonomy | Raw → canonical mapping | raw_tag, match_method, confirmed |
| `topics` | Taxonomy | Content 分類 | slug, sort_order |
| `notion_sources` | Config | Notion DB 註冊 | database_id, role(UNIQUE), sync_mode |

### Search Capabilities

| 搜尋類型 | 技術 | 適用 Table | Index |
|---------|------|-----------|-------|
| Full-text | PostgreSQL TSVECTOR + websearch_to_tsquery | contents, obsidian_notes | GIN |
| Semantic | pgvector cosine similarity (768-dim) | contents, obsidian_notes | HNSW |
| Tag filtering | text[] + GIN index | contents | GIN |
| Exact match | B-tree on slug/id | all | B-tree |
