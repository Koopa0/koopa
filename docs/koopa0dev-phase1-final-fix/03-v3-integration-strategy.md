# koopa0.dev 整合策略與功能規劃

> **版本**: v3.0  
> **日期**: 2026-03-12  
> **狀態**: 規劃文件（Reference — 按需查閱，不需通讀）
> **適用範圍**: koopa0.dev × Notion UB3.0 × Obsidian × GitHub × Genkit × Cloudflare

---

## 1. 核心定位與系統分工

### 1.1 三系統定位

| 系統 | 職責 | 資料性質 |
|------|------|----------|
| **Notion UB3.0** | 「做了什麼」— What & When | 結構化：Tasks、Projects、Goals、Books、Tags、People |
| **Obsidian** | 「學了什麼」— How & Why | 非結構化：解題筆記、讀書筆記、AI 討論記錄、技術深潛、decision log |
| **koopa0.dev** | 「整合 + 歸納 + 展示 + 行動」 | 聚合資料、Genkit 智慧分析、Blog 發佈、通知推送、MCP context provider |

### 1.2 關鍵原則

**Notion 管「寫入結構化資料」，Obsidian 管「寫入知識」，koopa0.dev 只做「讀取 + 分析 + 展示 + 推送」。**

koopa0.dev 不作為輸入源。唯一的「寫回」行為是 Genkit 產生的 review/report，寫回目標也是 Notion Notes 或 Obsidian vault，不是 koopa0.dev 自己的 DB。Blog 發佈的 source 是 Obsidian 的 `status: published` 筆記，koopa0.dev 只負責 render 和 serve。

---

## 2. 現有基建盤點（已完成）

- **Notion sync**: API polling + webhook
- **Obsidian sync**: Vault → git push → GitHub webhook → koopa0.dev
- **GitHub webhook**: Activity events 收集
- **LINE Bot / Telegram Bot**: 通知推送管道
- **Genkit flows**: 基礎歸納與分析 flow 已運行
- **可觀測性**: Prometheus + Grafana + Loki
- **安全防護**: Cloudflare 完整配置
- **Blog 系統**: 已上線

---

## 3. 資料管線架構

### 3.1 Unified Activity Events Table

```sql
CREATE TABLE activity_events (
    id          BIGSERIAL PRIMARY KEY,
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
```

**Event sources:**

| Source | Event Types | 觸發方式 |
|--------|------------|----------|
| GitHub | push, pull_request, issue, issue_comment | Webhook |
| Notion | task_status_change, project_update, book_progress, goal_update | API polling (5-15 min) |
| Obsidian | note_created, note_updated | Git log parse |

### 3.2 Obsidian Frontmatter 標準化

```yaml
---
type: leetcode | book-note | ardan-note | blog-draft | learning-log | decision-log | dev-log | weekly-review
source: leetcode | oreilly | ardanlabs | claude | self
context: resonance | koopa-blog | koopa0dev | novel | leetcode | general
tags: [array, dp, binary-search]
status: seed | sapling | tree | published
created: 2026-03-12
# === LeetCode 專用 ===
leetcode_id: 42
difficulty: easy | medium | hard
# === 讀書筆記專用 ===
book: "Designing Data-Intensive Applications"
chapter: "Chapter 5"
# === Decision Log 專用 ===
decision: "SSE broker 改用 channel per client"
alternatives_considered: "shared channel with mutex, sync.Pool"
trade_offs: "memory 增加但 contention 消失"
related_pr: "resonance#42"
notion_task_id: ""
---
```

### 3.3 Obsidian Notes Table

```sql
CREATE TABLE obsidian_notes (
    id              BIGSERIAL PRIMARY KEY,
    file_path       TEXT UNIQUE NOT NULL,
    title           TEXT,
    type            TEXT,
    source          TEXT,
    context         TEXT,
    status          TEXT DEFAULT 'seed',
    tags            JSONB,
    difficulty      TEXT,
    leetcode_id     INT,
    book            TEXT,
    chapter         TEXT,
    notion_task_id  TEXT,
    content_text    TEXT,
    content_hash    TEXT,
    embedding       vector(1536),  -- NOTE: 決策報告修正為 vector(768)
    git_created_at  TIMESTAMPTZ,
    git_updated_at  TIMESTAMPTZ,
    synced_at       TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 4. Notion UB3.0 深度整合

### 4.2 建議新增的 Notion 配置

**LeetCode Practice Project:** 在 Projects 建 "LeetCode Practice"，每題一個 Task，Labels 放難度。

**Notes Database Publish 機制:** 加 `Visibility` select：Draft / Published / Unlisted。

**Work Sessions 啟用:** Tasks 的 Sessions relation + Start/End button。

### 4.3 People Database 作為 Freelance CRM

每個 client 建成 People record，koopa0.dev 追蹤「上次互動距今 N 天」。（決策報告：推遲到 client > 5 個時再做。）

### 4.5 Notion Agent 與 Genkit 的分工策略

Notion Agent 負責 Notion 內部自動化（task 分類、project status 更新）。Genkit 負責跨系統智慧分析（activity correlation、語意搜尋、content pipeline）。免費期至 2026-05-03，不把 critical path 依賴放上去。

---

## 5. Genkit Flow 規劃

### 5.1 Daily Flows

#### 5.1.1 Daily Dev Log 自動生成

**觸發**: 每日 23:00 cron
**資料源**: 當天的 activity_events
**輸出**: Obsidian note (`type: dev-log`) + LINE 摘要

### 5.2 Weekly Flows

#### 5.2.1 統一週報

**觸發**: 每週日 20:00
**資料源**: 全部 — Notion + Obsidian + GitHub
**輸出**: LINE digest + Notion Note + Obsidian note

#### 5.2.2 Drift Detection

計算各 Project/Tag 的 activity 佔比，跟 Goals priority 比對。

#### 5.2.3 Knowledge Graph 分析

Wikilink parse → 孤島偵測、cluster 分析、action item 偵測。

### 5.3 Monthly Flows

#### 5.3.1 Retrospective Intelligence

Pattern detection across time。

#### 5.3.4 Personal Changelog 自動生成

從 activity_events 聚合，零維護。

---

## 11. Obsidian 生態系統善用

### 11.1 Bases

建議：LeetCode Base、Book Notes Base、Decision Log Base、Blog Pipeline Base。

### 11.3 建議插件配置

| 插件 | 用途 | 必要性 |
|------|------|--------|
| Obsidian Git | auto commit/push | 高 |
| Linter | frontmatter 格式 | 高 |
| Templater | 筆記 template | 高 |
| Dataview | 複雜 query | 中 |

---

## 13. 寫回機制設計

### 13.1 koopa0.dev → Obsidian 寫回

Genkit → .md 檔 → git commit + push → Obsidian sync。Commit message 標記 `[koopa0.dev-auto]`。Webhook handler 忽略自己的 push event。

---

## 16. 技術提案評審

### 16.1 Go-based Delta Map-Reduce

**結論：Aggregation 做，Filter/Compress 不做。**

### 16.2 MCP Server Hybrid Search (pgvector + tsvector + RRF)

**結論：採納。** tsvector 用 `simple` configuration。CamelCase preprocessing 在 Go 端做。HNSW 而非 IVFFlat。加第三路 signal：Frontmatter Exact Match。

### 16.3 Rust Worker

**結論：不做。**

---

## 17. 戰略決策記錄

### 17.1 拒絕 ActivityWatch / WakaTime

**決策：產出導向時間追蹤。** 緩解：activity_events metadata 存 diff stats，計算 churn ratio。

**行動項：GitHub webhook handler 增加 diff stats extraction。**

### 17.2 拒絕 Readwise

**決策：手動高 SNR 輸入。**

### 17.3 拒絕 Linear，堅持 Notion UB3.0

**決策：Notion 覆蓋 100%。**

**緩解方案：** PR merge webhook → 自動更新 Notion Task status。Branch naming convention：`feat/<notion-task-id>-<short-description>`。

**「必須在 Phase 1 實作，否則 data integrity 會腐爛。」**

---

## 18. 設計哲學總結

1. **寧可少一個 data source，也不要多一層 integration complexity。**
2. **能用一個 SQL query 解決的就不要建 pipeline，能用 Go 標準庫解決的就不要引入新語言。**
3. **Go code 做 LLM 做不好的事，LLM 做 Go code 做不好的事。**

---

## 19. Genkit Pipeline Audit 結論

### 19.1 整體評估

| 維度 | 評分 |
|------|------|
| 架構穩健性 | **A** |
| Prompt 工程深度 | **B-** |
| Tool 整合 | **C** |
| Flow 語意設計 | **B** |
| 生產穩定性 | **A-** |
| 成本控制 | **A** |

### 19.2 修正版行動優先級

**P0（立即修復）：** Temperature 修正（build-log 0.6→0.3, bookmark 0.5→0.3）。`GenerateData[T]()` 替換。JSON 容錯 parser（`RobustUnmarshal`）。Content policy permanent fail。

**P1（短期改善）：** `review.txt` 擴充。`tags.txt` 擴充。`excerpt.txt` 擴充。

**P2（中期優化）：** Flow 拆分（content-proofread / content-metadata / content-embed）。Prompt template injection。Token usage logging。content-strategy 分工。

**P3（長期考慮）：** Eval 框架。search tool。Flow composition。Model fallback。
