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

**中期（需改 code，deferred to post-production-mode）：**

4. **加 `target` 欄位** — directive 目前靠 content 裡的文字標明目標部門，應加 DB 欄位讓 query 能 filter by target
5. **加 `status` 欄位** — directive 寫入後狀態是 `pending`，部門讀取後變 `acknowledged`，完成後變 `completed`
6. **加 `parent_id` 欄位** — report 可連結到它回應的 directive，建立因果鏈
7. **加 validation middleware** — 在 MCP 層驗證 content 是否包含必要 section（如 directive 必須有目標部門）

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

## 已知問題

| 問題 | 嚴重度 | 狀態 | 解法 |
|------|--------|------|------|
| Content Studio 用 `"ceo-directive"` 讀 directive — 不在 enum 裡 | **P0** | 需修正 instructions | 改為 `"directive"` |
| Content Studio 用 `"department-output"` 寫 report — 不在 enum 裡 | **P0** | 需修正 instructions | 改為 `"report"` |
| MCP-TOOLS-REFERENCE.md 的 note_type/source enum 過時 | P1 | 需更新文件 | 對齊後端 `write.go:797-808` |
| Desktop Schedule 需聚焦 Cowork view 才觸發 | P2 | Anthropic 已知 bug | 改用 Cloud Schedule |
| Directive 無 target 欄位，靠 content 文字標明 | P3 | 設計限制 | 中期加 DB 欄位（deferred） |

---

## 參考文件

| 文件 | 內容 |
|------|------|
| `docs/TOOLCHAIN-INTEGRATION-REPORT-2026-04-02.md` | 完整工具鏈研究報告 |
| `docs/MCP-TOOLS-REFERENCE.md` | MCP 49 工具完整參考 |
| `docs/AUDIT-REPORT-2026-03-30.md` | 系統現況審計報告 |
| `internal/mcp/write.go:786-809` | `save_session_note` validation（enum 權威來源） |
| `internal/mcp/search.go:1014` | `session_notes` query validation |
