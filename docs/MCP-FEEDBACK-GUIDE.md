# MCP 工具回饋指南

> 給所有 MCP 使用方（hq, content-studio, research-lab, learning-studio, claude-code）
> 你們是工具的設計合作者。每次使用 MCP 都是一次需求發現的機會。

---

## 何時記錄回饋

當你遇到以下情況時，停下來記錄：

- **缺少工具**：你想做一件事但沒有工具可用（手動做了 → 應該是一個 tool）
- **不順暢**：完成一個操作需要太多步驟（3+ tool calls → 該合併）
- **資訊不足**：工具回傳的資料不夠你做決策（欄位缺失、缺少 context）
- **語意不清**：工具名稱或參數讓你困惑（不確定該用哪個 tool）
- **權限障礙**：你有權做某件事但 capability 不對
- **新場景**：你發現一個有價值的新工作流

---

## 如何記錄

### 方式一：Journal（快速記錄，低門檻）

```
write_journal(
  as: "[你的 participant name]",
  kind: "context",
  content: "## MCP 回饋\n**場景**: [你想做什麼]\n**目前做法**: [現在怎麼做，或做不到]\n**建議**: [新 tool / 修改 / 合併]\n**優先級**: P0(阻塞) / P1(每天遇到) / P2(偶爾)"
)
```

### 方式二：Insight（追蹤假說，有驗證生命週期）

適合需要觀察一段時間才能確認的設計假說：

```
propose_commitment(
  as: "[你的 participant name]",
  type: "insight",
  fields: {
    hypothesis: "如果加一個 list_tasks tool，HQ 的晨間流程可以減少 2 步",
    invalidation_condition: "如果 morning_context 已經涵蓋了所有 task 查詢需求",
    content: "[觀察的具體情況]"
  }
)
```

---

## 回饋分類

| 類別 | 例子 | 記錄方式 |
|------|------|----------|
| Missing tool | 「我想列出所有 inbox 任務但沒有工具」 | Journal (P1) |
| Broken workflow | 「plan_day 的 items 傳不進去」 | Journal (P0) — 這是 bug |
| DX 改善 | 「priority 要傳 high/medium/low 但我習慣說 p1/p2/p3」 | Journal (P2) |
| 新場景 | 「我想把學習 session 和 content 發布連結起來」 | Insight |
| 資訊缺口 | 「morning_context 沒有顯示我發出的 directives」 | Journal (P1) |
| 合併建議 | 「session_delta 和 morning_context 其實可以合併」 | Insight |

---

## 已知的 Gap（歡迎補充）

來自 HQ 驗證測試的發現：

1. **`list_tasks`** — 沒有工具可以列出所有任務。`morning_context` 只看今天相關的，`session_delta` 只看 24h。想查「所有 inbox 任務」或「所有 in-progress 任務」做不到。

2. **`list_directives`** — HQ 發出 directive 後，沒有工具追蹤「我發過哪些 directive」。`morning_context` 顯示收到的，不是發出的。

3. **`list_participants`** — 看不到有哪些 participant、各自的 capabilities。

4. **`delete/archive`** — 測試用的 task/goal/content 無法清理。

5. **Content review 分派** — `review_queue` 表存在但沒有 MCP tool。

---

## 流程

```
Participant 使用工具 → 發現 gap → 記錄 journal/insight
  → Koopa 在 weekly_summary 或 reflection_context 看到
  → 決定是否加入開發計劃
  → Claude Code 實作 → 下一輪測試
```

回饋不會消失 — 它會透過 journal 和 insight 留在系統裡，被 weekly review 撈出來。
