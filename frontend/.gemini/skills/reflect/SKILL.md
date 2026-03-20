---
name: reflect
description: >-
  Review accumulated session learnings and decide whether to promote them to persistent
  memory, rules, or skill updates. Trigger when user says "/reflect", "review learnings",
  "what did we learn", or at the end of a significant work session. Also provides
  in-conversation learning recording format.
metadata:
  author: koopa
  version: "1.0"
  security: human-gated
---

# Reflect — Session Learning 擷取與回顧

## 身份

你有兩個職責：

1. **工作中**：識別糾正、發現和可複用見解，記錄到 staging 檔案
2. **被 `/reflect` 呼叫時**：回顧累積的 learnings，幫使用者決定是否提升到持久化儲存

你**永遠不會**自動提升 learnings。每次提升需要明確的使用者批准。

---

## Part 1: 擷取（任何對話中）

### 何時擷取

| 觸發 | 範例 |
|------|------|
| 使用者糾正你的做法 | 「不，用 X 不要 Y」、「其實...」、「不要那樣」 |
| 你發現非顯而易見的模式 | Angular Signal 的 gotcha、Tailwind v4 陷阱 |
| 審查 agent 發現反覆出現的問題 | 多次審查中同樣的發現 |
| 除錯 session 揭示根因 | 值得記住的非平凡根因 |
| 慣例被澄清 | 「在這個專案中，我們總是這樣做因為...」 |

### 何時不擷取

| 跳過 | 原因 |
|------|------|
| 見解已在現有 rule 中 | 先檢查 `.claude/rules/` |
| 糾正是情境特有的 | 「這個檔案不要」≠「永遠不要這樣」 |
| 學習是標準 Angular 知識 | Angular 官方文件已涵蓋 |

### 擷取格式

Append 到 `.claude/session-learnings.log`：

```
---
date: YYYY-MM-DD
source: user-correction | self-discovery | review-finding | debug-finding
context: <學到這個時我們在做什麼>
learning: <見解、糾正或模式——一句清楚的話>
candidate-target: memory | rule:<rule-file> | skill:<skill-name> | agent-memory:<agent>
---
```

### 擷取規則（不可協商）

1. **只追加**。絕不編輯或刪除 log 中的現有條目。
2. **絕不寫入 CLAUDE.md、rules/、skills/ 或 agents/**。Log 檔案是唯一寫入目標。
3. **一個條目一個 learning**。每條不超過 5 行。
4. **檢查重複**。寫入前先讀 log 檔案。
5. **要具體**。「Signal 需要 X」是好的。「狀態管理的東西」是壞的。

---

## Part 2: 回顧（透過 `/reflect`）

### Step 1: 讀取累積的 Learnings

```bash
cat .claude/session-learnings.log
```

如果檔案為空或不存在：「沒有累積的 learnings。無需回顧。」

### Step 2: 分組並呈現

按 `candidate-target` 分組。對每個 learning 呈現：

```markdown
### Learning #N

- **日期**: YYYY-MM-DD
- **來源**: user-correction
- **Context**: 實作 user profile 時...
- **Learning**: linkedSignal() 在 source signal 改變時會重置，不保留本地修改
- **建議目標**: skill:angular-signals
- **建議變更**: 加到 "注意事項" 章節：
  > `linkedSignal()` 的值在 source signal 改變時會重置為初始值。如需保留本地修改，改用 `signal()` + `effect()`。

**動作？** [promote / defer / discard]
```

### Step 3: 處理使用者決定

| 決定 | 動作 |
|------|------|
| **promote** | 對目標檔案套用變更。套用前顯示 diff。 |
| **defer** | 保留在 log 中供下次回顧。 |
| **discard** | 從 log 中移除。 |

### Step 4: 清理

處理完所有項目後：
- 移除已 promote 和 discard 的條目
- 保留 deferred 條目供下次 `/reflect`
- 回報摘要：「Promoted N 個 learnings，deferred M 個，discarded K 個。」

---

## 安全模型

| 約束 | 理由 |
|------|------|
| 只有 staging 檔案——不直接寫 CLAUDE.md/rules/skills | 防止持久化 prompt injection |
| 每次 promotion 需人工閘門 | 確保人類驗證每個 learning |
| Log 檔案不自動載入 context | `.claude/session-learnings.log` 不在 `rules/` 或 `skills/` 中 |
| 只追加擷取 | 防止竄改現有條目 |
