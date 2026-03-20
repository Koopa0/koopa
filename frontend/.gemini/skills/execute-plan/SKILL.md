---
name: execute-plan
description: >-
  Execute approved implementation plans task-by-task using fresh subagents with crafted context.
  Trigger when user says "execute plan", "execute-plan", or after planner produces a
  Tier 3 feature plan with 4+ tasks. NOT for Tier 1/2 changes.
metadata:
  author: koopa
  version: "1.0"
  lang: angular
---

# Execute Plan — Subagent 驅動的任務執行

## 身份

你是計畫執行者。你讀取持久化的計畫檔案，分解為任務，為每個任務分派 fresh subagent 並精心構造 context。你協調、審查、處理阻塞。你不自己寫程式碼。

---

## 前置條件

- 已核准的計畫存在於 `.claude/plans/<feature>.md`
- 計畫有編號的 `實作任務`，包含檔案、範圍、依賴和驗證
- 使用者已核准計畫

如果沒有計畫檔案，告訴使用者先執行 `@planner`。

---

## 流程

### Step 1: 讀取與分解

1. 讀取 `.claude/plans/<feature>.md`
2. 擷取所有編號任務及完整詳情
3. 識別任務依賴
4. 向使用者回報：

```
計畫: <feature>
任務: N 個

1. [任務名稱] — [檔案] — 無依賴
2. [任務名稱] — [檔案] — 依賴 Task 1
3. [任務名稱] — [檔案] — 依賴 Task 2
...

開始循序執行。每個任務分派 fresh subagent。
```

### Step 2: 循序執行任務

對每個任務，按依賴順序：

#### 2a. 構造 Context

使用 `development-lifecycle.md` 中的任務 Context 模板：

```markdown
## Task: [任務名稱]
## Plan file: .claude/plans/<feature>.md — Task N
## 要建立/修改的檔案: [明確列表]
## 此任務依賴的型別/介面:
[從現有程式碼讀取，逐字貼入]
## 範圍: [此任務做什麼]
## 不在範圍內: [此任務不做什麼]
## 驗證: [確切指令]
## 專案慣例:
- Standalone Components + OnPush
- Signal: signal()、computed()、linkedSignal()、resource()
- inject()、input()/output()/model()
- Tailwind CSS v4、dark: 模式
- Vitest 測試、data-testid
```

**關鍵**：從 codebase 讀取型別/介面並逐字包含。subagent 不應需要探索 codebase。

#### 2b. 分派 Subagent

使用 Agent tool 分派 fresh subagent：
- 使用 `subagent_type: "general-purpose"`
- 包含構造好的 context 作為 prompt

#### 2c. 處理 Subagent 回應

| 狀態 | 動作 |
|------|------|
| **成功**（驗證通過） | 執行 lint gate，進入下一任務 |
| **有問題**（需要澄清） | 提供更多 context，重新分派 |
| **阻塞**（無法完成） | 評估：context 問題→補充 context；任務太大→拆分；計畫錯誤→向使用者回報 |
| **部分**（實作了但驗證失敗） | 讀取錯誤，提供修復指引，重新分派或呼叫 `@build-error-resolver` |

#### 2d. Lint Gate（每個任務）

```bash
npx tsc --noEmit && npx ng lint
```

失敗則修復後才進入下一任務。

### Step 3: 執行後

所有任務完成後：

1. **完整驗證**: `/angular-verify`（tsc → lint → test → build）
2. **審查 agents**: `@code-reviewer`（永遠）、`@security-auditor`（安全相關時）
3. **語意檢查**: 比對實作 vs `.claude/plans/<feature>.md`
4. **向使用者回報結果**

---

## 何時使用 vs 直接實作

| 情境 | 用 `/execute-plan` | 用直接實作 |
|------|--------------------|-|
| Tier 3, 4+ 任務 | Yes | No |
| Tier 3, 1-3 任務 | 可選 | 建議 |
| Tier 2 | No | Yes |
| Tier 1 | No | Yes |
| Context window 快滿 | Yes（fresh subagent 避免膨脹）| 有降質風險 |

---

## 執行中的計畫變更

### 小變更（同檔案，不同細節）
- 記錄變更
- 更新 `.claude/plans/<feature>.md` in-place
- 繼續執行

### 大變更（新元件、新 service、API 變更）
1. 停止執行
2. 執行 `/checkpoint`
3. 向使用者回報
4. 使用者核准後更新計畫檔案
5. 從變更點繼續

---

## 反模式

| 反模式 | 為何錯誤 | 正確做法 |
|--------|---------|---------|
| 整份計畫丟給 subagent | Context 污染 | 精心構造每個任務的 context |
| 任務間跳過 lint gate | 錯誤跨任務累積 | 每個任務後 lint |
| 自己寫程式碼 | 失去 fresh-context 優勢 | 永遠分派 subagent |
| 每個任務跑完整審查 | 不完整程式碼產生 false positive | 任務 lint，最後審查 |
| 平行分派 subagents | 檔案衝突 | 只循序執行 |
