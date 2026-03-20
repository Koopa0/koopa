---
name: checkpoint
description: >-
  Create a git checkpoint commit for work-in-progress before risky changes.
  Use before major plan changes, risky refactors, or when the development
  lifecycle's Plan Change Protocol requires saving progress. Trigger when
  user says "checkpoint", "save progress", or before Tier 3 plan changes.
metadata:
  author: koopa
  version: "1.0"
---

# Checkpoint — 儲存工作進度

## 用途

在風險性變更前建立 git checkpoint，確保可以安全回退。

## 使用時機

- Tier 3 計畫變更協議的步驟 2（「執行 `/checkpoint` 儲存進度」）
- 大規模重構前
- 嘗試新方案但不確定可行時
- 任何可能需要回退的操作前

## 執行步驟

### 1. 檢查當前狀態

```bash
git status
git diff --stat
```

### 2. Stage 所有變更

```bash
git add -A
```

### 3. 建立 Checkpoint Commit

```bash
git commit -m "chore: checkpoint — WIP before [description]

Work-in-progress checkpoint. Safe to reset to this commit if needed.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

### 4. 記錄 Checkpoint

向使用者回報：
```
Checkpoint 已建立：[commit hash]
描述：[what was saved]
回退方式：git reset --soft [hash]
```

## 回退方式

如需回退到 checkpoint：

```bash
# 保留修改在 staging area
git reset --soft <checkpoint-hash>

# 完全回退（丟棄 checkpoint 之後的所有修改）
git reset --hard <checkpoint-hash>
```

## 規則

- Checkpoint commit 訊息以 `chore: checkpoint` 開頭
- 永遠使用 `git add -A`（包含所有變更）
- 永遠回報 commit hash 給使用者
- 不要在 checkpoint commit 中混入非 WIP 的變更
