---
name: debug
description: >-
  Structured 4-phase debugging methodology for runtime bugs, test failures, and logic errors.
  Trigger when user says "debug", "why failing", "test failed", "unexpected behavior",
  "wrong output", or describes a runtime issue.
  NOT for build/lint/tsc errors (use @build-error-resolver).
metadata:
  author: koopa
  version: "1.0"
  lang: angular
---

# Debug — 結構化 4 階段除錯

## 身份

你是系統性除錯者。你不猜測。你從證據形成假設，測試它們，然後縮小範圍。

**禁止散彈式除錯** — 隨機修改直到成功是被禁止的。如果你無法解釋為什麼某個修改能修復 bug，你就還沒找到根因。

---

## 何時使用

| 症狀 | 用 `/debug` | 用 `@build-error-resolver` |
|------|-------------|---------------------------|
| 測試輸出錯誤值 | Yes | No |
| 非預期運行時行為 | Yes | No |
| Signal 值不更新 | Yes | No |
| Component 不重新渲染 | Yes | No |
| E2E 測試間歇性失敗 | Yes | No |
| `tsc --noEmit` 編譯錯誤 | No | Yes |
| `ng lint` 問題 | No | Yes |
| `ng build` 失敗 | No | Yes |

---

## 四個階段

### Phase 1: REPRODUCE（重現）

1. **取得確切失敗輸出**：
   ```bash
   # 測試失敗
   npx vitest run --reporter=verbose src/app/features/<feature>/<file>.spec.ts

   # E2E 失敗
   npx playwright test e2e/tests/<name>/ --reporter=list

   # 運行時錯誤 — 檢查瀏覽器 console
   npx ng serve  # 然後檢查 DevTools console
   ```

2. **建立最小重現**：
   - 寫一個簡單測試觸發同樣的 bug
   - 如果是 UI 問題，隔離到單一 component

3. **確認確定性**：
   ```bash
   # 執行 3 次確認一致性
   npx vitest run --reporter=verbose <file>.spec.ts
   npx vitest run --reporter=verbose <file>.spec.ts
   npx vitest run --reporter=verbose <file>.spec.ts
   ```

4. **記錄**：
   - **預期**：應該發生什麼
   - **實際**：實際發生什麼
   - **頻率**：每次 / 間歇性（N/10 次）

### Phase 2: DIAGNOSE（診斷）

1. **形成假設** — 基於失敗輸出，不是直覺：
   - 哪一層有問題？（Component / Service / Store / Template）
   - 哪個資料是錯的？（input / output / 中間狀態）
   - 哪個假設被違反了？

2. **對每個假設，定義**：
   - 什麼證據能**確認**它？
   - 什麼證據能**否定**它？
   - 如何測試？

3. **縮小範圍**：
   ```typescript
   // 在關鍵點加 console.log（記得加 // debug 註解）
   console.log('signal value:', this.items()); // debug
   console.log('computed result:', this.total()); // debug
   ```

4. **Angular 特有診斷工具**：
   | 工具 | 何時使用 |
   |------|---------|
   | `console.log` + `// debug` | Signal 值檢查 |
   | Vitest `--reporter=verbose` | 詳細測試輸出 |
   | Angular DevTools | Component 樹、Signal 追蹤 |
   | `effect(() => console.log(...))` | 追蹤 signal 變化（臨時）|
   | Playwright `--debug` | E2E 互動式除錯 |

5. **不要猜測循環**：
   - 假設 1 被否定 → 從新證據形成假設 2
   - 測試 3 個假設都不成立 → 退一步重新檢視失敗輸出

### Phase 3: FIX（修復）

1. **陳述根因**：一句話解釋什麼是錯的和為什麼
2. **解釋修復**：為什麼這個修改解決了根因
3. **應用修復**：
   - 最小修改——不順便重構
   - 如果修復改變了行為，更新或新增測試

4. **移除除錯殘留**：
   - 刪除 `// debug` 的 console.log
   - 刪除臨時的 effect()
   - 刪除臨時測試（除非成為有用的回歸測試）

### Phase 4: VERIFY（驗證）

1. **執行 Phase 1 的重現**：
   ```bash
   npx vitest run --reporter=verbose <previously-failing-test>
   ```
   必須通過。

2. **執行完整 feature 測試**：
   ```bash
   npx vitest run src/app/features/<feature>/
   ```

3. **執行 `/angular-verify`**：
   ```bash
   npx tsc --noEmit && npx ng lint && npx vitest run && npx ng build
   ```

4. **E2E 驗證**（如適用）：
   ```bash
   npx playwright test e2e/tests/<name>/
   ```

---

## Angular 常見 Bug 模式

### Signal / State Bugs

| 症狀 | 可能原因 | 修復 |
|------|---------|------|
| UI 不更新 | 缺少 OnPush + signal 未被 template 讀取 | 確認 `ChangeDetectionStrategy.OnPush` + template 中呼叫 signal |
| computed 值過時 | 依賴的 signal 沒在 computed 函式體內被讀取 | 確保所有依賴 signal 在 `computed()` 內被呼叫 |
| linkedSignal 不同步 | 來源 signal 變化但 linkedSignal 沒反映 | 確認 `linkedSignal()` 的 source 函式正確 |
| resource 不重新載入 | request signal 未改變 | 確認 request signal 在需要時更新 |

### Component Bugs

| 症狀 | 可能原因 | 修復 |
|------|---------|------|
| input 值是 undefined | 使用 `input()` 但父元件未傳值 | 改用 `input.required()` 或處理 undefined |
| output 事件沒觸發 | 忘記在 template 中綁定 | 檢查 `(eventName)="handler()"` 語法 |
| `@if` 條件不生效 | Signal 值未用 `()` 呼叫 | `@if (items().length > 0)` 不是 `@if (items.length > 0)` |

### E2E / Playwright Bugs

| 症狀 | 可能原因 | 修復 |
|------|---------|------|
| 元素找不到 | 缺少 `data-testid` | 加入 `data-testid` 屬性 |
| 間歇性失敗 | 非同步操作未等待 | 用 `await page.waitForSelector('[data-testid="..."]')` |
| 狀態殘留 | 測試間共享狀態 | 確認每個測試有獨立的 setup |

---

## 反模式（絕對不做）

| 反模式 | 為何錯誤 | 正確做法 |
|--------|---------|---------|
| 隨機改程式碼直到測試通過 | 掩蓋根因 | 形成假設，測試，迭代 |
| 壓制錯誤（`// @ts-ignore`） | 隱藏 bug | 理解為什麼錯誤發生 |
| 刪除失敗的測試 | Bug 仍存在 | 修程式碼，不修測試 |
| 加 `setTimeout` 修非同步問題 | 時序依賴的修復 | 使用 signal、computed、proper async |
| 加 `eslint-disable` 壓制發現 | 隱藏真實問題 | 修復底層原因 |
