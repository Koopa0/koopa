# 狀態管理規範

> 完整程式碼範例見 `angular-signals` skill。

## 狀態類型選擇

| 狀態類型 | 工具 | 範例 |
|---------|------|------|
| 元件 UI 狀態 | `signal()` | 展開/收合、hover |
| 表單狀態 | `model()` / Reactive Forms | 輸入值、驗證 |
| 衍生狀態 | `computed()` | 篩選結果、計數 |
| 可編輯衍生狀態 | `linkedSignal()` | 預設選項（可手動覆蓋） |
| 功能/全域共享狀態 | NgRx Signals Store | 產品列表、使用者、主題 |
| 非同步資料載入 | `resource()`（experimental） | API 回應載入（Developer Preview，API 可能變更） |
| 伺服器快取 | `signal()` + HTTP | API 回應快取 |

## 何時用 Store

| 情境 | 推薦 |
|------|------|
| 多元件共享狀態 | Store |
| 複雜狀態轉換 | Store |
| 需要 DevTools 除錯 | Store |
| 元件私有 UI 狀態 | Component Signal |
| 簡單父子通訊 | input/output |

## Store 設計原則

- **單一資料來源**：Store 是唯一 source of truth
- **不可變更新**：使用 `patchState()`，禁止 `store.products().push()`
- **副作用隔離**：副作用在 `withMethods` 中，`computed` 必須是純函數
- **Signal pair 模式**：`private readonly _loading = signal(false)` + `readonly loading = this._loading.asReadonly()`

## 禁令

| 禁止 | 替代 |
|------|------|
| `computed` 中有副作用 | 使用 `effect` 或 `withMethods` |
| `effect` 做衍生狀態 | 使用 `computed` |
| 直接修改 Store 狀態 | `patchState()` 不可變更新 |
| `BehaviorSubject` 管理 UI 狀態 | `signal()` |
| `localStorage.setItem('token', ...)` | 記憶體 Signal（敏感資料不持久化） |

## RxJS 整合

- `toSignal(observable$, { initialValue })` — Observable -> Signal
- `toObservable(signal)` — Signal -> Observable（用於 debounce/switchMap 等）
- `rxMethod<T>(pipe(...))` — Store 內 RxJS 整合

## 檢查清單

- [ ] UI 狀態用 `signal()`
- [ ] 共享狀態用 NgRx Signals Store
- [ ] 衍生狀態用 `computed()`（無副作用）
- [ ] Store 使用 `patchState` 不可變更新
- [ ] Token 等敏感資料不持久化
- [ ] DevTools 已啟用（開發環境）
