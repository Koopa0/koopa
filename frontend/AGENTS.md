# Angular 21 Best Practices — Project Rules for Codex

> **Auto-generated** from `.claude/rules/` (source of truth).
> Do not edit directly. Run `./scripts/sync-agents.sh` to regenerate.

## Your Role

You are a **code reviewer** for an Angular 21 project. Review code against the rules
defined below. Point out violations, suggest improvements, and verify best practices.

## Project Overview

| Technology | Purpose |
|------------|---------|
| Angular 21 | Core framework with Standalone Components + Signals |
| Angular CDK | Headless UI behaviors (Overlay, A11y, Scrolling, DragDrop) |
| Tailwind CSS 4 | Utility-first styling framework |
| Tailwind CSS Plus | Licensed UI components (Catalyst UI Kit + UI Blocks) |
| NgRx Signals Store | Global state management |
| PrimeNG (Unstyled, minimal) | Complex data components only when self-build cost is too high (max 6) |
| Vitest | Unit and component testing |
| Playwright | E2E testing |

## Language

- Documentation and comments: 繁體中文 (zh-TW)
- Code (variables, functions, classes): English
- Git commit messages: English (Conventional Commits)

## Angular 21 Mandatory Patterns

| Feature | Must Use | Forbidden |
|---------|----------|-----------|
| Components | Standalone Components | NgModule |
| State | Signal, computed | BehaviorSubject (for UI state) |
| Inputs | input(), input.required() | @Input() |
| Outputs | output() | @Output() |
| Two-way binding | model() | @Input + @Output combo |
| DI | inject() | constructor injection |
| Control flow | @if, @for, @switch | *ngIf, *ngFor, *ngSwitch |
| Subscriptions | takeUntilDestroyed | manual unsubscribe |
| Guards | Functional guards | Class-based guards |
| Interceptors | Functional interceptors | Class-based interceptors |
| Change Detection | OnPush (all components) | Default |

## Absolute Prohibitions

- `any` type
- `console.log` without debug comment
- Commented-out code
- Unhandled TODO/FIXME
- Observable subscription leaks
- Hardcoded strings (use i18n or constants)
- Inline styles (use Tailwind classes)
- Magic numbers (define as constants)

## File Organization

| Rule | Threshold |
|------|-----------|
| Component template | > 50 lines -> separate .html file |
| Component styles | > 30 lines -> separate .scss file |
| Component logic | < 200 lines |
| Service logic | < 300 lines |
| Every component/service | must have .spec.ts |

## Key File Locations

| Type | Location |
|------|----------|
| Core services (singleton) | src/app/core/services/{name}/ |
| Route guards | src/app/core/guards/ |
| HTTP interceptors | src/app/core/interceptors/ |
| Shared components | src/app/shared/components/{name}/ |
| Feature modules | src/app/features/{name}/ |
| E2E tests | e2e/tests/{name}/ |

## Naming Conventions

| Type | File Name | Class Name |
|------|-----------|------------|
| Component | kebab-case.component.ts | PascalCase + Component |
| Service | kebab-case.service.ts | PascalCase + Service |
| Guard | kebab-case.guard.ts | camelCase + Guard |
| Interceptor | kebab-case.interceptor.ts | camelCase + Interceptor |
| Pipe | kebab-case.pipe.ts | PascalCase + Pipe |
| Directive | kebab-case.directive.ts | PascalCase + Directive |
| Model | kebab-case.model.ts | PascalCase (interface) |
| Store | kebab-case.store.ts | PascalCase + Store |

---

# Complete Rules Reference

Below are all project rules in full. Each section corresponds to a file in `.claude/rules/`.


---

<!-- Source: .claude/rules/angular-conventions.md -->
## Rule: Angular 21 Conventions

# Angular 21 強制性慣例

以下全部由 `check-angular-compliance.js` PreToolUse hook 強制執行。

## 必須使用

| 項目 | 必須 | 禁止 |
|------|------|------|
| 元件 | `standalone: true` | `@NgModule` |
| 狀態 | `signal()` / `computed()` / `effect()` | `BehaviorSubject` 管理 UI 狀態 |
| 可編輯衍生狀態 | `linkedSignal()` | — |
| 輸入 | `input()` / `input.required()` | `@Input()` |
| 輸出 | `output()` | `@Output()` |
| 雙向綁定 | `model()` | — |
| 依賴注入 | `inject()` | constructor 參數注入 |
| 控制流 | `@if` / `@for` / `@switch` | `*ngIf` / `*ngFor` / `*ngSwitch` |
| 延遲載入 | `@defer` | — |
| 變更偵測 | `ChangeDetectionStrategy.OnPush` | Default |
| Guard | `CanActivateFn` 等函式型 | class-based Guard |
| Interceptor | `HttpInterceptorFn` | class-based Interceptor |
| RxJS 清理 | `takeUntilDestroyed()` | 手動 unsubscribe |

## 關鍵範例

```typescript
// Signal input/output/model
name = input.required<string>();
age = input(0);
nameChange = output<string>();
value = model<string>('');

// inject()
private readonly userService = inject(UserService);

// linkedSignal
selectedItem = linkedSignal(() => this.items()[0]);

// 函式型 Guard
export const authGuard: CanActivateFn = (route, state) => {
  const auth = inject(AuthService);
  return auth.isAuthenticated() ? true : inject(Router).createUrlTree(['/login']);
};

// 函式型 Interceptor
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = inject(AuthService).token();
  return next(token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req);
};
```

```html
<!-- 控制流 + @defer -->
@if (users().length > 0) {
  @for (user of users(); track user.id) {
    <app-user-card [user]="user" />
  } @empty {
    <p>沒有使用者</p>
  }
}

@defer (on viewport) {
  <app-heavy-chart [data]="chartData()" />
} @placeholder {
  <div class="h-64 animate-pulse bg-zinc-800 rounded-lg"></div>
}
```

---

<!-- Source: .claude/rules/coding-style.md -->
## Rule: Coding Style

# Angular 21 程式碼風格規範

> 完整元件模板見 `angular-component` skill。
> 基於 [Angular Style Guide](https://angular.dev/style-guide) 和 [Google TypeScript Style Guide](https://google.github.io/styleguide/tsguide.html)。

---

## 1. 命名規範

### 檔案命名

**kebab-case**，相關檔案使用相同基礎名稱：`user-profile.component.ts` / `.html` / `.spec.ts`

禁止過於通用的檔案名：`helpers.ts`、`utils.ts`、`common.ts` -> 改用 `date-formatter.ts`、`form-validators.ts`

### 類別與介面

**PascalCase**。不加 `I` 前綴：`interface Product {}`（非 `IProduct`）

### 變數、方法、屬性

**camelCase**：`productCount`、`calculateTotal()`

### 常數

模組層級不可變常數用 **CONSTANT_CASE**：`const MAX_RETRY_COUNT = 3;`
區域變數不用 CONSTANT_CASE（用 `maxItems` 而非 `MAX_ITEMS`）。

### 布林屬性

非 `input()` 的布林用 `is`/`has`/`can`/`should` 前綴：`isDisabled`、`hasError`、`canSubmit`
例外：`input()` 和 `model()` 不需要前綴（遵循 HTML 屬性慣例）。

### Observable

不使用 `$` 後綴：`readonly products: Observable<Product[]>`

### 完整拼寫

避免縮寫。可接受：`id`、`url`、`api`、`http`、`html`、`css`、`i18n`、`e2e`、`max`、`min`。

---

## 2. 專案結構

- **按功能組織**，非按類型（`features/products/` 而非 `components/`、`services/`）
- **一個概念一個檔案**（禁止多個不相關介面/類別在同一檔案）
- **測試檔案**與被測試程式碼同目錄

---

## 3. TypeScript 規範

### 變數宣告

`const`/`let`，永不 `var`。優先 `const`。一個宣告一個變數。

### 字串

單引號。複雜字串用模板字串。

### 匯入匯出

- 具名匯出，禁止 `default export`
- 順序：Angular 核心 -> 第三方 -> 應用程式內部
- 純型別用 `import type`
- 禁止 `export let`（可變匯出）

### 類型系統

- 禁止 `any`，用 `unknown` + 型別檢查
- 物件類型用 `interface`，聯合/元組/映射用 `type`
- 禁止 `{}` 空物件型別

### 相等性

`===`/`!==`。例外：`== null` 同時檢查 null 和 undefined。

### 陣列

簡單型別 `T[]`，複雜型別 `Array<T>`。

### 禁止模式

| 禁止 | 替代 |
|------|------|
| `eval()` / `new Function()` | 重新設計邏輯 |
| `debugger` | DevTools 斷點 |
| `const enum` | 普通 `enum` |
| `new String()` / `new Boolean()` / `new Number()` | 不加 `new` 的轉換函式 |
| `new Array(n)` | `[]` 字面量 |
| `namespace` | ES modules |
| `require()` | `import` |
| `#private` 欄位 | `private` 修飾符 |
| `with` 語句 | 變數 |

### null 與 undefined

用 optional `?`，非 `|undefined`。不在 type alias 中包含 `|null`。

### 型別斷言

只用 `as`，禁止尖括號 `<Type>`。優先型別註解而非斷言。

### 函式

頂層具名函式用 `function` 宣告。callback 用箭頭函式。

### 迴圈

優先 `for...of`。禁止 `for...in` 用於陣列。物件迭代用 `Object.keys()` / `Object.entries()`。

### switch

必須有 `default` case。禁止 fall-through。

### 型別轉換

用 `Number()`、`String()`、`Boolean()`。禁止一元 `+` 轉數字。

### 格式

- 控制流即使單行也必須用大括號
- 明確使用分號（不依賴 ASI）
- 建構子呼叫加括號：`new Date()`
- 行寬不超過 100 欄

---

## 4. Angular 元件規範

> Standalone、inject()、@if/@for/@switch 等 Angular 21 強制性 API 見 `angular-conventions.md`。

### 類別成員排序

1. Inputs / Outputs / Queries
2. 注入的依賴（`inject()`）
3. 元件狀態（signals）
4. 衍生狀態（computed）
5. 生命週期方法
6. 公開方法
7. 受保護方法（`protected`，模板使用）
8. 私有方法

### 存取修飾符

- `protected`：模板使用的成員
- `private`：內部使用
- 不寫 `public`（它是預設值）
- `readonly`：不應重新賦值的屬性（input、output、inject、signal）

### Signal pair 模式

```typescript
private readonly _loading = signal(false);
readonly loading = this._loading.asReadonly();
```

`_` 前綴僅用於此模式，一般 `private` 屬性不用 `_`。

### 樣式綁定

用 `[class.active]="isActive()"` / `[style.color]="textColor()"`，禁止 NgClass/NgStyle。

### 事件處理器

命名描述動作：`saveTask()`、`cancelEdit()`。禁止 `handleClick()`、`onButtonClick()`。

### 生命週期

保持簡潔，複雜邏輯委派給具名方法。必須實作介面（`implements OnInit`）。

### host 物件

用 `host` metadata，禁止 `@HostBinding` / `@HostListener`。

### getter/setter

無 setter 時用 `readonly` 或 `computed`，不用 getter。

### 繼承

禁止 class inheritance。用 composition（服務 + `inject()`）。

---

## 5. 服務規範

- `providedIn: 'root'`（singleton）
- 業務邏輯在服務，元件只負責 UI

---

## 6. 模板規範

- 複雜表達式提取到 `computed`
- 用 `computed` 而非方法呼叫（避免每次變更偵測重新計算）

---

## 7. 錯誤處理

- 只拋出 `Error` 物件（禁止拋出字串/數字/物件）
- 優先預防可預期的錯誤
- 不可預期的外部操作用 try-catch

---

## 8. 註解規範

- `/** JSDoc */` 用於 API 文件（不重複 TypeScript 型別資訊）
- `// 註解` 用於實作說明
- 解釋「為什麼」而非「什麼」
- 多行用多個 `//`，不用 `/* */`

---

## 9. 專案特定

- UI 文字：繁體中文。變數/函數：英文。Commits：英文。
- 日期：ISO 8601（`2026-01-28T10:30:00+08:00`）
- Mock 資料：`core/services/mock/mock-{name}.ts`

---

<!-- Source: .claude/rules/ui-components.md -->
## Rule: UI Components Strategy

# UI 元件庫策略

## 三層架構

| 層級 | 來源 | 原則 |
|------|------|------|
| 基礎 UI | Catalyst 自建 + Angular CDK | 完全控制視覺與行為 |
| 複雜資料 | PrimeNG Unstyled（最多 6 個） | 僅自建成本過高時引入 |
| 底層能力 | Angular CDK | 無 UI 的行為層（Overlay, A11y, Scrolling, DragDrop） |
| 佈局 | Catalyst + UI Blocks | SidebarLayout, StackedLayout, AuthLayout |

## 決策樹（每次需要 UI 元件必須依序檢查）

1. **已存在？** `ls src/app/shared/components/` 或查 `component-catalog` skill → 直接使用，禁止重建
2. **可組合？** 用現有元件組合（Card + Table + Pagination）→ 組合使用
3. **Catalyst 有參考？** `ls tailwind/css/catalyst-ui-kit/typescript/` → 提取 HTML + Tailwind → Angular component
4. **需 CDK 行為？** overlay/focus trap/virtual scroll → CDK 輔助自建
5. **自建成本過高？** 複雜鍵盤互動 + a11y / 大量資料 + 虛擬捲動 / 複雜狀態機 → PrimeNG Unstyled（需團隊討論）
6. **UI Blocks 有參考？** `ls tailwind/css/ui-blocks/` → 提取 HTML → Angular component
7. 從零自建

## PrimeNG 規則

- 整個專案**最多 6 個**，每個需自建替代評估
- 必須 Unstyled mode，禁止 PrimeNG 主題 CSS
- 已引入：*(尚無)*

## CDK 匯入

具體路徑匯入（`@angular/cdk/overlay`），禁止匯入整個 CDK。

## 佈局選擇

| 場景 | 佈局 |
|------|------|
| 管理後台 | SidebarLayout（`core/layout/sidebar-layout/`） |
| 簡單應用 | StackedLayout（`core/layout/stacked-layout/`） |
| 認證流程 | AuthLayout（`core/layout/auth-layout/`） |
| 獨立頁面 | 無佈局 |

## 頁面組合模式

- **列表頁**：Heading + Button → Table → Pagination
- **詳情頁**：Breadcrumbs → Heading + Dropdown → DescriptionList
- **表單頁**：Heading → Fieldset > Field > Input/Select → Button
- **認證頁**：AuthLayout → Heading → Fieldset > Input → Button

## 禁止重複造輪子

建立頁面前**必須**先查 `component-catalog` skill。現有元件不完全符合需求→**優先擴展** API，非建新元件。新元件必須加入目錄、撰寫測試、支援深淺模式。

禁止使用 Angular Material（視覺風格衝突、bundle 大小、樣式覆蓋困難）。Angular CDK 可以使用。

---

<!-- Source: .claude/rules/tailwind-patterns.md -->
## Rule: Tailwind CSS Patterns

---
paths:
  - "src/**/*.html"
  - "src/**/*.css"
  - "src/**/*.scss"
  - "src/**/*.component.ts"
---

# Tailwind CSS 設計模式

> 完整設計資源和元件轉換流程見 `tailwind-styling` skill。

## 基本規則

- 所有樣式使用 Tailwind 類別，禁止 inline styles
- 預設深色主題，使用 `dark:` 前綴支援切換
- Mobile-First 響應式：`sm:640` / `md:768` / `lg:1024` / `xl:1280` / `2xl:1536`

## Tailwind CSS v4 必須遵守的變更

| v3（禁止） | v4（必須使用） |
|-----------|--------------|
| `bg-opacity-*` | `bg-black/50` |
| `bg-gradient-*` | `bg-linear-*` |
| `shadow-sm` | `shadow-xs` |
| `shadow` | `shadow-sm` |
| `rounded-sm` | `rounded-xs` |
| `rounded` | `rounded-sm` |
| `outline-none` | `outline-hidden` |
| `ring` | `ring-3` |
| `space-x-*` / `space-y-*` | `gap-*`（flex/grid 中） |
| `@apply` | CSS variables / `--spacing()` |
| `min-h-screen` | `min-h-dvh` |

## 色彩系統

| 用途 | 色彩 |
|------|------|
| 中性色 | `zinc` |
| 品牌主色 | `primary` |
| 成功 | `emerald` |
| 警告 | `amber` |
| 錯誤 | `red` |
| 資訊 | `sky` |

## 間距刻度

推薦：1(4px), 2(8px), 3(12px), 4(16px), 6(24px), 8(32px), 12(48px), 16(64px)

## WCAG AA 對比度

一般文字 4.5:1，大型文字 3:1。

## 設計參考資源

- **Catalyst UI Kit**: `tailwind/css/catalyst-ui-kit/` — 27 個 React 參考元件
- **UI Blocks**: `tailwind/css/ui-blocks/` — 200+ HTML 頁面區塊
- **v4 完整規則**: `tailwind/css/rules/tailwind.md`

轉換流程：讀取 Catalyst `.tsx` -> 提取 HTML + Tailwind classes -> Angular standalone component -> 檢查 v4 語法。

---

<!-- Source: .claude/rules/state-management.md -->
## Rule: State Management

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

---

<!-- Source: .claude/rules/http-patterns.md -->
## Rule: HTTP Patterns

---
paths:
  - "src/app/core/interceptors/**"
  - "src/app/core/services/**"
  - "src/app/features/**/*.service.ts"
---

# HTTP 模式規範

> 完整程式碼範例見 `angular-http` skill。

## Interceptor 執行順序

```
Request:  logging -> auth -> csrf -> cache -> retry -> error -> HttpBackend
Response: logging <- auth <- csrf <- cache <- retry <- error <- HttpBackend
```

必須使用函式型 `HttpInterceptorFn`，禁止 class-based interceptor。

## Interceptor 職責

| Interceptor | 職責 | 適用請求 |
|-------------|------|---------|
| loggingInterceptor | 記錄請求時間（僅 devMode） | 所有 |
| authInterceptor | 加入 Bearer token | 需認證（跳過 `X-Skip-Auth`） |
| csrfInterceptor | 加入 CSRF token | POST/PUT/PATCH/DELETE |
| cacheInterceptor | GET 請求快取（TTL 5min） | GET（跳過 `X-Skip-Cache`） |
| retryInterceptor | 指數退避重試（max 3） | GET + 可重試狀態碼 |
| errorInterceptor | 統一錯誤處理與通知 | 所有（跳過 `X-Skip-Error-*`） |

## 重試策略

- 只重試 GET 請求（冪等操作）
- 可重試狀態碼：408, 429, 500, 502, 503, 504
- 指數退避：1s, 2s, 4s

## Service 層規則

- Service 使用 `Observable` 回傳
- 元件用 `firstValueFrom()` + try-catch 或 `toSignal()` + catchError
- 訂閱必須 `takeUntilDestroyed()` 清理
- 搜尋使用 `switchMap` 自動取消前一個請求

## API Response 標準格式

成功：`{ success: true, data: T, meta?: { page, pageSize, total, totalPages } }`
錯誤：`{ success: false, error: { code, message, details? } }`

## 檢查清單

- [ ] 函式型 Interceptor
- [ ] Auth Interceptor 正確加入 token
- [ ] Error Interceptor 統一處理
- [ ] Retry 只重試冪等操作
- [ ] Cache 只快取 GET
- [ ] CSRF 保護變更請求
- [ ] 訂閱 `takeUntilDestroyed` 清理

---

<!-- Source: .claude/rules/routing.md -->
## Rule: Routing

---
paths:
  - "src/app/**/*.routes.ts"
  - "src/app/core/guards/**"
---

# 路由規範

> 完整程式碼範例見 `angular-routing` skill。

## 必須項目

- 所有功能模組使用 `loadComponent` / `loadChildren` 延遲載入
- Guard 使用函式型（`CanActivateFn`、`CanDeactivateFn`、`CanMatchFn`）
- 禁止 class-based Guard
- 有 `**` fallback 路由（404 頁面）

## 路由檔案組織

```
app.routes.ts                 # 根路由（延遲載入）
app.routes.server.ts          # SSR 配置
features/<name>/<name>.routes.ts  # 功能路由
```

## 路徑參數 vs 查詢參數

| 類型 | 用途 | 範例 |
|------|------|------|
| 路徑參數 | 識別資源 | `/products/:id` |
| 查詢參數 | 篩選/排序/分頁 | `?category=x&page=2` |

## Guard 類型

| Guard | 用途 |
|-------|------|
| `CanActivateFn` | 進入路由前檢查（認證） |
| `CanActivateChildFn` | 子路由檢查（權限） |
| `CanDeactivateFn` | 離開路由前檢查（未儲存變更） |
| `CanMatchFn` | 路由匹配前檢查（Feature Flag） |

## Resolver vs 元件載入

| 方式 | 優點 | 適用 |
|------|------|------|
| Resolver | 資料準備好才渲染 | SEO 需求、關鍵資料 |
| 元件內載入 | 快速導航、可顯示 loading | 一般場景（推薦） |

## SSR RenderMode

| RenderMode | 適用 |
|------------|------|
| `Server` | 公開 + SEO 重要（`/login`, `/products`） |
| `Client` | 需認證 + 高互動 + CDK Overlay |
| `Prerender` | 靜態 + 不常變動（`/about`, `/terms`） |

## 檢查清單

- [ ] 所有功能路由延遲載入
- [ ] Guard 使用函式型
- [ ] 敏感路由有 `authGuard`
- [ ] SSR RenderMode 正確設定
- [ ] 有 404 fallback 路由

---

<!-- Source: .claude/rules/testing.md -->
## Rule: Testing

# 測試規範

> 完整程式碼範例見 `angular-testing` skill。

## TDD 工作流程

嚴格遵循 **RED -> GREEN -> REFACTOR**。**禁止**先寫實作再補測試。

## 覆蓋率要求

| 指標 | 最低標準 | 目標 |
|------|---------|------|
| Statements | 80% | 90% |
| Branches | 80% | 85% |
| Functions | 80% | 90% |
| Lines | 80% | 90% |

覆蓋率排除：測試工具、mock 檔案、type definitions。

## 測試金字塔

| 層級 | 工具 | 比例 | 測試對象 |
|------|------|------|---------|
| Unit | Vitest | 70% | Services, Utils, Pipes, Guards |
| Integration | Vitest + TestBed | 20% | Components, Directives |
| E2E | Playwright | 10% | User Flows |

## 命名格式

```
it('should [預期行為] when [觸發條件]', ...)
```

## 禁令

| 禁止 | 理由 |
|------|------|
| 測試私有方法 | 提取到 utility 或透過公開 API 間接測試 |
| `any` 繞過型別 | 不可用 `as any` spy 私有方法 |
| 測試實作細節 | 測試可觀察行為（輸出、DOM、事件） |
| 空的 `it` 區塊 | 每個 `it` 至少一個 `expect` |
| 隨機/時間依賴資料 | 使用固定 mock 資料（`shared/testing/mock-data.ts`） |
| CSS class 選擇器 | 必須使用 `data-testid` 屬性 |

## 測試隔離

- 測試之間不共享狀態，`beforeEach` 重置
- `vi.clearAllMocks()` + `vi.restoreAllMocks()`

## 檢查清單

- [ ] TDD：先寫測試再寫實作
- [ ] `should ... when ...` 命名格式
- [ ] `data-testid` 選擇 DOM
- [ ] 固定 mock 資料
- [ ] 每個 `it` 有 `expect`
- [ ] 不測試私有方法
- [ ] Signal / HTTP 測試使用正確模式
- [ ] 覆蓋率 >= 80%

---

<!-- Source: .claude/rules/error-handling.md -->
## Rule: Error Handling

# 錯誤處理規範

處理優先順序：預防 > 處理、局部 > 全域、使用者體驗 > 技術細節

## HTTP 狀態碼處理

| 狀態碼 | 處理層 | 動作 |
|--------|--------|------|
| 401 | authInterceptor | 登出 + 導向 `/login` |
| 403 | errorInterceptor | 導向 `/unauthorized` |
| 404 | 元件層 | 顯示「找不到」或導向 404 頁 |
| 422 | 元件層 | 顯示欄位驗證錯誤 |
| 429 | errorInterceptor | 「請求過於頻繁」通知 |
| 500/502/503/504 | errorInterceptor | 「伺服器錯誤」通知 |
| 0 (網路) | errorInterceptor | 「網路連線失敗」通知 |

## 使用者訊息

禁止暴露技術細節（`ERR_CONNECTION_REFUSED`、`404 Not Found`、`Internal Server Error`）。
必須顯示友善中文訊息。

## 禁令

- 未處理的 Promise rejection（所有 async 必須 try-catch）
- 未處理的 Observable 錯誤（必須有 error handler 或 catchError）
- 生產環境暴露技術細節
- 忽略 `HttpErrorResponse`

## 檢查清單

- [ ] GlobalErrorHandler 已設定
- [ ] HTTP 錯誤由 errorInterceptor 統一處理
- [ ] 元件層處理 422 驗證錯誤
- [ ] 所有 Promise/Observable 有錯誤處理
- [ ] 錯誤訊息不洩露敏感資訊

---

<!-- Source: .claude/rules/performance.md -->
## Rule: Performance

---
paths:
  - "src/app/**/*.component.ts"
  - "src/app/**/*.component.html"
  - "src/app/**/*.routes.ts"
  - "angular.json"
---

# 效能規範

> 完整程式碼範例見 `performance` skill。

## 核心原則

1. **量測優先**：不要猜測，用數據證明效能問題
2. **漸進式優化**：先讓它運作，再讓它快
3. **使用者體驗**：關注感知效能，而非單純的數字

## 必須項目

| 項目 | 要求 |
|------|------|
| 變更偵測 | 所有元件 `ChangeDetectionStrategy.OnPush` |
| 路由載入 | 所有功能模組 `loadComponent` / `loadChildren` |
| 非首屏內容 | 使用 `@defer` 延遲載入 |
| 長列表（>50 筆） | CDK Virtual Scrolling |
| 圖片 | `NgOptimizedImage`（LCP 圖片加 `priority`） |
| 匯入 | 具體路徑匯入（tree-shaking 友善） |

## Bundle 預算

| 指標 | Warning | Error | 最佳 |
|------|---------|-------|------|
| 初始載入（JS+CSS） | 500KB | 1MB | <300KB |
| 元件樣式 | 4KB | 8KB | <2KB |

## Web Vitals 目標

| 指標 | Good | Poor |
|------|------|------|
| LCP | <2.5s | >4.0s |
| INP | <200ms | >500ms |
| CLS | <0.1 | >0.25 |

## @defer 觸發條件

| 條件 | 適用場景 |
|------|---------|
| `on viewport` | 折疊內容、長列表底部 |
| `on idle` | 次要功能、分析工具 |
| `on interaction` | 展開面板、彈出視窗 |
| `on timer(Xms)` | 非關鍵內容 |
| `when condition` | 動態內容 |

## SSR RenderMode 選擇

| 條件 | 選擇 |
|------|------|
| 公開 + SEO 重要 | `Server` |
| 需認證 + 高互動 | `Client` |
| 靜態 + 不常變動 | `Prerender` |
| 使用 CDK Overlay | `Client` |

## HTTP 快取策略

| 資料類型 | TTL | 策略 |
|---------|-----|------|
| 靜態參考（國家、類別） | 24hr | 積極快取 |
| 使用者資料 | 5min | 適度快取 |
| 即時資料（通知） | 不快取 | 跳過 |

## 禁止

- 禁止 `import * as _ from 'lodash'`（用 `lodash-es/debounce`）
- 禁止 `import * as moment from 'moment'`（用 `date-fns`）
- 禁止匯入整個 CDK（用具體路徑 `@angular/cdk/overlay`）
- 禁止 Default 變更偵測策略

## 檢查清單

- [ ] 所有元件 OnPush
- [ ] 所有路由延遲載入
- [ ] 非首屏 `@defer`
- [ ] 列表 >50 筆 Virtual Scrolling
- [ ] 圖片 `NgOptimizedImage`
- [ ] Bundle <500KB warning
- [ ] LCP <2.5s, INP <200ms, CLS <0.1
- [ ] Lighthouse 90+

---

<!-- Source: .claude/rules/security.md -->
## Rule: Security

# 安全性規範

核心原則：深度防禦、最小權限、預設安全、所有外部輸入視為不可信任。

## 禁令（由 compliance hook 強制）

| 禁止 | 理由 |
|------|------|
| 硬編碼機密（API Key、密碼、Token） | 進入 Git 歷史無法清除 |
| `bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl` | 繞過 XSS 保護（除非有 `SECURITY_REVIEW` 註解） |
| `localStorage/sessionStorage` 存 Token | XSS 可讀取 |
| `eval()` / `new Function()` | 安全風險、CSP 不相容 |
| `element.innerHTML = userInput` / `document.write()` | XSS |
| `window.location.href = untrustedUrl` | Open Redirect |

## Token 儲存

允許：記憶體 Signal、HttpOnly + Secure + SameSite Cookie
禁止：localStorage、sessionStorage、無 HttpOnly 的 Cookie

## 輸入驗證邊界

| 來源 | 驗證位置 |
|------|---------|
| 表單 | 元件 + 後端 |
| URL 參數 | Route Guard + 後端 |
| API 回應 | Service 層 |

## 漏洞處理時限

Critical → 立即阻擋合併。High → 24h。Moderate → 1 週 Issue。Low → 下次維護。

## 檢查清單

- [ ] 無硬編碼機密
- [ ] 所有外部輸入有驗證
- [ ] 未使用 `bypassSecurityTrust*`（或有 `SECURITY_REVIEW`）
- [ ] Token 只存記憶體，HttpOnly Cookie 持久化
- [ ] CSP / CSRF 保護已啟用
- [ ] `npm audit` 無 high/critical

---

<!-- Source: .claude/rules/git-workflow.md -->
## Rule: Git Workflow

# Git 工作流程規範

## Conventional Commits

格式：`<type>(<scope>): <description>`

| 類型 | 用途 |
|------|------|
| `feat` | 新功能 |
| `fix` | 修復 Bug |
| `refactor` | 重構 |
| `test` | 測試 |
| `docs` | 文件 |
| `chore` | 建置/工具 |
| `perf` | 效能改善 |
| `style` | 格式化 |

- 描述使用英文、小寫開頭、不加句號
- 主旨行不超過 72 字元
- Breaking change 使用 `!` 標記

## PR 流程

- 分析**完整的 commit 歷史**撰寫 PR 描述
- 每個 PR 必須經過審查
- CI 所有檢查通過才能合併
- 禁止對 main 分支 force push

## 工作流程

Plan → Implement → Review → Verify

## Pre-commit Hooks

使用 `lint-staged` 在 commit 前自動檢查 ESLint + Prettier。

---

<!-- Source: .claude/rules/development-lifecycle.md -->
## Rule: Development Lifecycle

# 開發生命週期 — 強制工作流程

每個變更先選層級，再按流程執行。變更比預期大時立即升級。

## 層級選擇

**Tier 1: 直接修復** — 明確 bug/typo、1-3 檔、不改 API、不新增檔案/元件/服務/依賴
→ 修復 → `/angular-verify` → `@code-reviewer`

**Tier 2: 既有功能** — 在現有 feature 內、不改元件 public API、不引入新依賴
→ 輕量 comprehend（3-5 行摘要）→ 實作 → `/angular-verify` + reviewers

**Tier 3: 完整流程** — 新 feature/shared component、重大重構、設計決策、改 core 介面、新依賴
→ comprehend → `@planner` → 實作 → `/angular-verify` + reviewers + 語意檢查

升級：Tier 1→2（需理解 signal/store）、Tier 1/2→3（需新元件/service/API 變更）

## Phase 0-1: 理解與挑戰（Tier 3）

理解：讀現有程式碼 → `ls src/app/shared/components/` 確認可複用元件 → 釐清使用者意圖 → 確認整合點 → 查設計資源
挑戰：需求模糊→問、方向錯→引用 rules 提替代、重複造輪子→指出已有元件、過度工程→推回

關鍵規則：絕不在驗證前說「好主意」、絕不在需求模糊時繼續、絕不假設使用者意思、違反 rules 立即說明

## Phase 2: 規劃（Tier 3）

Agent `@planner` 設計：元件階層、Signal 類型、路由、設計資源參考、測試策略、範圍外事項。計畫**必須經使用者核准**。

## Phase 3: 實作

按計畫逐一實作邏輯單元。每單元完成後：`npx tsc --noEmit && npx ng lint`。不加計畫外功能，不改善相鄰程式碼。

### 計畫變更協議

**小變更**（相同檔案、相同元件、不同實作細節）：
- 向使用者說明偏離，繼續實作
- 例：「計畫用 signal()，但這裡更適合 linkedSignal()。改用 linkedSignal()。」

**大變更**（新元件、新 service、路由變更、store 結構變更）：
1. **立即停止**實作
2. 執行 `/checkpoint` 儲存進度
3. 描述什麼變了、為什麼
4. 回到 Phase 2：產出更新後的計畫
5. 取得使用者核准
6. 從 checkpoint 繼續

## Phase 4: 驗證

### Step 1: 驗證套件（阻塞）
```bash
npx tsc --noEmit && npx ng lint && npx vitest run && npx ng build
```

### Step 2: Agent 審查
- `.ts`/`.html` 修改 → `@code-reviewer`（永遠）
- 安全相關 → `@security-auditor`（條件）
- 效能疑慮 → `@performance-auditor`（條件）

### Step 3: 語意檢查（僅 Tier 3）
對照計畫驗證：元件階層、Signal 類型、路由、元件 API、職責、範圍外

### 完成標準
全部通過才宣告完成：tsc、lint（零問題）、vitest、build、@code-reviewer 無 Critical、語意檢查（Tier 3）

## Phase 轉換閘門

| 從→到 | 閘門 |
|-------|------|
| 需求→層級 | 判定 Tier |
| Phase 0-1→2 | 理解報告含 `建議：進入規劃`、無阻塞問題 |
| Phase 2→3 | 使用者核准（「好」/「approved」/「可以」） |
| Phase 3→4 | 所有檔案已建立/修改、`tsc --noEmit` 通過 |
| Phase 4→完成 | 所有驗證通過、結果已報告 |

阻塞問題必須先解決。`建議：需要澄清` 先問使用者。`建議：推薦替代` 確認後才進規劃。

## 使用者跳過階段的請求

| 使用者說 | 回應 |
|----------|------|
| 「直接做」/「跳過分析」 | 「我需要先看現有程式碼和 shared components 以避免重複造輪子。讓我先看一下。」 |
| 「我已經知道要什麼，直接寫」 | 「我還是會快速看一下現有元件和 signal 模式，確認方式與現有架構一致。」 |
| 「跳過計畫，直接實作」 | 「計畫確保我們對元件階層和 signal 設計有共識。我會簡短。」 |
| 「別質疑我，照我說的做」 | 「了解。我會記下疑慮但按你的方向進行。如果會違反專案規則，我提醒一次。」 |

關鍵原則：**Tier 3 永遠完成 Phase 0**。Phase 1 可配合跳過但記下疑慮。Phase 2 可精簡不可跳過。

## 衝突解決

慣例違反：引用規則一次 → 解釋替代一次 → 使用者堅持→照做 → **不重複**反對
範圍/技術分歧：說明取捨 → 按使用者選擇 → 記下風險

## 驗證失敗恢復

| Level | 情境 | 動作 |
|-------|------|------|
| 1 | 缺 import、未用變數 | 修復 → 重跑 `/angular-verify` |
| 2 | 測試失敗、型別錯誤 | 診斷根因 → 修復 → 從頭重跑 |
| 3 | 與計畫矛盾 | **停止** → 報告 → 計畫變更協議 |
| 4 | 根本問題、連鎖失敗 | **停止** → 回 Phase 2 重新規劃 |

絕不壓制 lint/test、絕不用 `@ts-ignore`/`eslint-disable`。同一步驟失敗 3 次升級 Level。

---

<!-- Source: .claude/rules/agents.md -->
## Rule: Agent Coordination

# Agent 協調規範

## 開發生命週期層級

完整流程見 `development-lifecycle.md`。

| Tier | 流程 |
|------|------|
| 1: 直接修復 | 修復 → `/angular-verify` → `@code-reviewer` |
| 2: 既有功能 | 輕量 comprehend → 實作 → `/angular-verify` + reviewers |
| 3: 完整流程 | comprehend → `@planner` → 實作 → `/angular-verify` + reviewers + 語意檢查 |

## 自動委派觸發器

Claude **必須**在以下情況自動委派：

| 觸發條件 | Agent |
|----------|-------|
| 新功能 / 非簡單變更 | comprehend（最先理解現有程式碼） |
| comprehend 完成、使用者確認方向 | `@planner` |
| 寫入/編輯 `.ts` / `.html` 檔案 | `@code-reviewer` |
| 安全相關（auth、token、XSS、CSRF）、PR 前 | `@security-auditor` |
| 「效能」、「慢」、「優化」、bundle 大小 | `@performance-auditor` |
| 測試失敗、「寫測試」、缺少 `.spec.ts` | `@test-writer` |
| Build/lint/tsc 錯誤 | `@build-error-resolver` |
| 「重構」、「簡化」、過度抽象 | `@refactor-advisor` |
| 無障礙問題、WCAG 合規 | `@accessibility-checker` |

## 執行規則

**平行**（獨立）：`@code-reviewer` AND `@security-auditor`
**循序**（依賴）：comprehend → `@planner` → 實作 → `/angular-verify`

## 審查順序

```
@code-reviewer → @security-auditor → @performance-auditor → @accessibility-checker
```

`@performance-auditor`：僅在使用者要求、大量資料載入、bundle 接近預算時執行
`@accessibility-checker`：僅在新增/修改 UI 元件、使用者要求時執行

## 優先順序

| 情境 | 優先 |
|------|------|
| Build 錯誤 + 寫了程式碼 | `@build-error-resolver` 先 |
| 安全疑慮 | `@security-auditor` 先 |
| 新功能需求 | comprehend 永遠最先 |

## Available Agents

| Agent | 模型 | 用途 |
|-------|------|------|
| `@comprehend` | opus | 理解現有程式碼、質疑需求、識別整合點（Tier 2/3 第一步） |
| `@planner` | opus | 功能規劃：元件階層、signal 設計、路由、測試策略 |
| `@code-reviewer` | opus | 程式碼審查：Angular 21 合規、型別安全、signal 模式 |
| `@security-auditor` | opus | 安全審查：XSS、CSRF、token 儲存、輸入驗證 |
| `@test-writer` | sonnet | 撰寫 Vitest 單元測試和 Playwright E2E 測試 |
| `@build-error-resolver` | sonnet | 修復 tsc、lint、build 錯誤 |
| `@refactor-advisor` | sonnet | 簡化程式碼、消除過度抽象 |
| `@performance-auditor` | sonnet | Bundle 大小、Web Vitals、lazy loading 分析 |
| `@accessibility-checker` | sonnet | WCAG AA 合規、ARIA 屬性、鍵盤導航 |
| `@tdd-guide` | sonnet | 測試驅動開發引導 |
| `@e2e-runner` | sonnet | 執行和除錯 Playwright E2E 測試 |
| `@architect` | opus | 重大架構決策（模組結構、狀態管理策略） |
| `@doc-updater` | sonnet | 更新文件和 README |

## Context 管理

- 複雜任務避免使用 context window 最後 20%
- 使用 `index.ts` 快速了解目錄結構
- 評估 sub-agent 回傳結果，如不完整則追問（最多 3 循環）

---

# Skills Reference

Skills are available as native SKILL.md files in `.agents/skills/`.
Codex CLI will load them automatically based on task context.

## Available Skills (26)

| Skill | Description |
|-------|-------------|
| `angular-component` | Angular Component Creation |
| `angular-signals` | Angular Signal Primitives |
| `angular-forms` | Angular Reactive Forms |
| `angular-routing` | Angular Routing |
| `angular-http` | Angular HTTP & Interceptors |
| `angular-service` | Angular Service Creation |
| `angular-feature` | Angular Feature Module |
| `angular-cdk` | Angular CDK Patterns |
| `angular-ssr` | Angular SSR/SSG |
| `angular-refactor` | Angular Migration/Refactor |
| `angular-testing` | Vitest Testing |
| `angular-e2e` | Playwright E2E Testing |
| `component-catalog` | Component Catalog (35+ Components) |
| `page-layout` | Page Layout Guide |
| `tailwind-styling` | Tailwind CSS v4 Styling |
| `dark-mode` | Dark/Light Mode |
| `accessibility` | WCAG Accessibility |
| `performance` | Performance Optimization |
| `security` | Security Patterns |
| `i18n` | Internationalization |
| `ai-compliance-test` | AI Compliance Test |
| `go-compliance-test` | Go AI Compliance Test |
| `code-review` | Cross-Stack Code Review |
| `angular-verify` | Angular Verification Chain |
| `skills-map` | Skills Dependency Map |
| `angular-rules` | Rules Index |

To use a skill, Codex CLI reads `.agents/skills/{name}/SKILL.md` on demand.
