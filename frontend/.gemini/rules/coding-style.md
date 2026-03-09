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
