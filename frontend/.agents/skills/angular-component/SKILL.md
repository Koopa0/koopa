---
name: angular-component
description: >-
  Angular 21 standalone component creation — file structure, template,
  signals, OnPush, input/output/model conventions.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Component

## 觸發條件

當需要建立新的 Angular standalone component 時使用此 skill。

## 元件類型

| 類型 | 位置 | 說明 |
|------|------|------|
| Page Component | `features/{feature}/` | 路由頁面入口 |
| Feature Component | `features/{feature}/components/` | 功能專屬子元件 |
| Shared Component | `shared/components/` | 跨功能重用元件 |
| Layout Component | `core/layout/` | 佈局相關元件 |

## 檔案結構

```
{component-name}/
├── {component-name}.component.ts
├── {component-name}.component.html
├── {component-name}.component.scss
├── {component-name}.component.spec.ts
└── index.ts
```

## 程式碼模板

```typescript
import {
  Component,
  ChangeDetectionStrategy,
  input,
  output,
  inject,
  signal,
  computed,
} from '@angular/core';

@Component({
  selector: 'app-{component-name}',
  standalone: true,
  imports: [],
  templateUrl: './{component-name}.component.html',
  styleUrl: './{component-name}.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class {ComponentName}Component {
  // 1. Inputs / Outputs / Queries
  readonly title = input.required<string>();
  readonly clicked = output<void>();

  // 2. 依賴注入
  private readonly service = inject(SomeService);

  // 3. 內部狀態
  protected readonly loading = signal(false);

  // 4. 計算屬性
  protected readonly displayTitle = computed(() =>
    this.title().toUpperCase()
  );

  // 5. 生命週期
  // 6. 公開方法（模板使用 → protected）
  // 7. 私有方法
}
```

## 設計參考資源

建立 UI 元件前，**務必先查閱本地設計資源**：

### 步驟 1：查找 Catalyst UI Kit 元件

Catalyst 提供 27 個參考元件，位於 `tailwind/css/catalyst-ui-kit/typescript/`。

**查找流程**：
1. 確認需要的元件類型（button / input / dialog / table 等）
2. 讀取對應的 `.tsx` 檔案：`Read tailwind/css/catalyst-ui-kit/typescript/{component}.tsx`
3. 提取 Tailwind classes 和 HTML 結構
4. 轉換為 Angular template（見下方轉換指南）

### 步驟 2：查找 UI Blocks 佈局

UI Blocks 提供 200+ 純 HTML 參考，位於 `tailwind/css/ui-blocks/`。

**快速查找指南**：

| 需求 | 查找路徑 |
|------|---------|
| 應用外殼/佈局 | `application-ui/application-shells/` |
| 表單 | `application-ui/forms/` |
| 表格/列表 | `application-ui/lists/` |
| 導航/Tabs | `application-ui/navigation/` |
| Modal/Drawer | `application-ui/overlays/` |
| Stats/資料展示 | `application-ui/data-display/` |
| Alert/Empty State | `application-ui/feedback/` |
| 完整頁面範例 | `application-ui/page-examples/` |

### 步驟 3：React → Angular 轉換

| React (Catalyst) | Angular |
|-------------------|---------|
| `clsx(...)` | `[class]` binding 或直接寫 class |
| `{...props}` | `input()` / `output()` |
| `<Dialog>` (Headless UI) | Angular CDK Dialog |
| `<Link href>` | `<a routerLink>` |
| `useState` | `signal()` |
| `useMemo` | `computed()` |
| `forwardRef` | 不需要 |

### 步驟 4：檢查 Tailwind v4 相容性

對照 `tailwind/css/rules/tailwind.md` 確認 Catalyst 原始碼中的 classes 是 v4 語法。

## MCP 整合

如果 MCP server 可用，建立元件時可使用以下工具：

1. `angular-cli` — 執行 `ng generate component`
2. `eslint` — 檢查新建檔案的 lint 品質
3. `typescript` — 驗證型別正確性

即使 MCP 不可用，仍可手動建立檔案。

## 模板規範

- 使用 `@if`, `@for`, `@switch` 控制流
- 使用 `data-testid` 屬性便於測試
- 使用 Tailwind CSS v4 類別 + `dark:` 前綴
- 超過 50 行分離為 `.html` 檔案

## 樣式規範

- `:host { display: block; }` 設定宿主樣式
- 主要使用 Tailwind classes
- 超過 30 行分離為 `.scss` 檔案

## 測試指引

### TestBed 元件測試模式

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { {ComponentName}Component } from './{component-name}.component';

describe('{ComponentName}Component', () => {
  let fixture: ComponentFixture<{ComponentName}Component>;
  let component: {ComponentName}Component;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [{ComponentName}Component],
    }).compileComponents();

    fixture = TestBed.createComponent({ComponentName}Component);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
```

### Signal Input 測試

使用 `fixture.componentRef.setInput()` 設定 signal input：

```typescript
it('should render title when provided', () => {
  fixture.componentRef.setInput('title', '測試標題');
  fixture.detectChanges();

  const el = fixture.nativeElement.querySelector('[data-testid="title"]');
  expect(el.textContent).toContain('測試標題');
});

it('should update computed value when input changes', () => {
  fixture.componentRef.setInput('title', 'hello');
  fixture.detectChanges();

  // 驗證 computed signal 衍生值
  expect(component.displayTitle()).toBe('HELLO');
});
```

### Signal 狀態斷言

```typescript
it('should set loading to true when fetching data', () => {
  component.loadData();
  expect(component['loading']()).toBe(true);
});

it('should compute item count correctly', () => {
  fixture.componentRef.setInput('items', [
    { id: '1', name: 'Item A' },
    { id: '2', name: 'Item B' },
  ]);
  fixture.detectChanges();

  expect(component.itemCount()).toBe(2);
});
```

### Output 事件測試

```typescript
it('should emit clicked event when button is clicked', () => {
  const spy = vi.fn();
  component.clicked.subscribe(spy);
  fixture.detectChanges();

  const button = fixture.nativeElement.querySelector('[data-testid="action-button"]');
  button.click();

  expect(spy).toHaveBeenCalledOnce();
});
```

### data-testid 選擇器使用

所有可測試的 DOM 元素必須加上 `data-testid` 屬性：

```html
<!-- 模板中加上 data-testid -->
<h1 data-testid="page-title">{{ title() }}</h1>
<button data-testid="submit-button" (click)="submit()">送出</button>
<ul data-testid="item-list">
  @for (item of items(); track item.id) {
    <li [attr.data-testid]="'item-' + item.id">{{ item.name }}</li>
  }
</ul>
```

```typescript
// 測試中使用 data-testid 選擇元素
const title = fixture.nativeElement.querySelector('[data-testid="page-title"]');
const button = fixture.nativeElement.querySelector('[data-testid="submit-button"]');
const items = fixture.nativeElement.querySelectorAll('[data-testid^="item-"]');
```

### 深淺模式測試

```typescript
it('should apply dark mode classes', () => {
  document.documentElement.classList.add('dark');
  fixture.detectChanges();

  const container = fixture.nativeElement.querySelector('[data-testid="container"]');
  // 驗證 DOM 結構正確渲染，具體樣式由 Tailwind 處理
  expect(container).toBeTruthy();
});
```

## CDK 整合模式

當元件需要底層 UI 行為時，使用 Angular CDK 而非自行實作。完整指引見 `.claude/skills/angular-cdk/SKILL.md`。

### 何時使用 CDK

| 需求 | CDK 模組 | 範例 |
|------|---------|------|
| 浮層定位（dropdown / tooltip / popover） | `@angular/cdk/overlay` | Select, Dropdown, Combobox |
| 焦點鎖定（modal / dialog） | `@angular/cdk/a11y` — FocusTrap | Dialog, Drawer |
| 鍵盤導航列表 | `@angular/cdk/a11y` — ListKeyManager | Listbox, Menu |
| 動態內容投射 | `@angular/cdk/portal` | Dialog content |
| 長列表虛擬捲動 | `@angular/cdk/scrolling` | 列表 > 50 筆 |
| 拖放排序 | `@angular/cdk/drag-drop` | Kanban, 排序列表 |
| Auto-resize textarea | `@angular/cdk/text-field` | 文字輸入區域 |

### CDK Overlay 快速模式

```typescript
// 建立浮層的標準流程
const positionStrategy = this.overlay
  .position()
  .flexibleConnectedTo(this.triggerElement)
  .withPositions(POSITIONS);

const overlayRef = this.overlay.create({
  positionStrategy,
  scrollStrategy: this.overlay.scrollStrategies.reposition(),
  hasBackdrop: true,
  backdropClass: 'cdk-overlay-transparent-backdrop',
});

// 必須處理：背景點擊關閉 + ESC 鍵關閉
overlayRef.backdropClick().subscribe(() => this.close());
overlayRef.keydownEvents()
  .pipe(filter((e) => e.key === 'Escape'))
  .subscribe(() => this.close());
```

### CDK A11y 快速模式

```typescript
// Dialog 必須使用 FocusTrap
template: `
  <div cdkTrapFocus [cdkTrapFocusAutoCapture]="true">
    <!-- dialog content -->
  </div>
`

// 列表鍵盤導航
this.keyManager = new ActiveDescendantKeyManager(this.items)
  .withWrap()
  .withHomeAndEnd();
```

## Showcase 自動整合

建立 Shared Component 時，應同時：

1. 建立 showcase 子元件 `src/app/features/showcase/components/{name}-showcase.component.ts`
2. 將 showcase 元件加入 `showcase.component.ts` 的 `imports` 陣列
3. 在 `showcase.component.html` 中用 `@defer (on viewport)` 包裹新的 showcase section
4. 新增 i18n key 到 `src/assets/i18n/` 三個語系檔案的 `showcase` 區塊

## 程式碼模板

建立元件時可參考 `.claude/templates/` 目錄下的標準模板：

| 模板 | 用途 |
|------|------|
| `component.ts.template` | 元件 TypeScript |
| `component.spec.ts.template` | 元件測試 |
| `service.ts.template` | 服務 TypeScript |
| `service.spec.ts.template` | 服務測試 |
| `page.ts.template` | 頁面元件 |
| `e2e-page.ts.template` | E2E Page Object |
| `e2e-spec.ts.template` | E2E 測試 |

## 檢查清單

- [ ] `standalone: true`
- [ ] `ChangeDetectionStrategy.OnPush`
- [ ] `input()` / `output()` 而非裝飾器
- [ ] `inject()` 而非 constructor 注入
- [ ] `signal()` / `computed()` 管理狀態
- [ ] `@if` / `@for` 控制流
- [ ] `data-testid` 屬性
- [ ] 深淺模式支援（Tailwind v4 語法）
- [ ] 參考 Catalyst UI Kit 視覺設計
- [ ] 完整測試（inputs、outputs、computed、互動行為）
- [ ] 測試命名遵循 `should ... when ...` 格式
- [ ] `index.ts` 匯出
- [ ] CDK Overlay：設定背景點擊關閉 + ESC 關閉（如適用）
- [ ] CDK A11y：Dialog 使用 FocusTrap（如適用）
- [ ] CDK A11y：列表使用 ListKeyManager（如適用）

## 參考資源

- [Angular Style Guide](https://angular.dev/style-guide) — 官方元件命名與結構規範
- [Angular Components CODING_STANDARDS](https://github.com/angular/components/blob/main/CODING_STANDARDS.md) — Angular 官方元件庫的程式碼標準
- [Google TypeScript Style Guide](https://google.github.io/styleguide/tsguide.html) — TypeScript 程式碼風格參考
- [Angular Standalone Components](https://angular.dev/guide/components) — Standalone 元件開發指南
- [Angular Signals](https://angular.dev/guide/signals) — Signal 狀態管理指南


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [angular-conventions](../angular-rules/references/angular-conventions.md) — Standalone、Signal 等強制性 API
- [coding-style](../angular-rules/references/coding-style.md) — 命名、格式與類別成員排序
