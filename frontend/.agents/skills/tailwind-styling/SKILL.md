---
name: tailwind-styling
description: >-
  Tailwind CSS v4 styling reference — v3-to-v4 breaking changes, dark mode,
  responsive design, spacing system, and Catalyst UI Kit conversion.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Tailwind CSS Styling

## 觸發條件

- 建立或修改任何 UI 元件的樣式時
- 需要使用 Tailwind CSS utility classes 時
- 從 Catalyst UI Kit 或 UI Blocks 轉換設計時
- 進行響應式設計或深淺模式實作時
- 任何涉及 CSS 樣式的變更

## 基本原則

- 所有樣式使用 Tailwind CSS v4 utility classes
- 禁止 inline styles
- 禁止 `@apply`（v4 已移除，使用 CSS variables 或元件封裝）
- Mobile-first 響應式設計
- 深淺模式支援（`dark:` 前綴）
- 完整的 v4 規則請參閱：`tailwind/css/rules/tailwind.md`

## Tailwind CSS v4 關鍵規則

### 禁止的 v3 語法

| 禁止 | 替代 |
|------|------|
| `bg-opacity-*` | `bg-black/50`（opacity modifier） |
| `text-opacity-*` | `text-black/50` |
| `bg-gradient-*` | `bg-linear-*` |
| `shadow-sm` | `shadow-xs` |
| `shadow` | `shadow-sm` |
| `rounded-sm` | `rounded-xs` |
| `rounded` | `rounded-sm` |
| `outline-none` | `outline-hidden` |
| `ring` | `ring-3` |
| `leading-*` | `text-base/7`（line height modifier） |
| `space-x-*` | `gap-*`（flex/grid 中） |
| `@apply` | CSS variables / `--spacing()` |
| `min-h-screen` | `min-h-dvh` |

### Typography

```html
<!-- 使用 line height modifier -->
<p class="text-base/7">Body text</p>
<h1 class="text-2xl/8 font-bold">Heading</h1>
```

### Spacing

```html
<!-- 使用 gap 而非 space-x -->
<div class="flex gap-4">...</div>
<div class="grid grid-cols-3 gap-6">...</div>
```

## 色彩系統

| 用途 | 色彩 |
|------|------|
| 中性色 | `zinc` |
| 品牌主色 | `primary`（自定義） |
| 成功 | `emerald` |
| 警告 | `amber` |
| 錯誤 | `red` |
| 資訊 | `sky` |

## 深淺模式

Light-first 撰寫，`dark:` 覆蓋：

```html
<div class="bg-white text-zinc-900 dark:bg-zinc-900 dark:text-zinc-100">
  <h1 class="text-zinc-900 dark:text-zinc-100">Title</h1>
  <p class="text-zinc-600 dark:text-zinc-400">Description</p>
</div>
```

## 響應式斷點（Mobile-First）

| 前綴 | 最小寬度 |
|------|---------|
| `sm:` | 640px |
| `md:` | 768px |
| `lg:` | 1024px |
| `xl:` | 1280px |
| `2xl:` | 1536px |

---

## 設計參考資源

### Catalyst UI Kit — 元件設計基準

**位置**：`tailwind/css/catalyst-ui-kit/`

Catalyst 是 Tailwind CSS Plus 的 React 元件庫。在本專案中，**作為 Angular 元件的視覺設計和 HTML/class 結構參考**。

#### 可用元件目錄

| 元件 | 檔案 | 用途 | Angular 對應 |
|------|------|------|-------------|
| Alert | `typescript/alert.tsx` | 提示訊息 | `shared/components/alert/` |
| Avatar | `typescript/avatar.tsx` | 使用者頭像 | `shared/components/avatar/` |
| Badge | `typescript/badge.tsx` | 標記標籤 | `shared/components/badge/` |
| Button | `typescript/button.tsx` | 按鈕 | `shared/components/button/` |
| Checkbox | `typescript/checkbox.tsx` | 核取方塊 | `shared/components/checkbox/` |
| Combobox | `typescript/combobox.tsx` | 搜尋下拉 | `shared/components/combobox/` |
| Description List | `typescript/description-list.tsx` | 描述列表 | `shared/components/description-list/` |
| Dialog | `typescript/dialog.tsx` | 對話框 | `shared/components/dialog/` |
| Divider | `typescript/divider.tsx` | 分隔線 | `shared/components/divider/` |
| Dropdown | `typescript/dropdown.tsx` | 下拉選單 | `shared/components/dropdown/` |
| Fieldset | `typescript/fieldset.tsx` | 表單群組 | `shared/components/fieldset/` |
| Heading | `typescript/heading.tsx` | 標題 | `shared/components/heading/` |
| Input | `typescript/input.tsx` | 輸入框 | `shared/components/input/` |
| Link | `typescript/link.tsx` | 連結 | `shared/components/link/` |
| Listbox | `typescript/listbox.tsx` | 列表選擇 | `shared/components/listbox/` |
| Navbar | `typescript/navbar.tsx` | 導航列 | `core/layout/navbar/` |
| Pagination | `typescript/pagination.tsx` | 分頁 | `shared/components/pagination/` |
| Radio | `typescript/radio.tsx` | 單選按鈕 | `shared/components/radio/` |
| Select | `typescript/select.tsx` | 下拉選擇 | `shared/components/select/` |
| Sidebar | `typescript/sidebar.tsx` | 側邊欄 | `core/layout/sidebar/` |
| Sidebar Layout | `typescript/sidebar-layout.tsx` | 側邊欄佈局 | `core/layout/sidebar-layout/` |
| Stacked Layout | `typescript/stacked-layout.tsx` | 堆疊佈局 | `core/layout/stacked-layout/` |
| Switch | `typescript/switch.tsx` | 開關 | `shared/components/switch/` |
| Table | `typescript/table.tsx` | 表格 | `shared/components/table/` |
| Text | `typescript/text.tsx` | 文字段落 | `shared/components/text/` |
| Textarea | `typescript/textarea.tsx` | 多行輸入 | `shared/components/textarea/` |

**Demo 應用**：`tailwind/css/catalyst-ui-kit/demo/typescript/src/`（含完整頁面範例）

#### React → Angular 轉換流程

1. **讀取 React 元件**：`Read tailwind/css/catalyst-ui-kit/typescript/{component}.tsx`
2. **提取 Tailwind classes**：複製 `styles` 物件和 JSX 中的 class 字串
3. **提取 HTML 結構**：將 JSX 轉為 Angular template
4. **轉換對應關係**：

| React (Catalyst) | Angular |
|-------------------|---------|
| `React.forwardRef` | 不需要（Angular 有自己的 ViewChild） |
| `clsx(...)` | `[class]="..."` 或直接寫 class |
| `{...props}` | Angular `input()` / `output()` |
| Headless UI `<Dialog>` | Angular CDK Dialog 或自建 |
| `<Link href>` | `<a routerLink>` |
| `data-slot` attributes | 保留，用於樣式 targeting |
| `clsx` conditionals | `[class.xxx]="condition()"` |

5. **包裝為 Angular component**：

```typescript
// 範例：從 Catalyst Button 轉換
@Component({
  selector: 'app-button',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button
      [class]="buttonClasses()"
      [disabled]="disabled()"
      [type]="type()"
      data-testid="button"
    >
      <ng-content />
    </button>
  `,
})
export class ButtonComponent {
  readonly variant = input<'solid' | 'outline'>('solid');
  readonly color = input<string>('primary');
  readonly disabled = input(false);
  readonly type = input<'button' | 'submit'>('button');

  protected readonly buttonClasses = computed(() => {
    const base = 'relative isolate inline-flex items-center justify-center gap-x-2 rounded-sm border text-base/6 font-semibold';
    const sizing = 'px-[calc(--spacing(3.5)-1px)] py-[calc(--spacing(2.5)-1px)] sm:px-[calc(--spacing(3)-1px)] sm:py-[calc(--spacing(1.5)-1px)] sm:text-sm/6';
    // ... variant-specific classes from Catalyst
    return `${base} ${sizing} ${variantClasses}`;
  });
}
```

### UI Blocks — 頁面佈局和元件參考

**位置**：`tailwind/css/ui-blocks/`

全部為純 HTML + Tailwind classes，可直接提取使用。

#### Application UI（應用介面）

| 分類 | 路徑 | 包含 |
|------|------|------|
| Application Shells | `application-ui/application-shells/` | sidebar / stacked / multi-column layouts |
| Data Display | `application-ui/data-display/` | calendars / stats / description lists |
| Elements | `application-ui/elements/` | avatars / badges / buttons / dropdowns |
| Feedback | `application-ui/feedback/` | alerts / empty states |
| Forms | `application-ui/forms/` | inputs / checkboxes / radio / toggles / sign-in / comboboxes |
| Headings | `application-ui/headings/` | page / section / card headings |
| Layout | `application-ui/layout/` | cards / containers / dividers / media objects |
| Lists | `application-ui/lists/` | tables / stacked lists / grid lists / feeds |
| Navigation | `application-ui/navigation/` | navbars / tabs / breadcrumbs / pagination / command palettes |
| Overlays | `application-ui/overlays/` | modal dialogs / drawers / notifications |
| Page Examples | `application-ui/page-examples/` | home / detail / settings screens |

#### Ecommerce（電商）

| 分類 | 路徑 |
|------|------|
| Components | `ecommerce/components/` — product overviews / shopping carts / checkout forms / reviews |
| Pages | `ecommerce/page-examples/` — storefront / category / product / cart / checkout / order |

#### Marketing（行銷）

| 分類 | 路徑 |
|------|------|
| Elements | `marketing/elements/` — banners / headers / flyout menus |
| Sections | `marketing/sections/` — heroes / features / pricing / testimonials / CTAs / footers |
| Pages | `marketing/page-examples/` — landing / about / pricing pages |
| Feedback | `marketing/feedback/` — 404 pages |

#### UI Block 使用流程

1. **確認需要什麼佈局或元件**
2. **查找對應分類目錄**（例如需要表單 → `application-ui/forms/`）
3. **讀取 HTML 檔案**：`Read tailwind/css/ui-blocks/{path}/{variant}.html`
4. **提取 HTML 結構和 Tailwind classes**
5. **轉換為 Angular template**：
   - 將靜態 HTML 改為 Angular `@if` / `@for` 控制流
   - 將 `<a href>` 改為 `<a routerLink>`
   - 將互動元素綁定到 Signal 和事件
   - 加入 `data-testid` 屬性
6. **加入深淺模式支援**：確保所有色彩有 `dark:` 對應
7. **檢查 v4 相容性**：對照 `tailwind/css/rules/tailwind.md` 確認無 v3 語法

### Tailwind v4 完整規則

**位置**：`tailwind/css/rules/tailwind.md`

包含：
- 移除/重命名的 utilities 完整清單
- Layout / spacing / typography / color 規則
- Container queries 用法
- Text shadows / masking 新功能
- CSS variables 和 `--spacing()` 函數用法
- 常見陷阱（Common Pitfalls）

**建立元件或修改樣式前，務必參閱此檔案確認 v4 語法正確。**

---

## 程式碼模板 / 核心模式

### 常用元件模式

```html
<!-- Card (v4 語法) -->
<div class="rounded-sm border border-zinc-200 bg-white p-6 shadow-xs dark:border-zinc-700 dark:bg-zinc-800">
  <h3 class="text-lg/7 font-semibold text-zinc-900 dark:text-zinc-100">Card Title</h3>
  <p class="mt-2 text-sm/6 text-zinc-600 dark:text-zinc-400">Card content</p>
</div>

<!-- Button (v4 語法) -->
<button class="rounded-sm bg-primary-600 px-4 py-2 text-sm/6 font-medium text-white shadow-xs hover:bg-primary-500 focus:outline-hidden focus:ring-3 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50">
  Button
</button>

<!-- Input (v4 語法) -->
<input class="block w-full rounded-sm border border-zinc-300 bg-white px-3 py-2 text-sm/6 text-zinc-900 shadow-xs placeholder:text-zinc-400 focus:border-primary-500 focus:ring-3 focus:ring-primary-500 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-100">
```

## 測試指引

### 樣式相關測試模式

```typescript
// 測試 Tailwind classes 是否正確套用
describe('ButtonComponent', () => {
  it('should apply solid variant classes when variant is solid', () => {
    const fixture = TestBed.createComponent(ButtonComponent);
    fixture.componentRef.setInput('variant', 'solid');
    fixture.detectChanges();

    const button = fixture.debugElement.query(By.css('[data-testid="button"]'));
    expect(button.nativeElement.className).toContain('bg-primary-600');
  });

  it('should apply outline variant classes when variant is outline', () => {
    const fixture = TestBed.createComponent(ButtonComponent);
    fixture.componentRef.setInput('variant', 'outline');
    fixture.detectChanges();

    const button = fixture.debugElement.query(By.css('[data-testid="button"]'));
    expect(button.nativeElement.className).toContain('border');
  });
});
```

### Playwright 視覺回歸測試

```typescript
// e2e/tests/visual/button.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Button 視覺回歸', () => {
  test('should match solid button snapshot', async ({ page }) => {
    await page.goto('/storybook/button');
    const button = page.getByTestId('button-solid');
    await expect(button).toHaveScreenshot('button-solid.png');
  });

  test('should match responsive layout on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/dashboard');
    await expect(page).toHaveScreenshot('dashboard-mobile.png');
  });
});
```

## WCAG AA 對比度

一般文字 4.5:1，大型文字 3:1。

## 檢查清單

- [ ] 所有樣式使用 Tailwind CSS v4 utility classes，無 inline styles
- [ ] 無 v3 遺留語法（`shadow-sm` → `shadow-xs`、`rounded-sm` → `rounded-xs` 等）
- [ ] 無 `@apply` 使用
- [ ] 所有色彩有 `dark:` 前綴對應
- [ ] Mobile-first 響應式設計（從小螢幕往上加斷點）
- [ ] WCAG AA 對比度達標（一般文字 4.5:1，大型文字 3:1）
- [ ] 使用專案色彩系統（zinc / primary / emerald / amber / red / sky）
- [ ] 參考 Catalyst UI Kit 元件設計
- [ ] 對照 `tailwind/css/rules/tailwind.md` 確認 v4 語法正確
- [ ] 使用 `gap-*` 取代 `space-x-*` / `space-y-*`

## 參考資源

- [Angular Style Guide](https://angular.dev/style-guide)
- [Tailwind CSS v4 Docs](https://tailwindcss.com/docs)
- [Catalyst UI Kit](https://catalyst.tailwindui.com)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [tailwind-patterns](../angular-rules/references/tailwind-patterns.md) — Tailwind v4 完整規則與色彩系統
- [ui-components](../angular-rules/references/ui-components.md) — Catalyst UI Kit 轉換流程
