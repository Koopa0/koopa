---
name: accessibility
description: >-
  WCAG 2.1 AA compliance patterns — semantic HTML, ARIA, keyboard navigation,
  color contrast, and Angular CDK a11y integration.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Accessibility (WCAG 2.1 AA)

## 觸發條件

- 建立或修改任何 UI 元件時
- 實作表單、對話框、導航等互動元件時
- 進行無障礙稽核或審查時
- 從 Catalyst UI Kit 或 UI Blocks 轉換元件時
- 處理鍵盤導航、焦點管理、螢幕閱讀器支援時

## 程式碼模板 / 核心模式

### 語義化 HTML

```html
<!-- 使用語義標籤 -->
<header>...</header>
<nav aria-label="Main navigation">...</nav>
<main>...</main>
<footer>...</footer>

<!-- 標題層級不跳級 -->
<h1>Page Title</h1>
<h2>Section</h2>
<h3>Subsection</h3>
```

### 表單無障礙

```html
<!-- label 關聯 -->
<label for="email">Email</label>
<input id="email" type="email" aria-describedby="email-hint">
<p id="email-hint">We'll never share your email</p>

<!-- 錯誤訊息 -->
@if (emailControl.errors?.['required'] && emailControl.touched) {
  <p role="alert" aria-live="polite" class="text-red-500">
    Email is required
  </p>
}

<!-- 必填欄位 -->
<label for="name">
  Name <span aria-hidden="true">*</span>
  <span class="sr-only">(required)</span>
</label>
<input id="name" required aria-required="true">
```

### 互動元素

```html
<!-- 按鈕 -->
<button type="button" aria-label="Close dialog">
  <svg aria-hidden="true">...</svg>
</button>

<!-- 連結 -->
<a href="/profile" aria-label="View profile for {{ user.name }}">
  {{ user.name }}
</a>

<!-- 圖片 -->
<img [ngSrc]="photo.url" [alt]="photo.description" width="200" height="150">

<!-- 裝飾性圖片 -->
<img [ngSrc]="decorative.url" alt="" aria-hidden="true" width="100" height="100">
```

### 動態內容

```html
<!-- aria-live 區域 -->
<div aria-live="polite" aria-atomic="true">
  @if (notification()) {
    <p>{{ notification() }}</p>
  }
</div>

<!-- 載入狀態 -->
@if (loading()) {
  <div role="status" aria-label="Loading">
    <span class="sr-only">Loading...</span>
    <app-spinner aria-hidden="true" />
  </div>
}
```

### 鍵盤導航

```typescript
@HostListener('keydown', ['$event'])
handleKeydown(event: KeyboardEvent): void {
  switch (event.key) {
    case 'Escape':
      this.close();
      break;
    case 'ArrowDown':
      this.focusNext();
      break;
    case 'ArrowUp':
      this.focusPrevious();
      break;
  }
}
```

### 焦點管理

```typescript
// 對話框焦點陷阱
import { CdkTrapFocus } from '@angular/cdk/a11y';

@Component({
  imports: [CdkTrapFocus],
  template: `
    <div cdkTrapFocus>
      <h2 id="dialog-title">Dialog</h2>
      <button (click)="close()">Close</button>
    </div>
  `,
})
```

### 色彩對比度

| 文字大小 | 最低對比度 |
|---------|-----------|
| 一般文字 (< 18pt) | 4.5:1 |
| 大型文字 (>= 18pt) | 3:1 |
| UI 元件和圖形 | 3:1 |

## 設計參考資源

### Catalyst 表單元件的 ARIA 模式

**位置**：`tailwind/css/catalyst-ui-kit/typescript/`

Catalyst UI Kit 的元件包含完整的 ARIA 屬性實作。轉換為 Angular 元件時，務必保留所有無障礙相關屬性。

#### 關鍵 ARIA 模式參考

| 元件 | 檔案 | ARIA 模式重點 |
|------|------|-------------|
| Dialog | `dialog.tsx` | `role="dialog"`, `aria-modal="true"`, `aria-labelledby`, 焦點陷阱 |
| Combobox | `combobox.tsx` | `role="combobox"`, `aria-expanded`, `aria-activedescendant`, `aria-controls` |
| Listbox | `listbox.tsx` | `role="listbox"`, `role="option"`, `aria-selected`, 鍵盤導航 |
| Dropdown | `dropdown.tsx` | `role="menu"`, `role="menuitem"`, `aria-haspopup`, 焦點管理 |
| Switch | `switch.tsx` | `role="switch"`, `aria-checked`, 鍵盤 Space/Enter 切換 |
| Checkbox | `checkbox.tsx` | `aria-checked`, `aria-labelledby`, indeterminate 狀態 |
| Radio | `radio.tsx` | `role="radiogroup"`, `role="radio"`, `aria-checked`, 方向鍵導航 |
| Select | `select.tsx` | `aria-expanded`, `aria-labelledby`, `aria-activedescendant` |
| Input | `input.tsx` | `aria-describedby`（錯誤提示）, `aria-invalid`, `aria-required` |
| Fieldset | `fieldset.tsx` | `role="group"`, `aria-labelledby`（legend 關聯） |
| Pagination | `pagination.tsx` | `aria-label="Pagination"`, `aria-current="page"` |
| Navbar | `navbar.tsx` | `role="navigation"`, `aria-label`, 行動版漢堡選單 ARIA |
| Table | `table.tsx` | `role="table"`, `scope="col"`, 排序 `aria-sort` |

#### Catalyst → Angular 無障礙轉換範例

```typescript
// 從 Catalyst Combobox 轉換 — 保留完整 ARIA
@Component({
  selector: 'app-combobox',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="relative">
      <label [id]="labelId()" class="block text-sm/6 font-medium text-zinc-900 dark:text-zinc-100">
        {{ label() }}
      </label>
      <input
        role="combobox"
        [attr.aria-expanded]="isOpen()"
        [attr.aria-controls]="listboxId()"
        [attr.aria-activedescendant]="activeDescendant()"
        [attr.aria-labelledby]="labelId()"
        aria-autocomplete="list"
        (keydown)="handleKeydown($event)"
        data-testid="combobox-input"
      />
      @if (isOpen()) {
        <ul
          [id]="listboxId()"
          role="listbox"
          [attr.aria-labelledby]="labelId()"
        >
          @for (option of filteredOptions(); track option.id) {
            <li
              [id]="'option-' + option.id"
              role="option"
              [attr.aria-selected]="option.id === selectedId()"
              (click)="selectOption(option)"
            >
              {{ option.label }}
            </li>
          }
        </ul>
      }
    </div>
  `,
})
export class ComboboxComponent {
  readonly label = input.required<string>();
  // ... 其餘實作
}
```

### Angular CDK a11y 模組

Angular CDK 提供多項無障礙輔助工具，專案中應優先使用：

#### LiveAnnouncer — 螢幕閱讀器公告

```typescript
import { LiveAnnouncer } from '@angular/cdk/a11y';

@Component({ /* ... */ })
export class NotificationComponent {
  private readonly liveAnnouncer = inject(LiveAnnouncer);

  protected async showNotification(message: string): Promise<void> {
    // 透過螢幕閱讀器播報訊息
    await this.liveAnnouncer.announce(message, 'polite');
  }

  protected async showUrgentAlert(message: string): Promise<void> {
    await this.liveAnnouncer.announce(message, 'assertive');
  }
}
```

#### FocusMonitor — 焦點來源追蹤

```typescript
import { FocusMonitor, FocusOrigin } from '@angular/cdk/a11y';

@Component({ /* ... */ })
export class ButtonComponent implements OnDestroy {
  private readonly focusMonitor = inject(FocusMonitor);
  private readonly elementRef = inject(ElementRef);

  constructor() {
    this.focusMonitor.monitor(this.elementRef, true)
      .pipe(takeUntilDestroyed())
      .subscribe((origin: FocusOrigin) => {
        // origin: 'keyboard' | 'mouse' | 'touch' | 'program' | null
        if (origin === 'keyboard') {
          // 僅在鍵盤焦點時顯示焦點環
          this.showFocusRing.set(true);
        }
      });
  }

  ngOnDestroy(): void {
    this.focusMonitor.stopMonitoring(this.elementRef);
  }
}
```

#### ListKeyManager — 列表鍵盤導航

```typescript
import { ActiveDescendantKeyManager } from '@angular/cdk/a11y';

@Component({ /* ... */ })
export class DropdownComponent implements AfterViewInit {
  private readonly menuItems = viewChildren(MenuItemDirective);
  private keyManager!: ActiveDescendantKeyManager<MenuItemDirective>;

  ngAfterViewInit(): void {
    this.keyManager = new ActiveDescendantKeyManager(this.menuItems())
      .withWrap()           // 到底後循環回頂
      .withHomeAndEnd()     // 支援 Home / End 鍵
      .withTypeAhead(200);  // 輸入字元快速跳轉
  }

  protected handleKeydown(event: KeyboardEvent): void {
    this.keyManager.onKeydown(event);
  }
}
```

#### FocusTrap — 焦點陷阱（對話框）

```typescript
import { CdkTrapFocus } from '@angular/cdk/a11y';

@Component({
  imports: [CdkTrapFocus],
  template: `
    <div
      role="dialog"
      aria-modal="true"
      [attr.aria-labelledby]="titleId"
      cdkTrapFocus
      [cdkTrapFocusAutoCapture]="true"
    >
      <h2 [id]="titleId">對話框標題</h2>
      <div>對話框內容</div>
      <button (click)="close()">關閉</button>
    </div>
  `,
})
export class DialogComponent {
  protected readonly titleId = 'dialog-title-' + Math.random().toString(36).slice(2);
}
```

## 測試指引

### axe-core 單元測試

```typescript
// 安裝：npm install -D axe-core
import axe from 'axe-core';

describe('FormComponent 無障礙', () => {
  it('should have no accessibility violations', async () => {
    const fixture = TestBed.createComponent(FormComponent);
    fixture.detectChanges();

    const results = await axe.run(fixture.nativeElement);
    expect(results.violations).toEqual([]);
  });

  it('should associate labels with inputs', () => {
    const fixture = TestBed.createComponent(FormComponent);
    fixture.detectChanges();

    const input = fixture.debugElement.query(By.css('input[data-testid="email-input"]'));
    const labelId = input.nativeElement.getAttribute('aria-labelledby');
    const label = fixture.debugElement.query(By.css(`#${labelId}`));

    expect(label).toBeTruthy();
    expect(label.nativeElement.textContent).toContain('Email');
  });

  it('should show error with role alert when validation fails', () => {
    const fixture = TestBed.createComponent(FormComponent);
    fixture.detectChanges();

    // 觸發驗證錯誤
    const input = fixture.debugElement.query(By.css('input[data-testid="email-input"]'));
    input.nativeElement.dispatchEvent(new Event('blur'));
    fixture.detectChanges();

    const errorMessage = fixture.debugElement.query(By.css('[role="alert"]'));
    expect(errorMessage).toBeTruthy();
    expect(errorMessage.nativeElement.getAttribute('aria-live')).toBe('polite');
  });
});
```

### Playwright axe-core 整合測試

```typescript
// 安裝：npm install -D @axe-core/playwright
// e2e/tests/a11y/accessibility.spec.ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('全站無障礙稽核', () => {
  const pagesToTest = [
    { name: '首頁', url: '/' },
    { name: '儀表板', url: '/dashboard' },
    { name: '登入', url: '/login' },
    { name: '設定', url: '/settings' },
  ];

  for (const page of pagesToTest) {
    test(`${page.name} should have no accessibility violations`, async ({ page: p }) => {
      await p.goto(page.url);

      const results = await new AxeBuilder({ page: p })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
        .analyze();

      expect(results.violations).toEqual([]);
    });
  }

  test('should be keyboard navigable on dashboard', async ({ page }) => {
    await page.goto('/dashboard');

    // Tab 到第一個互動元素
    await page.keyboard.press('Tab');
    const firstFocused = await page.evaluate(() =>
      document.activeElement?.getAttribute('data-testid')
    );
    expect(firstFocused).toBeTruthy();

    // 確認焦點樣式可見
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  });

  test('should trap focus in dialog', async ({ page }) => {
    await page.goto('/dashboard');

    // 開啟對話框
    await page.getByTestId('open-dialog').click();

    // 確認焦點在對話框內
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();

    // Tab 循環應該在對話框內
    const focusableElements = await dialog.locator(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    ).all();

    // 持續 Tab，焦點不應離開對話框
    for (let i = 0; i < focusableElements.length + 2; i++) {
      await page.keyboard.press('Tab');
      const activeElement = await page.evaluate(() => {
        const el = document.activeElement;
        return el?.closest('[role="dialog"]') !== null;
      });
      expect(activeElement).toBe(true);
    }
  });

  test('should announce dynamic content changes', async ({ page }) => {
    await page.goto('/dashboard');

    // 檢查 aria-live 區域存在
    const liveRegion = page.locator('[aria-live]');
    await expect(liveRegion.first()).toBeAttached();
  });
});
```

### 色彩對比度測試

```typescript
// e2e/tests/a11y/contrast.spec.ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('色彩對比度', () => {
  test('should meet WCAG AA contrast in light mode', async ({ page }) => {
    await page.goto('/dashboard');
    await page.evaluate(() => document.documentElement.classList.remove('dark'));

    const results = await new AxeBuilder({ page })
      .withRules(['color-contrast'])
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('should meet WCAG AA contrast in dark mode', async ({ page }) => {
    await page.goto('/dashboard');
    await page.evaluate(() => document.documentElement.classList.add('dark'));

    const results = await new AxeBuilder({ page })
      .withRules(['color-contrast'])
      .analyze();

    expect(results.violations).toEqual([]);
  });
});
```

## 檢查清單

- [ ] 所有圖片有 `alt`（裝飾性圖片 `alt=""` + `aria-hidden="true"`）
- [ ] 所有表單輸入有關聯的 `<label>`
- [ ] 所有互動元素可鍵盤操作（Tab / Enter / Space / Escape / Arrow keys）
- [ ] Tab 順序合理且符合視覺閱讀順序
- [ ] 焦點樣式可見（`focus:ring-3 focus:ring-primary-500`）
- [ ] 色彩對比度達標（一般文字 4.5:1，大型文字 3:1）
- [ ] 使用語義 HTML 標籤（`<header>`, `<nav>`, `<main>`, `<footer>`, `<section>`）
- [ ] 動態內容有 `aria-live` 區域
- [ ] 對話框有焦點陷阱（`cdkTrapFocus`）
- [ ] 頁面有唯一 `<h1>`，標題不跳級
- [ ] 錯誤訊息使用 `role="alert"` + `aria-live="polite"`
- [ ] 載入狀態使用 `role="status"`
- [ ] Icon 按鈕有 `aria-label`
- [ ] 使用 `NgOptimizedImage` 處理所有圖片
- [ ] Catalyst 元件的 ARIA 屬性已完整轉換
- [ ] Angular CDK a11y 模組已適當使用（FocusTrap / LiveAnnouncer / ListKeyManager）
- [ ] axe-core 測試通過（無 violations）
- [ ] Playwright 鍵盤導航測試通過

## 參考資源

- [WCAG 2.1 Guidelines](https://www.w3.org/TR/WCAG21/)
- [WCAG 2.1 Quick Reference](https://www.w3.org/WAI/WCAG21/quickref/)
- [Angular CDK Accessibility](https://material.angular.io/cdk/a11y/overview)
- [Angular Accessibility Guide](https://angular.dev/best-practices/a11y)
- [WAI-ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/)
- [axe-core Rules](https://github.com/dequelabs/axe-core/blob/develop/doc/rule-descriptions.md)
- [Catalyst UI Kit](https://catalyst.tailwindui.com) — ARIA 模式參考


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [angular-conventions](../angular-rules/references/angular-conventions.md) — Standalone、Signal 等強制性 API
- [ui-components](../angular-rules/references/ui-components.md) — 三層 UI 元件策略與 CDK A11y
- [coding-style](../angular-rules/references/coding-style.md) — 命名與程式碼格式規範
