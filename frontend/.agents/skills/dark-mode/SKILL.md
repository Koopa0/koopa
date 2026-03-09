---
name: dark-mode
description: >-
  Dark/light theme implementation — ThemeService, Tailwind dark: prefix,
  default dark mode, and instant theme switching.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Dark Mode

## 觸發條件

- 建立或修改任何 UI 元件時
- 設計色彩方案或主題切換功能時
- 審查元件是否支援深淺模式時
- 使用 Catalyst UI Kit 或 UI Blocks 轉換元件時
- 修改背景、文字、邊框等色彩相關樣式時

## 策略

- 預設深色模式
- 使用 Tailwind `dark:` 前綴
- 切換即時生效（不需要頁面重載）
- 使用 ThemeService 管理主題

## 程式碼模板 / 核心模式

### ThemeService

```typescript
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly _theme = signal<'light' | 'dark'>('dark');
  readonly theme = this._theme.asReadonly();
  readonly isDark = computed(() => this._theme() === 'dark');

  constructor() {
    // 從系統偏好初始化
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    this._theme.set(prefersDark ? 'dark' : 'light');
    this.applyTheme();
  }

  toggle(): void {
    this._theme.update(t => t === 'dark' ? 'light' : 'dark');
    this.applyTheme();
  }

  private applyTheme(): void {
    const root = document.documentElement;
    if (this._theme() === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }
}
```

### 元件樣式指南

```html
<!-- 背景 -->
<div class="bg-white dark:bg-zinc-900">

<!-- 文字 -->
<h1 class="text-zinc-900 dark:text-zinc-100">
<p class="text-zinc-600 dark:text-zinc-400">

<!-- 邊框 -->
<div class="border border-zinc-200 dark:border-zinc-700">

<!-- 輸入框 -->
<input class="bg-white text-zinc-900 border-zinc-300 dark:bg-zinc-800 dark:text-zinc-100 dark:border-zinc-600">

<!-- 卡片 -->
<div class="bg-white shadow-sm dark:bg-zinc-800">

<!-- 懸停 -->
<button class="hover:bg-zinc-100 dark:hover:bg-zinc-700">
```

## 色彩對照表

| 元素 | Light | Dark |
|------|-------|------|
| 背景 | `bg-white` | `bg-zinc-900` |
| 卡片 | `bg-white` | `bg-zinc-800` |
| 主要文字 | `text-zinc-900` | `text-zinc-100` |
| 次要文字 | `text-zinc-600` | `text-zinc-400` |
| 邊框 | `border-zinc-200` | `border-zinc-700` |
| 輸入框背景 | `bg-white` | `bg-zinc-800` |
| 懸停 | `hover:bg-zinc-100` | `hover:bg-zinc-700` |
| 分隔線 | `divide-zinc-200` | `divide-zinc-700` |
| 次要背景 | `bg-zinc-50` | `bg-zinc-800/50` |
| 焦點環 | `ring-primary-500` | `ring-primary-400` |
| 錯誤文字 | `text-red-600` | `text-red-400` |
| 成功文字 | `text-emerald-600` | `text-emerald-400` |
| 警告文字 | `text-amber-600` | `text-amber-400` |

## 設計參考資源

### Catalyst UI Kit 色彩參考

**位置**：`tailwind/css/catalyst-ui-kit/`

Catalyst 元件提供了完整的深淺模式色彩方案。轉換元件時，務必提取其 `dark:` 前綴的 class 對應。

#### 重要色彩模式參考

| 元件 | 檔案 | 深淺模式重點 |
|------|------|-------------|
| Button | `typescript/button.tsx` | solid / outline 按鈕在深淺模式下的色彩變化 |
| Input | `typescript/input.tsx` | 輸入框背景、邊框、placeholder 色彩 |
| Table | `typescript/table.tsx` | 表格行交替色、hover 效果 |
| Sidebar | `typescript/sidebar.tsx` | 導航項目的 active / hover 狀態色彩 |
| Dialog | `typescript/dialog.tsx` | 對話框背景、遮罩層色彩 |
| Alert | `typescript/alert.tsx` | 不同狀態（success / warning / error）的深淺色彩 |
| Badge | `typescript/badge.tsx` | 標籤在深淺模式下的色彩對比 |

#### 轉換範例

```typescript
// 從 Catalyst Alert 提取深淺模式色彩
@Component({
  selector: 'app-alert',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div
      [class]="alertClasses()"
      role="alert"
      data-testid="alert"
    >
      <ng-content />
    </div>
  `,
})
export class AlertComponent {
  readonly variant = input<'info' | 'success' | 'warning' | 'error'>('info');

  protected readonly alertClasses = computed(() => {
    const base = 'rounded-sm p-4 text-sm/6';

    const variantMap: Record<string, string> = {
      info: 'bg-sky-50 text-sky-800 dark:bg-sky-950 dark:text-sky-200',
      success: 'bg-emerald-50 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200',
      warning: 'bg-amber-50 text-amber-800 dark:bg-amber-950 dark:text-amber-200',
      error: 'bg-red-50 text-red-800 dark:bg-red-950 dark:text-red-200',
    };

    return `${base} ${variantMap[this.variant()]}`;
  });
}
```

### UI Blocks 深淺模式注意

UI Blocks 中的 HTML 範例大多只有 light 模式。轉換為 Angular 元件時，**必須手動加入 `dark:` 前綴**，參照色彩對照表。

## 測試指引

### 單元測試

```typescript
describe('ThemeService', () => {
  let service: ThemeService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ThemeService);
  });

  it('should toggle theme from dark to light', () => {
    // 預設深色
    expect(service.isDark()).toBe(true);

    service.toggle();
    expect(service.isDark()).toBe(false);
    expect(service.theme()).toBe('light');
  });

  it('should apply dark class to document root when dark mode', () => {
    service.toggle(); // 切到 light
    service.toggle(); // 切回 dark

    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });
});
```

### 元件深淺模式測試

```typescript
describe('AlertComponent 深淺模式', () => {
  it('should include dark mode classes', () => {
    const fixture = TestBed.createComponent(AlertComponent);
    fixture.componentRef.setInput('variant', 'error');
    fixture.detectChanges();

    const alert = fixture.debugElement.query(By.css('[data-testid="alert"]'));
    const classes = alert.nativeElement.className;

    // 確認同時包含 light 和 dark 色彩
    expect(classes).toContain('bg-red-50');
    expect(classes).toContain('dark:bg-red-950');
  });
});
```

### Playwright 截圖對比測試

```typescript
// e2e/tests/visual/dark-mode.spec.ts
import { test, expect } from '@playwright/test';

test.describe('深淺模式視覺測試', () => {
  test('should render correctly in dark mode', async ({ page }) => {
    await page.goto('/dashboard');
    // 確保深色模式
    await page.evaluate(() => document.documentElement.classList.add('dark'));
    await expect(page).toHaveScreenshot('dashboard-dark.png');
  });

  test('should render correctly in light mode', async ({ page }) => {
    await page.goto('/dashboard');
    // 切換到淺色模式
    await page.evaluate(() => document.documentElement.classList.remove('dark'));
    await expect(page).toHaveScreenshot('dashboard-light.png');
  });

  test('should toggle theme instantly', async ({ page }) => {
    await page.goto('/dashboard');
    const toggleButton = page.getByTestId('theme-toggle');

    // 截圖 - 深色模式
    await expect(page).toHaveScreenshot('before-toggle.png');

    // 切換主題
    await toggleButton.click();

    // 截圖 - 淺色模式
    await expect(page).toHaveScreenshot('after-toggle.png');
  });

  test('should maintain theme consistency across pages', async ({ page }) => {
    await page.goto('/dashboard');
    await page.evaluate(() => document.documentElement.classList.remove('dark'));

    // 導航到另一頁面
    await page.goto('/settings');

    // 確認主題狀態保持
    const isDark = await page.evaluate(() =>
      document.documentElement.classList.contains('dark')
    );
    expect(isDark).toBe(false);
  });
});
```

### 色彩對比度驗證

```typescript
// e2e/tests/a11y/contrast.spec.ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('色彩對比度（深淺模式）', () => {
  test('should pass contrast check in dark mode', async ({ page }) => {
    await page.goto('/dashboard');
    await page.evaluate(() => document.documentElement.classList.add('dark'));

    const results = await new AxeBuilder({ page })
      .withRules(['color-contrast'])
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('should pass contrast check in light mode', async ({ page }) => {
    await page.goto('/dashboard');
    await page.evaluate(() => document.documentElement.classList.remove('dark'));

    const results = await new AxeBuilder({ page })
      .withRules(['color-contrast'])
      .analyze();

    expect(results.violations).toEqual([]);
  });
});
```

## 檢查清單

- [ ] 所有背景色有 `dark:` 對應
- [ ] 所有文字色有 `dark:` 對應
- [ ] 所有邊框色有 `dark:` 對應
- [ ] 分隔線有 `dark:` 對應（`divide-zinc-200 dark:divide-zinc-700`）
- [ ] 圖片在深色背景上可見
- [ ] SVG 圖示色彩在深淺模式皆可見
- [ ] 色彩對比度符合 WCAG AA（一般文字 4.5:1，大型文字 3:1）
- [ ] 切換即時生效，無閃爍
- [ ] hover / focus / active 狀態有 `dark:` 對應
- [ ] 錯誤 / 成功 / 警告狀態的色彩在深淺模式皆清楚可辨
- [ ] Catalyst UI Kit 色彩方案已正確轉換
- [ ] Playwright 截圖對比測試通過

## 參考資源

- [Tailwind CSS Dark Mode](https://tailwindcss.com/docs/dark-mode)
- [Tailwind CSS v4 Docs](https://tailwindcss.com/docs)
- [Catalyst UI Kit](https://catalyst.tailwindui.com)
- [WCAG 2.1 Contrast Requirements](https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html)
- [Angular Style Guide](https://angular.dev/style-guide)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [tailwind-patterns](../angular-rules/references/tailwind-patterns.md) — Tailwind v4 深色模式與色彩系統
- [ui-components](../angular-rules/references/ui-components.md) — 元件深淺模式支援要求
