---
name: angular-e2e
description: >-
  Playwright E2E testing — Page Object pattern, user flow tests, dark mode
  verification, responsive layout, and accessibility checks.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular E2E Testing

## 觸發條件

當使用者要求以下任務時啟用此技能：

- 建立或修改 E2E 測試（Playwright）
- 建立 Page Object 模式
- 測試深淺模式切換
- 測試響應式佈局（多裝置視口）
- 執行無障礙（a11y）自動化測試
- 建立截圖比對測試
- 使用 `/e2e` 指令

## 框架

Playwright

## Page Object Pattern

```typescript
// e2e/pages/{feature}.page.ts
import { type Page, type Locator } from '@playwright/test';

export class {Feature}Page {
  readonly heading: Locator;
  readonly submitButton: Locator;
  readonly errorMessage: Locator;

  constructor(private readonly page: Page) {
    this.heading = page.getByTestId('heading');
    this.submitButton = page.getByTestId('submit-button');
    this.errorMessage = page.getByTestId('error-message');
  }

  async goto(): Promise<void> {
    await this.page.goto('/{feature}');
  }

  async submit(): Promise<void> {
    await this.submitButton.click();
  }

  async fillForm(data: Record<string, string>): Promise<void> {
    for (const [field, value] of Object.entries(data)) {
      await this.page.getByTestId(field).fill(value);
    }
  }
}
```

## 測試模板

```typescript
// e2e/tests/{feature}/{feature}.spec.ts
import { test, expect } from '@playwright/test';
import { {Feature}Page } from '../../pages/{feature}.page';

test.describe('{Feature Name}', () => {
  let featurePage: {Feature}Page;

  test.beforeEach(async ({ page }) => {
    featurePage = new {Feature}Page(page);
    await featurePage.goto();
  });

  test('should display page heading', async () => {
    await expect(featurePage.heading).toBeVisible();
    await expect(featurePage.heading).toHaveText('{Expected Title}');
  });

  test('should show error when form is invalid', async () => {
    await featurePage.submit();
    await expect(featurePage.errorMessage).toBeVisible();
  });
});
```

## 選擇器策略

優先順序：
1. `data-testid` 屬性（`page.getByTestId()`）
2. ARIA role 和 label（`page.getByRole()`）
3. 文字內容（`page.getByText()`）
4. CSS 選擇器（最後手段）

## 禁止事項

- 不使用 `page.waitForTimeout()`（用自動等待）
- 不使用脆弱的 CSS 選擇器
- 不寫相依的測試
- 不使用 `page.evaluate()` 存取 Angular 內部

## 配置

```typescript
// playwright.config.ts
export default defineConfig({
  testDir: './e2e/tests',
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
```

## 深淺模式測試

使用截圖比對驗證深色與淺色模式的視覺正確性。透過 `emulateMedia` 或手動切換 `ThemeService` 來切換主題。

```typescript
// e2e/tests/{feature}/{feature}-theme.spec.ts
import { test, expect } from '@playwright/test';
import { {Feature}Page } from '../../pages/{feature}.page';

test.describe('{Feature} 深淺模式', () => {
  let featurePage: {Feature}Page;

  test.beforeEach(async ({ page }) => {
    featurePage = new {Feature}Page(page);
    await featurePage.goto();
  });

  test('should render correctly in dark mode', async ({ page }) => {
    // 預設為深色模式
    await page.emulateMedia({ colorScheme: 'dark' });
    await expect(page).toHaveScreenshot('{feature}-dark.png', {
      maxDiffPixelRatio: 0.01,
    });
  });

  test('should render correctly in light mode', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await expect(page).toHaveScreenshot('{feature}-light.png', {
      maxDiffPixelRatio: 0.01,
    });
  });

  test('should switch theme without layout shift', async ({ page }) => {
    // 深色 → 淺色切換
    await page.emulateMedia({ colorScheme: 'dark' });
    const darkBg = await page.locator('body').evaluate(
      (el) => getComputedStyle(el).backgroundColor,
    );

    await page.emulateMedia({ colorScheme: 'light' });
    const lightBg = await page.locator('body').evaluate(
      (el) => getComputedStyle(el).backgroundColor,
    );

    expect(darkBg).not.toEqual(lightBg);

    // 確認切換後無佈局偏移
    await expect(page).toHaveScreenshot('{feature}-after-switch.png', {
      maxDiffPixelRatio: 0.01,
    });
  });
});
```

### 截圖比對配置

```typescript
// playwright.config.ts
export default defineConfig({
  expect: {
    toHaveScreenshot: {
      // 容許極小的像素差異（抗鋸齒等）
      maxDiffPixelRatio: 0.01,
      // 截圖儲存路徑
      snapshotPathTemplate: '{testDir}/__screenshots__/{testFilePath}/{arg}{ext}',
    },
  },
  // 第一次執行時自動產生基準截圖
  updateSnapshots: 'missing',
});
```

## 響應式測試

針對 4 種視口進行測試，確保佈局在各裝置上正確呈現。

```typescript
// e2e/tests/{feature}/{feature}-responsive.spec.ts
import { test, expect } from '@playwright/test';
import { {Feature}Page } from '../../pages/{feature}.page';

/** 四種標準視口尺寸 */
const VIEWPORTS = [
  { name: 'desktop', width: 1920, height: 1080 },
  { name: 'laptop', width: 1366, height: 768 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'mobile', width: 375, height: 667 },
] as const;

for (const viewport of VIEWPORTS) {
  test.describe(`{Feature} @ ${viewport.name} (${viewport.width}x${viewport.height})`, () => {
    test.use({
      viewport: { width: viewport.width, height: viewport.height },
    });

    let featurePage: {Feature}Page;

    test.beforeEach(async ({ page }) => {
      featurePage = new {Feature}Page(page);
      await featurePage.goto();
    });

    test(`should render correctly on ${viewport.name}`, async ({ page }) => {
      await expect(page).toHaveScreenshot(
        `{feature}-${viewport.name}.png`,
        { maxDiffPixelRatio: 0.01 },
      );
    });

    test(`should display heading on ${viewport.name}`, async () => {
      await expect(featurePage.heading).toBeVisible();
    });

    // 行動裝置專屬：漢堡選單可見性
    if (viewport.width < 768) {
      test('should show mobile navigation menu', async ({ page }) => {
        const mobileMenuButton = page.getByTestId('mobile-menu-button');
        await expect(mobileMenuButton).toBeVisible();
      });
    }

    // 桌面專屬：側邊欄可見性
    if (viewport.width >= 1024) {
      test('should show sidebar navigation', async ({ page }) => {
        const sidebar = page.getByTestId('sidebar');
        await expect(sidebar).toBeVisible();
      });
    }
  });
}
```

## 無障礙（a11y）自動化測試

整合 `@axe-core/playwright` 進行 WCAG AA 合規性自動檢測。

### 安裝

```bash
npm install -D @axe-core/playwright
```

### a11y 測試範例

```typescript
// e2e/tests/{feature}/{feature}-a11y.spec.ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { {Feature}Page } from '../../pages/{feature}.page';

test.describe('{Feature} 無障礙', () => {
  let featurePage: {Feature}Page;

  test.beforeEach(async ({ page }) => {
    featurePage = new {Feature}Page(page);
    await featurePage.goto();
  });

  test('should have no a11y violations (WCAG AA)', async ({ page }) => {
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('should have no a11y violations in dark mode', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('should have no a11y violations in light mode', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('should be navigable by keyboard only', async ({ page }) => {
    // Tab 到第一個互動元素
    await page.keyboard.press('Tab');
    const firstFocused = await page.evaluate(() => document.activeElement?.tagName);
    expect(firstFocused).toBeTruthy();

    // 確認焦點樣式可見
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  });

  test('should have proper ARIA landmarks', async ({ page }) => {
    // 主要 landmark 存在
    await expect(page.getByRole('main')).toBeVisible();
    await expect(page.getByRole('navigation')).toBeVisible();
  });
});
```

### a11y 工具函式

```typescript
// e2e/utils/a11y.utils.ts
import AxeBuilder from '@axe-core/playwright';
import { type Page, expect } from '@playwright/test';

/**
 * 執行 WCAG AA 無障礙掃描並斷言無違規
 *
 * @param page - Playwright Page 物件
 * @param options - 自訂 axe 選項
 */
export async function assertNoA11yViolations(
  page: Page,
  options?: {
    disableRules?: string[];
    includeSelector?: string;
  },
): Promise<void> {
  let builder = new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']);

  if (options?.disableRules) {
    builder = builder.disableRules(options.disableRules);
  }

  if (options?.includeSelector) {
    builder = builder.include(options.includeSelector);
  }

  const results = await builder.analyze();

  // 輸出詳細違規資訊便於除錯
  if (results.violations.length > 0) {
    const violationSummary = results.violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      description: v.description,
      nodes: v.nodes.length,
    }));
    // 使用 debug 註記輸出
    // debug: a11y violations found
    console.log('a11y violations:', JSON.stringify(violationSummary, null, 2));
  }

  expect(results.violations).toEqual([]);
}
```

## 測試指引

### 測試命名規範

使用 `should ... when ...` 格式：

```typescript
test('should display error message when form submission fails', async () => { ... });
test('should navigate to dashboard when login succeeds', async () => { ... });
test('should show mobile menu when viewport is narrow', async () => { ... });
```

### 測試結構

每個功能的 E2E 測試應分為以下檔案：

| 檔案 | 用途 |
|------|------|
| `{feature}.spec.ts` | 核心使用者流程 |
| `{feature}-theme.spec.ts` | 深淺模式視覺測試 |
| `{feature}-responsive.spec.ts` | 響應式佈局測試 |
| `{feature}-a11y.spec.ts` | 無障礙合規測試 |

### 測試資料

- 使用固定的測試資料，禁止使用隨機生成
- 透過 API Mock 或 MSW（Mock Service Worker）提供一致的後端回應
- 每個測試獨立，不依賴其他測試的執行結果

## 檢查清單

- [ ] Page Object 模式已建立，封裝頁面互動邏輯
- [ ] 使用 `data-testid` 選取元素
- [ ] 核心使用者流程已覆蓋
- [ ] 深色模式截圖測試通過
- [ ] 淺色模式截圖測試通過
- [ ] 四種視口（desktop / laptop / tablet / mobile）佈局測試通過
- [ ] axe-core 無障礙掃描零違規（WCAG AA）
- [ ] 鍵盤導航測試通過
- [ ] 測試獨立不相依
- [ ] 無 `page.waitForTimeout()` 硬等待
- [ ] 截圖基準已產生並提交至版本控制

## 參考資源

- [Angular Testing Guide](https://angular.dev/guide/testing)
- [Playwright 官方文件](https://playwright.dev/docs/intro)
- [Playwright 截圖比對](https://playwright.dev/docs/test-snapshots)
- [axe-core Playwright 整合](https://github.com/dequelabs/axe-core-npm/tree/develop/packages/playwright)
- [WCAG 2.1 AA 準則](https://www.w3.org/WAI/WCAG21/quickref/?levels=aaa)
- [Playwright 視口設定](https://playwright.dev/docs/emulation#viewport)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [testing](../angular-rules/references/testing.md) — TDD 工作流與覆蓋率要求
