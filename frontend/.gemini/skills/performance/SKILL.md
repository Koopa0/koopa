---
name: performance
description: >-
  Angular performance patterns — OnPush, lazy loading, @defer, virtual
  scrolling, NgOptimizedImage, bundle budgets, and Web Vitals targets.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Performance Optimization

## 觸發條件

- 建立新元件或功能模組時（確保 OnPush + 延遲載入）
- 處理大量資料列表（> 50 筆）時
- 加入圖片到模板時
- 進行效能稽核或最佳化時
- Bundle 大小超出預算時
- Web Vitals 指標未達標時
- 進行建置分析或效能基準測試時

## 程式碼模板 / 核心模式

### OnPush 變更偵測

```typescript
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
})
```

所有元件必須使用 `OnPush`。搭配 Signals 使用效果最佳。

### 延遲載入

#### 路由延遲載入

```typescript
{
  path: 'users',
  loadChildren: () => import('./features/users/users.routes')
    .then(m => m.USERS_ROUTES),
}
```

#### @defer 延遲區塊

```html
<!-- 進入可視區域時載入 -->
@defer (on viewport) {
  <app-heavy-chart [data]="chartData()" />
} @placeholder {
  <div class="h-64 animate-pulse bg-zinc-800 rounded-lg"></div>
} @loading (minimum 300ms) {
  <app-skeleton-loader />
}

<!-- 閒置時載入 -->
@defer (on idle) {
  <app-analytics-widget />
}

<!-- 互動時載入 -->
@defer (on interaction) {
  <app-comment-editor />
} @placeholder {
  <button>Write a comment...</button>
}
```

### 虛擬捲動

超過 50 筆使用 CDK Virtual Scrolling：

```typescript
import { CdkVirtualScrollViewport, CdkVirtualForOf } from '@angular/cdk/scrolling';

@Component({
  imports: [CdkVirtualScrollViewport, CdkVirtualForOf],
  template: `
    <cdk-virtual-scroll-viewport itemSize="48" class="h-96">
      <div *cdkVirtualFor="let item of items()" class="h-12">
        {{ item.name }}
      </div>
    </cdk-virtual-scroll-viewport>
  `,
})
```

### NgOptimizedImage

```typescript
import { NgOptimizedImage } from '@angular/common';

@Component({
  imports: [NgOptimizedImage],
  template: `
    <img ngSrc="/assets/hero.jpg"
         width="800"
         height="600"
         priority
         alt="Hero image">
  `,
})
```

### Bundle 預算

```json
// angular.json
{
  "budgets": [
    {
      "type": "initial",
      "maximumWarning": "500kB",
      "maximumError": "1MB"
    },
    {
      "type": "anyComponentStyle",
      "maximumWarning": "4kB",
      "maximumError": "8kB"
    }
  ]
}
```

### Web Vitals 目標

| 指標 | 目標 |
|------|------|
| LCP | < 2.5s |
| INP | < 200ms |
| CLS | < 0.1 |

### 最佳實踐

- 使用 `computed()` 而非模板方法
- `@for` 必須有 `track` 表達式
- 使用 `NgOptimizedImage` 處理圖片
- Tree-shakable imports（具體路徑匯入）
- 使用 `@defer` 延遲非關鍵內容

## MCP 整合

### angular-cli MCP Server 建置分析

使用 `angular-cli` MCP server 執行建置和分析：

```bash
# 透過 MCP 或 CLI 執行生產建置
ng build --configuration production

# 分析 bundle 大小
ng build --configuration production --stats-json

# 使用 webpack-bundle-analyzer 檢視結果
npx webpack-bundle-analyzer dist/angular-spec/stats.json
```

#### 建置效能指標檢查

```bash
# 檢查建置預算是否通過
ng build --configuration production 2>&1 | grep -E "(Warning|Error).*budget"

# 檢查延遲載入 chunk 是否正確分割
ls -la dist/angular-spec/chunk-*.js | sort -k5 -n
```

#### 使用 MCP 進行增量檢查

在開發過程中，透過 MCP server 定期驗證：

1. **型別檢查**：使用 `typescript` MCP server 確認無型別錯誤
2. **Lint 檢查**：使用 `eslint` MCP server 確認無效能相關 lint 問題
3. **建置驗證**：使用 `angular-cli` MCP server 執行 `ng build` 確認 bundle 預算

### Lighthouse CI 自動化

#### 安裝與設定

```bash
# 安裝 Lighthouse CI
npm install -D @lhci/cli
```

#### lighthouserc.json 設定

```json
{
  "ci": {
    "collect": {
      "url": [
        "http://localhost:4200/",
        "http://localhost:4200/dashboard",
        "http://localhost:4200/login"
      ],
      "startServerCommand": "npm run serve:prod",
      "startServerReadyPattern": "Angular Live Development Server",
      "numberOfRuns": 3
    },
    "assert": {
      "assertions": {
        "categories:performance": ["error", { "minScore": 0.9 }],
        "categories:accessibility": ["error", { "minScore": 0.9 }],
        "categories:best-practices": ["error", { "minScore": 0.9 }],
        "categories:seo": ["error", { "minScore": 0.9 }],
        "first-contentful-paint": ["warn", { "maxNumericValue": 1800 }],
        "largest-contentful-paint": ["error", { "maxNumericValue": 2500 }],
        "interactive": ["warn", { "maxNumericValue": 3500 }],
        "cumulative-layout-shift": ["error", { "maxNumericValue": 0.1 }],
        "total-blocking-time": ["warn", { "maxNumericValue": 200 }]
      }
    },
    "upload": {
      "target": "filesystem",
      "outputDir": ".lighthouseci"
    }
  }
}
```

#### package.json 腳本

```json
{
  "scripts": {
    "lighthouse": "lhci autorun",
    "lighthouse:collect": "lhci collect",
    "lighthouse:assert": "lhci assert",
    "serve:prod": "ng serve --configuration production"
  }
}
```

#### CI/CD 整合

```yaml
# .github/workflows/lighthouse.yml
lighthouse:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: '22'
    - run: npm ci
    - run: npm run build
    - name: Run Lighthouse CI
      run: npx @lhci/cli autorun
    - uses: actions/upload-artifact@v4
      with:
        name: lighthouse-results
        path: .lighthouseci/
```

## 測試指引

### 效能相關單元測試

```typescript
describe('VehicleListComponent 效能', () => {
  it('should use OnPush change detection', () => {
    const component = TestBed.createComponent(VehicleListComponent);
    const metadata = reflectComponentType(VehicleListComponent);
    expect(metadata?.changeDetection).toBe(ChangeDetectionStrategy.OnPush);
  });

  it('should use computed for derived state instead of methods', () => {
    const component = TestBed.createComponent(VehicleListComponent);
    // 確認 vehicleCount 是 computed signal 而非方法
    expect(typeof component.componentInstance['vehicleCount']).toBe('function');
    // Signal 呼叫後回傳值
    expect(typeof component.componentInstance['vehicleCount']()).toBe('number');
  });

  it('should track items by id in @for loop', () => {
    const fixture = TestBed.createComponent(VehicleListComponent);
    fixture.componentRef.setInput('vehicles', mockVehicles);
    fixture.detectChanges();

    // 確認 DOM 元素數量正確
    const cards = fixture.debugElement.queryAll(By.css('[data-testid="vehicle-card"]'));
    expect(cards.length).toBe(mockVehicles.length);
  });
});
```

### Bundle 大小測試

```typescript
// scripts/check-bundle-size.ts
import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

const BUDGET_INITIAL_WARNING = 500 * 1024;  // 500KB
const BUDGET_INITIAL_ERROR = 1024 * 1024;    // 1MB

function checkBundleSize(distDir: string): void {
  const files = readdirSync(distDir).filter(f => f.endsWith('.js'));
  let totalSize = 0;

  for (const file of files) {
    const filePath = join(distDir, file);
    const size = statSync(filePath).size;
    totalSize += size;

    // 檢查延遲載入 chunk 不超過 200KB
    if (file.startsWith('chunk-') && size > 200 * 1024) {
      console.warn(`Warning: ${file} is ${(size / 1024).toFixed(1)}KB (> 200KB)`);
    }
  }

  if (totalSize > BUDGET_INITIAL_ERROR) {
    throw new Error(`Initial bundle ${(totalSize / 1024).toFixed(1)}KB exceeds 1MB budget`);
  }

  if (totalSize > BUDGET_INITIAL_WARNING) {
    console.warn(`Warning: Initial bundle ${(totalSize / 1024).toFixed(1)}KB exceeds 500KB warning`);
  }
}
```

### Playwright 效能測試

```typescript
// e2e/tests/performance/web-vitals.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Web Vitals', () => {
  test('should meet LCP target on dashboard', async ({ page }) => {
    await page.goto('/dashboard');

    // 使用 Performance API 量測 LCP
    const lcp = await page.evaluate(() => {
      return new Promise<number>((resolve) => {
        new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const lastEntry = entries[entries.length - 1];
          resolve(lastEntry.startTime);
        }).observe({ type: 'largest-contentful-paint', buffered: true });

        // 逾時保護
        setTimeout(() => resolve(0), 10000);
      });
    });

    expect(lcp).toBeLessThan(2500);
  });

  test('should have no layout shifts on page load', async ({ page }) => {
    await page.goto('/dashboard');

    const cls = await page.evaluate(() => {
      return new Promise<number>((resolve) => {
        let clsValue = 0;
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            // @ts-ignore
            if (!entry.hadRecentInput) {
              // @ts-ignore
              clsValue += entry.value;
            }
          }
        }).observe({ type: 'layout-shift', buffered: true });

        setTimeout(() => resolve(clsValue), 3000);
      });
    });

    expect(cls).toBeLessThan(0.1);
  });

  test('should lazy load below-fold content', async ({ page }) => {
    // 攔截網路請求
    const lazyRequests: string[] = [];
    page.on('request', (request) => {
      if (request.url().includes('chunk-')) {
        lazyRequests.push(request.url());
      }
    });

    await page.goto('/dashboard');

    // 初始載入不應包含所有 chunk
    const initialChunks = lazyRequests.length;

    // 捲動到底部觸發延遲載入
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(1000);

    // 應該有新的 chunk 被載入
    expect(lazyRequests.length).toBeGreaterThanOrEqual(initialChunks);
  });
});
```

## 檢查清單

- [ ] 所有元件使用 `ChangeDetectionStrategy.OnPush`
- [ ] 所有功能路由使用 `loadComponent` / `loadChildren` 延遲載入
- [ ] 非首屏內容使用 `@defer` 延遲載入
- [ ] 列表超過 50 筆使用 CDK Virtual Scrolling
- [ ] 所有 `<img>` 使用 `NgOptimizedImage`
- [ ] 首屏重要圖片加上 `priority` 屬性
- [ ] 使用 `computed()` 而非模板方法處理衍生狀態
- [ ] `@for` 迴圈都有 `track` 表達式
- [ ] Tree-shakable imports（具體路徑匯入，非整包匯入）
- [ ] Bundle 預算通過（初始 < 500KB warning / < 1MB error）
- [ ] 元件樣式 < 4KB warning / < 8KB error
- [ ] LCP < 2.5s、INP < 200ms、CLS < 0.1
- [ ] Lighthouse Performance / Accessibility / Best Practices / SEO 全部 90+
- [ ] HTTP GET 請求使用 cache interceptor（5 分鐘 TTL）
- [ ] Lighthouse CI 自動化已設定並通過
- [ ] 生產建置無預算警告或錯誤

## 參考資源

- [Angular Performance Guide](https://angular.dev/best-practices/runtime-performance)
- [Angular Deferrable Views](https://angular.dev/guide/defer)
- [Angular Image Optimization](https://angular.dev/guide/image-optimization)
- [Web Vitals](https://web.dev/vitals/)
- [Lighthouse CI](https://github.com/GoogleChrome/lighthouse-ci)
- [Angular CDK Scrolling](https://material.angular.io/cdk/scrolling/overview)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [performance](../angular-rules/references/performance.md) — OnPush、@defer、Virtual Scrolling 與 Web Vitals
- [angular-conventions](../angular-rules/references/angular-conventions.md) — OnPush 變更偵測強制規則
