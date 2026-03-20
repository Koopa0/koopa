---
name: angular-feature
description: >-
  Angular feature module scaffolding — lazy-loaded route structure, directory
  layout, services, models, and component boilerplate.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Feature Module

## 觸發條件

當需要建立新的功能模組時使用此 skill。適用場景包括：

- 建立新的業務功能（如：使用者管理、訂單管理、儀表板）
- 建立包含路由、元件、服務、模型的完整功能模組
- 需要延遲載入的獨立功能區塊

## 目錄結構

```
src/app/features/{feature-name}/
├── {feature-name}.component.ts        # 主頁面元件
├── {feature-name}.component.html
├── {feature-name}.component.scss
├── {feature-name}.component.spec.ts
├── {feature-name}.routes.ts           # 路由定義
├── components/                         # 子元件
│   └── {sub-component}/
│       ├── {sub-component}.component.ts
│       ├── {sub-component}.component.html
│       ├── {sub-component}.component.scss
│       ├── {sub-component}.component.spec.ts
│       └── index.ts
├── services/                           # 功能專屬服務
│   └── {service-name}.service.ts
│   └── {service-name}.service.spec.ts
├── models/                             # 功能專屬模型
│   └── {model-name}.model.ts
└── index.ts                            # 匯出
```

## 程式碼模板 / 核心模式

### 路由定義（含 Guard 保護）

```typescript
// {feature-name}.routes.ts
import { Routes } from '@angular/router';
import { authGuard } from '../../core/guards/auth.guard';

export const {FEATURE_NAME}_ROUTES: Routes = [
  {
    path: '',
    loadComponent: () => import('./{feature-name}.component')
      .then(m => m.{FeatureName}Component),
    title: '{Feature Title}',
    canActivate: [authGuard],
    children: [
      {
        path: '',
        pathMatch: 'full',
        loadComponent: () => import('./components/{feature-name}-list/{feature-name}-list.component')
          .then(m => m.{FeatureName}ListComponent),
        title: '{Feature} 列表',
      },
      {
        path: 'create',
        loadComponent: () => import('./components/{feature-name}-form/{feature-name}-form.component')
          .then(m => m.{FeatureName}FormComponent),
        title: '新增 {Feature}',
      },
      {
        path: ':id',
        loadComponent: () => import('./components/{feature-name}-detail/{feature-name}-detail.component')
          .then(m => m.{FeatureName}DetailComponent),
        title: '{Feature} 詳情',
      },
      {
        path: ':id/edit',
        loadComponent: () => import('./components/{feature-name}-form/{feature-name}-form.component')
          .then(m => m.{FeatureName}FormComponent),
        title: '編輯 {Feature}',
      },
    ],
  },
];
```

### 主路由整合

```typescript
// app.routes.ts
export const APP_ROUTES: Routes = [
  {
    path: '{feature-name}',
    loadChildren: () => import('./features/{feature-name}/{feature-name}.routes')
      .then(m => m.{FEATURE_NAME}_ROUTES),
  },
  // 其他路由...
];
```

### 主頁面元件模板

```typescript
// {feature-name}.component.ts
import { Component, ChangeDetectionStrategy } from '@angular/core';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-{feature-name}',
  standalone: true,
  imports: [RouterOutlet],
  template: `<router-outlet />`,
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class {FeatureName}Component {}
```

### 服務整合模式

```typescript
// services/{feature-name}.service.ts
import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { {FeatureName} } from '../models/{feature-name}.model';

const API_BASE_URL = '/api/{feature-name}s';

@Injectable({
  providedIn: 'root',
})
export class {FeatureName}Service {
  private readonly http = inject(HttpClient);

  private readonly _items = signal<{FeatureName}[]>([]);
  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly items = this._items.asReadonly();
  readonly loading = this._loading.asReadonly();
  readonly error = this._error.asReadonly();
  readonly count = computed(() => this._items().length);

  async loadAll(): Promise<void> {
    this._loading.set(true);
    this._error.set(null);

    try {
      const response = await firstValueFrom(
        this.http.get<{FeatureName}[]>(API_BASE_URL)
      );
      this._items.set(response);
    } catch (e: unknown) {
      const message = e instanceof HttpErrorResponse
        ? e.message
        : '載入失敗';
      this._error.set(message);
    } finally {
      this._loading.set(false);
    }
  }

  async getById(id: string): Promise<{FeatureName} | null> {
    try {
      return await firstValueFrom(
        this.http.get<{FeatureName}>(`${API_BASE_URL}/${id}`)
      );
    } catch {
      return null;
    }
  }

  async create(data: Omit<{FeatureName}, 'id'>): Promise<{FeatureName}> {
    const result = await firstValueFrom(
      this.http.post<{FeatureName}>(API_BASE_URL, data)
    );
    this._items.update(items => [...items, result]);
    return result;
  }

  async update(id: string, data: Partial<{FeatureName}>): Promise<{FeatureName}> {
    const result = await firstValueFrom(
      this.http.put<{FeatureName}>(`${API_BASE_URL}/${id}`, data)
    );
    this._items.update(items =>
      items.map(item => item.id === id ? result : item)
    );
    return result;
  }

  async delete(id: string): Promise<void> {
    await firstValueFrom(
      this.http.delete<void>(`${API_BASE_URL}/${id}`)
    );
    this._items.update(items => items.filter(item => item.id !== id));
  }
}
```

### @defer 延遲載入非關鍵內容

```html
<!-- 在 feature 主頁面中使用 @defer -->
<div class="space-y-6">
  <!-- 關鍵內容：立即載入 -->
  <header data-testid="feature-header">
    <h1 class="text-2xl font-bold text-zinc-900 dark:text-zinc-100">
      {{ title() }}
    </h1>
  </header>

  <!-- 主要內容 -->
  @if (loading()) {
    <div class="animate-pulse space-y-4" data-testid="loading-skeleton">
      <div class="h-12 rounded-sm bg-zinc-200 dark:bg-zinc-700"></div>
      <div class="h-12 rounded-sm bg-zinc-200 dark:bg-zinc-700"></div>
      <div class="h-12 rounded-sm bg-zinc-200 dark:bg-zinc-700"></div>
    </div>
  } @else {
    @for (item of items(); track item.id) {
      <app-{feature-name}-card [item]="item" />
    } @empty {
      <app-empty-state message="沒有資料" />
    }
  }

  <!-- 非關鍵內容：延遲載入 -->
  @defer (on viewport) {
    <app-{feature-name}-stats [data]="statsData()" />
  } @placeholder {
    <div class="h-64 animate-pulse rounded-lg bg-zinc-200 dark:bg-zinc-700"
         data-testid="stats-placeholder">
    </div>
  } @loading (minimum 300ms) {
    <app-spinner />
  }

  @defer (on idle) {
    <app-{feature-name}-activity-log />
  } @placeholder {
    <div class="h-32 rounded-lg bg-zinc-100 dark:bg-zinc-800"></div>
  }
</div>
```

## 設計參考資源

建立 Feature UI 前，依照以下順序查找設計參考：

### 步驟 1：確認 UI 需求

| 需要的 UI | 查找位置 |
|-----------|---------|
| 列表頁面 | `tailwind/css/ui-blocks/application-ui/lists/` |
| 詳情頁面 | `tailwind/css/ui-blocks/application-ui/page-examples/detail-screens/` |
| 表單頁面 | `tailwind/css/ui-blocks/application-ui/forms/` |
| 儀表板 | `tailwind/css/ui-blocks/application-ui/page-examples/home-screens/` |
| 設定頁面 | `tailwind/css/ui-blocks/application-ui/page-examples/settings-screens/` |
| 空狀態 | `tailwind/css/ui-blocks/application-ui/feedback/empty-states/` |

### 步驟 2：查找 Catalyst 元件

| 需要的元件 | Catalyst 檔案 |
|-----------|---------------|
| 資料表格 | `tailwind/css/catalyst-ui-kit/typescript/table.tsx` |
| 表單輸入 | `tailwind/css/catalyst-ui-kit/typescript/input.tsx` |
| 按鈕 | `tailwind/css/catalyst-ui-kit/typescript/button.tsx` |
| 對話框 | `tailwind/css/catalyst-ui-kit/typescript/dialog.tsx` |
| 分頁 | `tailwind/css/catalyst-ui-kit/typescript/pagination.tsx` |
| 標記 | `tailwind/css/catalyst-ui-kit/typescript/badge.tsx` |
| 下拉選單 | `tailwind/css/catalyst-ui-kit/typescript/dropdown.tsx` |

### 步驟 3：套用 Tailwind v4 語法

確認所有 CSS 類別使用 Tailwind v4 語法（參考 `tailwind/css/rules/tailwind.md`）：

| 禁止（v3） | 必須使用（v4） |
|-----------|--------------|
| `shadow-sm` | `shadow-xs` |
| `shadow` | `shadow-sm` |
| `rounded-sm` | `rounded-xs` |
| `rounded` | `rounded-sm` |
| `outline-none` | `outline-hidden` |
| `ring` | `ring-3` |

## E2E Page Object 模板

```typescript
// e2e/pages/{feature-name}.page.ts
import { Page, Locator, expect } from '@playwright/test';

export class {FeatureName}Page {
  readonly page: Page;

  // 定位器
  readonly pageTitle: Locator;
  readonly loadingSpinner: Locator;
  readonly itemList: Locator;
  readonly createButton: Locator;
  readonly emptyState: Locator;
  readonly searchInput: Locator;

  constructor(page: Page) {
    this.page = page;
    this.pageTitle = page.getByTestId('feature-header');
    this.loadingSpinner = page.getByTestId('loading-skeleton');
    this.itemList = page.getByTestId('item-list');
    this.createButton = page.getByTestId('create-button');
    this.emptyState = page.getByTestId('empty-state');
    this.searchInput = page.getByTestId('search-input');
  }

  async goto(): Promise<void> {
    await this.page.goto('/{feature-name}');
  }

  async waitForLoaded(): Promise<void> {
    await expect(this.loadingSpinner).not.toBeVisible();
    await expect(this.pageTitle).toBeVisible();
  }

  async getItemCount(): Promise<number> {
    return this.page.getByTestId(/^item-/).count();
  }

  async clickCreate(): Promise<void> {
    await this.createButton.click();
  }

  async searchFor(query: string): Promise<void> {
    await this.searchInput.fill(query);
  }

  async clickItem(id: string): Promise<void> {
    await this.page.getByTestId(`item-${id}`).click();
  }
}
```

### E2E 測試範例

```typescript
// e2e/tests/{feature-name}/{feature-name}.spec.ts
import { test, expect } from '@playwright/test';
import { {FeatureName}Page } from '../../pages/{feature-name}.page';

test.describe('{Feature Name}', () => {
  let featurePage: {FeatureName}Page;

  test.beforeEach(async ({ page }) => {
    featurePage = new {FeatureName}Page(page);
    await featurePage.goto();
    await featurePage.waitForLoaded();
  });

  test('should display page title', async () => {
    await expect(featurePage.pageTitle).toBeVisible();
  });

  test('should show empty state when no items', async () => {
    await expect(featurePage.emptyState).toBeVisible();
  });

  test('should navigate to create page when create button clicked', async ({ page }) => {
    await featurePage.clickCreate();
    await expect(page).toHaveURL(/\/{feature-name}\/create/);
  });
});
```

## 測試指引

### 功能模組測試策略

| 測試類型 | 涵蓋範圍 | 工具 |
|---------|---------|------|
| 單元測試 | 服務方法、計算邏輯 | Vitest + TestBed |
| 元件測試 | 子元件的 inputs/outputs/互動 | Vitest + TestBed |
| 整合測試 | 路由導航、Guard 保護 | Vitest + RouterTestingHarness |
| E2E 測試 | 完整使用者流程 | Playwright |

### 路由測試

```typescript
import { RouterTestingHarness } from '@angular/router/testing';
import { provideRouter } from '@angular/router';

describe('{FeatureName} Routes', () => {
  let harness: RouterTestingHarness;

  beforeEach(async () => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter({FEATURE_NAME}_ROUTES),
      ],
    });
    harness = await RouterTestingHarness.create();
  });

  it('should load list component on root path', async () => {
    const component = await harness.navigateByUrl('/', {FeatureName}ListComponent);
    expect(component).toBeInstanceOf({FeatureName}ListComponent);
  });

  it('should load detail component on :id path', async () => {
    const component = await harness.navigateByUrl('/123', {FeatureName}DetailComponent);
    expect(component).toBeInstanceOf({FeatureName}DetailComponent);
  });
});
```

### 服務測試

```typescript
describe('{FeatureName}Service', () => {
  let service: {FeatureName}Service;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject({FeatureName}Service);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('should load all items', async () => {
    const mockData = [{ id: '1', name: 'Test' }];
    const promise = service.loadAll();
    httpMock.expectOne('/api/{feature-name}s').flush(mockData);
    await promise;

    expect(service.items()).toEqual(mockData);
    expect(service.count()).toBe(1);
    expect(service.loading()).toBe(false);
  });

  it('should set error when load fails', async () => {
    const promise = service.loadAll();
    httpMock.expectOne('/api/{feature-name}s').error(new ProgressEvent('error'));
    await promise;

    expect(service.error()).toBeTruthy();
    expect(service.loading()).toBe(false);
  });
});
```

## MCP 整合

如果 MCP server 可用，可使用以下工具加速 Feature 建立：

1. `angular-cli` — 批次生成元件與服務
   ```
   ng generate component features/{feature-name}
   ng generate component features/{feature-name}/components/{sub-component}
   ng generate service features/{feature-name}/services/{service-name}
   ```
2. `eslint` — 檢查所有新建檔案的 lint 品質
3. `typescript` — 驗證路由設定與型別正確性

## 建立流程

### Step 0: 查詢可複用的 Shared Components

建立 Feature 任何 UI 前：
1. 執行 `ls src/app/shared/components/` 確認現有元件
2. 查閱 `component-catalog` skill 的完整 API 文件
3. 評估現有元件是否可組合達成需求
4. 如果現有元件不完全符合 → 提出擴展提案（非新建元件）

### Step 1: 建立功能模組

1. 建立目錄結構
2. 建立資料模型（`models/{model-name}.model.ts`）
3. 建立功能服務（`services/{service-name}.service.ts`）
4. 建立主元件（使用 angular-component skill）
5. 建立子元件
6. 建立路由定義（含 Guard 保護）
7. 更新 `app.routes.ts`（懶載入）
8. 更新 `app.routes.server.ts`（設定 SSR RenderMode）
9. 加入 `@defer` 延遲載入非關鍵內容
10. 建立 E2E Page Object（`e2e/pages/{feature-name}.page.ts`）
11. 建立 E2E 測試骨架（`e2e/tests/{feature-name}/{feature-name}.spec.ts`）
12. 建立單元/元件測試
13. 新增 i18n keys（zh-TW / en / ja 三個語系）
14. 驗證（lint, build, test）

## SSR RenderMode 決策

新功能模組加入路由時，同時在 `app.routes.server.ts` 設定 RenderMode：

| 類型 | RenderMode | 原因 |
|------|-----------|------|
| 需認證的功能頁面 | `Client` | 無 SEO 價值，需認證 |
| 公開的行銷/登入頁面 | `Server` | SEO + 首屏速度 |
| 靜態參考頁面 | `Prerender` | 不常變動，可預渲染 |

## 程式碼模板

參考 `.claude/templates/` 目錄下的標準模板確保風格一致。

## 檢查清單

- [ ] 已查詢現有 shared components，評估複用或擴展方案
- [ ] 目錄結構完整（components / services / models）
- [ ] 所有元件 `standalone: true` + `OnPush`
- [ ] 路由使用 `loadComponent` 延遲載入
- [ ] 主路由使用 `loadChildren` 整合
- [ ] Guard 保護敏感路由
- [ ] 服務使用 `signal()` + `computed()` 管理狀態
- [ ] 非關鍵內容使用 `@defer` 延遲載入
- [ ] 所有模板使用 `data-testid` 屬性
- [ ] 深淺模式支援（`dark:` 前綴）
- [ ] Tailwind v4 語法正確
- [ ] 參考 Catalyst UI Kit 和 UI Blocks 設計
- [ ] 單元測試覆蓋所有服務方法
- [ ] 元件測試覆蓋 inputs / outputs / 互動
- [ ] E2E Page Object 已建立
- [ ] E2E 測試覆蓋關鍵使用者流程
- [ ] `index.ts` 匯出所有公開 API
- [ ] `npm run lint` 通過
- [ ] `npm run build` 通過
- [ ] `npm run test` 通過

## 參考資源

- [Angular Routing Guide](https://angular.dev/guide/routing) — 官方路由指南
- [Angular Lazy Loading](https://angular.dev/guide/ngmodules/lazy-loading) — 延遲載入指南
- [Angular Deferrable Views](https://angular.dev/guide/defer) — @defer 延遲載入指南
- [Angular Guards](https://angular.dev/guide/routing/common-router-tasks#preventing-unauthorized-access) — 路由守衛指南
- [Playwright Page Object Model](https://playwright.dev/docs/pom) — Playwright POM 最佳實踐
- [Angular Style Guide](https://angular.dev/style-guide) — 官方檔案結構與命名規範


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [angular-conventions](../angular-rules/references/angular-conventions.md) — Standalone、Signal 等強制性 API
- [routing](../angular-rules/references/routing.md) — 延遲載入與函式型 Guard
- [coding-style](../angular-rules/references/coding-style.md) — 檔案結構與命名規範
