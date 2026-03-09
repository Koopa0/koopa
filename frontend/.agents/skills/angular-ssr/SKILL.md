---
name: angular-ssr
description: >-
  Angular SSR and SSG configuration — RenderMode per route, platform
  detection, TransferState, and hydration strategies.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular SSR/SSG

## 觸發條件

當使用者要求以下任務時啟用此技能：

- 配置 Angular SSR（Server-Side Rendering）或 SSG（Static Site Generation）
- 設定 `ServerRoute` 與 `RenderMode`
- 處理伺服器端與客戶端的平台差異
- 使用 `TransferState` 避免重複 API 呼叫
- 使用 `afterNextRender()` 執行瀏覽器專屬邏輯
- 優化 LCP、FCP 等效能指標
- 解決 SSR 相關的 hydration 問題

## 配置

```typescript
// app.config.server.ts
import { ApplicationConfig, mergeApplicationConfig } from '@angular/core';
import { provideServerRendering } from '@angular/platform-server';
import { provideServerRouting } from '@angular/ssr';
import { appConfig } from './app.config';
import { serverRoutes } from './app.routes.server';

const serverConfig: ApplicationConfig = {
  providers: [
    provideServerRendering(),
    provideServerRouting(serverRoutes),
  ],
};

export default mergeApplicationConfig(appConfig, serverConfig);
```

## Server Routes

```typescript
// app.routes.server.ts
import { RenderMode, ServerRoute } from '@angular/ssr';

export const serverRoutes: ServerRoute[] = [
  {
    path: '',
    renderMode: RenderMode.Prerender,  // SSG
  },
  {
    path: 'dashboard',
    renderMode: RenderMode.Server,      // SSR
  },
  {
    path: '**',
    renderMode: RenderMode.Client,      // CSR fallback
  },
];
```

## SSR 注意事項

- 避免在伺服器端使用 `window`、`document`、`localStorage`
- 使用 `isPlatformBrowser()` / `isPlatformServer()` 進行平台檢測
- 使用 `afterNextRender()` 執行僅客戶端的邏輯
- 使用 `TransferState` 避免重複的 API 呼叫

```typescript
import { afterNextRender, PLATFORM_ID, inject } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

export class MyComponent {
  private readonly platformId = inject(PLATFORM_ID);

  constructor() {
    afterNextRender(() => {
      // 僅在瀏覽器端執行
      this.initChart();
    });
  }

  private initChart(): void {
    if (isPlatformBrowser(this.platformId)) {
      // 安全地使用 DOM API
    }
  }
}
```

## 程式碼模板

### TransferState 模式

使用 `TransferState` 在伺服器端擷取資料後傳遞給客戶端，避免二次 API 呼叫。

```typescript
// core/services/item/item.service.ts
import { Injectable, inject, makeStateKey, TransferState } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of, tap } from 'rxjs';

const ITEMS_KEY = makeStateKey<Item[]>('items');

@Injectable({ providedIn: 'root' })
export class ItemService {
  private readonly http = inject(HttpClient);
  private readonly transferState = inject(TransferState);
  private readonly API_URL = '/api/items';

  getAll(): Observable<Item[]> {
    // 優先使用 TransferState 中的資料
    if (this.transferState.hasKey(ITEMS_KEY)) {
      const items = this.transferState.get(ITEMS_KEY, []);
      this.transferState.remove(ITEMS_KEY);
      return of(items);
    }

    return this.http.get<Item[]>(this.API_URL).pipe(
      tap((items) => {
        // 伺服器端將資料存入 TransferState
        this.transferState.set(ITEMS_KEY, items);
      }),
    );
  }
}
```

### 安全的 DOM 操作

```typescript
// shared/utils/platform.utils.ts
import { inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser, isPlatformServer } from '@angular/common';

/**
 * 安全地在瀏覽器環境中執行回呼
 * 伺服器端會回傳 fallback 值
 */
export function runInBrowser<T>(
  callback: () => T,
  fallback: T,
): T {
  const platformId = inject(PLATFORM_ID);
  if (isPlatformBrowser(platformId)) {
    return callback();
  }
  return fallback;
}
```

### SSR 友善的第三方函式庫整合

```typescript
@Component({
  selector: 'app-map-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @defer (on viewport) {
      <div #mapContainer class="h-96 w-full" data-testid="map-container"></div>
    } @placeholder {
      <div class="h-96 w-full animate-pulse bg-zinc-200 dark:bg-zinc-800 rounded-sm"
           data-testid="map-placeholder">
      </div>
    }
  `,
})
export class MapViewComponent {
  private readonly mapContainer = viewChild<ElementRef>('mapContainer');

  constructor() {
    afterNextRender(() => {
      // 地圖函式庫僅在瀏覽器端載入
      this.initializeMap();
    });
  }

  private async initializeMap(): Promise<void> {
    const container = this.mapContainer()?.nativeElement;
    if (!container) return;

    // 動態載入僅瀏覽器端的函式庫
    const { Map } = await import('maplibre-gl');
    const map = new Map({
      container,
      // ... 地圖配置
    });
  }
}
```

## 測試指引

### 伺服器端測試

驗證元件在伺服器端渲染時不會存取瀏覽器 API。

```typescript
// my-component.server.spec.ts
import { TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { MyComponent } from './my-component';

describe('MyComponent (Server)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MyComponent],
      providers: [
        // 模擬伺服器端環境
        { provide: PLATFORM_ID, useValue: 'server' },
      ],
    }).compileComponents();
  });

  it('should create without errors on server', () => {
    const fixture = TestBed.createComponent(MyComponent);
    const component = fixture.componentInstance;
    expect(component).toBeTruthy();
  });

  it('should not access window on server', () => {
    const fixture = TestBed.createComponent(MyComponent);
    fixture.detectChanges();

    // 確認沒有拋出 ReferenceError: window is not defined
    expect(() => fixture.detectChanges()).not.toThrow();
  });

  it('should render placeholder content on server', () => {
    const fixture = TestBed.createComponent(MyComponent);
    fixture.detectChanges();

    const placeholder = fixture.nativeElement.querySelector(
      '[data-testid="map-placeholder"]',
    );
    // @defer 的 @placeholder 內容應在伺服器端可見
    expect(placeholder).toBeTruthy();
  });
});
```

### 客戶端測試

驗證元件在瀏覽器環境中正確初始化。

```typescript
// my-component.browser.spec.ts
import { TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { MyComponent } from './my.component';

describe('MyComponent (Browser)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MyComponent],
      providers: [
        // 模擬瀏覽器端環境
        { provide: PLATFORM_ID, useValue: 'browser' },
      ],
    }).compileComponents();
  });

  it('should create in browser environment', () => {
    const fixture = TestBed.createComponent(MyComponent);
    expect(fixture.componentInstance).toBeTruthy();
  });

  it('should initialize browser-only features', () => {
    const fixture = TestBed.createComponent(MyComponent);
    fixture.detectChanges();

    // 確認瀏覽器端功能已初始化
    // 例如圖表、地圖、動畫等
  });
});
```

### TransferState 測試

```typescript
// item.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { TransferState, makeStateKey } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ItemService } from './item.service';

const ITEMS_KEY = makeStateKey<Item[]>('items');

describe('ItemService (TransferState)', () => {
  let service: ItemService;
  let transferState: TransferState;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ItemService,
      ],
    });

    service = TestBed.inject(ItemService);
    transferState = TestBed.inject(TransferState);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should use TransferState data when available', () => {
    const mockItems: Item[] = [{ id: '1', name: '項目一' }];
    transferState.set(ITEMS_KEY, mockItems);

    service.getAll().subscribe((items) => {
      expect(items).toEqual(mockItems);
    });

    // 不應發出 HTTP 請求
    httpMock.expectNone('/api/items');
  });

  it('should fetch from API when TransferState is empty', () => {
    const mockItems: Item[] = [{ id: '1', name: '項目一' }];

    service.getAll().subscribe((items) => {
      expect(items).toEqual(mockItems);
    });

    const req = httpMock.expectOne('/api/items');
    req.flush(mockItems);
  });

  it('should remove TransferState key after reading', () => {
    const mockItems: Item[] = [{ id: '1', name: '項目一' }];
    transferState.set(ITEMS_KEY, mockItems);

    service.getAll().subscribe();

    expect(transferState.hasKey(ITEMS_KEY)).toBeFalsy();
  });
});
```

## 效能指標

### SSR 的 Web Vitals 目標

| 指標 | 目標值 | SSR 影響 | 說明 |
|------|--------|---------|------|
| LCP (Largest Contentful Paint) | < 2.5s | 顯著改善 | SSR 預渲染 HTML 讓內容更快可見 |
| FCP (First Contentful Paint) | < 1.8s | 顯著改善 | 伺服器回應即包含完整 HTML |
| INP (Interaction to Next Paint) | < 200ms | 注意 hydration | Hydration 完成前互動可能延遲 |
| CLS (Cumulative Layout Shift) | < 0.1 | 改善 | 伺服器端已計算正確佈局 |
| TTFB (Time to First Byte) | < 800ms | 可能增加 | 伺服器渲染需要時間，需監控 |

### LCP 優化策略

```typescript
// 1. 關鍵路由使用 SSR
export const serverRoutes: ServerRoute[] = [
  {
    path: '',
    renderMode: RenderMode.Prerender, // 首頁使用 SSG（最快）
  },
  {
    path: 'product/:id',
    renderMode: RenderMode.Server,     // 產品頁使用 SSR（動態內容）
  },
  {
    path: 'settings',
    renderMode: RenderMode.Client,     // 設定頁使用 CSR（非關鍵）
  },
];

// 2. LCP 圖片使用 priority 屬性
@Component({
  template: `
    <img
      ngSrc="/assets/hero-banner.jpg"
      width="1200"
      height="600"
      priority
      alt="主視覺圖片"
    />
  `,
})
export class HeroComponent {}

// 3. 非關鍵內容使用 @defer
@Component({
  template: `
    <!-- LCP 關鍵內容立即渲染 -->
    <app-hero-banner />
    <app-product-info [product]="product()" />

    <!-- 非關鍵內容延遲載入 -->
    @defer (on viewport) {
      <app-product-reviews [productId]="product().id" />
    } @placeholder {
      <div class="h-64 animate-pulse bg-zinc-200 dark:bg-zinc-800 rounded-sm"></div>
    }

    @defer (on idle) {
      <app-recommendation-carousel />
    } @placeholder {
      <div class="h-48 animate-pulse bg-zinc-200 dark:bg-zinc-800 rounded-sm"></div>
    }
  `,
})
export class ProductPageComponent {}
```

### Bundle 預算

```json
// angular.json budgets 設定
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

## 檢查清單

- [ ] `RenderMode` 正確配置：首頁 `Prerender`、動態頁 `Server`、非關鍵頁 `Client`
- [ ] 元件不在伺服器端直接存取 `window`、`document`、`localStorage`
- [ ] 使用 `isPlatformBrowser()` 進行平台檢測
- [ ] 使用 `afterNextRender()` 執行瀏覽器專屬初始化
- [ ] API 資料使用 `TransferState` 避免客戶端重複請求
- [ ] LCP 圖片設定 `priority` 屬性
- [ ] 非首屏內容使用 `@defer` 延遲載入
- [ ] 第三方瀏覽器函式庫使用動態 `import()` 載入
- [ ] TTFB < 800ms（監控伺服器渲染時間）
- [ ] LCP < 2.5s（使用 Lighthouse 驗證）
- [ ] CLS < 0.1（佔位符尺寸與實際內容一致）
- [ ] Bundle 初始載入 < 500KB warning / 1MB error
- [ ] 伺服器端測試（`PLATFORM_ID: 'server'`）通過
- [ ] 客戶端測試（`PLATFORM_ID: 'browser'`）通過
- [ ] TransferState 測試確認資料傳遞正確
- [ ] Hydration 無 mismatch 警告

## 參考資源

- [Angular SSR 指南](https://angular.dev/guide/ssr)
- [Angular Hydration](https://angular.dev/guide/hydration)
- [Angular Prerendering (SSG)](https://angular.dev/guide/prerendering)
- [Angular @defer 延遲載入](https://angular.dev/guide/defer)
- [NgOptimizedImage 指令](https://angular.dev/guide/image-optimization)
- [Web Vitals](https://web.dev/vitals/)
- [Lighthouse 效能審計](https://developer.chrome.com/docs/lighthouse/)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [performance](../angular-rules/references/performance.md) — SSR 策略、Web Vitals 與 Bundle 預算
- [routing](../angular-rules/references/routing.md) — RenderMode 路由配置
