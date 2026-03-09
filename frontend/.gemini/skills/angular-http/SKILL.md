---
name: angular-http
description: >-
  Angular HTTP services and functional interceptors — auth, error handling,
  caching, retry logic, and Signal integration patterns.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular HTTP

## 觸發條件

當使用者要求以下任務時啟用此技能：

- 建立或修改 HTTP 服務（CRUD 操作）
- 實作 HTTP Interceptor（認證、錯誤處理、快取、重試）
- 配置 `provideHttpClient`
- 撰寫 HTTP 服務的單元測試
- 處理 API 錯誤與載入狀態
- 使用 `/new-service` 建立資料服務

## HttpClient 配置

```typescript
// app.config.ts
export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withInterceptors([authInterceptor, errorInterceptor]),
      withFetch(),
    ),
  ],
};
```

## Functional Interceptors

```typescript
// auth.interceptor.ts
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const token = auth.token();

  if (token) {
    const cloned = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` },
    });
    return next(cloned);
  }

  return next(req);
};

// error.interceptor.ts
export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401) {
        inject(AuthService).logout();
        inject(Router).navigate(['/login']);
      }
      return throwError(() => error);
    }),
  );
};
```

## Service 中的 HTTP 呼叫

```typescript
@Injectable({ providedIn: 'root' })
export class ItemService {
  private readonly http = inject(HttpClient);
  private readonly API_URL = '/api/items';

  getAll(): Observable<Item[]> {
    return this.http.get<Item[]>(this.API_URL);
  }

  getById(id: string): Observable<Item> {
    return this.http.get<Item>(`${this.API_URL}/${id}`);
  }

  create(item: CreateItemDto): Observable<Item> {
    return this.http.post<Item>(this.API_URL, item);
  }

  update(id: string, item: UpdateItemDto): Observable<Item> {
    return this.http.put<Item>(`${this.API_URL}/${id}`, item);
  }

  delete(id: string): Observable<void> {
    return this.http.delete<void>(`${this.API_URL}/${id}`);
  }
}
```

## 錯誤處理

```typescript
async loadItems(): Promise<void> {
  this._loading.set(true);
  this._error.set(null);

  try {
    const items = await firstValueFrom(this.http.get<Item[]>(this.API_URL));
    this._items.set(items);
  } catch (e: unknown) {
    if (e instanceof HttpErrorResponse) {
      this._error.set(`Error ${e.status}: ${e.message}`);
    } else {
      this._error.set('An unexpected error occurred');
    }
  } finally {
    this._loading.set(false);
  }
}
```

## 禁止事項

- 不使用 `any` 作為回應型別
- 不忽略 HTTP 錯誤
- 不在元件中直接使用 HttpClient
- 不硬編碼 API URL（使用常數或環境變數）

## Retry Interceptor 模式

當 HTTP 請求因暫時性錯誤（5xx、網路中斷）失敗時，自動重試。

```typescript
// retry.interceptor.ts
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { retry, timer } from 'rxjs';

const MAX_RETRY_COUNT = 3;
const RETRY_DELAY_MS = 1000;

/**
 * HTTP 重試攔截器
 *
 * 僅對 GET 請求進行重試，避免非冪等操作重複執行。
 * 使用指數退避策略（1s → 2s → 4s）。
 */
export const retryInterceptor: HttpInterceptorFn = (req, next) => {
  // 僅對 GET 請求重試（冪等操作）
  if (req.method !== 'GET') {
    return next(req);
  }

  return next(req).pipe(
    retry({
      count: MAX_RETRY_COUNT,
      delay: (error: HttpErrorResponse, retryCount: number) => {
        // 僅對伺服器錯誤（5xx）或網路錯誤（status === 0）重試
        if (error.status >= 400 && error.status < 500) {
          throw error; // 客戶端錯誤不重試
        }
        // 指數退避：1s, 2s, 4s
        const delayMs = RETRY_DELAY_MS * Math.pow(2, retryCount - 1);
        return timer(delayMs);
      },
    }),
  );
};
```

## Cache Interceptor 模式

GET 請求快取，設定 TTL 避免重複的 API 呼叫。

```typescript
// cache.interceptor.ts
import { HttpInterceptorFn, HttpResponse } from '@angular/common/http';
import { of, tap } from 'rxjs';

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 分鐘

interface CacheEntry {
  response: HttpResponse<unknown>;
  timestamp: number;
}

/** 記憶體快取儲存區 */
const cache = new Map<string, CacheEntry>();

/**
 * HTTP 快取攔截器
 *
 * 僅快取 GET 請求。快取的 TTL 為 5 分鐘。
 * 可透過 request header 'x-skip-cache' 跳過快取。
 */
export const cacheInterceptor: HttpInterceptorFn = (req, next) => {
  // 僅快取 GET 請求
  if (req.method !== 'GET') {
    // 非 GET 操作清除相關快取
    invalidateCache(req.urlWithParams);
    return next(req);
  }

  // 允許個別請求跳過快取
  if (req.headers.has('x-skip-cache')) {
    const cleanReq = req.clone({
      headers: req.headers.delete('x-skip-cache'),
    });
    return next(cleanReq);
  }

  const cacheKey = req.urlWithParams;
  const cached = cache.get(cacheKey);

  // 檢查快取是否有效
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return of(cached.response.clone());
  }

  return next(req).pipe(
    tap((event) => {
      if (event instanceof HttpResponse) {
        cache.set(cacheKey, {
          response: event.clone(),
          timestamp: Date.now(),
        });
      }
    }),
  );
};

/** 清除指定 URL 前綴的快取 */
function invalidateCache(urlPrefix: string): void {
  const baseUrl = urlPrefix.split('?')[0];
  for (const key of cache.keys()) {
    if (key.startsWith(baseUrl)) {
      cache.delete(key);
    }
  }
}
```

### Interceptor 註冊順序

```typescript
// app.config.ts
export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withInterceptors([
        authInterceptor,     // 1. 認證（加入 token）
        cacheInterceptor,    // 2. 快取（避免重複請求）
        retryInterceptor,    // 3. 重試（處理暫時性錯誤）
        errorInterceptor,    // 4. 錯誤處理（全域錯誤攔截）
      ]),
      withFetch(),
    ),
  ],
};
```

## 測試指引

### HttpTestingController 測試範例

```typescript
// item.service.spec.ts
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ItemService } from './item.service';
import { Item } from '../models/item.model';

describe('ItemService', () => {
  let service: ItemService;
  let httpMock: HttpTestingController;

  const MOCK_ITEMS: Item[] = [
    { id: '1', name: '項目一', status: 'active' },
    { id: '2', name: '項目二', status: 'inactive' },
  ];

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ItemService,
      ],
    });

    service = TestBed.inject(ItemService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    // 確認沒有未處理的請求
    httpMock.verify();
  });

  describe('getAll', () => {
    it('should return all items', () => {
      service.getAll().subscribe((items) => {
        expect(items).toEqual(MOCK_ITEMS);
        expect(items.length).toBe(2);
      });

      const req = httpMock.expectOne('/api/items');
      expect(req.request.method).toBe('GET');
      req.flush(MOCK_ITEMS);
    });

    it('should handle server error', () => {
      service.getAll().subscribe({
        next: () => fail('should have failed'),
        error: (error) => {
          expect(error.status).toBe(500);
        },
      });

      const req = httpMock.expectOne('/api/items');
      req.flush('Server Error', {
        status: 500,
        statusText: 'Internal Server Error',
      });
    });
  });

  describe('getById', () => {
    it('should return a single item by ID', () => {
      const expectedItem = MOCK_ITEMS[0];

      service.getById('1').subscribe((item) => {
        expect(item).toEqual(expectedItem);
      });

      const req = httpMock.expectOne('/api/items/1');
      expect(req.request.method).toBe('GET');
      req.flush(expectedItem);
    });

    it('should handle 404 not found', () => {
      service.getById('nonexistent').subscribe({
        next: () => fail('should have failed'),
        error: (error) => {
          expect(error.status).toBe(404);
        },
      });

      const req = httpMock.expectOne('/api/items/nonexistent');
      req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    });
  });

  describe('create', () => {
    it('should create a new item', () => {
      const newItem = { name: '新項目', status: 'active' };
      const createdItem: Item = { id: '3', ...newItem };

      service.create(newItem).subscribe((item) => {
        expect(item).toEqual(createdItem);
      });

      const req = httpMock.expectOne('/api/items');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(newItem);
      req.flush(createdItem);
    });
  });

  describe('update', () => {
    it('should update an existing item', () => {
      const updateData = { name: '更新後的項目' };
      const updatedItem: Item = { id: '1', name: '更新後的項目', status: 'active' };

      service.update('1', updateData).subscribe((item) => {
        expect(item).toEqual(updatedItem);
      });

      const req = httpMock.expectOne('/api/items/1');
      expect(req.request.method).toBe('PUT');
      expect(req.request.body).toEqual(updateData);
      req.flush(updatedItem);
    });
  });

  describe('delete', () => {
    it('should delete an item', () => {
      service.delete('1').subscribe();

      const req = httpMock.expectOne('/api/items/1');
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });
});
```

### Interceptor 測試範例

```typescript
// auth.interceptor.spec.ts
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors, HttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from '../services/auth/auth.service';

describe('authInterceptor', () => {
  let httpClient: HttpClient;
  let httpMock: HttpTestingController;
  let authServiceMock: { token: ReturnType<typeof signal> };

  beforeEach(() => {
    authServiceMock = {
      token: signal<string | null>(null),
    };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        { provide: AuthService, useValue: authServiceMock },
      ],
    });

    httpClient = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should add Authorization header when token exists', () => {
    authServiceMock.token.set('test-token-123');

    httpClient.get('/api/data').subscribe();

    const req = httpMock.expectOne('/api/data');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-token-123');
    req.flush({});
  });

  it('should not add Authorization header when token is null', () => {
    authServiceMock.token.set(null);

    httpClient.get('/api/data').subscribe();

    const req = httpMock.expectOne('/api/data');
    expect(req.request.headers.has('Authorization')).toBeFalsy();
    req.flush({});
  });
});
```

## MCP 整合

### TypeScript Server

透過 MCP TypeScript server 驗證 HTTP 服務的型別安全：

| 操作 | 用途 |
|------|------|
| 型別檢查 | 確認 HTTP 回應型別與 Model 介面一致 |
| 自動完成 | 確認 `HttpClient` 泛型參數正確 |
| 錯誤診斷 | 檢測 API URL 常數與方法簽名的型別問題 |

使用時機：

1. **新建服務後** — 確認所有 HTTP 方法的泛型型別正確
2. **修改 Model 介面後** — 驗證所有引用該介面的服務不會產生型別錯誤
3. **新增 Interceptor 後** — 確認 `HttpInterceptorFn` 簽名正確

```bash
# 透過 MCP typescript server 進行型別檢查
# 或手動執行
npx tsc --noEmit
```

## 檢查清單

- [ ] 所有 HTTP 呼叫封裝在 Service 中，元件不直接使用 `HttpClient`
- [ ] 所有 HTTP 方法指定明確的泛型回應型別（禁止 `any`）
- [ ] API URL 使用常數或環境變數，禁止硬編碼
- [ ] 錯誤處理涵蓋 `HttpErrorResponse` 與未知錯誤
- [ ] GET 請求有快取機制（5 分鐘 TTL）
- [ ] GET 請求有重試機制（指數退避，僅 5xx 錯誤）
- [ ] Interceptor 使用函式型（`HttpInterceptorFn`），禁止 class-based
- [ ] Interceptor 註冊順序正確（auth → cache → retry → error）
- [ ] 每個 Service 方法有 `HttpTestingController` 單元測試
- [ ] `afterEach` 呼叫 `httpMock.verify()` 確認無未處理請求
- [ ] 認證 Token 僅儲存在記憶體中（Signal），禁止 `localStorage`
- [ ] 使用 `withFetch()` 啟用 Fetch API 後端

## 參考資源

- [Angular HttpClient 指南](https://angular.dev/guide/http)
- [Angular HTTP Interceptors](https://angular.dev/guide/http/interceptors)
- [Angular HTTP 測試](https://angular.dev/guide/http/testing)
- [RxJS retry operator](https://rxjs.dev/api/operators/retry)
- [Angular Security — XSRF](https://angular.dev/guide/http/security)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [http-patterns](../angular-rules/references/http-patterns.md) — 函式型 Interceptor 與 CRUD Service
- [error-handling](../angular-rules/references/error-handling.md) — HTTP 錯誤分類與處理策略
