---
name: angular-service
description: >-
  Angular service creation — file structure, state management decision tree,
  providedIn patterns, and core vs feature-scoped services.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Service

## 觸發條件

當需要建立新的 Angular 服務時使用此 skill。

## 服務類型

| 類型 | 位置 | 作用域 |
|------|------|--------|
| Core Service | `core/services/{name}/` | 全域單例 |
| Feature Service | `features/{feature}/services/` | 功能專屬 |

## 檔案結構

```
{service-name}/
├── {service-name}.service.ts
├── {service-name}.service.spec.ts
└── index.ts
```

## State Management 決策樹

| 場景 | 方案 | 說明 |
|------|------|------|
| 元件本地 UI 狀態 | `signal()` + `computed()` | 狀態僅限單一元件內，如 loading、form values |
| 可編輯的衍生狀態 | `linkedSignal()` | 基於來源 signal 但可獨立修改，如列表預設選取項 |
| 非同步資料載入 | `resource()` / `rxResource()` | 取代手動 loading + error 管理，自動追蹤狀態 |
| 跨元件共享狀態 | Service + `signal()` + `asReadonly()` | 簡單共享狀態，不需 entity 管理 |
| 全域實體管理（CRUD） | NgRx Signal Store + `withEntities()` | 管理 ID 唯一的集合，需增刪改查 |
| 全域簡單值狀態 | NgRx Signal Store + `withState()` | 固定結構物件或簡單值 |

### 決策流程

```
需要管理狀態？
│
├── 僅限單一元件？
│   ├── 是 → signal() + computed()
│   └── 否 → 繼續判斷
│
├── 狀態需要基於來源但可獨立修改？
│   ├── 是 → linkedSignal()
│   └── 否 → 繼續判斷
│
├── 是非同步資料載入（GET + loading + error）？
│   ├── 是 → resource() 或 rxResource()
│   └── 否 → 繼續判斷
│
├── 需要跨元件共享？
│   ├── 簡單值 → Service + signal() + asReadonly()
│   ├── 實體集合（有 ID，需 CRUD） → NgRx Signal Store + withEntities()
│   └── 固定結構物件 → NgRx Signal Store + withState()
```

## 程式碼模板 / 核心模式

### 標準 HTTP 服務

```typescript
import { Injectable, inject, signal, computed } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class {ServiceName}Service {
  private readonly http = inject(HttpClient);

  // 私有可寫 signals
  private readonly _items = signal<Item[]>([]);
  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  // 公開唯讀 signals
  readonly items = this._items.asReadonly();
  readonly loading = this._loading.asReadonly();
  readonly error = this._error.asReadonly();

  // 計算屬性
  readonly count = computed(() => this._items().length);
  readonly isEmpty = computed(() => this._items().length === 0);

  async loadItems(): Promise<void> {
    this._loading.set(true);
    this._error.set(null);

    try {
      const response = await firstValueFrom(
        this.http.get<Item[]>('/api/items')
      );
      this._items.set(response);
    } catch (e: unknown) {
      const message = e instanceof HttpErrorResponse
        ? e.message
        : 'Unknown error';
      this._error.set(message);
    } finally {
      this._loading.set(false);
    }
  }
}
```

### NgRx Signal Store 整合模式

用於需要跨元件共享的複雜全域狀態：

```typescript
// core/store/{store-name}.store.ts
import { computed } from '@angular/core';
import {
  signalStore,
  withState,
  withComputed,
  withMethods,
  patchState,
} from '@ngrx/signals';
import { rxMethod } from '@ngrx/signals/rxjs-interop';
import { pipe, switchMap, tap } from 'rxjs';
import { inject } from '@angular/core';
import { {EntityName}Service } from '../services/{entity-name}/{entity-name}.service';

// 定義狀態介面
interface {StoreName}State {
  items: {EntityName}[];
  selectedId: string | null;
  loading: boolean;
  error: string | null;
}

// 初始狀態
const initialState: {StoreName}State = {
  items: [],
  selectedId: null,
  loading: false,
  error: null,
};

export const {StoreName}Store = signalStore(
  { providedIn: 'root' },

  // 定義狀態
  withState(initialState),

  // 定義衍生狀態
  withComputed((store) => ({
    selectedItem: computed(() => {
      const id = store.selectedId();
      return store.items().find(item => item.id === id) ?? null;
    }),
    itemCount: computed(() => store.items().length),
    isEmpty: computed(() => store.items().length === 0),
  })),

  // 定義方法
  withMethods((store, service = inject({EntityName}Service)) => ({
    selectItem(id: string): void {
      patchState(store, { selectedId: id });
    },

    clearSelection(): void {
      patchState(store, { selectedId: null });
    },

    async loadAll(): Promise<void> {
      patchState(store, { loading: true, error: null });
      try {
        await service.loadAll();
        patchState(store, { items: service.items(), loading: false });
      } catch {
        patchState(store, { loading: false, error: '載入失敗' });
      }
    },

    // 使用 rxMethod 處理 RxJS 流
    loadById: rxMethod<string>(
      pipe(
        tap(() => patchState(store, { loading: true })),
        switchMap((id) => service.getById$(id)),
        tap({
          next: (item) => patchState(store, (state) => ({
            items: [...state.items.filter(i => i.id !== item.id), item],
            loading: false,
          })),
          error: () => patchState(store, { loading: false, error: '載入失敗' }),
        }),
      )
    ),
  })),
);
```

### NgRx Signal Store — withEntities() 實體管理模式

用於管理 ID 唯一的集合（CRUD 操作）：

```typescript
// core/store/{entity-name}.store.ts
import { computed } from '@angular/core';
import {
  signalStore,
  withEntities,
  withMethods,
  withComputed,
  patchState,
} from '@ngrx/signals';
import {
  addEntity,
  addEntities,
  updateEntity,
  removeEntity,
  setAllEntities,
  setEntity,
} from '@ngrx/signals/entities';

interface Vehicle {
  id: string;
  plateNumber: string;
  status: 'available' | 'on_route' | 'maintenance';
  driverName: string;
}

export const VehicleStore = signalStore(
  { providedIn: 'root' },

  // withEntities 自動提供 ids(), entities(), entityMap() signals
  withEntities<Vehicle>(),

  // 衍生狀態
  withComputed(({ entities }) => ({
    activeVehicles: computed(() =>
      entities().filter(v => v.status === 'available')
    ),
    onRouteVehicles: computed(() =>
      entities().filter(v => v.status === 'on_route')
    ),
    vehicleCount: computed(() => entities().length),
  })),

  // 方法
  withMethods((store) => ({
    // 設定全部實體（覆蓋）
    setVehicles(vehicles: Vehicle[]): void {
      patchState(store, setAllEntities(vehicles));
    },

    // 新增單一實體
    addVehicle(vehicle: Vehicle): void {
      patchState(store, addEntity(vehicle));
    },

    // 新增多個實體
    addVehicles(vehicles: Vehicle[]): void {
      patchState(store, addEntities(vehicles));
    },

    // 更新實體部分欄位
    updateVehicle(id: string, changes: Partial<Vehicle>): void {
      patchState(store, updateEntity({ id, changes }));
    },

    // 新增或更新（upsert）
    upsertVehicle(vehicle: Vehicle): void {
      patchState(store, setEntity(vehicle));
    },

    // 刪除實體
    removeVehicle(id: string): void {
      patchState(store, removeEntity(id));
    },
  })),
);
```

### withEntities() 使用時機

| 場景 | 適用 |
|------|------|
| 管理使用者列表（CRUD） | ✅ `withEntities()` |
| 管理車輛集合（有唯一 ID） | ✅ `withEntities()` |
| 管理訂單佇列 | ✅ `withEntities()` |
| 管理單一表單值 | ❌ 使用 `withState()` |
| 管理主題/語言設定 | ❌ 使用 `withState()` |
| 管理 loading / error 狀態 | ❌ 使用 `withState()` |

### withEntities() 測試模式

```typescript
import { TestBed } from '@angular/core/testing';
import { VehicleStore } from './vehicle.store';

describe('VehicleStore', () => {
  let store: InstanceType<typeof VehicleStore>;

  const MOCK_VEHICLES: Vehicle[] = [
    { id: 'v1', plateNumber: 'ABC-1234', status: 'available', driverName: 'Driver A' },
    { id: 'v2', plateNumber: 'DEF-5678', status: 'on_route', driverName: 'Driver B' },
    { id: 'v3', plateNumber: 'GHI-9012', status: 'maintenance', driverName: 'Driver C' },
  ];

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [VehicleStore],
    });
    store = TestBed.inject(VehicleStore);
  });

  describe('setVehicles', () => {
    it('should set all entities', () => {
      store.setVehicles(MOCK_VEHICLES);

      expect(store.entities()).toEqual(MOCK_VEHICLES);
      expect(store.ids()).toEqual(['v1', 'v2', 'v3']);
      expect(store.vehicleCount()).toBe(3);
    });

    it('should replace existing entities', () => {
      store.setVehicles(MOCK_VEHICLES);
      store.setVehicles([MOCK_VEHICLES[0]]);

      expect(store.entities()).toHaveLength(1);
      expect(store.ids()).toEqual(['v1']);
    });
  });

  describe('addVehicle', () => {
    it('should add a new entity', () => {
      store.setVehicles(MOCK_VEHICLES);
      const newVehicle: Vehicle = {
        id: 'v4',
        plateNumber: 'JKL-3456',
        status: 'available',
        driverName: 'Driver D',
      };

      store.addVehicle(newVehicle);

      expect(store.entities()).toHaveLength(4);
      expect(store.entityMap()['v4']).toEqual(newVehicle);
    });
  });

  describe('updateVehicle', () => {
    it('should update entity partial fields', () => {
      store.setVehicles(MOCK_VEHICLES);

      store.updateVehicle('v1', { status: 'on_route' });

      expect(store.entityMap()['v1'].status).toBe('on_route');
      expect(store.entityMap()['v1'].plateNumber).toBe('ABC-1234'); // 未變更
    });
  });

  describe('removeVehicle', () => {
    it('should remove entity by id', () => {
      store.setVehicles(MOCK_VEHICLES);

      store.removeVehicle('v2');

      expect(store.entities()).toHaveLength(2);
      expect(store.ids()).not.toContain('v2');
    });
  });

  describe('computed properties', () => {
    it('should compute activeVehicles correctly', () => {
      store.setVehicles(MOCK_VEHICLES);

      expect(store.activeVehicles()).toHaveLength(1);
      expect(store.activeVehicles()[0].id).toBe('v1');
    });

    it('should compute onRouteVehicles correctly', () => {
      store.setVehicles(MOCK_VEHICLES);

      expect(store.onRouteVehicles()).toHaveLength(1);
      expect(store.onRouteVehicles()[0].id).toBe('v2');
    });

    it('should update computed when entities change', () => {
      store.setVehicles(MOCK_VEHICLES);
      expect(store.activeVehicles()).toHaveLength(1);

      store.updateVehicle('v2', { status: 'available' });

      expect(store.activeVehicles()).toHaveLength(2);
    });
  });
});
```

**在元件中使用 Signal Store**：

```typescript
@Component({
  selector: 'app-{entity-name}-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (store.loading()) {
      <app-spinner />
    } @else {
      @for (item of store.items(); track item.id) {
        <app-{entity-name}-card
          [item]="item"
          [selected]="item.id === store.selectedId()"
          (click)="store.selectItem(item.id)"
        />
      } @empty {
        <app-empty-state message="沒有資料" />
      }
    }
  `,
})
export class {EntityName}ListComponent implements OnInit {
  protected readonly store = inject({StoreName}Store);

  ngOnInit(): void {
    this.store.loadAll();
  }
}
```

## MCP 整合

如果 MCP server 可用，建立服務時可使用以下工具：

### angular-cli 生成服務

```bash
# 生成 Core Service（全域單例）
ng generate service core/services/{service-name}/{service-name}

# 生成 Feature Service（功能專屬）
ng generate service features/{feature-name}/services/{service-name}
```

生成後需手動調整：
1. 加入 `signal()` 狀態管理模式
2. 加入 `inject()` 依賴注入
3. 加入完整錯誤處理
4. 建立 `index.ts` 匯出檔

### eslint 驗證

生成服務後，使用 `eslint` MCP server 檢查程式碼品質：
- 確認無 `any` 型別
- 確認無未使用的變數
- 確認 import 順序正確

### typescript 驗證

使用 `typescript` MCP server 確認：
- 所有型別正確
- 無型別錯誤
- HttpClient 的泛型參數正確

## 測試指引

### HttpTestingController 完整範例

```typescript
import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { {ServiceName}Service } from './{service-name}.service';

describe('{ServiceName}Service', () => {
  let service: {ServiceName}Service;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject({ServiceName}Service);
    httpMock = TestBed.inject(HttpTestingController);
  });

  // 確認沒有未處理的 HTTP 請求
  afterEach(() => httpMock.verify());

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('loadItems', () => {
    const MOCK_ITEMS: Item[] = [
      { id: '1', name: 'Item A' },
      { id: '2', name: 'Item B' },
    ];

    it('should set loading to true when request starts', () => {
      service.loadItems();
      expect(service.loading()).toBe(true);
      httpMock.expectOne('/api/items').flush(MOCK_ITEMS);
    });

    it('should set items when request succeeds', async () => {
      const promise = service.loadItems();
      httpMock.expectOne('/api/items').flush(MOCK_ITEMS);
      await promise;

      expect(service.items()).toEqual(MOCK_ITEMS);
      expect(service.count()).toBe(2);
      expect(service.isEmpty()).toBe(false);
      expect(service.loading()).toBe(false);
      expect(service.error()).toBeNull();
    });

    it('should set error when request fails', async () => {
      const promise = service.loadItems();
      httpMock.expectOne('/api/items').error(
        new ProgressEvent('error'),
        { status: 500, statusText: 'Internal Server Error' }
      );
      await promise;

      expect(service.error()).toBeTruthy();
      expect(service.items()).toEqual([]);
      expect(service.loading()).toBe(false);
    });

    it('should clear previous error on new request', async () => {
      // 第一次請求失敗
      const promise1 = service.loadItems();
      httpMock.expectOne('/api/items').error(new ProgressEvent('error'));
      await promise1;
      expect(service.error()).toBeTruthy();

      // 第二次請求開始時清除錯誤
      const promise2 = service.loadItems();
      expect(service.error()).toBeNull();
      httpMock.expectOne('/api/items').flush(MOCK_ITEMS);
      await promise2;
    });
  });

  describe('computed properties', () => {
    it('should compute count from items', async () => {
      const promise = service.loadItems();
      httpMock.expectOne('/api/items').flush([
        { id: '1', name: 'A' },
        { id: '2', name: 'B' },
        { id: '3', name: 'C' },
      ]);
      await promise;

      expect(service.count()).toBe(3);
    });

    it('should compute isEmpty correctly', async () => {
      expect(service.isEmpty()).toBe(true);

      const promise = service.loadItems();
      httpMock.expectOne('/api/items').flush([{ id: '1', name: 'A' }]);
      await promise;

      expect(service.isEmpty()).toBe(false);
    });
  });
});
```

### NgRx Signal Store 測試

```typescript
import { TestBed } from '@angular/core/testing';
import { {StoreName}Store } from './{store-name}.store';
import { {EntityName}Service } from '../services/{entity-name}/{entity-name}.service';

describe('{StoreName}Store', () => {
  let store: InstanceType<typeof {StoreName}Store>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        {StoreName}Store,
        {
          provide: {EntityName}Service,
          useValue: {
            loadAll: vi.fn(),
            items: vi.fn(() => []),
          },
        },
      ],
    });
    store = TestBed.inject({StoreName}Store);
  });

  it('should initialize with default state', () => {
    expect(store.items()).toEqual([]);
    expect(store.selectedId()).toBeNull();
    expect(store.loading()).toBe(false);
    expect(store.error()).toBeNull();
  });

  it('should select item by id', () => {
    store.selectItem('item-001');
    expect(store.selectedId()).toBe('item-001');
  });

  it('should clear selection', () => {
    store.selectItem('item-001');
    store.clearSelection();
    expect(store.selectedId()).toBeNull();
  });

  it('should compute selectedItem from items and selectedId', () => {
    const items = [
      { id: '1', name: 'A' },
      { id: '2', name: 'B' },
    ];
    // 模擬 store 內部狀態（視實際實作調整）
    store.selectItem('2');
    expect(store.selectedItem()?.id ?? null).toBe(null); // 尚未載入
  });
});
```

## 程式碼模板

建立服務時可參考 `.claude/templates/` 目錄下的標準模板：

| 模板 | 用途 |
|------|------|
| `service.ts.template` | 服務 TypeScript |
| `service.spec.ts.template` | 服務測試 |
| `store.ts.template` | NgRx Signal Store |
| `store.spec.ts.template` | Store 測試 |

## 規範

- `providedIn: 'root'`（全域單例）
- 使用 `inject()` 注入依賴
- 私有 signal 用 `_` 前綴
- 公開 signal 用 `asReadonly()`
- 完整錯誤處理
- 不超過 300 行
- 每個公開方法都有對應的測試
- 測試命名遵循 `should ... when ...` 格式

## 檢查清單

- [ ] `@Injectable({ providedIn: 'root' })`
- [ ] 使用 `inject()` 注入依賴
- [ ] 私有 signal 用 `_` 前綴 + `asReadonly()` 公開
- [ ] 使用 `computed()` 處理衍生狀態
- [ ] 完整的 try/catch/finally 錯誤處理
- [ ] HttpClient 使用正確的泛型型別
- [ ] 測試涵蓋成功與失敗路徑
- [ ] 測試使用 `HttpTestingController` + `afterEach(() => httpMock.verify())`
- [ ] 服務不超過 300 行
- [ ] `index.ts` 匯出
- [ ] 無 `any` 型別
- [ ] 使用確定性測試資料

## 參考資源

- [Angular Services Guide](https://angular.dev/guide/di) — 官方依賴注入與服務指南
- [Angular HttpClient](https://angular.dev/guide/http) — HttpClient 使用指南
- [Angular HttpClient Testing](https://angular.dev/guide/http/testing) — HttpTestingController 測試指南
- [NgRx Signal Store](https://ngrx.io/guide/signals) — NgRx Signal Store 官方文件
- [NgRx Signal Store Recipes](https://ngrx.io/guide/signals/signal-store) — Signal Store 進階用法
- [Angular Signals](https://angular.dev/guide/signals) — Signal 狀態管理指南


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [state-management](../angular-rules/references/state-management.md) — Signal、NgRx Signals Store 與衍生狀態
- [coding-style](../angular-rules/references/coding-style.md) — 服務命名與結構規範
