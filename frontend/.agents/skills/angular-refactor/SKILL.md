---
name: angular-refactor
description: >-
  Legacy Angular migration checklist — upgrade to standalone components,
  signals, functional guards/interceptors, and modern control flow.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Refactoring

## 觸發條件

當需要將舊版 Angular 程式碼遷移至 Angular 21 最佳實踐時使用此 skill。適用場景包括：

- 將 `@Input()` / `@Output()` 裝飾器遷移至 `input()` / `output()` 函式
- 將 `*ngIf` / `*ngFor` / `*ngSwitch` 遷移至 `@if` / `@for` / `@switch`
- 將 constructor 注入遷移至 `inject()` 函式
- 將 `BehaviorSubject` 遷移至 `signal()`
- 將 `NgModule` 遷移至 Standalone Component
- 將 class-based guard/interceptor 遷移至 functional 版本
- 將 Default 變更偵測遷移至 `OnPush`

## Angular 21 遷移清單

| 舊模式 | 新模式 | 搜尋模式 |
|--------|--------|---------|
| `@Input()` | `input()` / `input.required()` | `@Input` |
| `@Output()` | `output()` | `@Output` |
| `*ngIf` | `@if` | `\*ngIf` |
| `*ngFor` | `@for` (with `track`) | `\*ngFor` |
| `*ngSwitch` | `@switch` | `\*ngSwitch` |
| Constructor DI | `inject()` | `constructor(private` |
| BehaviorSubject | `signal()` | `BehaviorSubject` |
| NgModule | Standalone component | `@NgModule` |
| Class guard | Functional guard | `implements CanActivate` |
| Default CD | `OnPush` | 缺少 `changeDetection` |
| `@ViewChild` | `viewChild()` | `@ViewChild` |
| `@ViewChildren` | `viewChildren()` | `@ViewChildren` |

## 程式碼模板 / 核心模式

### 模式 1：@Input/@Output → input()/output()

**BEFORE（禁止）**：

```typescript
import { Component, Input, Output, EventEmitter } from '@angular/core';

@Component({
  selector: 'app-user-card',
  template: `
    <div>{{ name }}</div>
    <button (click)="onDelete()">刪除</button>
  `,
})
export class UserCardComponent {
  @Input() name!: string;
  @Input() age = 0;
  @Output() deleted = new EventEmitter<string>();

  onDelete(): void {
    this.deleted.emit(this.name);
  }
}
```

**AFTER（必須）**：

```typescript
import { Component, ChangeDetectionStrategy, input, output } from '@angular/core';

@Component({
  selector: 'app-user-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div>{{ name() }}</div>
    <button (click)="deleteUser()">刪除</button>
  `,
})
export class UserCardComponent {
  readonly name = input.required<string>();
  readonly age = input(0);
  readonly deleted = output<string>();

  protected deleteUser(): void {
    this.deleted.emit(this.name());
  }
}
```

**注意事項**：
- `input()` 回傳值是 signal，模板中需要用 `name()` 呼叫
- `input.required<T>()` 取代 `@Input() name!: string`（非空斷言）
- `input(defaultValue)` 取代 `@Input() age = 0`
- `output<T>()` 取代 `@Output() + EventEmitter`
- 雙向綁定使用 `model<T>()` 取代 `@Input() + @Output() + Change` 組合

**測試驗證**：

```typescript
it('should render name input correctly after migration', () => {
  fixture.componentRef.setInput('name', '測試使用者');
  fixture.detectChanges();
  const el = fixture.nativeElement.querySelector('div');
  expect(el.textContent).toContain('測試使用者');
});

it('should emit deleted event with name value', () => {
  const spy = vi.fn();
  component.deleted.subscribe(spy);
  fixture.componentRef.setInput('name', 'Alice');
  fixture.detectChanges();
  fixture.nativeElement.querySelector('button').click();
  expect(spy).toHaveBeenCalledWith('Alice');
});
```

---

### 模式 2：*ngIf/*ngFor → @if/@for

**BEFORE（禁止）**：

```html
<div *ngIf="loading">
  <app-spinner></app-spinner>
</div>

<div *ngIf="!loading && error">
  <p>{{ error }}</p>
</div>

<ul *ngIf="!loading && !error">
  <li *ngFor="let item of items; trackBy: trackById">
    {{ item.name }}
  </li>
</ul>

<div *ngIf="items.length === 0 && !loading">
  <p>沒有資料</p>
</div>
```

**AFTER（必須）**：

```html
@if (loading()) {
  <app-spinner />
} @else if (error()) {
  <p>{{ error() }}</p>
} @else {
  <ul>
    @for (item of items(); track item.id) {
      <li>{{ item.name }}</li>
    } @empty {
      <p>沒有資料</p>
    }
  </ul>
}
```

**注意事項**：
- `@for` 必須有 `track` 表達式（通常用 `item.id`）
- `@empty` 取代額外的空狀態判斷
- 所有狀態值改為 signal 呼叫（`loading()` 而非 `loading`）
- 移除 `trackBy` 方法，改用 `track` 內聯表達式
- 可移除 `CommonModule` import（控制流為內建語法）

**測試驗證**：

```typescript
it('should show spinner when loading', () => {
  component['loading'].set(true);
  fixture.detectChanges();
  expect(fixture.nativeElement.querySelector('app-spinner')).toBeTruthy();
});

it('should render all items when loaded', () => {
  component['loading'].set(false);
  component['items'].set([
    { id: '1', name: 'Item A' },
    { id: '2', name: 'Item B' },
  ]);
  fixture.detectChanges();
  const listItems = fixture.nativeElement.querySelectorAll('li');
  expect(listItems.length).toBe(2);
});

it('should show empty message when no items', () => {
  component['loading'].set(false);
  component['items'].set([]);
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('沒有資料');
});
```

---

### 模式 3：Constructor DI → inject()

**BEFORE（禁止）**：

```typescript
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { UserService } from '../services/user.service';
import { NotificationService } from '../../core/services/notification.service';

@Component({
  selector: 'app-user-list',
  templateUrl: './user-list.component.html',
})
export class UserListComponent implements OnInit {
  users: User[] = [];
  loading = false;

  constructor(
    private readonly userService: UserService,
    private readonly notificationService: NotificationService,
    private readonly router: Router,
  ) {}

  ngOnInit(): void {
    this.loadUsers();
  }

  private async loadUsers(): Promise<void> {
    this.loading = true;
    this.users = await this.userService.getAll();
    this.loading = false;
  }
}
```

**AFTER（必須）**：

```typescript
import { Component, ChangeDetectionStrategy, inject, signal, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { UserService } from '../services/user.service';
import { NotificationService } from '../../core/services/notification.service';

@Component({
  selector: 'app-user-list',
  standalone: true,
  templateUrl: './user-list.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UserListComponent implements OnInit {
  private readonly userService = inject(UserService);
  private readonly notificationService = inject(NotificationService);
  private readonly router = inject(Router);

  protected readonly users = signal<User[]>([]);
  protected readonly loading = signal(false);

  ngOnInit(): void {
    this.loadUsers();
  }

  private async loadUsers(): Promise<void> {
    this.loading.set(true);
    try {
      const data = await this.userService.getAll();
      this.users.set(data);
    } finally {
      this.loading.set(false);
    }
  }
}
```

**注意事項**：
- `inject()` 必須在建構時期呼叫（欄位初始化或 constructor 內）
- 搭配 `signal()` 替換普通屬性
- 加上 `ChangeDetectionStrategy.OnPush`
- 加上 `standalone: true`
- 加上錯誤處理（try/finally）

**測試驗證**：

```typescript
it('should inject services correctly', () => {
  expect(component).toBeTruthy();
  // inject() 的服務在 TestBed 中自動可用
});

it('should load users on init', async () => {
  fixture.detectChanges(); // 觸發 ngOnInit
  const req = httpMock.expectOne('/api/users');
  req.flush([{ id: '1', name: 'Alice' }]);
  await fixture.whenStable();
  expect(component.users().length).toBe(1);
});
```

---

### 模式 4：BehaviorSubject → signal()

**BEFORE（禁止）**：

```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, map } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class CartService {
  private readonly itemsSubject = new BehaviorSubject<CartItem[]>([]);
  readonly items$: Observable<CartItem[]> = this.itemsSubject.asObservable();
  readonly totalPrice$: Observable<number> = this.items$.pipe(
    map(items => items.reduce((sum, item) => sum + item.price * item.quantity, 0))
  );
  readonly itemCount$: Observable<number> = this.items$.pipe(
    map(items => items.length)
  );

  addItem(item: CartItem): void {
    const current = this.itemsSubject.getValue();
    this.itemsSubject.next([...current, item]);
  }

  removeItem(id: string): void {
    const current = this.itemsSubject.getValue();
    this.itemsSubject.next(current.filter(i => i.id !== id));
  }

  clear(): void {
    this.itemsSubject.next([]);
  }
}
```

**AFTER（必須）**：

```typescript
import { Injectable, signal, computed } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class CartService {
  private readonly _items = signal<CartItem[]>([]);

  readonly items = this._items.asReadonly();
  readonly totalPrice = computed(() =>
    this._items().reduce((sum, item) => sum + item.price * item.quantity, 0)
  );
  readonly itemCount = computed(() => this._items().length);

  addItem(item: CartItem): void {
    this._items.update(current => [...current, item]);
  }

  removeItem(id: string): void {
    this._items.update(current => current.filter(i => i.id !== id));
  }

  clear(): void {
    this._items.set([]);
  }
}
```

**注意事項**：
- `BehaviorSubject` → `signal()`
- `.asObservable()` → `.asReadonly()`
- `.pipe(map(...))` → `computed(() => ...)`
- `.getValue()` → 直接呼叫 signal `()`
- `.next(value)` → `.set(value)` 或 `.update(fn)`
- 元件中 `| async` → 直接呼叫 signal `()`
- 如果其他程式碼依賴 Observable，可用 `toObservable()` 橋接

**測試驗證**：

```typescript
it('should add item to cart', () => {
  const item: CartItem = { id: '1', name: 'Product A', price: 100, quantity: 2 };
  service.addItem(item);
  expect(service.items()).toEqual([item]);
  expect(service.itemCount()).toBe(1);
  expect(service.totalPrice()).toBe(200);
});

it('should remove item from cart', () => {
  service.addItem({ id: '1', name: 'A', price: 50, quantity: 1 });
  service.addItem({ id: '2', name: 'B', price: 30, quantity: 1 });
  service.removeItem('1');
  expect(service.items().length).toBe(1);
  expect(service.items()[0].id).toBe('2');
});

it('should clear all items', () => {
  service.addItem({ id: '1', name: 'A', price: 50, quantity: 1 });
  service.clear();
  expect(service.items()).toEqual([]);
  expect(service.itemCount()).toBe(0);
  expect(service.totalPrice()).toBe(0);
});
```

---

### 模式 5：NgModule → Standalone

**BEFORE（禁止）**：

```typescript
// user.module.ts
@NgModule({
  declarations: [
    UserListComponent,
    UserCardComponent,
    UserDetailComponent,
  ],
  imports: [
    CommonModule,
    FormsModule,
    RouterModule.forChild([
      { path: '', component: UserListComponent },
      { path: ':id', component: UserDetailComponent },
    ]),
  ],
  exports: [UserCardComponent],
})
export class UserModule {}

// user-list.component.ts
@Component({
  selector: 'app-user-list',
  templateUrl: './user-list.component.html',
})
export class UserListComponent {
  // ...
}
```

**AFTER（必須）**：

```typescript
// user.routes.ts
import { Routes } from '@angular/router';

export const USER_ROUTES: Routes = [
  {
    path: '',
    loadComponent: () => import('./user-list.component')
      .then(m => m.UserListComponent),
  },
  {
    path: ':id',
    loadComponent: () => import('./user-detail.component')
      .then(m => m.UserDetailComponent),
  },
];

// user-list.component.ts
@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [UserCardComponent],
  templateUrl: './user-list.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UserListComponent {
  // ...
}

// user-card.component.ts
@Component({
  selector: 'app-user-card',
  standalone: true,
  imports: [],
  templateUrl: './user-card.component.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UserCardComponent {
  // ...
}
```

**注意事項**：
- 刪除整個 `@NgModule` 檔案
- 每個元件加上 `standalone: true` 和自己的 `imports`
- 路由定義移至 `{feature}.routes.ts`，使用 `loadComponent` 延遲載入
- 主路由使用 `loadChildren` 載入 feature routes
- `CommonModule` 大多不再需要（控制流為內建語法），僅在使用 `DatePipe` 等時 import

**測試驗證**：

```typescript
// 確認 standalone 元件可以獨立渲染
it('should create standalone component', async () => {
  await TestBed.configureTestingModule({
    imports: [UserListComponent], // 直接 import 元件
  }).compileComponents();

  const fixture = TestBed.createComponent(UserListComponent);
  expect(fixture.componentInstance).toBeTruthy();
});
```

---

### 模式 6：Class Guard → Functional Guard

**BEFORE（禁止）**：

```typescript
// auth.guard.ts
@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly router: Router,
  ) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean | UrlTree {
    if (this.authService.isAuthenticated()) {
      return true;
    }
    return this.router.createUrlTree(['/login'], {
      queryParams: { returnUrl: state.url },
    });
  }
}

// 路由中使用
{ path: 'dashboard', component: DashboardComponent, canActivate: [AuthGuard] }
```

**AFTER（必須）**：

```typescript
// auth.guard.ts
import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth/auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  return router.createUrlTree(['/login'], {
    queryParams: { returnUrl: state.url },
  });
};

// 路由中使用（完全相同）
{ path: 'dashboard', loadComponent: () => import('./dashboard.component').then(m => m.DashboardComponent), canActivate: [authGuard] }
```

**Functional Interceptor 範例**：

```typescript
// auth.interceptor.ts
import { inject } from '@angular/core';
import { HttpInterceptorFn } from '@angular/common/http';
import { AuthService } from '../services/auth/auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = inject(AuthService).token();

  if (token) {
    const cloned = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` },
    });
    return next(cloned);
  }

  return next(req);
};
```

**注意事項**：
- Guard 函式名用 camelCase（`authGuard`），不是 PascalCase
- Interceptor 函式名用 camelCase（`authInterceptor`）
- 在函式內部使用 `inject()` 取得依賴
- 不需要 `@Injectable` 裝飾器
- 路由設定中的使用方式相同

**測試驗證**：

```typescript
describe('authGuard', () => {
  let authService: AuthService;
  let router: Router;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: { isAuthenticated: vi.fn() } },
      ],
    });
    authService = TestBed.inject(AuthService);
    router = TestBed.inject(Router);
  });

  it('should allow access when authenticated', () => {
    vi.mocked(authService.isAuthenticated).mockReturnValue(true);

    const result = TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, { url: '/dashboard' } as RouterStateSnapshot)
    );

    expect(result).toBe(true);
  });

  it('should redirect to login when not authenticated', () => {
    vi.mocked(authService.isAuthenticated).mockReturnValue(false);

    const result = TestBed.runInInjectionContext(() =>
      authGuard({} as ActivatedRouteSnapshot, { url: '/dashboard' } as RouterStateSnapshot)
    );

    expect(result).toBeInstanceOf(UrlTree);
  });
});
```

## 重構流程

1. 確認測試存在且通過
2. 每次只做一種重構
3. 執行重構
4. 確認測試仍然通過
5. 如需要，更新測試

## 安全守則

- 必須有測試保護
- 保持外部 API 不變
- 不在重構中新增功能
- 移除的程式碼完全刪除（不留 `_unused` 或註解）
- 每個重構步驟獨立 commit，方便回滾
- 重構前後執行 `npm run lint` 和 `npm run build` 確認無破壞

## 測試指引

### 重構前後的測試策略

1. **重構前**：確認所有現有測試通過
2. **重構中**：每完成一個模式的遷移，立即執行測試
3. **重構後**：更新測試以使用新 API（如 `setInput()` 取代直接賦值）

### 常見測試更新

```typescript
// BEFORE — 舊的 input 設定方式
component.name = 'Test';
fixture.detectChanges();

// AFTER — 新的 signal input 設定方式
fixture.componentRef.setInput('name', 'Test');
fixture.detectChanges();
```

```typescript
// BEFORE — 舊的 output 訂閱方式
component.deleted.subscribe(spy);

// AFTER — output() 的訂閱方式相同
component.deleted.subscribe(spy);
```

```typescript
// BEFORE — BehaviorSubject 測試
service.items$.subscribe(items => {
  expect(items.length).toBe(2);
});

// AFTER — Signal 測試
expect(service.items().length).toBe(2);
```

## 檢查清單

- [ ] 重構前所有測試通過
- [ ] 每次只做一種重構模式
- [ ] `@Input()` / `@Output()` 已遷移至 `input()` / `output()`
- [ ] `*ngIf` / `*ngFor` / `*ngSwitch` 已遷移至 `@if` / `@for` / `@switch`
- [ ] Constructor DI 已遷移至 `inject()`
- [ ] `BehaviorSubject` 已遷移至 `signal()`
- [ ] `NgModule` 已遷移至 Standalone Component
- [ ] Class guard/interceptor 已遷移至 functional 版本
- [ ] 所有元件使用 `ChangeDetectionStrategy.OnPush`
- [ ] `@ViewChild` / `@ViewChildren` 已遷移至 `viewChild()` / `viewChildren()`
- [ ] 測試已更新為新 API
- [ ] `npm run lint` 通過
- [ ] `npm run build` 通過
- [ ] `npm run test` 通過
- [ ] 無殘留的舊模式程式碼或註解

## 參考資源

- [Angular Migration Guide](https://angular.dev/guide/migrations) — 官方遷移指南
- [Angular Signal Inputs Migration](https://angular.dev/guide/migrations/signal-input) — @Input → input() 遷移
- [Angular Signal Queries Migration](https://angular.dev/guide/migrations/signal-queries) — @ViewChild → viewChild() 遷移
- [Angular Control Flow Migration](https://angular.dev/guide/migrations/control-flow) — *ngIf → @if 遷移
- [Angular inject() Migration](https://angular.dev/guide/migrations/inject-function) — Constructor DI → inject() 遷移
- [Angular Standalone Migration](https://angular.dev/guide/migrations/standalone) — NgModule → Standalone 遷移


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [angular-conventions](../angular-rules/references/angular-conventions.md) — Angular 21 強制性 API（遷移目標）
- [coding-style](../angular-rules/references/coding-style.md) — 命名與格式規範
