---
name: angular-routing
description: >-
  Angular 21 routing — lazy-loaded routes, functional guards, route
  parameters, navigation patterns, and SSR render modes.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Routing

## 觸發條件

當使用者要求以下任務時啟用此技能：

- 配置應用程式路由或子路由
- 建立或修改 Route Guard（認證、角色權限）
- 實作延遲載入（`loadComponent` / `loadChildren`）
- 建立導航元件（Navbar / Sidebar / Breadcrumbs）
- 處理路由參數、查詢參數
- 使用 `/new-feature` 建立功能模組路由

## 路由配置

```typescript
// app.routes.ts
export const routes: Routes = [
  {
    path: '',
    redirectTo: 'dashboard',
    pathMatch: 'full',
  },
  {
    path: 'dashboard',
    loadComponent: () => import('./features/dashboard/dashboard.component')
      .then(m => m.DashboardComponent),
    title: 'Dashboard',
  },
  {
    path: 'users',
    loadChildren: () => import('./features/users/users.routes')
      .then(m => m.USERS_ROUTES),
    canActivate: [authGuard],
  },
  {
    path: '**',
    loadComponent: () => import('./shared/components/not-found/not-found.component')
      .then(m => m.NotFoundComponent),
    title: 'Page Not Found',
  },
];
```

## Functional Guards

```typescript
// auth.guard.ts
export const authGuard: CanActivateFn = (route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.isAuthenticated()) {
    return true;
  }

  return router.createUrlTree(['/login'], {
    queryParams: { returnUrl: state.url },
  });
};

// role.guard.ts
export const roleGuard = (requiredRole: string): CanActivateFn => {
  return (route, state) => {
    const auth = inject(AuthService);
    return auth.hasRole(requiredRole);
  };
};
```

## Feature Routes

```typescript
// features/users/users.routes.ts
export const USERS_ROUTES: Routes = [
  {
    path: '',
    loadComponent: () => import('./users-list.component')
      .then(m => m.UsersListComponent),
    title: 'Users',
  },
  {
    path: ':id',
    loadComponent: () => import('./user-detail.component')
      .then(m => m.UserDetailComponent),
    title: 'User Detail',
  },
];
```

## 延遲載入

所有功能模組必須使用延遲載入：
- `loadComponent` 用於單一元件
- `loadChildren` 用於子路由

## 設計參考資源

### Catalyst UI Kit 導航元件

從 `tailwind/css/catalyst-ui-kit/typescript/` 提取 HTML 結構與 Tailwind classes，轉換為 Angular standalone component。

| Catalyst 元件 | 檔案路徑 | Angular 用途 |
|---------------|---------|-------------|
| Navbar | `navbar.tsx` | 頂部導航列 |
| Sidebar | `sidebar.tsx` | 側邊導航欄 |
| Sidebar Layout | `sidebar-layout.tsx` | 側邊欄佈局容器 |
| Stacked Layout | `stacked-layout.tsx` | 堆疊式佈局容器 |
| Link | `link.tsx` | 導航連結（轉換為 `routerLink`） |
| Pagination | `pagination.tsx` | 分頁導航 |

### UI Blocks 導航參考

| 區塊分類 | 路徑 | 說明 |
|---------|------|------|
| Navbars | `ui-blocks/application-ui/navigation/navbars/` | 頂部導航列範例 |
| Sidebar Navigation | `ui-blocks/application-ui/navigation/sidebar-navigation/` | 側邊導航範例 |
| Tabs | `ui-blocks/application-ui/navigation/tabs/` | 頁籤式導航 |
| Breadcrumbs | `ui-blocks/application-ui/navigation/breadcrumbs/` | 麵包屑導航 |
| Pagination | `ui-blocks/application-ui/navigation/pagination/` | 分頁控制 |
| Application Shells | `ui-blocks/application-ui/application-shells/` | 完整應用外殼佈局 |

### Catalyst Navbar Angular 轉換範例

```typescript
// core/layout/navbar/navbar.component.ts
@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <nav class="flex items-center justify-between px-4 py-3
                bg-white dark:bg-zinc-900
                border-b border-zinc-200 dark:border-zinc-800"
         role="navigation"
         aria-label="主導航"
         data-testid="navbar">
      <!-- 品牌標誌 -->
      <a routerLink="/" class="flex items-center gap-2" data-testid="navbar-brand">
        <img [ngSrc]="logoSrc()" alt="Logo" width="32" height="32" />
        <span class="text-lg font-semibold text-zinc-950 dark:text-white">
          {{ appName() }}
        </span>
      </a>

      <!-- 桌面導航連結 -->
      <div class="hidden md:flex items-center gap-6" data-testid="navbar-links">
        @for (link of navLinks(); track link.path) {
          <a
            [routerLink]="link.path"
            routerLinkActive="text-zinc-950 dark:text-white"
            [routerLinkActiveOptions]="{ exact: link.exact ?? false }"
            class="text-sm/6 text-zinc-500 hover:text-zinc-950
                   dark:text-zinc-400 dark:hover:text-white
                   transition-colors"
            [attr.data-testid]="'nav-link-' + link.id"
          >
            {{ link.label }}
          </a>
        }
      </div>

      <!-- 行動裝置漢堡選單 -->
      <button
        class="md:hidden p-2 text-zinc-500 hover:text-zinc-950
               dark:text-zinc-400 dark:hover:text-white"
        (click)="toggleMobileMenu()"
        [attr.aria-expanded]="mobileMenuOpen()"
        aria-controls="mobile-menu"
        data-testid="mobile-menu-button"
      >
        <span class="sr-only">開啟選單</span>
        <!-- 漢堡圖示 -->
        <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
        </svg>
      </button>
    </nav>

    <!-- 行動裝置導航選單 -->
    @if (mobileMenuOpen()) {
      <div id="mobile-menu" class="md:hidden bg-white dark:bg-zinc-900
                                    border-b border-zinc-200 dark:border-zinc-800"
           data-testid="mobile-menu">
        @for (link of navLinks(); track link.path) {
          <a
            [routerLink]="link.path"
            routerLinkActive="bg-zinc-100 dark:bg-zinc-800"
            class="block px-4 py-2 text-sm text-zinc-700 dark:text-zinc-300
                   hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
            (click)="closeMobileMenu()"
          >
            {{ link.label }}
          </a>
        }
      </div>
    }
  `,
})
export class NavbarComponent {
  readonly appName = input<string>('App');
  readonly logoSrc = input<string>('/assets/logo.svg');
  readonly navLinks = input.required<NavLink[]>();

  protected readonly mobileMenuOpen = signal(false);

  protected toggleMobileMenu(): void {
    this.mobileMenuOpen.update((open) => !open);
  }

  protected closeMobileMenu(): void {
    this.mobileMenuOpen.set(false);
  }
}

interface NavLink {
  id: string;
  label: string;
  path: string;
  exact?: boolean;
}
```

### Catalyst Sidebar Angular 轉換範例

```typescript
// core/layout/sidebar/sidebar.component.ts
@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterLink, RouterLinkActive],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <aside class="flex h-full w-64 flex-col bg-white dark:bg-zinc-900
                  border-r border-zinc-200 dark:border-zinc-800"
           role="navigation"
           aria-label="側邊導航"
           data-testid="sidebar">
      <!-- 品牌區域 -->
      <div class="flex h-16 items-center gap-2 px-4 border-b border-zinc-200 dark:border-zinc-800">
        <img [ngSrc]="logoSrc()" alt="Logo" width="32" height="32" />
        <span class="text-lg font-semibold text-zinc-950 dark:text-white">
          {{ appName() }}
        </span>
      </div>

      <!-- 導航項目 -->
      <nav class="flex-1 overflow-y-auto p-4">
        <ul class="space-y-1">
          @for (item of menuItems(); track item.path) {
            <li>
              <a
                [routerLink]="item.path"
                routerLinkActive="bg-zinc-100 text-zinc-950 dark:bg-zinc-800 dark:text-white"
                class="flex items-center gap-3 rounded-sm px-3 py-2
                       text-sm/6 text-zinc-700 dark:text-zinc-400
                       hover:bg-zinc-50 hover:text-zinc-950
                       dark:hover:bg-zinc-800/50 dark:hover:text-white
                       transition-colors"
                [attr.data-testid]="'sidebar-item-' + item.id"
              >
                {{ item.label }}
              </a>
            </li>
          }
        </ul>
      </nav>
    </aside>
  `,
})
export class SidebarComponent {
  readonly appName = input<string>('App');
  readonly logoSrc = input<string>('/assets/logo.svg');
  readonly menuItems = input.required<MenuItem[]>();
}

interface MenuItem {
  id: string;
  label: string;
  path: string;
}
```

## 測試指引

### Guard 測試範例（TestBed）

```typescript
// auth.guard.spec.ts
import { TestBed } from '@angular/core/testing';
import { Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { authGuard } from './auth.guard';
import { AuthService } from '../services/auth/auth.service';

describe('authGuard', () => {
  let authServiceMock: { isAuthenticated: ReturnType<typeof signal> };
  let router: Router;

  const mockRoute = {} as ActivatedRouteSnapshot;
  const mockState = { url: '/protected-page' } as RouterStateSnapshot;

  beforeEach(() => {
    authServiceMock = {
      isAuthenticated: signal(false),
    };

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        {
          provide: Router,
          useValue: {
            createUrlTree: vi.fn((commands, extras) => ({
              toString: () => `/login?returnUrl=${extras?.queryParams?.returnUrl}`,
            })),
          },
        },
      ],
    });

    router = TestBed.inject(Router);
  });

  it('should allow access when user is authenticated', () => {
    authServiceMock.isAuthenticated.set(true);

    const result = TestBed.runInInjectionContext(() =>
      authGuard(mockRoute, mockState),
    );

    expect(result).toBe(true);
  });

  it('should redirect to login when user is not authenticated', () => {
    authServiceMock.isAuthenticated.set(false);

    const result = TestBed.runInInjectionContext(() =>
      authGuard(mockRoute, mockState),
    );

    expect(router.createUrlTree).toHaveBeenCalledWith(['/login'], {
      queryParams: { returnUrl: '/protected-page' },
    });
    expect(result).not.toBe(true);
  });
});
```

### Role Guard 測試範例

```typescript
// role.guard.spec.ts
import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { roleGuard } from './role.guard';
import { AuthService } from '../services/auth/auth.service';

describe('roleGuard', () => {
  let authServiceMock: { hasRole: ReturnType<typeof vi.fn> };

  const mockRoute = {} as ActivatedRouteSnapshot;
  const mockState = { url: '/admin' } as RouterStateSnapshot;

  beforeEach(() => {
    authServiceMock = {
      hasRole: vi.fn(),
    };

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authServiceMock },
      ],
    });
  });

  it('should allow access when user has required role', () => {
    authServiceMock.hasRole.mockReturnValue(true);

    const guard = roleGuard('admin');
    const result = TestBed.runInInjectionContext(() =>
      guard(mockRoute, mockState),
    );

    expect(authServiceMock.hasRole).toHaveBeenCalledWith('admin');
    expect(result).toBe(true);
  });

  it('should deny access when user lacks required role', () => {
    authServiceMock.hasRole.mockReturnValue(false);

    const guard = roleGuard('admin');
    const result = TestBed.runInInjectionContext(() =>
      guard(mockRoute, mockState),
    );

    expect(result).toBe(false);
  });
});
```

### 路由整合測試

```typescript
// app.routes.spec.ts
import { TestBed } from '@angular/core/testing';
import { RouterModule, Router } from '@angular/router';
import { Location } from '@angular/common';
import { routes } from './app.routes';

describe('App Routes', () => {
  let router: Router;
  let location: Location;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RouterModule.forRoot(routes)],
    }).compileComponents();

    router = TestBed.inject(Router);
    location = TestBed.inject(Location);
  });

  it('should redirect empty path to dashboard', async () => {
    await router.navigate(['']);
    expect(location.path()).toBe('/dashboard');
  });

  it('should navigate to wildcard route for unknown paths', async () => {
    await router.navigate(['/nonexistent-page']);
    expect(location.path()).toBe('/nonexistent-page');
  });
});
```

## 檢查清單

- [ ] 所有功能模組使用 `loadComponent` / `loadChildren` 延遲載入
- [ ] Guard 使用函式型（`CanActivateFn`），禁止 class-based
- [ ] Guard 工廠函式支援參數化（如 `roleGuard('admin')`）
- [ ] 未認證使用者重導向到登入頁時保留 `returnUrl`
- [ ] 所有路由設定 `title` 屬性（改善 SEO 和無障礙）
- [ ] 萬用路由（`**`）放在路由陣列最後
- [ ] 導航元件支援深色 / 淺色模式（`dark:` 前綴）
- [ ] 導航元件在行動裝置上有漢堡選單
- [ ] 使用 `routerLinkActive` 標示當前啟用的路由
- [ ] 導航元件有 `role="navigation"` 和 `aria-label`
- [ ] 行動選單按鈕有 `aria-expanded` 和 `aria-controls`
- [ ] Guard 有完整的 TestBed 單元測試
- [ ] 使用 `data-testid` 屬性便於 E2E 測試選取

## 參考資源

- [Angular Routing 指南](https://angular.dev/guide/routing)
- [Angular Route Guards](https://angular.dev/guide/routing/route-guards)
- [Angular 延遲載入](https://angular.dev/guide/routing/lazy-loading)
- [Catalyst Navbar 元件](tailwind/css/catalyst-ui-kit/typescript/navbar.tsx)
- [Catalyst Sidebar 元件](tailwind/css/catalyst-ui-kit/typescript/sidebar.tsx)
- [UI Blocks 導航區塊](tailwind/css/ui-blocks/application-ui/navigation/)
- [UI Blocks 應用外殼](tailwind/css/ui-blocks/application-ui/application-shells/)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [routing](../angular-rules/references/routing.md) — 延遲載入、Guard 與 SSR 路由配置
- [performance](../angular-rules/references/performance.md) — 預載入策略與 Bundle 預算
