---
name: security
description: >-
  Angular security patterns — XSS protection, token storage in memory, CSRF
  interceptors, CSP headers, input validation, and OWASP top 10.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Security

## 觸發條件

- 實作認證或授權功能時
- 處理使用者輸入或外部資料時
- 建立 HTTP interceptor 或 API 通訊時
- 進行安全性稽核或審查時
- 儲存或傳輸敏感資料時
- 設定路由守衛或權限控制時

## 程式碼模板 / 核心模式

### Angular 安全機制

#### XSS 防護

Angular 預設會清理所有綁定的值。不要繞過它：

```typescript
// 禁止
this.sanitizer.bypassSecurityTrustHtml(userInput);

// 使用 Angular 內建清理
<div>{{ userContent }}</div>  // 自動轉義
```

#### 禁止 innerHTML

```html
<!-- 禁止 -->
<div [innerHTML]="userContent"></div>

<!-- 使用文字綁定 -->
<div>{{ userContent }}</div>
```

### 認證安全

#### Token 儲存

```typescript
// 僅存在記憶體中
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly _token = signal<string | null>(null);
  readonly token = this._token.asReadonly();
  readonly isAuthenticated = computed(() => this._token() !== null);
}

// 禁止存在 localStorage
localStorage.setItem('token', token);
sessionStorage.setItem('token', token);
```

#### CSRF 防護

```typescript
export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  const csrfToken = inject(CookieService).get('XSRF-TOKEN');
  if (csrfToken && !req.method.match(/^(GET|HEAD)$/)) {
    const cloned = req.clone({
      setHeaders: { 'X-XSRF-TOKEN': csrfToken },
    });
    return next(cloned);
  }
  return next(req);
};
```

### 路由守衛

```typescript
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
```

### 輸入驗證

```typescript
// 在系統邊界驗證
export function validateEmail(email: unknown): string {
  if (typeof email !== 'string') {
    throw new Error('Email must be a string');
  }
  const trimmed = email.trim().toLowerCase();
  if (!EMAIL_REGEX.test(trimmed)) {
    throw new Error('Invalid email format');
  }
  return trimmed;
}
```

### 禁止事項

- 硬編碼密碼、Token、API Key
- 使用 `localStorage` / `sessionStorage` 存儲認證資訊
- 使用 `bypassSecurityTrust*`
- 使用 `innerHTML` 綁定使用者輸入
- 錯誤訊息洩露系統資訊
- 在前端執行授權邏輯（僅 UI 層級守衛）

### CSP Headers

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
```

## 測試指引

### XSS 防護測試

```typescript
describe('XSS 防護', () => {
  it('should sanitize HTML in text bindings', () => {
    const fixture = TestBed.createComponent(UserProfileComponent);
    fixture.componentRef.setInput('displayName', '<script>alert("xss")</script>');
    fixture.detectChanges();

    const element = fixture.debugElement.query(By.css('[data-testid="display-name"]'));
    // Angular 會自動轉義 HTML
    expect(element.nativeElement.innerHTML).not.toContain('<script>');
    expect(element.nativeElement.textContent).toContain('<script>');
  });

  it('should not use bypassSecurityTrust methods', () => {
    // 在程式碼中搜尋禁止的方法
    // 此測試應在 lint 規則中實作
    const sourceCode = readFileSync('src/app/features/user/user-profile.component.ts', 'utf-8');
    expect(sourceCode).not.toContain('bypassSecurityTrust');
  });

  it('should escape user input in URL parameters', () => {
    const fixture = TestBed.createComponent(SearchComponent);
    fixture.componentRef.setInput('query', 'test"><script>alert(1)</script>');
    fixture.detectChanges();

    const link = fixture.debugElement.query(By.css('[data-testid="search-link"]'));
    const href = link.nativeElement.getAttribute('href');
    expect(href).not.toContain('<script>');
  });
});
```

### CSRF 防護測試

```typescript
describe('CSRF Interceptor', () => {
  let httpTesting: HttpTestingController;
  let httpClient: HttpClient;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([csrfInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    httpTesting = TestBed.inject(HttpTestingController);
    httpClient = TestBed.inject(HttpClient);
  });

  it('should add CSRF token to POST requests', () => {
    // 模擬 CSRF cookie
    spyOn(TestBed.inject(CookieService), 'get').and.returnValue('test-csrf-token');

    httpClient.post('/api/data', { value: 'test' }).subscribe();

    const req = httpTesting.expectOne('/api/data');
    expect(req.request.headers.get('X-XSRF-TOKEN')).toBe('test-csrf-token');
  });

  it('should not add CSRF token to GET requests', () => {
    spyOn(TestBed.inject(CookieService), 'get').and.returnValue('test-csrf-token');

    httpClient.get('/api/data').subscribe();

    const req = httpTesting.expectOne('/api/data');
    expect(req.request.headers.has('X-XSRF-TOKEN')).toBe(false);
  });
});
```

### Auth Guard 測試

```typescript
describe('authGuard', () => {
  let authService: AuthService;
  let router: Router;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        AuthService,
        provideRouter([
          { path: 'dashboard', component: DashboardComponent, canActivate: [authGuard] },
          { path: 'login', component: LoginComponent },
        ]),
      ],
    });
    authService = TestBed.inject(AuthService);
    router = TestBed.inject(Router);
  });

  it('should allow access when authenticated', async () => {
    // 模擬已認證狀態
    authService['_token'].set('valid-token');

    const result = await router.navigateByUrl('/dashboard');
    expect(result).toBe(true);
  });

  it('should redirect to login when not authenticated', async () => {
    // 確保未認證
    authService['_token'].set(null);

    await router.navigateByUrl('/dashboard');
    expect(router.url).toContain('/login');
  });

  it('should preserve return URL in query params', async () => {
    authService['_token'].set(null);

    await router.navigateByUrl('/dashboard');
    expect(router.url).toContain('returnUrl=%2Fdashboard');
  });
});
```

### Token 儲存安全測試

```typescript
describe('AuthService Token 安全', () => {
  let service: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AuthService);
    localStorage.clear();
    sessionStorage.clear();
  });

  it('should not store token in localStorage', () => {
    service.setToken('test-token');

    expect(localStorage.getItem('token')).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it('should not store token in sessionStorage', () => {
    service.setToken('test-token');

    expect(sessionStorage.getItem('token')).toBeNull();
    expect(sessionStorage.length).toBe(0);
  });

  it('should store token only in memory signal', () => {
    service.setToken('test-token');

    expect(service.token()).toBe('test-token');
    expect(service.isAuthenticated()).toBe(true);
  });

  it('should clear token on logout', () => {
    service.setToken('test-token');
    service.logout();

    expect(service.token()).toBeNull();
    expect(service.isAuthenticated()).toBe(false);
  });
});
```

### 輸入驗證測試

```typescript
describe('輸入驗證', () => {
  it('should reject non-string email input', () => {
    expect(() => validateEmail(123)).toThrow('Email must be a string');
    expect(() => validateEmail(null)).toThrow('Email must be a string');
    expect(() => validateEmail(undefined)).toThrow('Email must be a string');
  });

  it('should reject invalid email format', () => {
    expect(() => validateEmail('not-an-email')).toThrow('Invalid email format');
    expect(() => validateEmail('test@')).toThrow('Invalid email format');
    expect(() => validateEmail('@domain.com')).toThrow('Invalid email format');
  });

  it('should sanitize and normalize valid email', () => {
    expect(validateEmail('  User@Example.COM  ')).toBe('user@example.com');
  });

  it('should reject email with potential injection', () => {
    expect(() => validateEmail('user@domain.com<script>')).toThrow('Invalid email format');
  });
});
```

### Playwright 安全性 E2E 測試

```typescript
// e2e/tests/security/auth.spec.ts
import { test, expect } from '@playwright/test';

test.describe('認證安全', () => {
  test('should redirect unauthenticated user to login', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/);
  });

  test('should not expose token in URL', async ({ page }) => {
    await page.goto('/login');
    // 模擬登入
    await page.getByTestId('email-input').fill('user@example.com');
    await page.getByTestId('password-input').fill('password');
    await page.getByTestId('login-button').click();

    // 確認 token 不在 URL 中
    expect(page.url()).not.toContain('token');
  });

  test('should not expose sensitive data in error messages', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('email-input').fill('wrong@example.com');
    await page.getByTestId('password-input').fill('wrong');
    await page.getByTestId('login-button').click();

    const errorMessage = page.getByTestId('error-message');
    await expect(errorMessage).toBeVisible();

    // 錯誤訊息不應洩露系統資訊
    const text = await errorMessage.textContent();
    expect(text).not.toContain('SQL');
    expect(text).not.toContain('stack trace');
    expect(text).not.toContain('Internal Server Error');
  });

  test('should clear auth state on logout', async ({ page }) => {
    // 模擬登入後登出
    await page.goto('/dashboard');
    // ... 登入流程
    await page.getByTestId('logout-button').click();

    // 嘗試訪問受保護頁面
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/);
  });
});
```

### HTTP 安全標頭測試

```typescript
// e2e/tests/security/headers.spec.ts
import { test, expect } from '@playwright/test';

test.describe('HTTP 安全標頭', () => {
  test('should include security headers', async ({ page }) => {
    const response = await page.goto('/');

    if (response) {
      const headers = response.headers();

      // 檢查常見安全標頭（需要後端支援）
      // 這些測試在整合環境中執行
      expect(headers['x-content-type-options']).toBe('nosniff');
      expect(headers['x-frame-options']).toBeDefined();
      expect(headers['content-security-policy']).toBeDefined();
    }
  });
});
```

## 檢查清單

### 認證與授權

- [ ] Token 僅儲存在記憶體中（Signal / Service 變數）
- [ ] 不使用 `localStorage` / `sessionStorage` 存儲認證資訊
- [ ] 使用 HttpOnly Cookie 進行持久化認證（後端設定）
- [ ] 路由守衛使用函式型 `CanActivateFn`
- [ ] 前端守衛僅用於 UI 層級（授權邏輯在後端）
- [ ] 登出時完全清除認證狀態

### XSS 防護

- [ ] 不使用 `bypassSecurityTrust*` 方法
- [ ] 不使用 `[innerHTML]` 綁定使用者輸入
- [ ] 所有使用者輸入透過 Angular 內建清理機制
- [ ] URL 參數經過驗證和編碼

### CSRF 防護

- [ ] 使用 HTTP Interceptor 自動附加 CSRF Token
- [ ] 非 GET/HEAD 請求都包含 CSRF Token
- [ ] CSRF Token 從 HttpOnly Cookie 讀取

### 輸入驗證

- [ ] 所有外部輸入在系統邊界驗證
- [ ] 使用強型別（避免 `any`）
- [ ] Email、URL、數值等有格式驗證
- [ ] API 回應有型別守衛驗證

### 敏感資料

- [ ] 無硬編碼密碼、Token、API Key
- [ ] 敏感設定使用環境變數
- [ ] 錯誤訊息不洩露系統資訊（SQL、stack trace、內部路徑）
- [ ] `.env` 檔案在 `.gitignore` 中

### HTTP 安全

- [ ] CSP Headers 正確設定
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options` 防止 clickjacking
- [ ] HTTPS 強制使用

### 依賴安全

- [ ] CI/CD 中執行 `npm audit --audit-level=high`
- [ ] 無 high / critical 等級漏洞
- [ ] 定期更新依賴套件
- [ ] 不使用已知有漏洞的套件版本

### 測試覆蓋

- [ ] XSS 防護測試通過
- [ ] CSRF Interceptor 測試通過
- [ ] Auth Guard 測試通過（認證 / 未認證 / 重導向）
- [ ] Token 儲存安全測試通過（不洩漏到 storage）
- [ ] 輸入驗證測試通過
- [ ] E2E 認證流程測試通過

## 參考資源

- [Angular Security Guide](https://angular.dev/best-practices/security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Angular HttpClient XSRF](https://angular.dev/guide/http/security)
- [Google TypeScript Style Guide - Security](https://google.github.io/styleguide/tsguide.html)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [security](../angular-rules/references/security.md) — XSS、CSRF、Token 儲存與 OWASP Top 10
- [error-handling](../angular-rules/references/error-handling.md) — 錯誤訊息不洩露敏感資訊
