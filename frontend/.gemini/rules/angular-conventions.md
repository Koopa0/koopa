# Angular 21 強制性慣例

以下全部由 `check-angular-compliance.js` PreToolUse hook 強制執行。

## 必須使用

| 項目 | 必須 | 禁止 |
|------|------|------|
| 元件 | `standalone: true` | `@NgModule` |
| 狀態 | `signal()` / `computed()` / `effect()` | `BehaviorSubject` 管理 UI 狀態 |
| 可編輯衍生狀態 | `linkedSignal()` | — |
| 輸入 | `input()` / `input.required()` | `@Input()` |
| 輸出 | `output()` | `@Output()` |
| 雙向綁定 | `model()` | — |
| 依賴注入 | `inject()` | constructor 參數注入 |
| 控制流 | `@if` / `@for` / `@switch` | `*ngIf` / `*ngFor` / `*ngSwitch` |
| 延遲載入 | `@defer` | — |
| 變更偵測 | `ChangeDetectionStrategy.OnPush` | Default |
| Guard | `CanActivateFn` 等函式型 | class-based Guard |
| Interceptor | `HttpInterceptorFn` | class-based Interceptor |
| RxJS 清理 | `takeUntilDestroyed()` | 手動 unsubscribe |

## 關鍵範例

```typescript
// Signal input/output/model
name = input.required<string>();
age = input(0);
nameChange = output<string>();
value = model<string>('');

// inject()
private readonly userService = inject(UserService);

// linkedSignal
selectedItem = linkedSignal(() => this.items()[0]);

// 函式型 Guard
export const authGuard: CanActivateFn = (route, state) => {
  const auth = inject(AuthService);
  return auth.isAuthenticated() ? true : inject(Router).createUrlTree(['/login']);
};

// 函式型 Interceptor
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = inject(AuthService).token();
  return next(token ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : req);
};
```

```html
<!-- 控制流 + @defer -->
@if (users().length > 0) {
  @for (user of users(); track user.id) {
    <app-user-card [user]="user" />
  } @empty {
    <p>沒有使用者</p>
  }
}

@defer (on viewport) {
  <app-heavy-chart [data]="chartData()" />
} @placeholder {
  <div class="h-64 animate-pulse bg-zinc-800 rounded-lg"></div>
}
```
