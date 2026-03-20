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
| 查詢 | `viewChild()` / `viewChildren()` / `contentChild()` / `contentChildren()` | `@ViewChild` / `@ViewChildren` / `@ContentChild` / `@ContentChildren` |
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

// Signal queries
formEl = viewChild<ElementRef>('form');
items = viewChildren(ItemComponent);
header = contentChild(HeaderComponent);
tabs = contentChildren(TabComponent);
```

## 實驗性 API（Developer Preview）

以下 API 在 Angular v21 仍為 experimental，生產程式碼請謹慎使用：

| API | 狀態 | 說明 |
|-----|------|------|
| `resource()` / `rxResource()` | Developer Preview | 非同步資料載入，API 可能變更 |
| `httpResource()` | Developer Preview | HTTP 專用 resource，API 可能變更 |
| Signal Forms (`@angular/forms/signals`) | Developer Preview | Signal-based 表單，API 可能變更 |

> **注意**：v19+ `standalone: true` 為預設值，本專案明確寫出為專案慣例以確保一致性。

> **注意**：v21 預設 zoneless（無 Zone.js），所有元件的變更偵測行為接近 OnPush。本專案仍要求明確標註 `ChangeDetectionStrategy.OnPush` 以確保向下相容和意圖明確。

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
