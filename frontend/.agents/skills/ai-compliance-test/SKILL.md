---
name: ai-compliance-test
description: >-
  Trap-pattern test scenarios for AI self-validation — verifies generated code
  follows Angular 21 project standards and catches common AI mistakes.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: AI Compliance Testing

## 目的

本技能提供 AI 自我驗證測試情境，確保 AI 助手正確應用 Angular Spec 專案的所有標準和最佳實踐。包含 4 類「陷阱」測試，驗證 AI 能夠識別並修正違規程式碼。

---

## 使用方式

AI 在產生或審查程式碼時，應自動對照本技能中的陷阱模式，確保不會落入任何陷阱。

---

## 陷阱類型 1：Angular 21 API 陷阱

### 陷阱 1.1：裝飾器 vs 函式

```typescript
// ❌ 陷阱：使用 @Input/@Output 裝飾器
@Component({...})
export class UserCard {
  @Input() user!: User;           // 陷阱！
  @Output() select = new EventEmitter<User>();  // 陷阱！
}

// ✅ 正確：使用 input()/output() 函式
@Component({...})
export class UserCard {
  readonly user = input.required<User>();
  readonly select = output<User>();
}
```

**驗證點**：
- 搜尋 `@Input()` → 應為 0 個
- 搜尋 `@Output()` → 應為 0 個
- 搜尋 `new EventEmitter` → 應為 0 個

### 陷阱 1.2：Constructor 注入

```typescript
// ❌ 陷阱：Constructor 參數注入
@Component({...})
export class ProductList {
  constructor(
    private readonly productService: ProductService,  // 陷阱！
    private readonly router: Router,
  ) {}
}

// ✅ 正確：使用 inject() 函式
@Component({...})
export class ProductList {
  private readonly productService = inject(ProductService);
  private readonly router = inject(Router);
}
```

**驗證點**：
- 搜尋 `constructor(private` → 應為 0 個
- 搜尋 `constructor(protected` → 應為 0 個
- 搜尋 `constructor(readonly` → 應為 0 個

### 陷阱 1.3：結構指令 vs 控制流

```html
<!-- ❌ 陷阱：使用 *ngIf/*ngFor/*ngSwitch -->
<div *ngIf="isLoading">Loading...</div>
<div *ngFor="let item of items">{{ item.name }}</div>
<div [ngSwitch]="status">
  <span *ngSwitchCase="'active'">Active</span>
</div>

<!-- ✅ 正確：使用 @if/@for/@switch -->
@if (isLoading()) {
  <div>Loading...</div>
}
@for (item of items(); track item.id) {
  <div>{{ item.name }}</div>
}
@switch (status()) {
  @case ('active') {
    <span>Active</span>
  }
}
```

**驗證點**：
- 搜尋 `*ngIf` → 應為 0 個
- 搜尋 `*ngFor` → 應為 0 個
- 搜尋 `*ngSwitch` → 應為 0 個
- 搜尋 `[ngSwitch]` → 應為 0 個

### 陷阱 1.4：@ViewChild 裝飾器

```typescript
// ❌ 陷阱：使用 @ViewChild 裝飾器
@Component({...})
export class FormComponent {
  @ViewChild('inputRef') inputElement!: ElementRef;  // 陷阱！
  @ViewChildren('items') itemElements!: QueryList<ElementRef>;  // 陷阱！
}

// ✅ 正確：使用 viewChild()/viewChildren() 函式
@Component({...})
export class FormComponent {
  readonly inputElement = viewChild<ElementRef>('inputRef');
  readonly itemElements = viewChildren<ElementRef>('items');
}
```

**驗證點**：
- 搜尋 `@ViewChild` → 應為 0 個
- 搜尋 `@ViewChildren` → 應為 0 個

### 陷阱 1.5：NgModule

```typescript
// ❌ 陷阱：使用 NgModule
@NgModule({
  declarations: [UserListComponent],
  imports: [CommonModule],
  exports: [UserListComponent],
})
export class UserModule {}

// ✅ 正確：Standalone Components
@Component({
  selector: 'app-user-list',
  standalone: true,
  imports: [TranslocoPipe],
})
export class UserListComponent {}
```

**驗證點**：
- 搜尋 `@NgModule` → 應為 0 個（在 src/app/ 下）

### 陷阱 1.6：Class-based Guard/Interceptor

```typescript
// ❌ 陷阱：Class-based Guard
@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  canActivate(route, state) { ... }  // 陷阱！
}

// ✅ 正確：Functional Guard
export const authGuard: CanActivateFn = (route, state) => {
  const auth = inject(AuthService);
  return auth.isAuthenticated();
};
```

**驗證點**：
- 搜尋 `implements CanActivate` → 應為 0 個
- 搜尋 `implements HttpInterceptor` → 應為 0 個

### 陷阱 1.7：缺少 OnPush

```typescript
// ❌ 陷阱：未設定 OnPush
@Component({
  selector: 'app-product-card',
  // 缺少 changeDetection: ChangeDetectionStrategy.OnPush  // 陷阱！
})
export class ProductCard {}

// ✅ 正確：必須設定 OnPush
@Component({
  selector: 'app-product-card',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProductCard {}
```

**驗證點**：
- 每個 `@Component` 必須有 `changeDetection: ChangeDetectionStrategy.OnPush`

---

## 陷阱類型 2：Tailwind v4 陷阱

### 陷阱 2.1：舊版 Shadow 語法

```html
<!-- ❌ 陷阱：v3 shadow 語法 -->
<div class="shadow-sm">...</div>   <!-- v3 的 shadow-sm = v4 的 shadow-xs -->
<div class="shadow">...</div>      <!-- v3 的 shadow = v4 的 shadow-sm -->

<!-- ✅ 正確：v4 shadow 語法 -->
<div class="shadow-xs">...</div>   <!-- 小陰影 -->
<div class="shadow-sm">...</div>   <!-- 預設陰影 -->
```

**驗證點**：
- 審查所有 `shadow-sm` 使用 → 確認是否應為 `shadow-xs`
- 審查獨立 `shadow` 使用 → 應為 `shadow-sm`

### 陷阱 2.2：舊版 Rounded 語法

```html
<!-- ❌ 陷阱：v3 rounded 語法 -->
<div class="rounded-sm">...</div>  <!-- v3 的 rounded-sm = v4 的 rounded-xs -->
<div class="rounded">...</div>     <!-- v3 的 rounded = v4 的 rounded-sm -->

<!-- ✅ 正確：v4 rounded 語法 -->
<div class="rounded-xs">...</div>  <!-- 2px -->
<div class="rounded-sm">...</div>  <!-- 4px -->
```

**驗證點**：
- 審查所有 `rounded-sm` 使用 → 確認是否應為 `rounded-xs`
- 審查獨立 `rounded` 使用 → 應為 `rounded-sm`

### 陷阱 2.3：Opacity 語法

```html
<!-- ❌ 陷阱：v3 opacity 語法 -->
<div class="bg-black bg-opacity-50">...</div>  <!-- 陷阱！ -->
<div class="text-white text-opacity-75">...</div>  <!-- 陷阱！ -->

<!-- ✅ 正確：v4 opacity modifier -->
<div class="bg-black/50">...</div>
<div class="text-white/75">...</div>
```

**驗證點**：
- 搜尋 `bg-opacity-` → 應為 0 個
- 搜尋 `text-opacity-` → 應為 0 個

### 陷阱 2.4：outline-none

```html
<!-- ❌ 陷阱：outline-none -->
<button class="outline-none focus:ring-2">...</button>  <!-- 陷阱！ -->

<!-- ✅ 正確：outline-hidden -->
<button class="outline-hidden focus:ring-3">...</button>
```

**驗證點**：
- 搜尋 `outline-none` → 應為 0 個

### 陷阱 2.5：Ring 無尺寸

```html
<!-- ❌ 陷阱：ring 沒有尺寸 -->
<button class="focus:ring focus:ring-blue-500">...</button>  <!-- 陷阱！ -->

<!-- ✅ 正確：ring 需要尺寸 -->
<button class="focus:ring-3 focus:ring-blue-500">...</button>
```

**驗證點**：
- 搜尋獨立 `ring` class（非 `ring-[0-9]`）→ 應加上尺寸

### 陷阱 2.6：Gradient 語法

```html
<!-- ❌ 陷阱：v3 gradient 語法 -->
<div class="bg-gradient-to-r from-blue-500 to-purple-500">...</div>  <!-- 陷阱！ -->

<!-- ✅ 正確：v4 gradient 語法 -->
<div class="bg-linear-to-r from-blue-500 to-purple-500">...</div>
```

**驗證點**：
- 搜尋 `bg-gradient-` → 應為 0 個

### 陷阱 2.7：min-h-screen

```html
<!-- ❌ 陷阱：min-h-screen -->
<div class="min-h-screen">...</div>  <!-- 陷阱！ -->

<!-- ✅ 正確：min-h-dvh -->
<div class="min-h-dvh">...</div>
```

**驗證點**：
- 搜尋 `min-h-screen` → 應為 0 個

### 陷阱 2.8：@apply 指令

```css
/* ❌ 陷阱：使用 @apply */
.btn-primary {
  @apply bg-blue-500 text-white px-4 py-2;  /* 陷阱！ */
}

/* ✅ 正確：使用 CSS variables 或元件封裝 */
.btn-primary {
  background-color: var(--color-blue-500);
  color: white;
  padding: var(--spacing-2) var(--spacing-4);
}
```

**驗證點**：
- 搜尋 `@apply` → 應為 0 個

### 陷阱 2.9：space-x/space-y

```html
<!-- ❌ 陷阱：space-x/space-y 在 flex 中 -->
<div class="flex space-x-4">...</div>  <!-- 陷阱！ -->

<!-- ✅ 正確：使用 gap -->
<div class="flex gap-4">...</div>
```

**驗證點**：
- 審查 `space-x-` / `space-y-` → 在 flex/grid 容器中應使用 `gap-`

---

## 陷阱類型 3：安全陷阱

### 陷阱 3.1：Token 存於 localStorage

```typescript
// ❌ 陷阱：Token 存於 localStorage
export class AuthService {
  login(token: string) {
    localStorage.setItem('authToken', token);  // 陷阱！XSS 風險
  }

  getToken() {
    return localStorage.getItem('authToken');  // 陷阱！
  }
}

// ✅ 正確：Token 只存於記憶體
export class AuthService {
  private readonly token = signal<string | null>(null);

  login(token: string) {
    this.token.set(token);
  }

  getToken() {
    return this.token();
  }
}
```

**驗證點**：
- 搜尋 `localStorage.setItem.*token` → 應為 0 個
- 搜尋 `sessionStorage.setItem.*token` → 應為 0 個

### 陷阱 3.2：bypassSecurityTrust 無審查

```typescript
// ❌ 陷阱：bypassSecurityTrust 無安全審查
export class RichTextComponent {
  getSafeHtml(html: string) {
    return this.sanitizer.bypassSecurityTrustHtml(html);  // 陷阱！
  }
}

// ✅ 正確：必須有安全審查文件
export class RichTextComponent {
  getSafeHtml(html: string) {
    // SECURITY_REVIEW: 2026-02-05
    // Reason: Admin-only content, input sanitized by backend
    // Reviewed by: security@example.com
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
}
```

**驗證點**：
- 每個 `bypassSecurityTrust` 前必須有 `SECURITY_REVIEW` 註解

### 陷阱 3.3：硬編碼機密

```typescript
// ❌ 陷阱：硬編碼 API Key
const API_KEY = 'sk_live_1234567890abcdef';  // 陷阱！

// ✅ 正確：使用環境變數
const API_KEY = environment.apiKey;
```

**驗證點**：
- 搜尋 `api[_-]?key.*=.*['"][a-zA-Z0-9]{20,}['"]` → 應為 0 個
- 搜尋 `password.*=.*['"][^'\"]+['"]` → 應為 0 個（排除 type="password"）
- 搜尋 `secret.*=.*['"][^'\"]+['"]` → 應為 0 個

### 陷阱 3.4：innerHTML 綁定無清理

```typescript
// ❌ 陷阱：直接 innerHTML 綁定
@Component({
  template: `<div [innerHTML]="userContent"></div>`,  // 陷阱！
})
export class UnsafeComponent {
  userContent = this.userInput;  // 未清理！
}

// ✅ 正確：使用 DomSanitizer 清理
@Component({
  template: `<div [innerHTML]="sanitizedContent()"></div>`,
})
export class SafeComponent {
  private readonly sanitizer = inject(DomSanitizer);

  readonly sanitizedContent = computed(() =>
    this.sanitizer.sanitize(SecurityContext.HTML, this.userInput())
  );
}
```

**驗證點**：
- 每個 `[innerHTML]` 綁定必須使用 `sanitize()` 或有安全審查

### 陷阱 3.5：eval/new Function

```typescript
// ❌ 陷阱：使用 eval 或 new Function
const result = eval(userInput);  // 陷阱！
const fn = new Function('x', userCode);  // 陷阱！

// ✅ 正確：重新設計邏輯，避免動態程式碼執行
```

**驗證點**：
- 搜尋 `eval(` → 應為 0 個
- 搜尋 `new Function(` → 應為 0 個

---

## 陷阱類型 4：測試陷阱

### 陷阱 4.1：測試命名不符規範

```typescript
// ❌ 陷阱：測試命名不符 should...when 格式
it('test login', () => { ... });  // 陷阱！
it('works correctly', () => { ... });  // 陷阱！
it('button disabled', () => { ... });  // 陷阱！

// ✅ 正確：使用 should...when 格式
it('should display error message when login fails', () => { ... });
it('should disable submit button when form is invalid', () => { ... });
```

**驗證點**：
- 所有 `it('...'` 必須以 `should` 開頭並包含 `when`

### 陷阱 4.2：空測試

```typescript
// ❌ 陷阱：空測試無 expect
it('should create the component', () => {
  // 沒有 expect！陷阱！
});

// ✅ 正確：必須有 expect
it('should create the component', () => {
  expect(component).toBeTruthy();
});
```

**驗證點**：
- 每個 `it(` 區塊必須包含至少一個 `expect(`

### 陷阱 4.3：測試私有方法

```typescript
// ❌ 陷阱：測試私有方法
it('should call private method', () => {
  expect(component['privateMethod']()).toBe('result');  // 陷阱！
});

// ✅ 正確：透過公開 API 測試行為
it('should display result when data is processed', () => {
  component.processData();  // 公開方法
  expect(component.result()).toBe('expected');
});
```

**驗證點**：
- 搜尋 `component['` 或 `service['` → 應為 0 個（測試檔案中）

### 陷阱 4.4：使用 CSS class 作為選擇器

```typescript
// ❌ 陷阱：使用 CSS class 選擇器
const button = fixture.debugElement.query(By.css('.btn-primary'));  // 陷阱！
const input = element.querySelector('.form-input');  // 陷阱！

// ✅ 正確：使用 data-testid
const button = fixture.debugElement.query(By.css('[data-testid="submit-button"]'));
const input = element.querySelector('[data-testid="email-input"]');
```

**驗證點**：
- 測試中的 DOM 選擇器應使用 `data-testid`

### 陷阱 4.5：隨機測試資料

```typescript
// ❌ 陷阱：使用隨機資料
const user = {
  id: Math.random().toString(),  // 陷阱！不確定性
  name: faker.name.fullName(),   // 陷阱！
};

// ✅ 正確：使用固定資料
const user = MOCK_USER;  // 來自 shared/testing/mock-data.ts
```

**驗證點**：
- 搜尋 `Math.random()` → 測試檔案中應為 0 個
- 搜尋 `faker.` → 測試檔案中應為 0 個

---

## 自動化驗證腳本

```bash
#!/bin/bash
# scripts/ai-compliance-check.sh

echo "╔══════════════════════════════════════╗"
echo "║     AI Compliance Trap Detection     ║"
echo "╚══════════════════════════════════════╝"

errors=0

# Angular 21 API Traps
echo "▸ Angular 21 API..."
for pattern in "@Input()" "@Output()" "@ViewChild" "@NgModule" "*ngIf" "*ngFor" "*ngSwitch" "implements CanActivate" "implements HttpInterceptor"; do
  count=$(grep -rc "$pattern" src/ --include="*.ts" --include="*.html" --exclude="*.spec.ts" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
  if [ "$count" -gt 0 ]; then
    echo "  ❌ $pattern: $count occurrences"
    errors=$((errors + count))
  fi
done

# Tailwind v4 Traps
echo "▸ Tailwind v4..."
for pattern in "bg-opacity-" "text-opacity-" "outline-none" "min-h-screen" "@apply" "bg-gradient-"; do
  count=$(grep -rc "$pattern" src/ --include="*.html" --include="*.ts" --include="*.css" --include="*.scss" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
  if [ "$count" -gt 0 ]; then
    echo "  ❌ $pattern: $count occurrences"
    errors=$((errors + count))
  fi
done

# Security Traps
echo "▸ Security..."
token_storage=$(grep -rc "localStorage.setItem.*token\|sessionStorage.setItem.*token" src/ --include="*.ts" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$token_storage" -gt 0 ]; then
  echo "  ❌ Token in storage: $token_storage occurrences"
  errors=$((errors + token_storage))
fi

bypass_no_review=$(grep -l "bypassSecurityTrust" src/ -r --include="*.ts" 2>/dev/null | while read f; do
  if ! grep -B5 "bypassSecurityTrust" "$f" | grep -q "SECURITY_REVIEW"; then
    echo "$f"
  fi
done | wc -l)
if [ "$bypass_no_review" -gt 0 ]; then
  echo "  ❌ bypassSecurityTrust without review: $bypass_no_review files"
  errors=$((errors + bypass_no_review))
fi

eval_usage=$(grep -rc "eval(\|new Function(" src/ --include="*.ts" --exclude="*.spec.ts" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$eval_usage" -gt 0 ]; then
  echo "  ❌ eval/new Function: $eval_usage occurrences"
  errors=$((errors + eval_usage))
fi

# Testing Traps
echo "▸ Testing..."
empty_tests=$(grep -l "it('" src/ -r --include="*.spec.ts" 2>/dev/null | xargs -I {} sh -c 'grep -A3 "it(" {} | grep -c "});" | grep -v "expect"' 2>/dev/null || echo "0")

private_access=$(grep -rc "component\['\|service\['" src/ --include="*.spec.ts" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$private_access" -gt 0 ]; then
  echo "  ❌ Private method testing: $private_access occurrences"
  errors=$((errors + private_access))
fi

echo ""
echo "════════════════════════════════════════"
if [ "$errors" -eq 0 ]; then
  echo "✅ All compliance checks passed"
else
  echo "❌ Found $errors compliance issues"
fi
```

---

## AI 自我檢查清單

在產生程式碼前，AI 應確認：

### Angular 21
- [ ] 使用 `input()`/`output()` 而非 `@Input`/`@Output`
- [ ] 使用 `inject()` 而非 constructor 注入
- [ ] 使用 `@if`/`@for`/`@switch` 而非 `*ngIf`/`*ngFor`
- [ ] 使用 `viewChild()`/`viewChildren()` 而非 `@ViewChild`
- [ ] 使用函式型 Guard/Interceptor
- [ ] 設定 `ChangeDetectionStrategy.OnPush`
- [ ] 使用 `standalone: true`

### Tailwind v4
- [ ] 使用 `shadow-xs`（非 `shadow-sm`）表示小陰影
- [ ] 使用 `rounded-xs`（非 `rounded-sm`）表示小圓角
- [ ] 使用 `bg-black/50`（非 `bg-opacity-50`）
- [ ] 使用 `outline-hidden`（非 `outline-none`）
- [ ] 使用 `ring-3`（非獨立 `ring`）
- [ ] 使用 `bg-linear-*`（非 `bg-gradient-*`）
- [ ] 使用 `min-h-dvh`（非 `min-h-screen`）
- [ ] 使用 `gap-*`（非 `space-x-*`/`space-y-*` 在 flex 中）
- [ ] 不使用 `@apply`

### 安全性
- [ ] Token 只存於記憶體（Signal/Service）
- [ ] 無硬編碼機密
- [ ] `bypassSecurityTrust` 有安全審查註解
- [ ] `innerHTML` 有適當清理
- [ ] 無 `eval`/`new Function`

### 測試
- [ ] 測試名稱符合 `should...when` 格式
- [ ] 每個 `it` 有 `expect`
- [ ] 使用 `data-testid` 選擇器
- [ ] 使用固定 mock 資料
- [ ] 不測試私有方法


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [angular-conventions](../angular-rules/references/angular-conventions.md) — Angular 21 強制性 API
- [coding-style](../angular-rules/references/coding-style.md) — 命名與程式碼格式規範
- [testing](../angular-rules/references/testing.md) — TDD 工作流與覆蓋率要求
