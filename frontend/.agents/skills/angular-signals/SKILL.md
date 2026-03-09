---
name: angular-signals
description: >-
  Angular Signal primitives reference — signal(), computed(), effect(),
  linkedSignal(), resource(), input(), output(), and model().
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Signals

## 觸發條件

當需要建立或管理元件狀態時使用此 skill。包含以下場景：

- 建立元件內部狀態（`signal()`）
- 定義衍生/計算狀態（`computed()`）
- 處理副作用同步（`effect()`）
- 建立可編輯的衍生狀態（`linkedSignal()`）
- 非同步資料載入（`resource()` / `rxResource()`）
- 查詢模板元素（`viewChild()` / `viewChildren()`）
- 定義元件輸入/輸出（`input()` / `output()` / `model()`）

## 程式碼模板 / 核心模式

### Signal 基礎

```typescript
// 可寫 signal
const count = signal(0);
count.set(1);
count.update(v => v + 1);

// 唯讀 signal
const readonlyCount = count.asReadonly();

// 計算 signal
const doubled = computed(() => count() * 2);
```

### 元件中的 Signal

```typescript
@Component({
  selector: 'app-counter',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p>Count: {{ count() }}</p>
    <p>Doubled: {{ doubled() }}</p>
    <button (click)="increment()">+</button>
  `,
})
export class CounterComponent {
  protected readonly count = signal(0);
  protected readonly doubled = computed(() => this.count() * 2);

  protected increment(): void {
    this.count.update(v => v + 1);
  }
}
```

### Signal-based Input / Output

```typescript
// Input
readonly name = input<string>();              // 可選
readonly id = input.required<string>();        // 必填
readonly count = input(0);                     // 預設值

// Output
readonly clicked = output<void>();
readonly valueChanged = output<string>();

// Model (雙向綁定)
readonly value = model<string>('');

// 使用
this.clicked.emit();
this.valueChanged.emit('new value');
```

### linkedSignal

```typescript
// 基於來源但可獨立修改的 signal
readonly items = input.required<Item[]>();
readonly selectedItem = linkedSignal(() => this.items()[0]);

// 使用者可以手動選擇
selectItem(item: Item): void {
  this.selectedItem.set(item);
}
// 當 items 變化時，自動重置為第一個
```

### Signal Queries — viewChild / viewChildren

```typescript
// viewChild — 查詢單一模板元素或元件
readonly inputEl = viewChild<ElementRef>('myInput');
readonly dialog = viewChild(DialogComponent);

// viewChildren — 查詢多個元素或元件
readonly items = viewChildren(ItemComponent);

// contentChild / contentChildren — 查詢投影內容
readonly header = contentChild(HeaderDirective);
readonly tabs = contentChildren(TabComponent);
```

**viewChild / viewChildren 使用範例**：

```typescript
@Component({
  selector: 'app-search-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <input #searchInput data-testid="search-input" />
    <button (click)="focusInput()">聚焦</button>

    @for (result of results(); track result.id) {
      <app-result-card [data]="result" />
    }
  `,
})
export class SearchFormComponent {
  // Signal query — 回傳值為 Signal<ElementRef | undefined>
  private readonly searchInput = viewChild<ElementRef>('searchInput');

  // Signal query — 回傳值為 Signal<readonly ResultCardComponent[]>
  private readonly resultCards = viewChildren(ResultCardComponent);

  protected readonly resultCount = computed(() => this.resultCards().length);

  protected focusInput(): void {
    this.searchInput()?.nativeElement.focus();
  }
}
```

### effect()

```typescript
// 僅用於必要的副作用
constructor() {
  effect(() => {
    // 同步到 localStorage
    localStorage.setItem('theme', this.theme());
  });
}
```

注意：Angular 官方建議「你很少需要 `effect()`」。優先使用 `computed()`。

### resource() 和 rxResource()

用於根據 signal 變化自動載入非同步資料。

```typescript
// 使用 fetch API
readonly userId = input.required<string>();
readonly userData = resource({
  request: () => this.userId(),
  loader: ({ request: id }) => fetch(`/api/users/${id}`).then(r => r.json()),
});

// 使用 RxJS（推薦搭配 Angular HttpClient）
readonly userData = rxResource({
  request: () => this.userId(),
  loader: ({ request: id }) => this.http.get<User>(`/api/users/${id}`),
});
```

**resource() 狀態管理**：

```typescript
@Component({
  selector: 'app-user-profile',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (userData.isLoading()) {
      <app-spinner />
    } @else if (userData.error()) {
      <app-error-message [message]="errorMessage()" />
    } @else if (userData.value()) {
      <h1 data-testid="user-name">{{ userData.value()!.name }}</h1>
      <p>{{ userData.value()!.email }}</p>
    }
  `,
})
export class UserProfileComponent {
  private readonly http = inject(HttpClient);
  readonly userId = input.required<string>();

  // resource 自動追蹤 userId 變化並重新載入
  protected readonly userData = rxResource({
    request: () => this.userId(),
    loader: ({ request: id }) => this.http.get<User>(`/api/users/${id}`),
  });

  protected readonly errorMessage = computed(() => {
    const err = this.userData.error();
    return err instanceof HttpErrorResponse ? err.message : '載入失敗';
  });
}
```

## 測試指引

### 測試 signal 值變化

```typescript
it('should initialize count to zero', () => {
  expect(component['count']()).toBe(0);
});

it('should increment count when increment is called', () => {
  component.increment();
  expect(component['count']()).toBe(1);
});

it('should set items correctly', () => {
  const mockItems: Item[] = [
    { id: '1', name: 'Item A' },
    { id: '2', name: 'Item B' },
  ];
  component['items'].set(mockItems);
  expect(component['items']()).toEqual(mockItems);
});
```

### 測試 computed signal

```typescript
it('should compute doubled value from count', () => {
  component['count'].set(5);
  expect(component.doubled()).toBe(10);
});

it('should recompute when dependency changes', () => {
  component['count'].set(3);
  expect(component.doubled()).toBe(6);

  component['count'].set(7);
  expect(component.doubled()).toBe(14);
});
```

### 測試 input signal（透過 TestBed）

```typescript
it('should update display when input changes', () => {
  fixture.componentRef.setInput('userId', 'user-001');
  fixture.detectChanges();

  const el = fixture.nativeElement.querySelector('[data-testid="user-id"]');
  expect(el.textContent).toContain('user-001');
});
```

### 測試 linkedSignal

```typescript
it('should reset selectedItem when items input changes', () => {
  const items1: Item[] = [{ id: '1', name: 'A' }, { id: '2', name: 'B' }];
  fixture.componentRef.setInput('items', items1);
  fixture.detectChanges();

  // 初始選擇第一個
  expect(component.selectedItem()).toEqual(items1[0]);

  // 手動選擇第二個
  component.selectItem(items1[1]);
  expect(component.selectedItem()).toEqual(items1[1]);

  // 當 items 變化時，自動重置為新列表的第一個
  const items2: Item[] = [{ id: '3', name: 'C' }];
  fixture.componentRef.setInput('items', items2);
  fixture.detectChanges();
  expect(component.selectedItem()).toEqual(items2[0]);
});
```

### 測試 effect（透過觀察副作用結果）

```typescript
it('should sync theme to localStorage when theme changes', () => {
  const spy = vi.spyOn(Storage.prototype, 'setItem');

  component['theme'].set('dark');
  // effect 在 signal 變化後自動執行
  TestBed.flushEffects();

  expect(spy).toHaveBeenCalledWith('theme', 'dark');
});
```

### 測試 viewChild / viewChildren

```typescript
it('should focus search input when focusInput is called', () => {
  fixture.detectChanges();

  const input = fixture.nativeElement.querySelector('[data-testid="search-input"]');
  const spy = vi.spyOn(input, 'focus');

  component.focusInput();

  expect(spy).toHaveBeenCalled();
});
```

## 最佳實踐

- 使用 `computed()` 而非模板方法呼叫
- 使用 `signal()` 而非 BehaviorSubject
- 私有 signal 用 `_` 前綴 + `asReadonly()` 公開
- `effect()` 僅用於外部同步（localStorage、analytics）
- 避免在 `computed()` 中產生副作用
- `resource()` / `rxResource()` 用於根據 signal 變化自動載入非同步資料
- `linkedSignal()` 用於需要「基於來源但可獨立修改」的場景
- `viewChild()` / `viewChildren()` 取代 `@ViewChild()` / `@ViewChildren()` 裝飾器

## 檢查清單

- [ ] 使用 `signal()` 管理可變狀態
- [ ] 使用 `computed()` 處理衍生狀態，而非模板方法呼叫
- [ ] `effect()` 僅用於必要的副作用場景
- [ ] 私有 signal 搭配 `asReadonly()` 公開
- [ ] 使用 `input()` / `output()` / `model()` 而非裝飾器
- [ ] 使用 `viewChild()` / `viewChildren()` 而非 `@ViewChild()` / `@ViewChildren()`
- [ ] 非同步載入使用 `resource()` 或 `rxResource()`
- [ ] 可編輯衍生狀態使用 `linkedSignal()`
- [ ] 所有 signal 測試包含值變化與衍生驗證
- [ ] `computed()` 內無副作用

## 參考資源

- [Angular Signals Guide](https://angular.dev/guide/signals) — 官方 Signal 完整指南
- [Angular Signal Inputs](https://angular.dev/guide/signals/inputs) — Signal-based Input API
- [Angular Signal Queries](https://angular.dev/guide/signals/queries) — viewChild / viewChildren / contentChild / contentChildren
- [Angular resource() API](https://angular.dev/guide/signals/resource) — 非同步資料載入
- [Angular linkedSignal()](https://angular.dev/guide/signals/linked-signal) — 可編輯衍生狀態


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [angular-conventions](../angular-rules/references/angular-conventions.md) — Signal 強制性使用規則
- [state-management](../angular-rules/references/state-management.md) — Signal 與 NgRx Signals Store 整合
