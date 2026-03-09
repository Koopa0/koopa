---
name: angular-testing
description: >-
  Vitest + TestBed testing — TDD workflow, Signal testing patterns, component
  and service test templates, and coverage requirements.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Testing

## 觸發條件

當需要撰寫或維護測試時使用此 skill。適用場景包括：

- 建立新元件/服務的測試檔案
- 為現有程式碼補充測試
- TDD 開發流程中的紅綠重構循環
- 修復失敗的測試

## 測試框架

- **Unit / Component**: Vitest + Angular TestBed
- **E2E**: Playwright

## 程式碼模板 / 核心模式

### 測試原則

#### 應該測試

- 公開方法的行為和返回值
- Signal 狀態變化
- Computed 計算結果
- 元件的 inputs / outputs
- 使用者互動行為
- 邊界情況和錯誤處理

#### 不應該測試

- 私有方法（透過公開方法間接測試）
- 框架內部實作
- 第三方函式庫功能
- 純 UI 樣式

### 測試命名規範

所有測試案例使用 `should ... when ...` 格式命名，清楚描述預期行為與觸發條件：

```typescript
// ✅ Good — 清楚描述行為與條件
it('should display error message when login fails', () => {});
it('should disable submit button when form is invalid', () => {});
it('should emit valueChanged event when input value changes', () => {});
it('should set loading to true when data fetch starts', () => {});
it('should navigate to dashboard when login succeeds', () => {});

// ❌ Bad — 描述模糊或缺少條件
it('should work', () => {});
it('test error', () => {});
it('handles click', () => {});
```

### describe 區塊組織

```typescript
describe('{ComponentName}Component', () => {
  // setup...

  it('should create', () => {});

  describe('inputs', () => {
    it('should render title when title input is provided', () => {});
    it('should use default value when optional input is not provided', () => {});
  });

  describe('outputs', () => {
    it('should emit clicked event when action button is clicked', () => {});
  });

  describe('computed state', () => {
    it('should compute fullName when firstName and lastName are set', () => {});
  });

  describe('user interactions', () => {
    it('should toggle menu when hamburger button is clicked', () => {});
  });

  describe('error handling', () => {
    it('should display error message when API request fails', () => {});
  });
});
```

### 服務測試模板

```typescript
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

  afterEach(() => httpMock.verify());

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('loadItems', () => {
    it('should set items when request succeeds', async () => {
      const mockData = [{ id: '1', name: 'Test' }];
      const promise = service.loadItems();
      httpMock.expectOne('/api/items').flush(mockData);
      await promise;
      expect(service.items()).toEqual(mockData);
    });

    it('should set error when request fails', async () => {
      const promise = service.loadItems();
      httpMock.expectOne('/api/items').error(new ProgressEvent('error'));
      await promise;
      expect(service.error()).toBeTruthy();
    });
  });
});
```

### 元件測試模板

```typescript
describe('{ComponentName}Component', () => {
  let fixture: ComponentFixture<{ComponentName}Component>;
  let component: {ComponentName}Component;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [{ComponentName}Component],
    }).compileComponents();

    fixture = TestBed.createComponent({ComponentName}Component);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('inputs', () => {
    it('should render title when provided', () => {
      fixture.componentRef.setInput('title', 'Test Title');
      fixture.detectChanges();
      const el = fixture.nativeElement.querySelector('[data-testid="title"]');
      expect(el.textContent).toContain('Test Title');
    });
  });

  describe('outputs', () => {
    it('should emit clicked event when button clicked', () => {
      const spy = vi.fn();
      component.clicked.subscribe(spy);
      fixture.nativeElement.querySelector('[data-testid="button"]').click();
      expect(spy).toHaveBeenCalled();
    });
  });
});
```

## Signal 測試工具模式

### 測試 signal 值設定與讀取

```typescript
it('should initialize loading to false', () => {
  expect(component['loading']()).toBe(false);
});

it('should update items when setItems is called', () => {
  const mockItems: Item[] = [
    { id: '1', name: 'Item A' },
    { id: '2', name: 'Item B' },
  ];
  component.setItems(mockItems);
  expect(component.items()).toEqual(mockItems);
  expect(component.items().length).toBe(2);
});
```

### 測試 computed signal

```typescript
it('should compute itemCount from items signal', () => {
  fixture.componentRef.setInput('items', [
    { id: '1', name: 'A' },
    { id: '2', name: 'B' },
    { id: '3', name: 'C' },
  ]);
  fixture.detectChanges();

  expect(component.itemCount()).toBe(3);
});

it('should recompute activeItems when items change', () => {
  fixture.componentRef.setInput('items', [
    { id: '1', name: 'A', active: true },
    { id: '2', name: 'B', active: false },
    { id: '3', name: 'C', active: true },
  ]);
  fixture.detectChanges();

  expect(component.activeItems().length).toBe(2);
});

it('should compute fullName from firstName and lastName inputs', () => {
  fixture.componentRef.setInput('firstName', '王');
  fixture.componentRef.setInput('lastName', '大明');
  fixture.detectChanges();

  expect(component.fullName()).toBe('王 大明');
});
```

### 測試 effect 副作用

```typescript
it('should persist theme to localStorage when theme signal changes', () => {
  const spy = vi.spyOn(Storage.prototype, 'setItem');

  component['theme'].set('light');
  TestBed.flushEffects();

  expect(spy).toHaveBeenCalledWith('theme', 'light');
  spy.mockRestore();
});
```

### 測試 linkedSignal 重置行為

```typescript
it('should reset selection when source signal changes', () => {
  const list1 = [{ id: '1' }, { id: '2' }];
  fixture.componentRef.setInput('options', list1);
  fixture.detectChanges();
  expect(component.selectedOption()).toEqual(list1[0]);

  // 手動選擇
  component.selectOption(list1[1]);
  expect(component.selectedOption()).toEqual(list1[1]);

  // 來源變化 → 自動重置
  const list2 = [{ id: '3' }];
  fixture.componentRef.setInput('options', list2);
  fixture.detectChanges();
  expect(component.selectedOption()).toEqual(list2[0]);
});
```

### 測試 signal input（使用 setInput）

```typescript
it('should update view when input signal changes', () => {
  fixture.componentRef.setInput('userName', 'Alice');
  fixture.detectChanges();

  const el = fixture.nativeElement.querySelector('[data-testid="user-name"]');
  expect(el.textContent).toContain('Alice');

  // 更新 input 並驗證視圖同步
  fixture.componentRef.setInput('userName', 'Bob');
  fixture.detectChanges();

  expect(el.textContent).toContain('Bob');
});
```

## data-testid 使用指南

### 命名規範

使用 kebab-case 命名，具描述性且唯一：

```html
<!-- 靜態 data-testid -->
<h1 data-testid="page-title">{{ title() }}</h1>
<button data-testid="submit-button" (click)="submit()">送出</button>
<div data-testid="loading-spinner">載入中...</div>
<p data-testid="error-message">{{ errorMessage() }}</p>

<!-- 動態 data-testid（用於列表項目） -->
@for (item of items(); track item.id) {
  <div [attr.data-testid]="'item-' + item.id">
    <span [attr.data-testid]="'item-name-' + item.id">{{ item.name }}</span>
    <button [attr.data-testid]="'delete-item-' + item.id" (click)="deleteItem(item.id)">
      刪除
    </button>
  </div>
}
```

### 測試中選取元素

```typescript
// 選取單一元素
const title = fixture.nativeElement.querySelector('[data-testid="page-title"]');
const button = fixture.nativeElement.querySelector('[data-testid="submit-button"]');

// 選取動態元素
const item = fixture.nativeElement.querySelector('[data-testid="item-123"]');

// 選取所有匹配的元素（前綴匹配）
const allItems = fixture.nativeElement.querySelectorAll('[data-testid^="item-"]');

// 確認元素存在/不存在
expect(fixture.nativeElement.querySelector('[data-testid="error-message"]')).toBeNull();
expect(fixture.nativeElement.querySelector('[data-testid="page-title"]')).toBeTruthy();
```

### E2E 測試中的 data-testid（Playwright）

```typescript
// Playwright 中使用 data-testid
await page.getByTestId('submit-button').click();
await expect(page.getByTestId('page-title')).toHaveText('儀表板');
await expect(page.getByTestId('error-message')).not.toBeVisible();
```

## 禁止模式

- 空測試（沒有 `expect`）
- 測試私有方法
- 使用 `any` 繞過型別
- 使用隨機資料（用確定性資料）
- `fdescribe` / `fit` / `xdescribe`
- 靜默通過

## 覆蓋率目標

| 指標 | 目標 |
|------|------|
| Statements | >= 80% |
| Branches | >= 80% |
| Functions | >= 80% |
| Lines | >= 80% |

## 檢查清單

- [ ] 每個 `it` 至少有一個 `expect` 斷言
- [ ] 測試命名遵循 `should ... when ...` 格式
- [ ] 使用 `data-testid` 選取 DOM 元素
- [ ] 使用 `fixture.componentRef.setInput()` 設定 signal inputs
- [ ] Signal 狀態變化有對應的斷言
- [ ] Computed signal 的衍生邏輯有驗證
- [ ] 錯誤處理路徑有覆蓋
- [ ] 使用確定性測試資料（禁止 faker/隨機生成）
- [ ] 無 `fdescribe` / `fit` / `xdescribe` 殘留
- [ ] 覆蓋率 >= 80%（Statements / Branches / Functions / Lines）

## 參考資源

- [Angular Testing Guide](https://angular.dev/guide/testing) — 官方測試完整指南
- [Angular TestBed API](https://angular.dev/api/core/testing/TestBed) — TestBed API 參考
- [Vitest Documentation](https://vitest.dev/) — Vitest 測試框架文件
- [Playwright Documentation](https://playwright.dev/) — Playwright E2E 測試文件
- [Angular Testing Library](https://testing-library.com/docs/angular-testing-library/intro/) — 以使用者行為為中心的測試工具


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [testing](../angular-rules/references/testing.md) — TDD 工作流、命名規範與覆蓋率要求
- [coding-style](../angular-rules/references/coding-style.md) — 測試檔案位置與命名
