---
name: tdd
description: >-
  Strict test-driven development cycle. Enforces RED (write failing test) → GREEN
  (minimal code to pass) → REFACTOR (cleanup + lint gate). Trigger when user says
  "tdd", "test first", "red green refactor", or requests test-first development.
metadata:
  author: koopa
  version: "1.0"
  lang: angular
---

# TDD — 嚴格測試驅動開發

## 身份

你正在執行嚴格的 RED-GREEN-REFACTOR 循環。你不會在測試之前寫實作程式碼。你不會跳過任何階段。每個循環只產出一個可測試的行為。

---

## 循環

### Phase 1: RED — 寫失敗的測試

1. **撰寫測試** 在 `*.spec.ts` 中
   - 使用 `describe` / `it` 結構
   - 使用 Vitest 斷言（`expect`）
   - Component 測試使用 `TestBed`
   - Signal 測試直接測試 signal 值變化
   - 加入 `data-testid` 屬性用於 E2E

2. **執行測試** — 必須失敗：
   ```bash
   npx vitest run --reporter=verbose src/app/features/<feature>/<file>.spec.ts
   ```

3. **驗證失敗正確**：
   - 編譯錯誤（函式不存在）→ 正確
   - 測試執行但斷言失敗 → 正確
   - 測試通過 → 錯誤！測試沒有在測新行為，重寫

**RED 階段硬規則**：
- 一次只寫一個測試案例
- 測試必須表達期望行為，不是當前實作
- Component 測試使用 `TestBed.configureTestingModule`
- Service 測試可直接 `new` 或用 `TestBed`

### Phase 2: GREEN — 最少實作

1. **寫最少程式碼** 讓測試通過
   - 不優化、不清理、不處理測試以外的邊界條件
   - Signal 狀態用 `signal()`，衍生用 `computed()`
   - 遵守 OnPush + Standalone + inject()

2. **執行測試** — 必須通過：
   ```bash
   npx vitest run --reporter=verbose src/app/features/<feature>/<file>.spec.ts
   ```

3. **測試仍失敗**：修實作，不修測試

**GREEN 階段硬規則**：
- 不寫超過測試要求的程式碼
- 不加功能、helper、抽象層
- 不優化——醜陋但能跑的程式碼在此階段是正確的

### Phase 3: REFACTOR — 清理

1. **重構實作** 提升清晰度和規範合規：
   - 提取重複
   - 修正命名（kebab-case 檔案、PascalCase 類別、camelCase 變數）
   - Signal 類型決策：`signal()` vs `linkedSignal()` vs `resource()`
   - 加入 JSDoc 註解
   - 確認 `readonly` 在 input/output/inject 上

2. **執行完整 lint gate** — 全部必須通過：
   ```bash
   npx tsc --noEmit && npx ng lint
   ```

3. **再次執行測試** — 必須仍然通過：
   ```bash
   npx vitest run src/app/features/<feature>/
   ```

**REFACTOR 階段硬規則**：
- 不改變行為——只改結構和清晰度
- 不加新功能（那需要新的 RED 階段）
- 不跳過 lint gate

---

## 測試模式參考

### Component 測試（Signal-based）

```typescript
describe('UserCardComponent', () => {
  it('should display user name from input signal', async () => {
    const fixture = TestBed.createComponent(UserCardComponent);
    const component = fixture.componentInstance;

    // 設定 input signal
    fixture.componentRef.setInput('user', { name: 'Alice', email: 'a@b.c' });
    fixture.detectChanges();

    const el = fixture.nativeElement.querySelector('[data-testid="user-name"]');
    expect(el.textContent).toContain('Alice');
  });
});
```

### Service 測試

```typescript
describe('UserService', () => {
  it('should fetch user by id', async () => {
    const httpMock = TestBed.inject(HttpTestingController);
    const service = TestBed.inject(UserService);

    const user$ = service.getUser('123');
    const req = httpMock.expectOne('/api/users/123');
    req.flush({ id: '123', name: 'Alice' });

    // 驗證 signal 狀態
    expect(service.currentUser()).toEqual({ id: '123', name: 'Alice' });
  });
});
```

### Signal 單元測試

```typescript
describe('computed total', () => {
  it('should compute total from items signal', () => {
    const items = signal([
      { price: 100, qty: 2 },
      { price: 50, qty: 1 },
    ]);
    const total = computed(() => items().reduce((sum, i) => sum + i.price * i.qty, 0));

    expect(total()).toBe(250);

    items.update(prev => [...prev, { price: 30, qty: 3 }]);
    expect(total()).toBe(340);
  });
});
```

---

## 與開發生命週期整合

TDD 是 Phase 3（實作）中的**方法論選擇**：

- **Tier 1**：TDD 可選（修復太簡單不需要）
- **Tier 2**：TDD 建議（避免既有功能回歸）
- **Tier 3**：TDD 強烈建議（新功能最受益於測試先行）

TDD 不取代：
- comprehend / planner（Tier 3 仍需先執行）
- `/angular-verify`（所有循環完成後仍需執行）
- 審查 agents（驗證後仍需執行）

---

## 反模式（絕對不做）

| 反模式 | 為何錯誤 |
|--------|---------|
| 先寫實作再寫測試 | 測試可能被實作 bug 影響 |
| 一次寫所有測試再實作 | 失去 RED-GREEN 回饋循環 |
| 測試第一次就通過 | 沒在測新行為 |
| 跳過 REFACTOR | 累積技術債、lint 問題複合 |
| 一個循環多個行為 | 失去粒度，難以診斷失敗 |
