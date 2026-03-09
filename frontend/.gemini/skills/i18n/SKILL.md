---
name: i18n
description: >-
  Multi-language support setup — Angular i18n or Transloco, translation file
  extraction, locale-aware formatting, and zh-TW default.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Internationalization (i18n)

## 觸發條件

當使用者要求以下任務時啟用此技能：

- 設定或修改應用程式的多語言支援
- 標記需要翻譯的文字（`i18n` 屬性）
- 提取翻譯檔案（`ng extract-i18n`）
- 處理複數、性別、ICU 表達式
- 格式化日期、數字、貨幣的本地化
- 常數化 UI 字串
- 測試翻譯內容的正確性

## Angular i18n

### 標記翻譯文字

```html
<!-- 靜態文字 -->
<h1 i18n="@@pageTitle">Dashboard</h1>

<!-- 帶描述 -->
<p i18n="user greeting|A welcome message for the user@@greeting">
  Welcome, {{ user.name }}
</p>

<!-- 屬性翻譯 -->
<img [src]="logo" i18n-alt="@@logoAlt" alt="Company Logo">

<!-- 複數 -->
<span i18n="@@itemCount">
  {count, plural,
    =0 {No items}
    =1 {One item}
    other {{{count}} items}
  }
</span>
```

### 提取翻譯

```bash
ng extract-i18n --output-path src/locale
```

### 配置多語言

```typescript
// angular.json
{
  "projects": {
    "app": {
      "i18n": {
        "sourceLocale": "zh-TW",
        "locales": {
          "en": "src/locale/messages.en.xlf"
        }
      }
    }
  }
}
```

## 語言使用規範

| 位置 | 語言 |
|------|------|
| UI 文字 | 繁體中文（zh-TW） |
| 變數/函數/類別名稱 | 英文 |
| 註解 | 繁體中文或英文 |
| Git commit | 英文 |
| 文件 | 繁體中文 |

## 常數化字串

```typescript
// 禁止硬編碼
// ❌ Bad
const message = '操作成功';

// ✅ Good
const MESSAGES = {
  SUCCESS: '操作成功',
  ERROR: '操作失敗',
  LOADING: '載入中...',
} as const;
```

## 日期格式

```typescript
// 使用 ISO 8601
const date = '2026-01-28T10:30:00+08:00';

// Angular DatePipe
{{ date | date:'yyyy/MM/dd HH:mm' }}

// 使用 locale
{{ date | date:'mediumDate':'':'zh-TW' }}
```

## 程式碼模板

### 訊息常數檔案結構

```typescript
// shared/constants/messages.constants.ts

/** 通用操作訊息 */
export const COMMON_MESSAGES = {
  SAVE_SUCCESS: '儲存成功',
  SAVE_ERROR: '儲存失敗，請稍後再試',
  DELETE_SUCCESS: '刪除成功',
  DELETE_CONFIRM: '確定要刪除嗎？此操作無法復原。',
  LOADING: '載入中...',
  NO_DATA: '目前沒有資料',
  NETWORK_ERROR: '網路連線異常，請檢查網路狀態',
} as const;

/** 表單驗證訊息 */
export const VALIDATION_MESSAGES = {
  REQUIRED: '此欄位為必填',
  EMAIL_INVALID: '請輸入有效的 Email 地址',
  MIN_LENGTH: (min: number) => `最少需要 ${min} 個字元`,
  MAX_LENGTH: (max: number) => `最多允許 ${max} 個字元`,
  PASSWORD_MISMATCH: '密碼不一致',
  PHONE_INVALID: '請輸入有效的電話號碼',
} as const;

/** 認證相關訊息 */
export const AUTH_MESSAGES = {
  LOGIN_SUCCESS: '登入成功',
  LOGIN_FAILED: '帳號或密碼錯誤',
  LOGOUT_SUCCESS: '已成功登出',
  SESSION_EXPIRED: '登入階段已過期，請重新登入',
  UNAUTHORIZED: '您沒有權限執行此操作',
} as const;
```

### ICU 複數與選擇表達式

```html
<!-- 複數表達式 -->
<p i18n="@@vehicleCount">
  {vehicleCount, plural,
    =0 {目前沒有車輛}
    =1 {共 1 輛車}
    other {共 {{vehicleCount}} 輛車}
  }
</p>

<!-- 選擇表達式（性別等） -->
<p i18n="@@userGreeting">
  {gender, select,
    male {先生您好}
    female {女士您好}
    other {您好}
  }
</p>

<!-- 巢狀 ICU 表達式 -->
<p i18n="@@orderSummary">
  {orderCount, plural,
    =0 {您沒有待處理的訂單}
    =1 {您有 1 筆 {status, select,
      pending {待處理}
      processing {處理中}
      other {未知狀態}
    } 的訂單}
    other {您有 {{orderCount}} 筆訂單}
  }
</p>
```

### 本地化數字與貨幣

```typescript
@Component({
  selector: 'app-price-display',
  standalone: true,
  imports: [CurrencyPipe, DecimalPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <!-- 貨幣格式（新台幣） -->
    <span data-testid="price">{{ price() | currency:'TWD':'symbol':'1.0-0':'zh-TW' }}</span>

    <!-- 數字格式 -->
    <span data-testid="count">{{ count() | number:'1.0-0':'zh-TW' }}</span>

    <!-- 百分比 -->
    <span data-testid="rate">{{ rate() | percent:'1.1-1':'zh-TW' }}</span>
  `,
})
export class PriceDisplayComponent {
  readonly price = input.required<number>();
  readonly count = input<number>(0);
  readonly rate = input<number>(0);
}
```

## 測試指引

### 翻譯內容測試

```typescript
// price-display.component.spec.ts
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { LOCALE_ID } from '@angular/core';
import { registerLocaleData } from '@angular/common';
import localeZhTW from '@angular/common/locales/zh-Hant';
import { PriceDisplayComponent } from './price-display.component';

describe('PriceDisplayComponent', () => {
  let fixture: ComponentFixture<PriceDisplayComponent>;

  beforeAll(() => {
    registerLocaleData(localeZhTW);
  });

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PriceDisplayComponent],
      providers: [
        { provide: LOCALE_ID, useValue: 'zh-TW' },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(PriceDisplayComponent);
  });

  it('should format currency in TWD', () => {
    fixture.componentRef.setInput('price', 1500);
    fixture.detectChanges();

    const priceElement = fixture.nativeElement.querySelector(
      '[data-testid="price"]',
    );
    // 確認顯示新台幣符號與數字格式
    expect(priceElement.textContent).toContain('$');
    expect(priceElement.textContent).toContain('1,500');
  });

  it('should format large numbers with comma separator', () => {
    fixture.componentRef.setInput('count', 1234567);
    fixture.detectChanges();

    const countElement = fixture.nativeElement.querySelector(
      '[data-testid="count"]',
    );
    expect(countElement.textContent).toContain('1,234,567');
  });
});
```

### 常數化字串測試

```typescript
// messages.constants.spec.ts
import { COMMON_MESSAGES, VALIDATION_MESSAGES, AUTH_MESSAGES } from './messages.constants';

describe('Message Constants', () => {
  describe('COMMON_MESSAGES', () => {
    it('should have all required keys defined', () => {
      expect(COMMON_MESSAGES.SAVE_SUCCESS).toBeTruthy();
      expect(COMMON_MESSAGES.SAVE_ERROR).toBeTruthy();
      expect(COMMON_MESSAGES.DELETE_SUCCESS).toBeTruthy();
      expect(COMMON_MESSAGES.LOADING).toBeTruthy();
      expect(COMMON_MESSAGES.NO_DATA).toBeTruthy();
      expect(COMMON_MESSAGES.NETWORK_ERROR).toBeTruthy();
    });
  });

  describe('VALIDATION_MESSAGES', () => {
    it('should generate min length message with parameter', () => {
      const message = VALIDATION_MESSAGES.MIN_LENGTH(8);
      expect(message).toContain('8');
    });

    it('should generate max length message with parameter', () => {
      const message = VALIDATION_MESSAGES.MAX_LENGTH(100);
      expect(message).toContain('100');
    });
  });

  describe('AUTH_MESSAGES', () => {
    it('should have all authentication messages defined', () => {
      expect(AUTH_MESSAGES.LOGIN_SUCCESS).toBeTruthy();
      expect(AUTH_MESSAGES.LOGIN_FAILED).toBeTruthy();
      expect(AUTH_MESSAGES.SESSION_EXPIRED).toBeTruthy();
    });
  });
});
```

### i18n 屬性覆蓋測試

```typescript
// component-i18n.spec.ts
import { ComponentFixture, TestBed } from '@angular/core/testing';

describe('Component i18n Coverage', () => {
  /**
   * 驗證元件模板中所有使用者可見的文字都已標記 i18n
   * 或使用常數化字串
   */
  it('should not contain hardcoded Chinese text in template', () => {
    const fixture = TestBed.createComponent(TargetComponent);
    fixture.detectChanges();

    const html = fixture.nativeElement.innerHTML;

    // 確認不存在未經常數化的硬編碼中文
    // 注意：此規則僅適用於不使用 i18n 標記的情況
    // 如果使用 Angular i18n，文字會在編譯時被替換
  });

  it('should display correct text from message constants', () => {
    const fixture = TestBed.createComponent(TargetComponent);
    fixture.detectChanges();

    const loadingElement = fixture.nativeElement.querySelector(
      '[data-testid="loading-text"]',
    );
    expect(loadingElement?.textContent?.trim()).toBe(COMMON_MESSAGES.LOADING);
  });
});
```

## 檢查清單

- [ ] UI 文字使用繁體中文（zh-TW）
- [ ] 所有使用者可見的字串已常數化或標記 `i18n`
- [ ] 禁止在元件中硬編碼字串（使用 `MESSAGES` 常數或 `i18n`）
- [ ] 日期格式統一使用 ISO 8601
- [ ] 貨幣格式使用 `CurrencyPipe` 搭配正確的 locale
- [ ] 數字格式使用 `DecimalPipe` 搭配正確的 locale
- [ ] 複數表達式使用 ICU 語法
- [ ] 翻譯 ID（`@@`）命名有意義且唯一
- [ ] `angular.json` 中 `sourceLocale` 設為 `zh-TW`
- [ ] 訊息常數檔案使用 `as const` 確保型別安全
- [ ] 動態訊息使用函式（如 `MIN_LENGTH(8)`）而非模板字串硬編碼
- [ ] 翻譯內容有對應的單元測試
- [ ] `img` 的 `alt` 屬性有 `i18n-alt` 標記

## 參考資源

- [Angular i18n 指南](https://angular.dev/guide/i18n)
- [Angular DatePipe](https://angular.dev/api/common/DatePipe)
- [Angular CurrencyPipe](https://angular.dev/api/common/CurrencyPipe)
- [Angular DecimalPipe](https://angular.dev/api/common/DecimalPipe)
- [ICU 訊息格式](https://unicode-org.github.io/icu/userguide/format_parse/messages/)
- [CLDR — Unicode 語言資料](https://cldr.unicode.org/)


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [coding-style](../angular-rules/references/coding-style.md) — 語言規範（zh-TW UI、英文變數）
- [angular-conventions](../angular-rules/references/angular-conventions.md) — 禁止硬編碼字串
