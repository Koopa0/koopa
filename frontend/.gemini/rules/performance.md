---
paths:
  - "src/app/**/*.component.ts"
  - "src/app/**/*.component.html"
  - "src/app/**/*.routes.ts"
  - "angular.json"
---

# 效能規範

> 完整程式碼範例見 `performance` skill。

## 核心原則

1. **量測優先**：不要猜測，用數據證明效能問題
2. **漸進式優化**：先讓它運作，再讓它快
3. **使用者體驗**：關注感知效能，而非單純的數字

## 必須項目

| 項目 | 要求 |
|------|------|
| 變更偵測 | 所有元件 `ChangeDetectionStrategy.OnPush` |
| 路由載入 | 所有功能模組 `loadComponent` / `loadChildren` |
| 非首屏內容 | 使用 `@defer` 延遲載入 |
| 長列表（>50 筆） | CDK Virtual Scrolling |
| 圖片 | `NgOptimizedImage`（LCP 圖片加 `priority`） |
| 匯入 | 具體路徑匯入（tree-shaking 友善） |

## Bundle 預算

| 指標 | Warning | Error | 最佳 |
|------|---------|-------|------|
| 初始載入（JS+CSS） | 500KB | 1MB | <300KB |
| 元件樣式 | 4KB | 8KB | <2KB |

## Web Vitals 目標

| 指標 | Good | Poor |
|------|------|------|
| LCP | <2.5s | >4.0s |
| INP | <200ms | >500ms |
| CLS | <0.1 | >0.25 |

## @defer 觸發條件

| 條件 | 適用場景 |
|------|---------|
| `on viewport` | 折疊內容、長列表底部 |
| `on idle` | 次要功能、分析工具 |
| `on interaction` | 展開面板、彈出視窗 |
| `on timer(Xms)` | 非關鍵內容 |
| `when condition` | 動態內容 |

## SSR RenderMode 選擇

| 條件 | 選擇 |
|------|------|
| 公開 + SEO 重要 | `Server` |
| 需認證 + 高互動 | `Client` |
| 靜態 + 不常變動 | `Prerender` |
| 使用 CDK Overlay | `Client` |

## HTTP 快取策略

| 資料類型 | TTL | 策略 |
|---------|-----|------|
| 靜態參考（國家、類別） | 24hr | 積極快取 |
| 使用者資料 | 5min | 適度快取 |
| 即時資料（通知） | 不快取 | 跳過 |

## 禁止

- 禁止 `import * as _ from 'lodash'`（用 `lodash-es/debounce`）
- 禁止 `import * as moment from 'moment'`（用 `date-fns`）
- 禁止匯入整個 CDK（用具體路徑 `@angular/cdk/overlay`）
- 禁止 Default 變更偵測策略

## 檢查清單

- [ ] 所有元件 OnPush
- [ ] 所有路由延遲載入
- [ ] 非首屏 `@defer`
- [ ] 列表 >50 筆 Virtual Scrolling
- [ ] 圖片 `NgOptimizedImage`
- [ ] Bundle <500KB warning
- [ ] LCP <2.5s, INP <200ms, CLS <0.1
- [ ] Lighthouse 90+
