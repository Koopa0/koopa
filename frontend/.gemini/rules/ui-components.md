# UI 元件庫策略

## 三層架構

| 層級 | 來源 | 原則 |
|------|------|------|
| 基礎 UI | Catalyst 自建 + Angular CDK | 完全控制視覺與行為 |
| 複雜資料 | PrimeNG Unstyled（最多 6 個） | 僅自建成本過高時引入 |
| 底層能力 | Angular CDK | 無 UI 的行為層（Overlay, A11y, Scrolling, DragDrop） |
| 佈局 | Catalyst + UI Blocks | SidebarLayout, StackedLayout, AuthLayout |

## 決策樹（每次需要 UI 元件必須依序檢查）

1. **已存在？** `ls src/app/shared/components/` 或查 `component-catalog` skill → 直接使用，禁止重建
2. **可組合？** 用現有元件組合（Card + Table + Pagination）→ 組合使用
3. **Catalyst 有參考？** `ls tailwind/css/catalyst-ui-kit/typescript/` → 提取 HTML + Tailwind → Angular component
4. **需 CDK 行為？** overlay/focus trap/virtual scroll → CDK 輔助自建
5. **自建成本過高？** 複雜鍵盤互動 + a11y / 大量資料 + 虛擬捲動 / 複雜狀態機 → PrimeNG Unstyled（需團隊討論）
6. **UI Blocks 有參考？** `ls tailwind/css/ui-blocks/` → 提取 HTML → Angular component
7. 從零自建

## PrimeNG 規則

- 整個專案**最多 6 個**，每個需自建替代評估
- 必須 Unstyled mode，禁止 PrimeNG 主題 CSS
- 已引入：*(尚無)*

## CDK 匯入

具體路徑匯入（`@angular/cdk/overlay`），禁止匯入整個 CDK。

## 佈局選擇

| 場景 | 佈局 |
|------|------|
| 管理後台 | SidebarLayout（`core/layout/sidebar-layout/`） |
| 簡單應用 | StackedLayout（`core/layout/stacked-layout/`） |
| 認證流程 | AuthLayout（`core/layout/auth-layout/`） |
| 獨立頁面 | 無佈局 |

## 頁面組合模式

- **列表頁**：Heading + Button → Table → Pagination
- **詳情頁**：Breadcrumbs → Heading + Dropdown → DescriptionList
- **表單頁**：Heading → Fieldset > Field > Input/Select → Button
- **認證頁**：AuthLayout → Heading → Fieldset > Input → Button

## 禁止重複造輪子

建立頁面前**必須**先查 `component-catalog` skill。現有元件不完全符合需求→**優先擴展** API，非建新元件。新元件必須加入目錄、撰寫測試、支援深淺模式。

禁止使用 Angular Material（視覺風格衝突、bundle 大小、樣式覆蓋困難）。Angular CDK 可以使用。
