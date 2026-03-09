---
paths:
  - "src/**/*.html"
  - "src/**/*.css"
  - "src/**/*.scss"
  - "src/**/*.component.ts"
---

# Tailwind CSS 設計模式

> 完整設計資源和元件轉換流程見 `tailwind-styling` skill。

## 基本規則

- 所有樣式使用 Tailwind 類別，禁止 inline styles
- 預設深色主題，使用 `dark:` 前綴支援切換
- Mobile-First 響應式：`sm:640` / `md:768` / `lg:1024` / `xl:1280` / `2xl:1536`

## Tailwind CSS v4 必須遵守的變更

| v3（禁止） | v4（必須使用） |
|-----------|--------------|
| `bg-opacity-*` | `bg-black/50` |
| `bg-gradient-*` | `bg-linear-*` |
| `shadow-sm` | `shadow-xs` |
| `shadow` | `shadow-sm` |
| `rounded-sm` | `rounded-xs` |
| `rounded` | `rounded-sm` |
| `outline-none` | `outline-hidden` |
| `ring` | `ring-3` |
| `space-x-*` / `space-y-*` | `gap-*`（flex/grid 中） |
| `@apply` | CSS variables / `--spacing()` |
| `min-h-screen` | `min-h-dvh` |

## 色彩系統

| 用途 | 色彩 |
|------|------|
| 中性色 | `zinc` |
| 品牌主色 | `primary` |
| 成功 | `emerald` |
| 警告 | `amber` |
| 錯誤 | `red` |
| 資訊 | `sky` |

## 間距刻度

推薦：1(4px), 2(8px), 3(12px), 4(16px), 6(24px), 8(32px), 12(48px), 16(64px)

## WCAG AA 對比度

一般文字 4.5:1，大型文字 3:1。

## 設計參考資源

- **Catalyst UI Kit**: `tailwind/css/catalyst-ui-kit/` — 27 個 React 參考元件
- **UI Blocks**: `tailwind/css/ui-blocks/` — 200+ HTML 頁面區塊
- **v4 完整規則**: `tailwind/css/rules/tailwind.md`

轉換流程：讀取 Catalyst `.tsx` -> 提取 HTML + Tailwind classes -> Angular standalone component -> 檢查 v4 語法。
