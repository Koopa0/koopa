---
name: page-layout
description: >-
  Application layout selection — SidebarLayout, StackedLayout, and AuthLayout
  usage with existing page examples as reference.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Page Layout

## 觸發條件

- 建立新頁面時需要選擇佈局
- 設計頁面結構與內容區域時
- 需要響應式佈局處理時
- 使用 UI Blocks 作為頁面參考時

---

## ⭐ 現有頁面範例（建議先參考）

建立新頁面前，**先查看這些現有範例**的結構和模式：

| 範例 | 路徑 | 佈局 | 特點 |
|------|------|------|------|
| **Login** | `src/app/features/login/` | AuthLayout | 表單驗證、錯誤處理 |
| **Dashboard** | `src/app/features/dashboard/` | SidebarLayout | 卡片組合、統計展示 |
| **Settings** | `src/app/features/settings/` | SidebarLayout | Tabs 分頁、表單 |
| **Showcase** | `src/app/features/showcase/` | SidebarLayout | 元件展示、響應式 |

```bash
# 查看 Login 頁面結構
cat src/app/features/login/login.component.ts
cat src/app/features/login/login.component.html

# 查看 Settings 頁面結構
cat src/app/features/settings/settings.component.ts
```

---

## 佈局選擇指引

### 決策樹

```
建立新頁面？
│
├── 需要認證嗎？（Login / Register / Forgot Password）
│   └── 是 → AuthLayout
│
├── 需要持久的側邊導航嗎？（後台管理、多功能應用）
│   └── 是 → SidebarLayout（透過 AppShell）
│
├── 頂部導航就足夠嗎？（簡單應用、行銷頁面）
│   └── 是 → StackedLayout
│
└── 不需要佈局？（獨立頁面、錯誤頁面）
    └── 使用獨立元件（如 NotFound）
```

### 三種佈局比較

| 特性 | SidebarLayout | StackedLayout | AuthLayout |
|------|--------------|---------------|------------|
| 固定側邊欄 | ✅（桌面 w-64） | ❌ | ❌ |
| 頂部導航列 | ✅ | ✅ | ❌ |
| 行動版漢堡選單 | ✅ | ✅ | ❌ |
| 內容置中 | ❌（max-w-6xl） | ❌（max-w-6xl） | ✅（flex 居中） |
| 適用場景 | 管理後台 | 簡單應用 | 認證流程 |
| 路由模式 | 子路由 | 子路由 | 獨立路由 |

---

## SidebarLayout 使用指引

### 結構

桌面版：左側固定側邊欄（w-64）+ 右側主要內容區域
行動版：側邊欄隱藏，顯示漢堡按鈕，點擊展開抽屜式側邊欄

### 四個插槽

| 插槽屬性 | 用途 | 必要 |
|----------|------|------|
| `sidebar` | 桌面版固定側邊欄（`max-lg:hidden`） | ✅ |
| `mobileSidebar` | 行動版抽屜式側邊欄 | ✅ |
| `navbar` | 頂部導航列（桌面偏移 `lg:pl-64`） | ✅ |
| `main` | 主要內容區域（`max-w-6xl` 居中） | ✅ |

### 典型路由結構

```typescript
// app.routes.ts
export const routes: Routes = [
  {
    path: '',
    component: AppShellComponent,  // 包裝 SidebarLayout
    canActivate: [authGuard],
    children: [
      {
        path: 'dashboard',
        loadComponent: () => import('./features/dashboard/dashboard.component')
          .then(m => m.DashboardComponent),
      },
      {
        path: 'settings',
        loadComponent: () => import('./features/settings/settings.component')
          .then(m => m.SettingsComponent),
      },
    ],
  },
];
```

### 內容區域寬度

主內容區已包含 `max-w-6xl`（1152px）限制。頁面元件不需再設寬度限制。

---

## StackedLayout 使用指引

### 結構

無固定側邊欄。頂部導航列 + 主要內容區域。
行動版：顯示漢堡按鈕，點擊展開 overlay 側邊欄。

### 三個插槽

| 插槽屬性 | 用途 | 必要 |
|----------|------|------|
| `mobileSidebar` | 行動版 overlay 側邊欄 | 建議 |
| `navbar` | 頂部導航列 | ✅ |
| `main` | 主要內容區域（`max-w-6xl` 居中） | ✅ |

### 適用場景

- 導航項目少（< 5 個），頂部導航列就足夠
- 不需要多層級導航的應用
- 內容導向的頁面（部落格、文件閱讀器）

### 與 SidebarLayout 的差異

- 主內容區使用 `lg:px-2`（兩側留白），非 `lg:pl-64`（左側偏移）
- 桌面版沒有固定側邊欄 DOM
- 更寬的可用內容空間

---

## AuthLayout 使用指引

### 結構

全螢幕置中卡片。`min-h-dvh` + flex 居中。
桌面版：內容區域有 `lg:rounded-lg`、`lg:shadow-xs`、`lg:ring-1` 卡片效果。

### 單一插槽

直接投影內容（無需屬性選擇器）。

```html
<app-auth-layout>
  <div class="w-full max-w-sm">
    <!-- 登入表單 -->
  </div>
</app-auth-layout>
```

### 典型路由結構

```typescript
export const routes: Routes = [
  {
    path: 'login',
    component: AuthLayoutComponent,  // 或包裝在 AuthShell 中
    children: [
      {
        path: '',
        loadComponent: () => import('./features/auth/login/login.component')
          .then(m => m.LoginComponent),
      },
    ],
  },
];
```

### 內容寬度建議

| 頁面類型 | 建議寬度 |
|----------|---------|
| Login | `max-w-sm`（384px） |
| Register | `max-w-md`（448px） |
| Forgot Password | `max-w-sm` |
| Email Verification | `max-w-sm` |

---

## 響應式斷點處理

### Tailwind CSS 斷點

| 斷點 | 寬度 | 用途 |
|------|------|------|
| `sm:` | 640px | 小型手機以上 |
| `md:` | 768px | 平板以上 |
| `lg:` | 1024px | 桌面以上（佈局切換點） |
| `xl:` | 1280px | 大螢幕 |
| `2xl:` | 1536px | 超大螢幕 |

### 關鍵佈局切換（lg: = 1024px）

- **SidebarLayout**：`lg:` 以下側邊欄隱藏，顯示漢堡按鈕
- **StackedLayout**：`lg:` 以下漢堡按鈕出現
- 所有佈局的主內容卡片效果（`lg:rounded-lg lg:shadow-xs`）在 `lg:` 以下消失

### 頁面內容響應式模式

```html
<!-- 兩欄佈局：行動版堆疊，桌面版並排 -->
<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
  <app-card>左側內容</app-card>
  <app-card>右側內容</app-card>
</div>

<!-- 三欄統計：行動版堆疊，平板兩欄，桌面三欄 -->
<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
  <app-card>統計 1</app-card>
  <app-card>統計 2</app-card>
  <app-card>統計 3</app-card>
</div>
```

---

## 頁面內容區域結構

### 標準頁面頭部

```html
<!-- 頁面標題 + 操作按鈕 -->
<div class="flex items-center justify-between">
  <app-heading [level]="1">頁面標題</app-heading>
  <app-button variant="solid" color="primary">
    新增
  </app-button>
</div>
```

### 帶麵包屑的頁面頭部

```html
<app-breadcrumbs [items]="breadcrumbs()" />
<div class="mt-4 flex items-center justify-between">
  <app-heading [level]="1">詳情頁</app-heading>
  <app-dropdown>
    <app-button variant="outline">操作</app-button>
    <app-dropdown-menu>
      <app-dropdown-item>編輯</app-dropdown-item>
      <app-dropdown-item>刪除</app-dropdown-item>
    </app-dropdown-menu>
  </app-dropdown>
</div>
```

### 帶頁籤的頁面

```html
<app-heading [level]="1">設定</app-heading>
<div class="mt-6">
  <app-tabs [tabs]="settingTabs()" [(selectedIndex)]="activeTab()" />
</div>
<div class="mt-6">
  @switch (activeTab()) {
    @case (0) { <app-profile-settings /> }
    @case (1) { <app-preference-settings /> }
    @case (2) { <app-security-settings /> }
  }
</div>
```

---

## UI Blocks 參考路徑

建立頁面時，可參考 UI Blocks 的 HTML 範例取得設計靈感：

| 頁面類型 | 參考路徑 |
|----------|---------|
| 應用外殼 | `tailwind/css/ui-blocks/application-ui/application-shells/` |
| 列表頁 | `tailwind/css/ui-blocks/application-ui/lists/` |
| 詳情頁 | `tailwind/css/ui-blocks/application-ui/data-display/` |
| 表單頁 | `tailwind/css/ui-blocks/application-ui/forms/` |
| 設定頁 | `tailwind/css/ui-blocks/application-ui/page-examples/settings-screens/` |
| 導航 | `tailwind/css/ui-blocks/application-ui/navigation/` |
| 對話框 | `tailwind/css/ui-blocks/application-ui/overlays/` |
| 錯誤頁 | `tailwind/css/ui-blocks/marketing/feedback/` |
| 登入頁 | `tailwind/css/ui-blocks/application-ui/forms/sign-in-and-registration/` |

### 使用工作流程

1. 確認頁面類型，選擇對應的 UI Blocks 參考
2. 讀取 HTML 檔案，提取 Tailwind classes 和結構
3. 使用現有元件目錄中的元件組合頁面
4. 根據響應式斷點調整佈局
5. 確認深淺模式支援

---

## 深淺模式

所有佈局元件已內建深淺模式支援：

| 模式 | 背景色 |
|------|--------|
| 淺色（桌面） | `bg-zinc-100`（外層）/ `bg-white`（內容卡片） |
| 深色（桌面） | `bg-zinc-950`（外層）/ `bg-zinc-900`（內容卡片） |
| 淺色（行動） | `bg-white` |
| 深色（行動） | `bg-zinc-900` |

頁面內容只需確保文字色彩有 `dark:` 對應即可，佈局背景由佈局元件處理。


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [ui-components](../angular-rules/references/ui-components.md) — 佈局元件架構與選擇指引
- [tailwind-patterns](../angular-rules/references/tailwind-patterns.md) — 響應式設計與深色模式
