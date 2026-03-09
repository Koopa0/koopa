---
name: component-catalog
description: >-
  Master inventory of 35+ shared components — selectors, APIs, and usage
  guidelines to prevent duplicate creation. Check before building new UI.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Component Catalog

## 觸發條件

- 建立新頁面或新功能時
- 需要選擇 UI 元件時
- 組合多個元件建立頁面佈局時
- 回答「有哪些元件可用」的問題時

## 重要原則

- **禁止重複造輪子**：建立頁面前必須查閱此目錄，使用現有元件
- **組合優先**：用現有元件組合，而非從零建立
- **一致性**：所有元件遵循相同的 API 模式（`input()` / `output()` / `model()`）

---

## 佈局元件（core/layout/）

| 元件 | 選擇器 | 用途 | 何時使用 |
|------|--------|------|---------|
| SidebarLayout | `app-sidebar-layout` | 側邊欄佈局（桌面固定側邊欄 + 行動版抽屜） | 需要持久導航的管理後台 |
| StackedLayout | `app-stacked-layout` | 堆疊式佈局（頂部導航 + 內容區，無側邊欄） | 頂部導航即足夠的頁面 |
| AuthLayout | `app-auth-layout` | 認證頁面佈局（全螢幕置中卡片） | Login / Register / Forgot Password |
| Navbar | `app-navbar` | 頂部導航列（含主題切換、語系切換） | 所有佈局共用 |
| Sidebar | `app-sidebar` | 側邊欄導航（header / body / footer 插槽） | SidebarLayout 內使用 |
| AppShell | `app-shell` | 根層應用殼（整合 SidebarLayout + Sidebar + Navbar） | 包裝 router-outlet |

### 佈局插槽

**SidebarLayout** 插槽：

```html
<app-sidebar-layout>
  <nav sidebar>桌面版側邊欄</nav>
  <nav mobileSidebar>行動版側邊欄</nav>
  <nav navbar>導航列</nav>
  <div main>主要內容</div>
</app-sidebar-layout>
```

**StackedLayout** 插槽：

```html
<app-stacked-layout>
  <nav mobileSidebar>行動版側邊欄（漢堡選單開啟）</nav>
  <nav navbar>導航列</nav>
  <div main>主要內容</div>
</app-stacked-layout>
```

**AuthLayout** 插槽：

```html
<app-auth-layout>
  <!-- 直接投影內容（居中顯示） -->
  <div class="w-full max-w-sm">登入表單</div>
</app-auth-layout>
```

---

## 表單元件（shared/components/）

| 元件 | 選擇器 | 關鍵 API | 何時使用 |
|------|--------|---------|---------|
| Input | `app-input` | `type`, `placeholder`, `label`, `errorMessage`, `disabled`, `value` (model) | 單行文字輸入 |
| Textarea | `app-textarea` | `label`, `placeholder`, `errorMessage`, `disabled`, `resizable`, `rows`, `value` (model) | 多行文字輸入 |
| Select | `app-select` | `label`, `disabled`, `errorMessage`, `multiple`, `placeholder`, `value` (model) | 固定選項的下拉選擇 |
| Combobox | `app-combobox` | `options` (required), `placeholder`, `label`, `disabled`, `value` (model) | 可搜尋的下拉選擇 |
| Listbox | `app-listbox` | `options` (required), `placeholder`, `label`, `disabled`, `value` (model) | 列表式選擇 |
| Checkbox | `app-checkbox` | `label`, `disabled`, `color`, `indeterminate`, `checked` (model) | 多選 |
| RadioGroup | `app-radio-group` | `label`, `disabled`, `color`, `value` (model)；子項 `app-radio-item` | 單選 |
| Switch | `app-switch` | `label`, `disabled`, `color`, `checked` (model) | 開/關切換 |
| Fieldset | `app-fieldset` | `disabled` | 表單分組容器 |

### 表單輔助元件

| 元件 | 選擇器 | 用途 |
|------|--------|------|
| Field | `app-field` | 單一欄位容器（包裝 Label + 輸入 + ErrorMessage） |
| Label | `app-label` | 欄位標籤 |
| Legend | `app-legend` | Fieldset 群組標題 |
| ErrorMessage | `app-error-message` | 欄位驗證錯誤訊息 |

### 表單組合範例

```html
<app-fieldset>
  <app-legend>個人資料</app-legend>

  <app-field>
    <app-input label="名稱" [(value)]="name()" />
  </app-field>

  <app-field>
    <app-select label="角色" [(value)]="role()">
      <option value="admin">管理員</option>
      <option value="user">使用者</option>
    </app-select>
  </app-field>

  <app-field>
    <app-switch label="啟用通知" [(checked)]="notificationsEnabled()" />
  </app-field>
</app-fieldset>
```

---

## 資料展示元件

| 元件 | 選擇器 | 關鍵 API | 何時使用 |
|------|--------|---------|---------|
| Table | `app-table` | `bleed`, `dense`, `grid`, `striped`, `selectable`, `selectedRows` (model) | 結構化表格資料 |
| DescriptionList | `app-description-list` | dl/dt/dd 結構 | key-value 資料展示 |
| Badge | `app-badge` | `color` | 狀態標記、標籤 |
| Avatar | `app-avatar` | `src`, `size`, `initials` | 使用者頭像 |
| Progress | `app-progress` | `value`, `max`, `variant` | 進度指示 |
| Skeleton | `app-skeleton` | `variant`, `width`, `height` | 載入佔位動畫 |
| EmptyState | `app-empty-state` | `title` (required), `description` | 列表無資料時的提示 |
| Card | `app-card` | `variant` | 卡片容器 |

### Table 子元件

| 元件 | 選擇器 |
|------|--------|
| TableHead | `app-table-head` |
| TableBody | `app-table-body` |
| TableRow | `app-table-row` |
| TableHeader | `app-table-header` |
| TableCell | `app-table-cell` |

### Table 組合範例

```html
<app-table [striped]="true" [selectable]="true" [(selectedRows)]="selected()">
  <app-table-head>
    <app-table-row>
      <app-table-header>名稱</app-table-header>
      <app-table-header>狀態</app-table-header>
    </app-table-row>
  </app-table-head>
  <app-table-body>
    @for (item of items(); track item.id) {
      <app-table-row [attr.data-row-id]="item.id">
        <app-table-cell>{{ item.name }}</app-table-cell>
        <app-table-cell>
          <app-badge [color]="item.statusColor">{{ item.status }}</app-badge>
        </app-table-cell>
      </app-table-row>
    } @empty {
      <app-table-row>
        <app-table-cell colspan="2">
          <app-empty-state title="沒有資料" />
        </app-table-cell>
      </app-table-row>
    }
  </app-table-body>
</app-table>
```

---

## 導航元件

| 元件 | 選擇器 | 關鍵 API | 何時使用 |
|------|--------|---------|---------|
| Breadcrumbs | `app-breadcrumbs` | `items` (required: BreadcrumbItem[]) | 階層導航 |
| Tabs | `app-tabs` | `tabs` (required: TabItem[]), `selectedIndex` (model) | 頁內分頁 |
| Pagination | `app-pagination` | `totalItems` (required), `pageSize`, `maxVisiblePages`, `currentPage` (model), `pageChange` (output) | 分頁導航 |
| Link | `app-link` | `href`, `external` | 導航連結 |

### 導航組合範例

```html
<!-- 麵包屑 -->
<app-breadcrumbs [items]="[
  { label: '首頁', href: '/' },
  { label: '使用者', href: '/users' },
  { label: '詳情' }
]" />

<!-- 頁籤 -->
<app-tabs
  [tabs]="[
    { label: '基本資料', id: 'profile' },
    { label: '偏好設定', id: 'preferences' },
    { label: '安全', id: 'security' }
  ]"
  [(selectedIndex)]="activeTab()"
/>
```

---

## 回饋元件

| 元件 | 選擇器 | 關鍵 API | 何時使用 |
|------|--------|---------|---------|
| Alert | `app-alert` | `type`, `title`, `dismissible`, `dismissed` (output) | 頁面內通知 |
| Toast | `app-toast` | 透過 `ToastService.show()` 使用 | 臨時通知（自動消失） |
| Dialog | `app-dialog` | `title`, `size`, `open` (model) | 模態對話框 |
| Drawer | `app-drawer` | `title`, `position`, `size`, `open` (model) | 側邊滑出面板 |
| ErrorBoundary | `app-error-boundary` | `title` | 捕捉子元件渲染錯誤 |
| CommandPalette | `app-command-palette` | `items`, `placeholder`, `open` (model), `selected` (output) | 全域命令搜尋（⌘K） |

### Toast 使用方式

```typescript
private readonly toastService = inject(ToastService);

showSuccess(): void {
  this.toastService.show({
    type: 'success',
    title: '儲存成功',
    message: '您的設定已更新。',
  });
}
```

### Dialog 組合範例

```html
<app-dialog [(open)]="showDialog()" title="確認刪除" size="sm">
  <p>確定要刪除此項目嗎？此操作無法復原。</p>
  <div class="mt-4 flex justify-end gap-3">
    <app-button variant="plain" (click)="showDialog.set(false)">
      取消
    </app-button>
    <app-button color="red" (click)="confirmDelete()">
      刪除
    </app-button>
  </div>
</app-dialog>
```

---

## 基礎元素

| 元件 | 選擇器 | 關鍵 API | 何時使用 |
|------|--------|---------|---------|
| Button | `app-button` | `variant` (solid/outline/plain), `color`, `size`, `disabled`, `type` | 所有按鈕互動 |
| Heading | `app-heading` | `level` (1-6) | 語義化標題 |
| Subheading | `app-subheading` | `level` (1-6) | 次要標題 |
| Text | `app-text` | 內容投影 | 文字段落 |
| Strong | `app-strong` | 內容投影 | 粗體強調 |
| Code | `app-code` | 內容投影 | 行內程式碼 |
| TextLink | `app-text-link` | `href` | 文字內連結 |
| Divider | `app-divider` | `soft` | 分隔線 |
| Dropdown | `app-dropdown` | `disabled`, `anchor` | 操作選單容器 |
| NotFound | `app-not-found` | 無 | 404 頁面 |

### Dropdown 子元件

| 元件 | 選擇器 |
|------|--------|
| DropdownMenu | `app-dropdown-menu` |
| DropdownItem | `app-dropdown-item` |
| DropdownDivider | `app-dropdown-divider` |

### Dropdown 組合範例

```html
<app-dropdown>
  <app-button variant="outline">操作</app-button>
  <app-dropdown-menu>
    <app-dropdown-item (click)="edit()">編輯</app-dropdown-item>
    <app-dropdown-item (click)="duplicate()">複製</app-dropdown-item>
    <app-dropdown-divider />
    <app-dropdown-item (click)="delete()">刪除</app-dropdown-item>
  </app-dropdown-menu>
</app-dropdown>
```

---

## 指令

| 指令 | 選擇器 | 關鍵 API | 何時使用 |
|------|--------|---------|---------|
| Tooltip | `[appTooltip]` | `appTooltip` (文字), `tooltipPosition` (top/right/bottom/left) | 懸浮提示 |
| AutoFocus | `[appAutoFocus]` | `appAutoFocus` (boolean) | 元件初始化時自動聚焦 |
| ClickOutside | `[appClickOutside]` | `(appClickOutside)` (事件) | 點擊外部關閉 |

### 指令使用範例

```html
<!-- Tooltip -->
<app-button appTooltip="儲存變更" tooltipPosition="bottom">
  儲存
</app-button>

<!-- AutoFocus -->
<app-input appAutoFocus label="搜尋" />

<!-- ClickOutside -->
<div (appClickOutside)="closePanel()">面板內容</div>
```

---

## Pipes

| Pipe | 名稱 | 用途 | 範例 |
|------|------|------|------|
| SafeHtml | `safeHtml` | 安全渲染 HTML（僅限可信來源） | `{{ html \| safeHtml }}` |
| Truncate | `truncate` | 截斷文字 | `{{ text \| truncate:50 }}` |
| RelativeTime | `relativeTime` | 相對時間（3 分鐘前） | `{{ date \| relativeTime }}` |
| ByteFormat | `byteFormat` | 檔案大小格式化 | `{{ bytes \| byteFormat }}` |

---

## 頁面組合模式

### 管理後台列表頁

```
SidebarLayout
  └── 頁面元件
        ├── Breadcrumbs
        ├── Heading + Button（新增）
        ├── Table（selectable + striped）
        │     └── Badge（狀態欄）
        │     └── Dropdown（操作欄）
        └── Pagination
```

### 管理後台詳情頁

```
SidebarLayout
  └── 頁面元件
        ├── Breadcrumbs
        ├── Heading + Dropdown（操作）
        ├── Card
        │     └── DescriptionList
        └── Card
              └── Table（相關資料）
```

### 管理後台表單頁

```
SidebarLayout
  └── 頁面元件
        ├── Breadcrumbs
        ├── Heading
        ├── Fieldset
        │     ├── Legend
        │     ├── Field > Input
        │     ├── Field > Select
        │     └── Field > Switch
        └── Button（提交）
```

### 設定頁

```
SidebarLayout
  └── 頁面元件
        ├── Heading
        ├── Tabs
        └── 各設定區塊
              ├── Fieldset > Field > Input/Select/Switch
              └── Button（儲存）
```

### 認證頁面

```
AuthLayout
  └── 卡片容器 (max-w-sm)
        ├── Heading
        ├── Fieldset
        │     ├── Field > Input（email）
        │     ├── Field > Input（password）
        │     └── Checkbox（記住我）
        └── Button（登入）
```

### 錯誤頁面

```
AuthLayout（或獨立頁面）
  └── NotFound / EmptyState
```

---

## 元件匯入路徑

```typescript
// 佈局元件
import { SidebarLayoutComponent } from '@core/layout/sidebar-layout';
import { StackedLayoutComponent } from '@core/layout/stacked-layout';
import { AuthLayoutComponent } from '@core/layout/auth-layout';

// 共用元件（統一從 barrel export）
import { ButtonComponent } from '@shared/components/button';
import { InputComponent } from '@shared/components/input';
import { TableComponent } from '@shared/components/table';
// ... 依此類推

// 指令
import { TooltipDirective } from '@shared/directives/tooltip';
import { AutoFocusDirective } from '@shared/directives/auto-focus';

// Pipes
import { TruncatePipe } from '@shared/pipes/truncate.pipe';
import { RelativeTimePipe } from '@shared/pipes/relative-time.pipe';
```

---

## 元件總數

| 分類 | 數量 |
|------|------|
| 佈局元件 | 6 |
| 表單元件 | 9 + 4 輔助 |
| 資料展示元件 | 8 + 5 Table 子元件 |
| 導航元件 | 4 |
| 回饋元件 | 6 |
| 基礎元素 | 10 + 3 Dropdown 子元件 |
| 指令 | 3 |
| Pipes | 4 |
| **合計** | **62** |


## 相關規範

完整開發規範請參閱 `angular-rules` skill：
- [ui-components](../angular-rules/references/ui-components.md) — 三層 UI 元件策略與決策樹
- [coding-style](../angular-rules/references/coding-style.md) — 元件命名與結構規範
