---
name: angular-rules
description: >-
  Complete Angular 21 development rules collection — coding style, conventions,
  testing, security, performance, state management, and more. Install this to
  get all project rules as portable references.
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# Skill: Angular Rules

## 觸發條件

- 需要查閱 Angular 21 開發規範時
- 設定新專案的開發標準時
- 進行程式碼審查時

## 概述

本 skill 包含 Angular 21 專案的完整開發規範。這些規範檔案定義了從程式碼風格、
元件慣例到安全性和效能的所有開發標準。

> **⚠️ 在 angular-spec 專案中：禁止讀取 `references/` 目錄，所有規範已由 `.claude/rules/` 自動載入，重複讀取會浪費 context window。**
> 此 `references/` 目錄僅供透過 `npx skills add` 安裝到其他專案時使用。

## 規範索引

| 規範 | 檔案 | 說明 |
|------|------|------|
| Angular 慣例 | [angular-conventions.md](references/angular-conventions.md) | Standalone、Signal、inject()、控制流等強制性 API |
| 程式碼風格 | [coding-style.md](references/coding-style.md) | 命名、格式、TypeScript 規則、元件結構 |
| UI 元件策略 | [ui-components.md](references/ui-components.md) | 三層架構（Catalyst + CDK + PrimeNG）決策樹 |
| Tailwind 樣式 | [tailwind-patterns.md](references/tailwind-patterns.md) | Tailwind CSS v4 規則、深色模式、色彩系統 |
| 狀態管理 | [state-management.md](references/state-management.md) | Signal、NgRx Signals Store、衍生狀態 |
| HTTP 模式 | [http-patterns.md](references/http-patterns.md) | 函式型 Interceptor、CRUD Service、錯誤處理 |
| 路由 | [routing.md](references/routing.md) | 延遲載入、函式型 Guard、SSR 路由配置 |
| 測試 | [testing.md](references/testing.md) | TDD 工作流、Vitest + TestBed、覆蓋率要求 |
| 錯誤處理 | [error-handling.md](references/error-handling.md) | ErrorHandler、ErrorBoundary、HTTP 錯誤分類 |
| 效能 | [performance.md](references/performance.md) | OnPush、@defer、Virtual Scrolling、Web Vitals |
| 安全性 | [security.md](references/security.md) | XSS、CSRF、Token 儲存、CSP、OWASP Top 10 |
| Git 工作流 | [git-workflow.md](references/git-workflow.md) | Conventional Commits、PR 流程 |
| Agent 協調 | [agents.md](references/agents.md) | 任務委派策略、模型選擇、執行流程 |

## 使用方式

### 在其他專案中使用

安裝後，這些規範檔案會放在 `.claude/skills/angular-rules/references/` 目錄下。
可以在 CLAUDE.md 或其他 skill 中引用：

```markdown
請參閱 `.claude/skills/angular-rules/references/coding-style.md` 的命名規範。
```

### 快速查閱

```bash
# 查看所有規範檔案
ls .claude/skills/angular-rules/references/

# 查看特定規範
cat .claude/skills/angular-rules/references/testing.md
```

## 規範分類

### 必讀（每次開發都需要）

- **angular-conventions.md** — Angular 21 強制性 API（必須/禁止清單）
- **coding-style.md** — 命名、格式、TypeScript 規則

### 依任務查閱

| 任務 | 規範 |
|------|------|
| 建立元件/頁面 | angular-conventions, coding-style, ui-components |
| 寫樣式 | tailwind-patterns |
| HTTP 服務 | http-patterns, error-handling |
| 狀態管理 | state-management |
| 路由設定 | routing |
| 寫測試 | testing |
| 安全相關 | security |
| 效能優化 | performance |
| Git 提交 | git-workflow |
