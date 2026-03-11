# Angular 21 Best Practices Starter Template

## 🚀 Quick Start for AI Agents

**開始任何開發任務前，依序檢查：**

1. **理解任務** — 確認要做什麼
2. **查詢現有元件** — 執行 `ls src/app/shared/components/` 或查閱 `.claude/skills/component-catalog/SKILL.md`
3. **禁止重複造輪子** — 現有元件直接使用，不要重建
4. **查閱相關規範** — 相關的 `.claude/rules/*.md` 檔案
5. **開始實作** — 遵循規範和現有模式

### 元件發現指令

```bash
# 列出所有現有元件（35+ 個）
ls src/app/shared/components/

# 搜尋特定元件
ls src/app/shared/components/ | grep -i dialog

# 查看元件 API
head -50 src/app/shared/components/dialog/dialog.component.ts

# 查閱完整元件目錄（含使用範例）
cat .claude/skills/component-catalog/SKILL.md
```

### 關鍵 Skills（需主動查閱）

| Skill               | 何時查閱                   | 路徑                                        |
| ------------------- | -------------------------- | ------------------------------------------- |
| `component-catalog` | 建立新頁面、需要選擇元件時 | `.claude/skills/component-catalog/SKILL.md` |
| `page-layout`       | 決定頁面佈局時             | `.claude/skills/page-layout/SKILL.md`       |
| `angular-component` | 建立新元件時               | `.claude/skills/angular-component/SKILL.md` |
| `tailwind-styling`  | 撰寫樣式時                 | `.claude/skills/tailwind-styling/SKILL.md`  |

### 現有頁面範例

| 頁面類型 | 範例路徑                      | 使用佈局                       |
| -------- | ----------------------------- | ------------------------------ |
| 登入頁   | `src/app/features/login/`     | AuthLayout                     |
| 儀表板   | `src/app/features/dashboard/` | SidebarLayout（透過 AppShell） |
| 設定頁   | `src/app/features/settings/`  | SidebarLayout                  |
| 元件展示 | `src/app/features/showcase/`  | SidebarLayout                  |

**建立新頁面前，先參考這些範例的結構和模式。**

### 任務 → Rules 對應表

| 任務類型      | 必讀 Rules                                                      |
| ------------- | --------------------------------------------------------------- |
| 建立元件/頁面 | `angular-conventions.md`, `coding-style.md`, `ui-components.md` |
| 寫樣式        | `tailwind-patterns.md`                                          |
| HTTP 服務     | `http-patterns.md`, `error-handling.md`                         |
| 狀態管理      | `state-management.md`                                           |
| 路由設定      | `routing.md`                                                    |
| 寫測試        | `testing.md`                                                    |
| 安全相關      | `security.md`                                                   |
| 效能優化      | `performance.md`                                                |
| Git 提交      | `git-workflow.md`                                               |

---

## Project Overview

This is an Angular 21 project specification and starter template using modern best practices.

| Technology                  | Purpose                                                               |
| --------------------------- | --------------------------------------------------------------------- |
| Angular 21                  | Core framework with Standalone Components + Signals                   |
| Angular CDK                 | Headless UI behaviors (Overlay, A11y, Scrolling, DragDrop)            |
| Tailwind CSS 4              | Utility-first styling framework                                       |
| Tailwind CSS Plus           | Licensed UI components (Catalyst UI Kit + UI Blocks)                  |
| NgRx Signals Store          | Global state management                                               |
| PrimeNG (Unstyled, minimal) | Complex data components only when self-build cost is too high (max 6) |
| Vitest                      | Unit and component testing                                            |
| Playwright                  | E2E testing                                                           |

## Language

- Documentation and comments: 繁體中文 (zh-TW)
- Code (variables, functions, classes): English
- Git commit messages: English (Conventional Commits)

## Core Rules

All rules in `.claude/rules/` are always-follow guidelines. Key mandatory patterns:

### Angular 21 Mandatory Patterns

| Feature          | Must Use                  | Forbidden                      |
| ---------------- | ------------------------- | ------------------------------ |
| Components       | Standalone Components     | NgModule                       |
| State            | Signal, computed          | BehaviorSubject (for UI state) |
| Inputs           | input(), input.required() | @Input()                       |
| Outputs          | output()                  | @Output()                      |
| Two-way binding  | model()                   | @Input + @Output combo         |
| DI               | inject()                  | constructor injection          |
| Control flow     | @if, @for, @switch        | *ngIf, *ngFor, \*ngSwitch      |
| Subscriptions    | takeUntilDestroyed        | manual unsubscribe             |
| Guards           | Functional guards         | Class-based guards             |
| Interceptors     | Functional interceptors   | Class-based interceptors       |
| Change Detection | OnPush (all components)   | Default                        |

### Absolute Prohibitions

- `any` type
- `console.log` without debug comment
- Commented-out code
- Unhandled TODO/FIXME
- Observable subscription leaks
- Hardcoded strings (use i18n or constants)
- Inline styles (use Tailwind classes)
- Magic numbers (define as constants)

## File Organization

| Rule                    | Threshold                        |
| ----------------------- | -------------------------------- |
| Component template      | > 50 lines → separate .html file |
| Component styles        | > 30 lines → separate .scss file |
| Component logic         | < 200 lines                      |
| Service logic           | < 300 lines                      |
| Every component/service | must have .spec.ts               |

## File Locations

| Type                      | Location                          |
| ------------------------- | --------------------------------- |
| Core services (singleton) | src/app/core/services/{name}/     |
| Route guards              | src/app/core/guards/              |
| HTTP interceptors         | src/app/core/interceptors/        |
| Data models               | src/app/core/models/              |
| Global store              | src/app/core/store/               |
| Layout components         | src/app/core/layout/{name}/       |
| Shared components         | src/app/shared/components/{name}/ |
| Shared directives         | src/app/shared/directives/        |
| Shared pipes              | src/app/shared/pipes/             |
| Utilities                 | src/app/shared/utils/             |
| Test utilities            | src/app/shared/testing/           |
| Page components           | src/app/pages/{name}/             |
| E2E tests                 | e2e/tests/{name}/                 |
| E2E Page Objects          | e2e/pages/                        |

## Naming Conventions

| Type        | File Name                 | Class Name              | Example                                          |
| ----------- | ------------------------- | ----------------------- | ------------------------------------------------ |
| Component   | kebab-case.component.ts   | PascalCase + Component  | user-profile.component.ts → UserProfileComponent |
| Service     | kebab-case.service.ts     | PascalCase + Service    | auth.service.ts → AuthService                    |
| Guard       | kebab-case.guard.ts       | camelCase + Guard       | auth.guard.ts → authGuard                        |
| Interceptor | kebab-case.interceptor.ts | camelCase + Interceptor | auth.interceptor.ts → authInterceptor            |
| Pipe        | kebab-case.pipe.ts        | PascalCase + Pipe       | date-format.pipe.ts → DateFormatPipe             |
| Directive   | kebab-case.directive.ts   | PascalCase + Directive  | auto-focus.directive.ts → AutoFocusDirective     |
| Model       | kebab-case.model.ts       | PascalCase              | user.model.ts → User (interface)                 |
| Store       | kebab-case.store.ts       | PascalCase + Store      | user.store.ts → UserStore                        |

## UI Component Library

Three-tier strategy (see `.claude/rules/ui-components.md` for full details):

| Tier               | Source                            | Components                                                                                               |
| ------------------ | --------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Base UI            | Catalyst self-built + CDK         | Button, Input, Select, Checkbox, Radio, Switch, Badge, Alert, Avatar, Dialog, Dropdown, Pagination, etc. |
| Complex Data       | PrimeNG Unstyled (minimal, max 6) | Only when self-build cost is too high (DataTable, Calendar, Tree, etc.)                                  |
| Low-level Behavior | Angular CDK                       | Overlay, Portal, A11y, Scrolling, DragDrop, Layout, Clipboard                                            |
| Layout             | Catalyst + UI Blocks self-built   | SidebarLayout, StackedLayout, Navbar                                                                     |

**Decision rule**: Self-build from Catalyst first → CDK for behavior → PrimeNG Unstyled only as last resort.

## Dark Mode

All UI components must support dark/light mode using Tailwind's `dark:` prefix. Default is dark mode. Theme switching must be instant via ThemeService.

## Testing Requirements

| Type              | Coverage    | Notes                         |
| ----------------- | ----------- | ----------------------------- |
| Services          | Required    | All public methods            |
| Shared components | Required    | Inputs, outputs, interactions |
| Page components   | Recommended | Critical business logic       |
| E2E               | Required    | Critical user flows           |

Overall coverage target: 80%+

## Accessibility

- All interactive elements must be keyboard accessible
- All images must have alt text
- Forms must have associated labels
- Color contrast must meet WCAG AA (4.5:1 normal text, 3:1 large text)
- Use semantic HTML tags

## Tailwind CSS Plus Reference

The project includes Tailwind CSS Plus resources at `tailwind/css/`:

- **catalyst-ui-kit/**: 27 React reference components — extract HTML structure and Tailwind classes, then convert to Angular standalone components
- **ui-blocks/**: 200+ pure HTML page blocks for application-ui, ecommerce, and marketing layouts
- **rules/tailwind.md**: Complete Tailwind CSS v4 rules — **must read before writing any styles** (contains v3 → v4 breaking changes)

### UI Component Development Workflow

**⚠️ 重要：每次需要 UI 元件時，必須依序檢查！**

1. **🔍 先查現有元件** — `ls src/app/shared/components/` 或查閱 `.claude/skills/component-catalog/SKILL.md`
   - 已存在 → 直接使用，**禁止重建**
   - 不存在 → 繼續下一步
2. **Check Catalyst UI Kit** — read `tailwind/css/catalyst-ui-kit/typescript/{component}.tsx` for visual design and class structure
3. **Check UI Blocks** — read `tailwind/css/ui-blocks/{category}/{variant}.html` for page-level layout patterns
4. **Convert React → Angular** — `clsx()` → `[class]`, `useState` → `signal()`, `useMemo` → `computed()`, `<Link>` → `routerLink`
5. **Verify v4 syntax** — cross-check against `tailwind/css/rules/tailwind.md` (no `@apply`, use `shadow-xs` not `shadow-sm`, `rounded-xs` not `rounded-sm`, etc.)

完整決策樹參見 `.claude/rules/ui-components.md`。
完整元件目錄參見 `.claude/skills/component-catalog/SKILL.md`。

## MCP Integration

Configured in `.claude/mcp-servers.json`. Three MCP servers are available:

| Server        | Purpose                                         | Usage                                           |
| ------------- | ----------------------------------------------- | ----------------------------------------------- |
| `angular-cli` | `ng generate`, `ng build`, `ng test`, `ng lint` | Component/service scaffolding, build validation |
| `eslint`      | Lint checking and auto-fix                      | Code quality verification after edits           |
| `typescript`  | Type checking, completions                      | Type validation after edits                     |

MCP servers are optional — all tasks can be performed manually via CLI commands if servers are unavailable.

## Available Commands

| Command                  | Purpose                          |
| ------------------------ | -------------------------------- |
| /new-feature {name}      | Create new feature module        |
| /new-page {feature/page} | Create new page within a feature |
| /new-component {name}    | Create new standalone component  |
| /new-service {name}      | Create new service               |
| /status                  | Project health dashboard         |
| /review                  | Code review current changes      |
| /test {target?}          | Run tests                        |
| /e2e {target?}           | Run E2E tests                    |
| /refactor {target}       | Refactor target code             |
| /acceptance              | Full acceptance check            |
| /audit-a11y              | Accessibility audit              |
| /audit-perf              | Performance audit                |
| /audit-security          | Security audit                   |
| /plan                    | Implementation planning          |
| /tdd                     | Test-driven development workflow |
| /build-fix               | Fix build errors                 |
| /checkpoint              | Save verification state          |
| /learn                   | Extract patterns from session    |
| /update-docs             | Sync documentation               |

## Available Agents

| Agent                  | Model  | Role                                   |
| ---------------------- | ------ | -------------------------------------- |
| @planner               | opus   | Feature implementation planning        |
| @architect             | opus   | System design decisions                |
| @code-reviewer         | opus   | Code quality and best practices review |
| @security-auditor      | opus   | Security vulnerability analysis        |
| @test-writer           | sonnet | Test case writing expert               |
| @tdd-guide             | sonnet | Test-driven development enforcement    |
| @build-error-resolver  | sonnet | Build error fixing                     |
| @e2e-runner            | sonnet | Playwright E2E test generation         |
| @refactor-advisor      | sonnet | Refactoring consultant                 |
| @accessibility-checker | sonnet | WCAG compliance checking               |
| @performance-auditor   | sonnet | Performance optimization               |
| @doc-updater           | haiku  | Documentation sync                     |

## Workflows

### Pre-Development Checklist

開始任何開發前，確認以下項目：

- [ ] **理解需求** — 確認要做什麼、為什麼做
- [ ] **查詢現有元件** — `ls src/app/shared/components/` 確認不重複造輪子
- [ ] **選擇正確佈局** — SidebarLayout / StackedLayout / AuthLayout
- [ ] **查閱相關規範** — `.claude/rules/` 中的相關檔案
- [ ] **確認測試策略** — 需要哪些測試

### New Feature Standard Flow

1. **Pre-check** — 執行 Pre-Development Checklist
2. `/plan` - Plan the implementation
3. `/new-feature {name}` - Create feature module structure
4. Implement business logic（使用現有元件組合）
5. `/tdd` - Write tests following TDD
6. `/review` - Code review
7. `/acceptance` - Full acceptance check

### Modify Existing Feature Flow

1. Verify existing tests pass
2. Make changes
3. Verify tests still pass
4. Add tests for new functionality
5. `/review` - Code review

### Acceptance Checklist

- [ ] `npm run lint` passes
- [ ] `npm run build` passes
- [ ] `npm run test` passes (coverage >= 80%)
- [ ] `npm run e2e` passes
- [ ] Dark/light mode works correctly
- [ ] Responsive design verified
- [ ] Accessibility check passes
