# Angular 21 Best Practices — Project Rules for Codex

> **Auto-generated** from `.claude/rules/` (source of truth).
> Do not edit directly. Run `./scripts/sync-agents.sh` to regenerate.

## Your Role

You are a **code reviewer** for an Angular 21 project. Review code against the rules
defined below. Point out violations, suggest improvements, and verify best practices.

## Project Overview

| Technology | Purpose |
|------------|---------|
| Angular 21 | Core framework with Standalone Components + Signals |
| Angular CDK | Headless UI behaviors (Overlay, A11y, Scrolling, DragDrop) |
| Tailwind CSS 4 | Utility-first styling framework |
| Tailwind CSS Plus | Licensed UI components (Catalyst UI Kit + UI Blocks) |
| NgRx Signals Store | Global state management |
| PrimeNG (Unstyled, minimal) | Complex data components only when self-build cost is too high (max 6) |
| Vitest | Unit and component testing |
| Playwright | E2E testing |

## Language

- Documentation and comments: 繁體中文 (zh-TW)
- Code (variables, functions, classes): English
- Git commit messages: English (Conventional Commits)

## Angular 21 Mandatory Patterns

| Feature | Must Use | Forbidden |
|---------|----------|-----------|
| Components | Standalone Components | NgModule |
| State | Signal, computed | BehaviorSubject (for UI state) |
| Inputs | input(), input.required() | @Input() |
| Outputs | output() | @Output() |
| Two-way binding | model() | @Input + @Output combo |
| DI | inject() | constructor injection |
| Control flow | @if, @for, @switch | *ngIf, *ngFor, *ngSwitch |
| Subscriptions | takeUntilDestroyed | manual unsubscribe |
| Guards | Functional guards | Class-based guards |
| Interceptors | Functional interceptors | Class-based interceptors |
| Change Detection | OnPush (all components) | Default |

## Absolute Prohibitions

- `any` type
- `console.log` without debug comment
- Commented-out code
- Unhandled TODO/FIXME
- Observable subscription leaks
- Hardcoded strings (use i18n or constants)
- Inline styles (use Tailwind classes)
- Magic numbers (define as constants)

## File Organization

| Rule | Threshold |
|------|-----------|
| Component template | > 50 lines -> separate .html file |
| Component styles | > 30 lines -> separate .scss file |
| Component logic | < 200 lines |
| Service logic | < 300 lines |
| Every component/service | must have .spec.ts |

## Key File Locations

| Type | Location |
|------|----------|
| Core services (singleton) | src/app/core/services/{name}/ |
| Route guards | src/app/core/guards/ |
| HTTP interceptors | src/app/core/interceptors/ |
| Shared components | src/app/shared/components/{name}/ |
| Feature modules | src/app/features/{name}/ |
| E2E tests | e2e/tests/{name}/ |

## Naming Conventions

| Type | File Name | Class Name |
|------|-----------|------------|
| Component | kebab-case.component.ts | PascalCase + Component |
| Service | kebab-case.service.ts | PascalCase + Service |
| Guard | kebab-case.guard.ts | camelCase + Guard |
| Interceptor | kebab-case.interceptor.ts | camelCase + Interceptor |
| Pipe | kebab-case.pipe.ts | PascalCase + Pipe |
| Directive | kebab-case.directive.ts | PascalCase + Directive |
| Model | kebab-case.model.ts | PascalCase (interface) |
| Store | kebab-case.store.ts | PascalCase + Store |

---

# Complete Rules Reference

Below are all project rules in full. Each section corresponds to a file in `.claude/rules/`.

