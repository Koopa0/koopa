---
name: code-review
description: >-
  Cross-stack PR review checklist for Go + Angular. Use before commits, during
  code review, or when user asks to "review", "check my code", or "PR review".
metadata:
  author: koopa
  version: "1.0"
---

# Skill: Code Review Checklist

Fast-scan checklist for PR review. Check all applicable sections.

## Review Process

1. **Read changed files thoroughly** — understand the full diff before commenting
2. **Check against Angular 21 conventions** — see checklists below
3. **Prioritize by severity**:
   - **Critical** — security vulnerabilities, data loss, broken functionality
   - **Warning** — performance issues, anti-patterns, missing error handling
   - **Info** — style, naming, minor improvements

---

## General

- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `refactor:`, etc.)
- [ ] One PR does one thing — no unrelated changes bundled
- [ ] No debug residue (`console.log`, `fmt.Println`, `debugger`, `TODO`, `FIXME`, `HACK`)
- [ ] No secrets (`API_KEY`, `password`, `token`, `secret` hardcoded in source)
- [ ] No commented-out code blocks
- [ ] New files follow project naming conventions

---

## Go Backend

### Error Handling
- [ ] Every error has wrapping context (`fmt.Errorf("doing X: %w", err)`)
- [ ] No log AND return of same error
- [ ] Using `errors.Is`/`errors.As`, never `err ==` or `strings.Contains(err.Error()...)`
- [ ] `%v` (not `%w`) at API boundaries to prevent type leaking

### Naming & Style
- [ ] No `Get` prefix on methods (`UserByID` not `GetUserByID`)
- [ ] Using `any` not `interface{}`
- [ ] Error messages lowercase, no trailing punctuation
- [ ] Exported names don't stutter (`user.Service` not `user.UserService`)
- [ ] New exported names have godoc comment

### Architecture
- [ ] No cross-feature store imports (uses interface instead)
- [ ] No `os.Getenv` outside `main.go`
- [ ] Store layer has no business logic
- [ ] New endpoint has handler test

### Concurrency
- [ ] No `t.Fatal` in goroutines
- [ ] Every goroutine has exit condition
- [ ] No I/O while holding mutex

### Database
- [ ] SQL migration has both up AND down
- [ ] sqlc queries regenerated after schema change
- [ ] `pgx.ErrNoRows` translated to domain sentinel

---

## Angular Frontend

### Component Patterns
- [ ] Standalone component (`standalone: true`)
- [ ] `ChangeDetectionStrategy.OnPush`
- [ ] `inject()` not constructor injection
- [ ] `input()`/`output()`/`model()` not `@Input`/`@Output` decorators
- [ ] `@if`/`@for`/`@switch` not `*ngIf`/`*ngFor`/`*ngSwitch`
- [ ] `viewChild()`/`viewChildren()` not `@ViewChild`/`@ViewChildren`

### State & Reactivity
- [ ] `signal()` for mutable state, `computed()` for derived
- [ ] No `BehaviorSubject` for UI state (use Signal)
- [ ] Subscriptions use `takeUntilDestroyed()`
- [ ] No `effect()` for derived state (use `computed()`)

### Routing
- [ ] New routes are lazy-loaded (`loadComponent`/`loadChildren`)
- [ ] Guards are functional (`CanActivateFn`)
- [ ] SSR `RenderMode` set appropriately

### Styling
- [ ] Tailwind classes, no inline styles
- [ ] Tailwind v4 syntax (see `ai-compliance-test` Trap Type 2)
- [ ] Dark mode supported (`dark:` variants present)
- [ ] No `@apply` in CSS

### i18n & Content
- [ ] i18n keys, not hardcoded UI strings
- [ ] New components checked against `component-catalog` (no reinventing)

---

## Security (Both Stacks)

- [ ] User input validated/sanitized at boundary
- [ ] HTTP responses don't leak internal error details to client
- [ ] No `CORS: *` in production config
- [ ] No `eval()`, `new Function()`, or `bypassSecurityTrust*` without review comment
- [ ] Auth tokens stored in memory only (not localStorage/sessionStorage)
- [ ] Sensitive data not logged (`console.log(token)`, `slog.Info("password", ...)`)

---

## Testing

### Go
- [ ] New endpoint has handler test
- [ ] Integration tests use testcontainers, not mocks for DB
- [ ] `t.Parallel()` on independent tests
- [ ] `t.Setenv` not `os.Setenv`

### Angular
- [ ] New component/service has `.spec.ts`
- [ ] Tests use `data-testid` selectors
- [ ] Test names follow `should ... when ...` format
- [ ] Every `it()` has at least one `expect()`
- [ ] No testing of private methods (`component['...']`)
- [ ] Fixed mock data, no `Math.random()` or `faker`

---

## Quick Scan Commands

```bash
# Go — find common issues
grep -rn 'fmt.Println\|log.Print' internal/ --include="*.go" --exclude="*_test.go"
grep -rn 'panic(err)\|panic(fmt' internal/ --include="*.go"
grep -rn 'os.Getenv' internal/ --include="*.go" --exclude="*_test.go"

# Angular — find common issues
grep -rn '@Input()\|@Output()\|@ViewChild' src/ --include="*.ts" --exclude="*.spec.ts"
grep -rn 'console.log' src/ --include="*.ts" --exclude="*.spec.ts"
grep -rn '*ngIf\|*ngFor' src/ --include="*.html"
```

---

## Output Format

```
## [Critical/Warning/Info] Title

**File:** `path/to/file.ts:42`
**Issue:** Description of the problem
**Suggestion:** How to fix it
```

---

## Related Skills

- `verify` / `angular-verify` — run full verification chain before review
- `ai-compliance-test` — Angular trap patterns
- `go-compliance-test` — Go trap patterns
- `error-patterns` — Go error handling reference
