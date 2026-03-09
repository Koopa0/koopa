---
name: angular-verify
description: >-
  Run the full Angular verification chain (tsc, lint, test, build, e2e) and
  report results. Use after any code change, before commits, or when user asks
  to "check", "verify", or "validate" the project.
user_invocable: true
metadata:
  author: koopa
  version: "1.0"
  framework: angular-21
---

# /angular-verify — Angular Verification Loop

Run the full verification chain for this Angular project. **Every step must pass with zero issues** before the code is considered ready.

## Execution Order

Run these commands SEQUENTIALLY. Stop at the first failure and report it.

### Step 1: Type Check
```bash
npx tsc --noEmit
```
If TypeScript types have problems, nothing else matters. Fix them first.

### Step 2: Lint
```bash
npx ng lint
```
Zero tolerance. Fix ALL issues. If `ng lint` is not configured, fall back to `npx eslint .`.

### Step 3: Unit Tests
```bash
npx vitest run
```
All tests must pass. If coverage is configured, verify >= 80%.

### Step 4: Build
```bash
npx ng build
```
Production build must succeed. Tree-shaking may expose import errors invisible at dev time.

### Step 5: E2E Tests (Optional)
```bash
npx playwright test
```
Run if `e2e/` directory exists and contains test files. Skip with note if not present.

## Output Format

Report results as a table:

```
| Step          | Status | Details              |
|---------------|--------|----------------------|
| tsc --noEmit  | PASS   |                      |
| ng lint       | FAIL   | 3 issues in dialog.ts|
| vitest        | SKIP   | blocked by lint fail |
| ng build      | SKIP   | blocked by lint fail |
| playwright    | SKIP   | blocked by lint fail |
```

## On Failure

When a step fails:
1. Show the full error output
2. Identify the root cause
3. Fix the issue (if simple and safe)
4. Re-run **from Step 1** (not just the failed step)
5. If the fix is non-trivial or would change behavior, stop and explain

## Rules

- NEVER skip a step
- NEVER suppress issues with `// @ts-ignore`, `// @ts-expect-error`, or `// eslint-disable` unless it's a verified false positive AND has a comment explaining why
- NEVER change ESLint config to make errors disappear
- Run ALL steps even if user only asks to "check the build"
- If tests were passing before your changes, they must still pass after
- `node_modules/` and generated files are excluded from linting — this is configured in ESLint config

## Suppression Usage

If a suppression directive is genuinely needed:

```typescript
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- third-party lib returns untyped value, validated below
const data = externalLib.getData();
```

Requirements:
1. MUST have a comment explaining why
2. MUST be specific (e.g., `@typescript-eslint/no-unsafe-assignment` not blanket `eslint-disable`)
3. MUST be approved by the user

## Pre-Commit Integration

This verification chain should run before every commit. The project uses `lint-staged` for pre-commit hooks, but `/angular-verify` runs the FULL chain — not just staged files.

## Relationship to Other Skills

- After verify passes → safe to commit (see `git-workflow` rules)
- Before PR → run verify + `code-review` checklist
- After refactor → run verify to confirm no regressions
