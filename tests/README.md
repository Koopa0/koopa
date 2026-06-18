# Validation Test Suite

This directory contains the validation system for the go-spec Claude configuration.

## Quick Start

```bash
# Run all automated tests
make verify-spec

# Or run individually:
bash tests/test-hooks.sh        # Hook behavior (82 tests)
bash tests/test-consistency.sh  # Rule consistency (125 tests)
```

## Test Layers

### Layer 1: Deterministic Tests (Automated)

| Script | Tests | What It Validates |
|--------|-------|-------------------|
| `test-hooks.sh` | 82 | Hook blocks forbidden directories, allows valid paths |
| `test-consistency.sh` | 125 | File structure, cross-references, settings, rule content |

Run with `make verify-spec` before any changes to `.claude/` configuration.

### Layer 2: AI Behavior Tests (Manual)

`VALIDATION-PLAYBOOK.md` contains 55 scenarios to test Claude's behavior:

| Category | Scenarios | Purpose |
|----------|-----------|---------|
| Development Lifecycle | 1-5 | comprehend → planner → implement → verify chain |
| Package Organization | 6-10 | Rejection of DDD/service patterns |
| Naming | 11-14 | Go naming conventions enforcement |
| HTTP Patterns | 15-18 | net/http patterns, no frameworks |
| Database | 19-25 | pgx/sqlc patterns, no ORMs |
| Testing | 26-29 | go-cmp, no testify |
| Error Handling | 30-32 | Error wrapping, handle once |
| Go Idioms | 33-38 | Standard library first, YAGNI |
| Concurrency | 39-41 | Sync functions, context patterns |
| Config & Security | 42-45 | os.Getenv only, SQL injection prevention |
| JSON API | 46-48 | Empty slices, no validation libraries |
| Observability | 49-50 | slog only, no wrappers |
| Git & Workflow | 51-52 | Verification before commit |
| Integration | 53-55 | Multi-rule interaction |

## When to Re-Run

- After modifying `.claude/rules/`, `.claude/agents/`, `.claude/skills/`
- After modifying `.claude/settings.json` or hooks
- After upgrading Claude Code
- Before starting a project based on this spec

## Test Structure

```
tests/
├── README.md              # This file
├── test-hooks.sh          # Hook behavior tests
├── test-consistency.sh    # Cross-reference and structure tests
└── VALIDATION-PLAYBOOK.md # Manual AI behavior scenarios
```

## Pass Criteria

| Test Suite | Required |
|------------|----------|
| test-hooks.sh | 100% pass |
| test-consistency.sh | 100% pass |
| VALIDATION-PLAYBOOK.md | ≥96% pass (53/55 scenarios) |

## Adding New Tests

### For hook behavior:
Add test cases to `test-hooks.sh` following the existing pattern.

### For rule consistency:
Add checks to `test-consistency.sh` for new rules/skills/agents.

### For AI behavior:
Add scenarios to `VALIDATION-PLAYBOOK.md` following the table format.
