# blog — Gemini CLI

This project uses `AGENTS.md` as the single source of truth for cross-agent Go conventions. Gemini CLI loads it via `.gemini/settings.json`.

## What you get

- **`AGENTS.md`** — Full Go specification: naming, error handling, testing, database, HTTP, security, concurrency
- **`.agents/skills/`** — 32 shared skills (symlinked from `.claude/skills/`; excludes Claude-specific `verify` and `checkpoint`)
- **`.gemini/settings.json`** — Hooks that block forbidden directories and auto-format Go files

## Hooks

Gemini CLI runs the same enforcement hooks as Claude Code:

| Event | Hook | Effect |
|-------|------|--------|
| `BeforeTool` | `check-anti-patterns.sh` | Blocks file creation in forbidden directories (services/, models/, domain/, etc.) |
| `BeforeTool` | `check-generated-code.sh` | Blocks edits to sqlc-generated code and files with DO NOT EDIT header |
| `AfterTool` | `format-go.sh` | Auto-runs goimports/gofmt on written `.go` files |

## Build & Verify

```bash
make build              # go build ./...
make test               # go test ./...
make lint               # golangci-lint run ./...
make verify-spec        # full configuration validation (207 tests)
```

## Reference

- `AGENTS.md` — Cross-agent Go conventions
- `CLAUDE.md` — Claude Code specific configuration (agents, skills, lifecycle tiers)
- `.claude/rules/` — 20 detailed rule files (Claude Code conditional loading)
