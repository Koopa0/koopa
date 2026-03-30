# koopa0.dev — 個人知識引擎平台

> 這不是一個部落格。這是一個可輸入、可輸出的個人知識系統。

## 專案結構

```
/
├── cmd/app/          → Go API entry point, wiring only
├── cmd/mcp/          → MCP server entry point
├── internal/         → All Go application code, organized by feature
│   <feature>/        → <feature>.go, handler.go, store.go, query.sql, <feature>_test.go
│   db/               → sqlc-generated code (NEVER edit by hand)
├── migrations/       → Numbered SQL: NNN_desc.up.sql / NNN_desc.down.sql
├── prompts/          → Genkit dotprompt files: <feature>/*.prompt
├── frontend/         → Angular 21 前端（SSR + Tailwind v4）
├── docs/             → 共用設計文件
│   └── PLATFORM-VISION.md  ← 完整平台設計（必讀）
├── sqlc.yaml         → sqlc configuration (pgx/v5)
├── go.mod            → module github.com/Koopa0/koopa0.dev
└── CLAUDE.md         → 你現在在讀的這份
```

## 必讀文件

| 文件 | 用途 |
|------|------|
| `docs/PLATFORM-VISION.md` | **完整平台設計** — 系統架構、API spec、資料模型、執行階段 |
| `frontend/CLAUDE.md` | Angular 前端開發規範（元件、規則、命名、測試） |
| `.claude/rules/` | Go 後端開發規範（規則、命名、測試、安全） |

## 平台三大面向

1. **輸入** — Obsidian 知識庫同步、外部資料主動收集（RSS/API/爬蟲）
2. **處理** — Go Genkit AI Pipeline：整理、分類、生成草稿、審核分級
3. **輸出** — Angular SSR 網站：主題式內容呈現、個人品牌展示

## 技術棧

| 層 | 技術 |
|----|------|
| 前端 | Angular 21, Tailwind CSS v4, SSR |
| 後端 | Go 1.26+, Genkit, PostgreSQL, pgx/v5, sqlc |
| AI | Genkit Flow, Prompt 模板 |
| Cache | Ristretto (in-memory, single machine) |
| Messaging | NATS (Core + JetStream) |
| Logging | log/slog (std lib) |
| Tracing | OpenTelemetry (progressive adoption) |
| Testing | std testing + go-cmp, testcontainers-go |
| Linting | golangci-lint v2 |
| 部署 | Docker, VPS |

## 核心設計原則

- **Obsidian-first** — 內容源頭是 Obsidian，網站是呈現層
- **AI 輔助，人類把關** — 審核分級制（自動/輕度/標準/嚴格）
- **主題驅動** — 內容按 Topic 組織，格式次要
- **用作品說話** — 不列學經歷，讓作品和內容展示能力
- **對自己有用** — 首先是知識管理工具，其次是對外展示

## Go 核心原則

1. **Design before mechanics** — understand WHY before changing WHAT
2. **Package-by-feature, not by layer** — no services/, repositories/, handlers/, models/
3. **Standard library first** — no frameworks (chi, gin, echo), no testify
4. **Simplicity over cleverness** — obvious code beats elegant code
5. **No DDD** — no domain/, infrastructure/, application/ layering
6. **Errors are values** — wrap with `%w`, handle once, lowercase messages

## 內容類型

| 類型 | 說明 |
|------|------|
| `article` | 深度技術文章 |
| `essay` | 個人想法、非技術反思 |
| `build-log` | 專案開發紀錄 |
| `til` | 每日學習（短） |
| `note` | 技術筆記片段 |
| `bookmark` | 推薦資源 + 個人評語 |
| `digest` | 週報/月報 |

## Go Key Patterns

- **Table-driven tests** mandatory for >1 test case
- **go-cmp** for comparisons, never testify
- **b.Loop()** for benchmark loops (Go 1.24+)
- **Error wrapping**: `fmt.Errorf("operation: %w", err)` — lowercase, no punctuation
- **testcontainers-go** for database integration tests, never mock the database
- **`//go:build integration`** tag for integration tests
- **Linter suite**: staticcheck, gosec, errcheck, gocritic — zero tolerance

## Development Lifecycle

Every code change follows one of three tiers:

| Tier | When | Flow |
|------|------|------|
| 1 | Obvious fix, 1-3 files, no design | fix → `/verify` → `go-reviewer` |
| 2 | Existing feature, no new packages | lightweight comprehend → implement → `/verify` + reviewers |
| 3 | New feature, new package, design decisions | `comprehend` → `planner` → implement → `/verify` + reviewers |

**Quick decision**: See `.claude/QUICKSTART.md` for the decision tree.
**Full details**: See `.claude/rules/development-lifecycle.md`.

## Available Agents

| Agent | Model | Memory | Purpose |
|-------|-------|--------|---------|
| `comprehend` | opus | project | **FIRST STEP** — understand codebase + challenge user request |
| `planner` | opus | project | Design architecture and implementation plans |
| `go-reviewer` | sonnet | project | Code review for Go idioms and conventions |
| `db-reviewer` | sonnet | project | Review SQL, migrations, pgx usage, sqlc config |
| `security-reviewer` | sonnet | project | Security review (OWASP, SQL injection, secrets) |
| `review-code` | opus | project | **L2 quality gate** — paranoid 8-dimension deep review |
| `perf-reviewer` | sonnet | — | Performance review (allocations, N+1, hot paths) |
| `test-writer` | sonnet | — | Generate table-driven, bench, fuzz, integration tests |
| `scaffold` | sonnet | — | Create new feature package in `internal/` |
| `refactor` | sonnet | — | Simplify code, flatten abstractions, remove DDD |
| `build-resolver` | sonnet | — | Fix build, vet, and lint errors |

**Invocation**: Use `Agent` tool with `subagent_type="<agent-name>"`. See `.claude/QUICKSTART.md`.

## Available Skills

| Skill | Command | Purpose |
|-------|---------|---------|
| `verify` | `/verify` | Run full verification chain: build → vet → lint → test |
| `checkpoint` | `/checkpoint` | Create git checkpoint before risky changes |
| `pgx-patterns` | `/pgx-patterns` | pgx/v5 best practices reference |
| `sqlc-guide` | `/sqlc-guide` | sqlc configuration and usage guide |
| `testcontainers` | `/testcontainers` | testcontainers-go PostgreSQL patterns |
| `postgres-patterns` | `/postgres-patterns` | PostgreSQL schema, indexing, migrations |
| `otel-guide` | `/otel-guide` | OpenTelemetry progressive adoption |
| `http-server` | `/http-server` | net/http Go 1.22+ server patterns |
| `migrations` | `/migrations` | golang-migrate patterns, safe migration SQL |
| `go-project-init` | `/go-project-init` | Project init: feature scaffold or new project bootstrap |
| `manage-spec` | `/manage-spec` | Add, list, validate skills/rules/hooks/agents |
| `genkit-go` | `/genkit-go` | Genkit Go flows, tools, prompts, integration |
| `error-patterns` | `/error-patterns` | Error handling: sentinels, wrapping, domain→HTTP mapping |
| `graceful-shutdown` | `/graceful-shutdown` | Signal handling, connection draining, shutdown ordering |
| `auth-patterns` | `/auth-patterns` | JWT, auth middleware, RBAC, bcrypt, rate limiting |
| `config-management` | `/config-management` | Env vars, type-safe config, validation, redaction |
| `docker-deploy` | `/docker-deploy` | Dockerfile, Docker Compose, K8s manifests |
| `go-concurrency` | `/go-concurrency` | Goroutine lifecycle, errgroup, worker pools, channels |
| `api-design` | `/api-design` | Pagination, filtering, error format, versioning |
| `devil-advocate` | `/devil-advocate` | Adversarial review: challenge decisions, find over-engineering |
| `tdd` | `/tdd` | Strict RED-GREEN-REFACTOR test-driven development cycle |
| `debug` | `/debug` | Structured 4-phase debugging (reproduce, diagnose, fix, verify) |
| `reflect` | `/reflect` | Review session learnings, promote to memory/rules/skills |
| `execute-plan` | `/execute-plan` | Execute approved plan task-by-task with fresh subagents |
| `test-strategy` | `/test-strategy` | Test type decision tree: determines WHICH tests to write |
| `design-review` | `/design-review` | Deep design review: package purpose, naming, stdlib comparison |
| `build-log` | `/build-log` | Record development session as a build log via MCP |

## Verification Workflow

Before any commit or PR, run `/verify` or:
```bash
go build ./... && go vet ./... && golangci-lint run ./... && go test ./...
```

## 開發分工

| 負責人 | 範圍 |
|--------|------|
| Koopa | Go API、AI Pipeline、Obsidian 整合、資料收集 |
| Claude Code | Angular 前端、API 對接、Admin UI、設計調整 |

## 語言規範

- 文件和 UI 文字：繁體中文
- 程式碼（變數、函式）：English
- Git commits：English (Conventional Commits)
