# go-spec — Project Memory

## Tech Stack

- **Language**: Go 1.26+
- **HTTP**: net/http (std lib, Go 1.22+ routing)
- **Database**: PostgreSQL via pgx/v5 (pgxpool)
- **Query Generation**: sqlc
- **AI Framework**: Genkit Go (flows, tools, structured output)
- **Cache**: Ristretto (in-memory, single machine)
- **Messaging**: NATS (Core + JetStream)
- **Logging**: log/slog (std lib)
- **Tracing**: OpenTelemetry (progressive adoption)
- **Testing**: std testing + go-cmp, testcontainers-go for integration
- **Linting**: golangci-lint v2

## Core Principles

1. **Package-by-feature, not by layer** — no services/, repositories/, handlers/, models/ directories
2. **Standard library first** — no frameworks (chi, gin, echo), no testify, no unnecessary abstractions
3. **Simplicity over cleverness** — obvious code beats elegant code
4. **No DDD** — no domain/, infrastructure/, application/ layering
5. **Errors are values** — wrap with `%w`, handle once, lowercase messages

## Project Layout

```
cmd/app/          → Entry point, wiring only (middleware goes here when needed)
internal/         → All application code, organized by feature
  <feature>/      → <feature>.go, handler.go, store.go, query.sql, <feature>_test.go, flow.go*, tool.go*
  db/             → sqlc-generated code (NEVER edit by hand)
migrations/       → Numbered SQL: NNN_desc.up.sql / NNN_desc.down.sql
prompts/          → Genkit dotprompt files: <feature>/*.prompt
sqlc.yaml         → sqlc configuration (pgx/v5)
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build binary to bin/ |
| `make run` | Run the application |
| `make test` | Run unit tests |
| `make test-integration` | Run integration tests (requires Docker) |
| `make test-all` | Run all tests |
| `make lint` | Run golangci-lint |
| `make fmt` | Format code (goimports + gofmt) |
| `make vet` | Run go vet |
| `make sqlc` | Generate sqlc code |
| `make bench` | Run benchmarks |
| `make fuzz PKG=./internal/order` | Run fuzz tests (30s, single package) |
| `make coverage` | Generate coverage report |
| `make sqlc-check` | Check sqlc generated code is up to date |
| `make verify-spec` | Run all automated spec validation (hooks + consistency + build) |
| `make docker-build` | Build Docker image |
| `make clean` | Remove build artifacts |

## Key Patterns

- **Table-driven tests** are mandatory for any function with >1 test case
- **go-cmp** for comparisons, never testify
- **b.Loop()** for benchmark loops (Go 1.24+)
- **Error wrapping**: `fmt.Errorf("operation: %w", err)` — lowercase, no punctuation
- **testcontainers-go** for database integration tests, never mock the database
- **`//go:build integration`** tag for integration tests
- **Linter suite**: staticcheck, gosec, errcheck, gocritic — zero tolerance for issues

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
| `review-code` | opus | project | **L2 quality gate** — paranoid 7-dimension deep review |
| `perf-reviewer` | sonnet | — | Performance review (allocations, N+1, hot paths) |
| `test-writer` | sonnet | — | Generate table-driven, bench, fuzz, integration tests |
| `scaffold` | sonnet | — | Create new feature package in `internal/` |
| `refactor` | sonnet | — | Simplify code, flatten abstractions, remove DDD |
| `build-resolver` | sonnet | — | Fix build, vet, and lint errors |

Agents with `memory: project` write directly to their `.claude/agent-memory/` files (no delegation).

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
| `ristretto` | `/ristretto` | In-memory cache patterns (single machine) |
| `nats` | `/nats` | NATS Core + JetStream messaging patterns |
| `error-patterns` | `/error-patterns` | Error handling: sentinels, wrapping, domain→HTTP mapping |
| `graceful-shutdown` | `/graceful-shutdown` | Signal handling, connection draining, shutdown ordering |
| `auth-patterns` | `/auth-patterns` | JWT, auth middleware, RBAC, bcrypt, rate limiting |
| `config-management` | `/config-management` | Env vars, type-safe config, validation, redaction |
| `docker-deploy` | `/docker-deploy` | Dockerfile, Docker Compose, K8s manifests |
| `go-concurrency` | `/go-concurrency` | Goroutine lifecycle, errgroup, worker pools, channels |
| `api-design` | `/api-design` | Pagination, filtering, error format, versioning |
| `go-types` | `/go-types` | Value vs pointer, receivers, nil pitfalls, slice/map behavior |
| `go-interfaces` | `/go-interfaces` | Consumer-side interfaces, composition, testing with interfaces |
| `go-generics` | `/go-generics` | When to use generics, constraints, comparable pitfall |
| `go-testing-advanced` | `/go-testing-advanced` | Golden files, fixtures, coverage, go-cmp advanced |
| `go-stdlib-patterns` | `/go-stdlib-patterns` | io, json, time, sort/slices, strings, context advanced |
| `go-slog` | `/go-slog` | slog setup, logger injection, key naming, OTel correlation |
| `go-iteration` | `/go-iteration` | Range-over-func, iter.Seq, push vs pull, channel vs iterator |
| `go-performance` | `/go-performance` | Pre-allocation, escape analysis, sync.Pool, pprof |
| `go-middleware` | `/go-middleware` | Middleware ordering (CORS before Auth WHY), chain composition |
| `go-doc` | `/go-doc` | Go 1.19+ doc comments, links, headings, what to document |
| `go-modules` | `/go-modules` | go.mod, MVS, vendoring, go.work, build tags |
| `go-reflection` | `/go-reflection` | When to avoid reflect, struct tags, DeepEqual |
| `go-unsafe` | `/go-unsafe` | When to avoid unsafe/cgo, cost analysis, safe alternatives |
| `go-compliance-test` | `/go-compliance-test` | AI compliance traps, detection commands, self-check checklist |
| `devil-advocate` | `/devil-advocate` | Adversarial retroactive review: challenge existing decisions, find over-engineering, detect AI echo chamber drift |
| `tdd` | `/tdd` | Strict RED-GREEN-REFACTOR test-driven development cycle |
| `debug` | `/debug` | Structured 4-phase debugging (reproduce, diagnose, fix, verify) |
| `reflect` | `/reflect` | Review session learnings, promote to memory/rules/skills with human gate |
| `execute-plan` | `/execute-plan` | Execute approved plan task-by-task with fresh subagents + crafted context |
| `test-strategy` | `/test-strategy` | Test type decision tree (Q0-Q6): determines WHICH tests to write per function |
| `research` | `/research` | Targeted external research before planning (triggered by comprehend's "Research Needed") |

## Verification Workflow

Before any commit or PR, run `/verify` or:
```bash
go build ./... && go vet ./... && golangci-lint run ./... && go test ./...
```

## Built-in Commands Reference

| Command | Purpose | When |
|---------|---------|------|
| `/loop 10m <cmd>` | Recurring monitoring (session-scoped) | Long Tier 3 implementation |
| `/batch <instruction>` | Parallel changes across files (worktrees) | 5-30 files, same pattern |
| `/simplify` | Post-implementation cleanup (3 parallel reviewers) | After Phase 3, before Phase 4 |
| `/btw <question>` | Side question without context pollution | Quick lookup during work |
| `/diff` | Interactive uncommitted changes viewer | Pre-commit review |
| `/context` | Context window usage visualization | Debug degraded responses |
| `/branch [name]` | Branch conversation at current point | Explore alternatives |
| `/effort [level]` | Set model effort (low/medium/high/max) | Adjust quality vs speed |
| `/security-review` | Built-in security vulnerability scan | Pre-PR security check |
| `/stats` | Usage statistics and session history | Observability |
| `/insights` | Session pattern analysis | Meta-analysis |
| `/voice` | Push-to-talk voice dictation | Hands-free input |
| `/remote-control` | Mobile/browser bridge to local session | Remote work |
