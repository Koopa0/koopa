# blog — Project Memory

## Tech Stack

- **Language**: Go 1.26+
- **HTTP**: net/http (std lib, Go 1.22+ routing)
- **Database**: PostgreSQL via pgx/v5 (pgxpool)
- **Query Generation**: sqlc
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
  <feature>/      → <feature>.go, handler.go, store.go, query.sql, <feature>_test.go
  db/             → sqlc-generated code (NEVER edit by hand)
migrations/       → Numbered SQL: NNN_desc.up.sql / NNN_desc.down.sql
sqlc.yaml         → sqlc configuration (pgx/v5)
```

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
| `perf-reviewer` | sonnet | — | Performance review (allocations, N+1, hot paths) |
| `test-writer` | sonnet | — | Generate table-driven, bench, fuzz, integration tests |
| `scaffold` | sonnet | — | Create new feature package in `internal/` |
| `refactor` | sonnet | — | Simplify code, flatten abstractions, remove DDD |
| `build-resolver` | sonnet | — | Fix build, vet, and lint errors |

Agents with `memory: project` persist learnings in `.claude/agent-memory/`.

**Invocation**: Use `Task` tool with `subagent_type="<agent-name>"`. See `.claude/QUICKSTART.md`.

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
| `go-project-init` | `/go-project-init` | Project initialization workflow |
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

## Infrastructure & Secrets

### 部署架構

```
瀏覽器 → Cloudflare Tunnel → SSR Server (:4000) → Go Backend (:8080) → PostgreSQL (:5432)
                                    ↑ BFF proxy /bff/*                        ↓
                                    └── 後端零暴露，不對外                Cloudflare R2
```

- **VPS**: Hostinger KVM 2 (2 vCPU / 8GB RAM / 96GB), Ubuntu 24.04
- **流量入口**: Cloudflare Tunnel（無 nginx/caddy），只有 SSH port 對外
- **前端**: Angular 21 SSR (port 4000)，同時作為 BFF proxy
- **後端**: Go API (port 8080)，只在 Docker 內網可達
- **資料庫**: PostgreSQL 17 (Docker)，只在 Docker 內網可達
- **物件儲存**: Cloudflare R2 (S3 兼容)

### 環境變數

Production `.env` 存放在 VPS `~/blog/.env`，由 docker-compose 讀取。

| 變數 | 用途 | 來源 |
|------|------|------|
| `DATABASE_URL` | PostgreSQL 連線字串 | docker-compose 組合 |
| `JWT_SECRET` | JWT 簽發密鑰 | VPS `~/blog/.env` (隨機生成) |
| `POSTGRES_PASSWORD` | PG 密碼 | VPS `~/blog/.env` (隨機生成) |
| `R2_ACCESS_KEY_ID` | R2 S3 存取金鑰 | VPS `~/blog/.env` |
| `R2_SECRET_ACCESS_KEY` | R2 S3 秘密金鑰 | VPS `~/blog/.env` |
| `R2_ENDPOINT` | R2 S3 端點 | `https://d0ec7a1b2a7e00da142c766e7263dd3f.r2.cloudflarestorage.com` |
| `R2_BUCKET` | R2 Bucket 名稱 | `blog` |
| `CORS_ORIGIN` | 允許的 CORS 來源 | `https://koopa0.dev` |

### R2 使用方式

R2 走 S3 兼容 API，用 AWS SDK for Go：

```go
import (
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
        os.Getenv("R2_ACCESS_KEY_ID"),
        os.Getenv("R2_SECRET_ACCESS_KEY"),
        "",
    )),
    config.WithRegion("auto"),
)
client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String(os.Getenv("R2_ENDPOINT"))
})
```

R2 API Token 已鎖定 IP `46.202.155.7`（VPS），只能從 VPS 存取。

### Docker Network

所有服務都在 `internal` network，**不對外暴露 port**（除了前端 4000 給 Tunnel）。
- `postgres:5432` — 只有 backend 能連
- `backend:8080` — 只有 frontend (BFF proxy) 能連
- `frontend:4000` — Cloudflare Tunnel 連入

## Verification Workflow

Before any commit or PR, run `/verify` or:
```bash
go build ./... && go vet ./... && golangci-lint run ./... && go test ./...
```
