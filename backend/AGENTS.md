# go-spec — Cross-Agent Project Conventions

This file defines universal project conventions for all AI coding agents. Tool-specific configuration (Claude agents/skills, Gemini extensions, Codex overrides) lives in their respective directories.

## Tech Stack

- **Language**: Go 1.26+
- **HTTP**: net/http (std lib, Go 1.22+ routing)
- **Database**: PostgreSQL via pgx/v5 (pgxpool)
- **Query Generation**: sqlc
- **AI Framework**: Genkit Go
- **Cache**: Ristretto (in-memory, single machine)
- **Messaging**: NATS (Core + JetStream)
- **Logging**: log/slog (std lib)
- **Tracing**: OpenTelemetry (progressive adoption)
- **Testing**: std testing + go-cmp, testcontainers-go for integration
- **Linting**: golangci-lint v2

## Core Principles

1. **Package-by-feature, not by layer** — no `services/`, `repositories/`, `handlers/`, `models/` directories
2. **Standard library first** — no frameworks (chi, gin, echo), no testify, no unnecessary abstractions
3. **Simplicity over cleverness** — obvious code beats elegant code
4. **No DDD** — no `domain/`, `infrastructure/`, `application/` layering
5. **Errors are values** — wrap with `%w`, handle once, lowercase messages

## Project Layout

```
cmd/app/main.go       → Wiring ONLY: config, deps, routes, server
internal/<feature>/   → ALL application code, by feature
  <feature>.go        → Types, constants, sentinel errors
  handler.go          → HTTP handlers
  store.go            → Database operations (pgx)
  query.sql           → sqlc queries
  <feature>_test.go   → All tests
internal/db/          → sqlc-generated code (NEVER edit by hand)
migrations/           → NNN_desc.up.sql / NNN_desc.down.sql
prompts/<feature>/    → Genkit dotprompt files
sqlc.yaml             → sqlc config (pgx/v5)
```

## Build & Verify

```bash
go build ./...                  # must compile
go vet ./...                    # must pass
golangci-lint run ./...         # must pass, zero issues
go test ./...                   # must pass
go test -race ./...             # must pass (CI)
go test -tags integration ./...  # integration tests (requires Docker)
```

Make targets: `build`, `run`, `test`, `test-integration`, `test-all`, `lint`, `fmt`, `vet`, `sqlc`, `sqlc-check`, `bench`, `fuzz`, `coverage`, `verify-spec`, `docker-build`, `clean`.

---

## Forbidden Directories

The following directory names are **banned**. NEVER create files in any of these:

`services`, `service`, `repositories`, `repository`, `handlers`, `handler`, `controllers`, `controller`, `models`, `model`, `entities`, `entity`, `dto`, `dtos`, `mappers`, `mapper`, `factory`, `factories`, `domain`, `infrastructure`, `application`, `presentation`, `util`, `utils`, `helper`, `helpers`, `common`, `shared`, `base`, `types`, `src`, `pkg`

Place code in feature packages under `internal/` (e.g., `internal/order/`, `internal/user/`).

---

## Naming Conventions

### Packages

- Lowercase, single-word: `order`, `auth`
- Constructor: `order.New`, not `order.NewOrder`
- NEVER stutter: `order.Status` not `order.OrderStatus`

### Getters/Setters

- No `Get` prefix on getters: `func (u *User) Name()` not `GetName()`
- Setter uses `Set` prefix: `func (u *User) SetName(name string)`
- Expensive operations use a verb: `Compute`, `Fetch`, `List`

### Receivers

- 1-2 letters, abbreviation of type: `func (s *Store)`, `func (o *Order)`
- NEVER `this` or `self`

### Interfaces

- One-method: method + `-er` (`Reader`, `Writer`)
- Multi-method: descriptive noun (`OrderReader`)
- NEVER prefix with `I`

### Initialisms

- All caps: `HTTPServer`, `JSONParser`, `serverID`, `URL`
- Never `HttpServer` or `Url`

### Store Methods

| Pattern | Meaning | Example |
|---------|---------|---------|
| `Order(ctx, id)` | Single record by PK | `s.Order(ctx, "abc")` |
| `OrderByEmail(ctx, email)` | By alternate key | `s.OrderByEmail(ctx, "a@b.c")` |
| `Orders(ctx, filter)` | List (returns slice, never nil) | `s.Orders(ctx, f)` |
| `CreateOrder(ctx, params)` | Insert | `s.CreateOrder(ctx, p)` |
| `UpdateOrder(ctx, id, params)` | Modify | `s.UpdateOrder(ctx, id, p)` |
| `DeleteOrder(ctx, id)` | Remove | `s.DeleteOrder(ctx, id)` |

NEVER use `Find`, `Fetch`, `Retrieve`, `Get` for store methods.

### Files

- Lowercase with underscores
- NEVER name a file after a pattern (`service.go`, `repository.go`)

### Constants

- `MixedCaps`, never `SCREAMING_SNAKE_CASE`
- Never prefix with `K`

---

## Error Handling

### Format

Lowercase, no punctuation, context at end:

```go
fmt.Errorf("querying order %s: %w", id, err)
```

### Rules

- `%w` for internal code (preserves chain for `errors.Is`/`errors.As`)
- `%v` at system boundaries (prevents leaking internal types)
- Handle exactly once: either return OR log, NEVER both
- Add non-redundant context only — don't repeat function name
- NEVER ignore errors without `// best-effort` comment
- NEVER use string matching: `strings.Contains(err.Error(), ...)`
- NEVER use `log.Fatal` outside `main()` startup helpers
- NEVER panic for normal error handling

### Sentinel Errors

Define in `<feature>.go`. Each sentinel = a distinct caller decision:

| Error | HTTP Status | When |
|-------|-------------|------|
| `ErrNotFound` | 404 | Record doesn't exist |
| `ErrConflict` | 409 | Unique constraint violated |
| `ErrForbidden` | 403 | Caller lacks permission |
| `ErrInvalidInput` | 422 | Business validation fails |

- Only define sentinels the handler branches on
- Map pgx errors in store: `pgx.ErrNoRows` -> `ErrNotFound`, unique violation -> `ErrConflict`
- NEVER create sentinels for infrastructure errors
- Use `var`, not `type`: `var ErrNotFound = errors.New("not found")`
- Prefer `errors.AsType[*MyErr](err)` over `errors.As` (Go 1.26+)

---

## Interfaces

- **Consumer defines interface**, producer returns concrete
- NEVER return an interface from a function
- NEVER define an interface until 2+ implementations or a real testing need
- Keep small: 1-3 methods maximum
- Compile-time check: `var _ OrderReader = (*Store)(nil)`
- NEVER embed an interface in a struct (zero value panics)

---

## Testing

### Assertion Libraries Forbidden

NEVER use testify or custom assert helpers. Use stdlib + `go-cmp`:

```go
if diff := cmp.Diff(want, got); diff != "" {
    t.Errorf("Order() mismatch (-want +got):\n%s", diff)
}
```

### Failure Messages

MUST follow `FuncName(input) = got, want expected`:

```go
t.Errorf("ParseStatus(%q) = %v, want %v", input, got, want)
```

Got before want. Always. Use `%q` for strings.

### Table-Driven Tests (Mandatory for 2+ Cases)

```go
tests := []struct {
    name    string
    input   string
    want    Status
    wantErr bool
}{...}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) { ... })
}
```

ALWAYS use field names in struct literals. NEVER positional.

### Other Testing Rules

- `t.Helper()` in any function that calls `t.Fatal`/`t.Error`
- `t.Fatal` for setup failures; `t.Error` for test case failures
- NEVER call `t.Fatal` from a goroutine
- Full structure comparison with `cmp.Diff`, NEVER field-by-field
- NEVER compare `json.Marshal` output strings
- Benchmarks: use `b.Loop()` (Go 1.24+), not `b.N`
- HTTP tests: `httptest.NewRecorder` + `SetPathValue` (Go 1.22+)
- Concurrent tests: use `testing/synctest.Test()` with virtualized time (Go 1.25+)
- Test attributes: `t.Attr("key", "value")` for structured metadata (Go 1.25+)
- Test artifacts: `t.ArtifactDir()` for persistent output (Go 1.26+)

### Integration Tests

- Build tag: `//go:build integration`
- testcontainers-go with real PostgreSQL, NEVER mock the database
- `t.Cleanup()` for teardown, `t.Parallel()` for independent tests
- In tests (Go 1.24+), prefer `t.Context()` over `context.Background()`

---

## HTTP Server

### Constraints

- MUST use `net/http` with Go 1.22+ routing. NEVER chi, gin, echo, fiber.
- Handlers: closure-based or struct-based DI. Parse, call, encode only.
- NEVER put SQL or business logic in handlers
- Path params: `r.PathValue("id")`, validate before use
- MUST set `Content-Type: application/json` and `X-Content-Type-Options: nosniff`

### Server Configuration

- MUST set `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `MaxHeaderBytes`
- MUST implement graceful shutdown with `srv.Shutdown(ctx)`
- MUST have `/healthz` (liveness) and `/readyz` (readiness)
- Health endpoints MUST NOT go through auth middleware

### Middleware

- Order: Recovery -> RequestID -> CORS -> Logging -> Auth -> Handler
- Recovery ONLY in HTTP layer, NEVER in business logic
- Request IDs with `crypto/rand`, NEVER `math/rand`

### Error Responses

- 4xx: specific and actionable
- 5xx: generic "internal error", NEVER expose `err.Error()`
- 5xx: MUST log real error with `slog.Error`

### Outgoing HTTP

- Reuse a single `*http.Client` (create at startup)
- MUST set `http.Client{Timeout: ...}`
- MUST use `http.NewRequestWithContext(ctx, ...)`
- NEVER use `http.Get`, `http.Post`, or `http.DefaultClient`

---

## JSON API

- MUST limit request body with `http.MaxBytesReader` (default 1MB)
- MUST use `json.NewDecoder` for requests. NEVER `json.Unmarshal` + `io.ReadAll`.
- API lists MUST return `[]`, NEVER `null`. Use `emit_empty_slices: true` in sqlc.
- JSON tags: `snake_case`. Tag all exported serialized fields.
- Validation in handler, BEFORE calling store. NEVER use validation libraries.
- `decode`, `encode`, `respondError` are unexported per-feature helpers (intentional duplication)
- Pagination: `limit` default 20, max 100. Empty result: `{"data": []}`.

---

## Database

### Stack (Non-Negotiable)

| Component | MUST Use | NEVER Use |
|-----------|----------|-----------|
| Driver | pgx/v5 (`pgxpool.Pool`) | database/sql |
| Queries | sqlc | raw SQL strings, ORM (gorm/ent/bun) |
| Testing | testcontainers-go (real PostgreSQL) | mocks, sqlmock, in-memory DB |
| Migrations | numbered SQL files | ORM migrations |

### Store Rules

- Constructor accepts `db.DBTX`, NEVER `*pgxpool.Pool` directly
- Provide `WithTx(tx pgx.Tx) *Store` for transaction support
- Map `pgx.ErrNoRows` to `ErrNotFound`
- NEVER expose `db.*` generated types outside store

### sqlc Rules

- ALL queries in `.sql` files with sqlc annotations
- Run `sqlc generate` after any SQL change, then `go build ./...`
- NEVER modify `internal/db/` by hand
- Use `emit_empty_slices: true`

### Schema Rules

- Every column MUST have `COMMENT ON COLUMN`
- Default to `NOT NULL`. Nullable requires documented justification.
- Enums: `TEXT` + `CHECK` constraint, document state machine
- Money: integer cents or `NUMERIC`, NEVER `FLOAT`
- Timestamps: always `TIMESTAMPTZ`
- UUIDs: `gen_random_uuid()` in database
- Foreign keys for all references, CHECK constraints for validation
- NEVER use JSONB to avoid schema design, NEVER use triggers for business logic

### Migrations

- Files: `NNN_description.up.sql` / `NNN_description.down.sql`
- Must be reversible. NEVER modify existing migrations.

---

## Security

### Critical

- NEVER build SQL with string concatenation or `fmt.Sprintf`
- NEVER hardcode secrets, API keys, passwords in source
- NEVER commit `.env` files
- MUST use `crypto/rand` for security-sensitive values
- MUST use parameterized queries (`$1`, `$2`) or sqlc

### Input Validation

- Validate ALL external input at handler boundary
- Validate path parameters, bound query parameters (limit 1-100)
- Reject absolute paths and `..` in user input (path traversal)
- NEVER pass user input to `exec.Command` through shell

### HTTP Security

- `Content-Type: application/json` + `X-Content-Type-Options: nosniff`
- `http.MaxBytesReader` for request body limits
- `MaxHeaderBytes` on `http.Server`
- `ReadTimeout`, `WriteTimeout`, `IdleTimeout`
- NEVER use `*` as CORS allowed origin in production

### Auth

- bcrypt or argon2 for passwords, NEVER MD5/SHA
- `subtle.ConstantTimeCompare` for tokens
- Auth checks BEFORE business logic

### Error Leakage

- 5xx: generic message, NEVER expose internals
- NEVER return stack traces, SQL errors, or file paths

---

## Concurrency

- Write synchronous functions by default. Let the CALLER add concurrency.
- Prefer `wg.Go(func() { ... })` over manual `Add/Done` (Go 1.25+)
- Every goroutine MUST have a documented exit condition. NEVER fire-and-forget.
- `context.Context` ALWAYS first parameter. NEVER store in struct. NEVER custom context types.
- Sender closes channels, NEVER the receiver.
- Long-running goroutines MUST check `ctx.Done()`.
- Use `errgroup` for concurrent operations that can fail.
- NEVER use `time.Sleep` for synchronization.
- NEVER start a goroutine without a plan for how it stops.
- NEVER hold a mutex during I/O.
- NEVER use unbounded `go func()` in a loop — use `errgroup` with `SetLimit()`.

### Context Values

- Allowed: request ID, authenticated user, trace span
- Key: unexported struct type (never `string` or `int`)
- NEVER store request body, DB connection, config, or logger in context

---

## Configuration

- All configuration from environment variables, loaded in `cmd/app/main.go` only
- Required values: `requireEnv()` + fail fast with `log.Fatalf`
- Optional values: `getEnv(key, fallback)`
- NEVER read `os.Getenv` inside business logic — pass as function parameters
- NEVER use config libraries (viper, envconfig) unless outgrown
- NEVER commit `.env` files
- Validate at startup, fail fast

---

## Observability

- MUST use `log/slog`. NEVER logrus, zap, zerolog, or custom wrappers.
- Keys: `snake_case`. Structured key-value pairs. No `fmt.Sprintf` in messages.
- NEVER log errors you also return — pick one
- NEVER log secrets, PII, connection strings, full request bodies
- OTel adoption: slog first -> otelhttp -> custom spans -> metrics
- Spans only at boundaries (HTTP, DB, external APIs), NEVER per-function

---

## Generics

Use ONLY for:
- Container-like helpers: `decode[T]`, `encode[T]`, collection utilities
- Type-safe wrappers where `any` would lose type info
- Functions identical on multiple types (>3 concrete implementations)

NEVER for:
- Avoiding 2-3 concrete functions
- Types with only one instantiation
- Domain types (`Store[T]` is wrong)

Prefer `any` over `interface{}`, `cmp.Ordered` for ordering, `comparable` for map keys.
Use `new(expr)` for pointer creation (Go 1.26+), replacing `ptr[T]` helpers.

---

## Git Workflow

### Commit Format

```
<type>: <description>

[optional body]
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`

- Lowercase, imperative, no period: `feat: add order creation endpoint`
- Body explains WHY, not WHAT
- One logical change per commit

### Before Committing

1. `go build ./...`
2. `go vet ./...`
3. `golangci-lint run ./...`
4. `go test ./...`

ALL must pass. Fix before committing.

### NEVER

- NEVER commit `.env`, credentials, secrets
- NEVER `git add .` or `git add -A` — stage specific files
- NEVER push directly to main without PR
- NEVER amend after hook failure — create new commit

---

## Go Philosophy — Hard Rules

These are patterns AI agents frequently violate. Treat as hard errors.

- NEVER use `SCREAMING_SNAKE_CASE` for constants. Use `MixedCaps`.
- NEVER use `interface{}`. Use `any`.
- NEVER use `math/rand` for security-sensitive values.
- NEVER add redundant `break` at end of `switch` case.
- NEVER shadow standard library package names with variables.
- NEVER use `var x = value` inside function when `x := value` is clearer.
- NEVER call `t.Fatal` from a goroutine.
- NEVER use `panic` for normal error handling.
- NEVER recover panics in business logic. Recovery ONLY in HTTP middleware and `main`.
- NEVER copy a struct containing `sync.Mutex` or `bytes.Buffer`.
- NEVER defer in a loop without extracting the body to a function.
- Avoid `init()`. Only acceptable for registering codecs/drivers.
- Every exported symbol MUST have a doc comment starting with the symbol name.

---

## Shared Skills (`.agents/skills/`)

The following Go reference skills are available in `.agents/skills/` (symlinked from `.claude/skills/`). Both Gemini CLI and Codex CLI auto-discover this directory.

| Skill | Topic |
|-------|-------|
| `api-design` | REST API design: pagination, filtering, error format, versioning |
| `auth-patterns` | JWT, auth middleware, RBAC, bcrypt, rate limiting |
| `config-management` | Env vars, type-safe config, validation, redaction |
| `docker-deploy` | Dockerfile, Docker Compose, K8s manifests |
| `error-patterns` | Error handling: sentinels, wrapping, domain-to-HTTP mapping |
| `genkit-go` | Genkit Go flows, tools, structured output |
| `devil-advocate` | Adversarial retroactive review: challenge existing decisions, detect drift |
| `go-compliance-test` | AI compliance traps, detection commands, self-check |
| `go-concurrency` | Goroutine lifecycle, errgroup, worker pools, channels |
| `go-doc` | Go 1.19+ doc comments, links, headings |
| `go-generics` | Generics: constraints, comparable pitfall, when to use |
| `go-interfaces` | Consumer-side interfaces, composition, testing |
| `go-iteration` | Range-over-func, iter.Seq, push vs pull (Go 1.23+) |
| `go-middleware` | Middleware ordering, chain composition |
| `go-modules` | go.mod, MVS, vendoring, go.work, build tags |
| `go-performance` | Pre-allocation, escape analysis, sync.Pool, pprof |
| `go-project-init` | Project init: feature scaffold or new project bootstrap |
| `manage-spec` | Add, list, validate skills/rules/hooks/agents |
| `go-reflection` | When to avoid reflect, struct tags, DeepEqual |
| `go-slog` | slog setup, logger injection, key naming, OTel correlation |
| `go-stdlib-patterns` | io, json, time, sort/slices, strings, context advanced |
| `go-testing-advanced` | Golden files, fixtures, coverage, go-cmp advanced |
| `go-types` | Value vs pointer, receivers, nil pitfalls, embedding |
| `go-unsafe` | When to avoid unsafe/cgo, cost analysis, safe alternatives |
| `graceful-shutdown` | Signal handling, connection draining, shutdown ordering |
| `http-server` | net/http Go 1.22+ routing and server patterns |
| `migrations` | golang-migrate numbered SQL migrations |
| `nats` | NATS Core + JetStream messaging |
| `otel-guide` | OpenTelemetry progressive adoption |
| `pgx-patterns` | pgx/v5 connection pooling, queries, transactions |
| `postgres-patterns` | PostgreSQL schema, indexing, migrations |
| `ristretto` | Ristretto in-memory cache patterns |
| `sqlc-guide` | sqlc configuration and query generation |
| `testcontainers` | testcontainers-go integration testing |
| `checkpoint` | Create git checkpoint before risky changes |
| `debug` | Structured 4-phase debugging (reproduce, diagnose, fix, verify) |
| `execute-plan` | Execute approved plan task-by-task with fresh subagents |
| `reflect` | Review session learnings, promote to memory/rules/skills |
| `tdd` | Strict RED-GREEN-REFACTOR test-driven development cycle |
| `verify` | Run full verification chain: build → vet → lint → test |

---

## Cross-Agent Setup

| Tool | Instructions | Skills | Hooks |
|------|-------------|--------|-------|
| **Claude Code** | `CLAUDE.md` (primary, richest) | `.claude/skills/` (36 skills) | `.claude/settings.json` |
| **Gemini CLI** | `AGENTS.md` (via `.gemini/settings.json`) | `.agents/skills/` (33 skills) | `.gemini/settings.json` |
| **Codex CLI** | `AGENTS.md` (native) | `.agents/skills/` (33 skills) | Not supported |
