You are writing comprehensive tests for a Go backend codebase that just
completed a major architecture audit (82→10 interfaces, zero adapters,
zero lint issues). The codebase is at stdlib quality. Tests must MATCH
that quality.

## Philosophy

Tests CHALLENGE code. They do not SERVE it.

- Every test tries to BREAK something
- If a test can't fail, it's not testing anything
- Error paths are MORE important than happy paths
- Adversarial cases are rows in the SAME table as happy-path cases, not separate functions

## Standards

1. Go standard library testing patterns
2. Google Go Style Guide (testing section)
3. Project rules: table-driven, go-cmp (never testify), t.Context(), b.Loop()
4. "Do not add interfaces for the sole purpose of testing" — use testcontainers for DB, not mocks

## Tech stack

Go 1.26+, net/http stdlib routing, PostgreSQL/pgx/v5, sqlc, Firebase Genkit AI,
testcontainers-go, Ristretto cache. See `.claude/rules/testing.md` for full rules.

## 16 Test Dimensions

### 1. Unit tests

- Table-driven with named cases, go-cmp for struct comparison
- Pure functions: every input/output combination, focus on edge cases
- Format: `FuncName(input) = got, want expected`
- t.Parallel() for independent cases, t.Helper() in helpers

### 2. Benchmark tests

- `b.Loop()` (Go 1.24+), NOT `for i := 0; i < b.N; i++`
- `b.ReportAllocs()` mandatory — primary signal is allocs/op, not ns/op
- Target: handler encode/decode, store hot paths, any per-request function
- Regression threshold: >0 new allocs/op for hot-path pure functions

### 3. Fuzz tests

- Every function that parses external input: JSON decode, date parsing,
  tag normalization, query parameter parsing, Obsidian frontmatter
- Goal: function must not panic on ANY input
- `f.Add()` with representative seeds including edge cases
- `-fuzztime=30s` minimum

### 4. Integration tests

- `//go:build integration` tag
- testcontainers-go with real PostgreSQL — NEVER mock the database
- Test actual SQL: constraint violations (unique, FK, CHECK), pgx error mapping
- `t.Cleanup()` for ALL resources, even when test panics
- Test: insert → read → verify, concurrent writes, constraint violations

### 5. Adversarial inputs (failure table rows)

- Adversarial cases are rows in the SAME table-driven test, not separate functions
- For every handler: malformed JSON, missing required fields, invalid UUIDs,
  SQL injection payloads, XSS strings, oversized bodies, null bytes
- For every store: duplicate inserts (ErrConflict), non-existent IDs (ErrNotFound)
- Goal: find logic bugs, not confirm happy paths

### 6. Race condition tests

- `go test -race` on ALL packages
- Explicit concurrent access tests for shared state:
  - Ristretto caches (content, topic)
  - Rate limiter map (server/middleware)
  - DeduplicationCache (webhook)
  - sync.Map in notion handler (syncInFlight)
  - Event bus (concurrent Emit + On)

### 7. Error injection tests

- Simulate: DB connection drop, context cancellation mid-query,
  API timeout, malformed external response
- Verify: handler returns proper HTTP status, error is logged (not swallowed),
  partial state is not persisted
- Test graceful degradation: MCP morning context with partial failures

### 8. Contract tests

- `var _ Interface = (*Type)(nil)` for every interface satisfaction
- Sentinel error mapping: `pgx.ErrNoRows` → `ErrNotFound`,
  unique violation (23505) → `ErrConflict`
- Verify every store's error mapping is correct

### 9. Boundary value tests

- nil pointer fields, zero-value structs, empty strings, empty slices
- Max int32 for pagination limits, max int64 for IDs
- Unicode: Chinese characters, emoji, RTL text, zero-width characters
- Dates: epoch, far future, timezone boundaries, DST transitions

### 10. Security tests

- SQL injection: `'; DROP TABLE --` in every text input
- Path traversal: `../../etc/passwd` in file paths and slugs
- Auth bypass: missing JWT, expired JWT, wrong audience, tampered signature
- HMAC forgery: modified webhook body with original signature
- CSRF: state-changing requests without proper origin
- Size limits: oversized request bodies, oversized external responses

### 11. Concurrency tests

- Goroutine leak detection: test that background goroutines stop on context cancel
- Channel behavior: full channels, closed channels, nil channels
- errgroup error propagation: one goroutine fails → all cancelled
- Mutex contention: concurrent read/write to protected state

### 12. Regression tests

- Every bug found during audit gets a named test case
- Test name format: `TestRegression_IssueDescription`
- Bugs to cover:
  - O'Reilly/collector unbounded response (now bounded)
  - OAuth unbounded client registration (now capped)
  - Goal handler silent status default (now returns 400)
  - ParsePagination returning default instead of clamp
  - statusWriter missing Unwrap (now present)

### 13. synctest (Go 1.26+)

- `testing/synctest.Run` for time-dependent behavior
- DeduplicationCache TTL expiry — deterministic, no time.Sleep
- Rate limiter stale entry eviction
- Cron-like timeout behavior
- Pipeline retry backoff (if applicable)

### 14. Golden file tests

- AI flow output shape regression: `testdata/*.golden`
- Run with `-update` flag to re-record
- Compare structure (field presence, types) not exact values
- Applicable to: content-review, digest, morning brief output shapes

### 15. Idempotency tests

- Webhook: same delivery ID twice → only one record
- Cron: run reconciler twice without changes → state unchanged
- Notion sync: same page update twice → idempotent upsert
- Pipeline: same GitHub push event replayed → deduplication works

### 16. HTTP contract tests

- Every handler: assert exact JSON field names and structure
- Use go-cmp with cmpopts.IgnoreFields for dynamic values (IDs, timestamps)
- Golden file approach: `testdata/handler_response.golden`
- Catches: field renames, added/removed fields, type changes
- Frontend depends on these contracts — breaking change = test failure

## Package priority (by risk)

### Critical (test first)

| Package   | LOC   | Risk | Why                                                    |
| --------- | ----- | ---- | ------------------------------------------------------ |
| notion    | 1200+ | HIGH | Webhook routing, Notion sync, new callback design      |
| pipeline  | 900+  | HIGH | GitHub webhook, content/note sync orchestration        |
| ai/exec   | 500+  | HIGH | Flow dispatch, worker pool, retry logic                |
| reconcile | 400+  | HIGH | Cross-feature drift detection (tests deleted in audit) |

### High

| Package        | LOC   | Risk | Why                                              |
| -------------- | ----- | ---- | ------------------------------------------------ |
| auth           | 600+  | HIGH | OAuth, JWT, refresh rotation — security critical |
| mcp            | 3000+ | HIGH | 20+ tools, external protocol boundary            |
| feed/collector | 400+  | HIGH | External RSS fetching, scoring                   |

### Medium (existing tests, extend coverage)

| Package | LOC  | Has tests? | Extend with                                |
| ------- | ---- | ---------- | ------------------------------------------ |
| content | 800+ | Yes        | Adversarial, boundary, contract            |
| tag     | 400+ | Yes        | Fuzz (normalization), security             |
| note    | 500+ | Yes        | Fuzz (search), golden (RRF merge)          |
| server  | 300+ | Yes        | Security (middleware), race (rate limiter) |
| upload  | 200+ | Yes        | Security (path traversal strengthening)    |

### Low (simple CRUD, extend when touching)

activity, budget, event, feed, feed/entry, goal, learning, monitor,
obsidian, project, review, session, stats, topic

## Test file naming

- `<feature>_test.go` — unit + adversarial + boundary + contract
- `<feature>_integration_test.go` — `//go:build integration`, testcontainers
- `<feature>_bench_test.go` — benchmarks (if separate file needed)
- `testdata/*.golden` — golden files

## Commands

```bash
# Unit + adversarial + boundary + contract + race
go test -race -count=1 ./...

# Benchmarks
go test -bench=. -benchmem ./internal/<pkg>/...

# Fuzz
go test -fuzz=FuzzParseXxx ./internal/<pkg>/... -fuzztime=30s

# Integration (requires Docker)
go test -tags integration -race ./...

# Full suite
go test -race -count=1 ./... && go test -bench=. -benchmem ./... && go test -tags integration -race ./...

What to output

For each package tested:
1. What tests written (count by dimension)
2. What bugs found (if any — fix AND add regression test)
3. What edge cases discovered
4. Coverage delta

Start with Critical packages, then High, then Medium.
```
