# Proposal 003: Naming Conventions & Dead Code Cleanup

## Overview

Based on full-codebase go-reviewer and security-reviewer findings (post-Proposal 002), this proposal addresses Go naming convention violations and dead code in the session layer.

**Scope**: `session.Store` method renames, dead code removal, `clientIP()` security fix.
**Risk**: Medium — public API rename across multiple consumers, but zero interface breakage.
**Tier**: 2 (existing feature modification, no new packages or types).

### Reviewer Status

- go-reviewer: 0 BLOCKING, 3 WARNING, 3 SUGGESTION — all addressed below
- security-reviewer: 0 CRITICAL, 1 HIGH, 3 MEDIUM — all addressed below

---

## Phase 1: Remove Dead Code (Low Risk)

Remove 2 exported methods on `session.Store` that have **zero callers and zero tests**, plus their associated sentinel error.

### 1.1 Delete `GetUserMessageBefore`

**File**: `internal/session/store.go:611-658`
**Evidence**: Comprehend agent confirmed 0 production callers, 0 test callers.
**SQL**: `db/queries/sessions.sql:104-113` — `-- name: GetUserMessageBefore :one`

Delete the Store method and remove the SQL query.

### 1.2 Delete `GetMessageByID`

**File**: `internal/session/store.go:660-676`
**Evidence**: Comprehend agent confirmed 0 production callers, 0 test callers.
**SQL**: `db/queries/sessions.sql:115-119` — `-- name: GetMessageByID :one`

Same approach — delete Store method and SQL query.

### 1.3 Delete `ErrMessageNotFound`

**File**: `internal/session/errors.go:42-43`

After removing the two methods above, `ErrMessageNotFound` has zero remaining references. Remove the sentinel error to avoid dead code.
(go-reviewer SUGGESTION #1 — confirmed via grep: all 5 usages are within the two deleted methods)

### 1.4 Update doc.go

Remove any references to deleted methods in `internal/session/doc.go`.

### 1.5 Regenerate sqlc

```bash
cd build/sql && sqlc generate
```

This removes the generated code for the two deleted SQL queries.

### Verification

```bash
go build ./...      # Confirms no broken references
go vet ./...        # Static analysis
go test ./...       # No test regression (methods had 0 tests)
```

---

## Phase 2: Rename Store Methods (Medium Risk)

Remove `Get` prefix from 3 `session.Store` getter methods per `naming.md`:
> "No `Get` prefix for getters"

### 2.1 Rename SQL Queries

**File**: `db/queries/sessions.sql`

| Before | After | Line |
|--------|-------|------|
| `-- name: GetSession :one` | `-- name: Session :one` | 9 |
| `-- name: GetMessages :many` | `-- name: Messages :many` | 53 |

**Note**: `GetHistory` has no SQL query (it's composed in Go from `Session` + `Messages`).

### 2.2 Regenerate sqlc

```bash
cd build/sql && sqlc generate
```

This produces cascading changes in `internal/sqlc/sessions.sql.go`:
- `func (q *Queries) GetSession(...)` -> `func (q *Queries) Session(...)`
- `func (q *Queries) GetMessages(...)` -> `func (q *Queries) Messages(...)`
- `type GetMessagesParams` -> `type MessagesParams`

### 2.3 Rename `session.Store` Methods

**File**: `internal/session/store.go`

| Before | After | Line |
|--------|-------|------|
| `func (s *Store) GetSession(...)` | `func (s *Store) Session(...)` | 90 |
| `func (s *Store) GetMessages(...)` | `func (s *Store) Messages(...)` | 323 |
| `func (s *Store) GetHistory(...)` | `func (s *Store) History(...)` | 404 |

Internal self-calls within `store.go`:
- Line 406: `s.GetSession(ctx, sessionID)` -> `s.Session(ctx, sessionID)`
- Line 417: `s.GetMessages(ctx, sessionID, limit, 0)` -> `s.Messages(ctx, sessionID, limit, 0)`

Internal sqlc calls:
- Line 91: `s.queries.GetSession(ctx, sessionID)` -> `s.queries.Session(ctx, sessionID)`
- Line 324: `s.queries.GetMessages(ctx, sqlc.GetMessagesParams{...})` -> `s.queries.Messages(ctx, sqlc.MessagesParams{...})`

### 2.4 Update Production Callers

| File | Line | Before | After |
|------|------|--------|-------|
| `cmd/cli.go` | 64 | `store.GetSession(ctx, *currentID)` | `store.Session(ctx, *currentID)` |
| `internal/api/session.go` | 57 | `sm.store.GetSession(r.Context(), sessionID)` | `sm.store.Session(r.Context(), sessionID)` |
| `internal/api/session.go` | 268 | `sm.store.GetSession(r.Context(), sessionID)` | `sm.store.Session(r.Context(), sessionID)` |
| `internal/api/session.go` | 313 | `sm.store.GetSession(r.Context(), id)` | `sm.store.Session(r.Context(), id)` |
| `internal/api/chat.go` | 321 | `h.sessions.store.GetSession(ctx, sessionUUID)` | `h.sessions.store.Session(ctx, sessionUUID)` |
| `internal/api/session.go` | 340 | `sm.store.GetMessages(r.Context(), id, 100, 0)` | `sm.store.Messages(r.Context(), id, 100, 0)` |
| `internal/agent/chat/chat.go` | 248 | `c.sessions.GetHistory(ctx, sessionID)` | `c.sessions.History(ctx, sessionID)` |

**7 production call sites total.**

### 2.5 Update Test Files

Approximately ~40 test call sites across:
- `internal/session/integration_test.go` (~30 sites)
- `internal/session/benchmark_test.go` (~10 sites)

All are direct `store.GetSession(...)`, `store.GetMessages(...)`, `store.GetHistory(...)` calls -> rename to `store.Session(...)`, `store.Messages(...)`, `store.History(...)`.

**Note on `internal/api/session_test.go`**: 4 test functions contain `GetSession`/`GetSessionMessages` in their names (`TestGetSession_InvalidUUID`, `TestGetSession_MissingID`, `TestGetSessionMessages_InvalidUUID`, `TestGetSessionMessages_OwnershipDenied`). These test the HTTP handler methods (`sm.getSession`, `sm.getSessionMessages`) which are *unexported* and *not* being renamed. The test function names are **intentionally left unchanged** as they reference the handler, not the Store method.
(go-reviewer SUGGESTION #2 — addressed)

### 2.6 Update Documentation

- `internal/session/doc.go` — update method name references
- `internal/session/errors.go:34` — update doc comment example `store.GetSession(ctx, id)` -> `store.Session(ctx, id)`
- `internal/agent/chat/doc.go` — update `GetHistory` reference

(go-reviewer WARNING #1 — `errors.go` doc comment added to list)

### Verification

```bash
cd build/sql && sqlc generate   # Regenerate
go build ./...                  # Compile check
go vet ./...                    # Static analysis
golangci-lint run ./...         # 0 issues
go test -race ./...             # Full test suite
```

---

## Phase 3: Fix clientIP() Proxy Header Trust (Low-Medium Risk)

### Problem

`internal/api/middleware.go:363-383` — `clientIP()` unconditionally trusts `X-Forwarded-For` header. Any client can spoof this header to bypass rate limiting.
(security-reviewer H2 — current vulnerability being fixed)

### Fix

Add a `TrustProxy` configuration option. When `false` (default), ignore proxy headers entirely. When `true`, prefer `X-Real-IP` over `X-Forwarded-For` to prevent spoofing.
(security-reviewer H1 — switched to X-Real-IP priority to avoid leftmost-XFF spoofing)

#### 3.1 Add config chain

**File**: `internal/config/config.go`
- Add `TrustProxy bool` field to config struct
- Add `viper.SetDefault("trust_proxy", false)` in `setDefaults`
- Add `mustBind("trust_proxy", "KOOPA_TRUST_PROXY")` in `bindEnvVariables`

(security-reviewer M2 — full config wiring)

**File**: `config.example.yaml`
- Add `trust_proxy: false` with comment explaining when to set `true`

(security-reviewer M1 — migration note for existing proxy deployments)

#### 3.2 Wire through ServerConfig

**File**: `internal/api/server.go`

```go
type ServerConfig struct {
    // ... existing fields ...
    TrustProxy  bool     // Trust X-Real-IP/X-Forwarded-For headers (set true behind reverse proxy)
}
```

**File**: `cmd/serve.go` — pass `cfg.TrustProxy` into `api.ServerConfig`

#### 3.3 Update clientIP function

**File**: `internal/api/middleware.go`

```go
// clientIP extracts the client IP from the request.
// If trustProxy is true, checks X-Real-IP first (single-valued, set by proxy),
// then X-Forwarded-For. Validates extracted IP with net.ParseIP.
// Otherwise, uses RemoteAddr only (safe default for direct exposure).
func clientIP(r *http.Request, trustProxy bool) string {
    if trustProxy {
        // Prefer X-Real-IP: single value set by the reverse proxy, not spoofable
        if xri := r.Header.Get("X-Real-IP"); xri != "" {
            ip := strings.TrimSpace(xri)
            if net.ParseIP(ip) != nil {
                return ip
            }
        }
        // Fallback: X-Forwarded-For (first entry, client-provided — less trustworthy)
        if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
            raw, _, _ := strings.Cut(xff, ",")
            ip := strings.TrimSpace(raw)
            if net.ParseIP(ip) != nil {
                return ip
            }
        }
    }

    ip, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    return ip
}
```

Key changes from original proposal (per security review):
1. **X-Real-IP checked first** — single value set by trusted proxy, not appendable by client (H1 fix)
2. **`net.ParseIP` validation** — rejects garbage values, falls back to RemoteAddr (M3 fix)
3. **`trustProxy` parameter** — gated by config, default `false` (existing fix)

(security-reviewer H1 + M3 — addressed)

#### 3.4 Update rateLimitMiddleware

**File**: `internal/api/middleware.go`

Pass `trustProxy` through closure to `clientIP`:

```go
func rateLimitMiddleware(rl *rateLimiter, trustProxy bool, logger *slog.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ip := clientIP(r, trustProxy)
            // ... rest unchanged
        })
    }
}
```

Update call site in `server.go:83` to pass `cfg.TrustProxy`.

#### 3.5 Update tests

**File**: `internal/api/middleware_test.go`

- Update all 6 `clientIP(r)` calls to `clientIP(r, true)` for existing proxy-trust test cases
- Add new test cases for `clientIP(r, false)` verifying proxy headers are ignored
- Add test case for invalid IP in proxy header (falls back to RemoteAddr)

(go-reviewer WARNING #2 + SUGGESTION #3 — middleware_test.go added to file list)

### Verification

```bash
go build ./...
go vet ./...
golangci-lint run ./...
go test -race ./...
```

---

## Out of Scope

- RAG non-atomic upsert — documented, low-risk, runs only at startup
- Secret masking improvements — cosmetic, no security impact
- sqlc `emit_interface` change — unnecessary (no consumers need an interface)
- `GetMaxSequenceNumber` rename — not a getter on Store, it's an internal sqlc query name
- `TestGetSession_*` test function renames in `api/session_test.go` — test HTTP handlers, not Store

---

## Implementation Order

| Step | Phase | Files Modified | Risk |
|------|-------|---------------|------|
| 1 | Phase 1 | store.go, sessions.sql, errors.go, doc.go | Low |
| 2 | sqlc regenerate | `cd build/sql && sqlc generate` | None |
| 3 | Phase 2 | sessions.sql, store.go, cli.go, session.go, chat.go, doc.go, errors.go, tests | Medium |
| 4 | sqlc regenerate | `cd build/sql && sqlc generate` | None |
| 5 | Phase 3 | config.go, server.go, serve.go, middleware.go, middleware_test.go, config.example.yaml | Low-Medium |
| 6 | Full verification | — | — |

Each phase is independently verifiable. Phases 1+2 can be combined into a single sqlc regeneration if committed together.
(go-reviewer SUGGESTION #4 — sqlc path made consistent, combination noted)

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Missed call site breaks build | `go build ./...` catches immediately |
| sqlc param type rename missed | Compiler error on `sqlc.GetMessagesParams` |
| Test name references old method | Find-and-replace + `go test` catches |
| `clientIP` signature change breaks callers | Only 1 production call site + 6 test calls; compiler catches |
| TrustProxy default=false behind proxy | Documented migration: set `KOOPA_TRUST_PROXY=true` or `trust_proxy: true` |

---

## Estimated Edit Count

| Phase | Files | Edit Sites |
|-------|-------|-----------|
| Phase 1 (dead code) | 4 | ~7 |
| Phase 2 (rename) | 9 | ~50 |
| Phase 3 (clientIP) | 6 | ~15 |
| **Total** | **~15** | **~72** |
