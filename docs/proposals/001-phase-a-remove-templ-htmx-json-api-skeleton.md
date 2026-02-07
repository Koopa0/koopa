# Proposal 001: Phase A — Remove Templ/HTMX, Build JSON API Skeleton

> Status: PENDING REVIEW
> Author: Claude Code
> Date: 2026-02-04

---

## Summary

Remove all Templ/HTMX/SSE frontend code from `internal/web/`, migrate business logic to a new `internal/api/` package, and establish a JSON REST API skeleton. This is an atomic operation — `koopa serve` must work before and after.

---

## 2.1 Proposed Directory Structure

```
internal/api/
├── server.go                   # HTTP server, route registration, CORS, security headers
├── response.go                 # JSON response helpers: WriteJSON, WriteError, standard envelope
├── middleware/
│   ├── recovery.go             # Panic recovery (from web/middleware.go)
│   ├── logging.go              # Request logging (from web/middleware.go)
│   ├── cors.go                 # CORS for Angular dev server (NEW)
│   └── auth.go                 # Session cookie + CSRF validation (from web/handlers/sessions.go + web/middleware.go)
└── v1/
    ├── chat.go                 # POST /api/v1/chat/send, GET /api/v1/chat/stream (JSON SSE)
    ├── chat_test.go            # Chat handler tests (JSON response validation)
    ├── sessions.go             # GET/POST/DELETE /api/v1/sessions, session auth logic
    ├── sessions_test.go        # Session handler tests
    ├── health.go               # GET /api/v1/health, GET /api/v1/ready
    └── health_test.go          # Health handler tests
```

### Design Rationale

**Why `internal/api/` not `internal/web/` rename?**
- Clean break. No leftover references to templ/htmx imports.
- `internal/web/` will be re-used later for Angular `dist/` embedding (Phase B+).

**Why `v1/` versioning?**
- API versioning from day one. Angular client will target `/api/v1/`.
- Future breaking changes go to `v2/` without disrupting existing clients.

**Why `middleware/` as a sub-package?**
- Follows existing pattern separation (middleware was already logically separate in `web/middleware.go`).
- Allows middleware to be tested independently.

**Why `response.go` at package root?**
- Shared by all `v1/` handlers. Avoids circular imports.
- Single source of truth for JSON envelope format.

---

## Response Envelope

All JSON responses follow a consistent envelope:

```go
// internal/api/response.go

// Envelope is the standard JSON response wrapper.
type Envelope struct {
    Data  any    `json:"data,omitempty"`
    Error *Error `json:"error,omitempty"`
}

type Error struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

func WriteJSON(w http.ResponseWriter, status int, data any) { ... }
func WriteError(w http.ResponseWriter, status int, code, message string) { ... }
```

---

## Route Mapping (Old → New)

| Old Route | New Route | Method | Handler | Notes |
|-----------|-----------|--------|---------|-------|
| `GET /genui` | _(removed)_ | — | — | Page rendering, replaced by Angular |
| `POST /genui/send` | `POST /api/v1/chat/send` | POST | `v1.Chat.Send` | Returns JSON instead of HTML |
| `GET /genui/stream` | `GET /api/v1/chat/stream` | GET | `v1.Chat.Stream` | JSON SSE (not HTML SSE) |
| `GET /genui/sessions` | `GET /api/v1/sessions` | GET | `v1.Sessions.List` | JSON array |
| `POST /genui/sessions` | `POST /api/v1/sessions` | POST | `v1.Sessions.Create` | JSON response |
| `DELETE /genui/sessions/{id}` | `DELETE /api/v1/sessions/{id}` | DELETE | `v1.Sessions.Delete` | JSON response |
| `GET /health` | `GET /api/v1/health` | GET | `v1.Health.Health` | Same logic |
| `GET /ready` | `GET /api/v1/ready` | GET | `v1.Health.Ready` | Same logic |
| — | `OPTIONS /api/v1/*` | OPTIONS | CORS middleware | NEW: Preflight |

---

## Streaming Strategy

The SSE **transport protocol** is kept (it's standard HTTP, not HTMX-specific). What changes is the **content format**:

**Before (HTML SSE)**:
```
event: chunk
data: <div hx-swap-oob="innerHTML:#msg-123">Hello</div>

event: done
data: <div hx-swap-oob="outerHTML:#msg-123">...</div>
```

**After (JSON SSE)**:
```
event: chunk
data: {"msgId":"abc-123","text":"Hello"}

event: tool_start
data: {"msgId":"abc-123","tool":"web_search","message":"Searching..."}

event: tool_complete
data: {"msgId":"abc-123","tool":"web_search","message":"Done"}

event: done
data: {"msgId":"abc-123","sessionId":"xyz","title":"Chat Title"}

event: error
data: {"msgId":"abc-123","code":"timeout","message":"Request timed out"}
```

This preserves the existing streaming architecture (Genkit Flow → SSE) while making the output consumable by Angular's `EventSource` API. The SSE writer is rewritten as a simple JSON event writer in `internal/api/v1/chat.go` — no separate `sse/` package needed.

---

## Middleware Stack

```
Request
  → CORS (new)
  → Recovery (from web/middleware.go)
  → Logging (from web/middleware.go)
  → Auth (session cookie + CSRF, from web/middleware.go + handlers/sessions.go)
  → Route handler
```

**CORS middleware** (`middleware/cors.go`):
- Reads allowed origins from config (`KOOPA_CORS_ORIGINS`, default: `http://localhost:4200`)
- Handles preflight `OPTIONS` requests (204 No Content)
- Sets `Access-Control-Allow-Origin`, `Allow-Methods`, `Allow-Headers`, `Allow-Credentials`

**Auth middleware** (`middleware/auth.go`):
- Consolidates session cookie reading + CSRF validation from the old `RequireSession` + `RequireCSRF` + `Sessions` struct.
- HMAC-SHA256 token logic preserved exactly as-is.
- Pre-session CSRF pattern preserved for lazy session creation.
- CSRF token read from `X-CSRF-Token` header (instead of form field) for JSON API compatibility.

**MethodOverride middleware**: Removed. JSON API uses proper HTTP methods directly.

---

## Business Logic Migration Map

| Source | Destination | What Migrates |
|--------|-------------|---------------|
| `web/middleware.go` RecoveryMiddleware | `api/middleware/recovery.go` | Panic catch, error response (→ JSON) |
| `web/middleware.go` LoggingMiddleware | `api/middleware/logging.go` | Request logging (unchanged) |
| `web/middleware.go` RequireSession | `api/middleware/auth.go` | Lazy session creation logic |
| `web/middleware.go` RequireCSRF | `api/middleware/auth.go` | CSRF validation logic |
| `web/handlers/sessions.go` HMAC logic | `api/middleware/auth.go` | Token gen/validation (unchanged) |
| `web/handlers/sessions.go` cookie logic | `api/middleware/auth.go` | Cookie set/read (unchanged) |
| `web/handlers/sessions.go` List/Create/Delete | `api/v1/sessions.go` | CRUD → JSON responses |
| `web/handlers/chat.go` Send | `api/v1/chat.go` | Content validation, session handling → JSON |
| `web/handlers/chat.go` Stream | `api/v1/chat.go` | Flow streaming → JSON SSE |
| `web/handlers/chat.go` title gen | `api/v1/chat.go` | AI title generation (unchanged) |
| `web/handlers/chat.go` error classify | `api/v1/chat.go` | Error classification (unchanged) |
| `web/handlers/health.go` | `api/v1/health.go` | Health probes (unchanged) |
| `web/handlers/tool_display.go` | `api/v1/chat.go` (inline) | Tool display messages (simplified) |
| `web/handlers/convert.go` extractTextContent | `api/v1/sessions.go` | Message text extraction (unchanged) |
| `web/sse/writer.go` SSE format | `api/v1/chat.go` (inline) | SSE protocol (`event:`, `data:`, flush) |

---

## What Gets Deleted (No Migration)

| File/Dir | Reason |
|----------|--------|
| `internal/web/page/` | Templ page templates |
| `internal/web/layout/` | Templ layout templates |
| `internal/web/component/` | Templ components + 222 reference blocks |
| `internal/web/static/` | CSS, JS, embedded assets |
| `internal/web/sse/` | HTML SSE writer (replaced by inline JSON SSE) |
| `internal/web/e2e/` | Playwright test assets |
| `internal/web/handlers/htmx.go` | HTMX detection helper |
| `internal/web/handlers/pages.go` | HTML page rendering |
| `internal/web/handlers/tool_emitter.go` | SSE-specific tool emitter |
| `internal/web/fixture_test.go` | Playwright fixtures |
| `internal/web/e2e_*.go` | All E2E browser tests |
| `internal/web/server_test.go` | Tests for HTML server |
| `internal/web/static/assets_test.go` | Tests for embedded assets |
| `build/frontend/` | Tailwind CSS build config |

---

## Wire DI Impact

**No changes to `wire.go` or `wire_gen.go`.**

`web.NewServer` was never part of Wire — it's created manually in `cmd/serve.go`. The new `api.NewServer` will also be created manually in `cmd/serve.go`, using the same Runtime components.

---

## cmd/serve.go Changes

```go
// Before
webServer, err := web.NewServer(web.ServerConfig{
    Logger:       logger,
    Genkit:       runtime.App.Genkit,
    ChatFlow:     runtime.Flow,
    SessionStore: runtime.App.SessionStore,
    CSRFSecret:   []byte(cfg.HMACSecret),
    Config:       cfg,
})

// After
apiServer := api.NewServer(api.ServerConfig{
    Logger:       logger,
    Genkit:       runtime.App.Genkit,
    ChatFlow:     runtime.Flow,
    SessionStore: runtime.App.SessionStore,
    CSRFSecret:   []byte(cfg.HMACSecret),
    CORSOrigins:  cfg.CORSOrigins,
    IsDev:        cfg.Debug,
})
```

---

## Config Changes

**New fields in `config.Config`**:
```go
CORSOrigins []string // from KOOPA_CORS_ORIGINS, default: ["http://localhost:4200"]
```

**New env vars in `.env.example`**:
```bash
KOOPA_CORS_ORIGINS=http://localhost:4200  # Comma-separated allowed origins
```

**Removed env vars**: None. `HMAC_SECRET` stays (still used for CSRF).

---

## Dependency Removal

| Dependency | Action | Reason |
|------------|--------|--------|
| `github.com/a-h/templ` | Remove | No more templ templates |
| `github.com/playwright-community/playwright-go` | Remove | Only used in `internal/web/` E2E tests |

Verified: `cmd/e2e_test.go` does NOT use playwright (uses `os/exec` only).

---

## Taskfile.yml Changes

| Task | Action |
|------|--------|
| `css` | Remove |
| `css:watch` | Remove |
| `generate` | Change to `sqlc generate` only (remove `templ generate`) |
| `install:templ` | Remove |
| `install:npm` | Remove (no more build/frontend) |
| `build` | Remove templ/css deps |
| `build:dev` | Remove templ/css deps |
| `test:e2e` | Remove |
| `fmt` | Remove `templ fmt` |
| `dev` | Remove templ/css generation |

---

## Acceptance Criteria

All criteria from the user's spec apply. Additionally:

1. `go build ./...` — zero errors
2. `golangci-lint run ./...` — no errors
3. `go test ./...` — all pass (deleted web tests excluded)
4. `go vet ./...` — clean
5. `koopa serve` — starts, responds to `/api/v1/health`
6. `koopa` (CLI) — unaffected
7. `koopa mcp` — unaffected
8. CORS preflight returns 204 with correct headers
9. No `.templ` files remain
10. No `htmx` references in Go code
11. No `github.com/a-h/templ` in go.mod
12. `internal/web/` directory does not exist

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Wire DI breaks | Wire is not involved — server created in cmd/serve.go |
| Import cycle | `api/` depends on `session/`, `agent/chat/`, `config/` — same as `web/` did |
| Missing business logic | Comprehensive migration map above; each handler verified |
| Streaming breaks | SSE transport preserved, only content format changes (HTML → JSON) |
| Tests fail | Migrated tests adapted to JSON assertions |
| go.mod stale deps | `go mod tidy` cleans up automatically |
