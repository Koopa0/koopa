# Proposal 002: v0.2.0 Comprehensive Refactoring

## Overview

Based on a full-codebase comprehension (5 parallel agents analyzed every layer), this proposal defines a phased refactoring plan to bring Koopa to production quality.

**Scope**: From `main.go` to every internal package. All 3 modes (CLI, API, MCP) preserved.
**Priority**: CLI + HTTP API first, MCP in parallel where non-conflicting.
**Framework**: Genkit as core AI orchestration, Bubble Tea v2 for TUI.
**Storage**: PostgreSQL + pgvector retained as required dependency.

---

## Phase 1: Critical Bug Fixes (Low Risk, Immediate)

No architecture changes. Pure bug fixes with existing patterns.

### 1.1 Fix `listenForStream()` Stack Overflow

**File**: `internal/tui/commands.go`
**Problem**: Recursive call on empty events can overflow stack.
**Fix**: Replace recursion with `for` loop.

```go
// Before (recursive):
default:
    return listenForStream(eventCh)()

// After (iterative):
for {
    event, ok := <-eventCh
    if !ok { return streamErrorMsg{err: ...} }
    if event.err != nil { return streamErrorMsg{...} }
    if event.done { return streamDoneMsg{...} }
    if event.text != "" { return streamTextMsg{...} }
    // empty event: loop instead of recurse
}
```

### 1.2 Fix `truncateHistory` Break Logic

**File**: `internal/agent/chat/tokens.go`
**Problem**: Uses `break` instead of `continue`, drops old small messages after first large one.
**Fix**: Change `break` to `continue`.

### 1.3 Remove Ghost `knowledge_store` Reference

**File**: `internal/api/chat.go:59`
**Problem**: UI message references a tool that doesn't exist.
**Fix**: Remove the `knowledge_store` entry from toolDisplayMessages map.

### 1.4 Remove Dead `NormalizeMaxHistoryMessages`

**File**: `internal/config/validation.go`
**Problem**: Function defined but never called.
**Fix**: Delete the function (validation already handles range checks in `Validate()`).

### 1.5 Fix RAG Non-Atomic UPSERT

**File**: `internal/rag/system.go`
**Problem**: Delete + Insert without transaction; delete failure silently swallowed.
**Fix**: Wrap in PostgreSQL transaction.

---

## Phase 2: Remove Wire, Simplify DI (Medium Risk)

Wire adds indirection and `wire_gen.go` is hand-maintained despite claiming to be generated.

### 2.1 Replace Wire with Manual DI

**Delete**: `internal/app/wire.go`, `internal/app/wire_gen.go`
**Modify**: `internal/app/app.go`

Replace Wire-generated `InitializeApp()` with explicit construction:

```go
func InitializeApp(ctx context.Context, cfg *config.Config) (*App, func(), error) {
    // 1. OTel setup
    otelShutdown, err := observability.Setup(ctx, cfg.Datadog)

    // 2. DB pool + migrations
    pool, err := connectDB(ctx, cfg)

    // 3. Genkit init
    g := initGenkit(ctx, cfg)

    // 4. Embedder
    embedder := lookupEmbedder(g, cfg)

    // 5. RAG components
    docStore, retriever := initRAG(ctx, g, pool, embedder, cfg)

    // 6. Session store
    sessionStore := session.NewStore(pool)

    // 7. Security validators
    pathValidator := security.NewPath(...)

    // 8. Tools
    tools := registerTools(g, pathValidator, ...)

    // 9. Construct App
    app := &App{...}

    cleanup := func() {
        pool.Close()
        otelShutdown(ctx)
    }

    return app, cleanup, nil
}
```

### 2.2 Unify Tool Registration

**Problem**: Tools are created twice — once for Genkit (wire.go), once for MCP (cmd/mcp.go).
**Fix**: Create tools once, register to both Genkit and MCP from same instances.

```go
// internal/tools/registry.go (new file)
type Registry struct {
    File      *FileTools
    System    *SystemTools
    Network   *NetworkTools
    Knowledge *KnowledgeTools
}

func NewRegistry(pathValidator *security.Path, ...) *Registry { ... }

// Register to Genkit
func (r *Registry) RegisterGenkit(g *genkit.Genkit) ([]ai.Tool, error) { ... }
```

MCP server accepts `*tools.Registry` instead of individual tool structs.

### 2.3 Refactor App Struct

Split the God Object into focused structs:

```go
type App struct {
    Config  *config.Config
    AI      *AIComponents    // Genkit, Embedder
    Storage *StorageComponents // DBPool, DocStore, Retriever, SessionStore
    Tools   *tools.Registry

    // Lifecycle
    ctx    context.Context
    cancel context.CancelFunc
    eg     *errgroup.Group
}

type AIComponents struct {
    Genkit   *genkit.Genkit
    Embedder ai.Embedder
}

type StorageComponents struct {
    Pool         *pgxpool.Pool
    DocStore     *postgresql.DocStore
    Retriever    ai.Retriever
    SessionStore *session.Store
}
```

---

## Phase 3: TUI Upgrade to Bubble Tea v2 (High Value)

### 3.1 Dependency Upgrade

```
charm.land/bubbletea/v2
charm.land/bubbles/v2
charm.land/lipgloss/v2
github.com/charmbracelet/glamour  (for markdown rendering)
```

### 3.2 Rewrite TUI with v2 Patterns

**Key changes**:
- `View()` returns `tea.View` struct (declarative altscreen, cursor)
- `tea.KeyPressMsg` replaces `tea.KeyMsg`
- `tea.PasteMsg` for multi-line paste
- Synchronized output (Mode 2026) reduces flicker during streaming

**Streaming pattern** (replaces recursive listenForStream):
```go
func waitForStream(ch <-chan streamEvent) tea.Cmd {
    return func() tea.Msg {
        for {
            event, ok := <-ch
            if !ok { return streamDoneMsg{} }
            if event.err != nil { return streamErrorMsg{event.err} }
            if event.done { return streamDoneMsg{event.output} }
            if event.text != "" { return streamChunkMsg{event.text} }
        }
    }
}
```

### 3.3 Add Glamour Markdown Rendering

LLM responses contain markdown. Currently rendered as plain text.
- Use `glamour` for completed messages
- Raw text during active streaming (partial markdown may not parse)
- Re-render with glamour when stream completes

### 3.4 Improve TUI Components

- `bubbles/viewport` for scrollable chat history
- `bubbles/textarea` for multi-line input (shift+enter for newlines in v2)
- `bubbles/spinner` for "thinking" indicator
- `bubbles/help` for keyboard shortcuts
- `lipgloss` for message bubble styling (user vs assistant)

---

## Phase 4: API Improvements + Angular UI Spec (Medium Risk)

### 4.1 Fix Session Ownership

Add session-cookie based authorization:
```go
func (sm *sessionManager) authorizeSession(r *http.Request, sessionID uuid.UUID) error {
    cookieSessionID := sm.getSessionID(r)
    if cookieSessionID != sessionID {
        return ErrForbidden
    }
    return nil
}
```

### 4.2 Security Headers

Add missing HSTS header:
```go
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
```

### 4.3 Add API Versioning

Prefix all routes with `/api/v1/`:
```
/api/v1/csrf-token
/api/v1/sessions
/api/v1/sessions/{id}
/api/v1/sessions/{id}/messages
/api/v1/chat
/api/v1/chat/stream
```

### 4.4 Standardize Response Envelope

```json
{
  "data": { ... },
  "error": null
}
```

or on error:
```json
{
  "data": null,
  "error": { "code": "not_found", "message": "session not found" }
}
```

### 4.5 Angular UI Spec Document

Create `docs/api-spec.md` with:
- Complete endpoint documentation (request/response schemas)
- SSE event types and payloads
- Authentication flow (CSRF tokens, session cookies)
- WebSocket upgrade path (future consideration)
- Error code reference

---

## Phase 5: RAG & Knowledge Improvements

### 5.1 Update System Knowledge Content

Current 6 documents are outdated. Update to match actual registered tools.

### 5.2 Implement Knowledge Store Tool

The UI references `knowledge_store` but it doesn't exist. Either:
- Option A: Implement it (user can save conversations/documents to knowledge base)
- Option B: Remove UI reference (done in Phase 1.3)

Decision deferred to user.

### 5.3 Improve Token Estimation

Replace `rune/2` with proper estimation:
```go
func estimateTokens(text string) int {
    // Use tiktoken-go or similar for accurate counting
    // Fallback to heuristic per language detection
}
```

Or use Genkit's built-in token counter if available.

---

## Phase 6: Security Hardening

### 6.1 Fix Prompt Injection Homoglyph Bypass

Add Unicode NFKD normalization before pattern matching:
```go
import "golang.org/x/text/unicode/normalize"

normalized := normalize.NFKD.String(input)
// Then apply regex patterns
```

### 6.2 Enforce SafeTransport Usage

`SafeTransport()` exists but is never used in production. Wire it into network tools.

### 6.3 Command Whitelist Gaps

Add missing blocked patterns:
- `npm install` (postinstall hooks execute code)
- `go test -run` (executes test code)

---

## Phase 7: Testing Overhaul

### 7.1 Remove Pointless Tests

Tests that only call `t.Skip()` with no body add no value.
(Most already removed in Phase A cleanup.)

### 7.2 Add Missing Critical Tests

| Test | Module | Why |
|------|--------|-----|
| Stream empty event handling | tui | Validates Phase 1.1 fix |
| Concurrent stream start/cancel | tui | Race condition coverage |
| deepCopyMessages mutation | chat | Direct unit test (currently indirect) |
| MCP JSON-RPC protocol | mcp | No protocol-level tests exist |
| Session ownership check | api | Validates Phase 4.1 fix |

### 7.3 TUI Testing with teatest

Use `charmbracelet/x/exp/teatest` for golden file testing of TUI output.

---

## Execution Order

Phases can be partially parallelized:

```
Phase 1 (bug fixes) ─────────────────────────→ immediate
Phase 2 (wire removal, DI) ──────────────────→ after Phase 1
Phase 3 (TUI v2) ──────┐                       after Phase 2
Phase 4 (API + spec) ──┤ parallel              after Phase 2
Phase 5 (RAG) ─────────┘                       after Phase 2
Phase 6 (security) ──────────────────────────→ after Phase 4
Phase 7 (testing) ───────────────────────────→ continuous
```

**CLI and API work don't conflict** — Phase 3 (TUI) and Phase 4 (API) can run in parallel after Phase 2 establishes the new DI structure.

---

## Out of Scope

- Angular Web UI implementation (separate project)
- New AI providers beyond gemini/ollama/openai
- Multi-user authentication system
- WebSocket support (future consideration)
- Kubernetes deployment manifests

---

## Risk Assessment

| Phase | Risk | Mitigation |
|-------|------|------------|
| 1 (bugs) | Low | Pure fixes, existing tests validate |
| 2 (wire) | Medium | Manual DI is well-understood; test suite validates |
| 3 (TUI v2) | High | v2 is RC.2, API may change; pin specific version |
| 4 (API) | Medium | Existing tests cover endpoints; add ownership tests |
| 5 (RAG) | Low | Isolated module, minimal cross-dependencies |
| 6 (security) | Medium | Security changes need careful review |
| 7 (testing) | Low | Only adds tests, no production code risk |

---

## Success Criteria

- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] `golangci-lint run ./...` — 0 issues
- [ ] `go test -race ./...` — all pass
- [ ] All 4 red issues resolved
- [ ] Wire removed, manual DI working
- [ ] TUI running on Bubble Tea v2
- [ ] API spec document complete
- [ ] No regressions in existing functionality
