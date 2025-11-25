# API Implementation TODO

## Overview

This document tracks the implementation tasks for exposing Koopa's RAG and Session functionality as HTTP REST APIs using Genkit Flows.

See [DESIGN.md](./DESIGN.md) for architecture and API specifications.

---

## Phase 1: Core Infrastructure

### P1.1 Server Setup
- [ ] Create `api/server.go`
  - [ ] `NewServer(app *app.App, g *genkit.Genkit) *Server`
  - [ ] `Server.RegisterFlows()` - register all API flows
  - [ ] `Server.Start(addr string) error` - start HTTP server
  - [ ] Graceful shutdown handling

### P1.2 Types and Schemas
- [ ] Create `api/types.go`
  - [ ] `RAGAddRequest`, `RAGAddResponse`
  - [ ] `RAGListResponse`, `RAGDocument`
  - [ ] `RAGSearchRequest`, `RAGSearchResponse`
  - [ ] `SessionCreateRequest`, `SessionResponse`
  - [ ] `SessionListResponse`
  - [ ] `ErrorResponse` for consistent error handling

### P1.3 CLI Command
- [ ] Add `koopa serve` command in `cmd/`
  - [ ] Parse `--port` flag (default: 3400)
  - [ ] Parse `--host` flag (default: 127.0.0.1)
  - [ ] Initialize app and start API server

---

## Phase 2: RAG APIs

### P2.1 RAG Add Flow
- [ ] Create `api/rag.go`
- [ ] Implement `DefineRAGAddFlow(g, app)`
  - [ ] Input: `RAGAddRequest{Path string}`
  - [ ] Validate path using `app.PathValidator`
  - [ ] Handle file vs directory
  - [ ] Return `RAGAddResponse{FilesAdded, FilesSkipped, TotalSize}`

### P2.2 RAG List Flow
- [ ] Implement `DefineRAGListFlow(g, app)`
  - [ ] No input required
  - [ ] Return `RAGListResponse{Documents []RAGDocument, Total int}`

### P2.3 RAG Remove Flow
- [ ] Implement `DefineRAGRemoveFlow(g, app)`
  - [ ] Input: `RAGRemoveRequest{ID string}`
  - [ ] Return success/error

### P2.4 RAG Status Flow
- [ ] Implement `DefineRAGStatusFlow(g, app)`
  - [ ] Return database connection status
  - [ ] Return embedder status
  - [ ] Return document count and stats

### P2.5 RAG Search Flow
- [ ] Implement `DefineRAGSearchFlow(g, app)`
  - [ ] Input: `RAGSearchRequest{Query string, Limit int}`
  - [ ] Use retriever to search
  - [ ] Return `RAGSearchResponse{Results []SearchResult}`

### P2.6 RAG Tests
- [ ] Create `api/rag_test.go`
  - [ ] Unit tests for each flow
  - [ ] Integration tests with httptest

---

## Phase 3: Session APIs

### P3.1 Session Flows
- [ ] Create `api/session.go`
- [ ] Implement `DefineSessionCreateFlow(g, app)`
- [ ] Implement `DefineSessionListFlow(g, app)`
- [ ] Implement `DefineSessionGetFlow(g, app)`
- [ ] Implement `DefineSessionDeleteFlow(g, app)`
- [ ] Implement `DefineSessionSwitchFlow(g, app)`
- [ ] Implement `DefineSessionMessagesFlow(g, app)`

### P3.2 Session Tests
- [ ] Create `api/session_test.go`
  - [ ] Unit tests for each flow
  - [ ] Integration tests with httptest

---

## Phase 4: CLI Cleanup

### P4.1 Remove Slash Commands
- [ ] Remove `/rag` command handling from `cmd/cmd.go`
  - [ ] Remove `handleRAGCommand()`
  - [ ] Remove `handleRAGAdd()`, `handleRAGList()`, etc.
- [ ] Remove `/session` command handling from `cmd/cmd.go`
  - [ ] Remove `handleSessionCommand()`
  - [ ] Remove `handleSessionNew()`, `handleSessionList()`, etc.
- [ ] Update `/help` output to remove RAG/Session commands

### P4.2 Remove Unused Cobra Files
- [ ] Delete `cmd/root.go` (unused Cobra root command)
- [ ] Delete `cmd/version.go` (unused Cobra version command)
- [ ] Keep `cmd/root_test.go` if tests are still valid, else delete

### P4.3 Simplify Execute
- [ ] Review `cmd/execute.go` - ensure it's minimal
- [ ] Consider removing Cobra dependency entirely from go.mod

---

## Phase 5: Documentation & Polish

### P5.1 Documentation
- [ ] Update main README.md with API usage
- [ ] Add API examples to docs/
- [ ] Document authentication setup (when implemented)

### P5.2 OpenAPI Spec (Optional)
- [ ] Generate OpenAPI spec from Genkit schemas
- [ ] Add Swagger UI endpoint (optional)

---

## Priority Matrix

| Task | Priority | Complexity | Dependencies |
|------|----------|------------|--------------|
| P1.1 Server Setup | High | Medium | None |
| P1.2 Types | High | Low | None |
| P2.1-P2.5 RAG Flows | High | Medium | P1.1, P1.2 |
| P3.1 Session Flows | Medium | Medium | P1.1, P1.2 |
| P4.1 Remove Slash Cmds | Medium | Low | P2, P3 |
| P4.2 Remove Cobra | Low | Low | P4.1 |
| P5 Documentation | Low | Low | P2, P3 |

---

## Notes

- **Don't break CLI** - Keep `koopa` (interactive mode) and `koopa mcp` working
- **Backward compatible** - Old config should still work
- **Security first** - Path validation, input validation on all APIs
- **Testable** - Every flow should have unit tests

---

## Getting Started

When ready to implement, start with:

```bash
# 1. Create the server skeleton
touch api/server.go api/types.go

# 2. Implement one simple flow (e.g., RAG status)
# 3. Add tests
# 4. Iterate
```
