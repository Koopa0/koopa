# Koopa API Design

## Overview

This document outlines the design for exposing Koopa's functionality as HTTP REST APIs using Genkit's built-in flow-to-API mechanism.

## Motivation

Currently, RAG and Session management are implemented as slash commands (`/rag`, `/session`) in the interactive CLI. This approach has limitations:

1. **Not programmatically accessible** - Can't be called from external tools
2. **Tightly coupled to CLI** - Logic lives in `cmd/cmd.go`
3. **Hard to test** - Requires CLI interaction
4. **Not composable** - Can't be used in automation pipelines

By exposing these as HTTP APIs via Genkit Flows, we gain:

- **Programmatic access** - Call from any HTTP client
- **Better separation of concerns** - Business logic in `api/`, CLI is just a thin layer
- **Testability** - Standard HTTP testing patterns
- **Observability** - Genkit's built-in tracing and debugging
- **Future extensibility** - Easy to add authentication, rate limiting, etc.

## Genkit Flow-to-API Mechanism

Genkit provides `genkit.Handler(flow)` to convert any Flow into an HTTP handler:

```go
// Define a flow
myFlow := genkit.DefineFlow(g, "myFlow", func(ctx context.Context, input MyInput) (MyOutput, error) {
    // business logic
})

// Expose as HTTP endpoint
mux := http.NewServeMux()
mux.HandleFunc("POST /myFlow", genkit.Handler(myFlow))

// Or expose ALL flows automatically
for _, flow := range genkit.ListFlows(g) {
    mux.HandleFunc("POST /"+flow.Name(), genkit.Handler(flow))
}
```

## API Endpoints

### RAG (Knowledge Management)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/rag/add` | POST | Add file/directory to knowledge base |
| `/api/rag/list` | GET | List all indexed documents |
| `/api/rag/remove` | DELETE | Remove document by ID |
| `/api/rag/status` | GET | Get RAG system status |
| `/api/rag/search` | POST | Search knowledge base |

#### Request/Response Examples

**POST /api/rag/add**
```json
// Request
{
  "path": "/path/to/file.txt"
}

// Response
{
  "success": true,
  "files_added": 1,
  "files_skipped": 0,
  "total_size": 1024
}
```

**GET /api/rag/list**
```json
// Response
{
  "documents": [
    {
      "id": "doc-123",
      "file_name": "example.txt",
      "file_path": "/path/to/example.txt",
      "file_size": 1024,
      "indexed_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

**POST /api/rag/search**
```json
// Request
{
  "query": "how to handle errors in Go",
  "limit": 5
}

// Response
{
  "results": [
    {
      "id": "doc-456",
      "content": "...",
      "score": 0.95,
      "metadata": {...}
    }
  ]
}
```

### Session Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/session` | GET | Get current session |
| `/api/session/list` | GET | List all sessions |
| `/api/session/create` | POST | Create new session |
| `/api/session/{id}` | GET | Get session by ID |
| `/api/session/{id}` | DELETE | Delete session |
| `/api/session/{id}/switch` | POST | Switch to session |
| `/api/session/{id}/messages` | GET | Get session messages |

#### Request/Response Examples

**POST /api/session/create**
```json
// Request
{
  "title": "Code Review Session",
  "model_name": "gemini-2.5-flash",
  "system_prompt": "You are a code reviewer."
}

// Response
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "Code Review Session",
  "created_at": "2024-01-15T10:30:00Z"
}
```

**GET /api/session/list?limit=10**
```json
// Response
{
  "sessions": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Code Review Session",
      "message_count": 5,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T11:00:00Z"
    }
  ],
  "total": 1
}
```

## Package Structure

```
api/
├── DESIGN.md           # This document
├── TODO.md             # Implementation tasks
├── server.go           # HTTP server setup
├── rag.go              # RAG flow definitions
├── rag_test.go         # RAG API tests
├── session.go          # Session flow definitions
├── session_test.go     # Session API tests
├── middleware.go       # Auth, logging, CORS
└── types.go            # Shared request/response types
```

## Implementation Approach

### Phase 1: Core Infrastructure
- [ ] Create `api/server.go` with HTTP server setup
- [ ] Create `api/types.go` with shared types
- [ ] Add `koopa serve` command to start API server

### Phase 2: RAG APIs
- [ ] Implement RAG flows in `api/rag.go`
- [ ] Migrate logic from `cmd/cmd.go` handlers
- [ ] Add tests in `api/rag_test.go`

### Phase 3: Session APIs
- [ ] Implement Session flows in `api/session.go`
- [ ] Migrate logic from `cmd/cmd.go` handlers
- [ ] Add tests in `api/session_test.go`

### Phase 4: CLI Refactor
- [ ] Remove `/rag` and `/session` from `cmd/cmd.go`
- [ ] CLI calls API internally (optional, could keep as convenience)
- [ ] Remove unused Cobra files (`root.go`, `version.go`)

## Security Considerations

1. **Authentication** - Add API key or JWT authentication
2. **Authorization** - Role-based access control
3. **Rate Limiting** - Prevent abuse
4. **Input Validation** - Validate all inputs via Genkit schemas
5. **Path Validation** - Use existing `security.Path` validator

## Configuration

```yaml
# config.yaml (future)
api:
  enabled: true
  port: 3400
  host: "127.0.0.1"  # localhost only by default
  auth:
    enabled: false   # enable in production
    api_key: "${API_KEY}"
```

## Testing Strategy

1. **Unit Tests** - Test flow logic in isolation
2. **Integration Tests** - Test full HTTP request/response cycle
3. **E2E Tests** - Test with real database and Genkit

```go
func TestRAGAddFlow(t *testing.T) {
    // Setup test server
    srv := httptest.NewServer(api.NewRouter(testApp))
    defer srv.Close()

    // Test request
    resp, err := http.Post(srv.URL+"/api/rag/add", "application/json",
        strings.NewReader(`{"path": "/tmp/test.txt"}`))

    require.NoError(t, err)
    assert.Equal(t, http.StatusOK, resp.StatusCode)
}
```

## Future Enhancements

1. **WebSocket support** - Real-time chat streaming
2. **OpenAPI spec** - Auto-generate from Genkit schemas
3. **SDK generation** - Generate client SDKs from OpenAPI
4. **Metrics** - Prometheus metrics endpoint
5. **Health checks** - `/health` and `/ready` endpoints

## References

- [Genkit Go - Deploy flows](https://genkit.dev/go/docs/deploy/)
- [Genkit Go - Defining flows](https://genkit.dev/go/docs/flows/)
- [Genkit Handler API](https://firebase.google.com/docs/genkit-go/flows)
