# Proposal 001: v0.1.0 Release Plan

## Summary

Prepare Koopa for its first public release by:
1. Cleaning up code quality (testify removal, skipped tests)
2. Adding multi-model support (Gemini + Ollama + OpenAI)
3. Exposing RAG tools via MCP
4. Writing README and release automation

## Scope

**In scope (v0.1.0):**
- testify → stdlib + cmp.Diff migration (16 files)
- Multi-model: Gemini (current) + Ollama + OpenAI via Genkit plugins
- Config-driven model/provider selection
- MCP server exposes Knowledge/RAG tools
- README with install instructions and quick start
- goreleaser for macOS (arm64/amd64) + Linux (arm64/amd64)
- Complete skipped tests where feasible

**Out of scope (deferred to v0.2.0):**
- Claude/Anthropic support (Genkit plugin disables tool use)
- MCP Client (connecting to external MCP servers)
- Hybrid RAG (vector + keyword search)
- Extensible user-defined tool system
- Agent loop enhancement (multi-step task decomposition)

## Detailed Design

### 1. testify Migration (16 files)

**What changes:**
Replace all `assert.*` / `require.*` calls with stdlib patterns:

```go
// Before
assert.Equal(t, want, got)
require.NoError(t, err)

// After
if diff := cmp.Diff(want, got); diff != "" {
    t.Errorf("FuncName() mismatch (-want +got):\n%s", diff)
}
if err != nil {
    t.Fatalf("FuncName() unexpected error: %v", err)
}
```

**Files affected (16):**
- `internal/agent/chat/integration_rag_test.go`
- `internal/agent/chat/integration_test.go`
- `internal/agent/chat/integration_streaming_test.go`
- `internal/agent/chat/flow_test.go`
- `internal/agent/chat/chat_test.go`
- `internal/tools/system_integration_test.go`
- `internal/tools/register_test.go`
- `internal/tools/file_integration_test.go`
- `internal/tools/network_integration_test.go`
- `internal/session/integration_test.go`
- `internal/rag/system_test.go`
- `internal/mcp/integration_test.go`
- `internal/observability/datadog_test.go`
- `internal/testutil/postgres.go`
- `internal/testutil/sse.go`
- `cmd/e2e_test.go`

After migration, remove `github.com/stretchr/testify` from `go.mod`.

**Risk:** Low. Mechanical replacement, no logic changes.

### 2. Multi-Model Support

**Current state:**
- `wire.go:119` hardcodes `&googlegenai.GoogleAI{}` as the only AI plugin
- `wire.go:134` hardcodes `googlegenai.GoogleAIEmbedder()` as embedder
- `prompts/koopa.prompt:2` hardcodes `model: googleai/gemini-2.5-flash`

**Design:**

#### 2a. Config Changes (`internal/config/config.go`)

Add provider field:

```go
type Config struct {
    // AI configuration
    Provider    string  `mapstructure:"provider" json:"provider"`       // "gemini" (default), "ollama", "openai"
    ModelName   string  `mapstructure:"model_name" json:"model_name"`   // e.g. "gemini-2.5-flash", "llama3.3", "gpt-4o"
    // ... existing fields ...

    // Ollama configuration
    OllamaHost string `mapstructure:"ollama_host" json:"ollama_host"` // default: "http://localhost:11434"

    // OpenAI configuration (env: OPENAI_API_KEY)
    // No config field needed - key read by Genkit plugin from env
}
```

Defaults:
```yaml
provider: gemini
model_name: gemini-2.5-flash
ollama_host: http://localhost:11434
```

Env overrides:
```
KOOPA_PROVIDER=ollama
KOOPA_MODEL_NAME=llama3.3
KOOPA_OLLAMA_HOST=http://localhost:11434
OPENAI_API_KEY=sk-...  # for openai provider
```

#### 2b. Dynamic Plugin Loading (`internal/app/wire.go`)

Replace hardcoded GoogleAI with provider switch:

```go
func provideGenkit(ctx context.Context, cfg *config.Config, _ OtelShutdown, postgres *postgresql.Postgres) (*genkit.Genkit, error) {
    plugins := []genkit.Plugin{postgres} // PostgreSQL always needed for RAG

    switch cfg.Provider {
    case "gemini", "":
        plugins = append(plugins, &googlegenai.GoogleAI{})
    case "ollama":
        plugins = append(plugins, &ollama.Ollama{ServerAddress: cfg.OllamaHost})
    case "openai":
        plugins = append(plugins, &openai.OpenAI{})
    default:
        return nil, fmt.Errorf("unsupported provider: %q", cfg.Provider)
    }

    g := genkit.Init(ctx,
        genkit.WithPlugins(plugins...),
        genkit.WithPromptDir(promptDir),
    )
    return g, nil
}
```

#### 2c. Dynamic Model in Dotprompt

The dotprompt `model:` field determines which model Genkit uses. Two options:

**Option A: Override at runtime (preferred)**
Keep the dotprompt as-is with a default model. Override the model when executing the prompt via `ai.WithModel()` option. This requires checking if Genkit's prompt execution API supports model override.

**Option B: Generate dotprompt at startup**
Write the dotprompt file dynamically based on config. This is fragile and not recommended.

**Option C: Multiple dotprompt files**
Create `prompts/koopa-gemini.prompt`, `prompts/koopa-ollama.prompt`, etc. Select based on config. Duplicates prompt content.

**Recommendation: Option A** — override at execution time. The `ai.WithModel()` option in `ai.PromptExecuteOption` allows this. The dotprompt file remains the default/fallback.

Implementation in `chat.go`:
```go
// In generateResponse(), add model override to opts
if modelOverride != "" {
    model := genkit.LookupModel(c.g, modelOverride)
    if model != nil {
        opts = append(opts, ai.WithModel(model))
    }
}
```

The model name format follows Genkit convention:
- Gemini: `googleai/gemini-2.5-flash`
- Ollama: `ollama/llama3.3`
- OpenAI: `openai/gpt-4o`

Config `model_name` stores the short name (`gemini-2.5-flash`), and the provider prefix is derived from `cfg.Provider`.

#### 2d. Embedder Selection

Embedder is needed for RAG (pgvector). Options per provider:

| Provider | Embedder | Model |
|----------|----------|-------|
| gemini | `googlegenai.GoogleAIEmbedder` | text-embedding-004 |
| ollama | `ollama.Embedder` | nomic-embed-text |
| openai | `openai.Embedder` | text-embedding-3-small |

```go
func provideEmbedder(g *genkit.Genkit, cfg *config.Config) ai.Embedder {
    switch cfg.Provider {
    case "ollama":
        return ollama.Embedder(g, cfg.EmbedderModel)
    case "openai":
        return openai.Embedder(g, cfg.EmbedderModel)
    default:
        return googlegenai.GoogleAIEmbedder(g, cfg.EmbedderModel)
    }
}
```

**Note:** Switching embedder provider changes vector dimensions. Existing pgvector data from one embedder is incompatible with another. This is acceptable for v0.1.0 (users start fresh). Document this limitation.

#### 2e. Validation

- `gemini`: Require `GEMINI_API_KEY` env var
- `ollama`: Require `ollama_host` reachable (health check at startup)
- `openai`: Require `OPENAI_API_KEY` env var

### 3. MCP RAG Tools

**Current state:** MCP server exposes File, System, Network tools but NOT Knowledge tools.

**Change:** Register knowledge tools in MCP server alongside existing tools.

**File:** `internal/mcp/server.go` (or wherever MCP tools are registered)

Add the 3 knowledge tools:
- `search_history` — search past conversations
- `search_documents` — search indexed documents
- `search_system_knowledge` — search system knowledge base

**Risk:** Low. Tools already exist and are tested. Just wire them into MCP registration.

### 4. README

Structure:
```
# Koopa
One-line description.

## Features
- Terminal AI assistant (TUI)
- JSON REST API with SSE streaming
- MCP server for IDE integration
- 13 built-in tools (file, system, network, knowledge)
- RAG with pgvector
- Multi-model (Gemini, Ollama, OpenAI)

## Quick Start
### Prerequisites
- Go 1.23+
- PostgreSQL 17 with pgvector
- Docker (for SearXNG + Redis)

### Install
go install github.com/koopa0/koopa@latest
# or download from releases

### Setup
docker compose up -d
export GEMINI_API_KEY="your-key"
koopa

### Using Ollama (local models)
ollama pull llama3.3
export KOOPA_PROVIDER=ollama
export KOOPA_MODEL_NAME=llama3.3
koopa

## Configuration
## Architecture
## License
```

### 5. Release Automation (goreleaser)

Create `.goreleaser.yml`:
- Platforms: macOS (arm64, amd64), Linux (arm64, amd64)
- Binary name: `koopa`
- GitHub release with checksums
- Homebrew tap (optional, can add later)

### 6. Skipped Tests

7 skipped tests identified:
- 5 in `internal/api/session_test.go` — need PostgreSQL integration
- 2 in `cmd/e2e_test.go` — need MCP test harness

**Action:**
- `session_test.go`: Convert to testcontainers-based integration tests
- `e2e_test.go`: Assess feasibility. If MCP test harness is complex, document as known limitation.

## Implementation Order

| Step | Task | Depends On | Estimated Files |
|------|------|------------|-----------------|
| 1 | testify migration | none | 16 test files |
| 2 | Remove testify from go.mod | step 1 | go.mod, go.sum |
| 3 | Config: add Provider, OllamaHost fields | none | config.go, validation.go, config_test.go |
| 4 | wire.go: dynamic plugin loading | step 3 | wire.go, wire_gen.go |
| 5 | chat.go: model override at execution | step 4 | chat.go, chat_test.go |
| 6 | Embedder: provider-based selection | step 4 | wire.go |
| 7 | MCP: register knowledge tools | none | mcp/server.go or tools registration |
| 8 | go.mod: add ollama, openai plugins | step 4 | go.mod, go.sum |
| 9 | Skipped tests | none | session_test.go, e2e_test.go |
| 10 | README | after all features | README.md |
| 11 | goreleaser config | none | .goreleaser.yml |
| 12 | Final verification | all steps | - |

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Genkit Ollama plugin bugs | Tool calling fails | Test with popular models (llama3.3, qwen2.5) early |
| Embedder dimension mismatch | RAG breaks when switching provider | Document: switching provider requires fresh DB |
| Wire regeneration | Build breaks | Run `wire ./internal/app/` after wire.go changes |
| Dotprompt model override | May not work as expected | Verify `ai.WithModel()` in prompt execution; fallback to Option C if needed |

## Open Questions

1. Should `config.yaml` support per-command provider override? (e.g., TUI uses Ollama but API uses Gemini)
   - **Recommendation:** No. Single provider per instance for v0.1.0.

2. Should we add a `koopa config` CLI command to set provider/model interactively?
   - **Recommendation:** Defer. Environment variables and config file are sufficient.

3. Default embedder model names for Ollama/OpenAI — need to verify exact model IDs.
   - **Action:** Check during implementation.
