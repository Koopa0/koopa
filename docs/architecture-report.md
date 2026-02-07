# Koopa Project Architecture Report

> Generated: 2026-02-04 | Branch: main | Commit: 26e635b

---

## 1. Project Overview

### Module Information

| Field | Value |
|-------|-------|
| **Go Module** | `github.com/koopa0/koopa` |
| **Go Version** | 1.25.1 |
| **License** | MIT |
| **Entry Point** | `main.go` → `cmd.Execute()` |

### Directory Structure (3 Levels)

```
koopa/
├── main.go                       # Entry point → cmd.Execute()
├── go.mod / go.sum               # Dependencies
├── Taskfile.yml                  # Build tasks (task CLI)
├── docker-compose.yml            # PostgreSQL + SearXNG + Redis
├── .golangci.yml                 # Linter config
├── .mcp.json                     # MCP server config (Genkit)
├── .env.example                  # Environment template
├── config.example.yaml           # Advanced config template (~/.koopa/config.yaml)
├── GENKIT.md                     # Genkit framework guidelines
├── CLAUDE.md                     # Claude Code project rules
│
├── cmd/                          # CLI Commands (Cobra-like, manual)
│   ├── execute.go                # Command dispatcher
│   ├── cli.go                    # Interactive TUI mode (BubbleTea)
│   ├── serve.go                  # HTTP API server
│   ├── mcp.go                    # MCP server (stdio)
│   ├── version.go                # Version display
│   ├── e2e_test.go               # CLI E2E tests
│   └── integration_test.go       # CLI integration tests
│
├── internal/
│   ├── agent/                    # AI Agent abstraction
│   │   ├── errors.go             # Sentinel errors
│   │   └── chat/                 # Chat agent (Genkit Flow)
│   │       ├── chat.go           # Core agent (Execute, ExecuteStream)
│   │       ├── flow.go           # Genkit StreamingFlow definition
│   │       ├── retry.go          # Exponential backoff retry
│   │       ├── circuit.go        # Circuit breaker pattern
│   │       ├── tokens.go         # Token budget management
│   │       └── *_test.go         # Tests
│   │
│   ├── app/                      # Application lifecycle (DI)
│   │   ├── app.go                # App container struct
│   │   ├── runtime.go            # Runtime wrapper (App + Flow + cleanup)
│   │   ├── wire.go               # Wire DI providers (10-step chain)
│   │   ├── wire_gen.go           # Wire generated code
│   │   └── *_test.go             # Tests
│   │
│   ├── config/                   # Configuration
│   │   ├── config.go             # Main Config struct + Load() + Validate()
│   │   ├── tools.go              # MCP/SearXNG/WebScraper config
│   │   └── *_test.go             # Tests
│   │
│   ├── knowledge/                # Knowledge store (placeholder)
│   │
│   ├── log/                      # Logger setup
│   │   └── log.go                # slog wrapper (Logger = *slog.Logger)
│   │
│   ├── mcp/                      # MCP Server implementation
│   │   ├── doc.go                # Architecture documentation
│   │   ├── server.go             # MCP server (10 tools)
│   │   ├── file.go               # File tool MCP handlers
│   │   ├── system.go             # System tool MCP handlers
│   │   ├── network.go            # Network tool MCP handlers
│   │   ├── util.go               # Result → MCP conversion
│   │   └── *_test.go             # Tests
│   │
│   ├── observability/            # OpenTelemetry setup
│   │   └── datadog.go            # OTLP HTTP exporter → Datadog Agent
│   │
│   ├── rag/                      # RAG retriever/indexer
│   │   ├── constants.go          # Source types, schema config
│   │   ├── system.go             # System knowledge indexing (6 docs)
│   │   └── doc.go                # Package doc
│   │
│   ├── security/                 # Input validators (5 modules)
│   │   ├── path.go               # Path traversal prevention
│   │   ├── command.go            # Command injection prevention
│   │   ├── env.go                # Env variable access control
│   │   ├── url.go                # SSRF prevention
│   │   ├── prompt.go             # Prompt injection detection
│   │   └── *_test.go             # Tests (incl. fuzz)
│   │
│   ├── session/                  # Session persistence (PostgreSQL)
│   │   ├── types.go              # Session, Message, History structs
│   │   ├── store.go              # Store (CRUD, transactions)
│   │   ├── errors.go             # Sentinel errors, status constants
│   │   ├── state.go              # ~/.koopa/current_session persistence
│   │   └── *_test.go             # Tests
│   │
│   ├── sqlc/                     # Generated SQL code (sqlc)
│   │   ├── db.go                 # DBTX interface, Queries struct
│   │   ├── models.go             # Document, Message, Session models
│   │   ├── documents.sql.go      # Document queries
│   │   └── sessions.sql.go       # Session/message queries
│   │
│   ├── testutil/                 # Test utilities
│   │   ├── db.go                 # Testcontainer PostgreSQL setup
│   │   ├── embedder.go           # Deterministic test embedder
│   │   └── logger.go             # No-op logger
│   │
│   ├── tools/                    # Tool implementations
│   │   ├── types.go              # Result, Error, Status types
│   │   ├── metadata.go           # DangerLevel, ToolMetadata registry
│   │   ├── emitter.go            # ToolEventEmitter interface
│   │   ├── events.go             # WithEvents wrapper
│   │   ├── file.go               # File tools (5 tools)
│   │   ├── system.go             # System tools (3 tools)
│   │   ├── network.go            # Network tools (2 tools)
│   │   ├── knowledge.go          # Knowledge tools (3 tools)
│   │   └── *_test.go             # Tests (incl. fuzz)
│   │
│   ├── tui/                      # Terminal UI (BubbleTea)
│   │   ├── tui.go                # Model + Init + Update + View
│   │   ├── keys.go               # Key bindings
│   │   ├── commands.go           # Streaming tea.Cmd
│   │   ├── styles.go             # Lipgloss styles
│   │   └── *_test.go             # Tests
│   │
│   └── web/                      # HTTP server + Web UI
│       ├── server.go             # Server, route registration, security headers
│       ├── middleware.go         # Recovery, Logging, MethodOverride, Session, CSRF
│       ├── handlers/
│       │   ├── chat.go           # POST /genui/send, GET /genui/stream
│       │   ├── pages.go          # GET /genui (main page)
│       │   ├── sessions.go       # Session/CSRF management
│       │   ├── health.go         # Health/ready probes
│       │   └── *_test.go         # Tests (unit + integration + fuzz)
│       ├── sse/
│       │   └── writer.go         # SSE writer (chunks, done, error, tools)
│       ├── page/
│       │   └── chat.templ        # Chat page template
│       ├── layout/
│       │   └── app.templ         # Base HTML layout
│       ├── component/
│       │   ├── message_bubble.templ
│       │   ├── sidebar.templ
│       │   ├── chat_input.templ
│       │   ├── empty_state.templ
│       │   ├── session_placeholders.templ
│       │   └── _reference/       # templUI Pro blocks (222 blocks)
│       ├── static/               # CSS (Tailwind), JS (HTMX, Elements, Prism)
│       └── e2e/                  # Playwright E2E tests
│
├── db/                           # Database layer
│   ├── migrate.go                # Embedded migration runner
│   ├── migrations/
│   │   ├── 000001_init_schema.up.sql
│   │   └── 000001_init_schema.down.sql
│   └── queries/
│       ├── documents.sql         # 8 document queries
│       └── sessions.sql          # 28 session/message queries
│
├── build/
│   ├── frontend/                 # Tailwind CSS build config
│   └── sql/
│       └── sqlc.yaml             # SQLC code generation config
│
├── prompts/
│   └── koopa.prompt              # Dotprompt system prompt (665 lines)
│
├── scripts/                      # Utility scripts
├── searxng/                      # SearXNG Docker config
└── docs/                         # Documentation
```

### Third-Party Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| **AI/LLM** |
| `github.com/firebase/genkit/go` | v1.2.0 | LLM orchestration, Flow, tools, Dotprompt |
| **Database** |
| `github.com/jackc/pgx/v5` | v5.7.6 | PostgreSQL driver (connection pooling) |
| `github.com/pgvector/pgvector-go` | v0.3.0 | pgvector extension (vector embeddings) |
| `github.com/golang-migrate/migrate/v4` | v4.19.1 | Database schema migrations |
| **MCP** |
| `github.com/modelcontextprotocol/go-sdk` | v1.1.0 | MCP server SDK (official) |
| **TUI/CLI** |
| `charm.land/bubbletea/v2` | v2.0.0-rc.2 | Interactive terminal UI framework |
| `charm.land/bubbles/v2` | v2.0.0-rc.1 | BubbleTea components (textarea, spinner) |
| `charm.land/lipgloss/v2` | v2.0.0-beta.3 | Terminal styling/formatting |
| `github.com/charmbracelet/glamour` | v0.10.0 | Markdown → terminal rendering |
| **Web** |
| `github.com/a-h/templ` | v0.3.960 | Go HTML template compiler (SSR) |
| **Web Scraping** |
| `github.com/gocolly/colly/v2` | v2.2.0 | Web scraping framework |
| `github.com/PuerkitoBio/goquery` | v1.11.0 | HTML parsing (jQuery-like) |
| `github.com/go-shiori/go-readability` | v0.0.0-20250217 | Article extraction (Readability) |
| **Configuration** |
| `github.com/spf13/viper` | v1.21.0 | Config file + env var management |
| `github.com/google/wire` | v0.7.0 | Compile-time dependency injection |
| **Utilities** |
| `github.com/google/uuid` | v1.6.0 | UUID generation |
| `github.com/google/jsonschema-go` | v0.3.0 | JSON Schema inference for tool inputs |
| `github.com/gofrs/flock` | v0.13.0 | File-based locking |
| `golang.org/x/sync` | v0.18.0 | errgroup for lifecycle management |
| `golang.org/x/time` | v0.14.0 | rate.Limiter for rate limiting |
| **Observability** |
| `go.opentelemetry.io/otel/sdk` | v1.38.0 | OpenTelemetry tracing SDK |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` | v1.38.0 | OTLP HTTP exporter (Datadog) |
| **Testing** |
| `github.com/stretchr/testify` | v1.11.1 | Assertions and mocking |
| `github.com/testcontainers/testcontainers-go` | v0.40.0 | Docker containers for integration tests |
| `github.com/testcontainers/testcontainers-go/modules/postgres` | v0.40.0 | PostgreSQL testcontainer |
| `github.com/playwright-community/playwright-go` | v0.5200.1 | Browser automation (E2E tests) |
| `go.uber.org/goleak` | v1.3.0 | Goroutine leak detector |

---

## 2. Core Type Definitions

### 2.1 Agent Types

#### `internal/agent/chat/chat.go`

```go
// Chat is Koopa's main conversational agent - FULLY IMPLEMENTED
type Chat struct {
    languagePrompt string           // Resolved language for prompt template
    maxTurns       int              // Agentic loop iterations (default: 5)
    ragTopK        int              // RAG documents to retrieve
    retryConfig    RetryConfig      // LLM retry settings
    circuitBreaker *CircuitBreaker  // Failure handling
    rateLimiter    *rate.Limiter    // Proactive rate limiting (default: 10/s, burst 30)
    tokenBudget    TokenBudget      // Context window limits
    g              *genkit.Genkit
    retriever      ai.Retriever     // For RAG retrieval
    sessions       *session.Store   // Session persistence
    logger         log.Logger
    tools          []ai.Tool        // Pre-registered tools
    toolRefs       []ai.ToolRef     // Cached for efficiency
    toolNames      string           // Comma-separated for logging
    prompt         ai.Prompt        // Cached Dotprompt instance
}
// Methods: New(Config), Execute(ctx, sessionID, input), ExecuteStream(ctx, sessionID, input, callback)

// Config contains all required parameters for Chat agent
type Config struct {
    Genkit               *genkit.Genkit
    Retriever            ai.Retriever
    SessionStore         *session.Store
    Logger               log.Logger
    Tools                []ai.Tool
    MaxTurns             int
    RAGTopK              int
    Language             string
    RetryConfig          RetryConfig
    CircuitBreakerConfig CircuitBreakerConfig
    RateLimiter          *rate.Limiter
    TokenBudget          TokenBudget
}

// Response represents the complete result of an agent execution
type Response struct {
    FinalText    string
    ToolRequests []*ai.ToolRequest
}

// StreamCallback is called for each chunk of streaming response
type StreamCallback func(ctx context.Context, chunk *ai.ModelResponseChunk) error
```

#### `internal/agent/chat/flow.go`

```go
// Flow type alias for Genkit Streaming Flow
type Flow = core.Flow[Input, Output, StreamChunk]

const FlowName = "koopa/chat"

type Input struct {
    Query     string `json:"query"`
    SessionID string `json:"sessionId"`
}

type Output struct {
    Response  string `json:"response"`
    SessionID string `json:"sessionId"`
}

type StreamChunk struct {
    Text string `json:"text"`
}

// Singleton management:
// InitFlow(g, chat) - Initialize once via sync.Once
// GetFlow() *Flow   - Get initialized flow (panics if not initialized)
// ResetFlowForTesting() - Reset for test isolation
```

#### `internal/agent/chat/retry.go`

```go
type RetryConfig struct {
    MaxRetries      int           // Default: 3
    InitialInterval time.Duration // Default: 500ms
    MaxInterval     time.Duration // Default: 10s
}
// Methods: DefaultRetryConfig(), executeWithRetry(), retryableError()
```

#### `internal/agent/chat/circuit.go`

```go
type CircuitState int // CircuitClosed=0, CircuitOpen=1, CircuitHalfOpen=2

type CircuitBreakerConfig struct {
    FailureThreshold int           // Default: 5
    SuccessThreshold int           // Default: 2
    Timeout          time.Duration // Default: 30s
}

type CircuitBreaker struct { // Thread-safe (sync.RWMutex)
    mu               sync.RWMutex
    state            CircuitState
    failures         int
    successes        int
    lastFailure      time.Time
    failureThreshold int
    successThreshold int
    timeout          time.Duration
}
// Methods: NewCircuitBreaker(), Allow(), Success(), Failure(), State(), Reset()
```

#### `internal/agent/chat/tokens.go`

```go
type TokenBudget struct {
    MaxHistoryTokens int // Default: 8000
    MaxInputTokens   int // Default: 2000
    ReservedTokens   int // Default: 4000
}
// Methods: DefaultTokenBudget(), estimateTokens(), truncateHistory()
```

#### `internal/agent/errors.go`

```go
var (
    ErrInvalidSession  = errors.New("invalid session")
    ErrExecutionFailed = errors.New("execution failed")
)
```

### 2.2 Session / Message Types

#### `internal/session/types.go`

```go
// History - Thread-safe conversation history (sync.RWMutex) - FULLY IMPLEMENTED
type History struct {
    mu       sync.RWMutex
    messages []*ai.Message
}
// Methods: NewHistory(), SetMessages(), Messages(), Add(), AddMessage(), Count(), Clear()

// Session represents a conversation session
type Session struct {
    ID           uuid.UUID
    Title        string
    CreatedAt    time.Time
    UpdatedAt    time.Time
    ModelName    string
    SystemPrompt string
    MessageCount int
}

// Message represents a single conversation message
type Message struct {
    ID             uuid.UUID
    SessionID      uuid.UUID
    Role           string      // "user" | "assistant" | "system" | "tool"
    Content        []*ai.Part  // Genkit Part slice (stored as JSONB)
    Status         string      // "streaming" | "completed" | "failed"
    SequenceNumber int
    CreatedAt      time.Time
}
```

#### `internal/session/store.go`

```go
// Store manages session persistence with PostgreSQL backend - FULLY IMPLEMENTED
type Store struct {
    queries *sqlc.Queries
    pool    *pgxpool.Pool
    logger  *slog.Logger
}
// Methods: New(), CreateSession(), GetSession(), ListSessions(),
//          ListSessionsWithMessages(), DeleteSession(), UpdateSessionTitle(),
//          AddMessages(), GetMessages(), AppendMessages(), GetHistory(),
//          CreateMessagePair(), GetUserMessageBefore(), GetMessageByID(),
//          UpdateMessageContent(), UpdateMessageStatus()

// MessagePair represents a user-assistant message pair for streaming
type MessagePair struct {
    UserMsgID      uuid.UUID
    AssistantMsgID uuid.UUID
    UserSeq        int32
    AssistantSeq   int32
}
```

#### `internal/session/errors.go`

```go
const (
    StatusStreaming  = "streaming"
    StatusCompleted  = "completed"
    StatusFailed     = "failed"
)

var (
    ErrSessionNotFound = errors.New("session not found")
    ErrMessageNotFound = errors.New("message not found")
)

const (
    DefaultHistoryLimit int32 = 100
    MaxHistoryLimit     int32 = 10000
    MinHistoryLimit     int32 = 10
)
```

### 2.3 Tool / MCP Types

#### `internal/tools/types.go`

```go
type Status string
const (
    StatusSuccess Status = "success"
    StatusError   Status = "error"
)

type ErrorCode string
const (
    ErrCodeSecurity   ErrorCode = "SecurityError"
    ErrCodeNotFound   ErrorCode = "NotFound"
    ErrCodePermission ErrorCode = "PermissionDenied"
    ErrCodeIO         ErrorCode = "IOError"
    ErrCodeExecution  ErrorCode = "ExecutionError"
    ErrCodeTimeout    ErrorCode = "TimeoutError"
    ErrCodeNetwork    ErrorCode = "NetworkError"
    ErrCodeValidation ErrorCode = "ValidationError"
)

type Result struct {
    Status Status `json:"status"`
    Data   any    `json:"data,omitempty"`
    Error  *Error `json:"error,omitempty"`
}

type Error struct {
    Code    ErrorCode `json:"code"`
    Message string    `json:"message"`
    Details any       `json:"details,omitempty"`
}
```

#### `internal/tools/metadata.go`

```go
type DangerLevel int
const (
    DangerLevelSafe      DangerLevel = iota // read_file, list_files, get_env, web_fetch
    DangerLevelWarning                       // write_file (reversible)
    DangerLevelDangerous                     // delete_file, execute_command (irreversible)
    DangerLevelCritical                      // Reserved for future
)

type ToolMetadata struct {
    Name                 string
    Description          string
    RequiresConfirmation bool
    DangerLevel          DangerLevel
    IsDangerousFunc      func(params map[string]any) bool
    Category             string
}
// Functions: GetToolMetadata(), GetAllToolMetadata(), IsDangerous(),
//            RequiresConfirmation(), GetDangerLevel(), ListToolsByDangerLevel()
```

#### `internal/tools/emitter.go`

```go
// ToolEventEmitter receives tool lifecycle events - INTERFACE
type ToolEventEmitter interface {
    OnToolStart(name string)
    OnToolComplete(name string)
    OnToolError(name string)
}
// Functions: EmitterFromContext(ctx), ContextWithEmitter(ctx, emitter)
```

#### `internal/tools/file.go`

```go
type FileTools struct { // FULLY IMPLEMENTED
    pathVal *security.Path
    logger  log.Logger
}

type ReadFileInput struct {
    Path string `json:"path" jsonschema_description:"The file path to read"`
}
type WriteFileInput struct {
    Path    string `json:"path"`
    Content string `json:"content"`
}
type ListFilesInput struct {
    Path string `json:"path"`
}
type DeleteFileInput struct {
    Path string `json:"path"`
}
type GetFileInfoInput struct {
    Path string `json:"path"`
}
type FileEntry struct {
    Name string `json:"name"`
    Type string `json:"type"` // "file" | "directory"
}
```

#### `internal/tools/system.go`

```go
type SystemTools struct { // FULLY IMPLEMENTED
    cmdVal *security.Command
    envVal *security.Env
    logger log.Logger
}

type ExecuteCommandInput struct {
    Command string   `json:"command"`
    Args    []string `json:"args,omitempty"`
}
type GetEnvInput struct {
    Key string `json:"key"`
}
type CurrentTimeInput struct{}
```

#### `internal/tools/network.go`

```go
type NetworkTools struct { // FULLY IMPLEMENTED
    searchBaseURL    string
    searchClient     *http.Client
    fetchParallelism int
    fetchDelay       time.Duration
    fetchTimeout     time.Duration
    urlValidator     *security.URL
    skipSSRFCheck    bool
    logger           log.Logger
}

type NetworkConfig struct {
    SearchBaseURL    string
    FetchParallelism int
    FetchDelay       time.Duration
    FetchTimeout     time.Duration
}
```

#### `internal/tools/knowledge.go`

```go
type KnowledgeTools struct { // FULLY IMPLEMENTED
    retriever ai.Retriever
    logger    log.Logger
}

type KnowledgeSearchInput struct {
    Query string `json:"query"`
    TopK  int    `json:"topK,omitempty"`
}
```

#### `internal/mcp/server.go`

```go
type Server struct { // FULLY IMPLEMENTED
    mcpServer    *mcp.Server
    fileTools    *tools.FileTools
    systemTools  *tools.SystemTools
    networkTools *tools.NetworkTools
    name         string
    version      string
}

type Config struct {
    Name         string
    Version      string
    FileTools    *tools.FileTools
    SystemTools  *tools.SystemTools
    NetworkTools *tools.NetworkTools
}
// Methods: NewServer(Config), Run(ctx, transport), registerTools()
```

### 2.4 Security Types

#### `internal/security/path.go`

```go
type Path struct { // FULLY IMPLEMENTED
    allowedDirs []string
    workDir     string
}
// Methods: NewPath(allowedDirs), Validate(path) (string, error)

var (
    ErrPathOutsideAllowed    = errors.New("path is outside allowed directories")
    ErrSymlinkOutsideAllowed = errors.New("symbolic link points outside allowed directories")
    ErrPathNullByte          = errors.New("path contains null byte")
)
```

#### `internal/security/command.go`

```go
type Command struct { // FULLY IMPLEMENTED - WHITELIST mode
    blacklist []string
    whitelist []string
}
// Methods: NewCommand(), ValidateCommand(cmd, args), QuoteCommandArgs(args)
// 53 whitelisted commands: ls, cat, grep, git, go, npm, etc.
```

#### `internal/security/env.go`

```go
type Env struct { // FULLY IMPLEMENTED
    sensitivePatterns []string // 87 patterns blocked
}
// Methods: NewEnv(), Validate(key), GetAllowedEnvNames()
// 23 allowed variables: PATH, HOME, GOPATH, etc.
```

#### `internal/security/url.go`

```go
type URL struct { // FULLY IMPLEMENTED
    allowedSchemes map[string]struct{}
    blockedHosts   map[string]struct{}
}
// Methods: NewURL(), Validate(rawURL), SafeTransport(), ValidateRedirect()
// Blocks: localhost, metadata endpoints, private IPs, link-local
```

#### `internal/security/prompt.go`

```go
type PromptValidator struct { // FULLY IMPLEMENTED
    patterns []*regexp.Regexp // 13 patterns
}

type PromptInjectionResult struct {
    Safe     bool
    Patterns []string
}
// Methods: NewPromptValidator(), Validate(input), IsSafe(input)
```

### 2.5 Config Types

#### `internal/config/config.go`

```go
type Config struct { // FULLY IMPLEMENTED
    // AI
    ModelName          string
    Temperature        float32
    MaxTokens          int
    Language           string
    PromptDir          string
    // History
    MaxHistoryMessages int32
    MaxTurns           int
    // Database
    DatabasePath       string
    PostgresHost       string
    PostgresPort       int
    PostgresUser       string
    PostgresPassword   string  // Masked in MarshalJSON
    PostgresDBName     string
    PostgresSSLMode    string
    // RAG
    RAGTopK            int
    EmbedderModel      string
    // MCP
    MCP                MCPConfig
    MCPServers         map[string]MCPServer
    // Tools
    SearXNG            SearXNGConfig
    WebScraper         WebScraperConfig
    // Observability
    Datadog            DatadogConfig
    // Security
    HMACSecret         string  // Masked in MarshalJSON
}
// Methods: Load(), Validate(), MarshalJSON()
```

#### `internal/config/tools.go`

```go
type MCPConfig struct {
    Allowed  []string
    Excluded []string
    Timeout  int
}

type MCPServer struct {
    Command      string
    Args         []string
    Env          map[string]string
    Timeout      int
    IncludeTools []string
    ExcludeTools []string
}

type SearXNGConfig struct {
    BaseURL string
}

type WebScraperConfig struct {
    Parallelism int
    DelayMs     int
    TimeoutMs   int
}
```

### 2.6 App / Runtime Types

#### `internal/app/app.go`

```go
type App struct { // FULLY IMPLEMENTED
    Config        *config.Config
    Genkit        *genkit.Genkit
    Embedder      ai.Embedder
    DBPool        *pgxpool.Pool
    DocStore      *postgresql.DocStore
    Retriever     ai.Retriever
    SessionStore  *session.Store
    PathValidator *security.Path
    Tools         []ai.Tool
    ctx           context.Context
    cancel        context.CancelFunc
    eg            *errgroup.Group
    egCtx         context.Context
}
// Methods: Close(), Wait(), Go(func() error), CreateAgent(ctx)
```

#### `internal/app/runtime.go`

```go
type Runtime struct { // FULLY IMPLEMENTED
    App     *App
    Flow    *chat.Flow
    cleanup func()
}
// Factory: NewRuntime(ctx, cfg) → single init point for all entry points
// Methods: Close() error (App.Close() → Wire cleanup)
```

### 2.7 Web Handler Types

#### `internal/web/handlers/chat.go`

```go
// SSEWriter - INTERFACE
type SSEWriter interface {
    WriteChunkRaw(msgID, htmlContent string) error
    WriteDone(ctx context.Context, msgID string, comp templ.Component) error
    WriteError(msgID, code, message string) error
    WriteSidebarRefresh(sessionID, title string) error
}

type ChatConfig struct {
    Logger      *slog.Logger
    Genkit      *genkit.Genkit
    Flow        *chat.Flow
    Sessions    *Sessions
    SSEWriterFn func(w http.ResponseWriter) (SSEWriter, error)
}

type Chat struct { // FULLY IMPLEMENTED
    logger      *slog.Logger
    genkit      *genkit.Genkit
    flow        *chat.Flow
    sessions    *Sessions
    sseWriterFn func(w http.ResponseWriter) (SSEWriter, error)
}
// Methods: NewChat(ChatConfig), Send(w, r), Stream(w, r)

type streamState struct {
    msgID     string
    sessionID string
    buffer    strings.Builder
}
```

#### `internal/web/handlers/sessions.go`

```go
type Sessions struct { // FULLY IMPLEMENTED
    store      *session.Store
    hmacSecret []byte
    isDev      bool
}
// Methods: NewSessions(), GetOrCreate(r), ID(r), NewCSRFToken(sessionID),
//          CheckCSRF(r), RegisterRoutes(mux)
```

#### `internal/web/sse/writer.go`

```go
type Writer struct { // FULLY IMPLEMENTED
    w       io.Writer
    flusher http.Flusher
}
// Methods: NewWriter(), WriteChunk(), WriteChunkRaw(), WriteDone(),
//          WriteError(), WriteSidebarRefresh(),
//          WriteToolStart(), WriteToolComplete(), WriteToolError()
```

### 2.8 TUI Types

#### `internal/tui/tui.go`

```go
type State int
const (
    StateInput     State = iota // Awaiting input
    StateThinking               // Processing request
    StateStreaming               // Streaming response
)

type Message struct {
    Role    string // "user" | "assistant" | "system" | "error"
    Content string
}

type TUI struct { // FULLY IMPLEMENTED - BubbleTea Model
    input         textarea.Model
    history       []string
    historyIdx    int
    state         State
    lastCtrlC     time.Time
    spinner       spinner.Model
    output        strings.Builder
    viewBuf       strings.Builder
    messages      []Message
    streamCancel  context.CancelFunc
    streamEventCh <-chan streamEvent
    chatFlow      *chat.Flow
    sessionID     string
    ctx           context.Context
    ctxCancel     context.CancelFunc
    width         int
    height        int
    styles        Styles
    markdown      *markdownRenderer
}
// Implements tea.Model: Init(), Update(msg), View()
```

---

## 3. Genkit Integration

### 3.1 Initialization

**Location**: `internal/app/wire.go` lines 107-130

```go
g := genkit.Init(ctx,
    genkit.WithPlugins(&googlegenai.GoogleAI{}, postgres),
    genkit.WithPromptDir(promptDir), // Default: "prompts"
)
```

**Plugins Used**:
| Plugin | Purpose |
|--------|---------|
| `googlegenai.GoogleAI{}` | Gemini model access (chat + embeddings) |
| `postgresql.Postgres{}` | DocStore + Retriever for RAG (pgvector) |

**Initialization Order** (Wire DI):
1. OpenTelemetry setup (tracing before Genkit)
2. Database pool (migrations run)
3. PostgreSQL plugin creation
4. Genkit Init with plugins
5. Embedder provision
6. RAG components (DocStore + Retriever)
7. Session store
8. Security validators
9. Tool registration (all 13 tools)
10. App construction

### 3.2 Flow Definitions

**One flow defined**: `koopa/chat`

| Flow Name | Type | Input | Output | Stream Type |
|-----------|------|-------|--------|-------------|
| `koopa/chat` | `genkit.DefineStreamingFlow` | `Input{Query, SessionID}` | `Output{Response, SessionID}` | `StreamChunk{Text}` |

**Flow lifecycle**:
- Singleton via `sync.Once` in `InitFlow(g, chat)`
- Access via `GetFlow()` (panics if not initialized)
- `ResetFlowForTesting()` for test isolation

**Flow implementation** (`internal/agent/chat/flow.go` lines 87-149):
1. Parse session UUID from `input.SessionID`
2. Wrap `streamCb` into `StreamCallback` (adapts `StreamChunk` → `ai.ModelResponseChunk`)
3. Call `chat.ExecuteStream(ctx, sessionID, query, callback)`
4. Return `Output{Response, SessionID}`

### 3.3 Tool Calling

**13 tools registered** at app initialization via `genkit.DefineTool()`:

| Category | Tool Name | Danger Level |
|----------|-----------|-------------|
| **File** | `read_file` | Safe |
| | `write_file` | Warning |
| | `list_files` | Safe |
| | `delete_file` | Dangerous |
| | `get_file_info` | Safe |
| **System** | `current_time` | Safe |
| | `execute_command` | Dangerous |
| | `get_env` | Safe |
| **Network** | `web_search` | Safe |
| | `web_fetch` | Safe |
| **Knowledge** | `search_history` | Safe |
| | `search_documents` | Safe |
| | `search_system_knowledge` | Safe |

**Tool middleware**: `WithEvents` wrapper — emits `OnToolStart`/`OnToolComplete`/`OnToolError` lifecycle events via `ToolEventEmitter` interface (used for SSE tool status display).

**No other middleware** (no rate limiting, no caching, no request/response interceptors).

**Agentic loop**: `ai.WithMaxTurns(maxTurns)` — default 5 turns. LLM can call tools iteratively.

### 3.4 Structured Output

**Not used**. The flow uses plain string output:
- Input: JSON object `{query, sessionId}`
- Output: JSON object `{response, sessionId}`
- Streaming: JSON chunks `{text}`

Tool inputs use `jsonschema_description` tags for schema inference, but no output schema validation.

### 3.5 Session Management

**Custom** (NOT Genkit built-in). PostgreSQL-backed via `session.Store`:

```
Agent.ExecuteStream()
  → sessions.GetHistory(ctx, sessionID)     // Load []*ai.Message from DB
  → generateResponse(ctx, input, messages)  // LLM call
  → sessions.AppendMessages(ctx, sessionID) // Persist new messages
```

Messages stored as JSONB in `message.content` column, serialized from `[]*ai.Part`.

### 3.6 Streaming

**Two-layer architecture**:

1. **Agent → Flow** (internal): `ai.WithStreaming(callback)` where callback receives `*ai.ModelResponseChunk`
2. **Flow → HTTP** (SSE): Go 1.23 `range-over-func` iterator over `flow.Stream(ctx, input)`

**SSE endpoint**: `GET /genui/stream?msgId=X&session_id=Y`
- 5-minute timeout
- HTML escaping (XSS prevention)
- OOB swaps for HTMX (sidebar refresh, final message replacement)

---

## 4. Data Layer

### 4.1 Database

| Field | Value |
|-------|-------|
| **DBMS** | PostgreSQL 17 with pgvector extension |
| **Driver** | `pgx/v5` (connection pooling) |
| **Pool Config** | MaxConns=10, MinConns=2, MaxLifetime=30m, MaxIdle=5m, HealthCheck=1m |
| **Vector Extension** | pgvector (vector(768), HNSW index, cosine distance) |
| **Query Generation** | sqlc (type-safe Go from SQL) |
| **Migration Tool** | golang-migrate v4 |
| **Docker Image** | `pgvector/pgvector:pg17` |

### 4.2 SQLC Configuration

**Config**: `build/sql/sqlc.yaml`
- Engine: PostgreSQL
- Driver: `pgx/v5`
- Output: `internal/sqlc/`
- Features: JSON tags, empty slices (not nil), UUID type override

**Query Files**:

| File | Queries | Purpose |
|------|---------|---------|
| `db/queries/documents.sql` | 8 | Document CRUD + vector search |
| `db/queries/sessions.sql` | 28 | Session/message CRUD + streaming lifecycle |

### 4.3 Migration Files

Single migration: `db/migrations/000001_init_schema.up.sql`

Migrations are **embedded** via `//go:embed` and run automatically at startup in `provideDBPool()`.

### 4.4 Complete Schema (CREATE TABLE)

```sql
-- Extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Helper function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Table: documents (RAG/Knowledge Store)
CREATE TABLE IF NOT EXISTS documents (
    id         TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    embedding  vector(768) NOT NULL,
    source_type TEXT,
    metadata   JSONB
);
CREATE INDEX IF NOT EXISTS idx_documents_embedding
    ON documents USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);
CREATE INDEX IF NOT EXISTS idx_documents_source_type ON documents(source_type);
CREATE INDEX IF NOT EXISTS idx_documents_metadata_gin
    ON documents USING GIN (metadata jsonb_path_ops);

-- Table: sessions
CREATE TABLE IF NOT EXISTS sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    model_name    TEXT,
    system_prompt TEXT,
    message_count INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at DESC);
CREATE TRIGGER update_sessions_updated_at
    BEFORE UPDATE ON sessions FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Table: message
CREATE TABLE IF NOT EXISTS message (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         JSONB NOT NULL,
    sequence_number INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL DEFAULT 'completed'
                    CHECK (status IN ('streaming', 'completed', 'failed')),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_message_sequence UNIQUE (session_id, sequence_number),
    CONSTRAINT message_role_check CHECK (role IN ('user', 'assistant', 'system', 'tool'))
);
CREATE INDEX IF NOT EXISTS idx_message_session_id ON message(session_id);
CREATE INDEX IF NOT EXISTS idx_message_session_seq ON message(session_id, sequence_number);
CREATE INDEX IF NOT EXISTS idx_incomplete_messages ON message(session_id, updated_at)
    WHERE status IN ('streaming', 'failed');
CREATE INDEX IF NOT EXISTS idx_message_status ON message(session_id, status)
    WHERE status != 'completed';
CREATE INDEX IF NOT EXISTS idx_message_content_gin
    ON message USING GIN (content jsonb_path_ops);
CREATE TRIGGER update_message_updated_at
    BEFORE UPDATE ON message FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

### 4.5 pgvector Usage

| Aspect | Detail |
|--------|--------|
| **Dimension** | 768 (text-embedding-004 model) |
| **Index Type** | HNSW (m=16, ef_construction=64) |
| **Distance Metric** | Cosine (`<=>` operator) |
| **Similarity Formula** | `(1 - (embedding <=> query_embedding))::float8` |
| **Table** | `documents` |
| **Source Types** | `conversation`, `file`, `system` |
| **System Knowledge** | 6 pre-indexed documents at startup |

---

## 5. Channel Adapter Implementation

### Current State: No External Channel Adapters

The project has **three access channels**, all built-in:

| Channel | Implementation | Transport |
|---------|---------------|-----------|
| **CLI/TUI** | `internal/tui/` (BubbleTea) | Terminal stdin/stdout |
| **Web Chat** | `internal/web/` (Templ + HTMX) | HTTP + SSE |
| **MCP** | `internal/mcp/` (MCP SDK) | stdio |

**No Telegram, LINE, Discord, Slack, or WhatsApp adapters exist.**

### Web Chat Details

| Aspect | Detail |
|--------|--------|
| **Main Files** | `internal/web/server.go`, `handlers/chat.go`, `handlers/pages.go`, `handlers/sessions.go`, `sse/writer.go` |
| **Template Engine** | Templ (Go SSR) |
| **CSS Framework** | Tailwind CSS (compiled, embedded) |
| **Interactivity** | HTMX + Tailwind Plus Elements |
| **Streaming** | Server-Sent Events (SSE) |
| **Session** | HTTP cookie (30-day expiry) + CSRF tokens |
| **Routes** | `GET /genui`, `POST /genui/send`, `GET /genui/stream`, `POST /genui/sessions/*` |

### CLI/TUI Details

| Aspect | Detail |
|--------|--------|
| **Framework** | BubbleTea v2 |
| **State Machine** | 3 states: Input → Thinking → Streaming |
| **Streaming** | Go 1.23 range-over-func iterator, discriminated union channel |
| **Key Bindings** | Enter=submit, Shift+Enter=newline, Esc=cancel, Ctrl+C×2=quit |
| **Markdown** | Glamour rendering (graceful degradation to plain text) |
| **History** | In-memory (max 100 entries), Up/Down navigation |

---

## 6. MCP Integration

### 6.1 SDK

| Field | Value |
|-------|-------|
| **SDK** | `github.com/modelcontextprotocol/go-sdk` v1.1.0 (official) |
| **Role** | **MCP Server** only (not client) |
| **Transport** | Stdio |
| **Entry Point** | `cmd/mcp.go` → `mcp.NewServer(config).Run(ctx, &StdioTransport{})` |

### 6.2 MCP Server Tools (10 tools)

Same as Genkit tools minus the 3 knowledge tools (knowledge tools require Genkit retriever, MCP server doesn't initialize full Genkit):

| Tool | Description |
|------|-------------|
| `read_file` | Read file content (max 10MB) |
| `write_file` | Create/overwrite files |
| `list_files` | List directory contents |
| `delete_file` | Delete files |
| `get_file_info` | File metadata |
| `current_time` | System time |
| `execute_command` | Whitelisted commands |
| `get_env` | Non-sensitive env vars |
| `web_search` | SearXNG search |
| `web_fetch` | URL fetch with SSRF protection |

### 6.3 Tool Registry Management

- Tools registered via `mcp.AddTool()` in `Server.registerTools()`
- Input schemas auto-generated using `jsonschema.For[T](nil)`
- Results converted via `resultToMCP()` with error detail sanitization (blocks stack traces, file paths, API keys)

### 6.4 Connected MCP Servers

The `.mcp.json` configures one MCP server for **development** use with Claude Code:

```json
{
  "mcpServers": {
    "genkit": {
      "command": "genkit",
      "args": ["mcp", "--no-update-notification"]
    }
  }
}
```

`config.example.yaml` shows additional configurable MCP servers (fetch, filesystem, github) but these are **configuration templates**, not actively connected.

---

## 7. Permission / Security

### 7.1 Security Validators (5 modules)

| Validator | File | Prevents | Mechanism |
|-----------|------|----------|-----------|
| **Path** | `security/path.go` | Directory traversal (CWE-22) | Whitelist allowed dirs, symlink resolution, null byte rejection |
| **Command** | `security/command.go` | Command injection (CWE-78) | Whitelist 53 safe commands, argument validation |
| **Env** | `security/env.go` | Info leakage | Block 87 sensitive patterns, allow 23 safe vars |
| **URL** | `security/url.go` | SSRF (CWE-918) | Block private IPs, metadata endpoints, DNS rebinding protection |
| **Prompt** | `security/prompt.go` | Prompt injection | 13 regex patterns, Unicode normalization |

### 7.2 Tool Call Permission Check

Security validation is **inline** — each tool validates its inputs before execution:
- `FileTools.ReadFile()` → `pathVal.Validate(input.Path)`
- `SystemTools.ExecuteCommand()` → `cmdVal.ValidateCommand(cmd, args)`
- `SystemTools.GetEnv()` → `envVal.Validate(key)`
- `NetworkTools.WebFetch()` → `urlValidator.Validate(url)` + `SafeTransport()`

Security failures return `Result{Status: StatusError, Error: &Error{Code: ErrCodeSecurity}}` — business errors, not Go errors. This allows the LLM to handle rejections gracefully.

### 7.3 Approval Flow

**Not implemented**. `ToolMetadata.RequiresConfirmation` and `DangerLevel` are defined but there is no runtime approval mechanism. The metadata system is in place as infrastructure for a future approval flow.

### 7.4 Audit Logging

**slog-based** security event logging with structured fields:

```go
logger.Warn("security_event",
    "type", "path_traversal_attempt",
    "path", unsafePath,
    "allowed_dirs", allowedDirs,
)
```

Events logged for: path traversal, command injection, sensitive env access, SSRF blocks, symlink traversal, prompt injection.

**No database-backed audit log**. All events go to application logs only.

---

## 8. Frontend

### 8.1 Technology Stack

| Aspect | Technology |
|--------|-----------|
| **Template Engine** | Templ v0.3.960 (Go SSR, type-safe) |
| **CSS Framework** | Tailwind CSS (compiled, embedded in binary) |
| **Interactivity** | HTMX + HTMX SSE Extension |
| **Client-side** | Tailwind Plus Elements (dropdowns, modals) |
| **Code Highlighting** | Prism.js |
| **No SPA framework** | No Angular, React, or Vue |

### 8.2 Pages and Components

| Type | File | Purpose |
|------|------|---------|
| **Layout** | `layout/app.templ` | Base HTML (head, body, scripts) |
| **Page** | `page/chat.templ` | Two-column chat layout (sidebar + feed) |
| **Component** | `component/message_bubble.templ` | User/assistant message rendering |
| | `component/sidebar.templ` | Session list sidebar |
| | `component/chat_input.templ` | Message input form |
| | `component/empty_state.templ` | Empty state view |
| | `component/session_placeholders.templ` | Loading skeletons |

### 8.3 Real-time Updates

- **SSE** (Server-Sent Events) for streaming AI responses
- **HTMX OOB swaps** for sidebar refresh, session field updates
- **No WebSocket** implementation

### 8.4 Dashboard

**Not implemented**. Only a chat interface exists.

### 8.5 Static Asset Management

- **Production**: Assets embedded via `//go:embed` (single binary deployment)
- **Development**: `assets_dev.go` loads from filesystem (build tag: `dev`)
- **JS Libraries**: HTMX 2.x, htmx-sse extension, Tailwind Plus Elements, Prism.js — all vendored locally (no CDN)

---

## 9. Deployment & Configuration

### 9.1 Docker Compose

```yaml
services:
  postgres:
    image: pgvector/pgvector:pg17
    ports: ["5432:5432"]
    environment:
      POSTGRES_USER: koopa
      POSTGRES_PASSWORD: koopa_dev_password
      POSTGRES_DB: koopa
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/migrations:/docker-entrypoint-initdb.d  # Auto-init
    healthcheck: pg_isready -U koopa

  searxng:
    image: searxng/searxng:latest
    ports: ["8888:8080"]
    depends_on: [redis]
    healthcheck: wget --no-verbose --tries=1 http://localhost:8080/healthz

  redis:
    image: valkey/valkey:8-alpine
    healthcheck: valkey-cli ping
```

**No Dockerfile for Koopa itself** — built as a Go binary, not containerized.

### 9.2 Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `GEMINI_API_KEY` | Yes | — | Google Gemini API key |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `HMAC_SECRET` | Web only | — | CSRF token signing (min 32 chars) |
| `KOOPA_MODEL_NAME` | No | `gemini-2.5-flash` | LLM model name |
| `KOOPA_TEMPERATURE` | No | `0.7` | LLM temperature |
| `KOOPA_MAX_TOKENS` | No | `2048` | Max response tokens |
| `KOOPA_MAX_HISTORY_MESSAGES` | No | `100` | Conversation history limit |
| `KOOPA_RAG_TOP_K` | No | `3` | RAG documents to retrieve |
| `DEBUG` | No | `false` | Debug logging |
| `DD_API_KEY` | No | — | Datadog APM |

### 9.3 Configuration File

**Location**: `~/.koopa/config.yaml`

Used for MCP server definitions and advanced tool configuration. See `config.example.yaml` for template.

### 9.4 Startup Flow

```
main.go
  → cmd.Execute()
    → Parse flags (--version, --help)
    → Dispatch to: runCLI() | RunServe() | RunMCP()

runCLI():
  → config.Load()
  → signal.NotifyContext(SIGINT, SIGTERM)
  → app.NewRuntime(ctx, cfg)
    → Wire: InitializeApp() (10-step provider chain)
    → chat.New(Config{...})        # Create agent
    → chat.InitFlow(g, agent)      # Register Genkit Flow (sync.Once)
  → Load/create session ID (~/.koopa/current_session)
  → tui.New(ctx, flow, sessionID)
  → tea.NewProgram(model).Run()

RunServe():
  → Validate HMAC_SECRET
  → app.NewRuntime(ctx, cfg)
  → web.NewServer(ServerConfig{...})
  → http.Server{...} with timeouts
  → Graceful shutdown on SIGINT/SIGTERM

RunMCP():
  → app.InitializeApp(ctx, cfg)   # Wire directly
  → Create FileTools, SystemTools, NetworkTools
  → mcp.NewServer(Config{...})
  → server.Run(ctx, &StdioTransport{})
```

---

## 10. Testing

### 10.1 Test Types

| Type | Count | Build Tag | Runner |
|------|-------|-----------|--------|
| **Unit Tests** | ~70 files | none | `go test ./...` |
| **Integration Tests** | ~10 files | `integration` | `go test -tags integration ./...` |
| **Fuzz Tests** | 4 files | none | `go test -fuzz=FuzzXxx ./...` |
| **E2E Tests** | ~5 files | `e2e` | Playwright browser automation |
| **Race Tests** | 1 file | none | `go test -race ./...` |

### 10.2 Testing Patterns

**Unit Test Example** (handler testing):
```go
func TestChat_Send(t *testing.T) {
    fw := SetupTest(t)           // Test framework with mock deps
    defer fw.Cleanup()
    req := httptest.NewRequest(...)
    w := httptest.NewRecorder()
    fw.Chat.Send(w, req)
    assert.Equal(t, 200, w.Code)
}
```

**Integration Test Example** (real database):
```go
//go:build integration

func TestPages_Chat_LoadsHistoryFromDatabase(t *testing.T) {
    // Uses testcontainers PostgreSQL
    db := testutil.SetupTestDB(t)
    store := session.New(db, logger)
    // ... test with real DB operations
}
```

**Fuzz Test Example** (security):
```go
func FuzzMessageContent(f *testing.F) {
    f.Add("normal text")
    f.Add("<script>alert('xss')</script>")
    f.Add("'; DROP TABLE messages; --")
    f.Fuzz(func(t *testing.T, content string) {
        // Verify no panic, proper escaping
    })
}
```

### 10.3 Test Infrastructure

| Component | Location | Purpose |
|-----------|----------|---------|
| `testutil.SetupTestDB()` | `internal/testutil/db.go` | PostgreSQL testcontainer |
| `testutil.DiscardLogger()` | `internal/testutil/logger.go` | No-op logger |
| Deterministic embedder | `internal/testutil/embedder.go` | Predictable embeddings for tests |
| Mock SSE Writer | `internal/web/handlers/chat_test.go` | Records SSE events |
| Browser fixture | `internal/web/fixture_test.go` | Playwright browser context |
| SSE event parser | `internal/testutil/` | Parse SSE format |

### 10.4 Coverage

Not explicitly measured (no CI coverage badge), but `coverage.out` exists at root. Test infrastructure suggests moderate-to-good coverage for core packages (agent, tools, security, handlers).

---

## 11. Architecture Flow Diagram (Working)

### Message Processing Flow (Web Chat)

```
User types message in browser
  │
  ▼
POST /genui/send (HTMX form submission)
  │
  ├── Parse form: content, session_id, csrf_token
  ├── Validate CSRF token (HMAC-SHA256)
  ├── Lazy session creation (if first message)
  │
  ├── Render HTML response:
  │   ├── User message bubble (OOB swap into #message-feed)
  │   ├── Assistant skeleton with SSE connection:
  │   │   <div hx-ext="sse"
  │   │        sse-connect="/genui/stream?msgId=X&session_id=Y&query=Z"
  │   │        sse-swap="chunk"
  │   │        sse-close="done">
  │   └── OOB swaps: session_id field, csrf token refresh
  │
  ▼
GET /genui/stream (SSE endpoint)
  │
  ├── Parse query params: msgId, session_id, query
  ├── Create 5-minute timeout context
  │
  ├── flow.Stream(ctx, Input{Query, SessionID})
  │   │
  │   ▼
  │   Chat.ExecuteStream(ctx, sessionID, query, callback)
  │   │
  │   ├── sessions.GetHistory(ctx, sessionID)      # Load from PostgreSQL
  │   ├── deepCopyMessages(history)                 # Prevent Genkit data race
  │   ├── truncateHistory(messages, tokenBudget)    # Context window management
  │   ├── retrieveRAGContext(ctx, query)             # pgvector search (5s timeout)
  │   │
  │   ├── circuitBreaker.Allow()                    # Check circuit state
  │   ├── executeWithRetry(ctx, opts)               # Exponential backoff
  │   │   │
  │   │   ├── rateLimiter.Wait(ctx)                 # Rate limiting
  │   │   └── prompt.Execute(ctx, opts...)           # Genkit → Gemini API
  │   │       │
  │   │       ├── ai.WithTools(toolRefs...)          # 13 tools available
  │   │       ├── ai.WithMaxTurns(5)                 # Agentic loop
  │   │       ├── ai.WithStreaming(callback)          # Stream chunks
  │   │       └── ai.WithDocs(ragDocs...)             # RAG context
  │   │       │
  │   │       ▼
  │   │   [Gemini processes, may call tools]
  │   │       │
  │   │       ├── Tool call → security validation → execute → Result
  │   │       ├── Tool result → back to Gemini → next turn
  │   │       └── Final text response
  │   │
  │   ├── circuitBreaker.Success()
  │   ├── sessions.AppendMessages(ctx, sessionID, [user, assistant])
  │   └── Return Response{FinalText, ToolRequests}
  │
  ├── For each StreamChunk:
  │   └── sseWriter.WriteChunkRaw(msgID, escapedHTML)  → SSE "chunk" event
  │
  ├── maybeGenerateTitle(sessionID, content)            # AI title gen
  ├── sseWriter.WriteSidebarRefresh(sessionID, title)   # HX-Trigger
  └── sseWriter.WriteDone(ctx, msgID, finalComponent)   # SSE "done" event
      │
      ▼
Browser: HTMX processes SSE events
  ├── "chunk" events → swap into assistant bubble (innerHTML)
  ├── Sidebar refresh → re-render session list
  └── "done" event → close SSE connection
```

### Message Processing Flow (CLI/TUI)

```
User types in terminal textarea
  │
  ├── Enter key → submit
  │
  ▼
TUI.handleKey() → StateInput → StateThinking
  │
  ├── startStream(query) → tea.Cmd
  │   │
  │   ├── Create buffered channel (100 items)
  │   ├── Spawn goroutine with 5-min timeout
  │   └── flow.Stream(ctx, Input{Query, SessionID})
  │       │
  │       └── [Same agent flow as Web Chat above]
  │
  ├── streamStartedMsg → StateStreaming
  │   ├── streamTextMsg → append to output.Builder
  │   ├── streamTextMsg → append to output.Builder
  │   └── ...
  │
  └── streamDoneMsg → StateInput
      ├── Append to messages slice (max 100)
      └── Clear output buffer
```

---

## 12. Gap Analysis

| Component | Status | Details |
|-----------|--------|---------|
| **Agent Runtime (Genkit flow-based)** | ✅ 完成 | `genkit.DefineStreamingFlow`, agentic loop with 5 max turns, retry + circuit breaker + rate limiting + token budget |
| **Channel Adapter: Telegram** | ❌ 尚未開始 | 無任何 Telegram 相關程式碼 |
| **Channel Adapter: LINE** | ❌ 尚未開始 | 無任何 LINE 相關程式碼 |
| **Channel Adapter: Web Chat** | ✅ 完成 | Templ SSR + HTMX + SSE streaming, session management, CSRF protection |
| **Permission Engine (Always/RequireApproval/RoleOnly)** | 🟡 部分完成 | **已完成**: `DangerLevel` enum (Safe/Warning/Dangerous/Critical), `ToolMetadata.RequiresConfirmation` flag, inline security validators (5 modules). **缺少**: Runtime approval flow (approve/reject UI), role-based access control, permission policy engine |
| **MCP Bridge (client + permission layer)** | 🟡 部分完成 | **已完成**: MCP Server (10 tools, stdio transport, official SDK v1.1.0). **缺少**: MCP Client (connecting to external MCP servers at runtime), permission layer for MCP tool calls |
| **Event Bus (structured events for observability)** | 🟡 部分完成 | **已完成**: `ToolEventEmitter` interface with `OnToolStart/Complete/Error`, context-based propagation, SSE tool status display. **缺少**: General-purpose event bus, structured event types beyond tools, event persistence, event subscribers/listeners pattern |
| **Memory: Short-term (conversation context)** | ✅ 完成 | `session.History` (thread-safe `[]*ai.Message`), token budget truncation (8K history limit), loaded from PostgreSQL per request |
| **Memory: Long-term (PostgreSQL cross-conversation)** | ✅ 完成 | `sessions` + `message` tables, JSONB content storage, sequence numbering, message status lifecycle (streaming/completed/failed), session listing with pagination |
| **Memory: Knowledge Base (RAG with pgvector)** | ✅ 完成 | `documents` table with vector(768), HNSW index, cosine similarity, 3 source types (conversation/file/system), 6 system knowledge docs, 3 knowledge tools for agent |
| **Session Management** | ✅ 完成 | PostgreSQL-backed `session.Store`, HTTP cookie sessions (30-day), CSRF tokens (HMAC-SHA256), lazy session creation, CLI session persistence (~/.koopa/current_session) |
| **Audit Logging (PostgreSQL)** | 🟡 部分完成 | **已完成**: slog-based security event logging (path traversal, command injection, SSRF, prompt injection). **缺少**: PostgreSQL audit table, queryable audit trail, audit log retention policy |
| **Approval Flow (pending → approved/rejected)** | ❌ 尚未開始 | `ToolMetadata.RequiresConfirmation` exists as schema but no runtime implementation. No pending state, no approval UI, no notification system |
| **Dashboard Frontend (Angular)** | ❌ 尚未開始 | 無 Angular 程式碼。目前只有 Templ SSR chat interface |
| **REST API for Dashboard** | 🟡 部分完成 | **已完成**: `GET /genui` (chat page), `POST /genui/send`, `GET /genui/stream` (SSE), `POST /genui/sessions/*`, `GET /health`, `GET /ready`. **缺少**: RESTful CRUD API for sessions/messages (JSON), admin/dashboard-specific endpoints, API versioning |
| **WebSocket for real-time events** | ❌ 尚未開始 | 目前使用 SSE (Server-Sent Events) 進行即時串流，無 WebSocket 實作 |
| **Docker Compose deployment** | 🟡 部分完成 | **已完成**: PostgreSQL + pgvector, SearXNG + Redis, health checks, volume mounts. **缺少**: Koopa 應用本身的 Dockerfile, production docker-compose profile, nginx/reverse proxy |
| **CLI / Configuration** | ✅ 完成 | 三種模式 (cli/serve/mcp), Viper config (.env + YAML), signal handling + graceful shutdown, Taskfile build system |

### Summary Table

| Status | Count | Items |
|--------|-------|-------|
| ✅ 完成 | 7 | Agent Runtime, Web Chat, Short-term Memory, Long-term Memory, Knowledge Base (RAG), Session Management, CLI/Config |
| 🟡 部分完成 | 6 | Permission Engine, MCP Bridge, Event Bus, Audit Logging, REST API, Docker Compose |
| ❌ 尚未開始 | 5 | Telegram Adapter, LINE Adapter, Approval Flow, Dashboard (Angular), WebSocket |

---

## Appendix: TODO/FIXME/HACK Comments

| File | Comment |
|------|---------|
| `internal/web/server.go:86-96` | TODO: Implement Settings and Search handlers |
| `internal/web/server.go:112-114` | TODO: Settings and Search routes |
| `internal/agent/chat/chat.go:412` | TODO: File Genkit GitHub issue (data race workaround) |
| `internal/app/app_test.go:108` | TODO: Re-enable when Toolset migration complete |
| `cmd/e2e_test.go:198-203` | FIXME: MCP server exits immediately (requires test harness) |
| `cmd/e2e_test.go:255-260` | FIXME: MCP communication fails with EOF (needs proper test client) |

---

## Appendix: Environment Configuration Template

**`.env.example`**:
```bash
# Required (All Modes)
GEMINI_API_KEY=your-api-key-here
DATABASE_URL=postgres://koopa:koopa_dev_password@localhost:5432/koopa?sslmode=disable

# Required (Web Mode Only)
HMAC_SECRET=  # openssl rand -base64 32

# Optional Model Settings
KOOPA_MODEL_NAME=gemini-2.5-flash
KOOPA_TEMPERATURE=0.7
KOOPA_MAX_TOKENS=2048
KOOPA_MAX_HISTORY_MESSAGES=100
KOOPA_RAG_TOP_K=3

# Optional
DEBUG=false
DD_API_KEY=  # Datadog APM
```

---

## Appendix: Build Commands

```bash
# Development
task build:dev              # Build with filesystem assets
task css:watch              # Watch CSS changes
task generate               # Generate templ files
task sqlc                   # Generate SQL code

# Testing
task test                   # All tests
task test:race              # With race detector
task test:unit              # Unit only
task test:integration       # With testcontainers
task test:fuzz              # Fuzz tests (30s each)
task test:e2e               # Playwright browser tests

# Quality
task lint                   # golangci-lint
task check                  # lint + test + build

# Production
task build                  # Embedded assets binary
go build -o koopa ./...     # Manual build
```
