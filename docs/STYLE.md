# koopa0.dev — 程式碼風格指南

> 不重複 Google Go Style Guide 的規則。用 codebase 的真實程式碼展示「我們怎麼做」。
> 對照 Google Style Guide 的 5 原則：Clarity > Simplicity > Concision > Maintainability > Consistency。

---

## Naming Conventions

### Package Names

所有 package 都遵循 lowercase single-word 規則：

```
activity, api, auth, budget, collected, collector, content, db, feed, flow,
flowrun, goal, mcp, note, notify, notion, obsidian, pipeline, project,
reconcile, review, server, session, stats, tag, task, topic, tracking,
upload, webhook
```

每個 package 都有 package-level doc comment：

```go
// Package task provides task tracking synced from Notion.
package task

// Package api provides shared HTTP response helpers for all handlers.
package api

// Package tag provides canonical tag management and normalization for the knowledge system.
package tag
```

**Google Style Guide 對齊度**：完全對齊。無 generic names（util, common, shared）。

### No Stutter

Package name 不會出現在 exported identifiers 裡：

```go
// 我們的做法（正確）
task.Task           // not task.TaskModel
task.Store          // not task.TaskStore
task.NewHandler     // not task.NewTaskHandler
task.Status         // not task.TaskStatus
content.Type        // not content.ContentType
tag.Resolved        // not tag.TagResolved
```

### Constructor Convention

Single constructor 用 `New`，多個 constructor 用 `NewX`：

```go
// internal/task/store.go
func NewStore(dbtx db.DBTX) *Store { return &Store{q: db.New(dbtx)} }

// internal/task/handler.go
func NewHandler(store *Store, logger *slog.Logger, opts ...HandlerOption) *Handler { ... }
```

Constructor 回傳 concrete type，不回傳 interface。

### Receiver Names

1-2 letter abbreviation of the type，一致使用：

| Type | Receiver | 用法 |
|------|----------|------|
| `*Store` | `s` | `func (s *Store) Tasks(ctx context.Context)` |
| `*Handler` | `h` | `func (h *Handler) List(w http.ResponseWriter, r *http.Request)` |
| `*Server` | `s` | `func (s *Server) completeTask(ctx context.Context, ...)` |
| `Task` | `t` | `func (t Task) IsRecurring() bool` |
| `Budget` | `b` | `func (b *Budget) Reserve(tokens int64) error` |
| `Feed` | `f` | implicit in filter methods |

**Google Style Guide 對齊度**：完全對齊。無 `this`, `self`, 或完整 type name。

### Interface Names

Consumer-defined，描述 caller 需要的 capability：

```go
// internal/task/handler.go — consumer 定義
type NotionClient interface {
    UpdatePageStatus(ctx context.Context, pageID, status string) error
    CreateTaskPage(ctx context.Context, databaseID, title, dueDate, description string) (string, error)
}

type DBIDResolver interface {
    DatabaseIDByRole(ctx context.Context, role string) (string, error)
}

// internal/pipeline/handler.go — consumer 定義 16 個小 interfaces
type ContentReader interface {
    ContentBySlug(ctx context.Context, slug string) (*content.Content, error)
}

type EventRecorder interface {
    CreateEvent(ctx context.Context, p activity.RecordParams) (int64, error)
}
```

每個 interface 1-3 methods，不存在 god interface。

**Google Style Guide 對齊度**：完全對齊。Consumer-side interfaces, small granularity。

### Constant Naming

Named string types for enums，MixedCaps constants：

```go
// internal/task/task.go
type Status string

const (
    StatusTodo       Status = "todo"
    StatusInProgress Status = "in-progress"
    StatusDone       Status = "done"
)

// internal/content/content.go
type Type string

const (
    TypeArticle  Type = "article"
    TypeEssay    Type = "essay"
    TypeBuildLog Type = "build-log"
    TypeTIL      Type = "til"
)
```

Pattern: `<TypeName><Value>`。附帶 `Valid()` validation method：

```go
func (t Type) Valid() bool {
    switch t {
    case TypeArticle, TypeEssay, TypeBuildLog, TypeTIL, TypeNote, TypeBookmark, TypeDigest:
        return true
    default:
        return false
    }
}
```

### Store Method Naming

| Pattern | 範例（from codebase） |
|---------|----------------------|
| Single by key | `s.Tag(ctx, id)`, `s.Order(ctx, id)` |
| By alternate key | `s.TagBySlug(ctx, slug)`, `s.ContentBySlug(ctx, slug)` |
| List | `s.Tasks(ctx)`, `s.Tags(ctx)`, `s.Contents(ctx, filter)` |
| Create | `s.CreateTag(ctx, params)`, `s.CreateContent(ctx, params)` |
| Update | `s.UpdateTag(ctx, id, params)` |
| Delete | `s.DeleteTag(ctx, id)` |
| Upsert (Notion sync) | `s.UpsertByNotionPageID(ctx, params)` |

無 `Get`, `Find`, `Fetch` prefix。

---

## Code Organization

### File Structure Per Feature

每個 feature package 遵循固定檔案結構：

```
internal/task/
├── task.go          ← Types, Status enum, sentinel errors, helper methods
├── handler.go       ← HTTP handlers, consumer-defined interfaces, HandlerOption
├── store.go         ← Database operations via sqlc (db.Queries)
├── query.sql        ← sqlc query definitions
└── task_test.go     ← All tests
```

Optional files（when feature uses AI）：
```
├── flow.go          ← Genkit flow definitions
└── tool.go          ← Genkit tool definitions
```

### Import Grouping

三組，blank line 分隔：

```go
import (
    "context"
    "fmt"
    "log/slog"
    "net/http"

    "github.com/google/uuid"

    "github.com/koopa0/blog-backend/internal/api"
    "github.com/koopa0/blog-backend/internal/db"
)
```

1. Standard library
2. Third-party
3. Local project

### Interface 放在 Consumer 端

Interfaces 定義在使用者的檔案裡，不是 provider 的檔案裡：

```go
// internal/task/handler.go — task package 定義它需要的 Notion interface
type NotionClient interface {
    UpdatePageStatus(ctx context.Context, pageID, status string) error
    CreateTaskPage(ctx context.Context, databaseID, title, dueDate, description string) (string, error)
}

// internal/mcp/mcp.go — MCP server 定義它需要的 task interface
type TaskReader interface {
    PendingTasksWithProject(ctx context.Context) ([]task.PendingTaskDetail, error)
    TaskByID(ctx context.Context, id uuid.UUID) (*task.Task, error)
}
```

Provider（Store）回傳 concrete type，滿足任何 consumer 的 interface：

```go
// internal/task/store.go — 回傳 *Store，不是 interface
func NewStore(dbtx db.DBTX) *Store { return &Store{q: db.New(dbtx)} }
```

---

## Error Handling

### Sentinel Errors

定義在 `<feature>.go`，package-level `var`：

```go
// internal/tag/tag.go
var (
    ErrNotFound      = errors.New("not found")
    ErrConflict      = errors.New("conflict")
    ErrHasReferences = errors.New("has references")
)

// internal/budget/budget.go
var ErrOverBudget = errors.New("over budget")
```

每個 feature 只定義 handler 實際 branch on 的 errors。

### Error Wrapping

Lowercase, no punctuation, context + variable：

```go
// internal/task/store.go
return nil, fmt.Errorf("listing tasks: %w", err)
return nil, fmt.Errorf("upserting task %s: %w", p.NotionPageID, err)

// internal/auth/store.go
return nil, fmt.Errorf("querying user by id: %w", err)
```

### pgx.ErrNoRows → Sentinel

Store 層把 pgx 的 infrastructure error 轉成 domain sentinel：

```go
// Pattern across all stores
if errors.Is(err, pgx.ErrNoRows) {
    return nil, ErrNotFound
}
return nil, fmt.Errorf("querying content %s: %w", id, err)
```

Unique constraint violation → `ErrConflict`：

```go
var pgErr *pgconn.PgError
if errors.As(err, &pgErr) && pgErr.Code == "23505" {
    return nil, ErrConflict
}
```

### Handler Error Mapping

Handler 把 sentinel errors map 到 HTTP status：

```go
// internal/task/handler.go
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
    tasks, err := h.store.Tasks(r.Context())
    if err != nil {
        h.logger.Error("listing tasks", "error", err)
        api.Error(w, http.StatusInternalServerError, "INTERNAL", "failed to list tasks")
        return
    }
    api.Encode(w, http.StatusOK, api.Response{Data: tasks})
}
```

MCP error handling 則直接 return error（MCP SDK handles error formatting）：

```go
// internal/mcp/write_tools.go
if input.TaskID == "" && input.TaskTitle == "" {
    return nil, CompleteTaskOutput{}, fmt.Errorf("either task_id or task_title is required")
}
```

---

## Dependency Injection

### Simple Constructor（0-2 optional params）

大部分 stores 和 handlers 用 direct parameter injection：

```go
// internal/task/store.go
func NewStore(dbtx db.DBTX) *Store {
    return &Store{q: db.New(dbtx)}
}

// internal/content/handler.go
func NewHandler(
    store *Store,
    siteURL string,
    graphCache *ristretto.Cache[string, *KnowledgeGraph],
    feedCache *ristretto.Cache[string, []byte],
    logger *slog.Logger,
) *Handler {
    return &Handler{
        store:      store,
        siteURL:    siteURL,
        graphCache: graphCache,
        feedCache:  feedCache,
        logger:     logger,
    }
}
```

### Functional Options（3+ optional params）

當有多個 optional dependencies 時用 functional options：

```go
// internal/task/handler.go
type HandlerOption func(*Handler)

func WithNotion(n NotionClient, r DBIDResolver) HandlerOption {
    return func(h *Handler) {
        h.notion = n
        h.dbResolver = r
    }
}

func WithProjectResolver(p ProjectResolver) HandlerOption {
    return func(h *Handler) { h.projects = p }
}

func NewHandler(store *Store, logger *slog.Logger, opts ...HandlerOption) *Handler {
    h := &Handler{store: store, logger: logger}
    for _, o := range opts {
        o(h)
    }
    return h
}
```

```go
// internal/mcp/server.go
type ServerOption func(*Server)

func WithNotionTaskWriter(n NotionTaskWriter, resolver TaskDBIDResolver) ServerOption {
    return func(s *Server) {
        s.notionTasks = n
        s.taskDBResolver = resolver
    }
}

func NewServer(notes NoteSearcher, activity ActivityReader, /* ... */ opts ...ServerOption) *Server {
    s := &Server{/* ... */}
    for _, opt := range opts {
        opt(s)
    }
    return s
}
```

### No DI Container

所有 wiring 在 `cmd/app/main.go` 手動完成。沒有 wire、dig、fx 等 DI framework：

```go
// cmd/app/main.go — 手動 wiring
taskStore := task.NewStore(pool)
taskHandler := task.NewHandler(taskStore, logger,
    task.WithNotion(notionClient, notionStore),
    task.WithProjectResolver(projectResolver),
)
```

---

## Database Patterns

### Store Struct

每個 feature 的 store 持有 `*db.Queries`（sqlc generated）：

```go
type Store struct {
    q *db.Queries
}

func NewStore(dbtx db.DBTX) *Store {
    return &Store{q: db.New(dbtx)}
}
```

`db.DBTX` interface 讓 store 可以用 pool 或 transaction：

```go
// db.DBTX (sqlc generated)
type DBTX interface {
    Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
    Query(context.Context, string, ...interface{}) (pgx.Rows, error)
    QueryRow(context.Context, string, ...interface{}) pgx.Row
}
```

### WithTx Pattern

Store 支援 transaction wrapping（用於跨 store 操作）：

```go
func (s *Store) WithTx(tx pgx.Tx) *Store {
    return &Store{q: db.New(tx)}
}
```

### Row Conversion

sqlc generated 的 row types 轉成 domain types 用 private helper：

```go
func rowToTask(r db.Task) Task {
    return Task{
        ID:            r.ID,
        Title:         r.Title,
        Status:        Status(r.Status),
        Due:           r.Due,
        // ...
    }
}
```

### Query Naming Convention

sqlc query names 遵循 store method naming（見 query.sql）：

```sql
-- name: Tasks :many
SELECT * FROM tasks ORDER BY ...;

-- name: PendingTasks :many
SELECT * FROM tasks WHERE status != 'done' ORDER BY ...;

-- name: UpsertTaskByNotionPageID :one
INSERT INTO tasks (...) VALUES (...) ON CONFLICT (notion_page_id) DO UPDATE SET ...
RETURNING *;
```

### Pre-allocation

List methods 預分配 slice：

```go
tasks := make([]Task, len(rows))
for i, r := range rows {
    tasks[i] = rowToTask(r)
}
```

或用 `make([]T, 0, len(rows))` + `append` 當需要 filtering：

```go
tasks := make([]flow.PendingTask, 0, len(rows))
for _, r := range rows {
    // conditional logic
    tasks = append(tasks, ...)
}
```

---

## HTTP Patterns

### Generic Response Helpers

`internal/api/api.go` 提供 type-safe generic helpers：

```go
// Decode — 1 MB size limit, returns typed T
body, err := api.Decode[CreateParams](w, r)

// Encode — sets Content-Type, writes status + JSON
api.Encode(w, http.StatusOK, api.Response{Data: tasks})

// Error — standard error format
api.Error(w, http.StatusNotFound, "NOT_FOUND", "task not found")

// PagedResponse — pagination meta
api.Encode(w, http.StatusOK, api.PagedResponse(items, total, page, perPage))
```

### Handler Method Signature

所有 HTTP handler methods 用標準 `http.HandlerFunc` 簽名：

```go
func (h *Handler) List(w http.ResponseWriter, r *http.Request) { ... }
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) { ... }
func (h *Handler) Complete(w http.ResponseWriter, r *http.Request) { ... }
```

### Path Parameter Extraction

Go 1.22+ `PathValue`：

```go
id := r.PathValue("id")
slug := r.PathValue("slug")
```

### Pagination

統一用 `api.ParsePagination`（defaults: page=1, perPage=20, max=100）：

```go
page, perPage := api.ParsePagination(r)
```

### Response Format

```json
// Success with pagination
{
  "data": [...],
  "meta": { "total": 42, "page": 1, "per_page": 20, "total_pages": 3 }
}

// Success without pagination
{ "data": { ... } }

// Error
{
  "error": { "code": "NOT_FOUND", "message": "task not found" }
}
```

---

## Testing

### Table-Driven Tests

Mandatory for 2+ test cases：

```go
// internal/tag/tag_test.go
func TestSlugify(t *testing.T) {
    tests := []struct {
        name  string
        input string
        want  string
    }{
        {name: "lowercase", input: "golang", want: "golang"},
        {name: "uppercase", input: "GoLang", want: "golang"},
        {name: "spaces", input: "hello world", want: "hello-world"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := Slugify(tt.input)
            if got != tt.want {
                t.Errorf("Slugify(%q) = %q, want %q", tt.input, got, tt.want)
            }
        })
    }
}
```

### go-cmp for Comparisons

Never testify：

```go
if diff := cmp.Diff(want, got); diff != "" {
    t.Errorf("mismatch (-want +got):\n%s", diff)
}
```

### Error Assertion Pattern

```go
if tt.wantErr {
    if err == nil {
        t.Fatal("expected error, got nil")
    }
    return
}
if err != nil {
    t.Fatalf("FuncName() unexpected error: %v", err)
}
```

### Integration Tests

`//go:build integration` tag + testcontainers-go for PostgreSQL：

```go
//go:build integration

func TestStore_Integration(t *testing.T) {
    ctx := t.Context()
    pool := setupTestDB(t)  // testcontainers PostgreSQL
    store := NewStore(pool)
    // ...
}
```

### Fuzz Tests

Pure function 有 fuzz test coverage：

```go
func FuzzSlugify(f *testing.F) {
    f.Add("hello world")
    f.Add("GoLang")
    f.Fuzz(func(t *testing.T, input string) {
        result := Slugify(input)
        // assert invariants
    })
}
```

---

## MCP Tool Patterns

### Input Struct with JSON Schema

```go
type CompleteTaskInput struct {
    TaskID    string `json:"task_id,omitempty" jsonschema_description:"Notion page ID or local task UUID"`
    TaskTitle string `json:"task_title,omitempty" jsonschema_description:"fuzzy match against pending task titles"`
    Notes     string `json:"notes,omitempty" jsonschema_description:"completion notes"`
}
```

### Tool Handler Signature

```go
func (s *Server) completeTask(
    ctx context.Context,
    _ *mcp.CallToolRequest,
    input CompleteTaskInput,
) (*mcp.CallToolResult, CompleteTaskOutput, error) {
    // validation
    if input.TaskID == "" && input.TaskTitle == "" {
        return nil, CompleteTaskOutput{}, fmt.Errorf("either task_id or task_title is required")
    }
    // implementation
    return nil, output, nil
}
```

### Error Handling in MCP

直接 return error（MCP SDK formats it）。不用 `api.Error`。

---

## Anti-patterns（坦誠列出）

### Known Issues

| Issue | 位置 | 說明 | 改進方向 |
|-------|------|------|---------|
| **Store imports flow types** | `task/store.go` imports `flow` | Store 回傳 `flow.PendingTask` 類型，造成 store 依賴 flow package | 應在 task package 定義自己的 type，或讓 flow 定義 interface |
| **Handler error messages 不完全一致** | 各 handler.go | 有些用 `"failed to list X"`，有些用 `"listing X"` | 統一用 gerund（`"listing tasks"`） |
| **UpdateParams 有些用 pointer，有些不用** | 各 feature.go | `tag.UpdateParams` 用 `*string` 表示 optional，但 `task.UpsertByNotionParams` 用 zero value | 統一用 pointer for optional update fields |
| **JSON tag 不一致** | 部分 domain types | `Tag` struct 沒有 JSON tags，但 `Task` struct 有 | 所有公開 API 回傳的 types 都應有 JSON tags |
| **ProjectResolver 是 func type 而非 interface** | `task/handler.go` | `type ProjectResolver func(ctx, slug) (uuid.UUID, string, error)` 跟其他 dependencies 用 interface 不一致 | 考慮統一用 interface（但 func type 對單一 method 也是合理的 Go pattern） |
| **Mixed receiver semantics** | `task.Task` | `IsRecurring()` 和 `NextDue()` 用 value receiver（`func (t Task)`），但 Task 有 pointer fields | Value receiver 是正確的（read-only methods），但需要注意不要在 pointer field 上 mutate |

### Google Style Guide 對照

| Google Style Guide 原則 | 我們的遵循度 | 備註 |
|------------------------|-------------|------|
| Package names: short, lowercase, no underscores | ✅ 完全遵循 | 所有 30 個 packages |
| No stutter in exported names | ✅ 完全遵循 | `task.Task` 而非 `task.TaskModel` |
| Consumer-defined interfaces | ✅ 完全遵循 | pipeline 和 mcp 的 interface 定義 |
| Return concrete, not interface | ✅ 完全遵循 | 所有 constructor |
| Wrap errors with context | ✅ 完全遵循 | `fmt.Errorf("context: %w", err)` |
| Doc comments on exported symbols | ⚠️ 大部分遵循 | 個別 struct fields 缺少 doc comment |
| Synchronous by default | ✅ 完全遵循 | 只有 pipeline 和 cron 用 goroutines |
| Avoid init() | ✅ 完全遵循 | 無 init() 使用 |
| Import grouping (3 groups) | ✅ 完全遵循 | stdlib / third-party / local |

### Positive Patterns（值得保持的）

| Pattern | 範例 | 為什麼好 |
|---------|------|---------|
| Generic API helpers | `api.Encode[T]`, `api.Decode[T]` | Type-safe，消除所有 handler 的 boilerplate |
| 4-step tag resolution | `tag.Resolved` with `MatchMethod` | Traceable normalization，不是 black box |
| Functional options for optional deps | `task.WithNotion(...)` | Required deps 在 constructor params，optional 在 options |
| Named string types for enums | `task.Status`, `content.Type` | Type safety + validation method |
| `WithTx` pattern | `store.WithTx(tx) *Store` | 乾淨的 transaction 支援，不改原始 store |
| Params structs | `CreateParams`, `UpdateParams` | Intent-based，不用 bare struct 初始化 |
| MCP input with jsonschema | `jsonschema_description` tags | Self-documenting tool interface |
