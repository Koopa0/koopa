---
name: go-compliance-test
description: >-
  Trap-pattern test scenarios for AI self-validation — verifies generated Go
  code follows project conventions and catches common AI mistakes in naming,
  concurrency, error handling, architecture, and testing.
metadata:
  author: koopa
  version: "1.0"
  language: go
---

# Skill: Go AI Compliance Testing

## Purpose

Self-validation trap patterns for Go code generation. AI should automatically check against these traps before submitting any Go code. Covers 5 categories of common AI mistakes.

---

## Usage

AI should cross-reference these traps when generating or reviewing Go code. Each trap has a grep-searchable verification point.

---

## Trap Type 1: Go Convention Traps

### Trap 1.1: Get Prefix on Methods

```go
// ❌ Trap: using Get prefix
func (s *Store) GetUserByID(ctx context.Context, id string) (*User, error) {
    // ...
}

// ✅ Correct: Go doesn't use Get prefix
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
    // ...
}
```

**Verification**: search `func.*Get[A-Z]` in non-generated code → should be 0

### Trap 1.2: interface{} Instead of any

```go
// ❌ Trap: using interface{} (pre-Go 1.18)
func process(data interface{}) error {
    // ...
}

// ✅ Correct: use any (Go 1.18+)
func process(data any) error {
    // ...
}
```

**Verification**: search `interface\{\}` → should be 0

### Trap 1.3: Error Message Formatting

```go
// ❌ Trap: capitalized error, punctuation
return fmt.Errorf("Failed to query user: %w.", err)
return errors.New("User not found.")

// ✅ Correct: lowercase, no punctuation
return fmt.Errorf("querying user: %w", err)
return errors.New("user not found")
```

**Verification**: search `fmt.Errorf\("[A-Z]` and `errors.New\("[A-Z]` → should be 0

### Trap 1.4: Unnecessary init()

```go
// ❌ Trap: using init() for setup
func init() {
    db = connectDB()
    cache = newCache()
}

// ✅ Correct: explicit initialization in main or constructors
func main() {
    db, err := connectDB()
    if err != nil {
        log.Fatal(err)
    }
    cache := newCache()
    // ...
}
```

**Verification**: search `func init()` → should be 0 (except rare justified cases with comment)

### Trap 1.5: panic for Recoverable Errors

```go
// ❌ Trap: panic on recoverable error
func loadConfig(path string) *Config {
    data, err := os.ReadFile(path)
    if err != nil {
        panic(err)  // Trap!
    }
    // ...
}

// ✅ Correct: return error
func loadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("reading config %s: %w", path, err)
    }
    // ...
}
```

**Verification**: search `panic(err)` and `panic(fmt` → should be 0

### Trap 1.6: Bad Package Names

```go
// ❌ Trap: camelCase or underscore in package name
package userProfile
package user_profile
package common_utils

// ✅ Correct: single lowercase word
package user
package profile
```

**Verification**: search `^package [a-z]*[A-Z_]` → should be 0

### Trap 1.7: Exported Names Stutter

```go
// ❌ Trap: package name repeated in exported name
package user
type UserService struct{}     // user.UserService stutters
func NewUserStore() *Store {} // user.NewUserStore stutters

// ✅ Correct: no stutter
package user
type Service struct{}         // user.Service
func NewStore() *Store {}     // user.NewStore
```

**Verification**: review exported names — should not repeat package name

---

## Trap Type 2: Concurrency Traps

### Trap 2.1: t.Fatal in Goroutine

```go
// ❌ Trap: t.Fatal/t.FailNow in goroutine — undefined behavior
func TestConcurrent(t *testing.T) {
    go func() {
        result, err := doWork()
        if err != nil {
            t.Fatal(err)  // Trap! runtime.Goexit in non-test goroutine
        }
    }()
}

// ✅ Correct: use t.Error (non-fatal) or channel
func TestConcurrent(t *testing.T) {
    errc := make(chan error, 1)
    go func() {
        _, err := doWork()
        errc <- err
    }()
    if err := <-errc; err != nil {
        t.Fatal(err)  // OK — in test goroutine
    }
}
```

**Verification**: search goroutine bodies for `t.Fatal` or `t.FailNow`

### Trap 2.2: Goroutine Without Exit Condition

```go
// ❌ Trap: goroutine runs forever — leak
func startWorker(jobs <-chan Job) {
    go func() {
        for job := range jobs {
            process(job)
        }
    }()
    // Who closes the jobs channel? When does this goroutine stop?
}

// ✅ Correct: context cancellation for lifecycle
func startWorker(ctx context.Context, jobs <-chan Job) {
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            case job, ok := <-jobs:
                if !ok {
                    return
                }
                process(job)
            }
        }
    }()
}
```

**Verification**: every `go func()` should have either `ctx.Done()` select case or a bounded channel

### Trap 2.3: sync.Mutex for Read-Only Operations

```go
// ❌ Trap: Mutex for read-heavy workload
type Cache struct {
    mu    sync.Mutex
    items map[string]Item
}

func (c *Cache) Get(key string) (Item, bool) {
    c.mu.Lock()         // Blocks ALL other readers
    defer c.mu.Unlock()
    item, ok := c.items[key]
    return item, ok
}

// ✅ Correct: RWMutex when reads >> writes
type Cache struct {
    mu    sync.RWMutex
    items map[string]Item
}

func (c *Cache) Get(key string) (Item, bool) {
    c.mu.RLock()        // Allows concurrent readers
    defer c.mu.RUnlock()
    item, ok := c.items[key]
    return item, ok
}
```

**Verification**: if struct has `sync.Mutex` + read-only methods → should be `sync.RWMutex`

### Trap 2.4: I/O While Holding Mutex

```go
// ❌ Trap: HTTP call while holding lock — blocks all waiters
func (s *Service) RefreshToken() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    token, err := s.httpClient.FetchToken()  // Trap! I/O under lock
    if err != nil {
        return err
    }
    s.token = token
    return nil
}

// ✅ Correct: do I/O outside lock
func (s *Service) RefreshToken() error {
    token, err := s.httpClient.FetchToken()  // I/O outside lock
    if err != nil {
        return err
    }
    s.mu.Lock()
    s.token = token
    s.mu.Unlock()
    return nil
}
```

**Verification**: code between `Lock()` and `Unlock()` should not contain HTTP/DB/file I/O

### Trap 2.5: defer Unlock in Loop

```go
// ❌ Trap: defer only runs at function return, not loop iteration
func processItems(items []Item) {
    for _, item := range items {
        mu.Lock()
        defer mu.Unlock()  // Trap! Defers stack up, only unlock at function end
        process(item)
    }
}

// ✅ Correct: explicit unlock or extract to function
func processItems(items []Item) {
    for _, item := range items {
        mu.Lock()
        process(item)
        mu.Unlock()  // Explicit unlock each iteration
    }
}

// ✅ Also correct: extract to function
func processItems(items []Item) {
    for _, item := range items {
        processItem(item)  // defer works correctly inside
    }
}

func processItem(item Item) {
    mu.Lock()
    defer mu.Unlock()
    process(item)
}
```

**Verification**: search `defer.*Unlock` inside `for` or `range` loops

---

## Trap Type 3: Error Handling Traps

### Trap 3.1: Log AND Return Error

```go
// ❌ Trap: same error logged and returned — appears twice in logs
func (s *Store) CreateOrder(ctx context.Context, o *Order) error {
    if err := s.db.Insert(ctx, o); err != nil {
        slog.Error("failed to create order", "error", err)  // Logged here
        return fmt.Errorf("creating order: %w", err)         // AND returned
    }
    return nil
}

// ✅ Correct: wrap and return — let the handler decide to log
func (s *Store) CreateOrder(ctx context.Context, o *Order) error {
    if err := s.db.Insert(ctx, o); err != nil {
        return fmt.Errorf("creating order: %w", err)  // Wrap only
    }
    return nil
}
```

**Verification**: search for `slog.Error.*\n.*return.*fmt.Errorf` pattern

### Trap 3.2: Direct Error Comparison

```go
// ❌ Trap: direct comparison doesn't traverse wrap chain
if err == sql.ErrNoRows {
    return ErrNotFound
}

// ✅ Correct: errors.Is traverses the chain
if errors.Is(err, sql.ErrNoRows) {
    return ErrNotFound
}
```

**Verification**: search `err == ` and `err != ` with error variables → should use `errors.Is`

### Trap 3.3: Naked Return Without Context

```go
// ❌ Trap: no wrapping context — loses call site info
func (s *Store) Order(ctx context.Context, id string) (*Order, error) {
    row, err := s.q.Order(ctx, id)
    if err != nil {
        return nil, err  // Trap! Where did this error come from?
    }
    return mapOrder(row), nil
}

// ✅ Correct: wrap with context
func (s *Store) Order(ctx context.Context, id string) (*Order, error) {
    row, err := s.q.Order(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("querying order %s: %w", id, err)
    }
    return mapOrder(row), nil
}
```

**Verification**: search `return.*nil, err$` without preceding `fmt.Errorf` → suspicious

### Trap 3.4: String Matching on Errors

```go
// ❌ Trap: string matching is fragile
if strings.Contains(err.Error(), "not found") {
    return ErrNotFound
}

// ✅ Correct: use errors.Is or errors.As
if errors.Is(err, pgx.ErrNoRows) {
    return ErrNotFound
}
```

**Verification**: search `err.Error()` used in `strings.Contains` → should be 0

### Trap 3.5: %w Leaking Internal Types at API Boundary

```go
// ❌ Trap: %w at API boundary exposes internal pgx error type
func (h *Handler) GetOrder(w http.ResponseWriter, r *http.Request) {
    order, err := h.store.Order(r.Context(), id)
    if err != nil {
        // Callers can now errors.As for pgconn.PgError — leaking implementation
        http.Error(w, fmt.Sprintf("failed: %w", err), 500)
    }
}

// ✅ Correct: %v at API boundary to break the chain
// Or better: use handleError() with domain error mapping
```

**Verification**: search `%w` in handler/HTTP response code → should use `%v` or `handleError`

---

## Trap Type 4: Architecture Traps

### Trap 4.1: Cross-Feature Store Import

```go
// ❌ Trap: feature directly imports another feature's store
package notification

import "myapp/internal/order"  // Trap! Direct dependency on order's internals

func (s *Service) NotifyOrderStatus(ctx context.Context, orderID string) error {
    o, err := order.NewStore(s.db).Order(ctx, orderID)  // Tight coupling
    // ...
}

// ✅ Correct: define consumer-side interface
package notification

type OrderReader interface {
    Order(ctx context.Context, id string) (*Order, error)
}

func (s *Service) NotifyOrderStatus(ctx context.Context, reader OrderReader, id string) error {
    o, err := reader.Order(ctx, id)
    // ...
}
```

**Verification**: feature packages should not import other feature packages' store types

### Trap 4.2: os.Getenv Outside main.go

```go
// ❌ Trap: reading env vars in feature package
package order

func NewStore() *Store {
    dbURL := os.Getenv("DATABASE_URL")  // Trap! Config should be injected
    // ...
}

// ✅ Correct: accept config as parameter
package order

func NewStore(dbURL string) *Store {
    // ...
}

// main.go is the only place that reads os.Getenv
```

**Verification**: search `os.Getenv` outside `main.go` and `*_test.go` → should be 0

### Trap 4.3: Handler Receives Entire Config

```go
// ❌ Trap: handler knows about entire config struct
func NewHandler(cfg *config.Config) *Handler {
    return &Handler{cfg: cfg}  // Handler can access DB password, JWT secret, etc.
}

// ✅ Correct: accept only what's needed
func NewHandler(apiURL string, timeout time.Duration) *Handler {
    return &Handler{apiURL: apiURL, timeout: timeout}
}
```

**Verification**: handlers should not receive `*config.Config` — accept individual values

### Trap 4.4: Business Logic in Store Layer

```go
// ❌ Trap: store does business validation
func (s *Store) CreateOrder(ctx context.Context, o *Order) error {
    // Business logic in store — wrong layer
    if o.Total < 0 {
        return ErrInvalidInput
    }
    if o.Items == nil || len(o.Items) == 0 {
        return ErrInvalidInput
    }
    // ... DB insert
}

// ✅ Correct: business logic in service, store does DB only
// service.go
func (svc *Service) CreateOrder(ctx context.Context, o *Order) error {
    if err := validateOrder(o); err != nil {
        return err
    }
    return svc.store.CreateOrder(ctx, o)
}

// store.go — DB operations only
func (s *Store) CreateOrder(ctx context.Context, o *Order) error {
    _, err := s.q.CreateOrder(ctx, mapCreateParams(o))
    if err != nil {
        return fmt.Errorf("inserting order: %w", err)
    }
    return nil
}
```

**Verification**: store methods should not contain validation logic or business rules

### Trap 4.5: Deep Package Nesting (DDD/Layered Architecture)

```go
// ❌ Trap: over-structured DDD layers
internal/
  domain/
    entities/
      order.go
    repositories/
      order_repository.go
    services/
      order_service.go
  infrastructure/
    persistence/
      postgres/
        order_repo_impl.go

// ✅ Correct: flat, package-by-feature
internal/
  order/
    order.go       // types + sentinel errors
    store.go       // DB operations
    service.go     // business logic (if needed)
    handler.go     // HTTP handlers
    handler_test.go
```

**Verification**: no `domain/`, `entities/`, `repositories/`, `infrastructure/` directories

---

## Trap Type 5: Testing Traps

### Trap 5.1: Mocking Everything

```go
// ❌ Trap: mocking the database instead of using real DB
func TestCreateOrder(t *testing.T) {
    mockDB := &MockDB{}  // Trap! Doesn't test real SQL
    mockDB.On("Insert", mock.Anything).Return(nil)
    store := NewStore(mockDB)
    // ...
}

// ✅ Correct: use testcontainers for integration tests
func TestCreateOrder(t *testing.T) {
    ctx := context.Background()
    db := setupTestDB(t)  // Real Postgres via testcontainers
    store := NewStore(db)

    err := store.CreateOrder(ctx, testOrder())
    require.NoError(t, err)
}
```

**Verification**: search `Mock` or `mock.` in store tests → prefer testcontainers

### Trap 5.2: Testing Implementation Details

```go
// ❌ Trap: testing internal method calls
func TestService(t *testing.T) {
    mockStore := &MockStore{}
    mockStore.On("FindByID", "123").Return(order, nil)
    svc := NewService(mockStore)
    svc.Process("123")
    mockStore.AssertCalled(t, "FindByID", "123")  // Trap! Tests HOW, not WHAT
}

// ✅ Correct: test observable behavior
func TestService(t *testing.T) {
    db := setupTestDB(t)
    store := NewStore(db)
    svc := NewService(store)

    result, err := svc.Process(ctx, "123")
    require.NoError(t, err)
    assert.Equal(t, "processed", result.Status)  // Tests WHAT happened
}
```

**Verification**: `AssertCalled` / `AssertNumberOfCalls` → testing implementation, not behavior

### Trap 5.3: Hardcoded UUIDs

```go
// ❌ Trap: hardcoded UUID — collision risk, unclear intent
func TestOrder(t *testing.T) {
    order := &Order{
        ID:     "550e8400-e29b-41d4-a716-446655440000",  // Trap!
        UserID: "550e8400-e29b-41d4-a716-446655440001",
    }
}

// ✅ Correct: generate UUIDs
func TestOrder(t *testing.T) {
    order := &Order{
        ID:     uuid.NewString(),
        UserID: uuid.NewString(),
    }
}
```

**Verification**: search hardcoded UUID patterns in test files

### Trap 5.4: os.Setenv Without Cleanup

```go
// ❌ Trap: os.Setenv leaks to other tests
func TestConfig(t *testing.T) {
    os.Setenv("API_URL", "http://test")  // Trap! Not cleaned up
    cfg := LoadConfig()
    // ...
}

// ✅ Correct: t.Setenv auto-cleans
func TestConfig(t *testing.T) {
    t.Setenv("API_URL", "http://test")  // Automatically restored after test
    cfg := LoadConfig()
    // ...
}
```

**Verification**: search `os.Setenv` in `*_test.go` → should use `t.Setenv`

### Trap 5.5: Missing t.Parallel()

```go
// ❌ Trap: tests run sequentially by default — slow
func TestOrderCreate(t *testing.T) {
    // ... (no t.Parallel())
}

// ✅ Correct: mark independent tests as parallel
func TestOrderCreate(t *testing.T) {
    t.Parallel()
    // ...
}
```

**Verification**: top-level test functions should call `t.Parallel()` unless they share state

---

## Automated Verification Script

```bash
#!/bin/bash
# scripts/go-compliance-check.sh

echo "╔══════════════════════════════════════╗"
echo "║   Go AI Compliance Trap Detection    ║"
echo "╚══════════════════════════════════════╝"

errors=0

# Convention Traps
echo "▸ Go Conventions..."
for pattern in 'interface{}' 'func init()' 'panic(err)' 'panic(fmt'; do
  count=$(grep -rc "$pattern" internal/ cmd/ --include="*.go" --exclude="*_test.go" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
  if [ "$count" -gt 0 ]; then
    echo "  ❌ $pattern: $count occurrences"
    errors=$((errors + count))
  fi
done

# Error formatting
cap_errors=$(grep -rcE 'fmt\.Errorf\("[A-Z]|errors\.New\("[A-Z]' internal/ cmd/ --include="*.go" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$cap_errors" -gt 0 ]; then
  echo "  ❌ Capitalized error messages: $cap_errors"
  errors=$((errors + cap_errors))
fi

# Error Handling Traps
echo "▸ Error Handling..."
string_match=$(grep -rc 'strings.Contains(err.Error()' internal/ --include="*.go" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$string_match" -gt 0 ]; then
  echo "  ❌ String matching on errors: $string_match"
  errors=$((errors + string_match))
fi

direct_cmp=$(grep -rcE 'err == Err|err != Err' internal/ --include="*.go" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$direct_cmp" -gt 0 ]; then
  echo "  ❌ Direct error comparison (use errors.Is): $direct_cmp"
  errors=$((errors + direct_cmp))
fi

# Architecture Traps
echo "▸ Architecture..."
env_outside_main=$(grep -rc 'os.Getenv' internal/ --include="*.go" --exclude="*_test.go" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$env_outside_main" -gt 0 ]; then
  echo "  ❌ os.Getenv outside main: $env_outside_main"
  errors=$((errors + env_outside_main))
fi

# Testing Traps
echo "▸ Testing..."
os_setenv=$(grep -rc 'os.Setenv' internal/ cmd/ --include="*_test.go" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
if [ "$os_setenv" -gt 0 ]; then
  echo "  ❌ os.Setenv in tests (use t.Setenv): $os_setenv"
  errors=$((errors + os_setenv))
fi

echo ""
echo "════════════════════════════════════════"
if [ "$errors" -eq 0 ]; then
  echo "✅ All compliance checks passed"
else
  echo "❌ Found $errors compliance issues"
fi
```

---

## AI Self-Check Checklist

Before submitting Go code, verify:

### Conventions
- [ ] No `Get` prefix on methods (`UserByID` not `GetUserByID`)
- [ ] Using `any` not `interface{}`
- [ ] Error messages lowercase, no punctuation
- [ ] No `init()` without justified comment
- [ ] No `panic` for recoverable errors
- [ ] Package names are single lowercase words
- [ ] Exported names don't stutter with package name

### Concurrency
- [ ] No `t.Fatal`/`t.FailNow` in goroutines
- [ ] Every goroutine has exit condition (`ctx.Done()` or bounded channel)
- [ ] `sync.RWMutex` for read-heavy workloads, not `sync.Mutex`
- [ ] No I/O while holding mutex
- [ ] No `defer mu.Unlock()` inside loops

### Error Handling
- [ ] Never log AND return the same error
- [ ] Using `errors.Is` not `==` for error comparison
- [ ] Every returned error has wrapping context (`fmt.Errorf("doing X: %w", err)`)
- [ ] No `strings.Contains(err.Error(), ...)` for error checking
- [ ] Using `%v` (not `%w`) at API boundaries to avoid leaking types

### Architecture
- [ ] No cross-feature store imports (use interfaces)
- [ ] No `os.Getenv` outside `main.go`
- [ ] Handlers accept individual values, not entire config struct
- [ ] Store layer does DB only, no business logic
- [ ] Flat package-by-feature structure, no DDD layers

### Testing
- [ ] Integration tests with testcontainers, not mocks for DB
- [ ] Testing behavior (WHAT), not implementation (HOW)
- [ ] UUIDs generated, not hardcoded
- [ ] Using `t.Setenv` not `os.Setenv`
- [ ] Independent tests call `t.Parallel()`
