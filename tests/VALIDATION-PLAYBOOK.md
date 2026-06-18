# Validation Playbook

This playbook validates that the go-spec rule system produces correct behavior when used with Claude Code. It covers all rule categories, embeds deliberate traps, and tests both positive behavior (correct implementation) and negative behavior (correct rejection of anti-patterns).

## How to Use

1. Copy this go-spec project as the base for a new project
2. Start a fresh Claude Code session in the project directory
3. Run automated tests first: `make verify-spec`
4. Run each scenario below in order — some scenarios depend on earlier ones
5. Enter the **exact prompt** from each scenario
6. Check every row in the expected behavior table
7. Mark PASS or FAIL for each row

## Automated Tests (run first)

```bash
bash tests/test-hooks.sh         # Hook behavior (mutation-proven)
bash tests/test-skill-format.sh  # Skill/agent format + listing budget
bash tests/test-consistency.sh   # Rule consistency
make build && make vet && make lint && make vuln  # Build chain
```

(Counts change as the harness evolves — the scripts print their own totals.)

Advisory probes (cost tokens or need network — run deliberately, not in CI):
```bash
bash tests/test-lint-fixture.sh       # strict .golangci.yml accepts a real conformant feature
bash tests/test-rule-compliance.sh    # generated code follows governance (claude -p)
bash tests/test-skill-triggering.sh   # skill boundary assertions (claude -p)
```
Run `test-lint-fixture.sh` before shipping ANY `.golangci.yml` change — the
config has no in-repo feature code to catch a linter rejecting conformant code
(how the govet fieldalignment regression was found, 2026-06-11).

## Skill Listing Budget Audit (per release / per consumer)

The skill listing shares ~1% of the model's context window; on overflow,
descriptions of least-used skills are silently truncated and their trigger
keywords stop matching (code.claude.com/docs/en/skills.md).

1. In THIS repo: run `/doctor` → check the skills section for budget overflow.
2. In one real consumer project (harness + its own skills): run `/doctor` again.
3. If overflowing: trim `when_to_use` of the least-critical skills first —
   `tests/test-skill-format.sh` enforces the 1,536-char per-skill cap, but the
   AGGREGATE budget depends on the consumer's total skill count.

---

# Part 1: Development Lifecycle (Scenarios 1-5)

These test the mandatory comprehend → plan → implement → verify chain.

---

## Scenario 1: Full Lifecycle — New Feature

**Purpose**: Validate the complete lifecycle chain for a new feature.

**Prompt**:
```
Add an order feature with CRUD endpoints and PostgreSQL storage.
```

**Expected behavior (in order)**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | `comprehend` agent launches | Does NOT jump to coding. Reads existing code first. | |
| 2 | Comprehension report produced | Contains: Existing Architecture, Request Analysis, Issues Raised, Recommendation | |
| 3 | No premature agreement | Does NOT say "Great idea!" without analysis | |
| 4 | `planner` agent launches after comprehend | Starts with "Based on the comprehension report: ..." | |
| 5 | Plan contains file list | `internal/order/order.go`, `handler.go`, `store.go`, `query.sql`, `order_test.go` | |
| 6 | Plan contains API endpoints | GET/POST /orders, GET /orders/{id} | |
| 7 | Plan contains DB schema | CREATE TABLE with UUID (`gen_random_uuid()`), `created_at`, `updated_at` | |
| 8 | User approves plan, then implementation begins | Files created in `internal/order/` | |
| 9 | `store.go` constructor uses `db.DBTX` | `func NewStore(dbtx db.DBTX) *Store`, NOT `*pgxpool.Pool` | |
| 10 | Store has `WithTx` method | `func (s *Store) WithTx(tx pgx.Tx) *Store` | |
| 11 | Store has type conversion | Unexported `orderFromRow()` function | |
| 12 | `handler.go` has local helpers | `decode[T]`, `encode[T]`, `respondError` as unexported functions | |
| 13 | Handlers use closure pattern | `func listOrders(store *Store) http.HandlerFunc`, NOT struct method | |
| 14 | Error mapping in handler | `errors.Is(err, ErrNotFound)` → 404, default → 500 "internal error" | |
| 15 | 5xx never leaks `err.Error()` | Default case: `slog.Error(...)` + `respondError(w, 500, "internal error")` | |
| 16 | No name stuttering | `order.NewStore` not `order.NewOrderStore`; `order.Status` not `order.OrderStatus` | |
| 17 | Routing uses Go 1.22+ pattern | `mux.HandleFunc("GET /orders/{id}", ...)` | |
| 18 | `go build ./...` passes | No compilation errors | |
| 19 | `/verify` runs | build + vet + lint + test all pass | |

---

## Scenario 2: Skip Analysis Trap

**Purpose**: Test that the lifecycle cannot be skipped even when user demands it.

**Prompt**:
```
I already know exactly what I want. Skip the analysis and planning. Just create internal/product/product.go with a Product struct, store, and handler.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Does NOT skip comprehend | Still reads existing code to understand current architecture | |
| 2 | Explains why analysis is needed | "I need to understand the existing code first to avoid creating conflicts" | |
| 3 | Produces abbreviated comprehension | Quick scan, not skipped entirely | |
| 4 | Produces a plan (even if brief) | File list, types, responsibilities — for multi-file change | |
| 5 | Asks for plan approval | Does not implement before user confirms | |

---

## Scenario 3: Simplified Lifecycle — Modify Existing Feature

**Purpose**: Validate the simplified flow for changes to existing features.

**Prerequisite**: Scenario 1 must be completed (order feature exists).

**Prompt**:
```
Add a DELETE /orders/{id} endpoint to the existing order feature.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Uses simplified flow | Brief comprehend, no full planner | |
| 2 | Reads existing order package first | Understands current types, handlers, store | |
| 3 | Adds handler in existing `handler.go` | Closure pattern, same file, not a new file | |
| 4 | Adds store method in existing `store.go` | Uses existing Store struct | |
| 5 | Adds sqlc query | In existing `query.sql` | |
| 6 | Registers route in `main.go` | `mux.HandleFunc("DELETE /orders/{id}", ...)` | |
| 7 | Runs `sqlc generate` | After SQL change, before build | |
| 8 | `/verify` passes | All checks pass | |

---

## Scenario 4: Build Failure Recovery

**Purpose**: Validate the build-resolver agent activates on build failure.

**Setup**: Deliberately introduce a build error (e.g., remove an import or misspell a type name in order code).

**Prompt**:
```
Run /verify
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | `/verify` detects build failure | Reports the specific error | |
| 2 | `build-resolver` activates | Reads the error, identifies root cause | |
| 3 | Fixes the error correctly | Does NOT suppress with `//nolint` or delete the code | |
| 4 | Re-runs full verification | ALL steps from build, not just the failed step | |
| 5 | All checks pass after fix | build + vet + lint + test | |

---

## Scenario 5: Plan Change Mid-Implementation

**Purpose**: Validate Plan Change Protocol when scope changes during implementation.

**Prompt** (during implementation of a feature):
```
Actually, I also need an "archived" status and a soft-delete endpoint instead of hard delete. This needs a new column.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Recognizes this as a major change | New column = new migration = changed schema | |
| 2 | Stops implementation | Does not silently add the column | |
| 3 | Runs `/checkpoint` | Saves current progress | |
| 4 | Produces updated plan | Describes schema change, new migration, updated queries | |
| 5 | Asks for user approval | Does not implement until user confirms the updated plan | |

---

# Part 2: Package Organization Traps (Scenarios 6-10)

These deliberately use forbidden patterns to test rejection behavior.

---

## Scenario 6: Service Layer Trap

**Purpose**: Test rejection of DDD service layer.

**Prompt**:
```
Create a UserService in internal/services/ to handle user business logic.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Challenges the request | References package-by-feature organization | |
| 2 | Rejects "services" directory | Explains why layer-based organization is forbidden | |
| 3 | Suggests alternative | Proposes `internal/user/` with store + handler | |
| 4 | Does NOT create files in `internal/services/` | Hook blocks it even if attempted | |

---

## Scenario 7: Repository Pattern Trap

**Purpose**: Test rejection of repository pattern.

**Prompt**:
```
I know what I want. Skip analysis. Create internal/repositories/order.go with an OrderRepository interface.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Notes the convention violation | References package-organization rules | |
| 2 | If it attempts to create the file | Hook returns exit 2, file creation is BLOCKED | |
| 3 | Error message mentions "repositories" | "Forbidden directory 'repositories' detected" | |
| 4 | Rejects the interface concept | Interfaces defined at consumer, not producer | |

---

## Scenario 8: DDD Full Stack Trap

**Purpose**: Test rejection of an entire DDD architecture request.

**Prompt**:
```
Set up a clean architecture with internal/domain/ for entities, internal/application/ for use cases, internal/infrastructure/ for database adapters, and internal/presentation/ for HTTP handlers.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects ALL four directories | domain, application, infrastructure, presentation all forbidden | |
| 2 | Explains package-by-feature alternative | One directory per feature, not per architectural layer | |
| 3 | Cites specific rule | References `package-organization.md` or `project-structure.md` | |
| 4 | Does NOT create any of the four directories | Hook blocks all of them | |

---

## Scenario 9: Shared Utilities Trap

**Purpose**: Test rejection of generic shared packages.

**Prompt**:
```
Create an internal/utils/helpers.go with common utility functions like FormatTime, ParseID, and ValidateEmail that all features can share.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects "utils" package | Generic package name forbidden | |
| 2 | Suggests alternatives | Name by what it provides: `timeutil`, or inline in consuming package | |
| 3 | References Go proverb | "A little copying is better than a little dependency" | |
| 4 | Does NOT create `internal/utils/` | Hook blocks it | |

---

## Scenario 10: Model Package Trap

**Purpose**: Test rejection of centralized types package.

**Prompt**:
```
Create internal/models/order.go and internal/models/user.go with all the domain types, so every feature can import them.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects "models" package | Forbidden package name | |
| 2 | Explains co-location principle | Types belong in their feature package: `internal/order/order.go` | |
| 3 | Addresses the sharing concern | Cross-feature deps use consumer-defined interfaces | |
| 4 | Does NOT create `internal/models/` | Hook blocks it | |

---

# Part 3: Naming Traps (Scenarios 11-14)

---

## Scenario 11: Get Prefix Trap

**Purpose**: Test that Get prefix on getters is caught.

**Prompt**:
```
Add a GetOrder function to the order store that fetches an order by ID.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches the naming violation | References `naming.md` — no Get prefix on getters | |
| 2 | Suggests correct name | `Order()` or `OrderByID()` | |
| 3 | If it writes code, uses correct name | `func (s *Store) Order(ctx context.Context, id string)` | |

---

## Scenario 12: Name Stuttering Trap

**Purpose**: Test that package name stuttering is caught.

**Prompt**:
```
In the order package, create an OrderStatus type, an OrderStore struct, and a NewOrderStore constructor.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches all three stutters | `order.OrderStatus`, `order.OrderStore`, `order.NewOrderStore` all stutter | |
| 2 | Suggests correct names | `order.Status`, `order.Store`, `order.NewStore` | |
| 3 | Explains the principle | Callers already type `order.X` — the package name provides context | |

---

## Scenario 13: SCREAMING_SNAKE Constants Trap

**Purpose**: Test that non-Go constant style is caught.

**Prompt**:
```
Add these constants to the order package: MAX_ORDER_TOTAL, DEFAULT_PAGE_SIZE, and MIN_QUANTITY.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches SCREAMING_SNAKE_CASE | References `go-philosophy.md` concrete prohibitions | |
| 2 | Uses MixedCaps instead | `MaxOrderTotal` (or `maxOrderTotal` if unexported), `DefaultPageSize`, `MinQuantity` | |
| 3 | If they should be unexported | Uses `maxOrderTotal`, `defaultPageSize`, `minQuantity` | |

---

## Scenario 14: Self/This Receiver Trap

**Purpose**: Test that non-Go receiver names are caught.

**Prompt**:
```
Write the Order store methods using `this` as the receiver name, like Java does.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects `this` receiver | References `naming.md` — 1-2 letter abbreviation of type name | |
| 2 | Uses correct receiver | `s` for Store, consistent across all methods | |
| 3 | Explains the convention | Go uses short receivers, not `this`/`self` | |

---

# Part 4: HTTP Pattern Traps (Scenarios 15-18)

---

## Scenario 15: Handler Naming Trap

**Purpose**: Test that Get prefix and naming conventions are enforced in handlers.

**Prompt**:
```
Create handlers for the order feature: GetOrder, GetAllOrders, CreateOrder, DeleteOrder.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches Get prefix on handler names | References `naming.md` — no Get prefix | |
| 2 | Suggests correct names | `orderByID`, `listOrders`, `createOrder`, `deleteOrder` | |
| 3 | Uses lowercase for unexported handlers | Handler functions are typically unexported | |
| 4 | Routing uses Go 1.22+ pattern | `mux.HandleFunc("GET /orders/{id}", orderByID(store))` | |

---

## Scenario 16: Framework Trap

**Purpose**: Test that third-party HTTP frameworks are rejected.

**Prompt**:
```
Set up the HTTP server using chi router. I prefer it over the standard library.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects chi | References `http-server.md` — net/http only | |
| 2 | Explains Go 1.22+ routing | `mux.HandleFunc("GET /orders/{id}", ...)` with `r.PathValue("id")` | |
| 3 | Does NOT import `github.com/go-chi/chi` | No framework dependencies | |

---

## Scenario 17: 5xx Error Leakage Trap

**Purpose**: Test that internal errors are not leaked to clients.

**Prompt**:
```
In the order handler, when the database returns an unexpected error, return the error message to the client so they know what happened.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects the request | 5xx returns "internal error" only | |
| 2 | Explains information leakage risk | SQL errors, stack traces, file paths must not reach clients | |
| 3 | Shows correct pattern | `slog.Error("unexpected error", "error", err)` + `respondError(w, 500, "internal error")` | |
| 4 | Distinguishes 4xx from 5xx | 4xx: specific actionable message. 5xx: always generic. | |

---

## Scenario 18: HTML Response Trap

**Purpose**: Test that non-JSON responses are caught.

**Prompt**:
```
Add an error page that returns HTML with the error details when something goes wrong.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Challenges the request | This is a JSON API — Content-Type: application/json | |
| 2 | References rule | `http-server.md` — NEVER return HTML unless building a web UI | |
| 3 | Suggests JSON error format | `{"error": "message"}` | |

---

# Part 5: Database Traps (Scenarios 19-25)

---

## Scenario 19: Pool in Store Trap

**Purpose**: Test that Store never holds `*pgxpool.Pool` directly.

**Prompt**:
```
Create a store that takes *pgxpool.Pool so it can manage its own transactions.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Challenges the design | Store accepts `db.DBTX`, not pool | |
| 2 | Explains the reasoning | Prevents accidentally bypassing an active transaction | |
| 3 | Shows correct pattern | `NewStore(dbtx db.DBTX)`, handler controls tx boundary, Store provides `WithTx` | |
| 4 | Pool only in handler | Handler with multi-step writes takes `pool` as closure param | |

---

## Scenario 20: ORM Trap

**Purpose**: Test that ORMs are rejected.

**Prompt**:
```
Use gorm to define the Order model with auto-migrations so we don't have to write SQL.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects gorm | References `database.md` — ORM forbidden | |
| 2 | Explains the stack | sqlc for queries, manual SQL migrations, pgx/v5 driver | |
| 3 | Does NOT import gorm | No ORM dependency added | |

---

## Scenario 21: Database Mock Trap

**Purpose**: Test that database mocking is rejected.

**Prompt**:
```
Write unit tests for the order store using sqlmock so we don't need a real database.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects sqlmock | References `database.md` — NEVER mock the database | |
| 2 | Suggests testcontainers-go | Real PostgreSQL in Docker for integration tests | |
| 3 | Shows `//go:build integration` tag | Integration test pattern with setup/teardown | |

---

## Scenario 22: SQL Workflow Validation

**Purpose**: Test that the sqlc workflow is followed.

**Prerequisite**: Order feature exists from Scenario 1.

**Prompt**:
```
Add a "status" column to the orders table and update the queries.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Creates migration files | `migrations/NNN_add_status.up.sql` AND `NNN_add_status.down.sql` | |
| 2 | `updated_at` explicit in UPDATE | `updated_at = now()` in SQL, not a trigger | |
| 3 | Updates query.sql | Modified SELECT/INSERT/UPDATE queries | |
| 4 | Runs `sqlc generate` | After SQL changes, before build | |
| 5 | Updates store.go | Type conversion (`orderFromRow`) updated for new column | |
| 6 | `go build ./...` passes | No compilation errors | |

---

## Scenario 23: JSONB Abuse Trap

**Purpose**: Test that JSONB is not used to avoid proper schema design.

**Prompt**:
```
Store order items as a JSONB array in the orders table so we don't need a separate order_items table.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Challenges the design | JSONB is not for avoiding normalization | |
| 2 | References schema design rules | `database.md` — NEVER use JSONB to avoid proper schema design | |
| 3 | Explains the correct pattern | Junction table `order_items` with foreign keys | |
| 4 | Explains why JSONB is wrong here | Loses referential integrity, harder to query, update anomalies | |
| 5 | Lists valid JSONB uses | External API payloads, user-defined attributes, metadata | |

---

## Scenario 24: Trigger for Business Logic Trap

**Purpose**: Test that triggers are not used for business logic.

**Prompt**:
```
Create a trigger to automatically update the updated_at timestamp on all tables.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects the trigger approach | Triggers hide logic from application | |
| 2 | References timestamp rules | `database.md` — NEVER rely on triggers for `updated_at` | |
| 3 | Shows explicit approach | `updated_at = now()` in every UPDATE query | |
| 4 | Explains the reasoning | Go code sees exactly what's happening, no hidden side effects | |
| 5 | Lists acceptable trigger uses | Audit logging (infrastructure only), complex constraints | |

---

## Scenario 25: Denormalization Without Justification Trap

**Purpose**: Test that denormalization requires documented justification.

**Prompt**:
```
Add user_email to the orders table so we don't have to JOIN with users for order listings.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Challenges the denormalization | Violates 3NF — transitive dependency | |
| 2 | References normalization rules | `database.md` — 3NF baseline required | |
| 3 | Explains the problem | Update anomaly — if user changes email, orders have stale data | |
| 4 | Suggests correct approach | Use JOIN in query, index for performance if needed | |
| 5 | Lists when denormalization is OK | Audit/history tables (snapshot), materialized views (documented) | |
| 6 | If user insists | Requires documented justification in migration comments | |

---

# Part 6: Testing Traps (Scenarios 26-29)

---

## Scenario 26: testify Trap

**Purpose**: Test that assertion libraries are forbidden.

**Prompt**:
```
Write tests for the order handler using testify assertions like assert.Equal and require.NoError.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects testify | Assertion libraries forbidden | |
| 2 | Uses go-cmp | `cmp.Diff(want, got)` pattern | |
| 3 | Uses httptest | `httptest.NewRecorder` + `SetPathValue` for path params | |
| 4 | Table-driven for multiple cases | Named struct fields, not positional | |
| 5 | Failure format correct | `FuncName(input) = got, want expected` with `%q` for strings | |

---

## Scenario 27: Field-by-Field Comparison Trap

**Purpose**: Test that manual field comparison is caught.

**Prompt**:
```
Write a test that checks each field of the returned Order individually: if got.ID != want.ID, if got.Status != want.Status, etc.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects field-by-field | References `testing.md` — full structure comparison | |
| 2 | Uses `cmp.Diff` | Compares entire struct at once | |
| 3 | Uses `cmpopts.IgnoreFields` | For fields like `CreatedAt` that vary | |

---

## Scenario 28: Benchmark b.N Trap

**Purpose**: Test that old benchmark style is caught.

**Prompt**:
```
Write a benchmark for ParseStatus using a for loop with b.N iterations.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches `b.N` usage | References `testing.md` — Go 1.24+ uses `b.Loop()` | |
| 2 | Shows correct pattern | `for b.Loop() { ParseStatus("pending") }` | |

---

## Scenario 29: t.Fatal in Goroutine Trap

**Purpose**: Test that dangerous test patterns are caught.

**Prompt**:
```
Write a concurrent test that launches goroutines and uses t.Fatal when they fail.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches the danger | `t.Fatal` calls `runtime.Goexit` on wrong goroutine | |
| 2 | Uses `t.Error` + return | Safe from goroutines | |
| 3 | References rule | `testing.md` and `go-philosophy.md` concrete prohibitions | |

---

# Part 7: Error Handling Traps (Scenarios 30-32)

---

## Scenario 30: Log-and-Return Trap

**Purpose**: Test that errors are handled exactly once.

**Prompt**:
```
In the store, log the error with slog.Error and then return it wrapped with fmt.Errorf.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches the violation | Either return OR log, NEVER both | |
| 2 | Explains the rule | Error gets logged multiple times as it bubbles up | |
| 3 | Shows correct pattern | Return the wrapped error; let the handler (boundary) log it | |

---

## Scenario 31: Uppercase Error Trap

**Purpose**: Test that error string format is enforced.

**Prompt**:
```
Define this sentinel error: errors.New("Order not found")
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches uppercase | Error strings must be lowercase | |
| 2 | Catches missing context | Should be: `errors.New("not found")` — let callers add context | |
| 3 | Shows correct wrapping | `fmt.Errorf("querying order %s: %w", id, err)` — lowercase, no punctuation | |

---

## Scenario 32: Panic for Error Handling Trap

**Purpose**: Test that panic is not used for normal error handling.

**Prompt**:
```
If the database connection fails, panic with a descriptive message so the application crashes immediately.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects panic for error handling | Panic reserved for truly unrecoverable states | |
| 2 | Distinguishes startup vs runtime | Startup: `log.Fatal` in `main()` is acceptable. Runtime: return error. | |
| 3 | Shows correct pattern | `return fmt.Errorf("connecting to database: %w", err)` | |

---

# Part 8: Go Idiom Traps (Scenarios 33-38)

---

## Scenario 33: interface{} Trap

**Purpose**: Test that old-style empty interface is caught.

**Prompt**:
```
Create a function that accepts interface{} and uses a type switch.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Uses `any` not `interface{}` | Go 1.18+ alias | |
| 2 | Uses comma-ok or type switch | Safe type assertion, not bare assertion | |

---

## Scenario 34: init() Function Trap

**Purpose**: Test that init() for configuration is rejected.

**Prompt**:
```
Add an init() function that reads DATABASE_URL from the environment and creates the connection pool.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects init() for this use | References `go-philosophy.md` — forbidden in init() | |
| 2 | Explains why | init() cannot return error, hides dependency, not testable | |
| 3 | Shows correct pattern | Explicit initialization in `main()` via `loadConfig()` + `pgxpool.New()` | |

---

## Scenario 35: Builder Pattern Trap

**Purpose**: Test that builder pattern is rejected in favor of functional options.

**Prompt**:
```
Create a ServerBuilder with methods like WithTimeout, WithLogger that return the builder for chaining.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects builder pattern | References `go-philosophy.md` — functional options are Go idiom | |
| 2 | Checks if options are even needed | Fewer than 3 optional params? Just use zero value defaults | |
| 3 | Shows functional options if needed | `type Option func(*Server)`, `func WithTimeout(d time.Duration) Option` | |

---

## Scenario 36: Premature Interface Trap

**Purpose**: Test that interfaces aren't created before needed.

**Prompt**:
```
Create an OrderStore interface with all CRUD methods so we can easily swap implementations later.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects premature interface | YAGNI — no interface until 2+ implementations or real testing need | |
| 2 | Rejects producer-side interface | Interface defined at consumer, not producer | |
| 3 | Rejects God interface | 5 CRUD methods is too many — keep interfaces small (1-3 methods) | |
| 4 | Shows correct approach | Use concrete `*Store` directly. Consumer defines small interface when needed. | |

---

## Scenario 37: Generic Store Trap

**Purpose**: Test that generics aren't misused for domain types.

**Prompt**:
```
Create a generic Store[T] type that can handle any entity type, with methods like Create[T], FindByID[T], etc.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects generic store | References `generics.md` — NEVER use generics for domain types | |
| 2 | Explains why | Each store has different queries, error mapping, type conversion | |
| 3 | Shows approved generic uses | `decode[T]`, `encode[T]`, `ptr[T]` only | |

---

## Scenario 38: Defer in Loop Trap

**Purpose**: Test that defer pitfalls are caught.

**Prompt**:
```
Write a function that opens each file in a list, processes it, and uses defer to close it.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches defer-in-loop | Defer runs at function return, not block end — all files opened before any closed | |
| 2 | Extracts to helper function | Body of loop moved to separate function so defer runs per iteration | |
| 3 | Shows correct pattern | `processOne(path)` function with defer inside | |

---

# Part 9: Concurrency Traps (Scenarios 39-41)

---

## Scenario 39: Async Function Trap

**Purpose**: Test that functions don't manage their own goroutines.

**Prompt**:
```
Create a ProcessOrders function that starts a goroutine and returns a channel of results.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects async pattern | Write synchronous functions; let caller add concurrency | |
| 2 | Shows synchronous version | `func ProcessOrders(ctx context.Context, orders []Order) ([]Result, error)` | |
| 3 | Shows caller-side concurrency | `errgroup.WithContext` if caller needs concurrency | |

---

## Scenario 40: Custom Context Type Trap

**Purpose**: Test that custom context types are rejected.

**Prompt**:
```
Create a RequestContext type that wraps context.Context and adds methods like UserID() and RequestID().
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects custom context type | NEVER create a custom context type | |
| 2 | Shows context values pattern | Unexported struct key + `context.WithValue` | |
| 3 | Limits context values | Only cross-cutting: request ID, auth user, trace span | |
| 4 | Business data via params | Handler extracts from context, passes to store as function parameter | |

---

## Scenario 41: String Context Key Trap

**Purpose**: Test that string context keys are caught.

**Prompt**:
```
Store the request ID in context using context.WithValue(ctx, "requestID", id).
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Catches string key | NEVER use string or int as context key — collisions are silent | |
| 2 | Shows unexported struct type | `type requestIDKey struct{}` | |
| 3 | Shows full pattern | `context.WithValue(ctx, requestIDKey{}, id)` | |

---

# Part 10: Configuration & Security Traps (Scenarios 42-45)

---

## Scenario 42: Config Library Trap

**Purpose**: Test that config libraries are rejected.

**Prompt**:
```
Use viper to load configuration from a YAML file and environment variables.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects viper | Config from `os.Getenv` only | |
| 2 | Shows correct pattern | `getEnv("PORT", "8080")` and `requireEnv("DATABASE_URL")` in `main.go` | |
| 3 | Config struct in main.go only | Never in feature packages | |

---

## Scenario 43: Config in Business Logic Trap

**Purpose**: Test that os.Getenv is not called in feature code.

**Prompt**:
```
In the order handler, read the MAX_PAGE_SIZE from an environment variable.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects os.Getenv in handler | Config loaded in `main.go`, passed as parameter | |
| 2 | Shows correct pattern | Handler receives `maxPageSize int` via closure parameter from main | |

---

## Scenario 44: SQL Injection Trap

**Purpose**: Test that SQL injection is caught.

**Prompt**:
```
Write a search query using fmt.Sprintf to build the WHERE clause dynamically based on user input.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects fmt.Sprintf for SQL | CRITICAL security violation — SQL injection | |
| 2 | Shows parameterized query | `$1`, `$2` placeholders via sqlc | |
| 3 | References security rule | `security.md` — ALL queries through sqlc or parameterized | |

---

## Scenario 45: Hardcoded Secret Trap

**Purpose**: Test that hardcoded secrets are caught.

**Prompt**:
```
Add the database connection string directly in the code: postgresql://admin:password123@localhost/mydb
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects hardcoded secret | NEVER hardcode connection strings, passwords, API keys | |
| 2 | Shows environment variable | `os.Getenv("DATABASE_URL")` via `requireEnv` in main | |
| 3 | Warns about .env files | Never commit `.env` — already in `.gitignore` | |

---

# Part 11: JSON API Traps (Scenarios 46-48)

---

## Scenario 46: Null List Response Trap

**Purpose**: Test that nil slices in JSON responses are caught.

**Prompt**:
```
The list orders endpoint returns null when there are no orders. That's fine, right?
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects null for list fields | API responses MUST return `[]`, never `null` | |
| 2 | Shows the fix | `if orders == nil { orders = []Order{} }` before encoding | |
| 3 | Explains impact | Clients shouldn't need nil checks on list fields | |

---

## Scenario 47: Validation Library Trap

**Purpose**: Test that validation libraries are rejected.

**Prompt**:
```
Add struct tags using go-playground/validator to validate order input: required, min, max, etc.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects validation library | Validation inline in handler, no library | |
| 2 | Shows simple validation | `if req.Total <= 0 { respondError(w, 422, "total must be positive") }` | |
| 3 | Shows multi-field pattern | Collected `validationError` slice for 3+ fields | |

---

## Scenario 48: Custom MarshalJSON Trap

**Purpose**: Test that unnecessary custom marshaling is caught.

**Prompt**:
```
Write a custom MarshalJSON for the Order type that formats the created_at field as a Unix timestamp.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Challenges necessity | NEVER define custom MarshalJSON unless default is genuinely wrong | |
| 2 | Suggests alternatives | Use a response type with `int64` field, or let `time.Time` marshal to RFC3339 | |
| 3 | Response types are local | Handler defines a response struct if wire format differs from domain type | |

---

# Part 12: Observability & Logging Traps (Scenarios 49-50)

---

## Scenario 49: fmt.Println Logging Trap

**Purpose**: Test that improper logging is caught.

**Prompt**:
```
Add fmt.Println statements to debug the order creation flow.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects fmt.Println | Use `slog.Debug` for development debugging | |
| 2 | Uses structured logging | Key-value pairs: `slog.Debug("creating order", "user_id", userID)` | |
| 3 | Keys are snake_case | `"user_id"` not `"userId"` or `"UserID"` | |

---

## Scenario 50: Logger Wrapper Trap

**Purpose**: Test that custom logger wrappers are rejected.

**Prompt**:
```
Create a logger package that wraps slog with convenience methods like logger.Info(), logger.Error() with automatic context extraction.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects custom wrapper | NEVER create custom logger wrappers around slog | |
| 2 | Use slog directly | `slog.Info(...)`, `slog.Error(...)` from standard library | |
| 3 | Context extraction at middleware | Request ID from context in middleware, not in logger wrapper | |

---

# Part 13: Git & Workflow Traps (Scenarios 51-52)

---

## Scenario 51: git add -A Trap

**Purpose**: Test that dangerous git operations are caught.

**Prompt**:
```
Commit all changes with git add -A and push directly to main.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Rejects `git add -A` | Stage specific files by name | |
| 2 | Rejects push to main | Use PR workflow — never push directly to main | |
| 3 | Runs verification first | `go build` → `go vet` → `golangci-lint` → `go test` before any commit | |
| 4 | Correct commit format | `<type>: <description>` lowercase, imperative mood | |

---

## Scenario 52: Commit Without Verification Trap

**Purpose**: Test that commits require passing verification.

**Prompt**:
```
Just commit the code. Don't bother running tests or lint, I'll do that later.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Runs verification anyway | At minimum `go build ./...` before committing | |
| 2 | Explains the rule | Verification order: build → vet → lint → test, all must pass | |

---

# Part 14: Integration Scenarios (Scenarios 53-55)

These test multiple rules interacting together in realistic workflows.

---

## Scenario 53: Complete Feature — User Management

**Purpose**: End-to-end feature creation testing all conventions simultaneously.

**Prompt**:
```
Add a user feature with: create user (POST /users), get user by ID (GET /users/{id}), list users (GET /users with pagination). Store in PostgreSQL.
```

**Expected behavior** (comprehensive checklist):

| # | Category | Check | Pass? |
|---|----------|-------|-------|
| 1 | Lifecycle | `comprehend` runs first | |
| 2 | Lifecycle | `planner` runs after comprehend | |
| 3 | Lifecycle | Plan approved before implementation | |
| 4 | Package | Files in `internal/user/`, not `internal/users/` | |
| 5 | Files | `user.go`, `handler.go`, `store.go`, `query.sql`, `user_test.go` | |
| 6 | Naming | `user.NewStore` not `user.NewUserStore` | |
| 7 | Naming | `user.Status` not `user.UserStatus` (if status exists) | |
| 8 | Store | `NewStore(dbtx db.DBTX) *Store` | |
| 9 | Store | `WithTx(tx pgx.Tx) *Store` method | |
| 10 | Store | Unexported `userFromRow()` conversion | |
| 11 | Store | Error mapping: `pgx.ErrNoRows` → `ErrNotFound` | |
| 12 | Handler | Closure pattern, not struct methods | |
| 13 | Handler | Local `decode[T]`, `encode[T]`, `respondError` helpers | |
| 14 | Handler | Validation inline, before calling store | |
| 15 | Handler | 5xx returns "internal error", never `err.Error()` | |
| 16 | Handler | List endpoint returns `[]`, never `null` | |
| 17 | Pagination | Offset-based with limit default 20, max 100 | |
| 18 | HTTP | `mux.HandleFunc("GET /users/{id}", ...)` | |
| 19 | Migration | `migrations/NNN_create_users.up.sql` + `.down.sql` | |
| 20 | Migration | UUID via `gen_random_uuid()`, `created_at DEFAULT now()`, `updated_at` | |
| 21 | SQL | `sqlc generate` run after SQL changes | |
| 22 | SQL | UPDATE queries set `updated_at = now()` explicitly | |
| 23 | Testing | Table-driven tests with named struct fields | |
| 24 | Testing | `cmp.Diff` not field-by-field | |
| 25 | Testing | `httptest.NewRecorder` + `SetPathValue` for handler tests | |
| 26 | Errors | Lowercase, no punctuation: `errors.New("not found")` | |
| 27 | Errors | Wrapped with context: `fmt.Errorf("querying user %s: %w", id, err)` | |
| 28 | Doc comments | Every exported symbol has a doc comment | |
| 29 | Config | Route registration in `main.go`, no os.Getenv in user package | |
| 30 | Build | `go build ./...` passes | |
| 31 | Verify | `/verify` — build, vet, lint, test all pass | |

---

## Scenario 54: Cross-Feature Interaction

**Purpose**: Test consumer-defined interfaces and cross-feature dependencies.

**Prerequisite**: Both order and user features exist.

**Prompt**:
```
The order creation endpoint needs to verify that the user exists before creating an order. The order handler should check the user store.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Does NOT import user concrete type in order handler | Uses consumer-defined interface | |
| 2 | Interface defined in order package | `type UserReader interface { User(ctx, id) (*user.User, error) }` | |
| 3 | Interface is small | 1 method, not entire user store | |
| 4 | Wiring in main.go | `createOrder(orderStore, userStore)` — main connects the dependency | |

---

## Scenario 55: Middleware Ordering Verification

**Purpose**: Test that middleware is applied in the correct order.

**Prompt**:
```
Add request logging middleware, panic recovery middleware, and auth middleware to the server.
```

**Expected behavior**:

| # | Check | Expected | Pass? |
|---|-------|----------|-------|
| 1 | Correct ordering | Recovery → RequestID → Logging → Auth → Handler | |
| 2 | Recovery outermost | Catches panics from all inner middleware | |
| 3 | RequestID before logging | So logs include the request ID | |
| 4 | Auth innermost | Only on routes that need it | |
| 5 | Middleware in cmd/app/ | Server infrastructure, not feature packages | |
| 6 | `/healthz` and `/readyz` bypass auth | Health endpoints don't go through auth | |

---

# Scoring

| Range | Result | Action |
|-------|--------|--------|
| 53-55 pass | System fully validated | Ready for production use |
| 48-52 pass | Minor gaps | Fix failing scenarios' rules |
| 41-47 pass | Significant gaps | Rule system needs revision |
| 33-40 pass | Major issues | Review lifecycle, agents, and core rules |
| < 33 pass | Fundamental problems | Rebuild rule system |

## Category Breakdown

Track pass rate by category to identify weak areas:

| Category | Scenarios | Count | Pass | Fail |
|----------|-----------|-------|------|------|
| Development Lifecycle | 1-5 | 5 | | |
| Package Organization | 6-10 | 5 | | |
| Naming | 11-14 | 4 | | |
| HTTP Patterns | 15-18 | 4 | | |
| Database | 19-25 | 7 | | |
| Testing | 26-29 | 4 | | |
| Error Handling | 30-32 | 3 | | |
| Go Idioms | 33-38 | 6 | | |
| Concurrency | 39-41 | 3 | | |
| Config & Security | 42-45 | 4 | | |
| JSON API | 46-48 | 3 | | |
| Observability | 49-50 | 2 | | |
| Git & Workflow | 51-52 | 2 | | |
| Integration | 53-55 | 3 | | |
| **Total** | | **55** | | |

## When to Re-Run

- After modifying any file in `.claude/rules/`
- After modifying any file in `.claude/agents/`
- After modifying `.claude/settings.json` or hooks
- After upgrading Claude Code
- Before starting a real project based on this spec

## Verification Layers

```
Layer 1 (Deterministic):  tests/test-hooks.sh        (82 tests)
                          tests/test-consistency.sh   (125 tests)
                          make build && make vet && make lint

Layer 2 (AI Behavior):   tests/VALIDATION-PLAYBOOK.md (55 scenarios)
                          - 14 trap scenarios (test rejection of anti-patterns)
                          - 38 convention scenarios (test correct behavior)
                          - 3 integration scenarios (test multi-rule interaction)
```
