# Codebase Semantic & Style Audit — Third-Party Review

**Date:** 2026-03-30
**Scope:** 31 packages, 140 production files, ~38,600 lines of Go
**Auditor:** Independent Go reviewer (hostile stance, assume everything is wrong until proven otherwise)

---

## PART 1: Package Identity (One-Sentence Test)

| Package | Identity | Verdict |
|---------|----------|---------|
| `activity` | Records and queries development activity events from all sources. | PASS |
| `ai` | Defines AI processing flows for the content pipeline using Genkit. | PASS |
| `ai/exec` | In-process worker pool for executing AI flows with persistent tracking. | PASS |
| `ai/report` | Generates periodic summary reports (daily, weekly, morning, digest). | PASS |
| `api` | Shared HTTP response helpers (encoding, errors, pagination) for all handlers. | PASS |
| `auth` | Google OAuth 2.0 login, JWT access tokens, and refresh token rotation. | PASS |
| `budget` | Tracks daily LLM token usage with an in-memory atomic counter. | PASS |
| `content` | Manages content lifecycle (articles, TILs, etc.) with full-text search and knowledge graph. | PASS |
| `db` | sqlc-generated database abstraction (NEVER hand-edit). | PASS |
| `event` | Synchronous, in-process event bus for pipeline notifications. | PASS |
| `feed` | Manages RSS/Atom feed subscriptions with auto-disable on repeated failures. | PASS |
| `feed/collector` | Fetches RSS feeds, deduplicates items, scores relevance, persists to collected_data. | PASS |
| `feed/entry` | Manages collected RSS items with status tracking and user feedback. | PASS |
| `github` | GitHub REST API client for file content, directory listing, and commit comparison. | PASS |
| `goal` | Tracks goals synced from Notion with lifecycle status management. | PASS |
| `learning` | Computes learning analytics: coverage matrices, tag summaries, weakness trends. | PASS |
| `mcp` | MCP server exposing 40+ tools for querying and managing the knowledge engine. | **PARTIAL** |
| `mcpauth` | OAuth 2.1 with Google login and PKCE for MCP server authentication. | PASS |
| `monitor` | Manages data collection topics and schedules for monitoring features. | PASS |
| `note` | Manages Obsidian knowledge notes with full-text and semantic search. | PASS |
| `notify` | Multi-channel text notification delivery (LINE, Telegram, Noop). | PASS |
| `notion` | Notion API integration: sync, webhooks, property mapping, source management. | **PARTIAL** |
| `obsidian` | Parses Obsidian-format markdown (frontmatter, wikilinks, camelCase tokenization). | PASS |
| `oreilly` | O'Reilly Learning Platform API client for search and chapter reading. | PASS |
| `pipeline` | Orchestrates GitHub webhooks and content sync workflows. | PASS |
| `project` | Manages portfolio projects synced from Notion with public/featured filtering. | PASS |
| `reconcile` | Compares Obsidian/Notion records against local DB to detect drift. | PASS |
| `review` | Manages human review queue for AI-generated content. | PASS |
| `server` | HTTP server configuration, middleware, and route registration. | PASS |
| `session` | Cross-environment session notes for context sharing (plan, reflection, insight). | PASS |
| `stats` | System observability and learning analytics queries (11-table aggregation). | PASS |
| `tag` | Manages canonical tag normalization via 4-step pipeline with alias resolution. | PASS |
| `task` | Syncs tasks from Notion, provides local task tracking with recurrence and My Day. | PASS |
| `testdb` | PostgreSQL test containers for integration tests (testcontainers-go). | PASS |
| `topic` | Manages content topics/categories with Ristretto cache. | PASS |
| `upload` | File uploads to Cloudflare R2 with MIME type validation. | PASS |
| `webhook` | HMAC-SHA256 signature verification and deduplication cache for webhooks. | PASS |

**Score: 33/35 PASS, 2 PARTIAL**

---

## PART 2: Detailed Findings

### CRITICAL (4 findings)

```
[CRITICAL] [RESPONSIBILITY] internal/mcp/ (all files)
Rule: Single Responsibility / No God Package
Source: Ardan Labs Package-Oriented Design, Google Style Guide
Finding: MCP Server has 110 exported methods, 16 store references (4 duplicated),
15 files, 40+ tool registrations in a single 500-line constructor. Covers 14 distinct
domains: knowledge search, task management, content CRUD, feed management, dev session
logging, goal tracking, learning analytics, project context, activity tracking, session
notes, insight tracking, morning planning, weekly summaries, and O'Reilly search.
Fix: Split into domain-specific files (already partially done) or sub-packages:
  mcp/tools_knowledge.go, mcp/tools_tasks.go, mcp/tools_content.go, etc.
  Remove duplicate store fields (notes/semanticNotes, activity/activityWriter,
  projects/projectWriter, stats/systemStatus are the SAME concrete type).
```

```
[CRITICAL] [ERROR] internal/auth, internal/monitor, internal/session, internal/task
Rule: MUST define ErrConflict and handle unique violations in stores with Create methods
Source: Project Rules (error-handling.md)
Finding: 4 packages with Create store methods but no ErrConflict sentinel:
  - auth: CreateUser can conflict on email
  - monitor: CreateTracking can conflict on unique constraints
  - session: SaveNote can conflict on unique constraints
  - task: CreateTask (delegates to Notion, but HTTP Create also exists)
  Users get 500 instead of 409 on duplicate creation.
Fix: Add ErrConflict to each package's type file. Map PostgreSQL 23505 to ErrConflict.
```

```
[CRITICAL] [RESPONSIBILITY] internal/notion/ (9 files, 60+ exported identifiers)
Rule: Single Responsibility
Source: Ardan Labs, Google Style Guide
Finding: Package covers 4+ distinct responsibilities:
  1. Notion API client (client.go) — HTTP, retries, rate limiting
  2. Webhook handler (handler.go) — signature verification, dispatch
  3. Sync orchestration (sync.go, sync_handler.go) — bulk queries, per-entity upsert
  4. Source registry CRUD (store.go, source_handler.go) — admin API
  5. Property extraction (property.go) — Notion response parsing
Fix: Consider sub-packages: notion/sync, notion/sources. Or at minimum,
reduce exported surface by making internal helpers unexported.
```

```
[CRITICAL] [DATABASE] internal/content/store.go:534-540, 623-629
Rule: Transaction boundary MUST be controlled by handler, not store
Source: Project Rules (database.md)
Finding: CreateContent and UpdateContent internally start transactions by type-asserting
their DBTX to a pool interface with Begin(). This puts transaction boundary inside the
store. If DBTX doesn't implement Begin, the error message is uppercase:
"CreateContent requires a connection with Begin support" (also violates error string rules).
Fix: Accept pgx.Tx as parameter or use WithTx pattern. Fix error string casing.
```

### HIGH (7 findings)

```
[HIGH] [ERROR] internal/content/store.go:537, 626
Rule: Error strings are lowercase, no punctuation
Source: Effective Go
Finding: "CreateContent requires a connection with Begin support" — uppercase C.
         "UpdateContent requires a connection with Begin support" — uppercase U.
Fix: "create content requires a connection with begin support"
```

```
[HIGH] [ERROR] internal/mcp/oreilly_tools.go:42, 127, 191
Rule: Error strings are lowercase
Source: Effective Go
Finding: "O'Reilly search is not configured (ORM_JWT not set)" — 3 occurrences.
Fix: "oreilly search is not configured (ORM_JWT not set)"
```

```
[HIGH] [ERROR] internal/notion/store.go:146
Rule: Error strings are lowercase
Source: Effective Go
Finding: "SetRole requires a pool with Begin support" — uppercase S.
Fix: "set role requires a pool with begin support"
```

```
[HIGH] [ERROR] internal/oreilly/oreilly.go:183
Rule: Error strings are lowercase
Source: Effective Go
Finding: "TOC API returned status %d" — uppercase T.
Fix: "toc api returned status %d"
```

```
[HIGH] [TYPE] internal/mcp/server.go:34-57
Rule: Don't duplicate struct fields for the same concrete type
Source: Google Style Guide, DRY
Finding: Server struct has 4 pairs of duplicate store references:
  - notes + semanticNotes (both *note.Store)
  - activity + activityWriter (both *activity.Store)
  - projects + projectWriter (both *project.Store)
  - stats + systemStatus (both *stats.Store)
  Comments say "same store, separate field for write operations" but there's
  no read-only store type — it's the exact same *Store used twice.
Fix: Remove duplicates. Use single field per store type.
```

```
[HIGH] [INTERFACE] internal/task/notion.go:41
Rule: Compile-time interface verification
Source: Project Rules (interfaces.md)
Finding: ProjectResolver interface defined but no compile-time check.
  topic.go:21 has `var _ ContentByTopicLister = (*content.Store)(nil)` — correct.
  task/notion.go has no equivalent for ProjectResolver.
Fix: Add `var _ ProjectResolver = (*project.Store)(nil)` after interface definition.
```

```
[HIGH] [FUNCTION] internal/pipeline/handler.go:56
Rule: Function arg count ≤ 5
Source: Google Style Best Practices
Finding: NewContentSync(pool *pgxpool.Pool, cr, cw *content.Store, tl TopicLookupFunc,
  fetcher *github.Client, jobs *exec.Runner, logger *slog.Logger) — 7 params.
  Also takes *pgxpool.Pool directly instead of db.DBTX.
Fix: Use ContentSyncDeps struct. cr and cw are both *content.Store — investigate if
they can be unified.
```

### MEDIUM (8 findings)

```
[MEDIUM] [NAMING] internal/mcp/ (various input/output types)
Rule: Naming — avoid misleading Get prefix
Source: Effective Go
Finding: Input/output types named GetSessionNotesInput, GetActiveInsightsInput,
GetSessionNotesOutput, GetActiveInsightsOutput. While these are MCP tool parameter
types (not Go method getters), the naming creates confusion with Go's getter convention.
Fix: Rename to SessionNotesInput/Output, ActiveInsightsInput/Output.
```

```
[MEDIUM] [INTERFACE] internal/notion/sync.go:22-26
Rule: Interface method count / No interface for one implementation
Source: Google Style Guide, interface-golden-rule.md
Finding: ProjectResolver has 3 methods but only 1 production implementation
(project.Store). GoalResolver also has 1 method, 1 implementation.
Both exist to avoid importing concrete types — valid architectural boundary, but borderline.
Fix: Document the boundary justification. Consider if UpdateLastActivity could use
the event bus instead, shrinking ProjectResolver to 2 methods.
```

```
[MEDIUM] [ERROR] internal/auth/middleware.go:38
Rule: Document intentional %v usage at security boundaries
Source: Project Rules (error-handling.md)
Finding: fmt.Errorf("unexpected signing method: %v", t.Header["alg"]) — uses %v.
This is intentional at a security boundary (don't expose internals), but undocumented.
Fix: Add comment: // %v intentional: security boundary, don't expose internal types
```

```
[MEDIUM] [TYPE] internal/tag/handler.go:35
Rule: Store takes db.DBTX, not *pgxpool.Pool
Source: Project Rules (database.md)
Finding: NewHandler(store *Store, pool *pgxpool.Pool, logger *slog.Logger) — handler
takes pool directly for transaction support (tag merge/backfill operations).
Fix: Consider using store.WithTx pattern instead of passing pool to handler.
```

```
[MEDIUM] [CONCURRENCY] internal/mcp/server.go:698
Rule: Goroutine lifecycle must be explicit
Source: Google Style, concurrency.md
Finding: Telemetry goroutine per tool call with detached context:
  go func() { tctx, cancel := context.WithTimeout(context.Background(), 5s) ... }()
  The //nolint:gosec comment documents intent. 5s timeout prevents leak.
  Acceptable but creates goroutine-per-call overhead.
Fix: Consider buffered channel + single worker goroutine for telemetry batching.
```

```
[MEDIUM] [SCHEMA] internal/session/handler.go (insight metadata)
Rule: Type definitions document schema
Source: Project Rules
Finding: Insight metadata schema (hypothesis, status, evidence, tags, conclusion) is
inferred from JSON parsing code but not formally defined as a Go struct.
Fix: Define InsightMetadata struct with json tags for documentation and type safety.
```

```
[MEDIUM] [DOC] internal/content/handler.go:274, internal/content/store.go:784
Rule: Exported function has doc comment
Source: Google Style Best Practices
Finding: parseFilter and DeleteContent missing doc comments.
Fix: Add doc comments starting with function name.
```

```
[MEDIUM] [CONCURRENCY] internal/auth/handler.go:238
Rule: Don't panic in library code
Source: Effective Go
Finding: panic("crypto/rand: " + err.Error()) — panics on crypto/rand failure.
crypto/rand.Read only fails if OS randomness source is broken (unrecoverable).
Matches stdlib behavior. ACCEPTABLE but worth noting.
Fix: None — this is the correct response to crypto/rand failure.
```

### LOW (3 findings)

```
[LOW] [NAMING] internal/mcpauth/mcpauth.go:154
Rule: No naked returns in functions > few lines
Source: Google Style Decisions
Finding: Single naked return at end of cleanup goroutine function.
Fix: Use explicit return values.
```

```
[LOW] [IMPORTS] internal/ai/prompt.go:3
Rule: No blank identifier imports in application code
Source: Google Style
Finding: import _ "embed" — standard way to enable //go:embed.
Fix: None — this is the only way to use embed. ACCEPTABLE.
```

```
[LOW] [CACHE] internal/topic/handler.go:35-39
Rule: Handle constructor errors
Source: Defensive programming
Finding: ristretto.NewCache called without checking error. If NewCache fails,
topicCache is nil, then Get() panics. Low risk (ristretto rarely fails for
these settings) but should handle defensively.
Fix: Check error and fall back to nil-safe cache or log.Fatal.
```

---

## PART 3: Dependency Graph Analysis

### Most Imported Packages (imported BY others)

| Package | Import Count | Role |
|---------|-------------|------|
| `api` | 38 | Shared HTTP helpers — EXPECTED |
| `content` | 29 | Central domain — EXPECTED |
| `db` | 19 | Generated queries — EXPECTED |
| `project` | 17 | Cross-cutting domain — EXPECTED |
| `feed/entry` | 13 | Collected item data — OK |
| `activity` | 13 | Event recording — OK |
| `task` | 11 | Task data — OK |
| `session` | 11 | Session notes — OK |
| `notify` | 9 | Notifications — OK |
| `goal` | 9 | Goal data — OK |
| `budget` | 9 | Token budget — OK |

### Highest Fan-Out Packages (imports FROM)

| Package | Internal Imports | Justification |
|---------|-----------------|---------------|
| `server` | 24 | Wiring package — EXPECTED |
| `pipeline` | 15 | Cross-cutting orchestration — EXPECTED |
| `mcp` | 14 | God package — NEEDS REFACTOR |
| `ai` | 13 | Orchestration layer — ACCEPTABLE |
| `reconcile` | 9 | Cross-feature drift detection — DOCUMENTED |

### Single-File Package Assessment

| Package | Lines | Import Count | Keep? |
|---------|-------|-------------|-------|
| `api` | 120 | 38 (by others) | YES — shared infrastructure |
| `budget` | 45 | 9 (by others) | YES — clear single responsibility |
| `event` | 76 | 12 (by others) | YES — clean event bus abstraction |
| `github` | 279 | 6 (by others) | YES — substantial external API client |
| `mcpauth` | 515 | 0 (standalone) | YES — substantial OAuth2 implementation |
| `oreilly` | 272 | 1 (by others) | YES — external API client |
| `testdb` | 180 | 6 (by tests) | YES — test infrastructure |

All single-file packages are justified.

---

## PART 4: What's Working Well

1. **Package-by-feature is consistently followed** — no services/, repositories/, models/ anywhere. PreToolUse hook enforces this.

2. **Interface discipline is excellent** — 11 interfaces total across 35 packages. 8 clearly justified (multiple implementations or cross-binary boundaries), 3 borderline but documented. Compile-time verification used where defined.

3. **Receiver naming is perfectly consistent** — every type across all packages uses 1-2 letter abbreviations (`s`, `h`, `c`, `r`). Zero inconsistency. No `this`/`self` anywhere.

4. **Store pattern is uniform** — all 16 stores take `db.DBTX`, use sqlc, return concrete types, propagate context. The pattern is mechanical and predictable.

5. **Goroutine lifecycle management is complete** — every `go func()` has documented shutdown. `sync.Once` for cleanup, `context.WithTimeout` for detached goroutines, `errgroup` for parallel operations.

6. **Error wrapping consistently uses `%w`** — only 1 intentional `%v` at a security boundary. Sentinel errors use `errors.Is`. Go 1.26 `errors.AsType` used for pgconn.PgError.

7. **No init() functions, no dot imports, no context in structs** — clean Go idioms throughout.

8. **Security** — HMAC OAuth state validation, PKCE, atomic token consumption, SSRF blocking in collector, parameterized queries only, proper CSRF with Go 1.25+ CrossOriginProtection.

9. **Modern Go patterns** — `wg.Go()` (1.25+), `errors.AsType` (1.26+), `r.PathValue()` (1.22+), `http.NewCrossOriginProtection()` (1.25+).

10. **Notify package is textbook** — `Notifier` interface with 4 implementations (LINE, Telegram, Multi, Noop), compile-time verification, fan-out composition. This is how stdlib would do it.

---

## PART 5: Summary Table

| Package | Identity | Responsibility | Naming | Errors | Interfaces | Verdict |
|---------|----------|---------------|--------|--------|------------|---------|
| activity | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| ai | PASS | PASS | PASS | PASS | PASS | **CLEAN** |
| ai/exec | PASS | PASS | PASS | PASS | PASS | **CLEAN** |
| ai/report | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| api | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| auth | PASS | PASS | PASS | CRITICAL | N/A | **NEEDS WORK** |
| budget | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| content | PASS | PASS | PASS | HIGH | N/A | **NEEDS WORK** |
| db | PASS | N/A | N/A | N/A | N/A | **CLEAN** |
| event | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| feed | PASS | PASS | PASS | PASS | PASS | **CLEAN** |
| feed/collector | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| feed/entry | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| github | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| goal | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| learning | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| mcp | PARTIAL | CRITICAL | MEDIUM | PASS | PASS | **NEEDS WORK** |
| mcpauth | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| monitor | PASS | PASS | PASS | CRITICAL | N/A | **NEEDS WORK** |
| note | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| notify | PASS | PASS | PASS | PASS | PASS | **CLEAN** |
| notion | PARTIAL | CRITICAL | PASS | PASS | BORDERLINE | **NEEDS WORK** |
| obsidian | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| oreilly | PASS | PASS | PASS | HIGH | N/A | **NEEDS WORK** |
| pipeline | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| project | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| reconcile | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| review | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| server | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| session | PASS | PASS | PASS | CRITICAL | N/A | **NEEDS WORK** |
| stats | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| tag | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| task | PASS | PASS | PASS | CRITICAL/HIGH | BORDERLINE | **NEEDS WORK** |
| testdb | PASS | PASS | PASS | N/A | N/A | **CLEAN** |
| topic | PASS | PASS | PASS | PASS | PASS | **CLEAN** |
| upload | PASS | PASS | PASS | PASS | N/A | **CLEAN** |
| webhook | PASS | PASS | PASS | PASS | N/A | **CLEAN** |

**Score: 27/35 CLEAN, 8 NEEDS WORK**

---

## Final Verdict

> **Codebase semantic health: ACCEPTABLE — trending toward STRONG**

### Top 5 Systemic Issues

1. **MCP is a god package (110 exported methods, 14 domains, 4 duplicated store fields)** — The single largest design debt. Should split into domain-specific tool files or sub-packages. The duplicate store fields (`notes`/`semanticNotes`, `activity`/`activityWriter`, `projects`/`projectWriter`, `stats`/`systemStatus`) are semantic noise that makes the struct harder to reason about.

2. **Missing ErrConflict in 4 packages with Create methods** — auth, monitor, session, task stores can hit unique constraint violations but have no ErrConflict sentinel. Users get 500 instead of 409. This is a data integrity UX bug waiting to surface.

3. **7 uppercase error strings across 4 packages** — content/store.go (2), mcp/oreilly_tools.go (3), notion/store.go (1), oreilly/oreilly.go (1). Indicates error conventions aren't enforced by linter or CI. Should add a grep-based CI check.

4. **notion package does too much (9 files, 60+ exports, 4 distinct responsibilities)** — API client, sync engine, webhook handler, source CRUD all in one package. The `ProjectResolver` and `GoalResolver` interfaces (1-3 methods, 1 implementation each) are symptoms of over-coupling.

5. **Transaction boundaries in store, not handler (content/store.go)** — CreateContent and UpdateContent internally start transactions by type-asserting DBTX. Violates "handler controls transaction boundary" rule and silently fails with non-pool DBTX.

### Absent Issues (Things I Expected to Find but Didn't)

- No circular imports
- No context stored in structs
- No init() functions in application code
- No dot imports
- No `interface{}` (all replaced with `any`)
- No `Get` prefix on getter methods (except MCP input types, which are DTO names)
- No `services/`, `repositories/`, `models/` directories
- No mock-only interfaces (all 11 interfaces have production justification)
- No goroutine leaks (all have managed lifecycle)
- No SQL injection vectors (all queries via sqlc or parameterized)
- No string-based error comparison (all use `errors.Is`/`errors.As`)
- No log-AND-return violations (only acceptable edge cases documented)
