# Claude Code Session 2 — Code Review Report (2026-03-30)

> Original report pasted by user. Preserved verbatim for cross-reference.

## All Findings

[CRITICAL] [BOUNDARY] internal/mcp/server.go:31
mcp is a concrete cross-feature super-facade (13 internal package dependencies, 11 required constructor args).
Fix: Split MCP tools by bounded context, define consumer-side interfaces per tool group, keep mcp.Server as thin registration/wiring only.

[CRITICAL] [RESPONSIBILITY] internal/notion/handler.go:74
notion.Handler mixes webhook auth, dedup/replay defense, source role routing, property extraction, cross-entity upsert orchestration, event emission, and background scheduling.
Fix: Split into Verifier, Router, PropertyMapper, and RoleSyncService.

[CRITICAL] [DEPENDENCY_INVERSION] internal/task/store.go:13
task imports ai and returns ai.PendingTask / ai.ProjectCompletion.
Fix: Move these DTOs to task and let ai/report consume task interfaces/types.

[HIGH] [RESPONSIBILITY] internal/pipeline/handler.go:40
pipeline contains three different subsystems with 15 internal imports.
Fix: Split into pipeline/contentsync, pipeline/webhook, pipeline/triggers.

[HIGH] [BOUNDARY] internal/github/github.go:160
github.Client.Compare returns *activity.DiffStats, leaking activity-domain type.
Fix: Define github.DiffStats locally; map at caller boundary.

[HIGH] [BOUNDARY] internal/topic/handler.go:34
topic.Handler depends on concrete *content.Store.
Fix: Define narrow ContentByTopicReader interface in topic.

[HIGH] [BOUNDARY] internal/project/notion.go:73
project imports tag only for tag.Slugify.
Fix: Move slug normalization into project or internal/slug.

[HIGH] [RESPONSIBILITY] internal/feed/store.go:20
feed.Store sends operational alerts (notify.Notifier) during failure auto-disable.
Fix: Return typed domain event/error from store, trigger notifications in orchestrator.

[HIGH] [CONCURRENCY] internal/pipeline/webhook.go:114
Background jobs detach request cancellation via context.WithoutCancel without adding bounded timeout.
Fix: Derive from app-shutdown context with explicit timeout.

[HIGH] [ERROR_HANDLING] internal/auth/handler.go:238
generateState panics on random-source failure.
Fix: Return (string, error) and propagate.

[HIGH] [FUNCTION_DESIGN] internal/mcp/server.go:142
Constructor signatures oversized (mcp.NewServer 11; ai.Setup 9; ai.NewContentReview 11).
Fix: Replace with validated dependency structs.

[HIGH] [FUNCTION_DESIGN] internal/content/store.go:791
rowToContent takes 21 positional parameters.
Fix: Accept single source struct.

[MEDIUM] [ERROR_STYLE] internal/content/store.go:497
Several error messages start uppercase.
Fix: Normalize to lowercase.

[MEDIUM] [FUNCTION_DESIGN] internal/mcp/oauth.go:138
issueToken uses named return values with naked return.
Fix: Return explicit values.

[MEDIUM] [DOCUMENTATION] internal/db/db.go:5
db has no package doc string.
Fix: Add internal/db/doc.go.

[MEDIUM] [DOCUMENTATION] internal/content/content.go:16
Exported const blocks and methods missing docs in multiple packages.
Fix: Add block-level comments.

[MEDIUM] [API_DESIGN] internal/api/api.go:13
api.Response.Data any forces runtime type assumptions.
Fix: Use generics Response[T].

[MEDIUM] [API_DESIGN] internal/upload/client.go:12
NewS3Client(ctx ...) accepts ctx but never uses it.
Fix: Remove ctx param.

[MEDIUM] [CONCURRENCY] internal/webhook/replay.go:46
DeduplicationCache.Stop closes channel directly; second call panics.
Fix: Guard with sync.Once.

[LOW] [DATABASE_TEST_SAFETY] internal/testdb/testdb.go:70
TRUNCATE SQL built via string concatenation.
Fix: Whitelist allowed table identifiers.

[LOW] [STYLE] internal/server/middleware.go:28
requestIDMiddleware(logger *slog.Logger) never uses logger.
Fix: Remove the parameter.

## Part 1.1 Package Identity

| Package | Identity |
|---|---|
| activity | Records and queries cross-source activity events, groups into session/changelog views. |
| ai | Executes and wires Genkit-based content and reporting flows. |
| api | Standardizes HTTP JSON encoding, decoding, pagination, and error responses. |
| auth | Authenticates admin users via Google OAuth and issues/rotates JWT + refresh tokens. |
| budget | Tracks daily AI token usage and enforces budget reservations. |
| content | Manages content lifecycle, search, embeddings, and knowledge-graph outputs. |
| db | Provides sqlc-generated query contracts and model mappings. |
| event | Dispatches synchronous in-process domain events. |
| feed | Manages feed source configuration and collection state. |
| github | Fetches files, commits, and compare stats from GitHub REST APIs. |
| goal | Manages goals and maps Notion goal status into local state. |
| learning | Computes learning analytics from tagged content activity. |
| mcp | Exposes MCP tools for querying and mutating knowledge-system data. |
| monitor | Manages trackable data-collection topics and schedules. |
| note | Stores, indexes, links, and searches Obsidian knowledge notes. |
| notify | Sends text notifications through multiple channels. |
| notion | Integrates Notion APIs/webhooks and synchronizes role-based data. |
| obsidian | Parses Obsidian markdown metadata, links, and text normalization. |
| pipeline | Orchestrates webhook-driven sync and manually triggered operations. |
| project | Manages project portfolio records and Notion synchronization mapping. |
| reconcile | Detects and reports drift between local data and external sources. |
| review | Manages content review queue state transitions. |
| server | Wires HTTP middleware and route registration for all handlers. |
| session | Stores and updates session notes/insight metadata. |
| stats | Aggregates operational and product metrics for admin dashboards. |
| tag | Canonicalizes raw tags, manages aliases, and syncs tag associations. |
| task | Manages task lifecycle with Notion sync and admin operations. |
| testdb | Provisions disposable PostgreSQL test infrastructure. |
| topic | Manages topic taxonomy and topic-centric content views. |
| upload | Uploads assets to S3-compatible object storage. |
| webhook | Verifies webhook signatures and provides replay-dedup cache. |

## Part 1.2 Import Analysis

Notable FAIL/SUSPECT:
- github → activity: FAIL (DiffStats return type)
- task → ai: FAIL (PendingTask/ProjectCompletion DTOs)
- project → tag: FAIL (Slugify utility usage)
- topic → content: SUSPECT (concrete *content.Store)
- feed → notify: SUSPECT (store sends alerts)
- mcp → 12 packages: SUSPECT (all concrete)
- notion → tag: SUSPECT (slug utility)
- notion → ai/exec: SUSPECT (background AI jobs)

## Part 1.3 Responsibility Boundaries

| Package | SRP | Feature Envy | God Package | Utility Dump |
|---|---|---|---|---|
| mcp | FAIL | FAIL | FAIL | PARTIAL |
| ai | FAIL | PARTIAL | FAIL | PARTIAL |
| notion | FAIL | PARTIAL | FAIL | PARTIAL |
| pipeline | FAIL | PARTIAL | FAIL | PARTIAL |
| task | FAIL | PARTIAL | FAIL | PARTIAL |
| content | PARTIAL | PARTIAL | PARTIAL | PARTIAL |

## Summary Table

| Package | Identity | Responsibility | Naming | Errors | Interfaces | Verdict |
|---|---|---|---|---|---|---|
| activity | PASS | PARTIAL | PASS | PASS | PASS | NEEDS WORK |
| ai | PASS | FAIL | PARTIAL | PASS | PARTIAL | NEEDS WORK |
| api | PASS | PASS | PASS | PASS | PARTIAL | ACCEPTABLE |
| auth | PASS | PARTIAL | PASS | PARTIAL | PASS | NEEDS WORK |
| budget | PASS | PASS | PASS | PASS | PASS | CLEAN |
| content | PASS | PARTIAL | PARTIAL | PARTIAL | PARTIAL | NEEDS WORK |
| db | PASS | PASS | PARTIAL | PASS | PASS | ACCEPTABLE |
| event | PASS | PASS | PASS | PASS | PARTIAL | ACCEPTABLE |
| feed | PASS | PARTIAL | PASS | PASS | PARTIAL | NEEDS WORK |
| github | PASS | PARTIAL | PASS | PASS | FAIL | NEEDS WORK |
| goal | PASS | PASS | PASS | PASS | PASS | CLEAN |
| learning | PASS | PARTIAL | PASS | PASS | PASS | ACCEPTABLE |
| mcp | FAIL | FAIL | PARTIAL | PARTIAL | FAIL | NEEDS WORK |
| monitor | PASS | PASS | PASS | PASS | PASS | CLEAN |
| note | PASS | PARTIAL | PARTIAL | PASS | PASS | ACCEPTABLE |
| notify | PASS | PASS | PASS | PASS | PASS | CLEAN |
| notion | PASS | FAIL | PASS | PASS | PARTIAL | NEEDS WORK |
| obsidian | PASS | PASS | PASS | PASS | PASS | CLEAN |
| pipeline | PASS | FAIL | PASS | PASS | PARTIAL | NEEDS WORK |
| project | PASS | PARTIAL | PASS | PASS | PARTIAL | NEEDS WORK |
| reconcile | PASS | PASS | PASS | PASS | PASS | ACCEPTABLE |
| review | PASS | PASS | PARTIAL | PASS | PASS | ACCEPTABLE |
| server | PASS | PASS | PARTIAL | PASS | PASS | ACCEPTABLE |
| session | PASS | PARTIAL | PASS | PASS | PARTIAL | NEEDS WORK |
| stats | PASS | PARTIAL | PASS | PASS | PASS | ACCEPTABLE |
| tag | PASS | PARTIAL | PASS | PASS | PARTIAL | NEEDS WORK |
| task | PASS | FAIL | PARTIAL | PASS | FAIL | NEEDS WORK |
| testdb | PASS | PASS | PASS | PARTIAL | PASS | ACCEPTABLE |
| topic | PASS | PARTIAL | PASS | PASS | PARTIAL | NEEDS WORK |
| upload | PASS | PARTIAL | PASS | PASS | PASS | ACCEPTABLE |
| webhook | PASS | PARTIAL | PASS | PASS | PASS | ACCEPTABLE |

## Final Verdict

Codebase semantic health: **NEEDS WORK**

Top 5 systemic issues:
1. Cross-feature concrete coupling instead of consumer-owned interfaces
2. God-package drift in orchestration layers (mcp, notion, pipeline, ai)
3. Constructor/function signature bloat
4. Public API hygiene drift (missing docs, weakly-typed any surfaces)
5. Inconsistent operational safety policy (panic, detached contexts, non-idempotent stop)
