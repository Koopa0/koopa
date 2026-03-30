# Auggie Code Review Report (2026-03-30)

> Original report pasted by user. Preserved verbatim for cross-reference.

## PART 1: Semantic Review

### 1.1 Package Identity

| Package | One-Sentence Identity |
|---------|----------------------|
| activity | Package activity records and queries developer activity events (coding sessions, commits, changelogs). |
| ai | Package ai defines AI processing flows (review, polish, excerpt, tags, etc.) for the content pipeline via Genkit. |
| ai/exec | Package exec manages flow run persistence, scheduling, retry, and observation. |
| ai/report | Package report implements scheduled AI report flows (digest, morning brief, weekly review, daily dev log). |
| api | Package api provides shared HTTP response helpers (encode, decode, pagination, error mapping). |
| auth | Package auth authenticates users via Google OAuth and issues/refreshes JWT tokens. |
| budget | Package budget tracks daily LLM token usage with an in-memory atomic counter. |
| content | Package content manages the content lifecycle (CRUD, publishing, search, knowledge graph, RSS, sitemap). |
| db | Package db is sqlc-generated database access code. |
| event | Package event provides a synchronous in-process event bus for cross-cutting dispatch. |
| feed | Package feed manages RSS/Atom feed subscriptions with filtering, scheduling, and auto-disable. |
| feed/collector | Package collector fetches and normalizes RSS/Atom feed items. |
| feed/entry | Package entry manages collected feed entries (curate, ignore, feedback). |
| github | Package github provides a client for the GitHub REST API (Contents, Compare, Commits). |
| goal | Package goal tracks personal goals synced from Notion. |
| learning | Package learning computes learning analytics (coverage matrix, tag summary, weakness trends) over content tag entries. |
| mcp | Package mcp provides an MCP server exposing tools for querying and managing the knowledge engine. |
| monitor | Package monitor configures data collection topics and schedules. |
| note | Package note manages Obsidian knowledge notes synced from the vault. |
| notify | Package notify provides multi-channel text notification delivery (LINE, Telegram, noop). |
| notion | Package notion handles Notion webhook events, API integration, and source registry. |
| obsidian | Package obsidian provides Markdown frontmatter parsing for Obsidian vault files. |
| pipeline | Package pipeline handles webhook processing and content sync orchestration. |
| project | Package project provides project portfolio management. |
| reconcile | Package reconcile compares Obsidian/Notion records against the local database to detect drift. |
| review | Package review provides content review queue management. |
| server | Package server provides HTTP server setup, routing, and middleware wiring. |
| session | Package session provides cross-environment context bridging via session notes. |
| stats | Package stats provides aggregated platform statistics for the admin dashboard. |
| tag | Package tag provides canonical tag management and normalization. |
| task | Package task provides task tracking synced from Notion. |
| testdb | Package testdb provides a shared PostgreSQL testcontainer for integration tests. |
| topic | Package topic provides topic management for content categorization. |
| upload | Package upload handles file uploads to R2/S3. |
| webhook | Package webhook provides deduplication and timestamp validation for incoming webhooks. |

Verdict: Every package passes the one-sentence test. Identities are clear and cohesive.

### 1.2 Dependency Analysis — Key Suspect Imports

| From | Imports | Reason | Verdict |
|------|---------|--------|---------|
| github | activity | Returns activity.DiffStats from Compare API | SUSPECT — DiffStats is a data type that github generates. Why does github import activity for a return type? The struct should live in github or a shared types location. This creates an upward dependency from an infrastructure package to a feature package. |
| reconcile | content, github, goal, notify, notion, project | Orchestrates cross-feature comparison | OK — explicitly documented as a cross-feature orchestration package. Uses concrete injection via constructor. |
| mcp | 12 internal packages | MCP server needs to access all domain stores | OK but heavy — MCP is inherently a gateway/facade. The 20+ fields on Server struct are a smell, but functionally correct for its role. |
| server | 22 internal packages | Route registration needs all handlers | OK — this is the wiring layer. |
| learning | content | Uses content.TagEntry for analytics | OK — pure computation on content data. |
| ai | content, review, topic, entry, project, budget, github, notify | AI flows need domain stores to read/write | OK but wide — the Setup function takes 9 parameters. |
| notion | activity, ai/exec, event, webhook | Notion handler records events, triggers flows, deduplicates webhooks | OK — each import serves a specific integration purpose. |
| pipeline | content, note, tag, activity, ai/exec, github, notion, project, webhook, event | Orchestrates push→sync→flow pipeline | OK — pipeline is the orchestration layer by design. |

### 1.3 Responsibility Boundary Checks

[CRITICAL] [RESPONSIBILITY] github/github.go:160
Rule: Package provides, not contains
Source: Ardan Labs
Finding: github.Client.Compare() returns *activity.DiffStats, creating a dependency from
         infrastructure (github) to feature (activity). github should not know about activity's types.
Fix: Define a DiffStats struct in github package. Let the caller (pipeline/activity) convert
     github.DiffStats → activity.DiffStats at the boundary.

[HIGH] [RESPONSIBILITY] content/handler.go:144-287
Rule: Single Responsibility
Source: Effective Go / Ardan Labs
Finding: content.Handler owns RSS feed generation and Sitemap generation (RSS, Sitemap methods),
         which is a presentation/syndication concern, not a content CRUD concern. The handler is
         ~710 lines with XML generation, caching, and knowledge graph computation.
Fix: Extract RSS/Sitemap into a separate package (e.g., internal/syndication or internal/feed/output)
     or at minimum a separate file. The knowledge graph builder (lines 471-633) could also be its own
     file or package.

[MEDIUM] [RESPONSIBILITY] mcp/server.go
Rule: God Package
Source: Ardan Labs
Finding: mcp.Server has 20+ fields and implements 30+ tool handlers across 700+ lines in server.go
         alone, plus 15+ additional files. Each tool file (search.go, content.go, goals.go, etc.) is
         effectively its own concern mixed into one struct.
Fix: Consider grouping tools into sub-structs (e.g., s.search.*, s.content.*) or using composition
     to reduce the Server struct field count.

[MEDIUM] [RESPONSIBILITY] notion/handler.go
Rule: Single Responsibility
Source: Ardan Labs
Finding: notion.Handler handles webhook verification, event dispatch, 3 different entity sync
         operations (project, goal, task), archiving, plus source cache management. This is 515 lines
         with many optional dependencies configured via functional options.
Fix: The current design uses functional options to keep it flexible, which partially mitigates this.
     However, consider breaking sync logic per entity into separate handler files.

## PART 2: Naming Audit

### 2.1 Effective Go Naming

[MEDIUM] [NAMING] mcp/search.go:973, mcp/insights.go:46
Rule: Getter has no Get prefix
Source: Effective Go
Finding: Methods getSessionNotes and getActiveInsights use "get" prefix. While unexported
         (lowercase), the naming convention still applies in idiomatic Go.
Fix: Rename to sessionNotes and activeInsights. These are unexported methods used as MCP
     tool handlers, so the "get" prefix adds no clarity beyond the function's signature.

[LOW] [NAMING] github/github.go — receiver name "g"
Rule: Receiver name: 1-2 letter abbreviation of type
Source: Google Style Decisions
Finding: github.Client uses receiver "g" (for github). The conventional abbreviation for
         *Client is "c".
Fix: Change receiver from "g" to "c" on all Client methods. This is a minor inconsistency —
     "g" is understandable but unconventional.

[LOW] [NAMING] topic/topic.go:49
Rule: Package name in identifier — stutter
Source: Effective Go
Finding: topic.Slug struct — "Slug" is generic enough and doesn't stutter. PASS.
         topic.TagCount — also used in stats.TagCount and learning.TagCount. Three independent
         TagCount types with identical structures across different packages.
Fix: Consider a shared type if these are always (name string, count int) pairs, or accept
     the duplication since they're in different semantic contexts.

Naming checks — all PASS:
  • MixedCaps only: No underscores found in exported identifiers (outside generated code)
  • Acronyms: GithubURL, LiveURL, APIKey — all correct
  • No Impl suffix anywhere
  • Package names are all lowercase single words
  • Receiver names are consistent per type (s *Store, h *Handler, c *Client, r *Reconciler, b *Budget, etc.)
  • No self receivers
  • No interface stutter (Notifier, not NotifyNotifier)

### 2.2–2.3 Google Style Guide

[LOW] [NAMING] Various packages — missing package doc comments in doc.go
Rule: Package doc in doc.go or main file
Source: Google Style Best Practices
Finding: No doc.go files exist. Package docs are in the main .go file, which is acceptable.
Fix: No action needed — package doc comments exist on main files consistently.

All other Google Style checks — PASS.

## PART 3: Error Handling Audit

[HIGH] [ERRORS] Various packages — generic sentinel error messages
Rule: Error context adds operation, not redundant message
Source: Google Style Decisions
Finding: Many packages use identical generic sentinel errors:
         var ErrNotFound = errors.New("not found")
         var ErrConflict = errors.New("conflict")
         Packages: content, tag, project, topic, review, feed, note, session, monitor, notion
         These are semantically ambiguous when composed — errors.Is(err, content.ErrNotFound)
         and errors.Is(err, topic.ErrNotFound) both unwrap to "not found". If both appear
         in the same error chain (e.g., a pipeline that touches both), the first match wins.
Fix: Add package context to sentinel errors:
     var ErrNotFound = errors.New("content: not found")
     This also makes log/debug output more useful.

[LOW] [ERRORS] auth/handler.go:238
Rule: Don't panic in library code
Source: Effective Go
Finding: panic("crypto/rand: " + err.Error()) in auth handler for CSRF token generation.
Fix: This is actually acceptable — crypto/rand.Read failing is a system-level invariant
     violation (entropy exhaustion). The Go stdlib itself panics in similar cases.
     PASS (borderline acceptable).

Error handling — bulk checks PASS.

## PART 4: Type & Interface Design

[CRITICAL] [INTERFACES] ai/ai.go:48 — Interface defined at implementor side
Rule: Interfaces belong to the consumer, not the implementor
Source: Effective Go
Finding: The Flow interface is defined in package ai, and all flow implementations also live
         in ai (and ai/report). The consumer (ai/exec.Runner) imports ai.Flow. This is actually
         the CORRECT direction: exec consumes ai.Flow. However, QueryEmbedder and PipelineTrigger
         in mcp/mcp.go ARE correctly consumer-defined interfaces. The ai.Flow case is acceptable
         because the interface is in the "shared" root of a family of implementations.
Fix: No action needed — this is the "standard library" pattern where the interface and
     implementations co-exist in the same package family. Reclassified to PASS.

[MEDIUM] [TYPES] notify/notify.go — Notifier interface defined at implementor
Rule: Interfaces belong to the consumer, not the implementor
Source: Effective Go
Finding: notify.Notifier is defined in package notify alongside all its implementations
         (LINE, Telegram, Multi, Noop). Consumers like reconcile, pipeline, and mcp import
         notify.Notifier. This is the "standard library" pattern (io.Reader defined in io,
         used everywhere). Acceptable for a cross-cutting concern.
Fix: No action needed. This is a valid pattern for infrastructure interfaces.

[LOW] [TYPES] Exported fields with constructors
Rule: Don't export fields if you provide a constructor
Source: Google Style Best Practices
Finding: All domain types (Content, Project, Task, etc.) export fields AND have no constructors
         — they are DTOs populated by store methods. This is correct for data transfer objects.
         Store types have constructors (NewStore) and unexported fields. PASS.
Fix: No action needed.

Interface/Type checks — PASS.

## PART 5: Function & Method Design

[MEDIUM] [FUNCTION] ai/pipeline.go:58 — Setup has 9 positional parameters
Rule: Function arg count ≤ 5
Source: Google Style Best Practices
Finding: Setup(ctx, cfg, stores, gh, notifier, tokenBudget, loc, logger, reportFlows) — 9 params.
         cfg and stores are already option structs (good), but the remaining 6 positional params
         are still excessive.
Fix: Bundle gh, notifier, tokenBudget, loc, logger into a PipelineDeps struct.

[LOW] [FUNCTION] content/handler.go:159-226 — RSS inline closure types
Rule: No complex inline closures / extract to named function
Source: Google Style Best Practices
Finding: RSS() and Sitemap() define XML struct types inline. These are 30+ line methods with
         inline type definitions. The types are only used once each, but the method is complex enough
         to warrant extraction.
Fix: Move rssItem/rssChannel/rss types to content.go or a syndication file.

Function design — bulk checks PASS.

## PART 6: Package Structure & File Organization

[LOW] [STRUCTURE] webhook package — utility/helper status
Finding: webhook has two files: webhook.go + replay.go. Provides dedup + timestamp validation.
Fix: Acceptable. Merging into pipeline would create circular dependency.

[LOW] [STRUCTURE] budget package — single-file
Finding: budget has only budget.go (46 lines).
Fix: Acceptable — clean, focused abstraction.

Structure checks — PASS.

## PART 7: Concurrency & Safety

Concurrency checks — all PASS.

## PART 8: Database & Store Layer

[LOW] [DATABASE] testdb/testdb.go:73, 153 — SQL injection in TRUNCATE
Finding: test-only code, table names from constants.
Fix: Acceptable for test utilities.

Database checks — PASS.

## Individual Findings Summary

[CRITICAL] github.Client.Compare() returns *activity.DiffStats — reverse dependency.
[HIGH] content.Handler 710 lines — RSS, Sitemap, knowledge graph, CRUD.
[HIGH] 10 packages define var ErrNotFound = errors.New("not found") with identical messages.
[MEDIUM] ai.Setup() takes 9 positional parameters.
[MEDIUM] mcp getSessionNotes/getActiveInsights use "get" prefix.
[MEDIUM] mcp.Server has 20+ fields and 30+ tool handlers.

## Final Verdict

Codebase semantic health: **STRONG**

Top 5 Systemic Issues:
1. Identical sentinel error messages across 10 packages
2. github → activity reverse dependency
3. content.Handler responsibilities too wide
4. ai.Setup parameter sprawl
5. mcp.Server field explosion
