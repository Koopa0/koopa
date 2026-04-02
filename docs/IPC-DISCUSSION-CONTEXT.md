# Context: Strengthening IPC Protocol for Multi-Agent System

I need your help reviewing and challenging an implementation plan for hardening the inter-process communication protocol in my system.

---

## What I Built

A Go backend (`koopa0.dev`) that serves as a personal knowledge engine. It exposes 54 MCP (Model Context Protocol) tools over a single PostgreSQL database. Multiple AI agent sessions connect to this backend and communicate with each other through it.

I run 4 Claude Desktop "Cowork" projects as a virtual studio:

| Project | Role | Analogy |
|---------|------|---------|
| Studio HQ | CEO — makes decisions, delegates work | Manager process |
| Content Studio | Content strategy, writing, publishing | Worker process |
| Research Lab | Deep research, structured reports | Worker process |
| Learning Studio | LeetCode coaching, spaced repetition | Worker process |

These projects **do not run concurrently**. Each is a separate Claude session that runs one at a time. They share state through one PostgreSQL database via the same MCP server.

## How They Communicate Today

All cross-project communication goes through a single table:

```sql
CREATE TABLE session_notes (
    id          BIGSERIAL PRIMARY KEY,
    note_date   DATE NOT NULL,
    note_type   TEXT NOT NULL
                CHECK (note_type IN ('plan','reflection','context','metrics','insight','directive','report')),
    source      TEXT NOT NULL
                CHECK (source IN ('claude','claude-code','manual','hq','learning-studio','content-studio','research-lab')),
    content     TEXT NOT NULL,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX idx_session_notes_date ON session_notes (note_date DESC);
CREATE INDEX idx_session_notes_type ON session_notes (note_date, note_type);
CREATE INDEX idx_session_notes_insight_status ON session_notes ((metadata->>'status')) WHERE note_type = 'insight';
```

The communication pattern:

```
HQ writes directive (note_type='directive', source='hq')
    → stored in session_notes
        → Content Studio reads it on next session start
            → executes work
                → writes report (note_type='report', source='content-studio')
                    → HQ reads report in next morning briefing
```

PostgreSQL is the message bus. `note_type` and `source` are the routing keys. Communication is **async** — each project writes, then exits. The next project reads on its next session.

## Current Validation (Go application layer)

```go
// write.go — validateSessionNoteMetadata()
// Per note_type required metadata:

// insight:    hypothesis (string), invalidation_condition (string)  — STRICT
// plan:       reasoning (string), committed_task_ids OR committed_items — STRICT
// metrics:    tasks_planned, tasks_completed, adjustments            — STRICT
// directive:  NOTHING REQUIRED                                       — PROBLEM
// report:     NOTHING REQUIRED                                       — PROBLEM
// context:    nothing (acceptable, internal use)
// reflection: nothing (acceptable, internal use)
```

## The Four Problems

1. **No schema enforcement on directives** — `metadata` is free-form JSONB. A directive can be written without specifying which department it targets or what priority it has. The target department is buried in the `content` TEXT field as prose.

2. **No delivery confirmation** — HQ writes a directive. There's no way to know if Content Studio ever read it. No `consumed_at`, no acknowledgment mechanism.

3. **No causal linking** — When Content Studio writes a report, there's no structural link back to which directive it's responding to. You have to infer from dates and content text.

4. **No targeting query** — You can't `SELECT * FROM session_notes WHERE target='content-studio'` because target isn't a field. You'd have to parse the prose in `content`.

## My Proposed Solution

### Key constraint: this is NOT a distributed systems problem

All 4 projects write to the **same PostgreSQL** through the **same Go server**. There are no network partitions, no multiple databases, no concurrent writers racing. CAP theorem doesn't apply. 2PC, saga pattern, compensating transactions — none of these are relevant.

This is a **message queue design problem** on a single database.

### Proposed changes (one migration)

```sql
-- 1. Delivery confirmation
ALTER TABLE session_notes ADD COLUMN consumed_at TIMESTAMPTZ;
ALTER TABLE session_notes ADD COLUMN consumed_by TEXT;

-- 2. Directive schema enforcement (DB safety net)
ALTER TABLE session_notes ADD CONSTRAINT chk_directive_metadata
  CHECK (note_type != 'directive' OR created_at <= '2026-04-07' OR (
    metadata IS NOT NULL
    AND metadata ? 'target'
    AND metadata ? 'priority'
    AND metadata->>'target' IN ('content-studio','research-lab','learning-studio','claude-code')
    AND metadata->>'priority' IN ('p0','p1','p2')
  ));

-- 3. Report causal link enforcement
ALTER TABLE session_notes ADD CONSTRAINT chk_report_metadata
  CHECK (note_type != 'report' OR created_at <= '2026-04-07' OR (
    metadata IS NOT NULL
    AND metadata ? 'in_response_to'
  ));

-- 4. Expression index for targeting
CREATE INDEX idx_session_notes_directive_target
  ON session_notes ((metadata->>'target'))
  WHERE note_type = 'directive';

-- 5. Index for unconsumed directives
CREATE INDEX idx_session_notes_unconsumed
  ON session_notes (note_type, consumed_at)
  WHERE consumed_at IS NULL;
```

### Go validation layer (in addition to DB CHECK)

```go
case "directive":
    // Require target + priority in metadata
    target := metadata["target"].(string)  // "content-studio" | "research-lab" | etc.
    priority := metadata["priority"].(string)  // "p0" | "p1" | "p2"

case "report":
    // Require in_response_to (the directive's session_note ID)
    inResponseTo := metadata["in_response_to"]  // int64
```

### New query: consume directive

```sql
UPDATE session_notes
SET consumed_at = now(), consumed_by = @consumer
WHERE id = @id AND consumed_at IS NULL
RETURNING *;
```

### Decisions already made

| Decision | Chose | Rejected | Why |
|----------|-------|----------|-----|
| Validation | DB CHECK + Go dual-layer | pg_jsonschema extension | No deployment dependency; CHECK is safety net, Go gives good error messages |
| Targeting | JSONB `metadata->>'target'` + expression index | New `target` column | Avoid schema change; JSONB + index achieves same query performance |
| Causal linking | `in_response_to` in JSONB metadata | `parent_id` column | Same reasoning |
| Delivery confirmation | `consumed_at` + `consumed_by` columns | Outbox pattern | Single DB, no relay needed |
| Concurrent safety | Not implementing SKIP LOCKED yet | FOR UPDATE SKIP LOCKED | Agents don't run concurrently today |
| Notification | Not implementing LISTEN/NOTIFY | PostgreSQL pub/sub | Agents are async sessions, not long-running listeners |
| Event format | Borrow CloudEvents envelope concept only | Full CloudEvents spec | Overkill for internal single-DB communication |

### Backward compatibility

The `created_at <= '2026-04-07'` clause in CHECK constraints exempts existing data. New directives/reports after that date must have proper metadata.

---

## What I Want to Discuss

1. **Am I over-engineering or under-engineering this?** The system works today with free-form text. Is the metadata enforcement worth the migration complexity, or should I keep it simple and just fix it in the Cowork project instructions (telling each agent what fields to include)?

2. **JSONB metadata vs dedicated columns for `target` and `in_response_to`?** I chose JSONB to avoid schema changes, but these fields are now structurally important routing fields — maybe they deserve to be first-class columns?

3. **Is `consumed_at` the right acknowledgment model?** Each directive targets one department. Should it be a simple boolean `consumed`, or does the timestamp + consumer identity matter? What if a directive targets multiple departments?

4. **The `created_at <= '2026-04-07'` backward compatibility hack** — is there a cleaner way to handle existing data that doesn't conform to the new constraints?

5. **Am I missing failure modes?** What happens if a department reads a directive but crashes before writing `consumed_at`? (In practice: the Claude session just ends — it's not a crash, it's normal session termination. The next session would re-read unconsumeed directives, which is actually desired behavior — retry semantics for free.)

6. **Should I version the protocol?** Add a `schema_version` field to metadata so future changes don't require more backward-compatibility hacks?

7. **Any patterns from event-driven architecture, message queue design, or actor model systems that I should consider but haven't?**

---

## Technical Context

- **Language**: Go 1.26+, stdlib `net/http`, no frameworks
- **Database**: PostgreSQL, pgx/v5, sqlc for query generation
- **Table size**: Small — hundreds of rows, not millions. Performance is not a concern.
- **Concurrency**: None. Sequential async sessions. May add concurrent sessions in the future.
- **The "consumers" are AI agents** (Claude), not traditional microservices. They don't have persistent connections or heartbeats. Each session is ephemeral.
