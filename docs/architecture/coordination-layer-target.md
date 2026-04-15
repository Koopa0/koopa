# koopa0.dev Coordination Layer — Target Architecture

> **Status**: Approved 2026-04-14
> **Scope**: Inter-agent coordination layer (IPC envelope, agent registry, capability enforcement, read-side projection)
> **Out of scope**: PARA structure, learning analytics (sessions/attempts/observations), GTD personal todos beyond the rename, MCP tool catalog, frontend
>
> This document is the destination. It is the result of a 5-round multi-agent review process synthesising four independent design proposals (this codebase's primary author, two Claude Code sessions with different lenses, and a Codex review). Disagreements between sources have been resolved with explicit reasoning. The document is meant to be read cold by a future engineer and implemented stage by stage. There is no journey here, only the destination.

---

## 1. Purpose & Scope

### 1.1 The four concerns this architecture addresses

This rebuild exists because the current coordination layer has four concrete pains:

1. **IPC fragility.** The current envelope shape (`directives.content TEXT + metadata JSONB`), lifecycle encoding (three nullable timestamps + CHECK constraints), and capability validation (one runtime check at `internal/mcp/ipc.go:44`, everything else policy-doc + reviewer discipline) are insufficiently disciplined.
2. **Handoff bloat.** `internal/mcp/morning.go:33-46` returns 11 parallel arrays of full-fidelity rows from 7 parallel store queries with no truncation, pagination, or field-selection controls. The bloat is a structural problem, not a discipline problem.
3. **Harness intuitiveness.** Agent definitions are scattered across five locations (`participant` table, `participant_schedules` table, policy doc, MCP handler code, decision policy meta-rules). No single source of truth.
4. **Add/remove agent friction.** Adding an agent requires SQL migration + policy doc edit + handler write + capability registration. Removing requires FK RESTRICT navigation. Configuration is awkward.

Every design decision below is justified by which of these four concerns it addresses. Decisions that don't address any of them have been removed (YAGNI).

### 1.2 Constraints

- Single-user, single-process, sequential dispatch
- All current data is test data; **no backward compatibility** is required
- Go 1.26+, pgx/v5, sqlc, std lib `net/http`, `go-cmp`, `testcontainers-go` for integration tests
- No frameworks (chi, gin, echo, testify), no DDD, no mocks for DB
- Project conventions in `.claude/rules/` (forbidden directory names, package-by-feature, etc.)

### 1.3 What this document does NOT do

- Adopt the `a2asrv` server framework, `a2aclient`, `a2agrpc`, or any A2A wire transport (HTTP/JSON-RPC, gRPC, SSE, push notifications). The `a2a/` types package IS partially imported — see §16 for the precise scope.
- Introduce streaming events, push notifications, signed agent cards, multi-tenancy, or any feature whose only justification is a future scenario.
- Touch `journal` (renamed to `agent_notes`), `hypotheses` (renamed from `insights`), `tasks` (renamed to `todo_items`), or learning analytics tables beyond the renames.

---

## 2. Design Principles

These are binding for the architecture below. Any deviation requires an explicit override.

1. **Stable semantics over preserved names.** Rename when the new name better captures what the entity actually is, not for cosmetic reasons. Don't preserve a name solely because it exists today.
2. **Code explains itself.** Good naming + small focused functions. No multi-paragraph docstrings, no decoration comments.
3. **Don't implement for unverified scenarios.** Every state, ENUM value, capability flag, and Part variant must correspond to a real handler or call site that exists today. Add later when needed.
4. **DB layer owns its responsibilities.** Constraints, foreign keys, CHECK conditions are the database's job. Don't shift integrity guarantees to Go code.
5. **Type system as enforcement.** When something must not happen, encode it in the type system so the compiler refuses to let it happen — not as a runtime check, not as a code review item.
6. **Independent gates.** Critical invariants get multiple independent enforcement layers with non-overlapping failure modes.
7. **By-feature package layout.** No `coord/`, `core/`, `services/`, `dispatch/`, `harness/`. Types live in the feature package that uses them. Duplicate three lines before introducing a shared package.

---

## 3. Naming Decisions

All the following renames are **final** and apply consistently across schema, Go packages, types, MCP tool names, policy documentation, and code comments.

| Current | Target | Reasoning |
|---|---|---|
| `participant` (table + concept) | `agent` | A2A vocabulary alignment. The entities are agents (named actors with capabilities and schedules), not generic participants. |
| `participant_schedules` | (DROP table) | Schedule definitions move to Go literal in `internal/agent/registry.go`. `schedule_runs` audit log keeps existing columns with `schedule_id` retyped to TEXT. |
| `directives` (table + concept) | `tasks` | A2A `Task` is the canonical work unit concept. The §4 directive vs task litmus test in the policy doc is rewritten to use `task` for inter-agent work units and `todo_item` for personal todos — the two concepts remain distinct, only the labels change. |
| `reports` (table + concept) | `artifacts` | A2A `Artifact` captures "structured task output, separate from conversation messages". Reports were a narrow case of this. |
| `journal` (table + package) | `agent_notes` | Agent's internal narrative log, semantically precise. |
| `insights` (table + package) | `hypotheses` | The schema already has `hypothesis` and `invalidation_condition` columns. The entity IS a falsifiable hypothesis tracker. |
| `tasks` (current GTD personal table) | `todo_items` | Frees `tasks` for the inter-agent work unit. GTD model is preserved unchanged. |
| `task_status` ENUM (GTD) | `todo_state` | Renames with the table. Values stay GTD-shaped. |
| `'in-progress'` (in old GTD ENUM) | `'in_progress'` | Underscore convention for SQL ENUM values. |
| `harness` (concept, no current package) | `dispatch` (NOT a package) | "Dispatch" is the action; there is no separate package. Dispatch logic lives in `internal/agent/` next to the registry. |

**Vocabulary discipline**: in all human-readable text (policy docs, CLAUDE.md, code comments, build logs, conversation), the word "task" now refers to inter-agent work units. Personal todos are referred to as "todo items" or "todos". When ambiguous, use the qualified form "agent task" vs "personal todo".

---

## 4. Conceptual Model

Five core entities in the coordination layer:

1. **Agent** — A named actor with capabilities, an optional schedule, and a platform binding. Source of truth: Go literal `BuiltinAgents()` in `internal/agent/registry.go`. DB row: projection only.
2. **Task** — A work unit assigned from one agent (source) to another (target). Has an explicit lifecycle state. Replaces `directives`.
3. **Message** — An immutable conversation turn within a task. Has a role (`request` or `response`) and ordered position. Multi-part content. Replaces `directives.content`.
4. **Part** — A typed content fragment within a message or artifact. Sealed union: `text` or `data`. Two variants are sufficient today.
5. **Artifact** — A structured deliverable produced by the target agent, separate from conversation messages. Replaces `reports`. Multi-part content, same Part type as messages.

Three entities **outside** the coordination layer that are renamed but not restructured:

- **AgentNote** (was `journal`) — agent-private narrative log, not IPC
- **Hypothesis** (was `insight`) — falsifiable hypothesis tracker, not IPC
- **TodoItem** (was `tasks`) — personal GTD item, not IPC

### 4.1 Task lifecycle

```
       ┌─────────┐    accept     ┌─────────┐   complete   ┌───────────┐
       │submitted│──────────────▶│ working │─────────────▶│ completed │
       └─────────┘               └─────────┘              └───────────┘
            │                         │
            │ cancel                  │ cancel
            ▼                         ▼
       ┌──────────┐              ┌──────────┐
       │ canceled │              │ canceled │
       └──────────┘              └──────────┘
```

Four states. Linear, no cycles. `failed` / `rejected` / `input_required` / `auth_required` are intentionally not present — there is no current handler that produces them. They can be added as ENUM values later via linear migration without restructuring.

### 4.2 Message structure

A task has 0..N messages, ordered by `position`. Each message has exactly one role:
- `request` — message from source agent to target agent
- `response` — message from target agent back to source agent

A task in `completed` state must have at least one response message AND at least one artifact (this is the resolution invariant; enforced via Go-side transition function, not DB CHECK).

### 4.3 Artifact structure

A task has 0..N artifacts. Each artifact belongs to exactly one task. Artifacts are produced by the target agent during or after task work. Artifacts are not message-shaped — they are structured outputs whose lifetime is independent of the conversation.

The distinction matters for future use cases (Claude Cowork document storage, file deliverables) where the deliverable is conceptually distinct from the conversation about it.

---

## 5. Go Package Layout

```
internal/
  agent/                       ← agent registry + capability + dispatch
    agent.go                   ← Agent struct, Capability, Schedule, Action types
    registry.go                ← BuiltinAgents() Go literal, Registry, Lookup
    authorize.go               ← Authorized wrapper type, Authorize() function
    sync.go                    ← startup-time sync to agents table
    agent_test.go

  task/                        ← coordination work unit
    task.go                    ← Task, State, sentinel errors
    summary.go                 ← TaskSummary (read-only projection)
    handler.go                 ← MCP handler closures
    store.go                   ← pgx CRUD
    query.sql                  ← sqlc queries
    task_test.go

  message/                     ← multi-turn conversation envelope
    message.go                 ← Message, Role (Parts is []*a2a.Part)
    message_test.go

  artifact/                    ← structured task outputs
    artifact.go                ← Artifact, ArtifactSummary
    store.go                   ← pgx CRUD
    query.sql
    artifact_test.go

  agent_note/                  ← was journal — UNCHANGED beyond rename
  hypothesis/                  ← was insight — UNCHANGED beyond rename
  todo/                        ← was task (GTD) — UNCHANGED beyond rename
  session/                     ← learning sessions — UNCHANGED
  attempt/                     ← learning attempts — UNCHANGED

  mcp/                         ← MCP handler dispatch
    handler.go                 ← calls agent.Authorize, then task/artifact stores
```

**No** `internal/coord/`, `internal/dispatch/`, `internal/harness/`, `internal/ipc/`, `internal/messaging/`, `internal/agents/` (plural). All would be layer/generic names violating `package-organization.md`.

**Justification for splitting `task`, `message`, `artifact` into separate packages**: each represents a distinct entity with its own table, its own store methods, its own test file. They are not three layers of the same concept; they are three coordinated entities. By-feature is satisfied.

`message` package has no DB store of its own — messages are stored via the `task` package's store (which writes both `tasks` and `task_messages` rows in a transaction). The `message` package only declares the `Message` struct and its `Role` enum. The `Part` sealed union and its `Text` / `Data` variants come from `github.com/a2aproject/a2a-go/v2/a2a` — see §16 for the precise rationale and scope of that import.

---

## 6. PostgreSQL Schema

### 6.1 ENUM types

```sql
CREATE TYPE agent_status AS ENUM ('active', 'retired');

CREATE TYPE task_state AS ENUM (
    'submitted',  -- created, target not yet acknowledged
    'working',    -- target accepted, work in flight
    'completed',  -- response artifact delivered
    'canceled'    -- source canceled before completion
);

CREATE TYPE message_role AS ENUM ('request', 'response');

-- No part_kind ENUM. Parts are stored as a JSONB array on task_messages/artifacts;
-- the kind discriminator lives inside each JSON object (a2a.Part flattened format).

CREATE TYPE agent_note_kind AS ENUM ('plan', 'context', 'reflection');

CREATE TYPE todo_state AS ENUM ('inbox', 'todo', 'in_progress', 'done', 'someday');

CREATE TYPE hypothesis_state AS ENUM ('unverified', 'verified', 'invalidated', 'archived');
```

### 6.2 `agents` table

```sql
CREATE TABLE agents (
    name         TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    platform     TEXT NOT NULL,
    description  TEXT,
    status       agent_status NOT NULL DEFAULT 'active',
    synced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at   TIMESTAMPTZ,

    CONSTRAINT chk_status_retired CHECK (
        (status = 'active'  AND retired_at IS NULL) OR
        (status = 'retired' AND retired_at IS NOT NULL)
    )
);
```

**No capability columns.** Capabilities live in the Go registry. The DB row exists only as a foreign key target for `tasks.source` / `tasks.target` and an audit projection of "what agents the system has known about". Hard delete is forbidden (FK RESTRICT); removed agents become `status = 'retired'`.

### 6.3 `tasks` table

```sql
CREATE TABLE tasks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source       TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    target       TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    title        TEXT NOT NULL,
    state        task_state NOT NULL DEFAULT 'submitted',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    canceled_at  TIMESTAMPTZ,
    metadata     JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT chk_state_timestamps CHECK (
        (state = 'submitted' AND accepted_at IS NULL     AND completed_at IS NULL AND canceled_at IS NULL) OR
        (state = 'working'   AND accepted_at IS NOT NULL AND completed_at IS NULL AND canceled_at IS NULL) OR
        (state = 'completed' AND accepted_at IS NOT NULL AND completed_at IS NOT NULL AND canceled_at IS NULL) OR
        (state = 'canceled'  AND canceled_at IS NOT NULL AND completed_at IS NULL)
    )
);

CREATE INDEX idx_tasks_target_open
    ON tasks (target, submitted_at DESC)
    WHERE state IN ('submitted', 'working');

CREATE INDEX idx_tasks_source_open
    ON tasks (source, submitted_at DESC)
    WHERE state IN ('submitted', 'working');
```

The `chk_state_timestamps` constraint makes illegal state combinations physically impossible. Any code path (Go, SQL, manual psql) that tries to set `state = 'completed'` without `accepted_at` will fail at the DB layer.

### 6.4 `task_messages` table

```sql
CREATE TABLE task_messages (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id    UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    role       message_role NOT NULL,
    position   INTEGER NOT NULL,
    parts      JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (task_id, position),

    CONSTRAINT chk_parts_count CHECK (
        jsonb_array_length(parts) BETWEEN 1 AND 16
    ),
    CONSTRAINT chk_parts_total_size CHECK (
        pg_column_size(parts) <= 32768
    )
);

CREATE INDEX idx_task_messages_task ON task_messages (task_id, position);
```

**Two CHECK constraints** are the structural bloat prevention:
- `chk_parts_count` bounds the number of parts to 16 — prevents fragmentation attacks
- `chk_parts_total_size` bounds total payload to 32 KB — prevents single-large-part attacks

Together they create an implicit "conversation vs deliverable" split: anything larger than 32 KB structurally cannot live in a message and must go to an artifact.

**JSONB shape inside `parts`**: each element is an `a2a.Part` value serialised by `a2a-go`'s `MarshalJSON` (the protocol's flattened form, e.g. `{"text": "..."}` for a text part, `{"data": {...}}` for a data part). The Go layer never hand-rolls this format — it is produced and consumed by `a2a-go`. See §16 for why this delegation is the partial-import boundary.

### 6.5 `artifacts` table

```sql
CREATE TABLE artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id     UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    parts       JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_artifact_parts_count CHECK (
        jsonb_array_length(parts) BETWEEN 1 AND 32
    ),
    CONSTRAINT chk_artifact_parts_total_size CHECK (
        pg_column_size(parts) <= 262144
    )
);

CREATE INDEX idx_artifacts_task ON artifacts (task_id, created_at);
```

Artifacts have **looser size bounds** than messages: 32 parts max, 256 KB total. This intentionally encodes "artifacts are bigger than messages" — a research report or document deliverable can be 100 KB without being abuse, but a conversation message that big is bloat.

### 6.6 `agent_schedule_runs` table (audit log)

```sql
-- The participant_schedules table is DROPPED.
-- Schedule definitions live in BuiltinAgents() Go literal.
-- Only the run audit log persists.

ALTER TABLE schedule_runs RENAME TO agent_schedule_runs;
ALTER TABLE agent_schedule_runs DROP CONSTRAINT IF EXISTS schedule_runs_schedule_id_fkey;
ALTER TABLE agent_schedule_runs ALTER COLUMN schedule_id TYPE TEXT;
ALTER TABLE agent_schedule_runs RENAME COLUMN schedule_id TO schedule_name;

-- schedule_name now references "<agent_name>:<schedule_name>" string in registry,
-- validated at Go layer (no FK).
```

### 6.7 Renamed-only tables

These tables are renamed but otherwise unchanged. ENUM types are renamed accordingly.

```sql
-- journal → agent_notes
ALTER TABLE journal RENAME TO agent_notes;
ALTER TYPE journal_kind RENAME TO agent_note_kind;
-- Drop 'metrics' value (no current writer)
-- Note: PostgreSQL doesn't support DROP VALUE; recreate the type:
ALTER TYPE agent_note_kind RENAME TO agent_note_kind_old;
CREATE TYPE agent_note_kind AS ENUM ('plan', 'context', 'reflection');
ALTER TABLE agent_notes ALTER COLUMN kind TYPE agent_note_kind USING kind::text::agent_note_kind;
DROP TYPE agent_note_kind_old;

-- insights → hypotheses
ALTER TABLE insights RENAME TO hypotheses;

-- tasks (GTD) → todo_items
ALTER TABLE tasks RENAME TO todo_items;
ALTER TYPE task_status RENAME TO todo_state_old;
CREATE TYPE todo_state AS ENUM ('inbox', 'todo', 'in_progress', 'done', 'someday');
-- Note: 'in-progress' → 'in_progress' (underscore convention)
ALTER TABLE todo_items
    ALTER COLUMN status TYPE todo_state
    USING (CASE status::text WHEN 'in-progress' THEN 'in_progress' ELSE status::text END)::todo_state;
ALTER TABLE todo_items RENAME COLUMN status TO state;
DROP TYPE todo_state_old;
```

These renames must happen BEFORE the `tasks` (coordination) table is created, because the new `tasks` table reuses the name. Migration ordering matters.

---

## 7. Go Types

### 7.1 `internal/agent/agent.go`

```go
package agent

import "time"

type Name string

type Capability struct {
    SubmitTasks      bool
    ReceiveTasks     bool
    PublishArtifacts bool
}

type Schedule struct {
    Trigger TriggerKind
    Expr    string
    Backend string
}

type TriggerKind string

const (
    TriggerNone   TriggerKind = ""
    TriggerCron   TriggerKind = "cron"
    TriggerManual TriggerKind = "manual"
)

type Agent struct {
    Name        Name
    DisplayName string
    Platform    string
    Description string
    Capability  Capability
    Schedule    Schedule
}
```

No `AgentCard` type. No `ToCard()` / `AsCard()` method. The `Agent` struct IS the complete agent description.

### 7.2 `internal/agent/registry.go`

```go
package agent

func BuiltinAgents() []Agent {
    return []Agent{
        {
            Name:        "hq",
            DisplayName: "Studio HQ",
            Platform:    "claude-cowork",
            Description: "CEO, decisions, delegation",
            Capability: Capability{
                SubmitTasks:      true,
                PublishArtifacts: true,
            },
        },
        {
            Name:        "research-lab",
            DisplayName: "Research Lab",
            Platform:    "claude-cowork",
            Capability: Capability{
                ReceiveTasks:     true,
                PublishArtifacts: true,
            },
        },
        // ... 6 more entries for content-studio, learning-studio,
        //     koopa0.dev, go-spec, claude, human
    }
}

type Registry struct {
    byName map[Name]Agent
}

func NewRegistry(agents []Agent) *Registry {
    byName := make(map[Name]Agent, len(agents))
    for _, a := range agents {
        byName[a.Name] = a
    }
    return &Registry{byName: byName}
}

func (r *Registry) Lookup(name Name) (Agent, bool) {
    a, ok := r.byName[name]
    return a, ok
}

func (r *Registry) All() []Agent {
    out := make([]Agent, 0, len(r.byName))
    for _, a := range r.byName {
        out = append(out, a)
    }
    return out
}
```

### 7.3 `internal/agent/authorize.go`

```go
package agent

import (
    "context"
    "errors"
    "fmt"
)

var (
    ErrUnknownAgent = errors.New("unknown agent")
    ErrForbidden    = errors.New("agent lacks capability")
)

type Action string

const (
    ActionSubmitTask      Action = "submit_task"
    ActionAcceptTask      Action = "accept_task"
    ActionPublishArtifact Action = "publish_artifact"
    ActionCancelTask      Action = "cancel_task"
)

func (c Capability) Allows(action Action) bool {
    switch action {
    case ActionSubmitTask, ActionCancelTask:
        return c.SubmitTasks
    case ActionAcceptTask:
        return c.ReceiveTasks
    case ActionPublishArtifact:
        return c.PublishArtifacts
    }
    return false
}

// Authorized is a compile-time proof of capability.
// External packages cannot construct this struct because the fields are unexported.
// The only construction path is Authorize().
type Authorized struct {
    caller Name
    action Action
}

func (a Authorized) Caller() Name   { return a.caller }
func (a Authorized) Action() Action { return a.action }

func Authorize(ctx context.Context, r *Registry, caller Name, action Action) (Authorized, error) {
    a, ok := r.Lookup(caller)
    if !ok {
        return Authorized{}, ErrUnknownAgent
    }
    if a.Status() == StatusRetired {
        return Authorized{}, fmt.Errorf("%w: %s is retired", ErrForbidden, caller)
    }
    if !a.Capability.Allows(action) {
        return Authorized{}, fmt.Errorf("%w: %s cannot %s", ErrForbidden, caller, action)
    }
    return Authorized{caller: caller, action: action}, nil
}
```

### 7.4 `internal/task/task.go`

```go
package task

import (
    "time"

    "github.com/google/uuid"

    "github.com/koopa0/koopa0.dev/internal/agent"
    "github.com/koopa0/koopa0.dev/internal/message"
)

type State string

const (
    StateSubmitted State = "submitted"
    StateWorking   State = "working"
    StateCompleted State = "completed"
    StateCanceled  State = "canceled"
)

type Task struct {
    ID          uuid.UUID
    Source      agent.Name
    Target      agent.Name
    Title       string
    State       State
    SubmittedAt time.Time
    AcceptedAt  *time.Time
    CompletedAt *time.Time
    CanceledAt  *time.Time
    Metadata    map[string]any
    // Messages and Artifacts populated only by Load(), never by Summarize()
    Messages  []message.Message
    Artifacts []artifact.Artifact
}
```

### 7.5 `internal/task/summary.go`

```go
package task

import (
    "time"

    "github.com/google/uuid"

    "github.com/koopa0/koopa0.dev/internal/agent"
)

// TaskSummary deliberately has NO Messages / Artifacts / parts fields.
// It is impossible to leak full content into a summary path because the type
// system does not allow it — DirectiveSummary{Messages: ...} fails to compile.
type TaskSummary struct {
    ID          uuid.UUID
    Source      agent.Name
    Target      agent.Name
    Title       string
    State       State
    SubmittedAt time.Time
}
```

### 7.6 `internal/message/message.go`

```go
package message

import (
    "time"

    "github.com/google/uuid"

    a2a "github.com/a2aproject/a2a-go/v2/a2a"
)

type Role string

const (
    RoleRequest  Role = "request"
    RoleResponse Role = "response"
)

// Message is a single turn in a task's request/response conversation.
//
// Parts uses a2a-go's sealed Part union directly. We borrow the type
// (not the SDK's task/agent types) because:
//   - Part is genuinely transport-agnostic and stable in the upstream
//   - Its sealed-union JSON marshalling is non-trivial (~50 lines) and
//     a2a-go already implements it correctly
//   - Borrowing only Part keeps the koopa-side Message / Task / Agent
//     types free to follow our access patterns
//
// See §16 for the full rationale and the audit of every other a2a type
// we deliberately did NOT import.
type Message struct {
    ID        uuid.UUID
    Role      Role
    Position  int
    Parts     []*a2a.Part
    CreatedAt time.Time
}
```

Construction at call sites:

```go
import a2a "github.com/a2aproject/a2a-go/v2/a2a"

msg := message.Message{
    Role: message.RoleRequest,
    Parts: []*a2a.Part{
        a2a.NewTextPart("research NATS exactly-once semantics"),
        a2a.NewDataPart(map[string]any{
            "deadline": "2026-04-20",
            "priority": "high",
        }),
    },
}
```

There is no `internal/message/part.go`, no koopa-defined `Part` interface, no koopa-defined `MarshalParts` / `UnmarshalParts`. The `a2a-go` package provides them all. The `internal/message/` package's only contribution is the `Message` envelope and the `Role` enum — both of which use koopa-native naming (`request` / `response`, not A2A's `ROLE_USER` / `ROLE_AGENT`).

### 7.7 `internal/task/store.go` (API shape)

```go
package task

import (
    "context"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"

    a2a "github.com/a2aproject/a2a-go/v2/a2a"

    "github.com/koopa0/koopa0.dev/internal/agent"
    "github.com/koopa0/koopa0.dev/internal/artifact"
)

type Store struct {
    pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
    return &Store{pool: pool}
}

// Read methods — Summarize and Load are deliberately separate.
// There is no SummarizeOptions{IncludeMessages bool}. Options-on-read is
// the API shape that allowed the original morning_context bloat.

func (s *Store) Summarize(ctx context.Context, target agent.Name) ([]TaskSummary, error)
func (s *Store) Load(ctx context.Context, id uuid.UUID) (*Task, error)

// Mutations — all require Authorized. The compiler refuses to call these
// without first going through agent.Authorize().

type SubmitInput struct {
    Source  agent.Name
    Target  agent.Name
    Title   string
    Request []*a2a.Part
}

func (s *Store) Submit(ctx context.Context, auth agent.Authorized, in SubmitInput) (*Task, error)
func (s *Store) Accept(ctx context.Context, auth agent.Authorized, id uuid.UUID) error
func (s *Store) Complete(ctx context.Context, auth agent.Authorized, id uuid.UUID, response []*a2a.Part, art artifact.Input) (*Task, error)
func (s *Store) Cancel(ctx context.Context, auth agent.Authorized, id uuid.UUID, reason string) error
```

The `Authorized` parameter is the wrapper type from `internal/agent/authorize.go`. Its fields are unexported, so external packages cannot literal-construct it. The only path to obtaining one is `agent.Authorize(ctx, registry, caller, action)`, which performs the capability check. Therefore:

> Any MCP handler that wants to call `task.Store.Submit` MUST first call `agent.Authorize`. The compiler enforces this. Forgetting the check is impossible.

---

## 8. MCP Handler Pattern

```go
// internal/mcp/handler.go

import (
    a2a "github.com/a2aproject/a2a-go/v2/a2a"

    "github.com/koopa0/koopa0.dev/internal/agent"
    "github.com/koopa0/koopa0.dev/internal/task"
)

func (s *Server) handleSubmitTask(ctx context.Context, req mcp.Request) (mcp.Response, error) {
    auth, err := agent.Authorize(ctx, s.registry, req.As, agent.ActionSubmitTask)
    if err != nil {
        return nil, err  // wraps ErrUnknownAgent or ErrForbidden
    }

    t, err := s.tasks.Submit(ctx, auth, task.SubmitInput{
        Source:  req.As,
        Target:  req.Target,
        Title:   req.Title,
        Request: []*a2a.Part{a2a.NewTextPart(req.Body)},
    })
    if err != nil {
        return nil, err
    }

    return mcp.OK(task.SummarizeOne(t)), nil
}
```

Pattern: every handler's first non-context operation is `agent.Authorize`. The returned `Authorized` value is the only way to call mutation methods on `task.Store` or `artifact.Store`.

---

## 9. Read-Side Bloat Prevention — Three Independent Gates

| Gate | Layer | Mechanism |
|---|---|---|
| **1. Type system** | Go compile time | `TaskSummary` struct has no `Messages`, `Artifacts`, or `parts` fields. `morning_context`'s output struct uses only `TaskSummary`. Attempting to put full content into the summary path fails compilation. |
| **2. Database** | PostgreSQL | `chk_parts_count` (≤16) + `chk_parts_total_size` (≤32 KB) on `task_messages.parts`. Any INSERT exceeding these is rejected by the DB. |
| **3. API contract** | Method signatures | `Summarize(ctx, target)` and `Load(ctx, id)` are two distinct methods with different return types. There is no `LoadOptions{IncludeMessages bool}`. To get details, the caller must explicitly call `Load` per task — friction by design. |

These three gates have non-overlapping failure modes. Bypassing one does not bypass the others. A future engineer (or AI) writing handler code cannot accidentally produce the original bloat shape.

---

## 10. Capability Enforcement — One Gate, Compile-Time

There is one mechanism: the `Authorized` wrapper type with unexported fields.

- Construction path: `agent.Authorize(ctx, registry, caller, action)`
- All mutation methods on `task.Store` and `artifact.Store` accept `Authorized` as a parameter
- External packages cannot literal-construct `Authorized{}` because the fields are unexported
- Therefore: handlers that bypass `Authorize` cannot compile

This is sufficient because:

1. The threat model is "future code (mine, AI-generated, or a contributor's) forgets the check"
2. The threat model is NOT "an adversary modifies the application binary" — single-user system, no adversary
3. The wrapper type catches the threat that exists and ignores the threat that doesn't

DB function approach (`REVOKE INSERT ... GRANT EXECUTE`) was considered and rejected — it adds significant SQL plumbing to defend against an adversary that does not exist.

---

## 11. Agent Lifecycle Workflows

### 11.1 Add an agent (current and near-term)

1. Edit `internal/agent/registry.go`, add an `Agent{...}` literal to `BuiltinAgents()`
2. If the agent uses a new capability or action, add the constant to `internal/agent/authorize.go`
3. If the agent needs new MCP handlers, write them
4. `go test ./internal/agent/... ./internal/task/...`
5. `go build ./... && /verify`
6. Restart the application
7. Startup sync upserts the new row into `agents` table

Total surface area: 1-3 Go files. No SQL migration, no YAML, no policy doc edit (capability validation is enforced by code, not policy).

### 11.2 Remove an agent

1. Delete the literal from `BuiltinAgents()`
2. Restart
3. Startup sync detects the missing entry and updates the DB row to `status = 'retired'`, sets `retired_at = now()`
4. Historical `tasks.source` / `tasks.target` references remain valid (FK RESTRICT)
5. The retired agent cannot pass `Authorize` (returns `ErrForbidden: ... is retired`)

### 11.3 Modify capability

1. Edit the `Capability{...}` field in the literal
2. Restart
3. Next `Authorize()` call reflects the new capability

### 11.4 Modify schedule

1. Edit the `Schedule{...}` field in the literal
2. Restart

### 11.5 Future evolution: when more is needed

**Scenario B — Claude Cowork becomes multi-user**: external operators define agents without Go compilation skills.

Evolution path (additive, non-breaking):
1. `BuiltinAgents()` becomes the "core" registry, unchanged
2. New function `LoadCustomAgents(ctx, source) ([]Agent, error)` loads from YAML / DB / API
3. `Registry` adds a `Merge(core, custom)` constructor
4. Custom agents still go through the same `Authorized` wrapper
5. Add `agent_customizations` table or admin UI as needed at that point

**Scenario C — Cross-process agent interop**: a second process or external A2A agent participates.

Evolution path:
1. Add `internal/agent/card.go` with `func (a Agent) ToA2ACard() a2a.AgentCard`
2. Expose `/.well-known/agent-card.json` HTTP endpoint
3. Begin importing `github.com/a2aproject/a2a-go/v2/a2a` at this point
4. Consider importing `a2asrv` for inbound RPC

**Critical**: today's design (Scenario A) does not lock out Scenarios B or C. The Go literal is the foundation that future evolution adds to, not replaces.

---

## 12. Migration Plan

Five stages. Each stage is independently shippable, has a verifiable acceptance condition, and is a permanent valid state. No throwaway abstractions, no dual-write, no phased rollouts. Test data only — destructive migrations are fine.

### Stage 1 — `internal/agent/` package + capability enforcement

**Estimated**: 4-6 hours

**Created**:
- `internal/agent/agent.go` — `Agent`, `Capability`, `Schedule`, `Name`, `TriggerKind`
- `internal/agent/registry.go` — `BuiltinAgents()` literal with 8 entries, `Registry`, `NewRegistry`, `Lookup`, `All`
- `internal/agent/authorize.go` — `Authorized` wrapper, `Action` constants, `Authorize()`, sentinels
- `internal/agent/sync.go` — `SyncToTable(ctx, registry, pool)` startup hook
- `internal/agent/agent_test.go` — unit tests for Authorize (success / unknown / forbidden / retired)
- `cmd/app/main.go` — call `agent.SyncToTable(ctx, registry, pool)` at startup

**Modified**:
- All MCP handlers currently using `participant.*` capability fields must call `agent.Authorize`
- `internal/mcp/ipc.go:44` — replace `p.CanWriteReports` check with `agent.Authorize(ctx, registry, caller, agent.ActionPublishArtifact)`
- `internal/mcp/commitment.go:335` — add `agent.Authorize(ctx, registry, caller, agent.ActionSubmitTask)` before `commitDirective`
- All other MCP handler entry points: same pattern

**Schema**:
- `ALTER TABLE participant RENAME TO agents`
- `ALTER TABLE agents ADD COLUMN status agent_status NOT NULL DEFAULT 'active'`
- `ALTER TABLE agents ADD COLUMN synced_at TIMESTAMPTZ NOT NULL DEFAULT now()`
- `ALTER TABLE agents ADD COLUMN retired_at TIMESTAMPTZ`
- `ALTER TABLE agents DROP COLUMN can_issue_directives, DROP COLUMN can_receive_directives, DROP COLUMN can_write_reports, DROP COLUMN task_assignable, DROP COLUMN can_own_schedules`
- `CREATE TYPE agent_status AS ENUM ('active', 'retired')`

**Acceptance**:
- `go test ./internal/agent/...` passes
- Adding a 9th agent requires editing only `BuiltinAgents()` and rebuilding
- Removing an agent flips `status` to `retired` after restart (verified via psql query)
- Calling any MCP handler with an unknown `as:` returns `ErrUnknownAgent` immediately
- Calling with insufficient capability returns `ErrForbidden` immediately
- `grep -r 'CanWriteReports\|CanIssueDirectives' internal/` returns zero hits outside `internal/agent/`

**Concerns addressed**: 3 (harness intuitiveness — single source of truth) + 4 (add/remove friction)

### Stage 2 — `internal/task/`, `internal/message/`, `internal/artifact/` packages + new schema

**Estimated**: 8-10 hours (largest stage)

**Schema** — migration `002_rebuild_coordination.up.sql`:
```sql
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS directives CASCADE;

ALTER TABLE journal RENAME TO agent_notes;
-- (kind ENUM rebuild as shown in §6.7)

ALTER TABLE insights RENAME TO hypotheses;

ALTER TABLE tasks RENAME TO todo_items;
-- (todo_state ENUM rebuild + 'in-progress' → 'in_progress' as shown in §6.7)

CREATE TYPE task_state AS ENUM ('submitted', 'working', 'completed', 'canceled');
CREATE TYPE message_role AS ENUM ('request', 'response');
-- No part_kind ENUM. Parts are stored as a JSONB array; the kind discriminator
-- lives inside each JSON object (a2a-go's flattened Part format).

CREATE TABLE tasks (...);          -- §6.3
CREATE TABLE task_messages (...);  -- §6.4
CREATE TABLE artifacts (...);      -- §6.5
CREATE INDEX ...;
```

**Created**:
- `internal/task/task.go`, `summary.go`, `store.go`, `query.sql`, `task_test.go`
- `internal/message/message.go`, `part.go`, `message_test.go`
- `internal/artifact/artifact.go`, `store.go`, `query.sql`, `artifact_test.go`
- testcontainers-go integration tests covering: full submit → accept → complete round trip; multi-part round trip; size-cap CHECK rejection; lifecycle CHECK rejection

**Modified / Removed**:
- Delete `internal/directive/`, `internal/report/` (if existed)
- Rename `internal/journal/` → `internal/agent_note/`
- Rename `internal/insight/` → `internal/hypothesis/`
- Rename `internal/task/` (old GTD) → `internal/todo/` BEFORE creating new `internal/task/`
- Update `internal/todo/` ENUM constant: `StatusInProgress` value `'in-progress'` → `'in_progress'`
- All references to old `task.Status` in existing code: replaced with `todo.State`

**Acceptance**:
- `go test -tags=integration ./internal/task/... ./internal/message/... ./internal/artifact/...` all green
- `grep 'content TEXT' migrations/` returns zero hits in coordination tables
- Inserting 17 parts into `task_messages.parts` is rejected by `chk_parts_count`
- Inserting `parts` exceeding 32 KB is rejected by `chk_parts_total_size`
- Setting `state = 'completed'` without `accepted_at` is rejected by `chk_state_timestamps`
- `TaskSummary` struct contains no fields with `Message`, `Part`, `Artifact`, or `[]byte` types (verified by code grep)
- `db-reviewer` and `go-reviewer` agents pass with no BLOCKING findings
- `review-code` (L2) passes with no CRITICAL/HIGH findings

**Concerns addressed**: 1 (IPC fragility — explicit state, bounded parts, structural invariants) + 2 (handoff bloat — first two gates installed)

### Stage 3 — MCP handler migration to `Authorized` wrapper

**Estimated**: 4-6 hours

**Modified**:
- All MCP handlers in `internal/mcp/` that currently touch coordination concepts:
  - `propose_commitment(directive)` → `submit_task`
  - `acknowledge_directive` → `accept_task`
  - `file_report` → `complete_task` (with artifact)
  - `cancel_directive` (if exists) → `cancel_task`
- Each handler's first non-context line: `auth, err := agent.Authorize(ctx, s.registry, req.As, agent.Action...)`
- All calls to old `directive.Store` / `report.Store` replaced with `task.Store` / `artifact.Store` calls
- Handler return values use `task.SummarizeOne` for individual responses

**Documentation update**:
- `.claude/rules/mcp-decision-policy.md` §11 (caller self-id) — update to reference `internal/agent/authorize.go` as the enforcement source
- `.claude/rules/mcp-decision-policy.md` §4 (directive vs task litmus test) — rewrite to use `task` for inter-agent and `todo` for personal
- Tool names in MCP: `propose_commitment(directive)` is a deprecated alias for `submit_task`; remove the alias once Stage 5 completes

**Acceptance**:
- `grep -r 'CanWriteReports\|CanIssueDirectives\|directive.Store' internal/mcp/` returns zero hits
- Manual end-to-end MCP flow: `submit_task` → `accept_task` → `complete_task` succeeds
- Manual end-to-end with wrong `as:` → immediate `ErrForbidden`
- All `internal/mcp/*.go` handlers have a `Authorize` call before any mutation
- `/verify` passes

**Concerns addressed**: 1 (capability enforcement is now compile-time, not runtime check)

### Stage 4 — `morning_context` projection rewrite

**Estimated**: 3-4 hours

**Modified**:
- `internal/mcp/morning.go:MorningContextOutput` rewritten:
  - 11 full-fidelity arrays → 11 summary arrays using `task.TaskSummary`, `agent_note.NoteSummary`, etc.
  - Add `MorningContextInput.Sections []string` (allowlist; default = all summaries, no content)
  - Add `MorningContextInput.Limit int` (per-section, default 10, hard cap 50)
- `internal/mcp/morning.go:fillTasks` (renamed from `fillDirectives`) — calls `task.Store.Summarize` only, never `Load`
- New MCP tool `get_task(id)` — calls `task.Store.Load` for callers that need detail
- New MCP tool `get_artifact(id)` — calls `artifact.Store.Load`
- Delete any code in `morning.go` that touches `parts`, `message`, `artifact` content directly

**Acceptance**:
- `MorningContextOutput` struct grep shows no `[]task.Task`, `[]message.Message`, `[]artifact.Artifact` fields — only `[]TaskSummary` etc.
- Integration test: build a task with 5 parts, call `morning_context`, assert the response JSON contains no `parts`, `text`, `body` keys
- `morning_context` default response byte size is at least 10× smaller than pre-Stage-2 baseline
- `get_task(id)` returns full content as expected
- Manual `morning_context` call from a real LLM session is usable in prompt context

**Concerns addressed**: 2 (handoff bloat — third gate, the API contract gate, is now installed)

### Stage 5 — Schedule consolidation + cleanup

**Estimated**: 3-4 hours

**Schema** — migration `003_drop_participant_schedules.up.sql`:
```sql
ALTER TABLE schedule_runs RENAME TO agent_schedule_runs;
ALTER TABLE agent_schedule_runs DROP CONSTRAINT IF EXISTS schedule_runs_schedule_id_fkey;
ALTER TABLE agent_schedule_runs ALTER COLUMN schedule_id TYPE TEXT;
ALTER TABLE agent_schedule_runs RENAME COLUMN schedule_id TO schedule_name;

DROP TABLE participant_schedules CASCADE;
```

**Created**:
- `internal/agent/schedule.go` — `Schedule` value type, `TriggerCron`, `TriggerManual`, `NoSchedule()` constructors
- Add `Schedule` literal to `Agent` entries in `BuiltinAgents()` for those that need it

**Modified**:
- `internal/harness/` (if exists) or wherever schedule dispatch lives — read schedules from `BuiltinAgents()` instead of `participant_schedules` table

**Documentation cleanup**:
- Audit `.claude/rules/mcp-decision-policy.md` for any remaining `participant`, `directive`, `report` references; replace
- Audit `.claude/rules/package-organization.md` for any examples using old names
- Audit all of `docs/` and `.claude/` for vocabulary consistency: `task` for inter-agent, `todo` for personal
- Audit `CLAUDE.md` and `frontend/CLAUDE.md` for vocabulary consistency
- Audit code comments and variable names for vocabulary consistency

**Acceptance**:
- `participant_schedules` table does not exist
- `agent_schedule_runs` records executions correctly
- Adding a scheduled agent requires editing only `BuiltinAgents()`
- `grep -r '\bparticipant\b' .` returns hits only in historical commit messages and migration comments (allowed)
- `grep -r 'directive\|directives' .claude/ docs/` returns zero hits in current rule files
- `/verify` passes

**Concerns addressed**: 3 (harness intuitiveness — schedule is now part of agent definition) + 4 (add/remove friction — final consolidation)

### Stage ordering and dependencies

```
Stage 1 ──┐
          ├──► Stage 2 ──► Stage 3 ──► Stage 4 ──► Stage 5
          │
(no other dependencies)
```

Stage 1 is independent and can be merged before Stage 2 begins. Stages 2-5 are linearly dependent. Total estimated effort: 22-30 hours, ~4 working days for one engineer.

---

## 13. Validation Against the Four Concerns

| Concern | Stage(s) | Acceptance criterion | Why structurally non-regressable |
|---|---|---|---|
| **1. IPC fragility** | 1 + 2 + 3 | (a) `task_state` ENUM replaces nullable timestamp encoding; (b) `chk_state_timestamps` CHECK enforces lifecycle consistency at DB layer; (c) `Authorized` wrapper enforces capability checks at compile time; (d) `chk_parts_count` and `chk_parts_total_size` bound message size at DB layer | DB CHECK + ENUM + compile-time wrapper are three independent layers. Even AI-generated handler code cannot bypass them. |
| **2. Handoff bloat** | 2 + 4 | (a) `TaskSummary` struct has no content fields → compile error if you try to put them in; (b) `chk_parts_count` ≤ 16 + `chk_parts_total_size` ≤ 32 KB; (c) `Summarize` and `Load` are two distinct methods, no `Options` parameter | Three independent gates (type system, DB CHECK, API contract) with non-overlapping failure modes. |
| **3. Harness intuitiveness** | 1 + 5 | (a) `BuiltinAgents()` is one Go file; (b) capability lookup is a pure function `Capability.Allows(action)`; (c) MCP dispatch is `request → response`, no event loop; (d) schedules live next to agent definitions | The "scattered across five locations" condition is structurally eliminated. There is no second place to look. |
| **4. Add/remove agent friction** | 1 | Adding = `BuiltinAgents()` literal addition + rebuild; removing = literal deletion + rebuild + automatic retire on next sync; modifying capability = field edit + rebuild | The modification surface is one Go literal. Every change goes through `go build` and code review. There is no second update path that could drift. |

---

## 14. What to Defer

| Item | Trigger condition |
|---|---|
| Import `a2a.Task`, `a2a.AgentCard`, `a2a.TaskState`, `a2a.Message` from `a2a-go` | A second process or external agent needs A2A wire interop AND the adapter cost outweighs maintaining koopa-native types. Until then these stay koopa-native — see §16 for the per-type rationale. |
| `/.well-known/agent-card.json` HTTP endpoint | A second process or external agent discovers koopa via A2A standard URL |
| `a2asrv` server framework | Inbound A2A RPC from a separate process |
| `a2aclient` outbound calls | Outbound A2A RPC to a separate process |
| Streaming / SSE / `iter.Seq2[a2a.Event, error]` | A single task run is expected to take longer than 10 seconds and needs intermediate progress visible |
| Push notifications | Multi-device or external webhook integration |
| Signed AgentCard | Multiple operators editing agent definitions, or multi-tenant deployment |
| Multi-tenancy / `tenant_id` columns | Multiple users on the same instance |
| `failed`, `rejected`, `input_required`, `auth_required` task states | A handler exists that produces this state |
| `system` message role | A real system-generated message use case appears |
| `FilePart`, `URLPart`, `RawPart` variants | A real file/URL/binary part use case appears |
| `metrics` agent_note kind | An AI participant exists that writes auto-summary metric snapshots |
| External object storage (S3 / R2 / MinIO) for artifacts | Single artifact regularly exceeds 256 KB or total artifact storage exceeds 2 GB |
| Concurrent / multi-worker dispatch | Single-worker dispatch causes user-perceptible wait times |
| YAML / DB-side custom agent definitions | Non-developer operators need to define agents (Scenario B) |

---

## 15. What to Never Implement

| Item | Reason |
|---|---|
| `internal/coord/`, `internal/dispatch/`, `internal/harness/`, `internal/ipc/`, `internal/messaging/`, `internal/agents/` (plural), or any other layer/generic-named package | Violates `package-organization.md`. Use feature names. |
| Any table named `coord_*`, `ipc_*`, `core_*` | Same reason. Use feature namespacing. |
| Re-introducing `content TEXT NOT NULL` in any coordination table | Would re-enable handoff bloat at the schema level. |
| Re-introducing nullable timestamp lifecycle encoding | Allows illegal state combinations in the DB. |
| `LoadOptions{IncludeMessages bool, IncludeArtifacts bool}` style API | Options-on-read is the bloat entry point. Use distinct `Summarize` and `Load` methods. |
| `task.Store` mutation methods that don't accept `Authorized` | Bypasses the compile-time capability gate. |
| Confusing A2A `AgentCapabilities` (feature flags: streaming/pushNotifications) with koopa `Capability` (permission flags: SubmitTasks/ReceiveTasks) | These are different concepts. Don't merge them. |
| `CanIssueDirectives` / `CanWriteReports` / etc. boolean columns on the `agents` table | The Go registry is the source of truth. Capabilities live in `Agent.Capability`, not in DB columns. |
| Mirroring `a2a-go` types into a koopa-side `internal/a2aproto/` package | Per-type decisions: `a2a.Part` is imported directly (§16), other a2a types are koopa-native re-implementations because their shape doesn't fit our access patterns. Mirroring an unmodified copy of any a2a type would combine the costs of both options without the benefits of either. |
| Direct-INSERT bypass of `task.Store.Submit` from inside another internal package | The store is the only legal entry. Bypassing means bypassing the `Authorized` check, which means the compiler should refuse. If you find a case where this seems necessary, the design is wrong. |
| Treating `agent_notes`, `hypotheses`, `todo_items`, or learning analytics tables as coordination layer entities | They are outside the coordination layer. Don't merge them. |

---

## 16. The `a2a-go` partial import — per-type audit

This section replaces the original blanket "don't import" position. After honest re-examination, the right answer is **partial import**: borrow the one a2a type whose shape genuinely matches our access pattern, and write koopa-native equivalents for the others where importing would cause real harm.

### 16.1 What is imported

**`github.com/a2aproject/a2a-go/v2/a2a` package, `a2a.Part` type only.**

That is the entire scope of the import. Concretely:
- `internal/message/Message.Parts` is `[]*a2a.Part`
- `internal/task/SubmitInput.Request` and `Complete(... response ...)` use `[]*a2a.Part`
- `internal/artifact` likewise stores `[]*a2a.Part`
- Construction at call sites uses `a2a.NewTextPart(...)` and `a2a.NewDataPart(...)`
- JSON serialisation of parts (in the `task_messages.parts` and `artifacts.parts` JSONB columns) goes through a2a-go's `MarshalJSON` / `UnmarshalJSON`

The transitive dependency cost is `github.com/google/uuid` plus stdlib. Nothing else is pulled in.

### 16.2 Per-type decisions and reasoning

| a2a type | Decision | Reasoning |
|---|---|---|
| **`a2a.Part`** | **IMPORT** | Genuinely transport-agnostic. The sealed union of `Text` / `Raw` / `Data` / `URL` variants is correct for any multi-part content system; the unused `Raw` and `URL` variants cost nothing at runtime. The custom `MarshalJSON` / `UnmarshalJSON` that flattens the variant into the parent JSON object is non-trivial (~50 lines correctly written) and a2a-go already implements it. Borrowing this saves real code, the type is stable upstream (one removed field across the whole package since v1.0 GA), and the JSON shape it produces is exactly the shape we want to store in our `parts JSONB` columns. **Net win.** |
| **`a2a.Task`** | **NO** — write `internal/task/Task` | `a2a.Task` embeds `History []*Message` and `Artifacts []*Artifact` as required fields on the struct. Our access pattern is "fetch task header from `tasks` row, optionally fetch messages and artifacts in separate queries." If `Task` had `History` as a member, our `TaskSummary` type — which deliberately has NO content fields so the type system blocks read-side bloat — would not exist as a distinct type. Importing `a2a.Task` would **break the type-system gate in §9**. This is structural, not cosmetic. |
| **`a2a.AgentCard`** | **NO** — write `internal/agent/Agent` | `a2a.AgentCard.SupportedInterfaces` is a required field describing transport endpoints; for in-process koopa it would always contain a synthetic `"in-process"` entry. `Signatures` and `SecurityRequirements` would always be empty. The struct is shaped for wire publication (signed cards served from `/.well-known/agent-card.json`); we don't publish anything. Worse: A2A's `AgentCapabilities` field is a **feature-flag block** (`streaming` / `pushNotifications` / `extendedAgentCard`), not a permission set. koopa's `Capability` (`SubmitTasks` / `ReceiveTasks` / `PublishArtifacts`) is permissions. Reusing `a2a.AgentCard` would force the conflation. |
| **`a2a.TaskState`** | **NO** — write `internal/task/State` | `a2a.TaskState` underlying values are protobuf-style uppercase strings: `"TASK_STATE_SUBMITTED"`, `"TASK_STATE_WORKING"`, etc. Adopting them would either force these strings into the SQL ENUM (violating decision 8a, lowercase ENUM values) or require a Go ↔ SQL string mapping at every boundary. Additionally, A2A defines 9 states and we use 4 — importing the type means the other 5 are visible at every `switch` site even though no handler produces them. |
| **`a2a.Message`** | **NO** — write `internal/message/Message` | `a2a.Message.Role` is `MessageRole` with values `"ROLE_USER"` / `"ROLE_AGENT"`. Our roles are `"request"` / `"response"`. The `ReferenceTasks`, `Extensions`, `MessageID` fields are wire-format concerns we don't have. The one field we'd want to inherit (`Parts`) is exactly the type we DO import (`a2a.Part`). Best of both: koopa-native `Message` struct holds `[]*a2a.Part`. |
| **`a2a.Artifact`** | **NO** — write `internal/artifact/Artifact` | Same shape mismatch as `a2a.Message` for the same reasons. The `Parts` field uses `[]*a2a.Part`, the wrapper is koopa-native. |
| **`a2asrv`** (server framework) | **NO** | Solves distribution: `RequestHandler` interface assumes incoming RPC, `AgentExecutor` returns `iter.Seq2[a2a.Event, error]` for streaming push, `TaskStore` interface assumes shared state across server instances, `eventqueue.Reader/Writer` split assumes producer/consumer in different goroutines. **None of these problems exist in koopa's in-process sequential dispatch.** This is the deepest architectural reason to reject anything beyond the types layer. |
| **`a2aclient`**, **`a2agrpc`**, push notification subsystem, SSE streaming | **NO** | Same reason as `a2asrv`: they solve the distribution problem we don't have. |

### 16.3 The principle behind the per-type split

The `a2a/` types package is genuinely transport-agnostic, but **transport-agnostic does not mean access-pattern-agnostic**. A2A's `Task` and `Message` and `AgentCard` were designed for a specific access pattern: agents communicate over a wire, the receiving party gets a complete object containing everything it needs to act, and the JSON shape on the wire matches the in-memory Go struct.

koopa's access pattern is the opposite: agents share a database, the receiving party fetches summary projections by default and loads details only on demand, and the in-memory Go struct shape is driven by the type system's bloat-prevention requirements rather than by wire serialisation needs.

`a2a.Part` survives both access patterns because it is small, leaf-level, and its JSON shape happens to be exactly the shape we want to store. The other types do not survive — they encode access-pattern assumptions that conflict with ours.

The honest version of "import or not" is therefore **leaf types yes, container types no**. This is what the implementation reflects.

### 16.4 What this implies for future evolution

If Scenario C (cross-process A2A interop) is triggered later:

1. The koopa-native `Task` struct gets a `func (t *Task) ToA2A() *a2a.Task` adapter that builds the embedded `History` and `Artifacts` fields from the separate DB queries
2. The koopa-native `Agent` struct gets a `func (a Agent) ToA2ACard() a2a.AgentCard` adapter that synthesises the `SupportedInterfaces` and security fields
3. The koopa-native `State` enum gets a `func (s State) ToA2A() a2a.TaskState` adapter
4. The koopa-native `MessageRole` gets a similar adapter
5. **The `Part` field needs no adapter** — it is already `[]*a2a.Part`

The adapter layer would be ~40 lines of Go. Today's design does not lock out Scenario C; it defers exactly the work that has no current value (writing adapters for non-existent consumers).

### 16.5 What is NOT a reason to avoid the import

For the record, the following are NOT reasons to refuse the partial import, despite appearing in earlier drafts of this analysis:

- "Upstream is fast-moving" — the changelog audit shows the `a2a/` types package is de facto stable since v1.0 GA. One field removed, one added. Release tags move weekly but the types package barely changes.
- "We don't need it today" — true but irrelevant. The question is whether importing would **harm** the current design, not whether the current design **needs** it. For `a2a.Part` the import is a strict simplification.
- "Adding a dependency is cost" — one import line, one transitive dep (`google/uuid` which we already use). Not zero, but small enough to be dwarfed by the ~50 lines of Part marshalling code we'd otherwise hand-roll and maintain.

The earlier blanket "don't import" position conflated these weak reasons with the genuine architectural reasons that apply only to the container types and the server framework. This section is the corrected, per-type position.

---

## 17. The single most important paragraph

The current coordination layer's four pains all share one root cause: there is no first-class "agent task" entity. `directives` and `reports` reinvent the envelope shape per table; `participant.can_*` flags are defended only by reviewer discipline; `morning_context` is built by hand-fanning seven stores into eleven arrays because there's no projection contract; agents are defined in five places because there's no single registry. This rebuild creates that first-class entity (`tasks`/`task_messages`/`artifacts`), encodes the lifecycle in an explicit ENUM with DB CHECK constraints, makes capability checks impossible to forget via a compile-time `Authorized` wrapper type, prevents read-side bloat with three independent gates (type system + DB CHECK + API contract), and consolidates agent definitions into one Go literal. A2A is the conceptual source for the vocabulary and structural choices and is a **partial runtime dependency**: `a2a.Part` is imported directly because it is the one a2a leaf type whose shape matches our access pattern, while `a2a.Task` / `a2a.Message` / `a2a.AgentCard` and the server framework are not imported because their shapes encode wire-format and distribution assumptions that conflict with our in-process DB-row model — see §16 for the per-type audit. Five stages, ~4 working days, every stage a permanent valid state, no throwaway abstractions, no dual-write. Each of the four pains is mapped to a specific stage with a structural (not procedural) acceptance condition.
