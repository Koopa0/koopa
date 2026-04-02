# Design Doc: Participant Capabilities & Schedules

**Date**: 2026-04-03
**Status**: Reviewed — incorporating feedback
**Prerequisite**: Schema v2 (signed off 2026-04-02)

---

## Context

Schema v2 established `platform → participant` as the identity model. Currently, routing rules (who can issue/receive directives, who can write reports) are enforced by Go validation checking `participant.platform = 'claude-cowork'`. This hard-codes platform identity into business rules.

This doc promotes two changes:

1. **Capability flags on participant** — routing rules become data, not code
2. **`participant_schedules` table** — schedules are participant-owned standing instructions

---

## What We're Locking In (一級語意)

### 1. Participant is the canonical actor

All routing, assignment, and scheduling happens at the participant level. Platform is execution context, not routing identity.

### 2. Capability model replaces platform hard-code

Participant capabilities determine what each actor can do:

| Capability               | Meaning                                                 |
| ------------------------ | ------------------------------------------------------- |
| `can_issue_directives`   | Can create directives targeting other participants      |
| `can_receive_directives` | Can be targeted by directives                           |
| `can_write_reports`      | Can create reports (directive-driven or self-initiated) |
| `task_assignable`        | Can be assigned as `tasks.assignee`                     |
| `can_own_schedules`      | Can have recurring scheduled sessions                   |

Go validation changes from:

```go
// OLD — platform hard-code
if targetParticipant.Platform != "claude-cowork" {
    return fmt.Errorf("target must be on claude-cowork platform")
}

// NEW — capability check
if !targetParticipant.CanReceiveDirectives {
    return fmt.Errorf("participant %s cannot receive directives", target)
}
```

### 3. Schedule is a participant-owned domain object

Not speculative — these are known, already-described requirements:

| Participant          | Schedule                                              | Described in                                             |
| -------------------- | ----------------------------------------------------- | -------------------------------------------------------- |
| HQ                   | Morning briefing (daily)                              | `docs/Koopa-HQ.md` §晨間 Briefing 流程                   |
| Content Studio       | Pipeline check + RSS scan                             | `docs/Koopa-Content-Studio.md` §你自己的 Scheduled Tasks |
| Research Lab         | Industry trend scan (weekly)                          | `docs/Koopa-Research-Lab.md` §你自己的 Scheduled Tasks   |
| Learning Studio      | (manual, not scheduled)                               | `docs/Koopa-Learning.md`                                 |
| Claude Code projects | Potential: backlog triage, health check, report to HQ | Future                                                   |

---

## What We're NOT Locking In (二級策略)

| Deferred                                              | Why                                                                               |
| ----------------------------------------------------- | --------------------------------------------------------------------------------- |
| Pair-specific routing (`A can directive B but not C`) | Current rules are participant-level capabilities, not pair matrix                 |
| Fixed SOP for directive/report flow                   | Who issues, who receives = capability config, not schema invariant                |
| execution_backend behavior parity                     | Backends have different capabilities — define interface, don't assume homogeneity |
| Automatic dispatch / scheduler daemon                 | Short term: platform-native schedule. Long term: koopa-owned scheduler            |

---

## Schema: `participant` capability columns

```sql
ALTER TABLE participant ADD COLUMN can_issue_directives   BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE participant ADD COLUMN can_receive_directives  BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE participant ADD COLUMN can_write_reports       BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE participant ADD COLUMN task_assignable       BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE participant ADD COLUMN can_own_schedules       BOOLEAN NOT NULL DEFAULT false;
```

### Seed values

| participant     | platform      | issue_dir | recv_dir | write_rep | task_assignable | own_sched |
| --------------- | ------------- | --------- | -------- | --------- | --------- | --------- |
| hq              | claude-cowork | ✅        | ❌       | ✅        | ✅        | ✅        |
| content-studio  | claude-cowork | ✅        | ✅       | ✅        | ✅        | ✅        |
| research-lab    | claude-cowork | ✅        | ✅       | ✅        | ✅        | ✅        |
| learning-studio | claude-cowork | ❌        | ✅       | ✅        | ✅        | ❌        |
| koopa0.dev      | claude-code   | ❌        | ❌       | ❌        | ✅        | ✅        |
| go-spec         | claude-code   | ❌        | ❌       | ❌        | ✅        | ❌        |
| claude          | claude-web    | ❌        | ❌       | ❌        | ❌        | ❌        |
| human           | human         | ❌        | ❌       | ❌        | ❌        | ❌        |

**Design notes:**

- HQ `can_receive_directives = false` — HQ dispatches, doesn't receive. If cross-department directives emerge (content-studio → research-lab), both already have `can_issue` + `can_receive`.
- `learning-studio` `can_issue_directives = false` — learning is interactive coaching, not a coordinator.
- `learning-studio` `can_own_schedules = false` — learning sessions are manual, not scheduled.
- `koopa0.dev` `can_own_schedules = true` — future: backlog triage, health checks.
- `claude` and `human` have no capabilities — they interact directly, not through the IPC protocol.

### COMMENT

```sql
COMMENT ON COLUMN participant.can_issue_directives IS 'Whether this participant can create directives. Go validation checks this flag, not platform name.';

-- Also update participant.platform COMMENT:
COMMENT ON COLUMN participant.platform IS 'Execution context (claude-cowork, claude-code, claude-web, human). Informational — routing and capability decisions are driven by capability flags, not platform name.';
COMMENT ON COLUMN participant.can_receive_directives IS 'Whether this participant can be targeted by directives. Go validation checks this instead of platform name.';
COMMENT ON COLUMN participant.can_write_reports IS 'Whether this participant can create reports (directive-driven or self-initiated).';
COMMENT ON COLUMN participant.task_assignable IS 'Whether this participant can be assigned as tasks.assignee.';
COMMENT ON COLUMN participant.can_own_schedules IS 'Whether this participant can have entries in participant_schedules.';
```

### Upgrade path to routing_policies

When pair-specific rules are needed (e.g. "content-studio can directive research-lab but not learning-studio"):

```sql
CREATE TABLE routing_policies (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_participant TEXT NOT NULL REFERENCES participant(name),
    target_participant TEXT NOT NULL REFERENCES participant(name),
    artifact_kind      TEXT NOT NULL CHECK (artifact_kind IN ('directive', 'report', 'task')),
    enabled            BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(source_participant, target_participant, artifact_kind)
);
```

Trigger condition: when boolean capabilities are insufficient to express a real routing need. Not before.

---

## Schema: `participant_schedules`

```sql
CREATE TABLE participant_schedules (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    participant           TEXT NOT NULL REFERENCES participant(name),
    name                  TEXT NOT NULL,
    purpose               TEXT NOT NULL,
    trigger_type          TEXT NOT NULL CHECK (trigger_type IN ('cron', 'interval', 'manual')),
    schedule_expr         TEXT,
    execution_backend     TEXT NOT NULL
                          CHECK (execution_backend IN (
                              'cowork_desktop',
                              'claude_code',
                              'github_actions',
                              'koopa_native'
                          )),
    instruction_template  TEXT NOT NULL,
    expected_outputs      TEXT[] NOT NULL DEFAULT '{}',
    missed_run_policy     TEXT NOT NULL DEFAULT 'skip'
                          CHECK (missed_run_policy IN ('skip', 'run_once_on_wake', 'queue_all')),
    enabled               BOOLEAN NOT NULL DEFAULT true,
    last_run_at           TIMESTAMPTZ,
    last_run_status       TEXT CHECK (last_run_status IN ('success', 'failure', 'skipped')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_cron_has_expr
        CHECK (trigger_type <> 'cron' OR schedule_expr IS NOT NULL),
    CONSTRAINT chk_interval_has_expr
        CHECK (trigger_type <> 'interval' OR schedule_expr IS NOT NULL),
    CONSTRAINT chk_manual_no_expr
        CHECK (trigger_type <> 'manual' OR schedule_expr IS NULL),
    UNIQUE (participant, name)
);
```

### COMMENTs

```sql
COMMENT ON TABLE participant_schedules IS 'Participant-owned standing instructions that spawn sessions on a recurring basis. Schedule defines WHAT and WHEN; execution_backend defines WHERE and HOW.';

COMMENT ON COLUMN participant_schedules.participant IS 'Owner. FK to participant. Go validates participant.can_own_schedules = true.';
COMMENT ON COLUMN participant_schedules.name IS 'Human-readable schedule name (e.g. Morning Briefing, RSS Pipeline Check).';
COMMENT ON COLUMN participant_schedules.purpose IS 'One-line description of what this schedule achieves.';
COMMENT ON COLUMN participant_schedules.trigger_type IS 'cron = fixed times (schedule_expr is cron expression). interval = recurring period. manual = only triggered by API/UI.';
COMMENT ON COLUMN participant_schedules.schedule_expr IS 'Cron expression for trigger_type=cron (e.g. "0 8 * * *"). Go time.Duration string for trigger_type=interval (e.g. "1h", "30m", "2h30m"). NULL for trigger_type=manual. Format validated by Go, not DB.';
COMMENT ON COLUMN participant_schedules.execution_backend IS 'Which runtime executes this schedule. Determines capabilities and constraints — see execution backend matrix below.';
COMMENT ON COLUMN participant_schedules.instruction_template IS 'Prompt/instructions for the spawned session. May reference MCP tools, participant instructions, etc.';
COMMENT ON COLUMN participant_schedules.expected_outputs IS 'Expected artifact types from each run. Convention: bare name = IPC table (directive, report, journal, insight); colon-separated = table:kind filter (journal:plan, journal:reflection). Monitoring validation is Go-side, not DB-enforced. If automated completeness checking is added, this column format becomes a contract.';
COMMENT ON COLUMN participant_schedules.missed_run_policy IS 'Normalized catch-up intent: skip = silently miss, run_once_on_wake = catch up with one run, queue_all = run all missed occurrences. Backend support may vary — Go execution layer maps unsupported combinations to actual runtime behavior.';
COMMENT ON COLUMN participant_schedules.last_run_at IS 'Denormalized from schedule_runs for quick lookup. NULL = never run.';
COMMENT ON COLUMN participant_schedules.last_run_status IS 'Denormalized from schedule_runs. NULL = never run.';
```

### Schedule run history

```sql
CREATE TABLE schedule_runs (
    id          BIGSERIAL PRIMARY KEY,
    schedule_id UUID NOT NULL REFERENCES participant_schedules(id) ON DELETE CASCADE,
    status      TEXT NOT NULL CHECK (status IN ('success', 'failure', 'skipped')),
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    error       TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE schedule_runs IS 'Append-only execution history for participant_schedules. Avoids the feeds.consecutive_failures pattern — full history from day one enables trend analysis, hit rate, and failure diagnosis.';
COMMENT ON COLUMN schedule_runs.status IS 'success = run completed without execution error. failure = errored. skipped = missed_run_policy decided to skip. Note: success does not guarantee expected_outputs were produced — output completeness is a separate monitoring concern.';
COMMENT ON COLUMN schedule_runs.error IS 'Error details on failure. NULL on success/skip.';
COMMENT ON COLUMN schedule_runs.metadata IS 'Run-specific data: produced artifact IDs, execution duration, backend-specific info.';

CREATE INDEX idx_schedule_runs_schedule ON schedule_runs (schedule_id, started_at DESC);
```

**Note:** `participant_schedules.last_run_at` / `last_run_status` are denormalized cache of the latest `schedule_runs` row. Avoids querying history for every schedule list view. Go must update both atomically.

### Cross-table invariant: can_own_schedules ↔ participant_schedules

```
INVARIANT: If participant.can_own_schedules is flipped from true → false,
all participant_schedules rows for that participant must be set to enabled = false.

Enforcement: Go layer — UpdateParticipant handler checks for this transition
and cascades the disable. Not a DB trigger (project rule: no triggers for business logic).

This is NOT enforced by DB constraints (cross-table CHECK impossible).
If violated: orphaned enabled schedules whose owner has lost capability.
Detection: SELECT ps.* FROM participant_schedules ps JOIN participant p ON ps.participant = p.name
           WHERE ps.enabled = true AND p.can_own_schedules = false;
```

### Execution backend capability matrix (documented, not schema-enforced)

| Backend          | Runs without local machine                  | Min interval                | Local file access      | MCP access      | Can push to GitHub |
| ---------------- | ------------------------------------------- | --------------------------- | ---------------------- | --------------- | ------------------ |
| `cowork_desktop` | ❌ (needs Desktop app + machine awake)      | ~1 min                      | ✅                     | ✅ (connectors) | ❌                 |
| `claude_code`    | Mixed — cloud subtask: ✅; desktop/loop: ❌ | cloud: 1h; desktop/loop: 1m | cloud: ❌; desktop: ✅ | ✅              | ✅                 |
| `github_actions` | ✅ (GitHub cloud)                           | per workflow                | ❌ (runner only)       | ❌              | ✅                 |
| `koopa_native`   | ✅ (koopa server)                           | any                         | ✅ (server-side)       | ✅ (built-in)   | depends            |

**This matrix is documentation, not schema.** Backend behavior differences are too nuanced for CHECK constraints. Go layer + documentation is the right enforcement level.

**Why `claude_code` is one value, not three:** Claude Code has cloud/desktop/loop execution modes, but they share the same participant and MCP tool surface. The mode distinction is an operational concern (where does it run), not a scheduling concern (what does it do). If mode-specific behavior (e.g. missed_run_policy differs between cloud and desktop) becomes important, split into `claude_code_cloud` / `claude_code_desktop` at that time.

### Seed schedule data (002_seed.up.sql)

```sql
-- Known schedules from Cowork project instructions
INSERT INTO participant_schedules (participant, name, purpose, trigger_type, schedule_expr, execution_backend, instruction_template, expected_outputs, missed_run_policy) VALUES
    ('hq', 'Morning Briefing', 'Daily briefing: tasks, projects, goals, insights, RSS highlights',
     'cron', '0 8 * * *', 'cowork_desktop',
     'Execute morning briefing flow: morning_context → produce briefing → write directives for departments',
     '{"directive", "journal:plan"}', 'run_once_on_wake'),

    ('hq', 'Weekly Review', 'Weekly summary and next-week planning',
     'cron', '0 17 * * 5', 'cowork_desktop',
     'Execute weekly review: weekly_summary → review department reports → write reflection + new directives',
     '{"directive", "journal:reflection"}', 'run_once_on_wake'),

    ('content-studio', 'Pipeline Check', 'Daily content pipeline health + RSS monitoring',
     'cron', '0 14 * * *', 'cowork_desktop',
     'Read directives → list_content_queue → rss_highlights → write report',
     '{"report"}', 'skip'),

    ('research-lab', 'Industry Scan', 'Weekly industry trend scanning',
     'cron', '0 9 * * 1', 'cowork_desktop',
     'Read directives → RSS + web search → produce industry trend report',
     '{"report"}', 'skip');
```

---

## COMMENT updates for directives/reports

Replace "Cowork-internal scope" with capability-driven language:

### directives TABLE COMMENT

```
Old: IPC — Cowork-internal coordination instructions. Scoped to claude-cowork platform only.
     For cross-platform work dispatch (e.g. HQ → Claude Code), use tasks.assignee instead.

New: IPC — coordination instructions between participants. Source must have can_issue_directives = true,
     target must have can_receive_directives = true (Go-validated).
     For work assignment to execution agents, use tasks.assignee.
```

### directives.source COMMENT

```
Old: Go layer validates source.platform = claude-cowork.

New: Go layer validates participant.can_issue_directives = true.
```

### directives.target COMMENT

```
Old: Go layer validates target.platform = claude-cowork. Cross-platform targets out of scope.

New: Go layer validates participant.can_receive_directives = true.
```

### reports.source COMMENT

```
Old: Currently limited to claude-cowork participants by Go validation. May expand if cross-platform
     reporting is needed.

New: Go layer validates participant.can_write_reports = true.
     Expandable by setting capability flag on any participant.
```

---

## Go impact summary

| Change                                                                            | Files                                                            |
| --------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `participant` struct: add 5 boolean fields                                        | `internal/platform/` (new package or existing)                   |
| Directive source validation: `platform == claude-cowork` → `can_issue_directives` | `internal/mcp/write.go` (or new `internal/directive/`)           |
| Directive target validation: same pattern                                         | same                                                             |
| Report source validation: same pattern                                            | same                                                             |
| Task assignee validation: check `task_assignable`                                 | `internal/mcp/write.go`                                          |
| Schedule CRUD: new store/handler                                                  | `internal/schedule/` (new package)                               |
| Schedule run recording                                                            | `internal/schedule/` — INSERT schedule*runs + UPDATE last_run*\* |
| New MCP tools: `list_schedules`, `schedule_detail`, maybe `trigger_schedule`      | `internal/mcp/server.go`                                         |

---

## Decision record

| Decision                       | Chose                                          | Rejected                               | Why                                                                                       |
| ------------------------------ | ---------------------------------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------- |
| Routing model                  | Capability flags on participant                | routing_policies table                 | Current rules are per-participant, not per-pair. Upgrade path documented.                 |
| Schedule ownership             | participant_schedules table                    | Platform-native only                   | Known requirements exist. Dashboard foundation needed.                                    |
| execution_backend              | TEXT CHECK enum                                | Separate backends table                | Fixed set of known backends. Backend capabilities documented, not schema-enforced.        |
| Backend capability enforcement | Documentation + Go validation                  | DB constraints                         | Nuances too complex for CHECK — min interval, file access, cloud/local differ per backend |
| missed_run_policy              | 3-value enum (skip/run_once/queue_all)         | Omit                                   | Platform-specific behavior mapped to normalized policy intent                             |
| Run history                    | schedule_runs table from day one               | last*run*\* columns only               | Avoid feeds.consecutive_failures pattern — full history enables trend analysis            |
| execution_backend granularity  | claude_code (merged)                           | claude_code_cloud/desktop/loop (split) | No current code path distinguishes modes. Split when needed — easier than rename          |
| can_receive_tasks naming       | `task_assignable`                              | `can_receive_tasks`                    | Precision over naming consistency — receive implies inbox semantics that tasks don't have |
| COMMENT style                  | Describe check semantics, not current snapshot | "Currently: Cowork departments"        | Snapshot descriptions expire. Semantic descriptions don't.                                |
