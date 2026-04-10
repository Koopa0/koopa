# MCP Decision Policy — Essential Rules

Complete source: `.claude/rules/mcp-decision-policy.md`

## Intent Classification (evaluation order)

| # | Signal | Detection | Action |
|---|--------|-----------|--------|
| 1 | Question | "what", "show", "哪些", no imperative | Read-only query tool |
| 2 | Reference to existing entity | mentions task/project/goal by name | Transition/update existing entity |
| 3 | Active learning session | session with ended_at IS NULL | Route to learning lifecycle |
| 4 | Capture impulse | "add", "remind me", "記一下" | `capture_inbox` |
| 5 | Commitment intent | "create a goal", "plan", explicit structural language | `propose_commitment` |
| 6 | Coordination intent | "tell X to", "assign", "directive" | `propose_commitment(type=directive)` |
| 7 | Reflection intent | "how did today go", "反思" | `write_journal` or `track_insight` |
| 8 | Learning intent | "let's practice", "start a session" | `start_session` |

**First match wins.** Exception: active learning session (row 3) always takes priority.

## Semantic Maturity

| Level | Name | Indicators | Allowed |
|-------|------|-----------|---------|
| M0 | Vague | No outcome, exploratory | Stay in conversation — write NOTHING |
| M1 | Forming | Direction but missing specifics | `capture_inbox` only |
| M2 | Structured | Outcome + rough scope, missing fields | `propose_commitment` (AI fills defaults) |
| M3 | Actionable | Specific, time-bound, all fields | `propose_commitment` (fast path) |

**Uncertain between levels → pick lower.**

## Entity Creation Ownership

### Direct-commit allowed
- Task (inbox/todo) → `capture_inbox`
- Journal → `write_journal`
- Daily plan items → `plan_day`
- Learning session → `start_session`
- Attempt + high-confidence observations → `record_attempt`

### Always proposal-first
- Goal, Project, Milestone, Directive, Insight, Learning Plan → `propose_commitment` → `commit_proposal`

### Never via MCP
- Area, Participant → human/seed data only
- Review card → FSRS system-managed

## Directive vs Task

| Output is... | Entity | Why |
|--------------|--------|-----|
| A report (analysis, synthesis) | Directive | Target exercises judgment |
| A status change (done) | Task | Work is prescribed |

## Capture Pollution Prevention

| Input type | Route |
|-----------|-------|
| Concrete work item with clear done state | `capture_inbox` |
| Direction/aspiration without specifics | Stay in conversation (M0) |
| Decision record or reflection | `write_journal` |
| Falsifiable hypothesis | `propose_commitment(type=insight)` |

## Observation Confidence — label, not gate

**Every observation persists regardless of confidence.** Confidence is a column on `attempt_observations`, not a filter at write time. Dashboard `mastery` and `weaknesses` views accept `confidence_filter` (default `"high"`, opt-in `"all"`). A `< 3` filtered-observation floor in `deriveMasteryStage` prevents any single observation — including a low-confidence one — from permanently labelling a concept.

### Label `high`
- Concept already exists (or auto-creation is allowed per Concept Auto-Creation Boundary)
- Signal **directly evidenced** by behavior (user said it, outcome proves it)
- Category matches domain conventions

### Label `low`
- Signal is **inferred** (coach diagnosed it, user didn't demonstrate directly)
- Concept needs auto-creation AND the signal is itself inferred
- Severity assessment is uncertain

Do NOT skip recording a low-confidence observation — it persists for future analysis and is excluded from default reads. The old `pending_observations` roundtrip is removed; there is nothing to "confirm later."
