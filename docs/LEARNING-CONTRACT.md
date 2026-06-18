# Learning — Consumer Contract

> Scope: the learning subsystem records attempts and derives concept
> mastery from them. This document pins down what the signal means, who
> writes it, who reads it, and where the boundaries are. Read this before
> assuming a read value implies a write path.

## One signal: concept mastery

Every `record_attempt` call appends an attempt row and zero-or-more
observations. There is a single analytic axis:

| Layer | Scope | Answers |
|---|---|---|
| **Concept mastery** (`learning_attempt_observations`) | per `concept` (aggregated across targets) | "Which **patterns / skills / principles** do I understand vs still get wrong?" |

Mastery is per-concept, not per-target. Solving one LeetCode problem does
not by itself mark the concept "mastered"; mastery advances when multiple
observations across multiple targets accumulate for the same concept (see
the mastery floor in `internal/learning/mastery.go::DeriveMasteryStage`).

> **No FSRS / spaced-repetition layer.** There is no per-target FSRS
> retention layer (`review_cards` / `review_logs`) and no tool that reads
> one. `record_attempt` schedules no reviews, and there is no "due" /
> retention surface on the agent MCP. If spaced repetition is ever wanted,
> it comes back as a separate, explicitly-designed subsystem — not as an
> implicit side effect of recording an attempt.

## The agent learning surface — five tools

The whole learning lifecycle is reachable through five MCP tools:

| Tool | Writability | Role |
|---|---|---|
| `start_session` | additive | Begin a session (`domain` + `mode`); rejects if another session is active. |
| `record_attempt` | additive | Append an attempt + observations within the active session. |
| `end_session` | additive | End the active session; optional reflection text. |
| `learning_read(view=…)` | read-only | Analytics: `overview` / `next_target` / `attempts` / `session_progress`. |
| `manage_plan(action=…)` | destructive | Plan entry lifecycle: `add_entries` / `remove_entries` / `update_entry` / `reorder` / `progress`. |

`learning_read` is read-only forever. The richer admin-only learning views
(mastery / weaknesses / timeline / variations dashboard) live behind the
HTTP admin surface (`GET /api/admin/learning/dashboard` and siblings), not
on the agent MCP.

## `learning_read(view=…)` — what reads what

| View | Source | Keyed by |
|---|---|---|
| `overview` | recent `learning_sessions` (filter by domain + window_days) | session |
| `next_target` | weakness analysis joined with the untried-variation graph (`learning_target_relations`); requires the active `session_id` | target |
| `attempts` | `learning_attempts` + their `learning_attempt_observations` | target / concept / session |
| `session_progress` | in-session aggregate for the active session (attempt count, elapsed, distributions) | session |

`next_target` is the only view that joins weakness signal with the
variation graph to recommend an in-session next problem; it replaces the
former standalone `recommend_next_target` tool.

## `record_attempt` writes — the full picture

One attempt call fans out to at most two write paths:

1. **Attempt row** (`learning_attempts`) — append-only, mandatory.
2. **Observations** (`learning_attempt_observations`) — zero or more per
   attempt, one per (concept, signal) tuple supplied in the input. Each
   observation has a `category` FK to `observation_categories` — typos are
   rejected at write, not silently split in a read-time GROUP BY.

Both high- and low-confidence observations are persisted; `confidence` is
a read-time label, not a write-time gate (the read-time filter lives in
`internal/learning/mastery.go::DeriveMasteryStage`). Auto-creation of leaf
targets and same-domain concepts happens inside `record_attempt`
(`internal/mcp/learning.go`), bounded to leaf nodes in the active
session's domain.

### Partial-write contract

The attempt row persists first, then observations are validated
per-element:

- `severity` is only valid for `signal='weakness'`; passing it on
  mastery/improvement rejects **that observation only** — siblings still
  try independently.
- `observations_recorded < len(observations)` is therefore a legal state;
  rejected indices are named in `observation_warnings`.
- The same per-element semantics apply to `related_targets`:
  `relations_linked < len(related_targets)` is legal and rejected entries
  land in `relation_warnings`.

## `attempt_number` is per-target, not per-session

`record_attempt` response `attempt_number` counts how many times this
*same* `learning_target_id` has been attempted across **all** sessions.
Three attempts on three different targets in one session all return
`attempt_number=1`. For the session-scoped count use
`learning_read(view=session_progress)`'s `attempt_count`.

## Outcome vocabulary

`record_attempt` accepts canonical DB enums and semantic synonyms, mapped
to the storage form by session mode (problem_solving vs immersive). The
response echoes `canonical_outcome` alongside the input so the coach sees
the normalized form.

| Canonical outcome | Paradigm |
|---|---|
| `solved_independent` | problem_solving |
| `solved_with_hint` | problem_solving |
| `solved_after_solution` | problem_solving |
| `completed` | immersive |
| `completed_with_support` | immersive |
| `incomplete` | shared |
| `gave_up` | shared |

Unknown outcome → error, not silent fallback. Adding a new outcome enum
value is a compile-time event — the mapping switch must be updated
alongside the schema enum.

## What is NOT coupled

These are real-sounding coupling candidates that are explicitly absent:

- **Concept mastery does not schedule anything.** There is no retention
  interval, no "due" date, no review queue. Mastery is a read-time
  aggregation over observations; it drives diagnosis, not scheduling.
- **Recording an attempt does not advance a plan entry.** Plan entries
  move only through `manage_plan(action=update_entry)`, and completing one
  requires a `completed_by_attempt_id` whose target matches the entry's
  (enforced in `internal/mcp/plan.go`).
- **Observations always flow through `record_attempt`.** An observation
  without an attempt is not a valid write path.

If you want a concept-driven drill (a next target chosen to exercise a
specific weak concept), use `learning_read(view=next_target)` — it is the
view that joins weakness signal with the variation graph.

## Where to extend this contract

- **Adding a paradigm** (e.g. `rubric_based` for system-design mock
  interviews): add an enum arm to `paradigm` and
  `chk_learning_attempts_paradigm_outcome`, add the new outcomes to the
  outcome→paradigm mapping, and update the Outcome vocabulary table above.
- **Adding a signal_type** (beyond weakness/improvement/mastery): update
  the CHECK on `learning_attempt_observations.signal_type` and decide
  explicitly whether mastery aggregation should include the new type.
  Update the dashboard queries accordingly.
- **Adding an observation category**: insert a row in
  `observation_categories` with the domain. The FK will accept writes
  immediately.

## Related docs

- `migrations/001_initial.up.sql` + `migrations/002_seed.up.sql` — schema,
  authoritative on columns / constraints / triggers.
- `internal/mcp/ops/catalog.go::All()` — the live MCP tool surface; the
  authoritative source for tool names and descriptions.
- `internal/mcp/learning.go` + `internal/mcp/plan.go` — which tool writes
  which entity, observation confidence labelling, concept auto-creation,
  and the plan-entry completion audit trail.
- `docs/backend-semantic-contract.md` §3 — system-wide domain model +
  entity catalogue.
