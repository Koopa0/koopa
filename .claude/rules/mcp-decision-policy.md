# MCP Decision Policy

This document is the operating contract between AI clients and the koopa0.dev MCP server.
It defines WHEN to create entities, WHICH entity type is correct, and WHO decides.

Authority: this file is the single source of truth for MCP behavior decisions.
Schema: `migrations/001_initial.up.sql` defines structure; this file defines policy.
Design: `.claude/plans/mcp-v2-design.md` defines tool surface; this file defines the rules tools enforce.

---

## 1. Intent Classification (Not Scenario Routing)

AI does NOT classify the user's message into a scenario first. Instead, it evaluates
**intent signals** and routes to the appropriate action directly.

Intent signals, in evaluation order:

| Signal | Detection | Action |
|--------|-----------|--------|
| **Question** | "what", "show", "how is", "哪些", "目前", no imperative verb | Read-only query tool. Zero write risk. |
| **Reference to existing entity** | mentions a task/project/goal by name, ID, or context | Transition or update on the existing entity |
| **Active learning session** | session exists with `ended_at IS NULL` | Route to learning lifecycle (record_attempt, end_session) |
| **Capture impulse** | "add", "remind me", "記一下", quick throwaway phrasing | capture_inbox (task.status=inbox) |
| **Commitment intent** | "create a goal", "plan a project", "set up", explicit structural language | propose_commitment (never direct create) |
| **Coordination intent** | "tell X to", "assign", "directive", involves another participant | propose_commitment(type=directive) (always proposal-first) |
| **Reflection intent** | "how did today go", "反思", "what did I learn", retrospective language | write_journal or track_insight |
| **Learning intent** | "let's practice", "start a session", "開始學", "drill" | start_session (begins learning lifecycle) |

When multiple signals are present, the FIRST match in the table above wins.
Exception: active learning session always takes priority (row 3).

---

## 2. Semantic Maturity Assessment

Before creating any entity that represents a commitment (goal, project, milestone,
directive, insight), the AI must assess maturity. This assessment is implicit — the
AI does not ask "what maturity level is this?" but evaluates the input against these
criteria:

### Maturity Levels

| Level | Name | Indicators | Allowed Actions |
|-------|------|-----------|-----------------|
| M0 | Vague | No outcome, exploratory ("maybe", "I wonder", "想想看") | Stay in conversation. Do NOT write anything. |
| M1 | Forming | Direction exists but missing specifics (no deadline, no scope, no success criteria) | capture_inbox only. Journal(plan) if explicitly reflective. |
| M2 | Structured | Has outcome + rough scope, missing some fields | propose_commitment — AI fills defaults, user reviews |
| M3 | Actionable | Specific outcome, time-bound, all key fields present | propose_commitment — fast approval path |

### Maturity Escalation Rule

The AI MUST NOT infer a maturity level higher than the input supports.

- "我想把英文變強" → M0 (no outcome, no timeline). Stay in conversation.
- "我想在六月前通過 JLPT N2" → M2 (outcome exists, timeline exists, scope implied).
- "建一個 goal: JLPT N2 by June, area=japanese, milestones: vocabulary 2000 words, grammar N2 level" → M3.

If the AI is uncertain between two levels, it MUST pick the lower one.

---

## 3. Entity Lifecycle Ownership

### Who can create each entity?

| Entity | AI Direct Create | AI Propose + User Approve | User Only | Side-effect Only |
|--------|-----------------|---------------------------|-----------|------------------|
| Task (inbox) | Yes | — | — | — |
| Task (todo) | Yes, if all fields present | — | — | — |
| Task (in-progress/done) | — | — | — | Via advance_work |
| Daily plan item | Yes, via plan_day | — | — | — |
| Journal | Yes | — | — | — |
| Goal | — | Always | — | — |
| Project | — | Always | — | — |
| Milestone | — | Always | — | — |
| Directive | — | Always | — | — |
| Insight | — | Always | — | — |
| Area | — | — | Yes | — |
| Participant | — | — | Yes | — |
| Concept (leaf, same domain) | — | — | — | Via record_attempt |
| Concept (structural change) | — | Always | — | — |
| Learning item | — | — | — | Via record_attempt |
| Learning session | Yes, via start_session | — | — | — |
| Attempt | — | — | — | Via record_attempt |
| Observation (high confidence) | — | — | — | Via record_attempt |
| Observation (low confidence) | — | User confirm in conversation | — | — |
| Content | — | Yes (create as draft) | — | — |
| Learning plan (shell) | — | Always (propose_commitment) | — | — |
| Learning plan item | Yes, via manage_plan | — | — | — |
| Learning plan status | — | — | — | Via manage_plan (Claude's semantic judgment) |
| Review card | — | — | — | System-managed (FSRS) |

### Entity transition ownership

| Transition | Who decides | Tool |
|-----------|-------------|------|
| Task: inbox → todo | AI (if fields present) or user | advance_work(action=clarify) |
| Task: todo → in-progress | User (implicit by starting work) | advance_work(action=start) |
| Task: → done | User confirms completion | advance_work(action=complete) |
| Task: → someday | User | advance_work(action=defer) |
| Daily plan item: planned → done | Follows task completion | advance_work auto-updates |
| Daily plan item: → deferred/dropped | User decision in reflection | advance_work(action=defer/drop) |
| Goal: status change | User | propose_commitment or track via goal_progress |
| Insight: unverified → verified/invalidated | User (AI may suggest with evidence) | track_insight |
| Directive: → acknowledged | Target participant | acknowledge_directive |
| Directive: → resolved | Source or target, after final report | file_report (sets resolved_at + resolution_report_id) |
| Learning session: → ended | User or AI at natural end | end_session |
| Learning plan: draft → active | User (via commit or manage_plan) | manage_plan(action=update_plan) |
| Learning plan: active → paused/completed | User | manage_plan(action=update_plan) |
| Learning plan: → abandoned | User | manage_plan(action=update_plan) |
| Plan item: → completed | Claude's semantic judgment after successful attempt | manage_plan(action=update_item). MUST include completed_by_attempt_id and reason. |
| Plan item: → skipped/substituted | User decision | manage_plan(action=update_item) |

---

## 4. Directive vs Task Litmus Test

This distinction is critical and must never be blurred.

### The test

Ask: **What is the expected output?**

| If the output is... | Then it's a... | Because... |
|---------------------|----------------|------------|
| A **report** (analysis, research, synthesis, recommendation) | **Directive** | The target exercises autonomous judgment about scope, approach, and output format |
| A **status change** (task.status=done) | **Task** | The work is prescribed and the target just executes |

### Additional signals

| Signal | → Directive | → Task |
|--------|------------|--------|
| Target has latitude in HOW to do it | Yes | No |
| Output goes back to the source for review | Yes | No |
| Can be expressed as a single imperative verb + object | No | Yes |
| Involves cross-participant coordination | Yes | No |
| Source needs to validate participant capabilities | Yes | No |

### Schema enforcement

- Directive: source must have `can_issue_directives=true`, target must have `can_receive_directives=true`
- Task: assignee must have `task_assignable=true`
- These are validated in the Go layer, not by the AI client

### Examples

| Input | Entity | Reasoning |
|-------|--------|-----------|
| "幫我叫 research-lab 去研究 NATS exactly-once semantics" | Directive | Target (research-lab) exercises judgment; output is a report |
| "建一個 task: 把 auth middleware 加上 rate limiting" | Task | Prescribed work, output is code change = status done |
| "請 content-studio 寫一篇關於 Go generics 的文章" | Directive | Content-studio decides structure, angle, depth |
| "加一個 task 給自己: 讀完 DDIA chapter 5" | Task | Clear action, completion = binary |

---

## 5. Observation Confidence Rules

Attempt observations are diagnostic signals that connect attempts to concepts.
They are **irreplaceable historical analytics** (concept_id uses RESTRICT).

**Confidence is a label, not a gate.** Every observation persists, regardless
of confidence. The `confidence` column on `attempt_observations` records HOW
the coach knew (directly evidenced vs inferred), and the dashboard's
`confidence_filter` controls whether low-confidence observations contribute
to mastery and weakness aggregations at read time. Default reads return only
high-confidence observations; `confidence_filter=all` surfaces both.

This replaces the prior gate model in which low-confidence observations
were returned as `pending_observations` and dropped on the next conversation
turn unless the AI immediately re-sent them. That model lost data
silently — there is no `pending_observations` field on `record_attempt`
output anymore.

### When to label `high`

ALL of these are true:
- The concept slug refers to a concept that already exists, OR auto-creation
  is permissible per section 6 (leaf, same domain, kind inferable)
- The signal is **directly evidenced** by the attempt outcome — the user said
  "I forgot how X works" or repeatedly failed at X
- The category matches established conventions for the domain

### When to label `low`

ANY of these is true:
- The signal is **inferred** by the coach — "you struggled with this problem
  and I suspect X is the missing skill" — even though the user did not name
  the gap
- The concept needs auto-creation AND the signal would otherwise have been
  high (auto-creation alone doesn't mean low; inference does)
- The severity assessment is uncertain (the coach is guessing critical vs
  moderate)

### Mastery floor invariant — why the gate is gone but the label still matters

`deriveMasteryStage` enforces a floor: a concept with fewer than 3
**filtered** observations always reports `developing`, regardless of signal
mix. The filter is whatever the dashboard request asked for — high (default)
or all. This is the property that makes `confidence` a true label rather than
a half-gate: a single low-confidence observation cannot "unlock" a concept
from no-data into struggling/solid, because under the default filter the low
observation isn't counted at all.

If you find yourself thinking "I'll mark this `high` even though it's
inferred so it influences the dashboard sooner," stop. The whole point of
the floor + filter design is that you can mark inferred signals freely
without polluting Koopa's view of his own progress. Mark accurately. The
analytics will surface them when there's enough data to trust.

### Concrete examples by domain

**LeetCode:**
- HIGH: User said "I forgot how binary search works on rotated arrays" → `{concept: "binary-search", signal: "weakness", category: "pattern-recognition", confidence: "high"}`. Directly stated.
- HIGH: User solved Two Sum independently in 3 minutes → `{concept: "hash-map", signal: "mastery", category: "data-structure", confidence: "high"}`. Behaviour-evidenced.
- LOW: User failed 3Sum but the coach suspects weak two-pointer skills (the user didn't mention them) → `{concept: "two-pointer", signal: "weakness", category: "approach-selection", confidence: "low"}`. Inferred. Persists for later analysis.
- LOW: User struggled, coach thinks a new concept "monotonic-stack" explains it → `{concept: "monotonic-stack", signal: "weakness", category: "approach-selection", confidence: "low"}`. Auto-create + inference.

**Japanese:**
- HIGH: User conjugated te-form incorrectly 3 times in a drill → `{concept: "te-form", signal: "weakness", category: "conjugation-accuracy", confidence: "high"}`.
- LOW: User struggled with a listening passage; coach infers vocabulary gap → `{concept: "N3-vocabulary", signal: "weakness", category: "vocabulary-recall", confidence: "low"}`.

**System Design:**
- HIGH: User couldn't estimate QPS for a URL shortener → `{concept: "capacity-estimation", signal: "weakness", category: "capacity-estimation", confidence: "high"}`.
- LOW: User's design lacked a cache layer; coach infers caching-tradeoff gap → `{concept: "caching-strategy", signal: "weakness", category: "tradeoff-analysis", confidence: "low"}`.

### Cross-reference

- The mastery stage heuristic itself (rules + floor) lives in
  `internal/mcp/learning.go::deriveMasteryStage` — the doc comment there
  is the canonical specification for the rules.
- The invariant that mastery and weakness views agree under the same
  filter is enforced by integration test
  `internal/mcp/integration_test.go::TestObservationConfidenceInvariant`.

---

## 6. Concept Auto-Creation Boundary

### Auto-create allowed (within record_attempt)

ALL of these must be true:
- The concept is a leaf node (no children)
- The concept's domain matches the active session's domain
- The concept kind is inferrable from context (pattern/skill/principle)
- No parent_id is being set (flat creation only)

### Proposal-first required (via propose_commitment)

ANY of these is true:
- The concept would create or modify a parent-child relationship
- The concept's domain differs from the active session's domain
- The concept would be the first in a new domain
- The change affects existing concept hierarchy

---

## 7. Capture Pollution Prevention

Task inbox (status=inbox) is for **concrete work captures that need later clarification**.
It is NOT a scratch pad, thought dump, or idea journal.

### Goes into inbox

- "加一個 task: 研究 pgvector 的 indexing 策略" — concrete, actionable after clarification
- "remind me to review the PR tomorrow" — specific action, needs scheduling
- "把 auth middleware 的 rate limiting 加上" — clear work item

### Stays in conversation (do NOT create entity)

- "我想把英文變強" — aspiration, not a task
- "也許應該重新想想 MCP 的架構" — reflection, not a work item
- "最近覺得學習效率不太好" — feeling, not actionable
- "Koopa Studio 是不是應該開始做了" — question, not a capture

### Goes into journal (write_journal)

- "今天決定不做 X 了，因為 Y" — decision record (kind=context or reflection)
- "這週的重點是把 Phase 1 完成" — plan statement (kind=plan)

### Goes into insight (propose_commitment)

- "我發現每次做 graph 題都卡在 DFS termination condition" — falsifiable hypothesis
- "我覺得 LeetCode 的弱點是 state definition 不是 transition" — testable pattern with implicit invalidation condition
- NOT insight: "今天效率不錯" — no hypothesis, no invalidation condition → journal(reflection)
- NOT insight: "最近 DP 做得不好" — feeling without a specific, testable claim → conversation or journal(reflection)

### Journal kind routing rule

When the input contains both quantitative data and narrative:
- **Use `reflection` as kind, put structured metrics into `metadata`.**
- Example: "今天完成 5 題但覺得效率不好" → `write_journal(kind=reflection, content="...", metadata={tasks_completed: 5})`
- Pure-narrative reflections ("覺得最近方向不對") → `reflection` with no metrics metadata
- Pure-metrics snapshots without narrative are rare in human use. When they occur, they are typically **AI-generated** (e.g., end-of-session auto-summary). In that case: `write_journal(kind=metrics, source=<ai_participant>)`.
- **Practical implication**: `metrics` kind will primarily be written by AI participants as automated quantitative snapshots, not by human users. Human journal entries almost always carry some narrative → `reflection` is the de facto default human kind.

### The test

Before writing to inbox, ask: **"Can this become a single task with a clear done state?"**
- Yes → inbox
- No, it's a direction → conversation (M0-M1)
- No, it's a reflection → journal
- No, it's a falsifiable hypothesis → propose_commitment(type=insight)

---

## 8. Proposal vs Direct-Commit Quick Reference

### Always proposal-first (propose_commitment → commit_proposal)

| Entity | Reason |
|--------|--------|
| Goal | Long-term commitment, affects planning horizon |
| Project | Scope commitment, creates work container |
| Milestone | Goal progress marker, affects tracking |
| Directive | Cross-participant coordination, creates obligations |
| Insight | Hypothesis needs human validation to be meaningful |

### Direct-commit allowed

| Entity | Reason | Tool |
|--------|--------|------|
| Task (inbox) | GTD capture must be frictionless; inbox = "not yet clarified" | capture_inbox |
| Task (todo) | If all fields present and user intent is clear | capture_inbox (auto-promotes if due provided) |
| Journal | Append-only, self-directed, low risk | write_journal |
| Daily plan item | Planning commitment, tracked by selected_by | plan_day |
| Attempt | Within active session, event recording | record_attempt |
| High-confidence observation | Within active session, directly evidenced | record_attempt |
| Learning session start | User explicitly requested | start_session |

### Never via MCP (user or system only)

| Entity | Reason |
|--------|--------|
| Area | PARA responsibility area — human life decision |
| Participant | System identity — infrastructure config |
| Review card | FSRS algorithm manages internally |
| Review log | System append on review |

---

## 9. Daily Plan: No Auto-Carryover

`morning_context` presents yesterday's unfinished planned items but does NOT
auto-defer them. The user decides:
- Defer: re-include in today's plan via plan_day
- Drop: explicitly dropped (daily_plan_item.status='dropped')
- Ignore: leave as-is (status stays 'planned' on yesterday's date)

Rationale: auto-defer hides accountability. The user's product philosophy is
ownership-preserving — forced confrontation with unfinished work is a feature,
not a bug.

---

## 10. Multiplexer Pattern Rules

The following tools use a multiplexer pattern (action parameter). This is accepted
when ALL conditions are met:

1. All actions share the same entity or the same workflow contract
2. Action set is ≤ 5
3. Input schema differences between actions are minor (shared base + optional fields)

### Approved multiplexers

| Tool | Actions | Justification |
|------|---------|---------------|
| propose_commitment | goal, project, milestone, directive, insight, learning_plan | Same workflow (propose→preview→commit), conceptually unified |
| advance_work | clarify, start, complete, defer, drop | Same entity (task), same lifecycle state machine |
| manage_content | create, update, publish, bookmark_rss | Same entity (content), small action set |
| manage_feeds | list, add, update, remove | Same entity (feed), small action set |
| learning_dashboard | overview, mastery, weaknesses, retrieval, timeline, variations | Same domain (learning analytics), same filters, different projections |
| manage_plan | add_items, remove_items, update_item, reorder, update_plan, progress | Same entity (learning_plan/items), 6 actions (at ceiling). Includes one read-only action (progress) — approved exception to read+write mixing because progress is intrinsic to the plan lifecycle |

### Prohibited multiplexer patterns

- Combining read + write operations in one tool (except manage_feeds.list which is read-only). Exception: a single read-only action within an otherwise write-oriented multiplexer is permitted when the read action is intrinsic to the entity lifecycle (e.g., plan progress within manage_plan).
- Action sets > 6
- Actions with fundamentally different input schemas (e.g., "search" + "create" + "delete" in one tool)

---

## 11. Participant Resolution — Caller Self-Identification

### Trust model

MCP's trust model: server trusts the caller (AI agent guided by project instructions).
Identity is **semantic** — project instructions tell the AI who it is, the AI passes
`as: "hq"` in tool calls. Server validates via **capability flags**, not transport identity.

This mirrors human organizational security: a CEO has authority because the organization
assigns that role and capability flags constrain what actions are permitted, not because
of a cryptographic key.

### Implementation

Every tool schema includes an optional `as` field:
```json
{ "as": "hq", "title": "新任務", ... }
```

The `as` field is extracted before input unmarshaling and stored in context.
All participant-dependent operations (`created_by`, `source`, `selected_by`, etc.)
read from `callerIdentity(ctx)`, which checks context first, then falls back to
the server-level `KOOPA_MCP_PARTICIPANT` env var (default: `"human"`).

### Project instructions contract

Each Cowork project's instructions MUST include:
```
你是 [participant_name]。在所有 MCP tool call 中傳入 as: "[participant_name]"。
```

Example for HQ:
```
你是 hq（Studio HQ — CEO, decisions, delegation）。
在所有 MCP tool call 中傳入 as: "hq"。
你可以 issue directives（can_issue_directives=true）和 write reports。
```

### Capability validation

The server trusts the `as` parameter but validates capabilities per-operation:
- `file_report` → `can_write_reports` must be true for the source participant
- `propose_commitment(directive)` → `can_issue_directives` must be true for source
- `acknowledge_directive` → participant must be the directive's target

Capability flags are the **organizational security** layer. Trust boundary is at
the application layer (does this participant have permission?), not the transport
layer (which connection sent this?).

### Upgrade trigger

When multi-user / third-party integration is needed:
- Add OAuth identity → participant mapping
- Validate `as` matches authenticated identity
- Current tools require no modification — only the middleware resolution changes

---

## 12. Learning Session Scoping Rules

### Active session constraint

Only ONE learning session can be active at a time (ended_at IS NULL).
`start_session` returns an error if an active session exists.

### Session-scoped operations

These operations are ONLY valid within an active session:
- record_attempt (requires session_id)
- end_session (requires session_id)

### Ad-hoc observations

If the AI observes a learning signal outside a session context (e.g., during
a code review or general conversation), it should:
1. Note the observation in conversation
2. Suggest starting a learning session to formally record it
3. NOT create a backdoor attempt/observation without a session

Rationale: the session boundary is the orchestration guarantee. Without it,
attempt data becomes noisy and unstructured.

---

## 13. Plan Item Completion Audit Trail

When Claude marks a plan item as completed via `manage_plan(action=update_item, status=completed)`,
the following fields are **MANDATORY** (policy-enforced, not schema-enforced):

| Field | Requirement | Example |
|-------|------------|---------|
| `completed_by_attempt_id` | The attempt UUID that informed the completion decision | `"a1b2c3..."` |
| `reason` | What attempt outcome and reasoning informed the decision | `"solved_independent on attempt #2, 8 min, clean implementation"` |

### Why policy-enforced, not schema-enforced

`completed_by_attempt_id` is nullable in the schema to allow future manual/UI completion
paths (e.g., user completed the item on another platform with no attempt record). The
schema constraint `chk_completed_by_attempt_requires_status` only ensures the FK is NULL
for non-completed items — it does NOT enforce NOT NULL for completed items.

The **AI path** (manage_plan called by Claude) MUST always provide both fields. The
**manual path** (future UI) MAY omit `completed_by_attempt_id` but SHOULD still provide
`reason` (e.g., "completed on LeetCode directly, no session").

### Reasoning

Without this audit trail, plan item completion is a black box — "Claude decided it was done"
with no traceable connection to the evidence. The attempt_id enables:
- `JOIN attempts ON plan_items.completed_by_attempt_id` for learning analytics
- Auditing completion quality (was a `solved_with_hint` really sufficient for this plan?)
- Detecting patterns (does Claude complete too aggressively for certain plan types?)

---

## 14. Directive Resolution

Directives have a three-phase lifecycle: **issued → acknowledged → resolved**.

| Phase | Column | Who sets it |
|-------|--------|-------------|
| Issued | `issued_date`, `created_at` | Source participant (via propose_commitment → commit_proposal) |
| Acknowledged | `acknowledged_at`, `acknowledged_by` | Target participant (via acknowledge_directive) |
| Resolved | `resolved_at`, `resolution_report_id` | Source or target (via file_report with resolution flag, or explicit resolution) |

### Rules

- A directive MUST be acknowledged before it can be resolved (`chk_resolved_requires_ack`)
- `resolution_report_id` links to the report that constitutes the final deliverable
- A directive with reports but no `resolved_at` is in-progress (reports are progress updates)
- `morning_context` queries unresolved directives via `WHERE resolved_at IS NULL AND acknowledged_at IS NOT NULL`
- Unacknowledged directives use the existing `idx_directives_unacked` partial index
