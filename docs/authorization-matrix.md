# Authorization Matrix

This document is the authoritative reference for **who may perform what
operation** on the koopa MCP server. Authorization is not a single
mechanism — four orthogonal axes compose to produce the effective rule
for each tool. The matrix at the bottom of this doc is the canonical
list; the prose above explains the model so the matrix is interpretable
without reading every handler.

> Authority order: this doc defers to the schema (`migrations/`) for
> entity invariants and to `internal/agent/registry.go` for the agent
> roster. If this doc and code disagree, the code wins and this doc is
> stale — open a fix.

---

## §1. The four axes

Each axis enforces exactly one concern. A handler may compose two or
three axes (e.g. capability + author); never blur their meaning.

### Axis 1 — Capability (compile-time)

Three flags live on `agent.Capability` (`internal/agent/agent.go`):

- `SubmitTasks` — may submit a task to another agent (directive source)
- `ReceiveTasks` — may be the target of a task and accept it
- `PublishArtifacts` — may attach artifacts (task-bound or standalone)

Capability is checked via `agent.Authorize(ctx, registry, caller,
action)` which returns an `agent.Authorized[Action]` value. Coordination
store mutation methods take that value in their signatures, so a caller
without the capability cannot reach the store at compile time.

Capability is intentionally narrow: it answers "may this caller speak
on this transport channel". It does not answer "is this caller the
right author of this domain entity" — that's Axis 3.

### Axis 2 — Platform (runtime)

Some operations are reserved for the human owner of the system. The
check (in `authz.go::requireExplicitHuman`):

1. The caller MUST supply an explicit `as` field. The MCP server has a
   default caller agent (env `KOOPA_MCP_CALLER_AGENT`, default
   `"human"`). A handler that accepts the default would let any client
   that omits `as` silently inherit human authority. `ExplicitCallerIdentity`
   distinguishes "explicit human" from "default human".
2. The registry row for the caller MUST have `Platform == "human"`. We
   check the platform attribute, not a hardcoded name, so a future
   trusted auto-publisher agent registered with `Platform="human"`
   inherits the right without code changes.

This axis is the load-bearing semantic for `publish_content` and for
`commit_proposal` of high-commitment entities — operations whose meaning
is "the human owner reviewed this".

### Axis 3 — Author (runtime allowlist)

Domain ownership: each write tool that crosses a domain boundary names
the cowork (or claude-code) agents that may legitimately author the
targeted entity. The check (`authz.go::requireAuthor`):

- `Platform=="human"` callers are always permitted, regardless of the
  list. The system has exactly one human; an allowlist that excluded
  the owner would be incoherent. Allowlists name the cowork agents
  that MAY also author — the human is never on the list because the
  human is never excluded.
- All other callers must match one of the named agents.

Author allowlists are runtime data, not capability flags. Adding "may
content-studio author goals" should not require rebuilding the binary.

### Axis 4 — Self (runtime, row-level)

Personal-GTD tools (`advance_work`) and task-bound coordination
(`file_report` with `in_response_to`, `task_detail`) require
`caller == row.created_by` or `caller == row.target`. Enforced inline
by the handler against the loaded row; no helper because the row source
varies.

---

## §2. Why explicit `as` matters for human-only gates

Operations gated by `requireAuthor` are content with the server default
— if the default agent is human, server-default human is still human.

Operations gated by `requireExplicitHuman` refuse the default. The
distinction matters specifically for `commit_proposal` of high-commitment
entities and for `publish_content`, where human review is the
load-bearing semantic — not a configuration default. A backdoor that
let an MCP client omit `as` and silently inherit publish authority
would defeat the gate.

---

## §3. The matrix

Read the columns left-to-right: each row names a write tool, the axes
that gate it, and the rule.

### Knowledge layer — intentionally open

Notes and content are write-rich, curate-late by design. Restricting
authorship would force agents to launder observations through
agent_notes and lose the slug-addressable knowledge graph that notes
provide. Front-end review, maturity transitions, and the publish gate
handle quality.

| Tool | Capability | Platform | Author | Self | Effective rule |
|---|---|---|---|---|---|
| `create_note` | — | — | — | — | Open to any registered caller |
| `update_note` | — | — | — | — | Open |
| `update_note_maturity` | — | — | — | — | Open |
| `create_content` | — | — | — | — | Open (drafts are private until publish) |
| `update_content` | — | — | — | — | Open |
| `submit_content_for_review` | — | — | — | — | Open |
| `revert_content_to_draft` | — | — | — | — | Open |
| `archive_content` | — | — | — | — | Open |
| `list_content` / `read_content` | — | — | — | — | Open (read-only) |

### Publish gate

| Tool | Capability | Platform | Author | Self | Effective rule |
|---|---|---|---|---|---|
| `publish_content` | — | **human** | — | — | Explicit `as` + Platform=human |

### Commitment layer — agent drafts, human confirms

The two-phase pattern's load-bearing semantic. `commit_proposal`
dispatches on `payload.Type`:

- `directive` is inter-agent coordination, not a commitment to Koopa.
  HQ commits its own delegation tokens in the same session. The
  capability check inside `commitDirective` is the gate; layering a
  human requirement on top would force Koopa to confirm every
  cross-agent task and turn HQ into a paperwork bottleneck.
- The other six types each reshape Koopa's commitment surface
  (quarterly horizon, multi-week scope, falsifiable claim tracker,
  learning taxonomy). They commit only with explicit human authority.

| Tool | Capability | Platform | Author | Self | Effective rule |
|---|---|---|---|---|---|
| `propose_directive` | **SubmitTasks** | — | — | — | Capability check at handler boundary |
| `propose_goal` | — | — | hq, content-studio, research-lab | — | Strategic commitment proposers |
| `propose_project` | — | — | hq, content-studio, research-lab | — | Same |
| `propose_milestone` | — | — | hq, content-studio, research-lab | — | Same |
| `propose_hypothesis` | — | — | hq, learning-studio, research-lab | — | Three roles that observe falsifiable claims |
| `propose_learning_plan` | — | — | learning-studio | — | Operational learning curriculum |
| `propose_learning_domain` | — | — | learning-studio, hq | — | Operational + strategic |
| `commit_proposal(directive)` | **SubmitTasks** (in commitDirective) | — | — | — | Capability already gates |
| `commit_proposal(others)` | — | **human** | — | — | Explicit `as` + Platform=human |

### Coordination layer

| Tool | Capability | Platform | Author | Self | Effective rule |
|---|---|---|---|---|---|
| `acknowledge_directive` | **ReceiveTasks** | — | — | task target | Capability + caller is the assigned target |
| `file_report(in_response_to=...)` | **PublishArtifacts** | — | — | task target | Capability + caller is the target completing the task |
| `file_report(standalone)` | **PublishArtifacts** | — | content-studio, research-lab, learning-studio | — | Capability + author allowlist (excludes hq) |
| `task_detail` | — | — | — | source or target | Caller must be a party to the task |

### Daily plan & GTD

| Tool | Capability | Platform | Author | Self | Effective rule |
|---|---|---|---|---|---|
| `plan_day` | — | — | hq | — | HQ daily ritual; other agents have their own work queues |
| `capture_inbox` | — | — | — | — | Open (caller's own todo) |
| `advance_work` | — | — | — | — | Currently open; future: caller == created_by |

---

## §4. Why each gate exists

Cross-references the rules above to the concrete reasoning so a future
reviewer can challenge a rule without re-deriving it.

### `publish_content` — human-only

Publishing flips three fields atomically (status, is_public, published_at)
and exposes content on the public website. The editorial lifecycle
(draft → review → published) is intentionally a two-actor handoff:
agent drafts and submits for review, human publishes. Without the
human gate the lifecycle is theatre.

### `commit_proposal` of high-commitment types — human-only

Each of the six gated types reshapes Koopa's commitment surface:

| Type | Effect on Koopa |
|---|---|
| goal | Occupies quarterly planning horizon |
| project | Multi-week scope budget |
| milestone | Affects goal_progress visibility |
| hypothesis | Enters world-view tracking system (morning_context.unverified_hypotheses) |
| learning_plan | Multi-week time budget |
| learning_domain | Mutates the closed learning taxonomy |

If any of these can be self-committed by the agent that proposed them,
the propose+token mechanism is just ceremony.

### `commit_proposal(directive)` — capability, NOT human

A directive is an inter-agent work request, not a commitment to Koopa.
HQ's morning briefing flow is "look at morning_context → decide what to
delegate → propose+commit a directive" in the same session. Forcing
Koopa to confirm every directive would invert the intended division of
labor.

### `propose_*` allowlists — fast-fail before token signing

Each propose handler checks its allowlist before allocating a signed
token. The same fast-fail discipline `propose_directive` uses for
SubmitTasks: an unauthorized caller learns the rule without paying a
propose+commit round-trip.

### `plan_day` — hq + human only

Schema COMMENT on `daily_plan_items.selected_by` already documents
"typically hq or human". The other cowork agents have their own work
queues:

- content-studio → content_pipeline
- research-lab → directive backlog
- learning-studio → learning_plan + FSRS schedule

`daily_plan_items` is not a generic "today's work" surface — it is
HQ's morning ritual.

### `file_report(standalone)` — excludes HQ

HQ has `PublishArtifacts` capability but no business reason to publish
standalone artifacts. HQ's outputs are agent_notes (plan / reflection)
and read-side aggregates (weekly_summary), not artifacts. Excluding HQ
from the standalone allowlist prevents drift where HQ accidentally
creates artifacts that nobody reads.

### Note authorship — open

Notes form the AI-for-human / human-for-human knowledge layer. Any
agent that observes something note-worthy may write it down; the
front-end review surface (maturity transitions, curation tools) is
where quality is enforced. Restricting authorship would force agents
to launder observations through agent_notes(kind=context|reflection)
and lose the slug-addressable knowledge graph notes provide.

This contrasts with content (publish gated to human) and with
commit_proposal (high-commitment types gated to human). Notes are not
commitments and never publish.

### Content authorship — open, with human-only publish

Same philosophy as notes. Any agent may draft a `content` row in
`status=draft`. The dangerous transition (review → published) is gated
at `publish_content`. Front-end review and human curation handle
quality; the create surface trusts the writer because every draft is
private until publish.

---

## §5. Why this is not RBAC

The agent set is closed and small (≤10 entries in
`internal/agent/registry.go::BuiltinAgents()`), defined as a Go
literal, and grows only when the binary is rebuilt. Roles in the RBAC
sense don't exist — each agent IS its own role.

The permission matrix has structural heterogeneity that flat RBAC
policies don't express well:

- self-only checks (caller == row.created_by) need row-level predicates
- platform checks need an attribute on the subject
- capability is compile-time, not policy-table-driven

A formal RBAC framework (Casbin, oso, cerbos) would replace four
small composable mechanisms with one large generic one — and violate
the project's no-framework dependency posture in the process.

The right framing: this is **declarative authorship policy**. The four
helpers in `authz.go` are the abstraction; this document is the policy.

---

## §6. Adding a new write tool

When you add a tool that mutates state, decide which axes apply:

1. Does the operation cross a transport boundary (submit/receive/publish)?
   → Capability check via `agent.Authorize`.
2. Is the operation reserved for the human owner?
   → `requireExplicitHuman` (e.g. publish, high-commitment commit).
3. Is the entity domain-owned by a subset of cowork agents?
   → `requireAuthor` with the allowlist.
4. Does the operation only make sense on the caller's own row?
   → Inline `caller == row.created_by` (or `target`) check.

Add the tool to the matrix in §3, add a one-paragraph rationale in §4
if the rule is non-obvious, and add gate tests in `internal/mcp/authz_test.go`.

If a new axis is needed (e.g. quota, time-window), add it as a new
helper in `authz.go` rather than overloading an existing one — the
axes are orthogonal by design.
