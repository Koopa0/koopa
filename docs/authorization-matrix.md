# Authorization Matrix

This document is the authoritative reference for **who may perform what
operation** on the koopa MCP server. Authorization is not a single
mechanism — three orthogonal axes compose to produce the effective rule
for each tool. The matrix at the bottom of this doc is the canonical
list; the prose above explains the model so the matrix is interpretable
without reading every handler.

> Authority order: this doc defers to the schema (`migrations/`) for
> entity invariants, to `internal/mcp/ops/catalog.go` for the live tool
> surface, and to `internal/agent/registry.go` for the agent roster. If
> this doc and code disagree, the code wins and this doc is stale — open
> a fix.

> **Post-contraction surface (MCP-v3).** The agent-facing MCP surface is
> exactly 11 tools (`internal/mcp/ops/catalog.go::All()`): `brief`,
> `search_knowledge`, `capture_inbox`, `plan_day`, `start_session`,
> `record_attempt`, `end_session`, `learning_read`, `manage_plan`,
> `create_note`, `update_note`. Of these, `brief`, `learning_read`, and
> `search_knowledge` are read-only and need no authz beyond being a
> registered caller. The eight write tools are gated below.
>
> Commitment creation (goal / milestone / learning_plan / learning_domain)
> and content authoring no longer exist on the MCP surface. They moved to
> **admin-only HTTP POST endpoints** behind JWT auth + the per-request
> actor tx (`adminMid` in `cmd/app/routes.go`) — i.e. human-gated. The
> agent-facing `propose_*` / `commit_proposal` two-phase flow, the seven
> content tools, the report lane, and the A2A coordination triad were all
> removed; their former rows are gone from the matrix. See §7 for the
> migration map.

---

## §1. The three axes

Each axis enforces exactly one concern. A handler may compose more than
one axis (e.g. author + self); never blur their meaning.

### Axis 1 — Platform (runtime)

Some operations are reserved for the human owner of the system. The
check (in `authz.go::requireExplicitHuman`):

1. The caller MUST supply an explicit `as` field. The MCP server has a
   default caller agent (env `KOOPA_MCP_CALLER_AGENT`, default
   `"unknown"`). Even if a future deploy overrides
   the default back to `"human"`, `requireExplicitHuman` refuses ANY
   default-fall-through — `ExplicitCallerIdentity` distinguishes
   "explicit `as` was supplied" from "fell through to server default",
   and the gate rejects the latter regardless of what the default
   points to. The `"unknown"` agent itself is zero-privilege (Platform `system`) so even the requireAuthor gate
   refuses it, closing the prior fail-open where the env default
   silently granted human authority to any client that forgot to set
   `as`.
2. The registry row for the caller MUST have `Platform == "human"`. We
   check the platform attribute, not a hardcoded name, so a future
   trusted auto-publisher agent registered with `Platform="human"`
   inherits the right without code changes.

> **Post-contraction note.** The operations this axis used to gate —
> content publication and high-commitment commits — are no longer MCP
> tools. The "human reviewed this" semantic now lives in the admin HTTP
> surface: every `POST /api/admin/...` mutation runs through `adminMid`
> (JWT auth + per-request actor tx) in `cmd/app/routes.go`, which is the
> human owner acting through the admin UI. `requireExplicitHuman` remains
> in `authz.go` and would re-gate any future human-only MCP tool, but no
> tool on the current surface invokes it.

### Axis 2 — Author (runtime allowlist)

Domain ownership: each write tool that crosses a domain boundary names
the cowork (or claude-code) agents that may legitimately author the
targeted entity. The check (`authz.go::requireAuthor`):

- `Platform=="human"` callers are always permitted, regardless of the
  list. The system has exactly one human; an allowlist that excluded
  the owner would be incoherent. Allowlists name the cowork agents
  that MAY also author — the human is never on the list because the
  human is never excluded.
- All other callers must match one of the named agents.

Author allowlists are runtime data baked into handlers. Adding "may
learning-studio author goals" should not require migrating existing rows.

### Axis 3 — Self (runtime, row-level)

Row-level self-binding requires `caller == row.created_by` or
`caller == row.target`, enforced inline by the handler against the
loaded row (no helper, because the row source varies).

> **Post-contraction note.** The tools this axis used to gate — the
> personal-GTD `advance_work` and task-bound coordination
> (`file_report(in_response_to)`, `task_detail`) — are removed. Todo
> state transitions moved to `POST /api/admin/commitment/todos/{id}/advance`
> (admin HTTP), and the coordination triad is gone entirely. No tool on
> the current 11-tool surface uses a self-binding check; the axis is kept
> in the model for completeness.

---

## §2. Why explicit `as` matters for human-only gates

The two `authz.go` gates treat the server-default caller differently:

- `requireAuthor` accepts the server default — if the default agent is
  human, server-default human is still human.
- `requireExplicitHuman` refuses the default. It demands that the caller
  supplied an explicit `as` AND that the named agent has
  `Platform == "human"`. A backdoor that let an MCP client omit `as` and
  silently inherit human authority would defeat the gate.

> **Post-contraction note.** The operations that historically motivated
> `requireExplicitHuman` — high-commitment `commit_proposal` and
> `publish_content` — are no longer MCP tools; both moved to admin HTTP
> (see §7). The distinction above is therefore latent on the current
> surface: it constrains how a future human-only MCP tool MUST be wired,
> not any tool that exists today. None of the eight current write tools
> is human-gated at the MCP layer.

---

## §3. The matrix

Read the columns left-to-right: each row names a write tool, the axes
that gate it, and the rule. Only the eight write tools on the current
11-tool MCP surface appear; the three read-only tools (`brief`,
`learning_read`, `search_knowledge`) are not gated beyond being a
registered caller and are listed at the end for completeness.

### Knowledge layer

Notes are write-rich, curate-late by design and open to any registered
caller — restricting authorship would force agents to launder
observations through some narrower channel and lose the slug-addressable
knowledge graph that notes provide. The two note tools are the entire
agent-facing knowledge-authoring surface; content authoring moved off MCP
to admin HTTP (see §7).

| Tool | Platform | Author | Self | Effective rule |
|---|---|---|---|---|
| `create_note` | — | — | — | Open to any registered caller |
| `update_note` | — | — | — | Open (covers field edits AND maturity transitions) |

### Learning layer

The learning lifecycle is the largest live write surface. All four write
tools are open to any registered caller — there is no per-role authorship
on learning: an agent that runs a session records its own attempts and
manages its own plan entries. `manage_plan` is `Destructive` because it
includes `remove_entries` and `reorder`; the per-entry completion audit
trail (`completed_by_attempt_id` + `reason`) is policy-enforced inside the
handler, not via the axes above.

| Tool | Platform | Author | Self | Effective rule |
|---|---|---|---|---|
| `start_session` | — | — | — | Open (one active session at a time, enforced by the handler) |
| `record_attempt` | — | — | — | Open (requires the active session) |
| `end_session` | — | — | — | Open (requires the session_id) |
| `manage_plan` | — | — | — | Open; completion audit fields are policy-enforced in-handler |

### Daily plan & GTD

| Tool | Platform | Author | Self | Effective rule |
|---|---|---|---|---|
| `plan_day` | — | planner | — | planner daily ritual (+ human implicit); other agents have their own work queues |
| `capture_inbox` | — | — | — | Open (caller's own todo) |

### Read-only tools (no authz row needed)

| Tool | Writability | Effective rule |
|---|---|---|
| `brief` | ReadOnly | Open to any registered caller; pure planning-state pull, carries no agent memory |
| `learning_read` | ReadOnly | Open to any registered caller |
| `search_knowledge` | ReadOnly | Open to any registered caller |

---

## §4. Why each gate exists

Cross-references the rules above to the concrete reasoning so a future
reviewer can challenge a rule without re-deriving it. After the MCP-v3
contraction only two gates remain on the agent surface — `plan_day`'s planner
allowlist and "note authorship is open". Everything else is open to any
registered caller (learning lifecycle, `capture_inbox`) or read-only.

### `plan_day` — planner + human only

Schema COMMENT on `daily_plan_items.selected_by` already documents
"typically planner or human". `daily_plan_items` is not a generic "today's
work" surface — it is planner's morning ritual, so the author allowlist names
`planner` (with the human always implicit) and every other caller is refused
before any write.

### Note authorship — open

Notes form the AI-for-human / human-for-human knowledge layer. Any
agent that observes something note-worthy may write it down; the admin
review surface (maturity transitions, curation tools) is where quality is
enforced. Restricting authorship would lose the slug-addressable
knowledge graph notes provide. `create_note` and `update_note` are
therefore both open; notes are never commitments and never publish.

### Learning lifecycle — open

`start_session`, `record_attempt`, `end_session`, and `manage_plan` carry
no author allowlist. An agent that runs a learning session records its
own attempts and manages its own plan; there is no cross-agent authorship
boundary to enforce. The integrity that matters on this surface is
intra-handler, not authz: `start_session` rejects a second concurrent
active session, `record_attempt` requires the active session, and
`manage_plan(update_entry, status=completed)` requires the
`completed_by_attempt_id` + `reason` audit pair (or a `manual override:`
forced reason). Those are policy/state-machine checks inside the handlers,
not one of the three axes.

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

A formal RBAC framework (Casbin, oso, cerbos) would replace a few
small composable mechanisms with one large generic one — and violate
the project's no-framework dependency posture in the process.

The right framing: this is **declarative authorship policy**. The
helpers in `authz.go` are the abstraction; this document is the policy.

---

## §6. Adding a new write tool

When you add a tool that mutates state, decide which axes apply:

1. Is the operation reserved for the human owner?
   → First ask whether it belongs on the MCP surface at all. Post-MCP-v3,
   the answer for high-commitment and publication operations is "no — it
   goes to admin HTTP" (see §7). If a human-only MCP tool is genuinely
   warranted, gate it with `requireExplicitHuman`.
2. Is the entity domain-owned by a subset of cowork agents?
   → `requireAuthor` with the allowlist.
3. Does the operation only make sense on the caller's own row?
   → Inline `caller == row.created_by` (or `target`) check.

Add the tool to the matrix in §3, add a one-paragraph rationale in §4
if the rule is non-obvious, and add gate tests in `internal/mcp/authz_test.go`.

If a new axis is needed (e.g. quota, time-window), add it as a new
helper in `authz.go` rather than overloading an existing one — the
axes are orthogonal by design.

---

## §7. Where the removed write tools went (MCP-v3 migration map)

The MCP-v3 semantic contraction moved every commitment-creation and
content-authoring operation off the agent surface and onto admin-only
HTTP POST endpoints. Those endpoints sit behind `adminMid` (JWT auth +
per-request actor tx) in `cmd/app/routes.go`, so they are human-gated by
construction — there is no `as`-field path to them. The agent-facing
`propose_* → commit_proposal` two-phase flow is gone; the human now
creates these entities directly through the admin UI.

| Removed MCP tool(s) | Replacement |
|---|---|
| `propose_goal` / `commit_proposal(goal)` | `POST /api/admin/commitment/goals` |
| `propose_milestone` / `commit_proposal(milestone)` | `POST /api/admin/commitment/goals/{id}/milestones` |
| `propose_learning_plan` / `commit_proposal(learning_plan)` | `POST /api/admin/learning/plans` |
| `propose_learning_domain` / `commit_proposal(learning_domain)` | `POST /api/admin/learning/domains` |
| `propose_project`, `propose_hypothesis`, `propose_directive` | No agent-facing replacement (project/hypothesis are admin HTTP; the directive/coordination triad was retired) |
| `create_content` / `update_content` | `POST` / `PUT /api/admin/knowledge/content` |
| `set_content_review_state` | `POST /api/admin/knowledge/content/{id}/submit-for-review` · `/revert-to-draft` |
| `archive_content` | `POST /api/admin/knowledge/content/{id}/archive` |
| `publish_content` | `POST /api/admin/knowledge/content/{id}/publish` |
| `update_note_maturity` | Folded into `update_note` (MCP) and `POST /api/admin/knowledge/notes/{id}/maturity` (admin) |
| `advance_work` | `POST /api/admin/commitment/todos/{id}/advance` |
| `manage_feeds` | `POST` / `PUT` / `DELETE /api/admin/knowledge/feeds` |
| `assign_research` / `create_report` (report lane) | Retired — no replacement |
| `acknowledge_directive` / `file_report` / `task_detail` / `request_revision` / `reaccept` (A2A triad) | Retired — no replacement |
| `write_agent_note` / `query_agent_notes` | Retired — agent memory lives in the agent's own `.md` |

Because every replacement is human-gated at the HTTP layer, the authz
model no longer needs Platform (`requireExplicitHuman`) rows on the MCP
surface — that concern crossed the boundary into admin HTTP along with
the tools.
