# a2a — Agent-to-Agent Coordination

The a2a protocol is how agents coordinate: issue directives, publish artifacts,
acknowledge work, attach deliverables. On-wire format is a2a-go's flattened
Part encoding; persistence is the tasks / task_messages / artifacts tables.

**Naming vs structure**: the words "directive" and "task" at the MCP tool
boundary name the same row. The database has a single `tasks` table with
no kind discriminator. A directive is simply a task whose expected output
is a report (target exercises autonomous judgment). Use `propose_commitment(type=directive)`
when that metaphor fits; call it a "task" in code and activity feeds.
See `.claude/rules/mcp-decision-policy.md §14` for the tool-selection test.

## Agents

| Name | Platform | Capabilities |
|---|---|---|
| `hq` | claude-cowork | SubmitTasks, PublishArtifacts |
| `content-studio` | claude-cowork | SubmitTasks, ReceiveTasks, PublishArtifacts |
| `research-lab` | claude-cowork | SubmitTasks, ReceiveTasks, PublishArtifacts |
| `learning-studio` | claude-cowork | ReceiveTasks, PublishArtifacts |
| `koopa` | claude-code | (dev session) |
| `go-spec` | claude-code | (dev session) |
| `claude` | claude-web | (none) |
| `human` | human | — |

Capability enforcement is compile-time in Go. You cannot call a mutation
method without proof the caller has the matching capability — the check
happens when the call is built, not at runtime.

## The four a2a channels

### 1. Directives (source → target)

Cross-agent instructions with accountability.

**Lifecycle**: `submitted → working → completed | canceled`

| Phase | Tool | Who |
|---|---|---|
| Issue | `propose_commitment(type=directive)` → `commit_proposal` | Source (must have `SubmitTasks`) |
| Acknowledge | `acknowledge_directive(directive_id)` | Target (must have `ReceiveTasks`). Transitions the task to `working`. |
| Resolve | `file_report(in_response_to=directive_id, response_parts=[...], artifact={...})` | Target (must have `CompleteTasks`). Creates a response message + artifact and flips the task to `completed`. |

**Rules**:
- Source ≠ target (no self-issue)
- A task cannot reach `completed` without at least one response message and one artifact — the DB enforces this via trigger.
- Priority: `high` | `medium` | `low` (matches `tasks.priority` CHECK). No P0/P1/P2 alias — the schema has one scale and the MCP layer rejects any other value.

### 2. Artifacts (task-bound or standalone)

Structured deliverables. Two modes:

**Task-bound** (`in_response_to` provided): attaches a response message + artifact to the task, then transitions it to `completed`.

**Standalone** (`in_response_to` omitted): creates an independent artifact attributed to the caller. No task involved.

| Field | Purpose |
|---|---|
| `artifact` | Required. Name + parts (the structured deliverable). |
| `in_response_to` | Task UUID. Omit for self-initiated artifacts. |
| `response_parts` | Response message parts. Required when `in_response_to` is set. |

**Tool**: `file_report`

Standalone artifacts are attributed via `created_by` (auto from `as` field).

### 3. Agent notes (self — not cross-agent)

An agent's own plan / context / reflection log. Append-only. NOT a way
to communicate with other agents — that's what directives are for.

| Kind | Purpose | When |
|---|---|---|
| `plan` | Daily plan reasoning | Morning, after `plan_day` |
| `context` | Session context snapshot | Session end |
| `reflection` | Retrospective | Evening / session end |

**Tool**: `write_agent_note`

**Routing rule** for mixed narrative + metrics input: use `kind=reflection`
and put structured metrics in `metadata`. Pure quantitative snapshots are
rare in human input.

### 4. Hypotheses (self → shared)

Trackable falsifiable claims.

**Lifecycle**: `unverified → verified | invalidated → archived`

**Required fields**:
- `claim` — one-line testable prediction
- `invalidation_condition` — what evidence would disprove it
- `content` — supporting narrative

`propose_commitment` rejects at propose-time if `claim`,
`invalidation_condition`, or `content` is blank or missing — no token
is signed. Commit-side keeps a defensive check that logs
`proposal validator drift` if it ever fires.

**Tools**:
- Create: `propose_commitment(type=hypothesis)` → `commit_proposal`
- Update: `track_hypothesis(action=verify | invalidate | archive | add_evidence)`

**Not a hypothesis**: "今天效率不錯" (no claim). "最近 DP 做得不好"
(feeling, not falsifiable). Both go into `write_agent_note(kind=reflection)`.

## Parts format

Every parts array is a list of a2a.Part JSON objects. Two kinds:

- **text part**: `{"text": "..."}` — a human-readable message fragment
- **data part**: `{"data": {...}}` — a structured payload (parameters, constraints, references)

You can mix both in one array. Example payload for a research directive:

```json
[
  {"text": "Research NATS exactly-once semantics with focus on JetStream consumer groups"},
  {"data": {"deadline": "2026-04-20", "priority": "high", "depth": "exhaustive"}}
]
```

Never hand-roll this shape beyond these two cases. The tools `file_report`,
`propose_commitment(type=directive)`, and related take parts as plain JSON
arrays and the server deserializes through a2a-go at the boundary.

## Common coordination patterns

### HQ delegates to Content Studio

```
HQ:       propose_commitment(type=directive,
            target="content-studio",
            priority="medium",
            request_parts=[{"text": "寫一篇 Go generics best practices 文章"}])
HQ:       commit_proposal(token)
Content:  acknowledge_directive(directive_id)
Content:  [work]
Content:  create_content(...)
Content:  file_report(
            in_response_to=directive_id,
            response_parts=[{"text": "文章已發布: [標題]"}],
            artifact={
              name: "article-delivery",
              parts: [{"data": {"content_id": "...", "slug": "...", "word_count": 2400}}]
            })
```

### HQ delegates to Research Lab

```
HQ:        propose_commitment(type=directive,
             target="research-lab",
             priority="high",
             request_parts=[
               {"text": "Research NATS exactly-once semantics"},
               {"data": {"deadline": "2026-04-20", "depth": "exhaustive"}}
             ])
HQ:        commit_proposal(token)
Research:  acknowledge_directive(directive_id)
Research:  [research + external sources]
Research:  file_report(
             in_response_to=directive_id,
             response_parts=[{"text": "研究完成，摘要在 artifact"}],
             artifact={
               name: "nats-exactly-once-report",
               parts: [{"text": "# Full report\n..."}, {"data": {"sources": [...]}}]
             })
```

### Learning Studio self-reports to HQ

```
Learning:  [session ends with significant findings]
Learning:  end_session(session_id, reflection="...")  # also writes agent_note(kind=reflection)
Learning:  write_agent_note(kind=context, content="session summary...")
Learning:  file_report(
             response_parts=[{"text": "Weekly learning summary"}],
             artifact={
               name: "learning-week-summary",
               parts: [{"data": {"mastery_improved": [...], "weaknesses_remaining": [...]}}]
             })
HQ:        [reads in next morning_context]
```
