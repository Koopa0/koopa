# IPC Protocol — Cross-Participant Coordination

## Participants

| Name | Platform | Capabilities |
|------|----------|-------------|
| `hq` | claude-cowork | issue directives, write reports, task assignable, own schedules |
| `content-studio` | claude-cowork | issue directives, receive directives, write reports, task assignable, own schedules |
| `research-lab` | claude-cowork | issue directives, receive directives, write reports, task assignable, own schedules |
| `learning-studio` | claude-cowork | receive directives, write reports, task assignable |
| `koopa0.dev` | claude-code | task assignable |
| `human` | human | everything |

## Four IPC Channels

### 1. Directives (source → target)

Cross-participant instructions with accountability.

**Lifecycle:** `issued → acknowledged → resolved`

| Phase | Tool | Who |
|-------|------|-----|
| Issue | `propose_commitment(type=directive)` → `commit_proposal` | Source (must have `can_issue_directives`) |
| Acknowledge | `acknowledge_directive(directive_id)` | Target (must have `can_receive_directives`) |
| Resolve | `file_report(in_response_to=directive_id)` with resolution flag | Source or target |

**Rules:**
- Must be acknowledged before resolved (`chk_resolved_requires_ack`)
- `resolution_report_id` links to final deliverable report
- Priority: P0 (immediate), P1 (today), P2 (this week)
- Cannot self-issue (source ≠ target)

### 2. Reports (source → optional directive)

Structured deliverables.

| Field | Purpose |
|-------|---------|
| `content` | Report body (markdown) |
| `source` | Who wrote it (auto from `as`) |
| `in_response_to` | Directive ID (optional — self-initiated reports have no directive) |

**Tool:** `file_report`

Self-initiated reports (no directive) are read by HQ during morning briefing.

### 3. Journal (self)

Self-directed records. Not cross-participant.

| Kind | Purpose | When |
|------|---------|------|
| `plan` | Daily plan reasoning | Morning |
| `context` | Session context snapshot | Session end |
| `reflection` | Retrospective | Evening |
| `metrics` | Quantitative snapshot | AI-generated |

**Tool:** `write_journal`

**Routing rule:** Human entries with narrative → `reflection`. Pure quantitative → `metrics` (primarily AI-generated).

### 4. Insights (self → shared)

Trackable hypotheses with falsification conditions.

**Lifecycle:** `unverified → verified | invalidated → archived`

**Required fields:**
- `hypothesis` — testable claim
- `invalidation_condition` — what would prove it wrong
- `content` — insight description (proposal warns if missing, commit rejects without it)

**Tool:** `propose_commitment(type=insight)` → `commit_proposal` → `track_insight(action=verify|invalidate|archive|add_evidence)`

**Not insights:** "今天效率不錯" (no hypothesis). "最近 DP 做得不好" (feeling, not testable).

## Common Coordination Patterns

### HQ delegates to Content Studio
```
HQ: propose_commitment(type=directive, target=content-studio, content="寫一篇...")
HQ: commit_proposal(token)
Content: acknowledge_directive(directive_id)
Content: [work]
Content: manage_content(action=create, ...)
Content: file_report(in_response_to=directive_id, content="報告...")
```

### HQ delegates to Research Lab
```
HQ: propose_commitment(type=directive, target=research-lab, content="研究...")
HQ: commit_proposal(token)
Research: acknowledge_directive(directive_id)
Research: [research + external sources]
Research: file_report(in_response_to=directive_id, content="完整研究報告...")
```

### Learning Studio reports to HQ
```
Learning: [session ends with significant findings]
Learning: write_journal(kind=context, content="session summary...")
Learning: file_report(content="學習成果報告: ...")
HQ: [reads in next morning_context]
```
