# Decision Policy — Quick Reference

## Intent classification (first match wins)

| Signal | Action |
|---|---|
| Question ("what / show / how is") | Read-only query tool |
| Reference to existing entity | Transition / update on that entity |
| Active learning session exists | `record_attempt` / `end_session` |
| Capture impulse ("add / remind me / 記一下") | `capture_inbox` |
| Commitment intent ("create goal / plan project") | `propose_commitment` |
| Reflection intent ("how did today go / 反思") | `write_agent_note` or `propose_commitment(type=hypothesis)` |
| Learning intent ("let's practice / 開始學") | `start_session` |

## Maturity gate

| Level | Indicators | Allowed actions |
|---|---|---|
| M0 | vague, exploratory, no outcome | Conversation only — write nothing |
| M1 | direction exists, missing specifics | `capture_inbox` or `write_agent_note(kind=plan)` |
| M2 | outcome + rough scope | `propose_commitment` — AI fills defaults |
| M3 | specific, time-bound, complete | `propose_commitment` — fast approval |

If uncertain between two levels, pick the lower one.

## Proposal-first entities

Always `propose_commitment` → user confirm → `commit_proposal`:

- Goal
- Project
- Milestone
- Hypothesis
- Learning plan (shell)
- Learning domain (runtime-added; 5 core domains are seeded at bootstrap)

## Direct-commit entities

- Todo (inbox) — `capture_inbox`
- Agent note — `write_agent_note`
- Daily plan entry — `plan_day`
- Attempt + observation — `record_attempt` (within active session)
- Learning session start — `start_session`
- Plan entries (into existing plan) — `manage_plan(add_entries)`

## Never via MCP

- Area (human life decision)
- Agent registry row (reconciled from `BuiltinAgents()` at startup)
- Review card / review log (FSRS-managed)
- `activity_events` (written only by AFTER triggers on covered tables)

## Concept auto-creation boundary

Auto-create allowed in `record_attempt` if ALL:

- Leaf concept (no children)
- Same domain as active session
- Kind inferable from context (pattern / skill / principle)
- No `parent_id` being set

Otherwise → `propose_commitment`.

## Observation confidence

`confidence` is a label, not a gate. Mark honestly:

- **high** — directly evidenced by attempt outcome, user-stated gap, behavior-confirmed
- **low** — coach-inferred, user didn't name it, uncertain severity

3-observation floor: a concept with fewer than 3 filtered observations
always reports `developing`, regardless of signal mix. Marking a signal
`low` cannot lift a concept out of `developing` under the default
`confidence_filter=high` read.

## Plan entry completion (mandatory fields)

When Claude marks a plan entry completed via
`manage_plan(action=update_entry, status=completed)`, you MUST provide:

- `completed_by_attempt_id` — the attempt that informed the decision
- `reason` — attempt outcome + reasoning

Both are required. A completion without them is a policy violation.
