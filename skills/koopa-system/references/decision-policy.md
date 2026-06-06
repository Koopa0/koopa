# Decision Policy — Quick Reference

## Intent classification (first match wins)

| Signal | Action |
|---|---|
| Question ("what / show / how is") | Read-only query tool (`brief`, `search_knowledge`, `learning_read`) |
| Reference to existing entity | Transition / update on that entity (`manage_plan(update_entry)`, `update_note`) |
| Active learning session exists | `record_attempt` / `end_session` |
| Capture impulse ("add / remind me / 記一下") | `capture_inbox` |
| Commitment intent ("create goal / plan project") | 對話起草 → 請 Koopa 在 admin 表單建立（no MCP propose tool） |
| Reflection intent ("how did today go / 反思") | 寫進 agent 自己的 `.md`（agent_notes feature 已退役） |
| Learning intent ("let's practice / 開始學") | `start_session` |

## Maturity gate

| Level | Indicators | Allowed actions |
|---|---|---|
| M0 | vague, exploratory, no outcome | Conversation only — write nothing |
| M1 | direction exists, missing specifics | `capture_inbox`，或記進 agent 自己的 `.md` |
| M2 | outcome + rough scope | 對話起草 commitment 草稿 → 請 Koopa 在 admin 表單建立 |
| M3 | specific, time-bound, complete | 同上 — 草稿完整，Koopa 在 admin 表單快速建立 |

If uncertain between two levels, pick the lower one.

## Commitment entities — admin HTTP forms only (no MCP)

高承諾實體不在 MCP surface；agent 在對話中起草，Koopa（human）在 admin 表單建立：

| Entity | Admin form |
|---|---|
| Goal | `POST /api/admin/commitment/goals` |
| Milestone | `POST /api/admin/commitment/goals/{id}/milestones` |
| Project | `POST /api/admin/commitment/projects` |
| Hypothesis | admin 表單（`/api/admin/learning/hypotheses/*`） |
| Learning plan (shell) | `POST /api/admin/learning/plans` |
| Learning domain (5 core domains seeded at bootstrap) | `POST /api/admin/learning/domains` |

## Direct-commit entities (MCP)

- Todo (inbox) — `capture_inbox`
- Daily plan entry — `plan_day`
- Attempt + observation — `record_attempt` (within active session)
- Learning session start — `start_session`
- Note (Zettelkasten) — `create_note` / `update_note`
- Plan entries (into existing plan) — `manage_plan(add_entries)`

## Agent memory

agent 的內部敘事、計畫、決策、反思 → 寫進 agent 自己的 `.md` 檔。
這**不是**系統 entity，不經 MCP，不會被 `search_knowledge` 檢索。
跨 session 需被系統檢索的知識 → `create_note`（`notes` 表，slug-addressable）。

## Never via MCP

- Area (human life decision)
- Goal / project / milestone / hypothesis / learning_plan / learning_domain (admin forms only)
- Content 發布生命週期 (admin HTTP only)
- Agent registry row (reconciled from `BuiltinAgents()` at startup)
- `activity_events` (written only by AFTER triggers on covered tables)

## Concept auto-creation boundary

Auto-create allowed in `record_attempt` if ALL:

- Leaf concept (no children)
- Same domain as active session
- Kind inferable from context (pattern / skill / principle)
- No `parent_id` being set

Otherwise → 對話起草，請 Koopa 在 admin 表單建立 hypothesis / 處理 structural concept changes.

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
