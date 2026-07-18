# Decision Policy — Quick Reference

## Intent classification (first match wins)

| Signal | Action |
|---|---|
| Question ("what / show / how is") | Read-only query tool (`brief`, `list_todos`, `list_content`, `review_period`, `project_progress`) |
| Capture impulse ("add / remind me / 記一下") | `capture_inbox` |
| Plan today | `plan_day`（候選 plan） |
| Recurring habit ("每天 / Mon-Sat / 每 N 天做") on a todo you created | `set_todo_recurrence`（週幾 mon..sun 或 interval+unit;clear 取消）— 之後每逢符合日進 brief，`resolve_todo` done 完成當日 occurrence |
| Commitment intent ("create area / goal / project") | `propose_area` / `propose_goal` / `propose_project`（inert draft，Koopa 在 admin activate） |
| Finished content piece ("這篇可以推") | `propose_content`（進審核佇列，Koopa 在 admin publish / reject） |
| Self-clear a todo you created | `resolve_todo`（done / archived / dismissed） |
| Reflection intent ("how did today go / 反思") | 寫進 agent 自己的 `.md` |

## Maturity gate

| Level | Indicators | Allowed actions |
|---|---|---|
| M0 | vague, exploratory, no outcome | Conversation only — write nothing |
| M1 | direction exists, missing specifics | `capture_inbox`，或記進 agent 自己的 `.md` |
| M2 | outcome + rough scope | `propose_area` / `propose_goal` / `propose_project`（inert draft），Koopa 在 admin activate |
| M3 | specific, time-bound, complete | 同上 — draft 完整，Koopa 在 admin 快速 activate |

If uncertain between two levels, pick the lower one.

## Commitment proposals (MCP inert draft → admin activate)

agent 用 `propose_*` 起草 inert draft（`status=proposed`，完全惰性 — 不進 brief / Today / active 讀取）；activate（proposed→active / in_progress）與 reject（hard delete）全在 admin，由 Koopa（human）完成。只 materialize Koopa 參與過的對話 — 絕不來自排程執行：

| Entity | MCP draft tool | Activate |
|---|---|---|
| Area | `propose_area` | admin triage（proposed→active；reject cascade 其 proposed 子 goal） |
| Goal（連帶 milestones） | `propose_goal` | admin triage（proposed→in_progress；reject 連帶 milestones cascade） |
| Project | `propose_project` | admin triage（proposed→in_progress；reject 後 todo 解除連結存活） |
| Milestone（獨立） | 對話起草 | `POST /api/admin/commitment/goals/{id}/milestones` |

## Direct-commit entities (MCP)

- Todo (inbox) — `capture_inbox`
- Daily plan entry — `plan_day`
- Finished content into the review queue — `propose_content`（lands `status=review`，Koopa 在 admin publish / reject）

## Agent memory

agent 的內部敘事、計畫、決策、反思 → 寫進 agent 自己的 `.md` 檔。
這**不是**系統 entity，也不經 MCP。知識寫作與檢索留在 Obsidian／Yomihon。

## Never via MCP

- Milestone 建立（admin form only）
- Commitment activation（area / goal / project 的 activate / reject 在 admin triage）
- Content 發布生命週期（`propose_content` 只進審核佇列；publish 是 admin HTTP）
- Agent registry row (reconciled from `BuiltinAgents()` at startup)
- `activity_events` (written only by AFTER triggers on covered tables)
