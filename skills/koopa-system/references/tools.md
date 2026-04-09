# MCP Tool Quick Reference

22 tools, organized by workflow.

## Query Tools (6, readOnly)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `morning_context` | 每日啟動：overdue tasks, today tasks, unacked directives, pending reports, RSS highlights | `sections?`, `date?` |
| `reflection_context` | 晚間回顧：planned vs actual, journals | `date?` |
| `search_knowledge` | 跨類型搜尋：articles, build logs, TILs, notes | `query`, `content_type?`, `project?`, `limit?` |
| `goal_progress` | 目標 + 里程碑進度 | `area?`, `status?` |
| `learning_dashboard` | 學習分析（6 views） | `domain?`, `view?`, `days?` |
| `system_status` | Pipeline health, feed health, flow runs | `scope?` |

### learning_dashboard views

| View | Returns |
|------|---------|
| `overview` (default) | Recent sessions list |
| `mastery` | Per-concept weakness/improvement/mastery counts |
| `weaknesses` | Cross-pattern weakness analysis (category + severity) |
| `retrieval` | Due FSRS review items |
| `timeline` | Sessions + attempts by day |
| `variations` | Item relation graph (easier/harder/prerequisite) |

## Capture & Structuring (3)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `capture_inbox` | Quick task capture (title only required) | additive |
| `propose_commitment` | Propose goal/project/milestone/directive/insight/learning_plan → returns preview + token | readOnly |
| `commit_proposal` | Submit token → writes to DB | additive |

## Execution (4)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `advance_work` | Task transitions: clarify, start, complete, defer, drop | destructive |
| `plan_day` | Set daily plan items (idempotent: replaces) | additiveIdempotent |
| `file_report` | Create report, optionally linked to directive | additive |
| `acknowledge_directive` | Mark directive received | additiveIdempotent |

## Learning (3)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `start_session` | Begin learning session (domain + mode) | additive |
| `record_attempt` | Record attempt with outcome + observations | additive |
| `end_session` | End session, optional reflection journal | additive |

### Outcome semantic mapping (record_attempt)

| Natural language | practice/retrieval mode | reading mode |
|-----------------|------------------------|--------------|
| "got it" | solved_independent | completed |
| "needed help" | solved_with_hint | completed_with_support |
| "saw answer" | solved_after_solution | — |
| "didn't finish" | incomplete | incomplete |
| "gave up" | gave_up | gave_up |

## Reflection (2)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `write_journal` | Journal: plan/context/reflection/metrics | additive |
| `track_insight` | Update insight: verify/invalidate/archive/add_evidence | additiveIdempotent |

## Content & Feed (2)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `manage_content` | Content lifecycle: create/update/publish/bookmark_rss | additive |
| `manage_feeds` | RSS feeds: list/add/update/remove | additive |

## Cross-session (2, readOnly)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `session_delta` | What happened since last session | `since?` (YYYY-MM-DD) |
| `weekly_summary` | Week review: tasks, journals, sessions, mastery | `week_of?` (Monday) |

## Learning Plan Management (1)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `manage_plan` | Plan lifecycle: add_items/remove_items/update_item/reorder/update_plan/progress | additive |

### manage_plan actions

| Action | Purpose |
|--------|---------|
| `add_items` | Add items to a learning plan |
| `remove_items` | Remove items from plan |
| `update_item` | Update item status (completed/skipped/substituted). Completed MUST include `completed_by_attempt_id` + `reason` |
| `reorder` | Reorder plan items |
| `update_plan` | Change plan status (draft→active→completed/paused/abandoned) |
| `progress` | Read-only: view plan completion progress |

## Annotation Legend

| Annotation | Meaning |
|------------|---------|
| `readOnly` | No state change |
| `additive` | Creates new records, never modifies existing |
| `additiveIdempotent` | Safe to retry, same result |
| `destructive` | Modifies existing state |
