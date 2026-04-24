# MCP Tool Quick Reference

24 tools, organized by workflow.

## Query Tools (7, readOnly)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `morning_context` | 每日啟動：overdue todos, today todos, unacknowledged directives, pending artifacts, RSS highlights, unverified hypotheses | `sections?`, `date?` |
| `reflection_context` | 晚間回顧：planned vs actual, agent notes | `date?` |
| `search_knowledge` | 跨類型搜尋：articles, build logs, TILs, notes | `query`, `content_type?`, `project?`, `limit?`, `after?`, `before?` |
| `goal_progress` | 目標 + 里程碑進度 | `area?`, `status?` |
| `learning_dashboard` | 學習分析（6 views） | `domain?`, `view?`, `window_days?` (mastery defaults to 60, others 30, range 1..365), `confidence_filter?` (mastery/weaknesses only: `"high"` default, `"all"` opt-in) |
| `attempt_history` | Per-item / per-concept / per-session attempt history (Improvement Verification Loop) | one of `item{title, domain?}` / `concept_slug` / `session_id`; `max_results?` |
| `system_status` | Pipeline health, feed health, process_runs by kind (flow / agent_schedule / drift_check) | `scope?` |

### learning_dashboard views

| View | Returns |
|------|---------|
| `overview` (default) | Recent sessions list |
| `mastery` | Per-concept signal counts + derived stage (struggling/developing/solid). < 3 filtered observations → always developing. |
| `weaknesses` | Cross-pattern weakness analysis (category + severity) |
| `retrieval` | Due FSRS review items |
| `timeline` | Sessions + attempts by day |
| `variations` | Item relation graph (easier/harder/prerequisite) |

### attempt_history modes

Exactly one of the three required. Not-found returns `resolved: false` with empty attempts — "never attempted" is a legal answer, not an error.

| Mode | Input | Returns | Use case |
|------|-------|---------|----------|
| `item` | `{title, domain?}` | attempts on this specific problem, newest-first | "How did he do this problem last time?" — Improvement Verification Loop |
| `concept` | `concept_slug` (+ `domain?`) | attempts that observed the concept, each with the matched observation inline (signal/category/severity/detail) | "What's his history with binary-search?" |
| `session` | `session_id` | all attempts in that session, chronological | "What did I do in yesterday's session?" |

### search_knowledge query syntax

Uses PostgreSQL `websearch_to_tsquery('simple', query)`. Supports:
- **Quoted phrases**: `"value semantics"` — exact phrase match
- **AND** (default): `Go generics` — both words must appear
- **OR**: `goroutine OR channel` — either word
- **Exclusion**: `-draft` — exclude results containing "draft"
- **Fallback**: if the primary query returns nothing, retries with OR semantics across all words

Empty results mean "not found in published content" — not a query syntax issue.

## Capture & Structuring (3)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `capture_inbox` | Quick task capture (title only required) | additive |
| `propose_commitment` | Propose goal / project / milestone / directive / hypothesis / learning_plan / learning_domain → returns preview + token. Missing required fields reject at propose-time (no token emitted). `learning_domain` needs `slug` (kebab-case, `^[a-z][a-z0-9-]*$`) + `name`. | readOnly |
| `commit_proposal` | Submit token → writes to DB | additive |

## Execution (4)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `advance_work` | Todo transitions: clarify, start, complete, defer, drop | destructive |
| `plan_day` | Set daily plan items (idempotent: replaces) | additiveIdempotent |
| `file_report` | Create report, optionally linked to directive via `in_response_to` | additive |
| `acknowledge_directive` | Mark directive received (target agent only) | additiveIdempotent |

## Learning (3 write + 2 read elsewhere)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `start_session` | Begin learning session (domain + mode) | additive |
| `record_attempt` | Record attempt with outcome + observations. Accepts `metadata` (free-form JSON for 8-step checklist output), `fsrs_rating` (explicit recall difficulty override), `related_targets[]` (variation graph links — same-domain only). **All observations persist** — `confidence` is a label (`"high"` default / `"low"`), not a gate. | additive |
| `end_session` | End session, optional reflection stored as agent_note | additive |

Read-side counterparts: `learning_dashboard` and `attempt_history` (see Query Tools).

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
| `write_agent_note` | Agent note: plan / context / reflection | additive |
| `track_hypothesis` | Update hypothesis: verify / invalidate / archive / add_evidence | additiveIdempotent |

## Content & Feed (2)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `manage_content` | Content lifecycle across 6 types (article / essay / build-log / til / digest / note). Actions: create / update / publish / list / read / bookmark_rss. **`bookmark_rss` is currently pending rewire** — it returns `bookmark_rss: rewire pending — needs bookmark.Store.Create injection` until the bookmark store is wired. Other 5 actions are production-ready. | additive |
| `manage_feeds` | RSS feeds: list / add / update / remove | additive |

### manage_content actions

| Action | Purpose |
|---|---|
| `create` | Insert a draft. `title` + `content_type` required. For `content_type='note'`, also pass `note_kind` (solve-note / concept-note / debug-postmortem / decision-log / reading-note / musing); `maturity` defaults to `seed`. Optional `learning_target_id` atomically sets `learning_targets.content_id` in the same tx (solve-note workflow). Optional `concept_slugs[]` links rows via `content_concepts` junction (concept-note workflow) — unknown slugs reject pre-tx. Slug defaults to title-derived when omitted. |
| `update` | Mutate fields on an existing row by `content_id`. Every field is optional; validates the closed sets for `content_type`, `status`, `note_kind`, `maturity` when provided. Changing `slug` goes through the same conflict-detection path as `create`. |
| `publish` | Atomically set `status='published'`, `is_public=true`, `published_at=now()`. Requires `content_id`. Do NOT use `update` to publish — it breaks the `chk_content_publication` invariant. |
| `list` | Filter contents by `status` / `content_type` with a `limit`. Returns lightweight summaries. |
| `read` | Return full content + tags by `content_id`. |
| `bookmark_rss` | Curate an RSS entry into a bookmark. Requires `entry_id` (and `comment` for annotation). **Pending rewire** — currently returns `ErrBookmarkRSSPending`. |

### manage_content response envelope

- Normal success: `{action, content, content_warnings[]}`.
- Slug collision: `{action, slug_conflict: {slug, content_id}}` returned **without error** so the caller can decide to retry with `action=update` or pick a new slug.
- Soft warnings in `content_warnings[]`:
  - `missing_target` — note_kind=solve-note created without `learning_target_id`
  - `missing_concepts` — note_kind=concept-note created without `concept_slugs`

## Cross-session (2, readOnly)

| Tool | Purpose | Key Params |
|------|---------|------------|
| `session_delta` | What happened since last session | `since?` (YYYY-MM-DD) |
| `weekly_summary` | Week review: todos, agent notes, sessions, mastery | `week_of?` (Monday) |

## Learning Plan Management (1)

| Tool | Purpose | Annotation |
|------|---------|------------|
| `manage_plan` | Plan lifecycle: add_entries / remove_entries / update_entry / reorder / update_plan / progress | additive |

### manage_plan actions

| Action | Purpose |
|---|---|
| `add_entries` | Add learning_plan_entries to a learning plan |
| `remove_entries` | Remove entries from plan (draft only) |
| `update_entry` | Update entry status (completed / skipped / substituted). Completed MUST include `completed_by_attempt_id` + `reason` |
| `reorder` | Reorder plan entries |
| `update_plan` | Change plan status (draft → active → completed / paused / abandoned) |
| `progress` | Read-only: view plan completion progress + entry list |

## Annotation Legend

| Annotation | Meaning |
|------------|---------|
| `readOnly` | No state change |
| `additive` | Creates new records, never modifies existing |
| `additiveIdempotent` | Safe to retry, same result |
| `destructive` | Modifies existing state |
