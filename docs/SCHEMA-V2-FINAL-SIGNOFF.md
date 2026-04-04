# Schema v2 — Final Sign-Off

**Date**: 2026-04-05
**Status**: Signed off (v2.2: four-party final review fixes applied)
**Reviewers**: Koopa (owner), Claude Code (Opus 4.6), Claude Web (Opus 4.6), ChatGPT, Codex, Gemini
**Migration**: `migrations/001_initial.up.sql` (clean slate rewrite + learning analytics extension)

---

## Schema Statistics

| Metric | Count |
|--------|-------|
| Tables | 46 (39 base + 7 learning analytics) |
| Existing tables modified | 1 (review_cards: unified FSRS target) |
| Views | 0 (telemetry offloaded to Loki/Grafana) |
| Enums (CREATE TYPE) | 11 |
| Indexes | 114 |
| Seed data INSERTs | 2 (platform: 4 rows, participant: 8 rows) |

---

## Conceptual Anchor

This schema is a **PARA + GTD domain model with goal progress checkpoints**.

| Framework | Coverage | Schema Entities |
|-----------|----------|----------------|
| **PARA** Projects | ✅ | `projects` |
| **PARA** Areas | ✅ | `areas` (first-class entity, FK from goals/projects) |
| **PARA** Resources | ✅ | `notes`, `contents`, `feeds`, `feed_entries`, `tags`, `topics` |
| **PARA** Archives | ✅ | Status-based archiving across tables + partial indexes |
| **GTD** Capture / Inbox | ✅ | `task_status = 'inbox'` |
| **GTD** Next Actions | ✅ | `task_status = 'todo'` + `daily_plan_items` |
| **GTD** Waiting For | ✅ | `tasks WHERE assignee != 'human' AND status != 'done'` (query-based) |
| **GTD** Someday/Maybe | ✅ | `task_status = 'someday'` |
| **GTD** Calendar | ✅ | `tasks.due` (expandable to Google Calendar) |
| **GTD** Weekly Review | ✅ | `participant_schedules` (HQ Weekly Review) |
| **GTD** Engage by energy/priority | ✅ | `tasks.energy`, `tasks.priority` |
| **Goal tracking** Objectives | ✅ | `goals` (planning objectives) |
| **Goal tracking** Checkpoints | ✅ | `milestones` (binary completion, NOT OKR Key Results) |
| **Goal tracking** Alignment | ✅ | `goals → milestones`, `goals → projects` (siblings) |

| **Learning Analytics** Concept ontology | ✅ | `concepts` (pattern/skill/principle, hierarchy via parent_id) |
| **Learning Analytics** Learning targets | ✅ | `learning_items` (independent from notes, domain-agnostic) |
| **Learning Analytics** Attempt tracking | ✅ | `attempts` (outcome, duration, approach), `attempt_observations` (weakness/improvement/mastery signals) |
| **Learning Analytics** Session orchestration | ✅ | `learning_sessions` (distinct from journal post-hoc reflection) |
| **Learning Analytics** Variation graph | ✅ | `item_relations` (easier_variant, prerequisite, same_pattern, etc.) |
| **Learning Analytics** Spaced repetition | ✅ | `review_cards` unified target (content_id OR learning_item_id, FSRS target-agnostic) |

**What this is NOT**: This is not an OKR engine. Milestones are binary checkpoints (done/not-done), not quantitative Key Results with target_value/current_value. The comment in `milestones` explicitly states this. Learning analytics computes mastery as derived state from attempt_observations, not as a stored snapshot table.

---

## Design Review Phases

| Phase | Date | Scope | Reviewers |
|-------|------|-------|-----------|
| 1 | 2026-04-02 | IPC split (directives/reports/journal/insights), participant identity model, topic normalization, table renames | Design Review Board + Claude Code + third-party |
| 2 | 2026-04-03 | Participant capabilities (5 boolean flags), participant_schedules + schedule_runs | Koopa + Claude Code |
| 3 | 2026-04-03~04 | daily_plan_items (replaces tasks.my_day), milestones (goal checkpoints) | Koopa + Claude Code + Claude Web |
| 4 | 2026-04-04 | PARA/GTD/OKR gap analysis: areas table, task_status expansion (inbox/someday), tasks.created_by, goal_status on-hold | Koopa + Claude Code + ChatGPT |
| 5 | 2026-04-04 | Semantic cleanup: remove UB 3.0 references, downgrade Notion to sync concern, honest naming | Koopa + Claude Code + Claude Web + ChatGPT |
| 6 | 2026-04-04 | Learning Analytics Engine: 7 new tables (concepts, learning_items, learning_item_concepts, learning_sessions, attempts, attempt_observations, item_relations) + review_cards unified target | Koopa (adjudicator) + Claude + ChatGPT + Gemini + Claude Code |

---

## Key Design Decisions

### Identity & IPC

| Decision | Chose | Rejected | Why |
|----------|-------|----------|-----|
| Actor model | `platform → participant` hierarchy | Flat participant table | Platform groups participants, capability flags replace hard-coded checks |
| IPC tables | Separate directives/reports/journal/insights | Single session_notes | Different lifecycles, routing, retention policies |
| Routing | Capability flags on participant | Platform-name checks / routing_policies table | Current rules are per-participant, not per-pair |

### Planning & Execution

| Decision | Chose | Rejected | Why |
|----------|-------|----------|-----|
| Daily planning | `daily_plan_items` table | `tasks.my_day` boolean | Boolean lacks date dimension, ordering, source tracking, rollover |
| Plan item status | planned → done \| deferred \| dropped | Two-state (planned/done) | Need to distinguish "carry over" from "removed" |
| Re-plan | INSERT ON CONFLICT DO UPDATE | Insert new row | One task, one row per day invariant |
| Rollover | Cron auto-defer + auto-populate | Manual only | Match existing cron behavior, reduce operational burden |
| Task lifecycle | inbox → todo/someday → in-progress → done | Three-state (todo/in-progress/done) | GTD requires Capture (inbox) and Someday/Maybe |
| Task origin | `created_by` FK to participant | No tracking | GTD capture requires knowing who/what brought tasks in |

### Goal Tracking

| Decision | Chose | Rejected | Why |
|----------|-------|----------|-----|
| Milestone model | Binary completion checkpoints | OKR Key Results with metrics | Personal system — binary sufficient, quantitative is team OKR |
| Milestone → Goal | Advisory (display progress, manual status) | Auto-derive goal status | Strategic decisions by human, not automated |
| Goal pause | `on-hold` status (resumable) | Only `abandoned` (terminal) | PARA archive = pause, not abandon |
| Areas | First-class `areas` table | Free-form `area TEXT` | PARA defines Areas as entities, not labels |

### Semantic Sovereignty

| Decision | Chose | Rejected | Why |
|----------|-------|----------|-----|
| Schema identity | PARA + GTD domain model | UB 3.0 PostgreSQL projection | Schema defines its own world view, Notion is sync concern |
| `notion_page_id` comments | "Sync identifier for external systems" | "Notion page ID for bidirectional sync" | Model sovereignty — Notion is a connector, not the domain |
| Milestone comments | "Goal progress checkpoints" | "Follows UB 3.0 model" | Honest naming — this is not UB 3.0 |
| Notes comment | "Major class of PARA resources" | "PARA Resources" | Notes are one resource type, not all resources |

---

## Upgrade Paths (documented in schema comments)

| Trigger | Upgrade | Where |
|---------|---------|-------|
| Second provider for same role | `sources` UNIQUE(role) → UNIQUE(provider, role) | `sources` table comment |
| Gmail/Calendar event type explosion | `event_type` ENUM → TEXT + CHECK | `events.event_type` column comment |
| Pair-specific routing needed | `routing_policies` table | `docs/PARTICIPANT-CAPABILITIES-AND-SCHEDULES.md` |
| Quantitative goal metrics needed | Add target_value/current_value to milestones or rename to key_results | `milestones` table comment |
| Multiple learning contexts per domain | Promote `domain` TEXT to `learning_tracks` entity | `docs/LEARNING-ANALYTICS-SCHEMA-DESIGN.md` §5.1 |

---

## Source of Truth

| Artifact | Path |
|----------|------|
| Schema DDL | `migrations/001_initial.up.sql` |
| Seed data | `migrations/002_seed.up.sql` |
| Go implementation guide | `docs/GO-IMPLEMENTATION-GUIDE.md` |
| Column-by-column audit | `docs/SCHEMA-V2-COLUMN-AUDIT.md` (pending) |
| IPC design history | `docs/ipc protocol decision doc final.md` |
| Participant capabilities | `docs/PARTICIPANT-CAPABILITIES-AND-SCHEDULES.md` |
| Learning analytics design | `docs/LEARNING-ANALYTICS-SCHEMA-DESIGN.md` |

---

## Four-Party Final Review (2026-04-05)

| Reviewer | Scope | Verdict |
|----------|-------|---------|
| Claude Code (Opus 4.6) | Learning-only + Full 001 | Approve with minor fixes |
| Codex | Learning-only + Full 001 | Approve with minor fixes |
| ChatGPT | Learning-only + Full 001 | Approve with minor fixes |
| Claude Web (Opus 4.6) | Learning-only + Full 001 | Approve with minor fixes |

All fixes from the four-party review have been applied (2026-04-05):
- 7 DDL constraint/FK fixes (down migration ordering, participant RESTRICT, schedule_runs CHECK, reports SET NULL, project_aliases NOT NULL, review_queue bidirectional, learning_item_concepts created_at)
- 8 new indexes (goals.area_id, projects.area_id, directives unacked, tasks assignee/created_by, feed_entries unread relevance)
- 12 comment additions/fixes (flow_runs full coverage, review_cards.tag_id cascade reasoning, note_tags/event_tags table comments, review_queue columns, attempts append-only, notes nullable rule, search_vector config, feed_entries columns, notes.source clarification, cross-domain/contradiction invariants)
- Document statistics synced

---

## Outdated Docs (removed or superseded)

| Doc | Status | Superseded By |
|-----|--------|--------------|
| `docs/AUDIT-REPORT-2026-03-30.md` | Historical — initial project audit | This sign-off doc |
| `docs/DATABASE-AUDIT-2026-03-31.md` | Historical — pre-v2 database audit | This sign-off doc |
| `docs/SCHEMA-AUDIT-2026-04-02.md` | Historical — drove v2 decisions | This sign-off doc |
| `docs/SCHEMA-V2-COLUMN-AUDIT.md` | Superseded — column comments now inline in DDL | `001_initial.up.sql` COMMENT ON COLUMN statements |
| `docs/SCHEMA-V2-MIGRATION-IMPACT.md` | Active — Go/MCP impact analysis | `GO-IMPLEMENTATION-GUIDE.md` is the primary reference |
| `docs/REVIEW-PROMPT-LEARNING-ANALYTICS.md` | Removed (04-05) | Review completed, prompt served its purpose |

---

## Next Steps

1. **DB reset + apply migrations** — VPS
2. **Go refactoring** — follow `GO-IMPLEMENTATION-GUIDE.md`
3. **MCP tool updates** — follow implementation guide §3
4. **Cron pipeline rewrite** — follow implementation guide §4
5. **Cowork instructions update** — after MCP tools are finalized
