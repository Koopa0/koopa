# PARA Semantic Contract

> The **classification / usage** layer for koopa's PARA model (area / goal / project / milestone / todo) and the content layer. The schema `COMMENT`s in `migrations/001_initial.up.sql` are the **grammar** SSOT (what each column means); this document is the **usage** SSOT (which real thing maps to which entity, and why). On any conflict the code wins — `migrations/001_initial.up.sql`, `internal/mcp/ops/catalog.go::All()`, `internal/mcp/authz.go`.
>
> Status: reconciled with live runtime (`project_progress`) and an adversarial gate, 2026-06-23. Real driver = the **internal knowledge-OS loop**, not an external portfolio.

## 1. Two axes

A piece of work sits on two orthogonal axes. The schema gives a project both `area_id` and `goal_id` (both nullable) precisely because these are independent.

| Axis | Question | Entity | State today |
|------|----------|--------|-------------|
| **Life-domain** | which sphere of my life/responsibility | `area` | in use — 6 real domains |
| **Artifact** | which concrete thing I am building | `project` | **dormant — 0 rows** |

Everything is currently tracked as **goals under life-domain areas**. The artifact (project) axis is unused and is only populated when a concrete deliverable needs build-logs or a public case study.

## 2. Entities

- **area** — a sphere of life / ongoing responsibility (a standard to maintain, no completion). PARA-canonical. *Is not* a product line, *is not* a competency label. Koopa's real areas are life-domains (日語, 文學閱讀, ヨルシカ, 工作室與系統, 職涯, 身體).
- **goal** — a finite objective under an area (has `quarter`/`deadline`/`status`). **Owns milestones** (`milestone.goal_id NOT NULL`). This is where a roadmap with checkpoints lives.
- **project** — a concrete execution vehicle / shippable artifact. Has nullable `area_id` and `goal_id`; can be `maintained` (continuous). It is the unit a public case study (`project_profiles`, 1:1) attaches to. A project **cannot own milestones** (they are goal-rooted).
- **milestone** — a binary checkpoint under a goal (`completed_at` = done). Only attaches to a goal.
- **todo** — a GTD work item, optional `project_id` only. `inbox` / `someday` / unclassified are first-class states, not defects. No `goal_id`/`area_id` edge.
- **project_profiles** — the public case-study facet of a project (1:1, independent lifecycle; can be edited after the project completes). Deferred — see §4.

## 3. Koopa's real material → entity (runtime-verified)

| Real thing | Entity | Note |
|------------|--------|------|
| 工作室與系統 / 日語 / 文學閱讀 / ヨルシカ / 職涯 / 身體 | **area** | the 6 real life-domains |
| backend / learning / studio / frontend / career / ops | (dead seeded areas) | unused, overlap the real ones → **cleanup** |
| "koopa0.dev 前後端架構完成、整合進工作流穩定運作" | **goal** (in_progress, under 工作室與系統) | finite objective — correct as a goal; **do not** reclassify to a project |
| reading a book | `reading` (has `goal_id`) | not a todo/project |
| 日語 / kana practice | goal + milestones | |
| obsidian | — | private upstream; not in this model |
| koopa0.dev *as a continuous product* | project (`maintained`) | **deferred** — only when build-logs / portfolio are needed; would link to the goal via `project.goal_id` |
| whetstone / kotonoha | project (each) | deferred with portfolio |

koopa is a single monorepo (`go.mod` module `github.com/Koopa0/koopa`) — one repo, one `github_url`.

## 4. The two loops

**Internal loop (the real need):** agent-assisted content drafting + daily planning + goal execution + periodic reflection. Tracked by area/goal/milestone/todo + `activity_events`.

**External loop:** published **content** (article / essay / build-log / til / digest) via the editorial queue — `propose_content` (agent) or admin draft → `status=review`, `is_public=false` → **owner publishes** in admin. 雜談 / 隨筆 map to `essay` losslessly. The public site renders content; the **projects portfolio is tertiary and dormant** (kept, not invested in).

## 5. Decided

- **No schema change.** The model is semantically sound; existing FKs suffice. Do **not** add `todo→goal/area` edges.
- The classification/usage layer lives here + in judgment, not in extra DB tables.
- External presence = content via review queue. Portfolio = dormant.
- `koopa0.dev` stays a **goal**. A koopa0.dev *project* is deferred (§6).

## 6. Deferred (each behind a tripwire — do not build now)

| Deferred item | Tripwire |
|---------------|----------|
| `koopa0.dev` project entity | when build-logs / a public case study are actually needed |
| Model B — `products` table + `projects.product_id` | when one product fans into 2+ separately-displayable efforts **and** the portfolio goes live |
| `resolve_task` state guard (block terminal-izing an already-adopted todo) | when an orphaned `daily_plan_items` row actually occurs |
| koopa0 `requireAuthor` on `propose_*` (identity allowlist) | when the hermes write-surface tripwire fires, or any wrapper wires `propose_*` |

## 7. Open tool-surface gaps (read-only / additive — **no schema**, validate before building)

Found by the adversarial gate; all are tool-surface, the schema already holds the data.

- **G1 — revise-after-propose.** `propose_content` is one-shot. If iteration happens after proposal (owner sends a draft back), there is no agent update path. *Decide:* iterate in-conversation before proposing (no tool), or add `revise_content`.
- **G2 — content proposal readback.** No analog to `list_tasks` for content: an agent cannot see if its proposal was published / rejected / still in review. Matters for non-conversational agents (hermes).
- **G3 — `propose_content` is project-blind. RESOLVED (2026-06-23): intentional decoupling, not a gap.** Content is the external loop, decoupled from the project/GTD axis. `contents.project_id` is nullable by design; the link is meaningful only for `build-log` and is applied by the owner in admin if/when the portfolio needs it (deferred). The agent content surface deliberately stays project-agnostic — `article`/`essay`/`til`/`digest` (incl. 雜談/隨筆) are standalone writing. Tripwire: revisit only if build-log volume + a live portfolio make manual linking painful.
- **G4 — windowed reflection look-back.** The reflection step ("what did I complete over the last N weeks") has no agent tool. `brief(reflection)` is single-date and depends on `daily_plan_items` existing; `list_tasks` is caller-scoped (can't see the owner's completions); `project_progress` is a current-state snapshot, not a windowed retrospective. The data exists (`activity_events.occurred_at` actor=human, `todos.completed_at`, `milestones.completed_at`); the published-content listing (`internal/content/query.sql`) even already takes a `since` window but is wired only to the public site, not MCP. *Decide:* add a `since`/`window` param to `brief(reflection)` or a small read-only look-back tool, and surface published-content accumulation on the agent surface.

## 8. Data actions (not schema)

- Delete the 6 dead seeded areas (backend / learning / studio / frontend / career / ops) in admin — they overlap the real life-domains.
- Keep `koopa0.dev` as a goal. To make its roadmap ("expose MCP", "ship reflection loop", "v1 architecture") drive the reflection loop, **add milestones to that goal** — milestone progress surfaces via `ActiveGoalMilestones`. (A maintained project is excluded from `project_progress.Momentum` by `WHERE status IN ('in_progress','planned')`, so milestone-shaped roadmap progress must live on the goal, not a project.)

## 9. D-4 — authz resolution

`propose_*` safety is the **inert-draft lifecycle** (`status=proposed`; the owner activates in admin), not caller-gating. All five write tools + `resolve_task` use `requireRegisteredCaller` (the weakest gate; rejects only the `unknown` fallback). authz has no cron-vs-chat axis (an MCP call carries no such signal), so "NEVER from scheduled runs" is prose guidance, not enforced. Blocking the caller would break the intended agent-propose → owner-approve loop. The real guard is detection on the hermes side (audit_write_surface tripwire, hermes commit c81bdd2). koopa0 adds no authz guard now (see §6 tripwire).

---

*Verification: reconciled with live `project_progress` and a 3-angle adversarial gate (koopa0.dev-as-project milestone hole, internal-loop sufficiency, content-collab completeness), all re-derived from source. Authorities remain the code: `migrations/001_initial.up.sql`, `internal/mcp/ops/catalog.go::All()`, `internal/mcp/authz.go`.*
