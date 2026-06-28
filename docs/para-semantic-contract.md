# PARA Semantic Contract

> The **classification / usage** layer for koopa's PARA model (area / goal / project / milestone / todo) and the content layer. The schema `COMMENT`s in `migrations/001_initial.up.sql` are the **grammar** SSOT (what each column means); this document is the **usage** SSOT (which real thing maps to which entity, and why). On any conflict the code wins — `migrations/001_initial.up.sql`, `internal/mcp/ops/catalog.go::All()`, `internal/mcp/server.go::callerIdentity`.
>
> Status: reconciled with live runtime (`project_progress`) and an adversarial gate, 2026-06-23. Real driver = the **internal knowledge-OS loop**, not an external portfolio.

## 1. Two axes

A piece of work sits on two orthogonal axes. The schema gives a project both `area_id` and `goal_id` (both nullable) precisely because these are independent.

| Axis | Question | Entity | State today |
|------|----------|--------|-------------|
| **Life-domain** | which sphere of my life/responsibility | `area` | in use — 6 real domains |
| **Artifact** | which concrete thing I am building | `project` | **dormant — 0 rows** |

Everything is currently tracked as **goals under life-domain areas**. The artifact (project) axis is unused and is only populated when a concrete deliverable needs build-logs.

## 2. Entities

- **area** — a sphere of life / ongoing responsibility (a standard to maintain, no completion). PARA-canonical. *Is not* a product line, *is not* a competency label. Koopa's real areas are life-domains (日語, 文學閱讀, ヨルシカ, 工作室與系統, 職涯, 身體).
- **goal** — a finite objective under an area (has `quarter`/`deadline`/`status`). **Owns milestones** (`milestone.goal_id NOT NULL`). This is where a roadmap with checkpoints lives.
- **project** — a concrete execution vehicle / shippable artifact. Has nullable `area_id` and `goal_id`; can be `maintained` (continuous). A project **cannot own milestones** (they are goal-rooted).
- **milestone** — a binary checkpoint under a goal (`completed_at` = done). Only attaches to a goal.
- **todo** — a GTD work item, optional `project_id` only. `inbox` / `someday` / unclassified are first-class states, not defects. No `goal_id`/`area_id` edge.

## 3. Koopa's real material → entity (runtime-verified)

| Real thing | Entity | Note |
|------------|--------|------|
| owner-curated life-domains (in prod) | **area** | no default/seeded areas exist; areas are added by the owner in admin and are the correct set |
| "koopa0.dev 前後端架構完成、整合進工作流穩定運作" | **goal** (in_progress, under 工作室與系統) | finite objective — correct as a goal; **do not** reclassify to a project |
| reading a book / a book's notes | — | private; lives in Obsidian, not in this model |
| 日語 / kana practice | goal + milestones | |
| obsidian | — | private upstream; not in this model |
| koopa0.dev *as a continuous product* | project (`maintained`) | **deferred** — only when build-logs are needed; would link to the goal via `project.goal_id` |
| whetstone / kotonoha | project (each) | deferred |

koopa is a single monorepo (`go.mod` module `github.com/Koopa0/koopa`) — one repo, one `github_url`.

## 4. The two loops

**Internal loop (the real need):** agent-assisted content drafting + daily planning + goal execution + periodic reflection. Tracked by area/goal/milestone/todo + `activity_events`.

**External loop:** published **content** (article / essay / build-log / til / digest) via the editorial queue — `propose_content` (agent) or admin draft → `status=review`, `is_public=false` → **owner publishes** in admin. 雜談 / 隨筆 map to `essay` losslessly. The public site renders published content only; the public project portfolio was **removed** (2026-06-23) — built work is shown as content, not a separate portfolio surface.

## 5. Decided

- **No PARA-entity schema change.** The classification model is semantically sound; existing FKs suffice. Do **not** add `todo→goal/area` edges. (Area attribution for the audit log uses a write-time `activity_events.area_id` denormalization — 2026-06-27 — which deliberately does NOT add a `todo→area` PARA edge.)
- The classification/usage layer lives here + in judgment, not in extra DB tables.
- External presence = content via review queue. The public project portfolio was removed (2026-06-23).
- `koopa0.dev` stays a **goal**. A koopa0.dev *project* is deferred (§6).

## 6. Deferred (each behind a tripwire — do not build now)

| Deferred item | Tripwire |
|---------------|----------|
| `koopa0.dev` project entity | when build-logs are actually needed |
| `resolve_todo` state guard (block terminal-izing an already-adopted todo) | when an orphaned `daily_plan_items` row actually occurs |
| ~~koopa0 `requireAuthor` on `propose_*`~~ | **CLOSED by Option B (2026-06)** — no tool-layer authz; the MCP transport is the access boundary, not a per-tool gate |

## 7. Tool-surface gaps (adversarial-gate findings — all RESOLVED 2026-06-23)

Found by the adversarial gate; all were tool-surface (the schema already held the data) and have since shipped.

- **G1 — revise-after-propose. RESOLVED (2026-06-23): `revise_content` shipped.** An agent revises content it created that is in `review`/`changes_requested`, returning it to the review queue and clearing the owner's review note.
- **G2 — content proposal readback. RESOLVED (2026-06-23): `list_content` shipped.** An agent reads back the disposition (review / changes_requested / published / archived) of the content it proposed — closing the loop for non-conversational agents (hermes).
- **G3 — `propose_content` is project-blind. RESOLVED (2026-06-23): intentional decoupling, not a gap.** Content is the external loop, decoupled from the project/GTD axis. `contents.project_id` is nullable by design; the link is meaningful only for `build-log` and is applied by the owner in admin if/when a build-log needs project context. The agent content surface deliberately stays project-agnostic — `article`/`essay`/`til`/`digest` (incl. 雜談/隨筆) are standalone writing.
- **G4 — windowed reflection look-back. RESOLVED (2026-06-23): `review_period` shipped.** A read-only windowed retrospective ("what did KOOPA complete between `since` and `until`") computed live from the activity log — closing the gap that `brief(reflection)` (single-date), `list_todos` (caller-scoped), and `project_progress` (current-state snapshot) left open.

## 8. Milestones live on the goal, not the project

`koopa0.dev` is a goal and carries its roadmap milestones directly. Milestone-
shaped progress must live on the **goal**, not a `maintained` project — a
maintained project is excluded from `project_progress.Momentum` by
`WHERE status IN ('in_progress','planned')`, and milestone progress surfaces via
`ActiveGoalMilestones`.

## 9. D-4 — authz resolution

`propose_*` safety is the **inert-draft lifecycle** (`status=proposed`; the owner activates in admin) plus **tool-absence** (no publish / activate / hard-delete tool exists), not caller-gating. There is **no tool-layer authz at all** (Option B, 2026-06 — the `requireAuthor` / `requireRegisteredCaller` gates were removed): the MCP transport is the access boundary, and `as` only carries attribution + caller-scope. An MCP call carries no cron-vs-chat signal, so "NEVER from scheduled runs" is prose guidance, not enforced. The real guard against a misbehaving scheduled agent is detection on the hermes side (audit_write_surface tripwire, hermes commit c81bdd2); a fabricated `as` is rejected by the `created_by` FK.

---

*Verification: reconciled with live `project_progress` and a 3-angle adversarial gate (koopa0.dev-as-project milestone hole, internal-loop sufficiency, content-collab completeness), all re-derived from source. Authorities remain the code: `migrations/001_initial.up.sql`, `internal/mcp/ops/catalog.go::All()`, `internal/mcp/server.go::callerIdentity`.*
