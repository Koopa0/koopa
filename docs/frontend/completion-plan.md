# Frontend Completion Plan — close every admin/design gap

> Basis: the 2026-06-08 design-fidelity audit (prototype recoverable at git `b11a01a5^:docs/frontend/prototypes`). Goal per owner: **補 every gap**. Two root causes: (1) the frontend was built BEFORE the MCP-v3 contraction, which moved authoring / lifecycle / commitment-creation from the agent surface to admin → real write-surface gaps; (2) several prototype interactions were shipped as read-only or stubs.
>
> Tags: **[FE]** frontend-only (endpoint exists) · **[BE+FE]** needs a Go endpoint first · **[verify]** confirm endpoint exists before building. Each feature still runs the normal dev lifecycle (comprehend → implement → /verify → review).

---

## Wave 0 — cheap correctness wins (do first, low risk)

- [ ] **[FE]** Delete or reconcile `frontend/src/app/styles/MINIMAL_DESIGN_SYSTEM.md` — it describes a contradictory old mono/no-teal system. Replace with a 1-page note describing the actual teal+serif token system, or delete.
- [ ] **[FE]** Wire the orphan `app-status-badge` into the templates that already render status inline, OR delete it if `StatusBadge`/`app-status-badge` duplicate.
- [ ] **[FE]** Embedding model name: once owner picks `gemini-embedding-2` vs `gemini-embedding-001`, sync `internal/embedder/embedder.go:25` + `embedder_test.go:38` + `db/models.go` comments + README EN/zh. (Code change, not frontend — but it's a pending one-shot.)

## Wave 1 — contraction-required admin write surfaces (highest value)

These are the gaps the contraction *created*: authoring/commitment that used to be agent-side is now admin-only and has no UI.

- [ ] **[verify]** **Admin content CREATE** — "New article/essay/build-log/til/digest" → create route reusing `content-editor` in create mode. `ContentService.create()` exists but has zero callers; confirm the POST endpoint, then add the entry point + route.
- [ ] **[verify]** **Admin note CREATE** — "New note" → create route reusing `note-editor`. `NoteService.create()` exists uncalled.
- [ ] **[FE]** **Daily-plan builder ("plan my day")** + **Today advance-on-click** — wire the dead `core/services/daily-plan.service.ts` (write endpoint exists, commit `7c23f118`); build the plan-day picker; make Today's committed items advance on click and the progress bar reflect it.
- [ ] **[verify]** **Milestone CRUD** — inline add + edit + status in the goal profile (currently read-only binary checklist).
- [ ] **[verify]** **Learning-plan management** — plan activation (`update_plan` is admin), entry reorder, Complete/Skip modals with the audit-gate (`completed_by_attempt_id` + reason; force-override `manual override:` ≥60 runes).

## Wave 2 — missing admin screens

- [ ] **[BE+FE]** **System → Health + Stats** — needs the unified `/api/admin/system/health` envelope (currently nav counts are synthesized placeholders in `admin-layout.ts`). Build the endpoint, then the pages.
- [ ] **[verify]** **Admin Search page** — standalone search route (today only the Cmd-K palette exists).
- [ ] **[verify]** **Tags & topics** management page.
- [ ] **[FE]** **nav restructure 4→5 groups** — split out DAILY (Today/Plan/Inbox/Todos) and SYSTEM (Health/Stats/Activity/Agents) to match the design IA.

## Wave 3 — design-fidelity UX richness

- [ ] **[FE]** **GTD** — 6-tab segmented view (Inbox/Today/Pending/Someday/Recurring/History), j/k keyboard triage + kbd hint bar, Clarify modal (set project/energy/due → promote inbox→todo).
- [ ] **[FE]** **Learning dashboard** — streak/heatmap widget + per-widget independent loading/error/retry.
- [ ] **[FE]** **Command palette** — add Create + Capture groups; broaden search beyond goals/projects/content.
- [ ] **[FE]** **Content editor publish-preview** — iframe the public `/preview/:slug` (DRY publish loop).
- [ ] **[verify]** **Feed triage real curation** — decide whether "Draft" should curate (needs a backend curation path) or stay as open-source-URL.

## Wave 4 — design-system clean migration (optional, large, low urgency)

- [ ] **[FE]** Migrate ~1025 `text-zinc-*` / legacy `bg-sky-*` utilities → semantic DS tokens (`text-fg`, `bg-brand`, …), removing reliance on the `@theme` remap shim. Mechanical, large; the app already *looks* right via the shim, so this is hygiene, not function.

---

## Sequencing notes

- **Wave 0 → 1 → 2 → 3**; Wave 4 anytime (independent).
- Wave 1 + the `[BE+FE]` items (System health, feed curation) may need Koopa to add Go endpoints first (per CLAUDE.md split: Koopa owns Go API; Claude Code owns Angular + API對接 + admin UI). Frontend-only items I can do end-to-end.
- Each feature is its own Tier 2/3 change with /verify + reviewers; this doc is the roadmap, not a single PR.
