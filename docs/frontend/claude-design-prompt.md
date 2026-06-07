# Claude Design prompt — koopa admin UI

> Paste the block below into Claude Design. It is written to (a) point Claude
> Design at the existing Angular frontend so it adopts the current design system,
> and (b) give it tight, frontend-first specs. Revise the ✏️ choices first
> (especially the priority flows and the admin-creation model), then run.

---

## PROMPT

**Role & goal.** You are designing the admin interface for **koopa** — a *personal*
knowledge / GTD / PARA / learning operating system used by exactly **one person**
(the owner, "Koopa"). This is not a multi-tenant SaaS product; optimise for a
power user's daily workflow: **information density, keyboard speed, fast scanning,
and low-friction capture/editing** over generic marketing polish. Output
high-fidelity, production-intent prototypes — not mood boards.

**Design-system foundation + a FRESH visual (the owner wants a new look).** First read
the codebase at `frontend/` to ingest the *structure*: the Angular component inventory
(`shared/components`: `data-table`, `modal`, `form-field`, `page-header`, `badge`,
`loading-spinner`, `empty-state`, `hero-canvas`), the SSR setup, Tailwind v4, and the
**dark-mode-default** baseline. Then **propose ONE cohesive, fresh visual language** —
new tokens (colour palette, type scale, spacing, radii, elevation) and a refreshed look
for those same components — and apply it **uniformly across ALL screens, rebuilt and
kept alike**, so the app reads as one consistent system, never half-old-half-new. Keep
the components' structure/semantics and the dark-mode default; refresh the skin.
Density and keyboard speed stay above decorative polish.

**Tech constraints the visuals must respect (Angular v22).** Forms use **Signal
Forms** (stable in v22) — design create/edit forms as reactive, inline-validated,
with per-field error states and an obvious primary action. Assume **OnPush**
change detection (favour explicit, discrete states over implicit reactivity),
**SSR for read-heavy pages / CSR for editors**, virtualised long lists, and
`@defer` for heavy panels. Meet **WCAG 2.1 AA**: semantic structure, visible focus
rings, keyboard operability, AA contrast in dark mode.

**Information architecture (5 areas, left sidebar).**
1. **Daily** — Today, Plan, GTD Inbox/Todos. (the everyday entry point)
2. **Commitment** — Goals (+ milestones), Projects, Areas.
3. **Knowledge** — Content, Notes, Feeds, Tags/Topics, Search.
4. **Learning** — Dashboard, Sessions, Plans, Concepts, Hypotheses, Domains.
5. **System** — Health, Stats, Activity, Agents (read-only).

**Priority screens to design (in this order) ✏️ adjust:**

1. **Daily → Today** (home). Renders: an at-a-glance day — *planned items* with
   completion progress (planned/completed/deferred), *overdue todos*, an
   *active learning session* card (if any), and *RSS highlights*. Primary actions:
   advance a todo, capture a new todo (command-bar style), start a session. Dense,
   skimmable, single screen, no scrolling for the core.

2. **Goal create + Goal detail.** Create form (Signal Forms): `title*`,
   `description`, `area` (select), `quarter` (select), `deadline` (date). Status is
   server-set (`not_started`) — not in the create form; show it as a status chip on
   the detail page with a separate status-change control. Detail renders:
   `{ goal, milestones[], linked projects[], recent activity[] }` with an
   "add milestone" inline form.

3. **Learning Plan create + detail.** Create form: `title*`, `description`,
   `domain*` (select), `goal` (optional), `target_count`. Detail: ordered plan
   entries with status + phase, a progress bar, drag-reorder, and an "update entry"
   flow where marking an entry **completed requires choosing the attempt that
   justifies it + a short reason** (an audit gate — design this as a small
   required modal, not a silent toggle).

4. **GTD Inbox / Todos.** Tabbed or segmented views: **Inbox** (unclarified
   captures), **Today**, **Pending** (with project), **Someday**, **Recurring**,
   **History**. Each row: title, project/area chip, energy, due, state. Fast
   keyboard triage (clarify → todo, advance, defer, drop). A persistent capture bar.

5. **Content editor + Note editor.** A focused writing surface (title, body,
   type/kind, topics/tags) with a lifecycle rail on the side: for content
   draft → review → published → archived (+ is-public toggle); for notes a maturity
   selector (seed → evergreen → archived). Autosave affordance.

6. **Learning Dashboard.** Mastery overview, streak, recent observations,
   concept weakness signals. Multi-widget; design for **graceful partial loading**
   (a widget may fail/empty independently — show per-widget empty/error, never a
   whole-page failure).

**Data shapes (use these as the truth for what each screen shows; do not invent
fields):**
- Today: `{ planned_items[], completion:{planned,completed,deferred}, overdue_todos[], active_session?, rss_highlights[] }`
- Todo: `{ id, title, state(inbox|todo|in_progress|done|someday), project?, area?, energy(high|medium|low), due?, position }`
- Goal: `{ id, title, description, status, area?, quarter?, deadline?, milestones[], projects[], recent_activity[] }`
- Plan: `{ id, title, domain, status(draft|active|…), entries[]:{ id, title, position, status, phase }, progress:{total,completed,skipped,substituted} }`
- Content: `{ id, title, type(article|essay|build-log|til|digest), status(draft|review|published|archived), is_public, topics[], tags[] }`
- Note: `{ id, slug, title, kind(solve-note|concept-note|debug-postmortem|decision-log|reading-note|musing), maturity(seed|stub|evergreen|needs_revision|archived) }`

**Interaction principles.** Keyboard-first (a command palette for capture +
navigation). Inline editing over modal-heavy flows where safe. Empty states that
teach the next action. Destructive actions confirmed. Optimistic UI only where the
backend is idempotent.

**Out of scope / do not design:** any multi-user, billing, onboarding, marketing,
team/collaboration, or "coordination/tasks" surfaces (the inter-agent task system
was retired). One user, no auth screens beyond a minimal owner login.

**Deliverables.** For each priority screen: a high-fidelity dark-mode prototype +
its key states (loading / empty / error / populated / form-invalid). Then a short
component map noting which existing shared components are reused vs. newly proposed
(keep new components minimal). Finish with one cohesive style frame (tokens:
colour, type scale, spacing, elevation) so the set is internally consistent.

---

### Notes for running it
- Claude Design can **point at the codebase** — do that so it ingests the real
  Tailwind theme + the 9 components (it builds your design system from them).
- Start with screens 1–3 (highest daily value + the W8 create-form backend is
  already shipped), review, then iterate to 4–6.
- After approving prototypes, the Angular build follows the
  `frontend-first-requirements-draft.md` data contracts; new endpoints (daily-plan
  write, the GTD list views, hypothesis/milestone create) get built to serve the
  approved screens — not before.
