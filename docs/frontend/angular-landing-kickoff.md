# Angular landing kickoff — koopa frontend (new-session context)

> You are a fresh Claude Code session. Your job: turn the approved **Claude Design
> prototypes** into real **Angular v22** code, bound to the real backend endpoints.
> The backend + the design are DONE; this is the implementation phase.

## Read first (in order)
1. `CLAUDE.md` (project rules) + `frontend/CLAUDE.md` (Angular conventions) + `.claude/rules/*.md` (local, on this machine).
2. `docs/frontend/frontend-first-requirements-draft.md` — page/data-needs map + 5 resolved decisions.
3. `docs/frontend/backend-contract-reference.md` — **admin** endpoint contracts (real shapes/enums).
4. `docs/frontend/public-site-contract-reference.md` — **public reading-site** contracts.
5. `docs/frontend/claude-design-prompt.md` — the brief that produced the prototypes.
6. The **prototypes (the SPEC)**: `koopa Admin.html` + `koopa.dev.html` — the user placed them locally; **ask where** (likely `docs/frontend/prototypes/` or the repo root).

## What just happened (so you don't re-derive it)
- The backend underwent a large **MCP-v3 semantic contraction**: agent MCP tool surface **49→11**; retired A2A/tasks, agent_notes, FSRS/review, bookmark, MCP content-authoring, the `propose_*`/`commit` commitment flow; schema converged to `migrations/001`+`002`. Ledger: `docs/decisions/mcp-v3-semantic-contraction.md`; runbook: `docs/decisions/mcp-v3-execution-progress.md`.
- **High-commitment creation** (goal/project/milestone/learning_plan/domain/hypothesis) is now **admin-only HTTP POST** — agents have no MCP path; the human creates via the admin UI. `todo`/`note`/`plan-entries` are agent **and** UI.
- A strict acceptance adversarial review ran; **all findings fixed**. Repo is fully green (build/vet/`golangci-lint` v2 0/unit/**full integration**; CI now has an integration lane). Backend is on `main`.
- Admin `Today` aggregate wired to the contracted `brief(morning)` shape; plan/session detail de-embedded to `{plan,entries,progress}` / `{session,attempts}` (kept `progress`, not `summary`).
- **FSRS is gone** — there is no Due-reviews/spaced-repetition backend. Don't build that widget.

## The two surfaces (both prototyped → now specs)
- **Admin cockpit** (`koopa Admin.html`): **dark, dense, keyboard-flow** (Linear/Notion), ⌘K command palette, Tweaks (density/accent/sidebar). 6 screens: Today, Goal create+detail, Learning Plan create+detail, GTD Inbox/Todos, Content/Note editors, Learning Dashboard. Fresh **teal** visual on the existing 9 shared components.
- **Public reading site** (`koopa.dev.html`): **Zed-docs aesthetic** — generous whitespace, IBM Plex **serif** long-form prose, quiet docs-style left nav, light/dark. Reads `/api/contents`, `/api/topics`, `/api/projects`. (This is the "用作品說話" surface.)
- The two opposite pressures are deliberate (dense tool vs. calm reading) — keep them separate.

## Locked frontend decisions
- **HYBRID** (keep structure, rebuild forms, fresh visual). **Frontend-first** (views drive the read-model/API contracts; the **domain model stays backend SSOT**).
- **Angular v22** (released 2026-06-03): OnPush default, **Signal Forms** stable (use for ALL create/edit forms — goal/milestone/plan/domain/content/note), Vitest, per-route render strategies (SSR read pages / CSR editors), zoneless. **Prereq: TypeScript v6 + Node 26** (drops Node 20).
- One cohesive **fresh teal** design system, applied uniformly to admin + public.
- Admin **owns** commitment creation (the create forms are mandatory, not optional).

## Landing plan (sequence)
1. **Angular v22 upgrade FIRST** (hard prerequisite): `ng update` 21→22, bump TS6 + Node 26, fix breaking changes, OnPush-default audit, Karma→Vitest. Gate: frontend build + lint + tests green.
2. **Design-system port**: land the new visual once — teal tokens + the 9 shared components re-skinned + the public-site serif/prose styles — applied to both surfaces. Mirror the prototypes' tokens.
3. **Vertical slices**: prove the pattern end-to-end on ONE screen first — recommend **Today** (real Angular component → `GET /api/admin/commitment/today` → Signal/OnPush/new visual + Vitest). Then fan out the remaining admin screens + the public site, each bound to the contracts in the reference docs.
4. Fold in extras as their slices come up: Projects detail page, knowledge-graph view (`/api/knowledge-graph` nodes+edges), admin **publish-preview** (reuse the public Article component against `/api/contents/{slug}` — DRY, free).

## Conventions
- **Stay on `main`** (no feature branches — owner's directive). Conventional commits, **no `Co-Authored-By`**, stage files by name (no `git add -A`).
- Gate before commit: frontend build + lint + Vitest; for any Go change, the Go gate (build/vet/`/opt/homebrew/bin/golangci-lint` v2 [0 issues]/test — the v2 binary, not the shadowed v1 in `~/go/bin`).
- `.claude/` + `CLAUDE.md` are gitignored (local on this machine) — read them; they won't be in git history.
- Independent verification discipline: never trust an implementer agent's "all green" — re-derive the gate yourself; gopls diagnostics lag on edits, `go build`/the real toolchain is ground truth.

## First action
Ask where the prototypes are, read the docs above, then start step 1 (Angular v22 upgrade).
