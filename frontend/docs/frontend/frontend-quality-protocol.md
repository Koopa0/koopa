# Frontend Quality Protocol

> **Status:** v1 (initial — minimal automated coverage)
> **Last updated:** 2026-05-28
> **Applies to:** `frontend/` (Angular 21 SSR app)
> **Scope:** defines the **frontend review gates** for changes under `frontend/`. It is NOT the ultimate authority over backend semantics, API contract truth, or product direction — those live in `docs/backend-semantic-contract.md`, `frontend/docs/api-spec.md`, and owner decisions respectively. When a gate here conflicts with those sources, the source wins and this protocol is updated.
> **Does NOT govern:** visual design, copy, component visual library choice (see `frontend/CLAUDE.md` and `.claude/rules/ui-components.md`).

---

## Purpose

Koopa is a single-admin personal AI / knowledge / learning / workflow operating system. The frontend is the owner's daily surface — it must be **semantically correct, stable, explainable, and privacy-safe**. It is not a SaaS dashboard and not a public demo product.

This protocol defines the seven quality gates that every change to `frontend/` must respect, and lists which gates are currently enforced by automated checks (`npm run check:quality`) versus which are gated by manual review.

---

## Quick reference

| Gate | What it protects | Auto-checked? |
|---|---|---|
| 1. Route correctness | No dead links, no silent route drift | Partial |
| 2. Public/private boundary | Public site can't leak admin | Yes |
| 3. API contract alignment | Frontend doesn't drift from backend | No (manual) |
| 4. UI semantic explainability | Owner can read the page and know what it means | No (manual) |
| 5. Affordance correctness | Buttons don't lie about what they do | No (manual) |
| 6. Testing policy | Tests prove behavior, not copy or mocks | No (policy only) |
| 7. Design escalation policy | Visual revamps don't override semantic contract | No (policy only) |

---

## Gate 1 — Route correctness

### Assertions

- No public template (`src/app/pages/**`) links to a private `/admin/**` route via `routerLink` or `href`.
- No public template links to a route that does not exist in `app.routes.ts`.
- `app.routes.ts` and `app.routes.server.ts` agree on which paths exist; SSR `serverRoutes` should not register paths that don't have a corresponding `routes` entry, and removed routes must be removed from both files. **Full route-table parity between the two files is not automated in v1** — only known high-risk drift patterns (e.g. the previously-removed `tags/:tag` path) are grep-checked. Broader parity is a manual review concern.
- Dynamic `routerLink` expressions that construct paths from string concatenation (e.g. `[routerLink]="'/x/' + slug"`) are reviewed for the slug source — if the slug can be attacker-influenced and the route is privileged, that is a Gate 2 escalation.

### Auto-checked

- `src/app/pages/**` contains no `routerLink`/`href` value starting with `/admin` (Gate 2 also enforces this).
- `src/app/pages/**` contains no reference to `/tags/` (the `/tags/:tag` route was removed on 2026-05-28; tag chips are content metadata only — see `api-spec.md` §11.7).
- `src/app/app.routes.ts` does not reintroduce a `tags/:tag` path.
- `src/app/app.routes.server.ts` does not reintroduce a `tags/:tag` path.

### Manual review (per PR)

- Dead-link audit: when removing or renaming a public route, grep the templates and update referrers.
- Public template links to dynamic strings (e.g. `'/articles/' + content.slug`): confirm the route is real.

---

## Gate 2 — Public/private boundary

### Assertions

- `src/app/pages/**` (public site) must not import any symbol from `src/app/admin/**`.
- `src/app/pages/**` must not issue requests to any URL containing `/api/admin`.
- The admin app (`src/app/admin/**`) must not be SSR-rendered or prerendered; it is `RenderMode.Client` only. The public site IS server-rendered, so any admin code path reached during SSR is a privacy and bundling leak.
- Public pages must not expose admin, system, or demo semantics in URLs, copy, or page metadata (e.g. no "/admin" labels on public navigation, no "system status" surfaces on the public site, no "demo data" banners).

### Auto-checked

- `pages/**` contains no `from '…/admin…'` import.
- `pages/**` contains no occurrence of the literal string `/api/admin`.
- `pages/**` contains no `routerLink`/`href` value to `/admin`.
- `app.routes.server.ts` keeps `admin` and `admin/**` on `RenderMode.Client`.

### Manual review (per PR)

- New core services: confirm they don't auto-call admin endpoints during SSR.
- Public-page metadata (`<title>`, `<meta description>`, Open Graph tags) must not mention admin or internal-only concepts.
- HTTP interceptors must not silently route public traffic through auth-bearing flows.

---

## Gate 3 — API contract alignment

### Assertions

- Every URL hard-coded in `src/app/core/services/**` and `src/app/admin/**/*.service.ts` must correspond to an endpoint documented in `frontend/docs/api-spec.md`.
- `api-spec.md` must be checked against the backend (`cmd/app/routes.go` is canonical, `internal/*/handler.go` for shape) when a service is added, renamed, or the response shape changes.
- A service test that mocks `HttpTestingController` proves request shape, NOT that the backend honors the request. When backend semantics differ from the test fixture, the test is a false positive. Concrete failure mode that motivated this gate: a public list service tested with a `?tag=` request expectation, while the backend silently ignored the parameter and returned unfiltered content (resolved by removing the misleading public route; canonical contract now in `api-spec.md` §11.7).

### Why this is manual today

- A reliable static check would require parsing TypeScript to extract URL literals and cross-referencing them against a machine-readable spec. `api-spec.md` is prose-formatted; the cost to make it machine-readable is higher than the current risk.
- Recommended interim discipline: when adding or modifying a service, the PR description must cite the relevant `api-spec.md` section and the backend handler that serves it.

### Manual review (per PR)

- New `*.service.ts` → must reference an `api-spec.md` section.
- New `/api/...` URL string → must exist in the backend route table.
- Service test fixtures → must match observed backend behavior, not assumed behavior.

---

## Gate 4 — UI semantic explainability

### Assertions

- Every page in `src/app/pages/**` and `src/app/admin/**` has a clear Koopa-domain meaning that the owner can state in one sentence. If a page exists but its semantic role is unclear, it is a candidate for removal.
- Raw backend enums (`status='review'`, `kind='inbox'`, `maturity='evergreen'`) shown in admin UI either:
  - Have a glossary entry in the admin UI itself (tooltip, legend), OR
  - Are labelled with a human-readable mapping (e.g. "Review" → "Pending review"), OR
  - Are intentionally surfaced raw because the enum value IS part of the owner's operating vocabulary (e.g. `maturity='evergreen'` in a Zettelkasten view where the owner thinks natively in those terms). In this case the PR must justify the choice — silently leaving raw enums visible is not an accepted default.
- Empty/loading/error/pending states must be honest:
  - "No results" must mean "the query returned zero rows", not "the request failed silently".
  - "Loading" must mean "request in flight", not "feature stub".
  - Endpoint-pending UI (button exists, endpoint does not) must be visibly distinguishable from "endpoint exists, currently disabled".

### Why this is manual today

- Semantic role assessment is judgment-based and not amenable to static checks. The control point is the per-PR manual review below; ad-hoc semantic audits, when run, are session artifacts and should not be committed as permanent docs.

### Manual review (per PR)

- New page or major page change: state the one-sentence semantic role in the PR description.
- Raw enum exposed in UI: confirm glossary or mapping exists, or justify omission.
- New empty/error state: confirm it distinguishes "no data" from "broken request".

---

## Gate 5 — Affordance correctness

### Assertions

- Illegal lifecycle options must not be shown as normal choices. **Prefer hiding actions that are impossible for the entity's current state**; use the disabled state only when the action is conceptually relevant to the surface but temporarily unavailable (e.g. "Save" while a request is in flight, "Publish" while required fields are empty). Example: a `content` row in `published` state should not render "Submit for review" at all, because that transition is not part of the published-state lifecycle — not just disable it.
- Disabled buttons must explain WHY they are disabled, OR show in-progress state when the disable is transient (e.g. "Saving…" while a request is in flight). A button that is disabled with no explanation is an explainability defect.
- Endpoint-pending UI must not masquerade as a shipped function. If the button calls a stub or unimplemented endpoint, it must be labelled (e.g. "Coming soon" badge, disabled-with-tooltip "Not yet wired").

### Why this is manual today

- Lifecycle legality depends on entity state machines defined in the backend (see `.claude/rules/mcp-decision-policy.md` §3). A static check would have to ingest the state machine; deferred.

### Manual review (per PR)

- New action button: confirm it maps to a backend endpoint that exists and accepts the entity's current state.
- Disabled state: confirm the disable reason is visible to the user (tooltip, helper text, or in-progress label).

---

## Gate 6 — Testing policy

### Assertions

- **Prefer behavior/invariant tests** over snapshot or copy tests. A test that asserts "clicking Save dispatches `contentStore.publish(id)`" is more durable than a test that asserts "the button text is 'Save'".
- **Avoid testing only copy** unless the copy IS the product contract (e.g. legal text in `/privacy`, `/terms`). For functional UI, copy changes should not break tests.
- **Playwright (E2E) is optional and not PR-gated** for the v1 of this protocol. E2E flows can be added per surface as it stabilizes; they are not a release blocker today.
- **Storybook is optional and not adopted** for the v1 of this protocol. If introduced later, scope it to semantic admin components only (forms, list rows, lifecycle widgets) — not to visual chrome.

### Why this is policy-only today

- Test framework choice and coverage targets are described in `frontend/CLAUDE.md` (Vitest + 80% target). This gate restates the philosophy: tests must prove the *behavior contract*, not the *render output*.

### Manual review (per PR)

- New `.spec.ts`: confirm assertions target behavior, not text strings (except where copy is the contract).
- Snapshot tests: justify why, or convert to invariant assertions.

---

## Gate 7 — Design escalation policy

### Assertions

- Claude Design (the Anthropic in-product design feature) or any external design review may only be invoked **after** a semantic brief exists for the page in question. The brief must state:
  - The page's one-sentence Koopa-domain role (Gate 4).
  - The entity lifecycle states the page must accommodate (Gate 5).
  - The public/private classification (Gate 2).
  - The API contract the page is bound to (Gate 3).
- Design output must NOT override:
  - The public/private boundary (Gate 2). A design that puts admin chrome on a public page is rejected regardless of visual merit.
  - The backend semantic contract (`docs/backend-semantic-contract.md`). A design that implies a vocabulary or capability the backend doesn't expose is rejected; if the design is correct and the backend is wrong, the change goes to the backend first.

### Why this is policy-only today

- Visual design is not amenable to automated gating. The control point is the brief and the review checklist below.

### Manual review (per design pass)

- Semantic brief exists and is current.
- Design proposal cites the gate constraints it operates within.
- Reviewer (Koopa as sole owner) explicitly approves or amends the brief before any frontend code change lands.

---

## Automated checks — current command

```bash
cd frontend
npm run check:quality
```

This runs `scripts/check-frontend-quality.sh`, which implements:

| # | Check | Gate |
|---|---|---|
| 1 | `pages/**` does not import from `admin/**` | 2 |
| 2 | `pages/**` does not reference `/api/admin` | 2 |
| 3 | `pages/**` does not contain `routerLink`/`href` to `/admin` | 1, 2 |
| 4 | `pages/**` does not contain `/tags/` | 1 |
| 5 | `app.routes.ts` does not contain `tags/:tag` | 1 |
| 6 | `app.routes.server.ts` does not contain `tags/:tag` | 1 |
| 7 | `app.routes.server.ts` keeps `admin` / `admin/**` on `RenderMode.Client` | 1, 2 |

Exit code is non-zero if any check fails. Output lists offending file:line for each failure.

---

## Known limitations

- The script uses `grep` with line-level matching. It can be defeated by:
  - String literals assembled at runtime (`'/' + 'admin'` — unlikely but not detected).
  - Imports rewritten via TypeScript path aliases. None are currently configured for `admin/`. **If a path alias covering `admin/` (or any other public/private boundary) is introduced, the public/private import-boundary check in `scripts/check-frontend-quality.sh` MUST be updated in the same PR that lands the alias, before the alias is merged.** Landing an alias first creates a silent gap in Gate 2.
  - Comments containing forbidden strings — these will be flagged. Acceptable: comments referring to removed routes should be cleaned up.
- Gates 3, 4, 5, 6, 7 are NOT covered by the script. They depend on per-PR review against the canonical API and backend contracts (`frontend/docs/api-spec.md`, `docs/backend-semantic-contract.md`). Ad-hoc audit artifacts (page-semantics surveys, reality snapshots, etc.) may be generated on request when a specific question warrants one, but they are session deliverables — they should not be committed as permanent docs, because they go stale and become misleading load-bearing references.
- No CI integration is configured today. The protocol is enforced by the owner running `npm run check:quality` and the L1 reviewers in the agent workflow.
- The check script is not a hook — it does not block file writes or commits. Promotion to a pre-commit hook is a future option once the script has settled.

---

## How this protocol evolves

- New gates: when a new class of regression is observed, add a gate here, then add an automated check if it is grep-tractable.
- Removed gates: when a gate is no longer load-bearing (e.g. a removed feature class), strike it from this file and remove the corresponding check from the script — do not leave dead checks.
- The protocol is the authority on what the script SHOULD check. The script is the authority on what is checked today. Drift between the two is itself a Gate 1 problem and should be fixed.

---

## References

- `frontend/docs/api-spec.md` — current public + admin API contract. §11 (Public site contract) and §11.7 (tags-as-metadata) are the canonical sources for the contract that Gates 1, 2, and 3 enforce.
- `frontend/CLAUDE.md` — Angular conventions, agent roster, testing requirements.
- `frontend/.claude/rules/routing.md` — routing conventions.
