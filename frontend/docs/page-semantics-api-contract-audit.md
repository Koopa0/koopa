# Page Semantics & API Contract Audit — Koopa.dev Frontend

> **Audit date:** 2026-05-28
> **Scope:** Angular 21 frontend at `/Users/koopa/koopa0.dev/frontend`. 23 public pages + 26 admin routes + global shell, inspector, command palette.
> **Method:** Page-by-page semantic review against `docs/backend-semantic-contract.md` (§1–§7), `frontend/docs/api-spec.md` (v2.2), and `cmd/app/routes.go` (canonical route registration). Cross-checked by seven parallel cluster reads of components, services, templates, and handlers.
> **Constraint:** No application code, tests, or `api-spec.md` modified. This document is the only artifact produced.
> **Author:** Claude Code (Opus 4.7).

---

## 0. How to read this

Every page gets a **Page Semantics Card** with seven slots:

| # | Slot | Meaning |
|---|---|---|
| 1 | Intended domain meaning | What Koopa function this page is supposed to represent, in Koopa terms (not generic SaaS) |
| 2 | UI/UX explanation quality | Self-explanation, vocabulary fidelity, empty/error honesty, fake-affordance risk |
| 3 | API contract alignment | Spec match, drift findings, client-side aggregation flag |
| 4 | Backend semantic alignment | Lifecycle/state representation, forbidden-assumption check |
| 5 | Privacy / public-private boundary | Risk level and evidence |
| 6 | Classification | One of A–G below |
| 7 | Recommendation | Concrete next step |

**Classification key:**

- **A** — Semantically sound; minor polish only.
- **B** — Semantically sound but under-explained or with minor drift.
- **C** — UI/UX likely misrepresents the domain.
- **D** — API contract mismatch or frontend/backend drift.
- **E** — Backend/API not ready; frontend should remain pending or honest about that.
- **F** — Privacy / public-private boundary risk.
- **G** — Dead / legacy / unclear; needs owner decision.

Cards use compressed prose to stay scannable. Full evidence (file paths, line numbers) is in line.

---

## 1. Executive summary

### 1.1 Overall semantic health

The frontend's **admin cluster is in surprisingly good semantic health**. Knowledge, learning, and coordination admin pages obey the backend contract with very few violations:

- Notes never show a "publish" affordance (correct — notes are Zettelkasten, lifecycle is maturity only).
- Bookmarks have no draft/review lifecycle in the UI (correct — bookmarks publish on create).
- Feed entry "curate" path is content-only; no bookmark target (correct — that path was removed).
- Concept profile does not expose mastery edit (correct — mastery is derived).
- Hypothesis lifecycle uses dedicated transition endpoints (correct — no `PUT :id/status`).
- Goal status is manually set; no auto-derivation from milestones (correct — schema mandate).
- Agents page is read-only; no CRUD (correct — registry is system-managed).
- Content editor knows `publish` is human-only (correct — schema mandate).

The **public-site cluster is where most of the real risk lives**. Two of its issues are CRITICAL and should be fixed before any visitor lands on the site:

1. **Broken navigation on `/build-logs`** — list items link to `/admin/build-logs/...`, which is not a route.
2. **SaaS-product tone on `/privacy` and `/terms`** — both pages copy templated commercial-service language ("we reserve", "Website users", "Acceptable Use Policy") and contradict Koopa's single-owner personal-system positioning.

In the admin cluster the largest semantic risk is the **known Today fan-out** — frontend bypasses the backend aggregate and fans out to six endpoints. This is documented in the contract (§6F) and explicitly acknowledged in `today.service.ts:96–104`. It is not blocking, but it is the single largest contract drift in the admin surface.

### 1.2 Top 7 risks (severity-ordered)

| # | Risk | Pages | Severity | Class |
|---|---|---|---|---|
| 1 | Public list links to non-existent `/admin/build-logs/...` route | `/build-logs` | HIGH | D |
| 2 | `/privacy` and `/terms` use SaaS-product tone — contradicts single-owner positioning | `/privacy`, `/terms` | HIGH | F |
| 3 | Today page bypasses backend aggregate; fans out to 6 endpoints | `/admin/commitment/today` | MEDIUM-HIGH | B/D |
| 4 | `/tags/:tag` assumes a public tag-listing API that does not exist as a first-class endpoint | `/tags/:tag` | MEDIUM | D |
| 5 | `/articles/:id` and `/essays/:id` route params are named `id` but used as `slug` everywhere | article-detail, essay-detail | MEDIUM | B |
| 6 | Command palette silently degrades for 6 of 9 declared Kinds; pipeline + activity actor depend on Phase 2/3 backend not yet shipped | command palette, pipeline, activity | LOW-MEDIUM | B/E |
| 7 | TIL list loads all 100 entries and filters client-side; will not scale | `/til` | LOW | B |

### 1.3 Highest-value next PRs (3)

1. **Fix `/build-logs` link target.** `pages/build-logs/build-logs.html:48` — change `'/admin/build-logs/' + log.slug` to `'/build-logs/' + log.slug`. Smallest possible change. Could ship today. Restores public-site navigation. **No backend, no test, no api-spec change required.**
2. **Rewrite `/privacy` and `/terms` to single-owner voice.** Replace SaaS-product language with first-person plain-English explanation of "this is one person's personal knowledge website; here is what it stores; here is what it shares." Or replace `/terms` entirely with a copyright/license note. Pure copy change.
3. **Today surface reconciliation (decide first, then act).** Run the contract's §6F reconciliation: decide whether to (a) wire `WithSources(...)` in `cmd/` so the backend aggregate is complete and switch the frontend to one call, or (b) accept the fan-out and mark the aggregate route as partial/scaffolded. The decision is a Tier-3 architectural call and should not be made by a PR.

### 1.4 What should NOT be touched yet

- **Admin knowledge cluster.** Content editor, notes editor, bookmarks list, feeds, triage are all in good shape. No semantic drift detected. Don't refactor.
- **Admin learning cluster.** Dashboard, concepts list/profile, session timeline, plan timeline, hypotheses list/profile all honor the contract. The mastery floor display is the only UX nit; not worth a PR right now.
- **Agents list and profile.** They correctly expose no CRUD, no "participant" vocabulary. Model example of semantic fidelity.
- **Auth pages.** `/login` and `/admin/oauth-callback` correctly use in-memory token + HttpOnly refresh + fragment-based OAuth. Don't touch.
- **Bookmark edit endpoint.** Open Question #2 in the contract — UI honestly defers the affordance; service method exists but is unwired. Don't wire it until the owner decides Create-only vs Create+edit.
- **Pipeline page.** It is explicitly scaffolded for Phase 3; the empty-stages panel hides honestly. Don't fake the data.
- **Activity actor field.** Phase 2 widen on the backend (`ChangelogEvent.actor`) is the gating dependency. Don't add an agent filter until the field is populated.
- **`/uses` component.** Unreachable — implemented but no route registration. Defer until owner decides whether to register (`Prerender`, like `/about`) or delete the directory. See §2.1.3.

---

## 2. Page-by-page semantic cards

Pages are grouped by route prefix. Each card follows the 7-slot template in §0.

---

### 2.1 Public landing & portfolio (6 components — 1 unreachable)

#### 2.1.1 `/` — Home

- **Files:** `pages/home/home.ts` + `home/sections/{featured-projects,latest-feed}.component.ts`
- **Services:** `ProjectService`, `ContentService`
- **Backend:** `cmd/app/routes.go:140-141` (`/api/projects`), `:128` (`/api/contents`)
- **api-spec:** §3.1 implied; public endpoints not enumerated in spec

1. **Domain meaning.** First-impression landing — hero, featured project tiles, latest publishable content feed. Public writing / portfolio.
2. **UI quality.** Clear hierarchy. Featured filters client-side by `featured && sort_order`. Latest feed maps `ContentType` to UI labels and explicitly excludes `essay` and `digest` — the *why* is not documented in code. Loading skeletons present; latest-feed has no error UI.
3. **API alignment.** `/api/projects` and `/api/contents` are not enumerated in `api-spec.md` (which is admin-focused). They exist on the backend (`routes.go:128, 140`) but the public contract is implicit. Drift: none in shape; gap in documentation.
4. **Backend alignment.** Trusts backend to filter `is_public=true` and `status='published'` — verified for content (`internal/content/public.go::PublicList`), assumed for projects.
5. **Privacy.** Risk: low. Backend gates correctly.
6. **Classification:** B (under-explained: api-spec gap + undocumented filter exclusion).
7. **Recommendation:** Add a "Public site contract" subsection to `api-spec.md` enumerating `/api/projects`, `/api/contents`, `/api/topics`, `/api/bookmarks`, `/api/search`, `/api/feed/rss`, `/api/feed/sitemap`. Add a one-line code comment explaining why `essay`/`digest` are out of the home feed.

#### 2.1.2 `/about`

- **Files:** `pages/about/about.{ts,html}`; `SeoService` only.
- Domain meaning: static bio + skills + contact. Public.
- All seven slots: clean. Hard-coded personal info appropriate for public.
- **Classification:** A. **Recommendation:** keep.

#### 2.1.3 `/uses` — **G (unreachable: component exists, no route registered)**

- **Files:** `pages/uses/uses.{ts,html}` — component is implemented.
- **Verified:** `grep -n "uses" frontend/src/app/app.routes.ts` returns no match; same for `app.routes.server.ts`. The `/uses` URL is therefore unreachable from the router and lands on the `**` → `not-found` fallback.
- Static reference page (tools, hardware, stack) if it were routed; self-explanatory categories.
- **Classification:** G (dead component or pending registration — owner decision).
- **Recommendation:** owner decision. Two options: (a) register the route in `app.routes.ts` with `loadComponent: () => import('./pages/uses/uses')...`, with SSR mode `Prerender` (same as `/about`); (b) delete `frontend/src/app/pages/uses/` entirely if the page is not part of the public surface. Status quo is unreachable code.

#### 2.1.4 `/projects`

- **Files:** `pages/projects/projects.{ts,html}`; `ProjectService`.
- **Backend:** `/api/projects` (`routes.go:140`).

1. Grid of public projects with status filter (all + 6 schema statuses).
2. Status labels match `project_status` enum; CSS color-coding consistent with status badge convention (api-spec §1.5).
3. `/api/projects` not in api-spec; status filter is client-side after fetch (acceptable for small N).
4. No forbidden assumptions detected.
5. Low (backend filters `is_public`).
6. **Classification:** B (api-spec gap, otherwise sound).
7. **Recommendation:** document the endpoint; add a contract-level note that `status` is one of `{planned, in_progress, completed, maintained, archived, on_hold}` so the frontend's color mapping is anchored.

#### 2.1.5 `/projects/:slug`

- **Files:** `pages/project-detail/project-detail.{ts,html}`.
- **Backend:** `/api/projects/:slug` (`routes.go:141`).

1. Single project detail (title, status, problem/solution/architecture, results, links).
2. Loading state has no skeleton (blank). 404 state is not rendered explicitly — relies on whatever the template does when `project()` is null.
3. Endpoint not in api-spec; single-resource shape (not wrapped in `{data}` envelope) is consistent with §1.1 "single resource: directly returns object".
4. Read-only view; no lifecycle UI; correct.
5. Low.
6. **Classification:** B.
7. **Recommendation:** add explicit 404 template branch; document the endpoint.

#### 2.1.6 `/bookmarks` (public)

- **Files:** `pages/bookmarks/bookmarks.{ts,html}`; `BookmarkService.list()` → `/api/bookmarks`.
- **Backend:** `routes.go:132` → `internal/bookmark/handler.go::PublicList` (handler doc-comment: "the is_public=true slice").

1. Curated bookmark stream for visitors.
2. Vocabulary clean. Empty/error/loading honest.
3. Service calls `/api/bookmarks?page=&per_page=` with no filters. The backend's `PublicList` filters `is_public=true`. Per contract §3 "bookmark: capture_channel field; curate = publish", `is_public=true` IS the "curated" predicate — so the SEO description "Curated resources with personal commentary" is **semantically accurate** (the original cluster audit flagged this as medium risk; that concern is mooted once the curate-equals-publish invariant is recognized).
4. No `bookmarks.status` lifecycle implied. No `bookmark_rss` references.
5. Low — backend filters at endpoint.
6. **Classification:** A (after invariant clarification).
7. **Recommendation:** add a one-line comment in `bookmark.service.ts::list()` noting "public path: `/api/bookmarks` returns is_public=true (= curated)" so future readers don't repeat the audit confusion. Document the endpoint in api-spec.

---

### 2.2 Public content reading (8 pages — 4 list + 4 detail)

These eight pages share an identical pattern: list page reads a content type and detail page renders one item. Two CRITICAL issues found.

#### 2.2.1 `/articles` — Articles list

- **Files:** `pages/articles/articles.{ts,html}`; `ContentService`.
- **Backend:** `/api/contents` (`routes.go:128`) → `internal/content/public.go::PublicList`.

1. Paginated published articles + search.
2. Clean filters, pagination, error message, loading state.
3. Spec match via implied content public contract.
4. Backend SQL enforces `status='published' AND is_public=true`. No forbidden affordances.
5. None.
6. **Classification:** A. **Recommendation:** keep.

#### 2.2.2 `/articles/:id` — Article detail — **B (route-param naming bug)**

- **Files:** `pages/article-detail/article-detail.ts`.
- **Backend:** `/api/contents/{slug}` (`routes.go:129`) → `PublicBySlug`.

1. Single article render with markdown, TOC, related links.
2. Self-explanation is good — back, share, copy buttons on code blocks. No raw enums.
3. **Drift:** route param is named `id` (`app.routes.ts:20`, `article-detail.ts:52: input.required<string>()` named `id`). The component then passes that value to `getArticleBySlug(slug)` (`article-detail.ts:110, 115`). The links across the app pass `article.slug` into this slot. Functionally it works; semantically the param name is wrong. Future maintainers reading the route will assume UUID-by-id semantics.
4. Backend gate on `is_public=true` verified.
5. None.
6. **Classification:** B.
7. **Recommendation:** rename route to `articles/:slug` (app.routes.ts:20) and rename the input. No behavior change. (Out of audit scope — recorded for owner.)

#### 2.2.3 `/essays` — Essays list

- **Files:** `pages/essays/essays.{ts,html}`.
- Calls `listByType('essay')` → `/api/contents/by-type/essay` (`routes.go:130`).
- All clean. **Classification:** A.

#### 2.2.4 `/essays/:id` — Essay detail — **B (same param-naming bug as 2.2.2)**

- Route `:id` used as `slug`. Same fix recommendation.

#### 2.2.5 `/til` — TIL list

- **Files:** `pages/tils/tils.{ts,html}`.
- Loads `perPage: 100` and filters tags client-side. Works for current corpus size; will not scale.
- **Classification:** B. **Recommendation:** push tag filter to the backend (query param) before the TIL corpus crosses ~100 items.

#### 2.2.6 `/til/:slug` — TIL detail

- Route param is `:slug` and used correctly as slug. **Classification:** A.

#### 2.2.7 `/build-logs` — Build logs list — **D (CRITICAL: broken navigation)**

- **Files:** `pages/build-logs/build-logs.{ts,html}`.
- **Verified bug** (`build-logs.html:48`):
  ```html
  [routerLink]="'/admin/build-logs/' + log.slug"
  ```
  The string `/admin/build-logs/` is **not a registered route anywhere** in the app. `app.routes.ts:87` defines `build-logs/:slug` (no `/admin` prefix). The detail page exists at `/build-logs/:slug`. Clicking a row in the public list either redirects through `**` → `not-found`, or — worse — triggers `adminGuard` to bounce the user to `/login`.
- All other slots clean.
- **Classification:** D (high-severity routing drift).
- **Recommendation:** change line 48 to `'/build-logs/' + log.slug`. One-character fix; ship immediately.

#### 2.2.8 `/build-logs/:slug` — Build log detail — **B (fragile metadata parsing)**

- Component parses `project`, `session_type`, `tags` from markdown body via regex (`build-log-detail.ts:61-75`). No schema validation; if frontmatter format drifts, the page silently shows empty metadata.
- Otherwise clean.
- **Classification:** B.
- **Recommendation:** consider moving build-log frontmatter into `contents.ai_metadata` or a typed column; revisit once a second `build-log` author exists.

---

### 2.3 Public discovery + auth + utility (10 pages)

This cluster contains the **highest-severity findings in the audit** (`/privacy`, `/terms`, `/tags/:tag`).

#### 2.3.1 `/topics` — Topics index

- Reflects the contract's "topic-driven, format-secondary" organization correctly. `GET /api/topics` exists. **Classification:** A.

#### 2.3.2 `/topics/:slug` — Topic detail

- `GET /api/topics/{slug}` returns `{topic, contents, related_tags}`. Component does client-side tag filtering inside a single page of content — does not paginate across all topic content matching a secondary tag.
- **Classification:** B.
- **Recommendation:** document the client-side filtering limit; if needed, add a backend `?tag=` query.

#### 2.3.3 `/tags/:tag` — Tag listing — **D (no first-class backing)**

- Backend has admin tag CRUD only (`routes.go:236-247`). There is **no public `/api/tags` index or `/api/tags/:tag` listing endpoint**.
- Frontend calls `ContentService.listPublished({tag})` → `/api/contents?tag=X`, which works as a content-filter but not as a "tag exists" query.
- Side effect: navigating to `/tags/nonexistent-tag` returns 200 + empty list (because filtering on a nonexistent tag is not an error). The page silently shows "no content" instead of 404.
- The semantic contract (§3) defines `tag` as content metadata, **not a first-class entity**. The `/tags/:tag` route promises a first-class tag page that the backend does not back.
- **Classification:** D.
- **Recommendation:** owner decision. Option (a) deprecate `/tags/:tag` and surface tag discovery only via topic detail or search. Option (b) add backend `/api/tags` and `/api/tags/:tag/contents` and validate tag existence before rendering. Status quo is dishonest UX.

#### 2.3.4 `/search` — Public search

- Calls `/api/search` (`routes.go:134`). FTS-only today (contract §6D, decided Phase 1D 2026-05-27).
- UI does not tell the user "this is full-text search" — the search-vs-semantic distinction is invisible.
- **Classification:** B.
- **Recommendation:** add subtle help text or placeholder: "Full-text search across published articles, essays, TILs, build-logs." Set expectations.

#### 2.3.5 `/login` — Login

- Verified: `AuthService._authState` is in-memory only; no `localStorage`/`sessionStorage` usage (grep clean). OAuth fragment delivery; history clearance after callback.
- **Classification:** A. **Recommendation:** keep.

#### 2.3.6 `/admin/oauth-callback`

- Tokens via URL fragment; cleared from history; stored in memory.
- **Classification:** A. **Recommendation:** keep.

#### 2.3.7 `/error`

- Generic "something went wrong" without stack traces or internal paths.
- **Classification:** A.

#### 2.3.8 `/**` (not-found)

- Clean 404. No internal route leakage.
- **Classification:** A.

#### 2.3.9 `/privacy` — **F (CRITICAL: SaaS-tone leakage)**

Verified strings in `pages/privacy/privacy.html`:
- Line 32: "This website may use third-party analytics tools (such as Google Analytics)"
- Line 58: "We reserve the right to modify this privacy policy at any time."

This is **commercial-service template language** ("we", "users", "analytics for improving experience", "reserve the right"). It contradicts the contract's foundational statement (`backend-semantic-contract.md §1`): *"private-by-default personal knowledge / learning / coordination OS for a single human owner... NOT a multi-user product, an RBAC system, a public CMS with arbitrary authorship."*

A visitor reading this page will reasonably conclude Koopa is a SaaS product. That misrepresents the system.

- **Classification:** F.
- **Recommendation:** rewrite to single-owner voice. Example skeleton:
  > This is [Author]'s personal website. Visiting this page leaves a standard server access log. No analytics or trackers are installed. Published articles are written and reviewed by one person. If you have questions about anything you read here, email [address].

  Or: delete the page and replace the footer link with a `mailto:` and a copyright line.

#### 2.3.10 `/terms` — **F (CRITICAL: SaaS-tone leakage)**

Verified strings in `pages/terms/terms.html`:
- Line 10: 'Welcome to koopa0.dev (the "Website"). By accessing or using this website…'
- Line 17: "Section 2: Website Content"
- Line 40: "Section 4: Acceptable Use"
- Line 62: "We reserve the right to modify these terms of service at any time."

"Acceptable Use Policy" + "Website" + "we reserve" is enterprise-T&C boilerplate. It implies a multi-user service relationship that does not exist.

- **Classification:** F.
- **Recommendation:** delete and replace with a one-paragraph License & Attribution note:
  > Articles, build logs, and TILs on this site are copyright [Author]. You're welcome to read, learn from, and link to them. For citation or commercial reuse, email [address]. Code examples are MIT-licensed unless noted otherwise.

  This is honest, short, and matches the system's actual nature.

---

### 2.4 Admin commitment (5 pages)

The largest known semantic risk in the admin cluster lives here (Today fan-out).

#### 2.4.1 `/admin/commitment/today` — **B (known fan-out drift; §6F)**

- **Files:** `admin/commitment/today/today-page.component.{ts,html}` + `today/today.service.ts`.
- **api-spec:** §2.1 expects a single `GET /api/admin/commitment/today` aggregate.
- **Verified:** `today.service.ts` (lines 96-104, 115-142) does **not** call the aggregate. It fans out via `combineLatest` to six endpoints:
  - `/api/admin/knowledge/content?status=review`
  - `/api/admin/learning/hypotheses?state=unverified`
  - `/api/admin/coordination/tasks?state=completed`
  - `/api/admin/commitment/daily-plan`
  - `/api/admin/learning/summary`
  - `/api/admin/system/health`
- The service's own doc comment acknowledges this is temporary "until `GET /api/admin/commitment/today` ships per §2.1."
- The backend aggregate handler exists (`cmd/app/routes.go:219` → `internal/today/handler.go::Today`) but is partially wired in production (`handler.go:78-100`: judgment/reviews/warnings sections come from optional `WithSources(...)` not called in `cmd/`). This is exactly the risk §6F of the contract calls out.
- **UI quality:** Strong. HERO with judgment queue, PLAN section, REVIEWS, WARNINGS. Vocabulary is clean (no todo/task confusion). Affordances correctly omit forbidden actions (no raw status dropdowns, no "blocked" filter).
- **Backend semantic alignment:** No forbidden assumptions on the page itself. The drift is purely contract — the page implements the right view-model from the wrong endpoints.
- **Classification:** B (semantic content correct; API contract drift documented).
- **Recommendation:** decide §6F first (canonical surface = fan-out or aggregate?), then either wire `WithSources(...)` and switch the frontend, or accept the fan-out and update api-spec.md §2.1 to mark the aggregate as "partial/planned" and document the fan-out as canonical. Do not just "switch to aggregate" without testing the payload shape against `TodayVm`.

#### 2.4.2 `/admin/commitment/todos`

- **Files:** `admin/commitment/todos/list/todos-list.page.{ts,html}`; `TodoService`.
- State chips: `inbox | todo | in_progress | done | someday` — correct enum.
- Advance actions: explicit buttons per `STATE_TRANSITIONS[state]` (lines 90-112). No raw state dropdown. 400 errors toasted as "Illegal state transition" (line 293).
- Capture form: "enters inbox, clarify later" — GTD-correct.
- 404/405/501 toasted as "Endpoint not yet available" (lines 269-276) — honest.
- **Classification:** A. **Recommendation:** model implementation; keep.

#### 2.4.3 `/admin/commitment/goals`

- **Files:** `admin/commitment/goals/list/goals-list.page.{ts,html}`; `PlanService`.
- Default filter "Active" = `in_progress || not_started`. Status chips match `goal_status` enum.
- Milestone rollup is `done/total` count (line 170) — binary, not quantitative. Correct.
- **Classification:** A.

#### 2.4.4 `/admin/commitment/goals/:id`

- **Files:** `admin/commitment/goals/profile/goal-profile.page.{ts,html}`.
- Status update uses `PUT /goals/:id/status` (not `PUT /goals/:id` with status field). Correct per api-spec §2.10 / §10.8.
- Milestone progress is client-side count of `m.completed`; no per-milestone percent. Correct (contract §3 forbids quantitative milestones).
- Health label (on-track / at-risk / stalled) is presented separately from status — no auto-derivation from milestones. Correct (no goal auto-status).
- **Classification:** A.

#### 2.4.5 `/admin/commitment/projects/:id`

- **Files:** `admin/commitment/projects/profile/project-profile.page.{ts,html}`.
- "Project" = PARA project (the `projects` table), not Cowork project (an agent identity). Component comment explicitly distinguishes. No §4 boundary violation.
- Todos grouped by state: In progress, Todo, Done, Someday. No "blocked" column (forbidden — `task_state` has no `blocked`, and todos likewise don't).
- **Classification:** A.

---

### 2.5 Admin knowledge (8 pages)

Cleanest admin cluster in the audit. Zero forbidden affordances detected.

#### 2.5.1 `/admin/knowledge/content` — Content list

- Status badges verbatim per api-spec §1.5 (`.status-draft`, `.status-review`, …).
- All 5 content types in type filter; all 4 statuses in status filter.
- No transition buttons on list rows (transitions live in editor — correct).
- Actor column shows `—` with code comment "until backend propagates activity_events.actor" — honest about §5.4 Phase 2 widen.
- **Classification:** A.

#### 2.5.2 `/admin/knowledge/content/:id/edit` — Content editor

- Topbar action buttons gated by status: Cancel / Save draft / Send for review / Revert to draft / Publish / Archive. Each maps to a dedicated transition endpoint, not `PUT status=…`.
- Publish button labeled "(human only)" (`content.service.ts:113` comment confirms backend rejects non-human with 403).
- 404/405/501 surfaced as "Endpoint pending" toast — honest.
- **Verified:** `ContentService.reject()` is **not** present in `content.service.ts` (grep clean). The api-spec §9 cleanup is complete.
- No `review_level`, no `maturity`, no `note_kind` field on content forms.
- **Classification:** A.

#### 2.5.3 `/admin/knowledge/review-queue`

- Same `ContentListPageComponent` as 2.5.1 with `initialStatus: 'review'` from route `data`. Topbar title changes to "Review queue". Honest reuse pattern.
- **Classification:** A.

#### 2.5.4 `/admin/knowledge/notes` — Notes list

- All 6 note kinds (solve / concept / debug / decision / reading / musing) in filter; all 5 maturity stages (seed / stub / evergreen / needs_revision / archived).
- Kind abbreviations (`KIND_SHORT` map) documented in code.
- **Zero publication affordance** anywhere. No "publish" button, no `is_public` field, no `status` column. Correct — notes never publish.
- **Classification:** A.

#### 2.5.5 `/admin/knowledge/notes/:id/edit` — Note editor

- Code comment: "⌘S — save. (No publish / revert; notes have no publication.)" Honest.
- Maturity changes use a separate `POST /:id/maturity` endpoint, distinct from `PUT /:id` field updates. Correct per api-spec §3.2.
- **Classification:** A.

#### 2.5.6 `/admin/knowledge/bookmarks` — Bookmarks list

- Filter chips: capture channel (all / rss / manual / shared) and visibility (all / public / private). Correct vocabulary (`capture_channel`, not the schema-only `origin_system`).
- Component comment: "No side panel edit yet — the PUT endpoint is not live; a dedicated edit route will land once the backend ships it." Honest about Open Question #2.
- Service method `update()` exists but no UI is wired to it. Defers cleanly.
- **Classification:** B (open question in the contract; UI correctly defers).

#### 2.5.7 `/admin/knowledge/feeds` — Feeds list

- Health is derived client-side from `enabled` + `consecutive_failures` count (`healthLabel()`). The derivation is deterministic and transparent — not a cell-state envelope, but a one-line rule. Acceptable.
- No relevance-score column (would be all zero per contract §6D; correctly omitted).
- **Classification:** A.

#### 2.5.8 `/admin/knowledge/feeds/triage` — Feed entry triage

- Single-entry card flow. Actions: Draft (D) / Ignore (I) / Undo (u).
- `curate(entryId, contentId)` posts `{content_id}` only — no `bookmark_id` path. Correct per contract / api-spec §9 ("curate only accepts content_id; bookmark target removed").
- `FeedEntryRow` model has `curated_content_id: string | null`, no `curated_bookmark_id` field. Verified.
- Relevance score is rendered as dots from `score * 5`. The dots are visualization; the page does not claim the score is meaningful. Per §6D it's all zero today; this is honest enough but borderline — see explainability table.
- **Classification:** A.

---

### 2.6 Admin learning (7 pages)

Highest semantic load in the project; cleanest implementation. No concept↔tag conflation, no mastery edit affordances, no hypothesis↔reflection blurring detected.

#### 2.6.1 `/admin/learning` — Learning dashboard

- Confidence filter exposed as top-level chips (`aria-pressed` state-bound). Default `high`. Toggles `confidence_filter=high|all` server-side.
- Concepts card uses `mastery_value` and `mastery_stage` from the response — no client-side derivation.
- Recent observations use wire fields `signal` / `body` per api-spec v2.2 ruling (not schema-native `signal_type` / `detail`).
- **Minor explainability gap:** mastery stage chip does not say "developing means <3 observations recorded" — see admin explainability table.
- **Classification:** A.

#### 2.6.2 `/admin/learning/concepts` — Concepts list

- Chip filters: kind (Pattern / Skill / Principle) + mastery stage (Struggling / Developing / Solid). Both omit when "all".
- No concept↔tag conflation. No cross-domain concept creation affordance.
- **Classification:** A.

#### 2.6.3 `/admin/learning/concepts/:slug` — Concept profile

- Path is `:slug?domain=<required>` per api-spec §4.3 v2.2 ruling. Correct.
- Mastery evidence shown as 3 buckets (weakness / improvement / mastery) with low-confidence counts as "+N low-conf" badges underneath. Confidence-as-label semantics correctly reflected.
- `obs_count` derived client-side from `mastery_counts` sum (spec note: detail omits it).
- Relations / linked_notes / linked_contents currently stub `[]` per spec — UI hides empty sections.
- **Classification:** A.

#### 2.6.4 `/admin/learning/sessions/:id` — Session timeline

- Read-only. Hero shows domain + mode + duration. Attempts list uses paradigm + outcome correctly.
- **No "Start new session" button** — correct. Single-active-session enforcement lives elsewhere (likely dashboard / a session list not yet built).
- **Classification:** A.

#### 2.6.5 `/admin/learning/plans/:id` — Plan timeline

- Entry rows display `status`, `completed_at`, `completed_by_attempt_id` (truncated 8 chars), and `reason` — the §13 audit-trail fields are surfaced read-only.
- **Edit affordance is out of scope of this view.** When entries are marked complete, it presumably happens through a modal/form not in this audit slice. The §13 enforcement (mandatory `completed_by_attempt_id` + `reason`) is the backend's responsibility; this page only displays. That's correct.
- **Classification:** B (display is correct; the edit surface needs separate audit when it lands).

#### 2.6.6 `/admin/learning/hypotheses` — Hypotheses list

- State chips: Unverified / Verified / Invalidated / Archived; default Unverified.
- No reflection_note confusion.
- **Classification:** A.

#### 2.6.7 `/admin/learning/hypotheses/:id` — Hypothesis profile

- State transition buttons gated by computed properties (`canVerify`, `canInvalidate`, `canArchive`). Verify/invalidate both allowed from unverified.
- Evidence form: kind selector (supporting/counter) + body + optional linked_attempt_id / linked_observation_id. Evidence list is append-only.
- Lineage endpoint degrades gracefully if 404/405/501.
- **Classification:** A.

---

### 2.7 Admin coordination + system + shell (10 components)

#### 2.7.1 `/admin/coordination/tasks` — Tasks list

- State chips: Submitted / Working / Revision / Completed. Color-coded dots.
- `canceled` state is intentionally hidden from chips pending unified `/tasks?state=` endpoint — temporary fan-out across `/open` + `/completed`.
- **No "directive" filter.** Correct — there is no `tasks.kind` discriminator (Open Question #4 not resolved).
- No "blocked" filter. Correct — `task_state` has no `blocked` value.
- **Classification:** A.

#### 2.7.2 `/admin/coordination/tasks/:id` — Task timeline

- Hero + a2a message stream + artifact rail. State-aware action bar.
- `canApprove`, `canCancel` etc. correctly gated by state.
- `revision_requested` payload contract is uncodified (Open Question #11) — UI is honest, prompts for notes optionally without claiming a schema.
- 404/405/501 → info banner "Endpoint not yet available". Honest about Phase 2/3 endpoints (approve/cancel) not yet shipped.
- **Classification:** A.

#### 2.7.3 `/admin/coordination/pipeline`

- Code comment (lines 78-86): "`stages` is always `[]` … The field maps to scheduler-level stage labels (crawl / classify / draft / grade) which aren't represented anywhere on `process_runs` yet." Stages panel hides when empty.
- `process_runs.kind` correctly restricted to `crawl | agent_schedule` (forbidden to invent new kinds).
- Status filter matches `process_run_status` enum.
- **Classification:** B (honest about Phase 3 scaffolding, but if backend shape drifts, page will silently render incomplete).

#### 2.7.4 `/admin/coordination/activity`

- Day-grouped audit log. Entity type + change kind filters.
- **Renders `actor` field conditionally** (template line 147-153). Backend `ChangelogEvent.actor` is Phase 2 widen — not yet live. Frontend gracefully hides when null, **but no user-facing banner explains why actor is empty.**
- No by-agent filter chips yet (correctly deferred).
- **Classification:** B (partial honesty — graceful null handling but no Phase 2 affordance explanation).

#### 2.7.5 `/admin/coordination/agents` — Agents list

- Activity state filter only (active / idle / blocked / retired). **Zero CRUD affordances.** No create / edit / delete / disable buttons. Empty state explicitly states: "Agents are reconciled from internal/agent/registry.go at server start."
- **No "participant" terminology** (retired vocab).
- **Classification:** A. Model example.

#### 2.7.6 `/admin/coordination/agents/:name` — Agent profile

- Two tabs: Workload (default) + Context notes.
- Notes endpoint (`/agents/:name/notes`) is Phase 3 in api-spec §5.2 line 822 — frontend handles 404/405/501 with info banner.
- Notes correctly use the term `agent_note` with kinds `plan` / `context` / `reflection`. No confusion with `notes` table.
- **Classification:** A.

#### 2.7.7 `/admin/settings` — Settings placeholder

- Renders `AdminPlaceholderComponent`. Honest about being unbuilt.
- **Classification:** A.

#### 2.7.8 `/admin` shell — Admin layout

- Nav has 4-domain structure (Commitment / Knowledge / Learning / Coordination). No legacy `now` or `atlas` nav references (the routes are kept as redirects only).
- Nav counts: `AdminNavCountsService` calls per-entity endpoints with `catchError → null` per source. Resilient. Not using `/system/health` cell-state envelope — acceptable; spec §6.1 lists it as 🔧 extend (not yet shipped).
- **Classification:** A.

#### 2.7.9 Inspector (global side panel)

- URL-driven (`?inspect=type:id`). Valid types whitelisted: content | hypothesis | task | goal | project | todo | concept | agent | bookmark.
- Invalid types reset to null. Read-only.
- **Classification:** A.

#### 2.7.10 Command palette (⌘K)

- Phase 2 lexical match on `title + keywords`. Loads only 3 entity types: goal, project, content.
- **Silent degradation:** spec §6.3 declares 9 Kinds (content, note, bookmark, hypothesis, concept, task, goal, todo, project). Palette loads 3. If the user types "task" or "bookmark" — empty results, no explanation. No banner telling the user "currently searching goals, projects, content only."
- **Classification:** B (correct for Phase 2, but the silent narrowing is an explainability issue).

---

## 3. API contract drift table

| Page / Service | Frontend expectation | api-spec / backend expectation | Class | Recommended action |
|---|---|---|---|---|
| `/build-logs` (template) | `routerLink` → `/admin/build-logs/${slug}` | Route is `/build-logs/:slug` (`app.routes.ts:87`) | **D** | One-character template fix |
| `/articles/:id`, `/essays/:id` (route definitions) | param named `id`, used as `slug` | api-spec implies slug-keyed URLs (contents addressed by slug) | B | Rename routes to `:slug` |
| `/tags/:tag` | First-class public tag-listing | No `/api/tags` listing endpoint exists; only admin tag CRUD + content `?tag=` filter | **D** | Owner decision: deprecate `/tags/:tag` OR add public tag-index endpoint |
| `/til` | client-side tag filter over `perPage: 100` | Backend supports `?tag=` query | B | Push tag to server query before corpus >100 |
| `/admin/commitment/today` | 6-endpoint fan-out via `combineLatest` | api-spec §2.1 single aggregate; contract §6F flags partial wiring | **B/D** | Decide §6F canonical surface; then either wire backend `WithSources` + switch FE to single call, or mark aggregate "partial" in api-spec |
| `/admin/coordination/activity` | renders `ChangelogEvent.actor` | api-spec §5.4 Phase 2 widen — field not yet populated | B | Add explanatory comment / banner; agent filter blocked until Phase 2 ships |
| Command palette | searches 3 Kinds (goal/project/content) | api-spec §6.3 Phase 2 lexical lists 9 Kinds | B | Add UI affordance describing search scope OR expand to declared Kinds |
| `/admin/coordination/pipeline` | `stages[]` always empty; UI hides panel | Phase 3 endpoint; stages not represented on `process_runs` | B/E | Document scheduler-stages source-of-truth before backend ships |
| `/api/projects`, `/api/contents` (public), `/api/bookmarks` (public), `/api/topics`, `/api/feed/{rss,sitemap}` | exist on backend | not enumerated in api-spec.md (admin-focused) | B | Add "Public site contract" section to api-spec |
| `/projects/:slug` | single-resource response shape | api-spec §1.1 allows single-resource direct return | B | Document shape explicitly |
| `/admin/knowledge/bookmarks` | `bookmarkService.update()` exists, no UI wiring | api-spec §3.3 includes `PUT /bookmarks/:id` (🔨 new); contract Open Question #2 unresolved | B | Hold — defer until owner decides Create-only vs Create+edit |
| `/admin/knowledge/content` ContentService | no `reject()` method present | api-spec §9 confirms removal | ✓ | (verified clean — no action) |
| Content editor `publish` | labeled "human only" | api-spec §10.3 + contract §5 — backend 403 on non-human | ✓ | (correct — no action) |
| Feed triage `curate` | posts `{content_id}` only | api-spec §9 — bookmark curate path removed | ✓ | (correct — no action) |
| Notes editor | no publish affordance | contract §3 — notes never publish | ✓ | (correct — no action) |

---

## 4. Admin explainability issue table

Owner-facing issues only — where admin pages do not adequately explain what the owner is looking at.

| Page | Issue | Why it matters semantically | Suggested fix | Test idea |
|---|---|---|---|---|
| `/admin/learning` | Mastery floor rule (<3 obs → `developing`) is not surfaced | Owner can't tell "developing" from a floor placeholder vs a real mastery position | Tooltip on the mastery stage icon: "Developing — fewer than 3 observations recorded, so mastery is not yet diagnosed" | Hover/aria-describedby snapshot test |
| `/admin/learning/concepts/:slug` | Confidence filter behavior not documented inline | Owner may not realize counts change because of filter, not data | One-line explainer above evidence bucket: "Showing high-confidence observations; toggle filter above to include low-confidence" | Toggle test: high vs all returns different counts on the same concept |
| `/admin/learning/plans/:id` | Entry-update affordance is not in this view; §13 audit-trail is only displayed | Owner may not know completing an entry requires `completed_by_attempt_id` + `reason` until they try | When the edit modal is built, enforce both fields client-side; reject submit without them | Form-validation test on the entry-update modal (when it exists) |
| `/admin/coordination/activity` | `actor` field is rendered but Phase 2 widen not live — always empty | Owner thinks the field doesn't work; doesn't know it's pending backend | Inline comment in template: "Phase 2: actor populated once `ChangelogEvent.actor` widen ships"; consider a one-time info banner | Once Phase 2 ships, assert actor names appear on rows |
| Command palette | Silent degrade for 6 of 9 Kinds (task, bookmark, note, hypothesis, todo, concept) | Owner types "task" and gets empty results; concludes search is broken | Either: (a) tiny help text below input "Currently: goals, projects, content"; (b) load the remaining Kinds when their services have list endpoints; (c) wait for Phase 3 semantic and remove the lexical narrowing | Manual: query "task" → palette currently empty; verify behavior under each fix |
| `/admin/coordination/pipeline` | "Stages" panel always empty; honest in code, opaque in UI | Owner doesn't know if pipeline is broken or stages are unbuilt | Add a one-line note in the empty state: "Stage aggregation lands in Phase 3" | Visual snapshot once backend ships stage data |
| `/admin/knowledge/feeds/triage` | Relevance dots all zero today (contract §6D); UI doesn't say so | Owner may interpret dots as a real signal | One-line comment in template + Tooltip on relevance dots: "AI relevance scoring not yet active — all entries currently score 0" | Once scoring ships, verify non-zero scores render correctly |
| `/admin/commitment/today` | UI is correct but its provenance — 6 fan-out endpoints, partial backend aggregate — is invisible | Owner can't tell whether a slow load is one slow endpoint or six | Once §6F is decided, document the canonical surface in api-spec and add a code-comment pointer | Add a slow-network test: assert per-section loading states, not a single skeleton |

---

## 5. Public/private boundary issue table

| Route / page | Risk | Severity | Recommendation |
|---|---|---|---|
| `/privacy` | SaaS-product tone contradicts single-owner positioning; visitor may conclude Koopa is a SaaS | **HIGH** | Rewrite to single-owner voice (skeleton in §2.3.9) |
| `/terms` | "Acceptable Use Policy" + "Website" + "we reserve" enterprise-T&C language | **HIGH** | Delete or replace with License & Attribution paragraph (skeleton in §2.3.10) |
| `/build-logs` | List links to `/admin/build-logs/` — invalid route; in practice users hit `not-found` or `adminGuard → /login` | **HIGH** (UX, indirectly privacy because a public click ends up in the login surface) | Fix template `build-logs.html:48` |
| `/tags/:tag` | No first-class backend; invalid tags silently return empty page | MEDIUM (UX honesty, no real data leak) | Owner decision: deprecate or back with endpoint |
| `/bookmarks` (public) | None — backend filters `is_public=true`; SEO "Curated" is accurate under "curate = publish" invariant | Low | Add code comment so future readers don't repeat the audit concern |
| `/admin/*` | All routes behind `adminGuard`; tokens in memory only; OAuth via URL fragment with history clearance | None / Low | Keep — auth design is correct |
| `/login`, `/admin/oauth-callback` | Tokens never persisted to localStorage / sessionStorage (grep clean) | None | Keep |
| `/error`, `/**` | No stack traces or internal paths leak | None | Keep |
| `/projects/:slug` | Missing explicit 404 template branch — a private/deleted project that returns 404 will render a blank-ish page | Low | Add 404 branch |

---

## 6. Testing implications

### 6.1 Which tests would actually prove frontend semantic quality

These are the tests that pin down something the contract cares about. They survive refactors and produce signal when the underlying assumption breaks.

- **Route–handler compatibility matrix** — for every admin page in this audit, assert: (a) the exact endpoint paths called match `cmd/app/routes.go`; (b) the response payload includes the fields the component reads; (c) empty responses return `{data: [], total: 0}` (api-spec §10.6) not 404. Run as a single integration test that walks the audit's API drift table.
- **State-transition endpoint mutex** — assert (frontend-side lint or test) that no component calls `PUT /<entity>/:id` with a state field, and that all state changes go through `/advance`, `/publish`, `/submit-for-review`, `/revert-to-draft`, `/archive`, `/verify`, `/invalidate`, `/end`, `/maturity`. This catches future regressions where a developer accidentally collapses transitions back into a generic PUT.
- **Forbidden-affordance regression** — for each forbidden assumption in contract §7 (tasks.kind, blocked task state, bookmarks.status, daily auto-carryover, content.maturity, review_level, quantitative milestones, goal auto-status, content/concept review cards), assert no template renders an affordance for it. Grep- or AST-based.
- **Today endpoint contract test** — once §6F is decided, write a single test that pins whether the canonical surface is fan-out (test the 6 endpoints) or aggregate (test one endpoint with the full envelope). Right now both paths exist; the test would expose this if it ran.
- **Public-vs-private filter assertions** — for `/api/contents`, `/api/projects`, `/api/bookmarks`, seed records that are `is_public=false` or `status≠published` and assert they do not appear in the public response. The reverse asserts the admin endpoints DO return them under auth. This is the only way to catch a backend filter regression that leaks private data.
- **No-localStorage / no-sessionStorage token storage** — a one-shot grep test in CI that fails if `auth.service.ts` or anything it transitively imports references `localStorage` or `sessionStorage`. Prevents drift away from in-memory.
- **Privacy / terms copy lint** — keyword test that fails if `/privacy` or `/terms` contains `we reserve|users|Website|Acceptable Use|analytics for|may collect`. Forces the page to stay in single-owner voice once it's rewritten.

### 6.2 Which tests would be superficial or noise

- Snapshot tests of admin pages — the markup changes too often; signal-to-noise is low.
- "Endpoint exists" tests that hit the URL and check for non-zero response — covers nothing semantic; passes for any 200 reply including the wrong shape.
- High-level user-flow E2E for every admin page — overkill; better to use the route–handler compatibility matrix above.
- "All buttons render" tests — coverage theater. The forbidden-affordance regression test is the version with semantic teeth.

### 6.3 First 3 test PRs (recommended order)

1. **Public/private filter regression test** (covers content / bookmarks / projects). Seeds a fixture with `is_public=false` + `status='draft'` and asserts they never appear on the public site. Smallest, highest privacy-floor value. Catches the riskiest class of regression first.
2. **No-PUT-status / no-localStorage / forbidden-affordance lint pack** as a single CI-time grep test. Cheap, fast, no flake risk. Locks down the contract's hardest-to-detect violations.
3. **Route–handler compatibility matrix** for the admin cluster — one integration test that walks the API drift table. Pays off most when the backend renames or reshapes an endpoint (e.g., the §6F decision lands).

---

## 7. Claude Design escalation candidates

These are pages or flows where a visual / product-design pass would add value beyond the engineering audit. Each carries an exact question to hand off.

### 7.1 `/privacy` and `/terms` — single-owner voice rewrite

**Question for Claude Design:** *"This is a one-person personal knowledge website, not a SaaS product. Draft `/privacy` and `/terms` pages (or argue they should be removed) that (a) honestly describe what data the site stores and shares; (b) use first-person, plain English; (c) avoid SaaS-template language. Length target: under 200 words each. Include a one-line License & Attribution alternative for `/terms`."*

If web search is available, Claude Design may compare against indie-developer personal sites that have rewritten away from boilerplate T&C (e.g., individual creator portfolios) — cite sources.

### 7.2 Today surface canonical shape (`/admin/commitment/today`)

**Question for Claude Design (and Architecture):** *"Should the Today page consume a single backend aggregate or fan out to per-entity endpoints? Decide using contract §6F as the brief: backend aggregate exists but is partially wired (only the plan section is guaranteed). Frontend currently fans out to 6 endpoints with independent error handling. Sketch the page's loading skeleton and partial-failure states for each option, and recommend a winner based on perceived performance, partial-failure UX, and maintenance cost. Do not write code."*

### 7.3 `/tags/:tag` — does a public tag page exist?

**Question for Claude Design:** *"Backend has no public tag index; the `/tags/:tag` page works only because filtering content by tag returns a list. Should public tag discovery exist at all? Compare (a) deprecate `/tags/:tag` and let tag discovery live inside `/topics/:slug` secondary filtering, (b) add a backend `/api/tags` catalog and elevate tags to first-class browsing. Cite at least one personal-knowledge-blog precedent for each, with sources."*

### 7.4 Pipeline visualization (`/admin/coordination/pipeline`)

**Question for Claude Design + Architecture:** *"Backend `process_runs` table has `kind ∈ {crawl, agent_schedule}` and a name; the frontend wants to show 'stages' (e.g., crawl → classify → draft → grade). There is no `stages` column today. Three options: (a) add `process_runs.stage` column; (b) adopt a `metadata.stage` convention; (c) live with application-code aggregation. Recommend one based on pipeline visibility needs and query simplicity."*

### 7.5 Command palette scope explainability

**Question for Claude Design:** *"Command palette currently searches 3 entity kinds but the spec declares 9. Without expanding scope, how should the palette UI communicate what is searchable today? Sketch the input affordance (placeholder text, help row, or scope chips). Keep it discreet — the palette is keyboard-driven and visual noise is costly."*

### 7.6 Build-log frontmatter robustness

**Question for Architecture (not Design):** *"Build-log detail page parses `project`, `session_type`, `tags` from markdown body via regex (`build-log-detail.ts:61-75`). Format drift breaks silently. Should these fields move to `contents.ai_metadata` or a typed column, or stay markdown-parsed?"*

---

## Appendix A: Verification

| Check | Result |
|---|---|
| `git diff --check` (whitespace errors in changed files) | passes — see Appendix B for changed files |
| App build required | No — only documentation added |
| Docs verification tooling | None present in repo (no `npm run docs:lint` or equivalent) — explicitly noted |
| Application code modified | No |
| Test files modified | No |
| `api-spec.md` modified | No |
| `backend-semantic-contract.md` modified | No |
| Backend handlers modified | No |
| Routes modified | No |

Behavioral surface area changed: **zero**.

## Appendix B: Files changed by this audit

- **Created:** `frontend/docs/page-semantics-api-contract-audit.md` (this document)

No application code, tests, or `api-spec.md` were modified by the audit run. The sibling document `frontend/docs/current-frontend-reality.md` was produced in parallel by a separate run and ships alongside this audit.

## Appendix C: Cross-references

Authoritative sources consulted (read-only):

- `docs/backend-semantic-contract.md` — §1 (purpose), §3 (vocabulary), §4 (boundaries), §5 (MCP semantics), §6 (claim-tested state, especially §6F Today), §7 (forbidden assumptions, open questions)
- `frontend/docs/api-spec.md` — §1 (conventions), §2 (Commitment), §3 (Knowledge), §4 (Learning), §5 (Coordination), §6 (cross-cutting), §9 (explicitly-not-needed endpoints), §10 (backend notes — especially §10.1 no-alias rename, §10.8 transitions-not-PUT, §10.9 pagination envelope)
- `cmd/app/routes.go` — canonical route registration (verified all public and admin endpoints called by the frontend)
- `internal/content/public.go`, `internal/bookmark/handler.go`, `internal/today/handler.go` — handler signatures cross-referenced to frontend service calls
- `frontend/src/app/app.routes.ts` — frontend route table (363 lines)
- `frontend/src/app/admin/commitment/today/today.service.ts` — verified §6F fan-out claim (lines 96-104, 115-142)
- `frontend/src/app/pages/build-logs/build-logs.html` — verified `/admin/build-logs/` link bug (line 48)
- `frontend/src/app/pages/privacy/privacy.html`, `terms/terms.html` — verified SaaS-tone strings
- `frontend/src/app/pages/article-detail/article-detail.ts`, `essay-detail/essay-detail.ts` — verified `:id` vs `:slug` naming
- `frontend/src/app/core/services/content.service.ts` — verified `reject()` removal
- All 33 page components and their primary services (`core/services/*.service.ts`)

End of audit.
