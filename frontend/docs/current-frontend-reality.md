# Current Frontend Reality

> **Snapshot date:** 2026-05-28
> **Scope:** factual inventory of routes, services, types, privacy boundary, and admin UX risks in the Angular app at `frontend/`. Read against backend contract `docs/api-spec.md` v2.2.
> **What this doc is:** a map. It is meant to be re-derived from source, not maintained as a separate truth. If a row goes stale, fix the row.
> **What this doc is not:** a product/SaaS positioning piece, a roadmap, or a demo plan. The system is a single-admin personal operating system.

---

## 1. Route inventory

Canonical source: `src/app/app.routes.ts`. SSR config: `src/app/app.routes.server.ts`. Guard: `src/app/core/guards/auth.guard.ts` (`adminGuard = authGuard`; backend OAuth allowlist enforces single-admin).

### 1.1 Public routes (SSR `Server` / `Prerender` / a few `Client`)

| Path | Component | SSR | Notes |
|---|---|---|---|
| `/` | `pages/home/home` | Server | Landing |
| `/home` | redirect → `/` | — | |
| `/articles`, `/articles/:id` | `pages/articles`, `pages/article-detail` | Server | |
| `/essays`, `/essays/:id` | `pages/essays`, `pages/essay-detail` | (fallback `**` → Server) | Not listed in `app.routes.server.ts` — falls through to `**: Server` |
| `/projects`, `/projects/:slug` | `pages/projects`, `pages/project-detail` | Server | |
| `/topics`, `/topics/:slug` | `pages/topics`, `pages/topic-detail` | Server | |
| `/tags/:tag` | `pages/tag` | Server | |
| `/til`, `/til/:slug` | `pages/tils`, `pages/til-detail` | Server | |
| `/search` | `pages/search` | Client | |
| `/build-logs`, `/build-logs/:slug` | `pages/build-logs`, `pages/build-log-detail` | (fallback `**` → Server) | Not listed in `app.routes.server.ts` |
| `/bookmarks` | `pages/bookmarks` | (fallback `**` → Server) | |
| `/resume` | redirect → `/about` | — | |
| `/about` | `pages/about` | Prerender | |
| `/privacy`, `/terms` | `pages/privacy`, `pages/terms` | (fallback `**` → Server) | |
| `/login` | `pages/login` | Client | `noIndex: true` |
| `/admin/oauth-callback` | `admin/oauth-callback` | Client | Public callback endpoint, not guarded |
| `/error` | `pages/error/error.component` | Client | |
| `/**` | `pages/not-found/not-found.component` | Server (fallback) | |

`pages/uses/` exists in `src/app/pages/` but **has no route registered** in `app.routes.ts` — uncertain whether it's intended to ship; flagged as dead-or-pending.

### 1.2 Admin/private routes (`canActivate: [adminGuard]`, SSR `Client`)

All under `/admin/*`. SSR explicitly `Client` for `admin`, `admin/**`, and `admin/oauth-callback` — admin is never server-rendered or prerendered.

| Path | Component | Notes |
|---|---|---|
| `/admin` (default) | redirect → `commitment/today` | |
| `/admin/commitment/today` | `admin/commitment/today/today-page.component` | Aggregates 6 sources client-side, see §2.2 |
| `/admin/commitment/todos` | `admin/commitment/todos/list/todos-list.page` | |
| `/admin/commitment/goals`, `:id` | `admin/commitment/goals/list`, `…/profile/goal-profile.page` | |
| `/admin/commitment/projects/:id` | `admin/commitment/projects/profile/project-profile.page` | No list route, only profile |
| `/admin/knowledge/content`, `:id/edit` | `admin/knowledge/content/list/content-list.page`, `…/editor/content-editor.page` | `contentEditorCanDeactivate` guard on edit |
| `/admin/knowledge/review-queue` | reuses `ContentListPageComponent` with `data: { initialStatus: 'review' }` | **Not a distinct page** — see §5 |
| `/admin/knowledge/notes`, `:id/edit` | `admin/knowledge/notes/list`, `…/editor/note-editor.page` | `noteEditorCanDeactivate` guard on edit |
| `/admin/knowledge/bookmarks` | `admin/knowledge/bookmarks/list` | |
| `/admin/knowledge/feeds`, `feeds/triage` | `admin/knowledge/feeds/list`, `…/triage/feed-triage.page` | |
| `/admin/learning` | `admin/learning/dashboard/learning-dashboard.page` | |
| `/admin/learning/concepts`, `concepts/:slug` | `admin/learning/concepts/list`, `…/profile/concept-profile.page` | Profile reads `?domain=` query — see §2.4 |
| `/admin/learning/sessions/:id` | `admin/learning/sessions/timeline/session-timeline.page` | |
| `/admin/learning/plans/:id` | `admin/learning/plans/timeline/plan-timeline.page` | |
| `/admin/learning/hypotheses`, `:id` | `admin/learning/hypotheses/list`, `…/profile/hypothesis-profile.page` | |
| `/admin/coordination/tasks`, `:id` | `admin/coordination/tasks/list`, `…/timeline/task-timeline.page` | |
| `/admin/coordination/pipeline` | `admin/coordination/pipeline/pipeline.page` | |
| `/admin/coordination/activity` | `admin/coordination/activity/activity.page` | |
| `/admin/coordination/agents`, `:name` | `admin/coordination/agents/list`, `…/profile/agent-profile.page` | |
| `/admin/settings` | `admin/shared/admin-placeholder.component` | **Stub** — see §5 |

### 1.3 Dead / legacy / uncertain

| Item | Evidence | Status |
|---|---|---|
| `/admin/now` route | `app.routes.ts:347` redirects to `commitment/today` | Legacy stub; route target reachable |
| `/admin/atlas` route | `app.routes.ts:348` redirects to `knowledge/content` | Legacy stub; route target reachable |
| `src/app/admin/now/now-page.component.{ts,html}` | Component file exists; only inbound reference is a comment in `admin/commitment/today/today.service.ts:46` ("now-page.component still uses … legacy model is fictional") — never imported by any route | **Dead code** behind a redirect |
| `src/app/admin/atlas/atlas-page.component.{ts,html}` | Component file exists; zero inbound references outside its own folder | **Dead code** behind a redirect |
| `src/app/pages/uses/` | Folder exists; not in `app.routes.ts` | **Unregistered** — uncertain if intentional, abandoned, or pending |
| `/resume` → `/about` redirect | `app.routes.ts:98-102` | Vestigial alias; harmless |
| `/home` → `/` redirect | `app.routes.ts:13` | Vestigial alias; harmless |

---

## 2. Service / API alignment

Canonical contract: `docs/api-spec.md` v2.2. Public-site services should only call `/api/*`; admin services should only call `/api/admin/*`. Verified: no file under `src/app/pages/` calls `/api/admin/*` and no public page imports from `src/app/admin/`.

### 2.1 Backed by shipped backend endpoints

Per spec compliance, these services are aligned with `✓ existing` endpoints (URL prefixes shown; see api-spec for full surface):

| Service | File | Endpoints |
|---|---|---|
| `ProjectService` (public) | `src/app/core/services/project/project.service.ts` | `GET /api/projects`, `GET /api/projects/:slug` |
| `AuthService` | `src/app/core/services/auth.service.ts` | `POST /api/auth/refresh` (token in-memory per `rules/security.md`) |
| `ContentService` | `src/app/core/services/content.service.ts` *(uncertain — agent-reported)* | `/api/admin/knowledge/content*` family per api-spec §3.1 |
| `BookmarkService`, `FeedService` | `src/app/core/services/{bookmark,feed}.service.ts` | `/api/admin/knowledge/bookmarks*`, `/api/admin/knowledge/feeds*`, `/feed-entries*` |
| `TaskService` | `src/app/core/services/task.service.ts` | `/api/admin/coordination/tasks*` |
| `AgentService` | `src/app/core/services/agent.service.ts` | `/api/admin/coordination/agents*` |
| `ActivityService`, `ProcessRunService` | `src/app/core/services/{activity,process-run}.service.ts` | `/api/admin/coordination/activity`, `/api/admin/coordination/process-runs` |
| `LearningService`, `HypothesisService` | `src/app/core/services/{learning,hypothesis}.service.ts` | `/api/admin/learning/dashboard`, `/learning/concepts`, `/learning/sessions*`, `/learning/plans*`, `/learning/hypotheses*`, `/learning/reviews/*`, `/learning/summary` |
| `TodoService`, `DailyPlanService`, `PlanService` | `src/app/core/services/{todo,daily-plan,plan}.service.ts` | `/api/admin/commitment/*` |
| `SystemService` | `src/app/core/services/system.service.ts` | `/api/admin/system/health` |

### 2.2 Client-side aggregates (frontend fans out and merges)

| Aggregate | File | Fanout |
|---|---|---|
| Admin nav badge counts | `src/app/admin/admin-layout/admin-nav-counts.service.ts:59-107` | `combineLatest` over content (review-filtered + total), goals, hypotheses, open tasks, bookmarks, system-health. Each leg wrapped in `catchError → null`; one failed leg does not blank the envelope. Uses experimental `rxResource()`. |
| Today dashboard | `src/app/admin/commitment/today/today.service.ts:115-142` | `combineLatest` over content review queue, unverified hypotheses, completed-task approvals, daily plan, learning summary, system health. Backend spec §2.1 returns a single `/commitment/today` envelope; the frontend currently does not consume it that way — uncertain whether the aggregate endpoint is shipped or whether frontend chose to fan out for resilience. |
| Tasks "all" view | `src/app/core/services/task.service.ts:38-42` | `forkJoin` of `/api/admin/coordination/tasks/open` + `/api/admin/coordination/tasks/completed`. |

### 2.3 Endpoint-pending or future-backed

These are referenced in api-spec as `🔨 new` (planned) and the frontend may either call them already (assuming backend will ship) or have no call site yet:

- `POST /api/admin/learning/sessions/:id/attempts` (api-spec §4.8) — **no frontend call site found** (Session Timeline page reads existing attempts but does not record new ones). Uncertain.
- `POST /api/admin/learning/plans/:id/entries` (§4.11) — **no frontend call site found**. Uncertain.
- `GET /api/admin/knowledge/topics` admin-side (§3.6, `🔧 extend`) — admin Content Editor metadata picker would need it; **no admin topics service found**. Uncertain.
- `GET /api/admin/search` (§6.3, `🔨 new`) — site-wide ⌘K. Search service is uncertain in admin layer.

### 2.4 Known drift between frontend and api-spec

| Drift | Evidence |
|---|---|
| `ConceptService.get(id)` sends `GET /api/admin/learning/concepts/${id}` with **no `?domain=` query**. api-spec §4.3 v2.2 ruling: `:slug?domain=` is required, missing `domain` → 400. The page (`concept-profile.page.ts:56-62`) reads both `slug` and `domain` from the route, so the data is available; the service simply does not forward it. The doc comment in `concept.service.ts:8` says "Uses uuid id (not slug)" which conflicts with the spec compliance table in api-spec §4.3 ("🟢 aligned"). | `src/app/core/services/concept.service.ts:15-19` + `src/app/admin/learning/concepts/profile/concept-profile.page.ts:56-62` |
| `LearningService.listConcepts(...)` — `mastery_stage` accepts single value, spec §4.2 accepts comma-separated multi-select (`struggling,developing`). | `src/app/core/services/learning.service.ts:74` (agent-reported; confirm before fixing) |

### 2.5 Inline HTTP outside services

| Location | Call | Note |
|---|---|---|
| `src/app/pages/login/login.ts:69` | `this.http.get<{ data: { url: string } }>('/bff/api/auth/google')` | Bypasses service layer. Note `/bff/` prefix — uncertain whether this is a separate BFF proxy or naming inconsistency vs. the rest of the app (which uses `/api/`). |

### 2.6 DTO/type concerns

`docs/api-spec.md` §9 lists fields the spec explicitly removed (`review_level`, `maturity`/`note_kind` on Content, `directive_id`, rich message Part shapes, `bookmark_rss` curate). A scan of `core/models/*` and `admin/inspector/inspector.types.ts` confirms:

- ✓ No `review_level`, `maturity` on Content, `note_kind` on Content found in frontend types.
- ✓ No `{markdown}` / `{code}` `Part` variants — only `{text} | {data}` in `workbench.model.ts`.
- ✓ No `bookmark_rss` references.
- ✗ **Naming collision**: `core/models/admin.model.ts::SessionSummary` and `core/models/learning.model.ts::SessionSummary` are different shapes. `learning.model.ts` version matches api-spec §4.5; `admin.model.ts` version is a legacy dashboard shape with no current spec match.
- ✗ **Frontend-only aggregate type**: `admin.model.ts::LearningDashboard` (and `ConceptWeakness` within it) has field names like `weakness_spotlight` / `mastery_by_domain` / `fail_count_30d` that do not appear in `GET /api/admin/learning/dashboard` per api-spec §4.1. Either dead from the legacy `now-page.component`, or a fictional shape — uncertain.
- ✓ Duplicate but identical `PlanStatus` union exists in both `admin.model.ts` and `learning.model.ts` — redundant, not fictional.

---

## 3. Privacy boundary

Single-admin personal system. Public must not reveal admin/system concepts; admin must never be used for public screenshots or demo data.

### 3.1 Structural separation (verified)

- ✓ No file in `src/app/pages/*` calls `/api/admin/*`. Verified by `grep -rn "/api/admin" src/app/pages/`.
- ✓ No file in `src/app/pages/*` imports from `src/app/admin/`. Verified by `grep -rn "from '.*admin"` against pages.
- ✓ `admin` and `admin/**` are `RenderMode.Client` in `app.routes.server.ts:64-71` — admin HTML is never produced during SSR/prerender, so admin entity titles or content cannot leak to public crawlers via prerendered pages.
- ✓ `adminGuard = authGuard` (`core/guards/auth.guard.ts:21`) — relies on backend OAuth email-allowlist for the "is this Koopa" check. Frontend has no fixture-admin escape hatch.

### 3.2 Places public UI could accidentally reveal admin

| Risk | Evidence | Severity |
|---|---|---|
| Public Build Logs list hardcodes admin-namespaced links | `src/app/pages/build-logs/build-logs.html:48` — `[routerLink]="'/admin/build-logs/' + log.slug"`. `/admin/build-logs/:slug` does not exist in `app.routes.ts` (admin route map lines 134-349 has no `build-logs` child). The public detail route is `/build-logs/:slug` (app.routes.ts:87). | **Medium** — leaks admin URL structure; the link itself is broken (no admin/build-logs route exists) so visitors hitting an `/admin/*` URL trip the `adminGuard` redirect to `/login`. Two bugs in one. |
| Login page meta | `pages/login/*` sets meta description "Admin login page" with `noIndex: true` (agent-reported). | Low — `noIndex` mitigates SEO indexing; the wording still appears in any social-card or unfurl that does fetch it. Uncertain whether `noIndex` covers all crawlers. |
| Public detail pages SSR-rendered with `**` fallback | `essays`, `essay-detail`, `build-logs`, `build-log-detail`, `bookmarks`, `privacy`, `terms` are not enumerated in `app.routes.server.ts` and hit the `**: RenderMode.Server` fallback (server-renders fine, just non-explicit). | Low — implicit, not a leak; flagged for hygiene. |

### 3.3 Places admin UI must not be used for public screenshots or demo

The admin cockpit contains real personal data (todos, hypotheses, agent notes, daily plan, learning attempts, etc.). Any of the following surfaces would be embarrassing or compromising if screenshotted:

- `/admin/commitment/today`, `/admin/commitment/todos`, `/admin/commitment/goals` — personal goals/plan.
- `/admin/knowledge/notes`, `/admin/knowledge/notes/:id/edit` — Zettelkasten private notes.
- `/admin/learning/sessions/:id`, `/admin/learning/hypotheses*` — learning weaknesses, falsifiable claims.
- `/admin/coordination/activity`, `/admin/coordination/tasks/*` — inter-agent task content (raw agent prompts/responses).
- `/admin/coordination/agents/:name` — agent registry, capabilities, recent notes/artifacts.

No admin component file ships fixture or hardcoded mock data (verified by Agent scan — see Service §2.1; all admin pages read from live services). That means a "demo mode" does not exist, which is good for safety but also means there is no safe way to screenshot the admin UI for marketing/onboarding/external docs without inventing fixtures first.

---

## 4. Admin explainability risks

The admin UI is for a single user (the system author). It can be terser than a multi-tenant product, but raw enums and unexplained disabled states still cause friction even for the author. Inventory below; remediation is §6.

### 4.1 Raw enum / shorthand rendering

Verbatim enum text bound directly in templates without humanized labels (sampled — see Agent 4 inventory for full list):

| File | Field | Enum source |
|---|---|---|
| `admin/coordination/pipeline/pipeline.page.html:181,191` | `run.kind`, `run.status` | `process_run.kind` (`crawl \| agent_schedule`), `process_run status` |
| `admin/coordination/activity/activity.page.html:142` | `ev.change_kind` | `activity change_kind` (`created\|updated\|state_changed\|...`) |
| `admin/coordination/agents/list/agents-list.page.html:91,130` | `row.platform`, `row.status` | `agents.platform` (`claude-cowork\|claude-code\|claude-web\|human\|system`) |
| `admin/learning/sessions/timeline/session-timeline.page.html:92,97,128,131` | `attempt.paradigm`, `attempt.outcome`, `obs.signal`, `obs.category` | `learning_attempts.paradigm`, `.outcome`, `observations.signal_type`, `.category` |
| `admin/learning/concepts/profile/concept-profile.page.html:57,177,216,239,240` | `c.kind`, `n.kind`, `n.maturity`, `a.outcome`, `obs.signal`, `obs.category` | concept/note enums |
| `admin/learning/dashboard/learning-dashboard.page.html:138,269,271` | `c.kind`, `obs.signal`, `obs.category` | same as above |
| `admin/learning/hypotheses/{list,profile}/*.html` | `row.state`, `h.state`, `a.outcome`, `obs.category` | `hypothesis_state` |
| `admin/knowledge/content/list/content-list.page.html:135` | `row.status` | `content_status` — already has badge styling via `statusTextClass()` but inner text is still raw enum value |
| `admin/knowledge/notes/editor/note-editor.page.html:71` | `n.kind` | note kind |
| `admin/commitment/goals/profile/...:233`, `…/projects/profile/…:175` | `p.status`, `t.priority` | goal/project status, todo priority |
| Inspector renderers (`admin/inspector/renderers/*`) | content/project/goal/agent/task/concept/hypothesis/todo statuses and kinds | various |
| Dead `admin/now/now-page.component.html:221`, `admin/atlas/atlas-page.component.html:137` | `g.status`, `item.status` | — fix indirectly when removing dead code |

These print machine-readable enum literals (e.g. `working`, `revision_requested`, `solved_with_hint`, `state-transition`, `evergreen`) without any human-readable label or visual cue. Some have a status-dot/badge wrapper but still show the raw token inside.

### 4.2 Breadcrumbs that may mislead

Breadcrumbs are declared via `data: { crumbs: [...] }` in `app.routes.ts`. Only three routes set crumbs:

| Route | Crumb chain | Note |
|---|---|---|
| `/admin/knowledge/content` | `Knowledge › Content` | Stable, clear. |
| `/admin/knowledge/review-queue` | `Knowledge › Review queue` | **Misleading** — the route reuses `ContentListPageComponent` with `data: { initialStatus: 'review' }` (see `app.routes.ts:192-202`). It is a filtered view of the same page, not a sibling entity. The crumb suggests a distinct resource. |
| `/admin/settings` | `Settings` | Maps to `AdminPlaceholderComponent` — see §4.5. |

All other admin routes (commitment, learning, coordination, notes, bookmarks, feeds, etc.) have no crumb metadata and rely on inline page titles instead. Inconsistent coverage; not strictly misleading, just patchy.

### 4.3 Disabled buttons without explanation

| File | Gated action | Disable condition (no user-facing reason) |
|---|---|---|
| `admin/commitment/today/today-page.component.html:59` | "Awaiting judgment" row link | `[disabled]="!row.route"` — entity has no detail route |
| `admin/coordination/activity/activity.page.html:122-123` | Open activity event detail | `[disabled]="!canOpen(ev)"` |
| Inspector action bars (content, task, hypothesis inspectors, `admin/inspector/renderers/*`) | Approve, Reply, Request Revision, Archive, etc. | `[disabled]="isActioning()"` — relies on opacity-50, no spinner, no aria-live, no text change |
| `admin/learning/hypotheses/profile/hypothesis-profile.page.html:189-190` | Add evidence | `[disabled]="isActioning() \|\| !evidenceBody().trim()"` |
| `admin/knowledge/feeds/list/feeds-list.page.html:132-133` | Force-fetch feed | `[disabled]="fetchingId() === row.id"` |

Pattern across all of these: opacity change only, no `aria-live` region announcing "in progress", no spinner glyph, no text change ("Submitting…"). For the single user, this means the button "looks the same" between idle-but-greyed and submitting-now.

### 4.4 Raw JSON / data dumps

One confirmed instance:

| File | Data |
|---|---|
| `admin/inspector/renderers/hypothesis-inspector/hypothesis-inspector.component.html:114-116` | `<pre>{{ item \| json }}</pre>` for each Evidence row (raw observation/evidence record) |

Otherwise, no `| json` pipe or `<pre>{{ … }}</pre>` blocks against rich entities were found in admin templates.

### 4.5 Placeholder / stub pages

| Route | Component | Message |
|---|---|---|
| `/admin/settings` | `admin/shared/admin-placeholder.component.ts:34-52` | "Coming soon … the route exists so navigation and keyboard shortcuts resolve; the page itself will land in a follow-up task." |

This is the **only** route currently delegated to `AdminPlaceholderComponent`. Grep-verified.

### 4.6 In-source `TODO` markers that affect UX

| File | TODO |
|---|---|
| `admin/knowledge/content/editor/content-editor.guard.ts:13` | "TODO(ux): replace window.confirm with the Catalyst Dialog component" |
| `admin/knowledge/notes/editor/note-editor.guard.ts:11` | Same TODO, notes editor |
| `admin/admin-layout/admin-layout.ts:84` | "TODO: remove once all surfaces use route navigation." (internal; not user-facing) |

Browser `window.confirm` is currently used for the unsaved-changes prompt on content/note editor exits.

---

## 5. What is uncertain / out of scope here

- Whether the `/api/admin/commitment/today` aggregate endpoint (api-spec §2.1) is shipped or only planned. The frontend builds the equivalent client-side and could either be defensive against an unshipped backend or deliberately fanning out — uncertain without backend confirmation.
- Whether `pages/uses/` is intentionally hidden (no route) or abandoned.
- Whether all `mastery_stage` multi-select callers in the frontend handle the comma-separated wire format per api-spec §4.2 — partially confirmed by an agent, not source-verified end-to-end.
- Whether `login.ts`'s `/bff/api/auth/google` URL is correct vs. a stale BFF naming relic.
- Whether the agent-reported inventory of "raw enum" sites is exhaustive — sampled, not 100% scanned.

---

## 6. Recommended next PRs

Each is intentionally small and behavior-isolated. Pick by priority, not by order.

1. **Fix broken admin-namespaced public link.** `pages/build-logs/build-logs.html:48` → switch `[routerLink]="'/admin/build-logs/' + log.slug"` to `[routerLink]="['/build-logs', log.slug]"`. Closes both the privacy leak and the broken navigation. ~2 LOC.
2. **Pass `?domain=` from `ConceptService.get()`.** Accept `(slug, domain)`, send `/api/admin/learning/concepts/${slug}?domain=${domain}`. Update the single caller `concept-profile.page.ts:56-62`. Aligns with api-spec §4.3 (slug+domain is required; current call would be a 400 if the backend tightened validation). Also rewrite the misleading doc comment in `concept.service.ts:8`.
3. **Delete dead admin pages.** Remove `src/app/admin/now/`, `src/app/admin/atlas/`, and the legacy redirect stubs `app.routes.ts:347-348` if those URLs are no longer linked anywhere off-app (uncertain; check external links to `/admin/now` and `/admin/atlas` first — bookmarks, old tweets, etc.). The comment in `today.service.ts:46` referencing `now-page` should also go.
4. **Decide on `pages/uses/`.** Either register a route + add to public nav, or delete the folder. Document the decision in the page README if kept.
5. **Reconcile `SessionSummary` and `LearningDashboard` type duplication.** Delete the `admin.model.ts` versions if they trace only to dead `now-page.component`; keep the `learning.model.ts` versions which match api-spec §4.1/§4.5.
6. **Humanize one enum surface at a time.** Start with the highest-traffic surfaces (Today page, Tasks list, Activity timeline, Content list status badge) — use a small `humanize(enumName, value)` helper or `*.enum.ts` label maps so the dashboard does not say `revision_requested` and `solved_with_hint` to a human reader. Inventory in §4.1.
7. **Add explanatory states to disabled buttons.** Smallest version: when `isActioning()` is true, change button label to e.g. "Approving…" and add `aria-live="polite"`. No new dependencies.
8. **Replace `<pre>{{ item | json }}</pre>` in `hypothesis-inspector.component.html`** with a humanized evidence row (the data has known shape — observation signal/category/severity).
9. **Decide whether `/admin/knowledge/review-queue` is a route or a filter.** If it's a filter, drop the standalone route + breadcrumb and link to `/admin/knowledge/content?status=review`. If it's a distinct surface, give it its own component so the breadcrumb stops being misleading.
10. **Decide on Settings.** Either implement (replace `AdminPlaceholderComponent`) or remove the route and any nav references until it is ready — placeholder-as-permanent erodes trust in nav targets.

None of these requires new dependencies, Storybook, Playwright, or test infrastructure. Each is a leaf-level change.

---

## 7. Changelog

- 2026-05-28 — initial map. Source: Angular app at `frontend/` HEAD = main, backend contract `docs/api-spec.md` v2.2.
