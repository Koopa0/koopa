# `/tags/:tag` — Owner Decision Memo

> **Date:** 2026-05-28
> **Author:** Claude Code (Opus 4.7)
> **Audit trigger:** `frontend/docs/page-semantics-api-contract-audit.md` §2.3.3 + §3 drift table + §7.3 Claude Design escalation.
> **Scope:** Investigation only. No application code, tests, or `api-spec.md` modified.
> **Decision required from:** Koopa (sole owner).

---

## 1. Source-confirmed facts (verified against code today)

### 1.1 Frontend route and component

- Route registered at `frontend/src/app/app.routes.ts:63-65`:
  ```ts
  { path: 'tags/:tag', loadComponent: () => import('./pages/tag/tag').then((m) => m.TagComponent) }
  ```
- Component: `frontend/src/app/pages/tag/tag.ts`
  - Reads `:tag` via `input.required<string>()`.
  - In `ngOnInit`, calls `TagService.getContentsByTag(tagValue, 1, 100)`.
  - Sets SEO `title: "Tag: ${tagValue}"`, `description: "All content tagged with ${tagValue}"`.
  - Renders: hero with tag name + `{N} related posts` counter; "Back to Articles" link; empty state "No content found for '{tag}'" → "Browse All Articles".
- Template `tag.html`: highlights `tag === tagName()` chip styling on each card (purely visual; no client-side filter).

### 1.2 Frontend service

- `frontend/src/app/core/services/tag.service.ts` — header comment is honest:
  > `// Tag is not a standalone API — aggregated from content list tags field`
- `getContentsByTag(tag, page, perPage)` delegates to `ContentService.listPublished({tag, page, perPage})`.
- `ContentService.listPublished` (`frontend/src/app/core/services/content.service.ts:21-33`) appends `tag` as a query parameter on `GET /api/contents`.

### 1.3 Backend public surface (canonical: `cmd/app/routes.go`)

Public, no-auth GET routes that exist today:
- `/api/contents`, `/api/contents/{slug}`, `/api/contents/by-type/{type}`, `/api/contents/related/{slug}`
- `/api/topics`, `/api/topics/{slug}`
- `/api/projects`, `/api/projects/{slug}`, `/api/portfolio`
- `/api/bookmarks`, `/api/bookmarks/{slug}`
- `/api/search`, `/api/knowledge-graph`, `/api/feed/rss`, `/api/feed/sitemap`

Tag-related routes that exist:
- `GET /api/admin/knowledge/tags`, `POST/PUT/DELETE /api/admin/knowledge/tags[/{id}]`, `POST /api/admin/knowledge/tags/merge` (all admin, auth-gated)
- `GET /api/admin/knowledge/tag-aliases`, plus admin tag-alias mutations

There is **no** public `/api/tags`, `/api/tags/{tag}`, or `/api/tags/{tag}/contents` endpoint.

### 1.4 What the backend actually does with `?tag=…` on `/api/contents`

**The backend silently drops the parameter.** Verified at `internal/content/public.go:124-140` (`parsePublicFilter`) and `internal/content/content.go:96-104` (`PublicFilter` struct):

```go
type PublicFilter struct {
    Page    int
    PerPage int
    Type    *Type
    Since   *time.Time
}

func (h *Handler) parsePublicFilter(r *http.Request) PublicFilter {
    page, perPage := api.ParsePagination(r)
    f := PublicFilter{Page: page, PerPage: perPage}

    if t := r.URL.Query().Get("type"); t != "" { /* ... */ }
    if s := r.URL.Query().Get("since"); s != "" { /* ... */ }
    return f
}
```

There is no `tag` read. The store call (`internal/content/content.go:366-408` `PublicContents`) passes only `Limit`, `Offset`, `ContentType`, `Since` into the sqlc query — no tag join.

**Operational consequence (today, in production):** A request to `/tags/Angular` triggers `GET /api/contents?tag=Angular&page=1&per_page=100`. The backend returns up to 100 of the most recent published-and-public contents, **completely unfiltered by tag**. The page renders all of them. The same content appears at `/tags/anything-else-that-does-not-exist`.

This contradicts the audit's softer claim (`page-semantics-api-contract-audit.md` §2.3.3) that filtering "works as a content filter but not as a 'tag exists' query." The audit was checking shape, not behavior. Re-verified today: the `?tag=` filter does nothing.

### 1.5 What 404 looks like for a nonexistent tag

- Backend: returns 200 with up to 100 unfiltered content items (per §1.4).
- Frontend page: renders the full grid — visitor cannot tell the tag doesn't exist.
- If the corpus is small enough that the page is empty, the empty state shows `"No content found for '{tag}'"` — but for the wrong reason.

### 1.6 api-spec coverage

`frontend/docs/api-spec.md` v2.2 mentions tags only at:
- §1.2 example (`?status=draft,review`) — tags not listed.
- §3.1 — content row has a `"tags": ["pg", "explain"]` field.
- §3.7 (admin) — `GET/POST/PUT/DELETE /api/admin/knowledge/tags` + `/merge` + tag-aliases.

The spec defines **no public tag routes** and does not document `/api/contents?tag=` as a supported query parameter. The frontend invocation is undocumented contract usage that the backend never implemented.

### 1.7 Existing tests

- `frontend/src/app/pages/tag/tag.spec.ts` — single `should create` test, no behavioral assertion (verified read).
- `frontend/src/app/core/services/tag.service.spec.ts` — three tests on `getContentsByTag` (URL shape, params, error propagation), all using HttpTestingController mocks. The mocks return tag-filtered data; **the test fixture does not match real backend behavior** described in §1.4. The tests would still pass against a backend that ignored the tag param, because they assert request shape, not response correctness.
- Other in-app entry points to `/tags/:tag`: `pages/articles/articles.html:79`, `pages/essays/essays.html:79`, `pages/til-detail/til-detail.html:35` (all `[routerLink]="'/tags/' + tag"`).

---

## 2. Questions answered

| # | Question | Answer |
|---|---|---|
| 1 | First-class public route or convenience content-filter page? | **Neither, in practice.** The route was implemented as a convenience content-filter (per `TagService` comment §1.2), but the filter doesn't work on the backend (§1.4). It is a route promising a tag listing that the system cannot fulfill. |
| 2 | Does api-spec define public tag routes? | **No.** §1.6. |
| 3 | Backend exposes public tag existence lookup or only content filtering by tag? | **Neither.** §1.3, §1.4. Only admin tag CRUD exists. Public `?tag=` on `/api/contents` is silently dropped. |
| 4 | What happens for a nonexistent tag? | The same as for an existent one — up to 100 latest published contents regardless. Page does not 404, does not empty out, does not signal the tag is unknown. §1.5. |
| 5 | UI implies stronger semantics than backend provides? | **Yes.** The page heading shows the tag as a first-class entity, the SEO copy promises "all content tagged with X", and `{N} related posts` reads as a filtered count. None of those are true. §1.1, §1.4. |
| 6 | Real UX/contract problem, or acceptable article-site behavior? | **Real problem.** The page silently lies about its content for every tag URL. This is worse than the audit characterized — the audit's "MEDIUM" rating assumed `?tag=` worked. With the backend not honoring it, every internal `[routerLink]="'/tags/' + tag"` (articles/essays/til-detail) becomes a misleading link. |

---

## 3. Options

### A. Keep `/tags/:tag` as a lightweight content-filter page

Make the existing route honest about what the backend can do today.

**Required UI wording changes:**
- Either remove the "Back to Articles" affordance and the `{N} related posts` count (they imply a filtered view), or
- Add a banner explaining: "Tag filtering is approximate — showing recent publications that include this tag in metadata." — only honest if backend filtering is implemented; see below.
- SEO meta description: drop "All content tagged with X"; replace with something like "Articles mentioning {tag} on koopa0.dev."

**Required backend change (mandatory for Option A to be honest):**
- Extend `internal/content/PublicFilter` with a `Tag *string` field.
- Extend `parsePublicFilter` to read `?tag=`.
- Extend the sqlc query `PublishedContents` (and `PublishedContentsCount`) with an optional `tag` join on `content_tags` + `tags`.
- Without this change, Option A is "keep the page, accept it shows the wrong content for every tag" — that is not an honest option.

**Required api-spec wording change:**
- Add a "Public site contract" subsection enumerating `/api/contents` query params and explicitly listing `?tag=<slug>` as a supported optional filter.

**Test implications:**
- `tag.service.spec.ts` already asserts the request shape; that part is still valid.
- Add a backend integration test seeding contents with overlapping tags and asserting `?tag=X` returns only contents whose `tags` array contains X.
- Add a public/private filter regression test (audit §6.3 PR 1): seed `is_public=false` content with the same tag and assert it does NOT appear in `?tag=X`.
- `tag.spec.ts` should gain a "renders empty state for unknown tag" test once the backend returns 0 rows for an unknown tag (currently impossible to test honestly).

**Cost:** small backend change + spec update + one frontend wording pass. Keeps internal links (articles/essays/til-detail) working.

**Trade-off:** still does not validate tag existence — `/tags/random-string` returns 0 results, page shows empty state. This is acceptable IF the empty state copy doesn't imply the tag is real.

---

### B. Deprecate/remove `/tags/:tag`

Remove the route and accept that tag discovery flows through topic detail (`/topics/:slug`) or search.

**What links/routes break:**
- `pages/articles/articles.html:79` — tag chips on article list page link to `/tags/` (3rd grep result in §1.7).
- `pages/essays/essays.html:79` — same on essays list.
- `pages/til-detail/til-detail.html:35` — same on TIL detail.
- Tag chips on the tag page itself (irrelevant if the page is removed).
- Tag chips on article-detail, build-log-detail, essay-detail, project-detail (need to be re-checked; the §1.7 grep was tight to current findings only and may have missed in-content occurrences).

**Redirect strategy:**
- Option B1 (hard remove): delete the `tags/:tag` route definition; rewrite the four templates above to either remove the `routerLink` (make tags non-clickable text) or point them to `/search?q={tag}`.
- Option B2 (soft redirect): keep `tags/:tag` as a redirect to `/search?q={tag}` for one release cycle, then remove. SSR-wise this works if rendered server-side; client navigation will redirect after the route resolves.

**Test implications:**
- Delete `frontend/src/app/pages/tag/tag.{ts,html,spec.ts}`.
- Delete `frontend/src/app/core/services/tag.service.{ts,spec.ts}` (or keep `TagService` only if anything else consumes it — grep `§1.7` confirms only `tag.ts` imports it; safe to delete).
- Add a new test asserting tag chips link to `/search` (or are non-clickable, per B1).

**Cost:** moderate — touches four templates and removes two files (and their tests). Zero backend work. Zero api-spec change beyond removing tag references if any are added later.

**Trade-off:** loses the dedicated tag page entirely. Topic-driven discovery (per backend semantic contract §1 "topic-driven, format-secondary") becomes the primary surface; this aligns with the project's stated direction better than the current tag page does.

---

### C. Add a first-class public tag endpoint

Elevate tags to a first-class browse surface backed by real endpoints.

**Proposed endpoint shape:**
- `GET /api/tags` — list publicly-visible tags ordered by usage count.
  ```
  { "data": [ { "name": "Angular", "slug": "angular", "count": 12 } ], "total": 84 }
  ```
- `GET /api/tags/{tag}` — verify tag existence + return metadata + contents.
  ```
  { "tag": { "name": "Angular", "slug": "angular", "count": 12 },
    "contents": [ { /* ApiContent row */ } ],
    "meta": { "total": 12, "page": 1, "per_page": 20, "total_pages": 1 } }
  ```
- 404 when tag does not exist (the part Option A still cannot deliver without an existence check).

**Backend responsibility:**
- New `internal/tag/public.go` with two handlers: `PublicList`, `PublicByName` (or `BySlug` if tag slugs are canonical).
- New sqlc queries: tag count aggregation (visible-content scope), contents-by-tag join with `is_public=true AND status='published'`.
- Decide whether tag canonicalization happens at write or read (the existing admin `/merge` and `/tag-aliases` plumbing suggests write-time canonicalization is the project's model — public lookup should use the canonical name post-alias resolution).
- Routes added to `cmd/app/routes.go` under the existing public block.

**Frontend responsibility:**
- `TagService` calls `/api/tags/{slug}` instead of routing through `ContentService.listPublished`.
- Component renders 404 view when backend returns 404 (currently impossible per §1.5).
- SEO + meta description become accurate.
- Optionally add a `/tags` index page using `/api/tags`.

**api-spec update:**
- Add §3.8 "Tags (public)" with both endpoint specs and the 404 contract.
- Cross-reference: state that the admin tag CRUD in §3.7 mutates the same `tags` rows that this public read surface exposes.

**Test implications:**
- Backend integration tests for both endpoints (existence check, count semantics, public/private filter).
- Update `tag.service.spec.ts` to point at the new URL.
- Update `tag.spec.ts` to assert 404 behavior.

**Why this is or is not worth it for Koopa:**
- **Against:** the project's own positioning treats topics as the canonical organizing axis and tags as descriptive content metadata (per backend semantic contract §3 vocabulary split). Promoting tags to first-class browse status mildly contradicts that. For a single-author site with a small published corpus (<100 articles per the audit's TIL scaling note), tag pages add a maintenance surface without much reader value.
- **For:** if Koopa wants tag-based discovery as a separate axis from topics (e.g. cross-cutting tags like `pgvector` that span multiple topics), a first-class endpoint is the only honest way to do it. The admin tag system already exists; the cost is one read-only handler pair plus tests.
- **Decision criterion:** does any visitor analytics or stated reader scenario depend on tag-as-browse-axis? If yes → C. If no → B (and consider removing tag chips from article/essay templates entirely).

---

## 4. Cross-option notes

- All three options require touching the same template surfaces that currently link to `/tags/` (§1.7 references). The PR scope differs only in destination, not in template count.
- The audit's §7.3 Claude Design escalation candidate is still live and should be reviewed against this memo before owner picks A/B/C. The Design escalation asks the broader product question ("should public tag discovery exist at all?"). This memo provides the technical reality the Design answer must work with.
- Whatever option is chosen, the `tag.service.spec.ts` fixture that mocks tag-filtered responses should be re-verified against actual backend behavior, not held up as proof of correctness.

---

## 5. Verification

| Check | Result |
|---|---|
| `git diff --check` (whitespace) | run after this memo lands; this memo creates a new file only |
| App build required | No — documentation only |
| Application code modified | No |
| Test files modified | No |
| `api-spec.md` modified | No |
| Backend handlers modified | No |
| Routes modified | No |

Behavioral surface area changed by this memo: **zero**.

Files created by this memo:
- `frontend/docs/frontend/tag-route-owner-decision.md` (this document)

---

## Appendix: Sources cited

- `frontend/src/app/app.routes.ts:63-65`
- `frontend/src/app/pages/tag/tag.ts`, `tag.html`, `tag.spec.ts`
- `frontend/src/app/core/services/tag.service.ts` + `.spec.ts`
- `frontend/src/app/core/services/content.service.ts:21-33`
- `frontend/docs/api-spec.md` (v2.2)
- `frontend/docs/page-semantics-api-contract-audit.md` §1.2 risk #4, §2.3.3, §3 drift table, §7.3
- `cmd/app/routes.go` (public block ~lines 99-115; admin tag block ~lines 222-247)
- `internal/content/public.go:19-140` (PublicList, parsePublicFilter)
- `internal/content/content.go:96-104` (PublicFilter struct), `:364-408` (PublicContents store)
- `internal/content/query.sql` (PublishedContents query — no tag filter)
- `internal/tag/` package (admin CRUD only)
- In-app `/tags/` referrers: `pages/articles/articles.html:79`, `pages/essays/essays.html:79`, `pages/til-detail/til-detail.html:35`
