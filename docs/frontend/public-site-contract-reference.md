# Public reading site — backend contract reference (real shapes)

> The visitor-facing (non-admin) read API for the koopa public reading site
> (the Zed-docs-aesthetic "let the work speak" surface). All **already built** —
> no auth, no admin gate. Verified against source 2026-06-07. Envelope `{ "data": … }`;
> lists are `[]` never `null`. `body` is **Markdown**. Only `is_public=true`,
> published content is exposed (detail 404s if not public).

## Content (article render model)

**`content.Content`** — the shape every content endpoint returns:
```json
{
  "id": "uuid", "slug": "…", "title": "…",
  "body": "# Markdown…",          // full body (detail/by-slug); present in list too
  "excerpt": "…",
  "type": "article|essay|build-log|til|digest",
  "status": "published",          // public API only exposes published
  "tags": ["…"], "topics": [{TopicRef}],
  "series_id"?: "…", "series_order"?: 1,
  "is_public": true,
  "project_id"?: "uuid",
  "ai_metadata"?: { … },          // advisory (e.g. quality_score) — optional
  "reading_time_min": 5,
  "cover_image"?: "url",
  "published_at"?: "RFC3339", "created_at": "…", "updated_at": "…"
}
```

**Endpoints:**
- `GET /api/contents` → `[Content]` — published list (the index / article cards: title, excerpt, type, tags, topics, reading_time_min, cover_image, published_at).
- `GET /api/contents/{slug}` → `Content` — the **article page** (full `body` Markdown). 404 if not public.
- `GET /api/contents/by-type/{type}` → `[Content]` — by type (article / essay / build-log / til / digest).
- `GET /api/contents/related/{slug}` → `[Content]` — related (for the "read next" rail).

## Topic

- `GET /api/topics` → `[Topic]` — the topic index (docs-style left nav source).
- `GET /api/topics/{slug}` → `{ "topic": {Topic}, "contents": [Content], "related_tags": [{TagCount}] }` — the **topic page** (a topic + its published content + related tags).

## Project / Portfolio (the "用作品說話" surface)

- `GET /api/projects` → `[ProjectSummary]` · `GET /api/projects/{slug}` → rich project profile:
  `{ title, long_description?, role?, tech_stack[], highlights[], problem?, solution?, architecture?, results?, github_url?, live_url?, cover_image?, featured, is_public, sort_order }`.
- `GET /api/portfolio` → curated portfolio view.

## Misc public reads
- `GET /api/search?q=` → public search across published content.
- `GET /api/knowledge-graph` → content/topic graph (nodes + edges) for a graph view.
- `GET /api/feed/rss` (RSS) · `GET /api/feed/sitemap` (sitemap XML).

## Design notes (Zed-docs aesthetic — the right home for it)
- This surface is **the opposite of admin**: generous whitespace, serif long-form body, quiet docs-style left nav (topics), mono code blocks, calm reading. Density is NOT the goal here.
- `body` is Markdown → render with a Markdown pipeline + your prose/typography styles; `reading_time_min`, `excerpt`, `cover_image` feed the article cards; `topics` drives the docs nav; `related/{slug}` feeds "read next".
- The bound design bundle already has the public-site kit (Home/Article/Topic) — extend those, dark-default kept but lean into the reading typography.
- **Admin reuse (option 3, free):** the admin content editor's "publish preview" embeds this same article component against `GET /api/contents/{slug}` (or an admin draft-preview variant) — DRY, no separate build.
