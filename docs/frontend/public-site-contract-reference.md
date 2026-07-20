# Public reading site — backend contract reference (real shapes)

> The visitor-facing (non-admin) read API for the koopa public reading site
> (the Zed-docs-aesthetic "let the work speak" surface). All **already built** —
> no auth, no admin gate. Verified against source 2026-06-23. Envelope `{ "data": … }`;
> lists are `[]` never `null`. `body` is **Markdown**. Only `is_public=true`,
> published content is fetched by public SQL (detail 404s for drafts and
> withdrawn snapshots).

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
- `GET /api/contents/{slug}` → `Content` — the **article page** (full `body` Markdown). 404 unless currently published and public.
- `GET /api/contents/by-type/{type}` → `[Content]` — by type (article / essay / build-log / til / digest).

## Topic

- `GET /api/topics` → `[Topic]` — the topic index (docs-style left nav source).
- `GET /api/topics/{slug}` → `{ "topic": {Topic}, "contents": [Content], "related_tags": [{TagCount}] }` — the **topic page** (a topic + its published content + related tags).

## Misc public reads
- `GET /api/feed/rss` (RSS) · `GET /api/feed/sitemap` (sitemap XML). These and
  public topic projections use `Cache-Control: no-store`, so a committed
  withdrawal is not retained by Koopa's own response caches.

## Design notes (Zed-docs aesthetic — the right home for it)
- This surface is **the opposite of admin**: generous whitespace, serif long-form body, quiet docs-style left nav (topics), mono code blocks, calm reading. Density is NOT the goal here.
- `body` is Markdown → render with a Markdown pipeline + your prose/typography styles; `reading_time_min`, `excerpt`, `cover_image` feed the article cards; `topics` drives the docs nav.
- The bound design bundle already has the public-site kit (Home/Article/Topic) — extend those, dark-default kept but lean into the reading typography.
- **Admin reuse (option 3, free):** the admin content editor's "publish preview" embeds this same article component against `GET /api/contents/{slug}` (or an admin draft-preview variant) — DRY, no separate build.
