# Admin API Reference

Base URL: `/bff/api` (Angular BFF proxy → backend :8080)

## Authentication

```
POST /api/auth/login     { email, password } → { token, refresh_token }
POST /api/auth/refresh   { refresh_token }   → { token, refresh_token }
```

All `/api/admin/*` routes require `Authorization: Bearer <token>`.
CSRF protection is handled via Fetch metadata (see CSRF section below) — no extra headers needed.

---

## Content Management

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/admin/contents` | — | `{ data: Content[], total, page, per_page }` | Query: `?page=1&per_page=20&type=article&tag=go` |
| POST | `/api/admin/contents` | `CreateParams` | `201 { data: Content }` | |
| PUT | `/api/admin/contents/{id}` | `UpdateParams` | `{ data: Content }` | Partial update |
| DELETE | `/api/admin/contents/{id}` | — | `204` | |
| POST | `/api/admin/contents/{id}/publish` | — | `{ data: Content }` | Sets status=published, published_at=now |

### Content Types
`article` | `essay` | `build-log` | `til` | `note` | `bookmark` | `digest`

### Content Statuses
`draft` | `review` | `published` | `archived`

---

## Review Queue

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/admin/review` | — | `{ data: Review[] }` | Pending reviews |
| POST | `/api/admin/review/{id}/approve` | — | `204` | |
| POST | `/api/admin/review/{id}/reject` | `{ notes }` | `204` | |
| PUT | `/api/admin/review/{id}/edit` | `{ body }` | `204` | Edit + approve |

---

## Collected Data (RSS/External)

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/admin/collected` | — | `{ data: CollectedData[] }` | Query: `?status=unread&page=1` |
| POST | `/api/admin/collected/{id}/curate` | — | `204` | Mark as curated |
| POST | `/api/admin/collected/{id}/ignore` | — | `204` | Mark as ignored |
| POST | `/api/admin/collected/{id}/feedback` | `{ feedback: "up"\|"down" }` | `204` | AI score feedback loop |

### CollectedData Fields
```
id, title, url, source_name, content_text,
ai_score, ai_title_zh, ai_summary_zh, ai_tags,
status (unread|read|curated|ignored),
feedback (null|up|down),
collected_at
```

---

## Feeds Management

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/admin/feeds` | — | `{ data: Feed[] }` | Query: `?schedule=hourly_4` |
| POST | `/api/admin/feeds` | `{ name, url, schedule, enabled }` | `201 { data: Feed }` | |
| PUT | `/api/admin/feeds/{id}` | Partial update | `{ data: Feed }` | |
| DELETE | `/api/admin/feeds/{id}` | — | `204` | |
| POST | `/api/admin/feeds/{id}/fetch` | — | `{ new_items: N }` | Manual fetch |

### Feed Schedules
`hourly_4` | `daily` | `weekly`

---

## Projects

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/projects` | — | `{ data: Project[] }` | Public |
| GET | `/api/projects/{slug}` | — | `{ data: Project }` | Public |
| POST | `/api/admin/projects` | `CreateParams` | `201 { data: Project }` | |
| PUT | `/api/admin/projects/{id}` | `UpdateParams` | `{ data: Project }` | |
| DELETE | `/api/admin/projects/{id}` | — | `204` | |

### Project Statuses
`planned` | `in-progress` | `on-hold` | `completed` | `maintained` | `archived`

---

## Topics

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/topics` | — | `{ data: Topic[] }` | Public |
| POST | `/api/admin/topics` | `{ slug, name, description }` | `201 { data: Topic }` | |
| PUT | `/api/admin/topics/{id}` | Partial | `{ data: Topic }` | |
| DELETE | `/api/admin/topics/{id}` | — | `204` | |

---

## Flow Runs (AI Pipeline)

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/admin/flow-runs` | — | `{ data: FlowRun[] }` | Query: `?status=completed&page=1` |
| GET | `/api/admin/flow-runs/{id}` | — | `{ data: FlowRun }` | Includes output JSON |

### Flow Names
`content-review` | `content-polish` | `collect-and-score` | `digest-generate` | `bookmark-generate` | `morning-brief` | `weekly-review` | `project-track` | `content-strategy` | `build-log-generate`

### Flow Statuses
`pending` | `running` | `completed` | `failed`

---

## Content Polish (AI Rewrite)

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| POST | `/api/admin/flow/polish/{content_id}` | — | `202` | Async, submits job |
| GET | `/api/admin/flow/polish/{content_id}/result` | — | `{ data: PolishResult }` | Poll until completed |
| POST | `/api/admin/flow/polish/{content_id}/approve` | — | `200` | Applies polished body |

---

## Pipeline Triggers

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| POST | `/api/pipeline/collect` | `{ schedule?: "hourly_4" }` | `202` | Triggers feed collection |
| POST | `/api/pipeline/digest` | `{ start_date, end_date }` | `202` | Generates weekly/monthly digest |

---

## Upload

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| POST | `/api/admin/upload` | `multipart/form-data` field=`file` | `{ url }` | Max 5MB, JPEG/PNG/WebP/GIF |

---

## Tracking Topics

| Method | Path | Body | Response | Notes |
|--------|------|------|----------|-------|
| GET | `/api/admin/tracking` | — | `{ data: TrackingTopic[] }` | |
| POST | `/api/admin/tracking` | `{ name, keywords[], sources[], schedule }` | `201` | |
| PUT | `/api/admin/tracking/{id}` | Partial | `200` | |
| DELETE | `/api/admin/tracking/{id}` | — | `204` | |

---

## Error Format

```json
{
  "error": {
    "code": "not_found",
    "message": "content not found"
  }
}
```

Common codes: `bad_request`, `unauthorized`, `not_found`, `conflict`, `internal_error`

---

## CSRF Protection (Fetch Metadata)

The backend uses **Fetch metadata** (`Sec-Fetch-Site` header) for CSRF protection, implemented via Go 1.25+ `http.CrossOriginProtection`.

- **Safe methods** (GET, HEAD, OPTIONS): always allowed.
- **Mutating methods** (POST, PUT, DELETE): blocked if `Sec-Fetch-Site` is `cross-site` from an untrusted origin.
- **Non-browser requests** (no `Sec-Fetch-Site` header): allowed — covers the BFF proxy and API clients like `curl`.
- **Trusted origin**: the configured `CORS_ORIGIN` (e.g., `https://koopa0.dev`).

No CSRF tokens or cookies are needed. The browser automatically sends `Sec-Fetch-Site`, and the backend rejects cross-origin mutating requests.

For the Angular frontend via BFF proxy: requests originate from the SSR server (server-to-server), so they pass through without `Sec-Fetch-Site` checks.

---

## Pagination

Query params: `?page=1&per_page=20` (max 100)

Response:
```json
{
  "data": [...],
  "total": 42,
  "page": 1,
  "per_page": 20
}
```

---

## Admin UI Screens (Suggested)

| Screen | Primary API | Purpose |
|--------|-------------|---------|
| Dashboard | `GET /stats`, `GET /flow-runs` | Overview, recent flow status |
| Content List | `GET /contents` | CRUD contents, publish, trigger polish |
| Review Queue | `GET /review` | Approve/reject/edit AI-reviewed content |
| Collected Data | `GET /collected` | Browse RSS items, feedback, curate |
| Feeds | `GET /feeds` | Manage RSS sources, manual fetch |
| Flow Runs | `GET /flow-runs` | Monitor AI pipeline execution |
| Projects | `GET /projects` | View/edit projects (synced from Notion) |
| Settings | `GET /tracking` | Manage tracking topics |
