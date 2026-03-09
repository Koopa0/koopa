# koopa0.dev Backend API 文件

> Base URL: `http://localhost:8080`
>
> 所有回應皆為 JSON，Content-Type: `application/json`（RSS/Sitemap 除外）

---

## 回應格式

### 成功（單筆資料）

```json
{
  "data": { ... }
}
```

### 成功（分頁列表）

```json
{
  "data": [ ... ],
  "meta": {
    "total": 42,
    "page": 1,
    "per_page": 20,
    "total_pages": 3
  }
}
```

### 錯誤

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "content not found"
  }
}
```

常見 error code：`BAD_REQUEST`、`UNAUTHORIZED`、`NOT_FOUND`、`CONFLICT`、`INTERNAL`

---

## 通用分頁參數

所有分頁端點支援：

| 參數 | 類型 | 預設 | 說明 |
|------|------|------|------|
| `page` | int | 1 | 頁碼 |
| `per_page` | int | 20 | 每頁筆數（上限 100） |

---

## 認證

需要認證的端點（`/api/admin/*`、`/api/pipeline/*`、`/api/webhook/*`）須在 Header 帶上 JWT：

```
Authorization: Bearer <access_token>
```

Access Token 有效期 15 分鐘，Refresh Token 有效期 7 天。

---

## 1. Auth 認證

### POST /api/auth/login

登入取得 Token。

**Request Body:**

```json
{
  "email": "admin@koopa0.dev",
  "password": "changeme"
}
```

**Response 200:**

```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2..."
  }
}
```

**Error 401:** 帳密錯誤

---

### POST /api/auth/refresh

用 Refresh Token 換新的 Token Pair（Rotation 機制，舊 token 立即失效）。

**Request Body:**

```json
{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2..."
}
```

**Response 200:** 同 login 回應格式

**Error 401:** Refresh Token 無效或過期

---

## 2. Contents 內容

### GET /api/contents

取得已發布的內容列表。

**Query Parameters:**

| 參數 | 類型 | 說明 |
|------|------|------|
| `page` | int | 頁碼 |
| `per_page` | int | 每頁筆數 |
| `type` | string | 篩選類型：`article`、`essay`、`build-log`、`til`、`note`、`bookmark`、`digest` |
| `tag` | string | 篩選標籤 |

**Response 200:**

```json
{
  "data": [
    {
      "id": "uuid",
      "slug": "building-knowledge-engine",
      "title": "打造個人知識引擎",
      "body": "...",
      "excerpt": "...",
      "type": "article",
      "status": "published",
      "tags": ["go", "architecture"],
      "topics": [
        { "id": "uuid", "slug": "backend", "name": "後端開發" }
      ],
      "source": "obsidian",
      "source_type": "obsidian",
      "series_id": null,
      "series_order": null,
      "review_level": "standard",
      "ai_metadata": null,
      "reading_time": 8,
      "cover_image": "https://r2.koopa0.dev/covers/knowledge-engine.jpg",
      "published_at": "2026-03-01T00:00:00Z",
      "created_at": "2026-02-28T10:00:00Z",
      "updated_at": "2026-03-01T00:00:00Z"
    }
  ],
  "meta": { "total": 42, "page": 1, "per_page": 20, "total_pages": 3 }
}
```

---

### GET /api/contents/{slug}

取得單篇內容（需已發布）。

**Response 200:**

```json
{
  "data": { ... }  // Content 物件，同上
}
```

**Error 404:** 找不到或未發布

---

### GET /api/contents/type/{type}

依類型篩選已發布內容。`{type}` 為：`article`、`essay`、`build-log`、`til`、`note`、`bookmark`、`digest`

回應格式同 `GET /api/contents`（分頁）。

---

### GET /api/search

全文搜尋已發布內容（PostgreSQL `websearch_to_tsquery`）。

**Query Parameters:**

| 參數 | 類型 | 必填 | 說明 |
|------|------|------|------|
| `q` | string | 是 | 搜尋關鍵字 |
| `page` | int | 否 | 頁碼 |
| `per_page` | int | 否 | 每頁筆數 |

**Response 200:** 分頁格式，同 `GET /api/contents`

**Error 400:** 缺少 `q` 參數

---

## 3. Topics 主題

### GET /api/topics

取得所有主題列表。

**Response 200:**

```json
{
  "data": [
    {
      "id": "uuid",
      "slug": "backend",
      "name": "後端開發",
      "description": "Go, PostgreSQL, 系統架構",
      "icon": "🔧",
      "content_count": 15,
      "sort_order": 1,
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

---

### GET /api/topics/{slug}

取得單一主題及其內容列表（分頁）。

**Query Parameters:** `page`、`per_page`

**Response 200:**

```json
{
  "data": {
    "topic": {
      "id": "uuid",
      "slug": "backend",
      "name": "後端開發",
      "description": "...",
      "icon": "🔧",
      "content_count": 15,
      "sort_order": 1,
      "created_at": "...",
      "updated_at": "..."
    },
    "contents": [
      { ... }  // Content 物件陣列
    ]
  },
  "meta": { "total": 15, "page": 1, "per_page": 20, "total_pages": 1 }
}
```

**Error 404:** 主題不存在

---

## 4. Projects 作品集

### GET /api/projects

取得所有專案列表。

**Response 200:**

```json
{
  "data": [
    {
      "id": "uuid",
      "slug": "knowledge-engine",
      "title": "個人知識引擎",
      "description": "可輸入、可輸出的知識系統",
      "long_description": "...",
      "role": "Full-stack Developer",
      "tech_stack": ["Go", "Angular", "PostgreSQL"],
      "highlights": ["AI Pipeline", "Obsidian 同步"],
      "problem": "...",
      "solution": "...",
      "architecture": "...",
      "results": "...",
      "github_url": "https://github.com/koopa0/blog",
      "live_url": "https://koopa0.dev",
      "featured": true,
      "sort_order": 1,
      "status": "in-progress",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

`status` 可能值：`in-progress`、`completed`、`maintained`、`archived`

---

### GET /api/projects/{slug}

取得單一專案。

**Response 200:**

```json
{
  "data": { ... }  // Project 物件
}
```

**Error 404:** 專案不存在

---

## 5. Feed 訂閱

### GET /api/feed/rss

RSS 2.0 訂閱（最新 20 篇已發布內容）。

**Response 200:** `Content-Type: application/rss+xml; charset=utf-8`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>koopa0.dev</title>
    <link>https://koopa0.dev</link>
    <description>Koopa's knowledge engine</description>
    <item>
      <title>文章標題</title>
      <link>https://koopa0.dev/article/slug</link>
      <description>摘要</description>
      <pubDate>Mon, 01 Mar 2026 00:00:00 +0000</pubDate>
      <guid>uuid</guid>
    </item>
  </channel>
</rss>
```

---

### GET /api/feed/sitemap

XML Sitemap（所有已發布內容）。

**Response 200:** `Content-Type: application/xml; charset=utf-8`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://koopa0.dev/article/slug</loc>
    <lastmod>2026-03-01</lastmod>
  </url>
</urlset>
```

---

## 6. Admin — Contents 管理

> 以下端點皆需 `Authorization: Bearer <token>`

### POST /api/admin/contents

建立新內容。

**Request Body:**

```json
{
  "slug": "my-article",
  "title": "文章標題",
  "body": "Markdown 內文...",
  "excerpt": "摘要",
  "type": "article",
  "status": "draft",
  "tags": ["go", "tutorial"],
  "topic_ids": ["uuid-1", "uuid-2"],
  "source": "obsidian",
  "source_type": "obsidian",
  "series_id": null,
  "series_order": null,
  "review_level": "standard",
  "ai_metadata": null,
  "reading_time": 5,
  "cover_image": "https://r2.koopa0.dev/covers/my-article.jpg"
}
```

必填欄位：`slug`、`title`、`type`

`cover_image` 為圖片 URL（nullable），用於文章封面。

預設值：`status` = `"draft"`、`review_level` = `"standard"`

**Response 201:** `{ "data": { ... } }` — Content 物件

**Error 400:** 缺少必填欄位
**Error 409:** slug 重複

---

### PUT /api/admin/contents/{id}

更新內容（部分更新，僅傳要改的欄位）。

**Request Body:**

```json
{
  "title": "新標題",
  "tags": ["updated", "tags"],
  "status": "review"
}
```

所有欄位皆為 optional。

**Response 200:** `{ "data": { ... } }` — 更新後的 Content

**Error 404:** 內容不存在
**Error 409:** slug 重複

---

### DELETE /api/admin/contents/{id}

刪除內容（Archive）。

**Response 204:** No Content

---

### POST /api/admin/contents/{id}/publish

發布內容（狀態改為 `published`，設定 `published_at`）。

**Response 200:** `{ "data": { ... } }` — 已發布的 Content

**Error 404:** 內容不存在

---

## 7. Admin — Topics 管理

### POST /api/admin/topics

建立新主題。

**Request Body:**

```json
{
  "slug": "backend",
  "name": "後端開發",
  "description": "Go, PostgreSQL, 系統架構",
  "icon": "🔧",
  "sort_order": 1
}
```

必填：`slug`、`name`

**Response 201:** `{ "data": { ... } }` — Topic 物件

**Error 409:** slug 重複

---

### PUT /api/admin/topics/{id}

更新主題（部分更新）。

**Request Body:**

```json
{
  "name": "新名稱",
  "description": "新描述"
}
```

**Response 200:** `{ "data": { ... } }` — Topic 物件

**Error 404:** 主題不存在

---

### DELETE /api/admin/topics/{id}

刪除主題。

**Response 204:** No Content

---

## 8. Admin — Projects 管理

### POST /api/admin/projects

建立新專案。

**Request Body:**

```json
{
  "slug": "my-project",
  "title": "專案名稱",
  "description": "簡短描述",
  "long_description": "詳細描述...",
  "role": "Full-stack Developer",
  "tech_stack": ["Go", "Angular"],
  "highlights": ["Feature A", "Feature B"],
  "problem": "要解決的問題",
  "solution": "解決方案",
  "architecture": "架構說明",
  "results": "成果",
  "github_url": "https://github.com/...",
  "live_url": "https://...",
  "featured": true,
  "sort_order": 1,
  "status": "in-progress"
}
```

必填：`slug`、`title`、`description`、`role`

`status` 可選值：`in-progress`（預設）、`completed`、`maintained`、`archived`

**Response 201:** `{ "data": { ... } }` — Project 物件

**Error 409:** slug 重複

---

### PUT /api/admin/projects/{id}

更新專案（部分更新）。

**Response 200:** `{ "data": { ... } }` — Project 物件

**Error 404:** 專案不存在

---

### DELETE /api/admin/projects/{id}

刪除專案。

**Response 204:** No Content

---

## 9. Admin — Review 審核佇列

### GET /api/admin/review

取得所有 pending 審核項目。

**Response 200:**

```json
{
  "data": [
    {
      "id": "uuid",
      "content_id": "uuid",
      "review_level": "standard",
      "status": "pending",
      "reviewer_notes": null,
      "content_title": "文章標題",
      "content_slug": "article-slug",
      "content_type": "article",
      "submitted_at": "2026-03-01T00:00:00Z",
      "reviewed_at": null
    }
  ]
}
```

---

### POST /api/admin/review/{id}/approve

核准審核項目。

**Response 204:** No Content

---

### POST /api/admin/review/{id}/reject

拒絕審核項目。

**Request Body:**

```json
{
  "notes": "需要修改的理由"
}
```

**Response 204:** No Content

---

### PUT /api/admin/review/{id}/edit

編輯後核准（先查詢再核准）。

**Response 204:** No Content

**Error 404:** 審核項目不存在

---

## 10. Admin — Collected 收集資料

### GET /api/admin/collected

取得收集的外部資料列表（分頁）。

**Query Parameters:**

| 參數 | 類型 | 說明 |
|------|------|------|
| `page` | int | 頁碼 |
| `per_page` | int | 每頁筆數 |
| `status` | string | 篩選狀態：`unread`、`read`、`curated`、`ignored` |

**Response 200:**

```json
{
  "data": [
    {
      "id": "uuid",
      "source_url": "https://example.com/article",
      "source_name": "Hacker News",
      "title": "外部文章標題",
      "original_content": "...",
      "ai_summary": "AI 產生的摘要",
      "relevance_score": 0.85,
      "topics": ["go", "performance"],
      "status": "unread",
      "curated_content_id": null,
      "collected_at": "2026-03-01T00:00:00Z"
    }
  ],
  "meta": { ... }
}
```

---

### POST /api/admin/collected/{id}/curate

將收集資料標記為已策展，並連結到已建立的內容。

**Request Body:**

```json
{
  "content_id": "uuid"
}
```

**Response 204:** No Content

---

### POST /api/admin/collected/{id}/ignore

將收集資料標記為忽略。

**Response 204:** No Content

---

## 11. Admin — Tracking 追蹤主題

### GET /api/admin/tracking

取得所有追蹤主題。

**Response 200:**

```json
{
  "data": [
    {
      "id": "uuid",
      "name": "Go 效能優化",
      "keywords": ["go", "performance", "benchmark"],
      "sources": ["hackernews", "reddit"],
      "enabled": true,
      "schedule": "0 */6 * * *",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

---

### POST /api/admin/tracking

建立追蹤主題。

**Request Body:**

```json
{
  "name": "Go 效能優化",
  "keywords": ["go", "performance"],
  "sources": ["hackernews"],
  "enabled": true,
  "schedule": "0 */6 * * *"
}
```

必填：`name`

預設值：`enabled` = `true`、`schedule` = `"0 */6 * * *"`

**Response 201:** `{ "data": { ... } }` — TrackingTopic 物件

---

### PUT /api/admin/tracking/{id}

更新追蹤主題（部分更新）。

**Response 200:** `{ "data": { ... } }` — TrackingTopic 物件

**Error 404:** 追蹤主題不存在

---

### DELETE /api/admin/tracking/{id}

刪除追蹤主題。

**Response 204:** No Content

---

## 12. Admin — Stats 統計

### GET /api/admin/stats

系統狀態（目前為 stub）。

**Response 200:**

```json
{
  "data": { "status": "ok" }
}
```

---

## 13. Pipeline 管線（Stub）

> 以下端點目前回傳 `501 Not Implemented`，尚未實作實際邏輯。

| 方法 | 路徑 | 說明 |
|------|------|------|
| POST | `/api/pipeline/sync` | 觸發 Obsidian 同步 |
| POST | `/api/pipeline/collect` | 觸發外部資料收集 |
| POST | `/api/pipeline/generate` | 觸發 AI 內容生成 |
| POST | `/api/pipeline/digest` | 觸發週報/月報生成 |

**Response 501:**

```
not implemented
```

---

## 14. Webhooks（Stub）

> 以下端點目前回傳 `501 Not Implemented`，尚未實作實際邏輯。

| 方法 | 路徑 | 說明 |
|------|------|------|
| POST | `/api/webhook/obsidian` | Obsidian 變更通知 |
| POST | `/api/webhook/notion` | Notion 變更通知 |
| POST | `/api/webhook/github` | GitHub 變更通知 |

---

## 內容類型對照表

| type | 說明 |
|------|------|
| `article` | 深度技術文章 |
| `essay` | 個人想法、非技術反思 |
| `build-log` | 專案開發紀錄 |
| `til` | 每日學習（短） |
| `note` | 技術筆記片段 |
| `bookmark` | 推薦資源 + 個人評語 |
| `digest` | 週報/月報 |

## 內容狀態流程

```
draft → review → published → archived
```

| status | 說明 |
|--------|------|
| `draft` | 草稿 |
| `review` | 審核中 |
| `published` | 已發布（公開可見） |
| `archived` | 已封存（不可見） |

## 審核等級

| review_level | 說明 |
|--------------|------|
| `auto` | 自動通過 |
| `light` | 輕度審核 |
| `standard` | 標準審核 |
| `strict` | 嚴格審核 |
