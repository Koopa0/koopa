# HTTP API Reference (v2)

> koopa0.dev HTTP server — cmd/app/
> Last updated: 2026-04-07

## 概覽

v2 HTTP server 服務 Angular 前端。MCP tools 處理 task/goal/learning/journal 的寫入操作，
HTTP API 提供 content/project/topic 的公開 API 和 admin CRUD。

**Server:** `cmd/app/main.go`
**Port:** `PORT` env（預設 8080）
**Middleware chain:** recovery → requestID → CORS → logging → securityHeaders

---

## Health Endpoints

| Method | Path | Auth | 說明 |
|--------|------|------|------|
| GET | `/healthz` | No | Liveness check — 回傳 `ok` |
| GET | `/readyz` | No | Readiness check — ping DB，失敗回 503 |

---

## Public API（無需認證）

### Content

| Method | Path | 說明 | Response |
|--------|------|------|----------|
| GET | `/api/contents` | 內容列表（分頁） | `{ data: Content[], meta: Pagination }` |
| GET | `/api/contents/{slug}` | 單一內容（by slug） | `{ data: Content }` |
| GET | `/api/contents/by-type/{type}` | 依類型篩選（article, til, essay...） | `{ data: Content[], meta }` |
| GET | `/api/contents/related/{slug}` | 相關內容（embedding 相似度） | `{ data: RelatedContent[] }` |
| GET | `/api/search` | 全文搜尋（`?q=keyword`） | `{ data: Content[], meta }` |
| GET | `/api/knowledge-graph` | 知識圖譜 JSON | `{ data: KnowledgeGraph }` |
| GET | `/api/feed/rss` | RSS feed（XML） | RSS 2.0 XML |
| GET | `/api/feed/sitemap` | Sitemap（XML） | Sitemap XML |

### Topics

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/topics` | 所有 topics |
| GET | `/api/topics/{slug}` | 單一 topic + 該 topic 的 contents |

### Projects

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/projects` | 公開專案列表（`is_public = true`） |
| GET | `/api/projects/{slug}` | 單一專案詳情 |

---

## Auth

> 僅在設定 `GOOGLE_CLIENT_ID` 時啟用

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/auth/google` | 啟動 Google OAuth flow |
| GET | `/api/auth/google/callback` | OAuth callback |
| POST | `/api/auth/refresh` | 刷新 JWT token |

---

## Admin API（需 JWT 認證）

所有 `/api/admin/*` 路由需要 `Authorization: Bearer <token>` header。

### Admin: Content CRUD

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/contents` | 所有內容列表（含未發布） |
| GET | `/api/admin/contents/{id}` | 單一內容（by UUID） |
| POST | `/api/admin/contents` | 建立內容（draft） |
| PUT | `/api/admin/contents/{id}` | 更新內容 |
| DELETE | `/api/admin/contents/{id}` | 刪除內容 |
| POST | `/api/admin/contents/{id}/publish` | 發布內容 |
| PATCH | `/api/admin/contents/{id}/is-public` | 切換公開/私密 |

### Admin: Review Queue

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/review` | 待審內容列表 |
| POST | `/api/admin/review/{id}/approve` | 核准 |
| POST | `/api/admin/review/{id}/reject` | 退回 |
| PUT | `/api/admin/review/{id}/edit` | 編輯後核准 |

### Admin: Projects CRUD

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/projects` | 所有專案（含非公開） |
| POST | `/api/admin/projects` | 建立專案 |
| PUT | `/api/admin/projects/{id}` | 更新專案 |
| DELETE | `/api/admin/projects/{id}` | 刪除專案 |

### Admin: Goals

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/goals` | 目標列表 |
| PUT | `/api/admin/goals/{id}/status` | 更新目標狀態 |

### Admin: Topics

| Method | Path | 說明 |
|--------|------|------|
| POST | `/api/admin/topics` | 建立 topic |
| PUT | `/api/admin/topics/{id}` | 更新 topic |
| DELETE | `/api/admin/topics/{id}` | 刪除 topic |

### Admin: Tags

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/tags` | 標籤列表 |
| POST | `/api/admin/tags` | 建立標籤 |
| PUT | `/api/admin/tags/{id}` | 更新標籤 |
| DELETE | `/api/admin/tags/{id}` | 刪除標籤 |
| POST | `/api/admin/tags/backfill` | 批次回填 |
| POST | `/api/admin/tags/merge` | 合併標籤 |

### Admin: Tag Aliases

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/aliases` | 別名列表 |
| POST | `/api/admin/aliases/{id}/map` | 建立別名對映 |
| POST | `/api/admin/aliases/{id}/confirm` | 確認別名 |
| POST | `/api/admin/aliases/{id}/reject` | 拒絕別名 |
| DELETE | `/api/admin/aliases/{id}` | 刪除別名 |

### Admin: RSS Feeds

> 僅在 feed collector 啟用時可用

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/feeds` | Feed 列表 |
| POST | `/api/admin/feeds` | 新增 feed |
| PUT | `/api/admin/feeds/{id}` | 更新 feed |
| DELETE | `/api/admin/feeds/{id}` | 刪除 feed |
| POST | `/api/admin/feeds/{id}/fetch` | 手動抓取 feed |

### Admin: Collected Items（RSS entries）

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/collected` | 收集項目列表 |
| POST | `/api/admin/collected/{id}/curate` | 策展（加入內容） |
| POST | `/api/admin/collected/{id}/ignore` | 忽略 |
| POST | `/api/admin/collected/{id}/feedback` | 提交回饋 |

### Admin: Notes（Obsidian knowledge search）

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/notes` | 搜尋 Obsidian 筆記 |
| GET | `/api/admin/decisions` | 決策紀錄列表 |

### Admin: Activity

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/activity/sessions` | 工作 session 列表 |
| GET | `/api/admin/activity/changelog` | 變更紀錄 |

### Admin: Stats

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/stats` | 總覽統計 |
| GET | `/api/admin/stats/drift` | 偏移分析 |
| GET | `/api/admin/stats/learning` | 學習統計 |

### Admin: Upload

> 僅在設定 R2 endpoint 時可用

| Method | Path | 說明 |
|--------|------|------|
| POST | `/api/admin/upload` | 上傳檔案到 R2 |

---

## Response 格式

### 成功（單一）
```json
{ "data": { ... } }
```

### 成功（列表 + 分頁）
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
    "message": "not found"
  }
}
```

分頁參數：`?page=1&per_page=20`（per_page 上限 100）

---

## 前端已移除的 API（v1 → v2 變動）

以下 v1 API 已不存在於 v2 HTTP server。對應功能已移至 MCP 或已移除：

| 舊 API | 狀態 | 替代方案 |
|--------|------|----------|
| `/api/admin/tasks/*` | 移至 MCP | `capture_inbox`, `advance_work`, `plan_day` |
| `/api/admin/insights/*` | 移至 MCP | `propose_commitment(type=insight)`, `track_insight` |
| `/api/admin/session-notes` | 移除 | `write_journal`（MCP）, `session_delta`（MCP） |
| `/api/admin/notion-sources/*` | 移除 | Notion 整合已完全移除 |
| `/api/admin/pipeline/*` | 移除 | `system_status`（MCP）查看狀態 |
| `/api/admin/flow-runs/*` | 移除 | AI pipeline 暫時離線 |
| `/api/admin/flow/polish/*` | 移除 | AI pipeline 暫時離線 |
| `/api/admin/tracking/*` | 移除 | monitor package 已移除 |
| `/api/admin/today/summary` | 移至 MCP | `morning_context` |
| `/api/admin/stats/coverage-matrix` | 移至 MCP | `learning_dashboard(view=mastery)` |
| `/api/admin/stats/tag-summary` | 移至 MCP | `learning_dashboard(view=weaknesses)` |
| `/api/admin/stats/weakness-trend` | 移至 MCP | `learning_dashboard(view=weaknesses)` |
| `/api/admin/stats/learning-timeline` | 移至 MCP | `learning_dashboard(view=timeline)` |
| `/api/admin/retrieval-attempts` | 移至 MCP | `learning_dashboard(view=retrieval)` |
| `/api/admin/reconcile/history` | 移除 | reconcile package 已移除 |
| `/api/webhook/github` | 移除 | pipeline package 已移除 |
| `/api/webhook/notion` | 移除 | Notion 整合已移除 |

**前端需要更新的 services：**
`task.service.ts`, `insight.service.ts`, `learning-analytics.service.ts`,
`session-note.service.ts`, `notion-source.service.ts`, `pipeline.service.ts`,
`flow-run.service.ts`, `flow-polish.service.ts`, `tracking.service.ts`

---

## Server Configuration（環境變數）

| 變數 | 必要 | 預設 | 說明 |
|------|------|------|------|
| `DATABASE_URL` | Yes | — | PostgreSQL 連線字串 |
| `JWT_SECRET` | Yes | — | JWT 簽名金鑰 |
| `PORT` | No | 8080 | HTTP port |
| `CORS_ORIGIN` | No | `http://localhost:4200` | CORS origin |
| `SITE_URL` | No | `https://koopa0.dev` | RSS/sitemap 的 base URL |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth（設定後啟用 auth） |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth |
| `GOOGLE_REDIRECT_URI` | No | — | Google OAuth callback URL |
| `ADMIN_EMAIL` | No | — | 管理員 email |
| `R2_ENDPOINT` | No | — | R2 endpoint（設定後啟用 upload） |
| `R2_ACCESS_KEY_ID` | No | — | R2 credentials |
| `R2_SECRET_ACCESS_KEY` | No | — | R2 credentials |
| `R2_BUCKET` | No | — | R2 bucket name |
| `R2_PUBLIC_URL` | No | — | R2 public URL |
