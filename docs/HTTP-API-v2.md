# HTTP API Reference (v2)

> koopa0.dev HTTP server — 給前端開發者
> Last updated: 2026-04-07

## 1. 系統架構：前端需要知道的事

koopa0.dev 是一個 **AI-native 個人知識引擎**。v2 做了架構拆分：

```
Angular Frontend ──HTTP API──→ cmd/app/     （內容展示 + Admin CRUD）
Claude Desktop   ──MCP────→ cmd/mcp/     （工作流管理：任務、目標、學習、日記）
```

**關鍵變化：** Task、Goal、Learning、Journal 的寫入操作已移至 MCP（AI agent 操作），
HTTP server 只提供 Content/Project/Topic 的公開展示 + Admin 管理。

前端需要分成兩個面向：
1. **公開網站** — 內容展示、專案展示、主題瀏覽（SSR）
2. **Admin 管理** — 內容管理、審核、RSS feeds、標籤

---

## 2. Domain Model（前端畫面設計依據）

### PARA Framework（組織架構）

```
Areas (責任領域)
  └── Goals (目標，屬於某個 area)
        └── Milestones (里程碑，binary completion)
        └── Projects (專案，可連結 goal)
              └── Contents (內容，屬於專案)
              └── Tasks (任務，屬於專案)
```

| Entity | 說明 | HTTP API | MCP |
|--------|------|----------|-----|
| **Areas** | PARA 責任領域（engineering, japanese, career...） | 僅作為篩選條件 | — |
| **Projects** | 專案，有 slug、description、tech_stack、highlights | CRUD ✅ | — |
| **Goals** | 個人目標，有 area、quarter、deadline、milestones | 列表+狀態 ✅ | 建立/進度 via MCP |
| **Milestones** | 目標的進度檢查點（done/not-done，非 OKR 的 Key Results） | — | via MCP |
| **Contents** | 文章、TIL、build-log、essay、bookmark、digest、note | CRUD ✅ | — |
| **Topics** | 內容分類主題 | CRUD ✅ | — |
| **Tags** | 標籤系統（含 aliases） | CRUD ✅ | — |

### GTD Lifecycle（任務管理 — 全在 MCP）

```
inbox → todo → in-progress → done
  ↘ someday (稍後再議)
```

| 狀態 | GTD 概念 | 說明 |
|------|----------|------|
| `inbox` | Capture | 快速捕獲，尚未釐清 |
| `todo` | Next Actions | 已釐清，可執行 |
| `in-progress` | Doing | 正在進行 |
| `done` | Complete | 完成 |
| `someday` | Someday/Maybe | 延遲，定期回顧 |

**Daily Planning:** `daily_plan_items` — 每天從 todo 選擇任務排入計劃，追蹤 planned → done/deferred/dropped。

> 前端不直接操作任務。如果 Admin UI 需要顯示任務狀態，可考慮加唯讀 API endpoint。

### Learning Engine（學習分析 — 全在 MCP）

```
Session (domain + mode)
  └── Attempt (一題一記錄)
        └── Observations (weakness/improvement/mastery 信號)
              └── Concepts (pattern/skill/principle 概念)

Item Relations (題目之間的關係圖)
Review Cards (FSRS spaced repetition)
```

| 概念 | 說明 |
|------|------|
| **Learning Session** | 一次學習活動（domain: leetcode/japanese/system-design, mode: practice/retrieval/reading） |
| **Attempt** | 對一個 learning item 的嘗試（outcome: solved_independent/solved_with_hint/gave_up...） |
| **Observation** | 嘗試中觀察到的認知信號（哪個 concept 是 weakness/mastery） |
| **Concept** | 知識本體（如 hash-map, binary-search, amortized-analysis） |
| **Review Card** | FSRS 排程卡片（什麼時候該複習） |

> 前端如果要做 Learning Dashboard，資料來源是 MCP `learning_dashboard` tool，
> 不是 HTTP API。可考慮加唯讀 proxy endpoint。

### IPC（跨 participant 協調 — 全在 MCP）

```
Directive (指令：HQ → content-studio)
  └── Report (回報：content-studio → HQ)
Journal (個人日記：plan/context/reflection/metrics)
Insight (假說追蹤：unverified → verified/invalidated)
```

---

## 3. Content Types（內容類型）

前端展示的核心 — 每種 type 可能需要不同的呈現方式：

| Type | 說明 | 典型長度 | 展示重點 |
|------|------|----------|----------|
| `article` | 深度技術文章 | 2000-5000 字 | 完整文章頁、目錄、相關文章 |
| `essay` | 個人想法/非技術反思 | 1000-3000 字 | 文章頁、較文學的排版 |
| `build-log` | 專案開發紀錄 | 500-2000 字 | timeline 式呈現、連結到專案 |
| `til` | Today I Learned | 100-500 字 | 短卡片、快速掃描 |
| `note` | 技術筆記片段 | 200-1000 字 | 參考用、搜尋導向 |
| `bookmark` | 推薦資源 + 評語 | 100-300 字 | 卡片、外部連結突出 |
| `digest` | 週報/月報 | 1000-3000 字 | 結構化、多段落 |

### Content Status Lifecycle

```
draft → review → published
```

- `draft` — 草稿，只有 Admin 看得到
- `review` — 待審，AI pipeline 審核後進入（目前 pipeline 離線）
- `published` — 已發布，公開 API 可見
- `is_public` — 額外的可見性控制（published 但 is_public=false 不會出現在公開 API）

---

## 4. HTTP API Endpoints

### 4.1 Health

| Method | Path | Auth | 說明 |
|--------|------|------|------|
| GET | `/healthz` | No | Liveness — `ok` |
| GET | `/readyz` | No | Readiness — ping DB |

### 4.2 Public API（前端 SSR 使用）

**Contents**

| Method | Path | Query Params | 說明 |
|--------|------|-------------|------|
| GET | `/api/contents` | `page`, `per_page`, `type`, `since` | 已發布內容列表 |
| GET | `/api/contents/{slug}` | — | 單一內容 |
| GET | `/api/contents/by-type/{type}` | `page`, `per_page` | 依類型篩選 |
| GET | `/api/contents/related/{slug}` | `limit` (max 20) | 相關內容（embedding 相似度） |
| GET | `/api/search` | `q` (必要), `type`, `page`, `per_page` | 全文搜尋 |
| GET | `/api/knowledge-graph` | — | 知識圖譜 JSON |
| GET | `/api/feed/rss` | — | RSS 2.0 XML |
| GET | `/api/feed/sitemap` | — | Sitemap XML |

**Topics**

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/topics` | 所有主題（帶 cache） |
| GET | `/api/topics/{slug}` | 單一主題 + 該主題的 contents |

**Projects**

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/projects` | 公開專案（`is_public = true`） |
| GET | `/api/projects/{slug}` | 專案詳情（description, tech_stack, highlights, github_url, live_url...） |

### 4.3 Auth

> 僅在設定 Google OAuth 時啟用

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/auth/google` | Google OAuth 登入 |
| GET | `/api/auth/google/callback` | OAuth callback |
| POST | `/api/auth/refresh` | JWT token 刷新 |

### 4.4 Admin API（JWT 認證）

**Content CRUD**

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/contents` | 所有內容（含 draft/review） |
| GET | `/api/admin/contents/{id}` | by UUID |
| POST | `/api/admin/contents` | 建立（body: slug, title, type, body...） |
| PUT | `/api/admin/contents/{id}` | 更新 |
| DELETE | `/api/admin/contents/{id}` | 刪除 |
| POST | `/api/admin/contents/{id}/publish` | 發布 |
| PATCH | `/api/admin/contents/{id}/is-public` | 切換公開性 |

**Review Queue**

| Method | Path | 說明 |
|--------|------|------|
| GET | `/api/admin/review` | 待審列表 |
| POST | `/api/admin/review/{id}/approve` | 核准 |
| POST | `/api/admin/review/{id}/reject` | 退回 |
| PUT | `/api/admin/review/{id}/edit` | 編輯後核准 |

**Projects / Goals / Topics / Tags / Feeds / Collected / Notes / Activity / Stats / Upload**

完整路由表見附錄 A。

---

## 5. 前端頁面設計建議

### 公開網站

| 頁面 | 資料來源 | 說明 |
|------|----------|------|
| 首頁 | `GET /api/contents` (featured) | 精選內容 + 最新文章 |
| 文章列表 | `GET /api/contents` | 分頁、可依 type 篩選 |
| 文章詳情 | `GET /api/contents/{slug}` + `related` | 完整文章 + 相關推薦 |
| 專案列表 | `GET /api/projects` | 展示個人作品集 |
| 專案詳情 | `GET /api/projects/{slug}` | problem/solution/architecture/results |
| 主題頁 | `GET /api/topics/{slug}` | 該主題下的所有內容 |
| 搜尋 | `GET /api/search?q=...` | 全文搜尋結果 |
| 知識圖譜 | `GET /api/knowledge-graph` | 視覺化內容關聯 |

### Admin 管理

| 頁面 | 資料來源 | 說明 |
|------|----------|------|
| 內容管理 | `/api/admin/contents` | CRUD + 發布 + 審核 |
| 審核佇列 | `/api/admin/review` | approve/reject/edit |
| 專案管理 | `/api/admin/projects` | CRUD |
| 目標總覽 | `/api/admin/goals` | 列表 + 狀態更新 |
| 標籤管理 | `/api/admin/tags` + `/api/admin/aliases` | CRUD + merge + backfill |
| RSS 管理 | `/api/admin/feeds` + `/api/admin/collected` | feed CRUD + 策展 |
| 統計 | `/api/admin/stats` | 總覽 + drift + learning |
| 活動紀錄 | `/api/admin/activity/*` | sessions + changelog |
| 筆記搜尋 | `/api/admin/notes` | Obsidian 知識搜尋 |

### 不再需要的 v1 頁面

| v1 頁面 | 狀態 | 原因 |
|---------|------|------|
| 任務管理 | 移除 | 任務由 AI agent 透過 MCP 管理 |
| Insight 管理 | 移除 | 由 MCP `track_insight` 管理 |
| Session Notes | 移除 | 被 Journal（MCP）取代 |
| Notion Sources | 移除 | Notion 整合完全移除 |
| Pipeline 觸發 | 移除 | AI pipeline 暫時離線 |
| Flow Runs | 移除 | AI pipeline 暫時離線 |
| Flow Polish | 移除 | AI pipeline 暫時離線 |
| Tracking | 移除 | monitor package 移除 |
| 學習分析儀表板 | 移除 | 由 MCP `learning_dashboard` 取代 |

---

## 6. Response 格式

```json
// 單一
{ "data": { ... } }

// 列表（分頁）
{
  "data": [ ... ],
  "meta": { "total": 42, "page": 1, "per_page": 20, "total_pages": 3 }
}

// 錯誤
{ "error": { "code": "NOT_FOUND", "message": "not found" } }
```

分頁：`?page=1&per_page=20`（per_page 上限 100）

---

## 附錄 A：完整 Admin 路由表

### Projects
| Method | Path |
|--------|------|
| GET | `/api/admin/projects` |
| POST | `/api/admin/projects` |
| PUT | `/api/admin/projects/{id}` |
| DELETE | `/api/admin/projects/{id}` |

### Goals
| Method | Path |
|--------|------|
| GET | `/api/admin/goals` |
| PUT | `/api/admin/goals/{id}/status` |

### Topics
| Method | Path |
|--------|------|
| POST | `/api/admin/topics` |
| PUT | `/api/admin/topics/{id}` |
| DELETE | `/api/admin/topics/{id}` |

### Tags
| Method | Path |
|--------|------|
| GET | `/api/admin/tags` |
| POST | `/api/admin/tags` |
| PUT | `/api/admin/tags/{id}` |
| DELETE | `/api/admin/tags/{id}` |
| POST | `/api/admin/tags/backfill` |
| POST | `/api/admin/tags/merge` |

### Tag Aliases
| Method | Path |
|--------|------|
| GET | `/api/admin/aliases` |
| POST | `/api/admin/aliases/{id}/map` |
| POST | `/api/admin/aliases/{id}/confirm` |
| POST | `/api/admin/aliases/{id}/reject` |
| DELETE | `/api/admin/aliases/{id}` |

### Feeds
| Method | Path |
|--------|------|
| GET | `/api/admin/feeds` |
| POST | `/api/admin/feeds` |
| PUT | `/api/admin/feeds/{id}` |
| DELETE | `/api/admin/feeds/{id}` |
| POST | `/api/admin/feeds/{id}/fetch` |

### Collected Items
| Method | Path |
|--------|------|
| GET | `/api/admin/collected` |
| POST | `/api/admin/collected/{id}/curate` |
| POST | `/api/admin/collected/{id}/ignore` |
| POST | `/api/admin/collected/{id}/feedback` |

### Notes
| Method | Path |
|--------|------|
| GET | `/api/admin/notes` |
| GET | `/api/admin/decisions` |

### Activity
| Method | Path |
|--------|------|
| GET | `/api/admin/activity/sessions` |
| GET | `/api/admin/activity/changelog` |

### Stats
| Method | Path |
|--------|------|
| GET | `/api/admin/stats` |
| GET | `/api/admin/stats/drift` |
| GET | `/api/admin/stats/learning` |

### Upload
| Method | Path |
|--------|------|
| POST | `/api/admin/upload` |

---

## 附錄 B：環境變數

| 變數 | 必要 | 預設 | 說明 |
|------|------|------|------|
| `DATABASE_URL` | Yes | — | PostgreSQL 連線字串 |
| `JWT_SECRET` | Yes | — | JWT 簽名金鑰 |
| `PORT` | No | 8080 | HTTP port |
| `CORS_ORIGIN` | No | `http://localhost:4200` | 前端 origin |
| `SITE_URL` | No | `https://koopa0.dev` | RSS/sitemap base URL |
| `GOOGLE_CLIENT_ID` | No | — | 設定後啟用 Google OAuth |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth |
| `GOOGLE_REDIRECT_URI` | No | — | OAuth callback URL |
| `ADMIN_EMAIL` | No | — | 管理員 email |
| `R2_ENDPOINT` | No | — | 設定後啟用 upload |
| `R2_ACCESS_KEY_ID` | No | — | R2 credentials |
| `R2_SECRET_ACCESS_KEY` | No | — | R2 credentials |
| `R2_BUCKET` | No | — | R2 bucket name |
| `R2_PUBLIC_URL` | No | — | R2 public URL |
