# Backend ↔ Frontend 功能全景對齊文件

> 產出日期：2026-03-27
> 產出方：Backend (Go API)
> 用法：Frontend 逐條對照，確認語意理解、UI 行為、API 用法是否一致

---

## 使用說明

每個功能條目包含：
- **場景**：使用者什麼時候會用到這個功能
- **Backend 設計**：API endpoint、request/response 格式、設計意圖
- **Frontend 預期行為**：Backend 預期 Frontend 如何使用這個 API
- **對齊狀態**：`[待確認]` — Frontend 填入 `[OK]`、`[不一致: 說明]`、`[未實作]`、`[Over-design]`

---

## 通用約定

### Response Envelope

所有 API 回傳統一格式：
```json
{
  "data": <payload>,
  "meta": { "total": 100, "page": 1, "per_page": 20, "total_pages": 5 }
}
```

Error:
```json
{ "error": { "code": "BAD_REQUEST", "message": "..." } }
```

### 分頁

- Query params: `?page=1&per_page=20`
- Default: page=1, per_page=20, max per_page=100
- Response 的 `meta` 裡有 total / total_pages

### Auth

- Public endpoints (`/api/...`): 無需 token
- Admin endpoints (`/api/admin/...`): 需要 `Authorization: Bearer <access_token>`
- Webhook endpoints (`/api/webhook/...`): HMAC signature 驗證，不是 JWT

---

# A. 公開頁面功能（訪客可見）

## A1. 首頁

| 項目 | 說明 |
|------|------|
| 場景 | 訪客進入網站首頁，看到最新內容、精選專案 |
| Frontend route | `/` |
| Backend API | 首頁不需要專屬 API — 組合使用下列 endpoint |
| 預期呼叫 | `GET /api/contents?per_page=5` (最新文章) + `GET /api/projects` (精選專案) |
| Frontend 預期 | 展示最新 published content + featured projects。不需要全部類型，挑重點 |
| 對齊狀態 | `[待確認]` Frontend 首頁打了哪些 API？組合方式？ |

## A2. 文章列表 + 搜尋

| 項目 | 說明 |
|------|------|
| 場景 | 訪客瀏覽技術文章，可搜尋、按 tag 過濾 |
| Frontend route | `/articles` |
| Backend API — 列表 | `GET /api/contents?type=article&page=1&per_page=20` |
| Backend API — 搜尋 | `GET /api/search?q=keyword&page=1&per_page=20` |
| 列表 query params | `type` (content type filter), `tag` (single tag filter), `page`, `per_page` |
| 搜尋 query params | `q` (required, 支援 OR 語法), `page`, `per_page` |
| 搜尋範圍 | **所有 published content**，不只 articles — 會搜到 TIL、notes、essays 等 |
| Response 格式 | 分頁 Content array，每個 content 有 slug, title, excerpt, type, tags, topics, published_at |
| Frontend 預期 | 用 `type=article` 過濾列表；搜尋用 `/api/search`，注意搜尋結果會包含非 article 類型 |
| 對齊狀態 | `[待確認]` 前端搜尋是打 `/api/search` 還是 `/api/contents`？搜到非 article 結果如何處理？ |

## A3. 文章詳情

| 項目 | 說明 |
|------|------|
| 場景 | 訪客點進一篇文章，看完整內容 + 相關推薦 |
| Frontend route | `/articles/:id` (注意：這裡 `:id` 實際上是 slug) |
| Backend API — 詳情 | `GET /api/contents/{slug}` |
| Backend API — 相關 | `GET /api/contents/related/{slug}?limit=5` |
| 相關內容機制 | 基於 pgvector embedding 語義相似度，回傳 similarity score (0-1) |
| Response — related | `[{slug, title, excerpt, type, similarity, topics}]` |
| Frontend 預期 | 載入文章後，另打 related API 顯示推薦區塊。Related 結果可能包含不同 type |
| 對齊狀態 | `[待確認]` route param 是 slug 對吧？有呼叫 related API 嗎？ |

## A4. 專案列表

| 項目 | 說明 |
|------|------|
| 場景 | 訪客瀏覽個人專案作品集 |
| Frontend route | `/projects` |
| Backend API | `GET /api/projects` |
| Response | 只回傳 `public=true` 的專案（Backend 已過濾），包含 slug, title, description, status, tech_stack, github_url, live_url, featured |
| Status 值 | `planned`, `in-progress`, `on-hold`, `completed`, `maintained`, `archived` |
| Frontend 預期 | 展示公開專案，可能按 status 分組或 filter。`featured=true` 的可以突出顯示 |
| 對齊狀態 | `[待確認]` 有做 status filter 嗎？featured 如何處理？ |

## A5. 專案詳情

| 項目 | 說明 |
|------|------|
| 場景 | 訪客點進某個專案看詳細介紹 |
| Frontend route | `/projects/:slug` |
| Backend API | `GET /api/projects/{slug}` |
| Response 欄位 | 除了基本資訊，還有：`long_description`, `role`, `highlights[]`, `problem`, `solution`, `architecture`, `results` — 這些是 case study 欄位 |
| Frontend 預期 | 如果專案有 long_description/problem/solution/results 等欄位，應該渲染成 case study 格式 |
| 對齊狀態 | `[待確認]` 這些 case study 欄位有渲染嗎？還是只顯示 description？ |

## A6. TIL 列表 + 詳情

| 項目 | 說明 |
|------|------|
| 場景 | 訪客瀏覽 Today I Learned 短篇學習紀錄 |
| Frontend route | `/til`, `/til/:slug` |
| Backend API | `GET /api/contents/by-type/til?page=1&per_page=20` (列表), `GET /api/contents/{slug}` (詳情) |
| 語意 | TIL 是短篇（通常 < 500 字），重點是「今天學到什麼」的快速紀錄 |
| Frontend 預期 | 列表用 by-type API；詳情用通用 content API（同一個 endpoint 處理所有 content type） |
| 對齊狀態 | `[待確認]` |

## A7. Notes 列表 + 詳情

| 項目 | 說明 |
|------|------|
| 場景 | 訪客瀏覽技術筆記（code snippets、config 片段等） |
| Frontend route | `/notes`, `/notes/:slug` |
| Backend API | `GET /api/contents/by-type/note` (列表), `GET /api/contents/{slug}` (詳情) |
| 語意 | **Public notes = 已發布的 note type content**。跟 Obsidian 原始筆記不同（那個是 admin-only） |
| Frontend 預期 | 同 TIL 模式 |
| 對齊狀態 | `[待確認]` |

## A8. Build Logs

| 項目 | 說明 |
|------|------|
| 場景 | 訪客瀏覽專案開發紀錄 |
| Backend API | `GET /api/contents/by-type/build-log` (列表), `GET /api/contents/{slug}` (詳情) |
| 語意 | Build log 是開發過程的紀錄，記錄「做了什麼、學到什麼、遇到什麼問題」 |
| Backend 設計 | **這是 public API**，不需要 auth |
| **問題** | Frontend route 把 build-logs 放在 `/admin/build-logs`（admin children 內），但 component 放在 `pages/` 目錄。Backend API 是 public 的 |
| 對齊問題 | Build log 應該是 public 頁面（`/build-logs`）還是 admin-only？Backend 的設計意圖是 **public** |
| 對齊狀態 | `[待確認]` 這是 routing 錯誤還是故意的？ |

## A9. Tag 瀏覽

| 項目 | 說明 |
|------|------|
| 場景 | 訪客點擊某個 tag，看到所有帶這個 tag 的 content |
| Frontend route | `/tags/:tag` |
| Backend API | `GET /api/contents?tag=learning&page=1&per_page=20` |
| 語意 | tag filter 是 content list 的 query param，不是獨立 endpoint |
| Frontend 預期 | 結果可能包含各種 content type（article, til, note 等），不只 articles |
| 對齊狀態 | `[待確認]` 混合 type 的結果如何呈現？有區分 type 的視覺差異嗎？ |

## A10. Topic 列表 + 詳情

| 項目 | 說明 |
|------|------|
| 場景 | 訪客按主題瀏覽內容（如「Go」「系統設計」「AI」） |
| Frontend route | 無專屬 route（？） |
| Backend API | `GET /api/topics` (列表), `GET /api/topics/{slug}` (詳情，含該 topic 下的 content) |
| 語意 | Topic 是 **知識領域**，比 tag 更高層級。一個 content 可以屬於多個 topics |
| Frontend 預期 | 應該有 `/topics` 或在首頁/導航展示 topic 入口 |
| 對齊狀態 | `[待確認]` 前端有做 topic 頁面嗎？還是只在文章卡片上顯示 topic label？ |

## A11. 全站搜尋

| 項目 | 說明 |
|------|------|
| 場景 | 訪客想找特定內容，輸入關鍵字搜尋 |
| Backend API | `GET /api/search?q=keyword&page=1&per_page=20` |
| 搜尋引擎 | PostgreSQL full-text search (tsvector)，支援 OR 語法 |
| 搜尋範圍 | **所有 published content**：articles, TILs, notes, essays, build-logs, bookmarks, digests |
| Response | 標準分頁 Content array，每項有 `type` 欄位可區分類型 |
| **問題** | Frontend 目前搜尋嵌在 `/articles` 頁面，但 Backend 搜尋涵蓋所有類型 |
| Frontend 預期 | 理想上應有 `/search` 獨立頁面，或至少搜尋結果要能處理非 article 類型 |
| 對齊狀態 | `[待確認]` 搜尋是只搜 articles 還是全站？結果中非 article 如何處理？ |

## A12. Knowledge Graph

| 項目 | 說明 |
|------|------|
| 場景 | 訪客看到內容之間的知識關聯圖（節點 = content/topic，邊 = 關聯） |
| Backend API | `GET /api/knowledge-graph` (rate limited) |
| Response | `{nodes: [{id, label, type, content_type, count}], links: [{source, target, type, similarity}]}` |
| 節點類型 | `content` (文章) 或 `topic` (主題) |
| 邊類型 | `topic` (content 屬於 topic) 或 `similar` (語義相似，帶 similarity 分數) |
| Frontend 現狀 | `content.service.ts` 有 `getKnowledgeGraph()` method，**但沒有任何 component 使用** |
| Frontend 預期 | 用 D3.js / vis.js / cytoscape.js 等渲染互動式知識圖。可以是獨立頁面或嵌入首頁 |
| 對齊狀態 | `[待確認]` 計畫做嗎？還是 defer？如果 defer，service method 要留著還是砍？ |

## A13. RSS Feed

| 項目 | 說明 |
|------|------|
| 場景 | RSS 閱讀器訂閱 |
| Backend API | `GET /api/feed/rss` |
| Response | XML (Atom/RSS 格式)，包含最新 published content |
| Frontend 預期 | 不需要渲染，但 `<head>` 裡應該有 `<link rel="alternate" type="application/rss+xml" href="/api/feed/rss">` |
| 對齊狀態 | `[待確認]` `<head>` 有放 RSS link 嗎？ |

## A14. Sitemap

| 項目 | 說明 |
|------|------|
| 場景 | SEO — 搜尋引擎爬蟲讀取 |
| Backend API | `GET /api/feed/sitemap` |
| Response | XML sitemap 格式 |
| Frontend 預期 | `robots.txt` 裡要指向 sitemap URL |
| 對齊狀態 | `[待確認]` robots.txt 有設嗎？ |

---

# B. 認證流程

## B1. Google OAuth 登入

| 項目 | 說明 |
|------|------|
| 場景 | Admin 用 Google 帳號登入 |
| Frontend route | `/login` → redirect → `/admin/oauth-callback` |
| 完整流程 | 1. Frontend 打 `GET /api/auth/google` 取得 Google OAuth URL |
|  | 2. Frontend redirect 到 Google 登入頁 |
|  | 3. Google callback 回到 Backend `GET /api/auth/google/callback?code=...&state=...` |
|  | 4. Backend 驗證後 redirect 到 `/admin/oauth-callback#access_token=...&refresh_token=...` |
|  | 5. Frontend 從 URL fragment (#) 取出 tokens 存入 state |
| Token 細節 | access_token: JWT (HS256, 24hr); refresh_token: base64 random (7 days, single-use) |
| 安全設計 | Token 放在 URL fragment (#) 而非 query (?) — 避免 server log 和 Referer header 洩漏 |
| 對齊狀態 | `[待確認]` OAuth callback 是從 fragment 取 token 嗎？Token 存在哪？(localStorage / memory / cookie?) |

## B2. Token Refresh

| 項目 | 說明 |
|------|------|
| 場景 | Access token 過期，自動 refresh |
| Backend API | `POST /api/auth/refresh` |
| Request | `{"refresh_token": "base64..."}` |
| Response | `{"data": {"access_token": "jwt...", "refresh_token": "new_base64..."}}` |
| **重要** | Refresh token 是 **single-use** — 每次 refresh 都拿到新的 refresh_token，舊的立刻失效 |
| Frontend 預期 | 必須在 refresh 成功後更新存儲的 refresh_token。如果用舊的 refresh_token 再打一次會失敗 |
| 對齊狀態 | `[待確認]` 前端有實作 token rotation 嗎？有 interceptor 自動 refresh 嗎？ |

---

# C. Admin — 內容生命週期

## C1. 建立內容 (Editor)

| 項目 | 說明 |
|------|------|
| 場景 | Admin 撰寫新文章/TIL/筆記 |
| Frontend route | `/admin/editor` (新建), `/admin/editor/:id` (編輯) |
| Backend API | `POST /api/admin/contents` |
| Required 欄位 | `slug` (URL-friendly 唯一值), `title`, `type` (article/essay/til/note/bookmark/build-log/digest) |
| Optional 欄位 | `body`, `excerpt`, `tags[]`, `topic_ids[]`, `status` (default: draft), `visibility` (default: public), `review_level` (default: standard), `project_id`, `cover_image`, `reading_time`, `series_id`, `series_order`, `source`, `source_type`, `ai_metadata` |
| 409 Conflict | slug 已存在 |
| Frontend 預期 | Editor 至少要有：title, slug (auto-generate from title?), body (markdown), type selector, tags input, topic multi-select |
| 對齊狀態 | `[待確認]` editor 有哪些欄位？slug 怎麼產生？type 選擇器？topic/tag UI？ |

## C2. 編輯內容

| 項目 | 說明 |
|------|------|
| 場景 | Admin 修改已存在的內容 |
| Frontend route | `/admin/editor/:id` |
| Backend API | `PUT /api/admin/contents/{id}` |
| Request | 所有欄位都 optional（只傳要改的），空值不會覆蓋 |
| 對齊狀態 | `[待確認]` 是送全部欄位還是只送 dirty fields？ |

## C3. 發布內容

| 項目 | 說明 |
|------|------|
| 場景 | Admin 把 draft 變成 published |
| Backend API | `POST /api/admin/contents/{id}/publish` |
| Request body | 空 |
| Backend 行為 | 設定 status=published, published_at=now |
| Frontend 預期 | 在 content list 或 editor 裡有「發布」按鈕 |
| 對齊狀態 | `[待確認]` 有發布按鈕嗎？在哪裡？ |

## C4. 切換可見性

| 項目 | 說明 |
|------|------|
| 場景 | Admin 把已發布的內容改為 private（不對外但不是 draft） |
| Backend API | `PATCH /api/admin/contents/{id}/visibility` |
| Request | `{"visibility": "public|private"}` |
| 語意 | `public` = 訪客可見; `private` = 只有 admin 可見。跟 status 獨立（可以是 published + private） |
| Frontend 預期 | Content list 裡有 toggle 或 dropdown 切換 |
| 對齊狀態 | `[待確認]` 有做 visibility toggle 嗎？ |

## C5. 刪除內容

| 項目 | 說明 |
|------|------|
| 場景 | Admin 刪除不要的內容 |
| Backend API | `DELETE /api/admin/contents/{id}` |
| Backend 行為 | Soft delete（標記 archived） |
| Frontend 預期 | 確認對話框後刪除 |
| 對齊狀態 | `[待確認]` |

## C6. Admin 內容列表

| 項目 | 說明 |
|------|------|
| 場景 | Admin 管理所有內容（包含 draft、private） |
| Frontend route | `/admin/contents` |
| Backend API | `GET /api/admin/contents?page=1&per_page=20&type=article&visibility=public` |
| 比 public list 多的 | `visibility` filter，且回傳**所有 status**（draft, review, published, archived） |
| Frontend 預期 | 可按 status、type、visibility 過濾；每項有 edit/publish/visibility/delete 操作 |
| 對齊狀態 | `[待確認]` 有這些 filter 和操作嗎？ |

---

# D. Admin — 內容審核

## D1. 審核佇列

| 項目 | 說明 |
|------|------|
| 場景 | AI pipeline 產生的內容或從 Obsidian 同步的內容進入審核 |
| Frontend route | `/admin/review` |
| Backend API | `GET /api/admin/review` |
| 語意 | Review queue 是 content 發布前的把關。content status = "review" 時會在這裡出現 |
| Review levels | `auto` (AI 自動通過), `light` (快速看), `standard` (正常審核), `strict` (仔細審核) |
| Frontend 預期 | 列出待審核項目，每項有 approve/reject/edit 操作 |
| 對齊狀態 | `[待確認]` 有做 review level 顯示嗎？三個操作都有嗎？ |

## D2. 審核操作

| 操作 | API | Request | 對 content 的影響 |
|------|-----|---------|-------------------|
| Approve | `POST /api/admin/review/{id}/approve` | 空 | content status → published |
| Reject | `POST /api/admin/review/{id}/reject` | `{"notes": "optional reason"}` | content status → draft |
| Edit | `PUT /api/admin/review/{id}/edit` | 空 | 等同 approve |

| 對齊狀態 | `[待確認]` reject 有讓 admin 填理由嗎？ |

---

# E. Admin — AI 內容潤色

## E1. Content Polish Flow

| 項目 | 說明 |
|------|------|
| 場景 | Admin 對一篇文章觸發 AI 潤色（改善文筆、修正語法） |
| Frontend route | `/admin/editor/:id` 裡的功能 |
| 三步驟流程 | 1. Trigger → 2. Poll result → 3. Approve/reject |
| Step 1 | `POST /api/admin/flow/polish/{content_id}` — 提交 AI 潤色任務 |
| Response 1 | `{"data": {"flow_run_id": "uuid"}}` — 非同步，回傳 job ID |
| Step 2 | `GET /api/admin/flow/polish/{content_id}/result` — 查詢結果 |
| Response 2 | `{"data": {"status": "pending|completed|failed", "polished_body": "...", "changes_summary": "..."}}` |
| Step 3 | `POST /api/admin/flow/polish/{content_id}/approve` — 套用潤色結果 |
| Frontend 預期 | Editor 裡有「AI 潤色」按鈕 → loading → 顯示 diff → approve/reject |
| 對齊狀態 | `[待確認]` 有做 diff 比較嗎？polling 機制是什麼？ |

---

# F. Admin — 內容收集 Pipeline

## F1. RSS Feed 管理

| 項目 | 說明 |
|------|------|
| 場景 | Admin 管理訂閱的 RSS 來源 |
| Frontend route | `/admin/feeds` |
| Backend CRUD | `GET/POST/PUT/DELETE /api/admin/feeds` |
| Create request | `{url, name, schedule, topics[], filter_config}` |
| schedule 值 | `4hourly`, `daily`, `weekly` |
| filter_config | `{deny_paths[], deny_title_patterns[], allow_tags[], deny_tags[]}` — 過濾不想要的文章 |
| 額外操作 | `POST /api/admin/feeds/{id}/fetch` — 手動抓取，回傳 `{new_items: N}` |
| Frontend 預期 | CRUD 表單 + 手動 fetch 按鈕 + 顯示 schedule/enabled 狀態 |
| 對齊狀態 | `[待確認]` filter_config 有 UI 嗎？手動 fetch 有嗎？ |

## F2. Collected Items 管理

| 項目 | 說明 |
|------|------|
| 場景 | RSS 抓回來的文章進入 collected，Admin 決定保留/忽略/轉為正式內容 |
| Frontend route | `/admin/collected` |
| Backend API | `GET /api/admin/collected?status=unread&sort=relevance&page=1&per_page=20` |
| Status 流轉 | `unread` → (`read`) → `curated` (轉為 content) 或 `ignored` (丟棄) |
| 三個操作 | |
| — Curate | `POST /api/admin/collected/{id}/curate` + `{content_id}` — 關聯到 content record |
| — Ignore | `POST /api/admin/collected/{id}/ignore` — 標記忽略 |
| — Feedback | `POST /api/admin/collected/{id}/feedback` + `{feedback: "up|down"}` — 評分 |
| **問題** | Curate 是這個 pipeline 最關鍵的操作：把外部收集的文章 → 變成自己的 content |
| **目前狀態** | Frontend service 有 `ignore()` 和 `submitFeedback()`，**缺少 `curate()`** |
| Frontend 預期 | 每個 collected item 旁邊有三個按鈕：Curate (→ 建立或關聯 content) / Ignore / Feedback |
| 對齊狀態 | `[待確認]` curate 功能缺失？怎麼補？ |

## F3. Pipeline 手動觸發

| 項目 | 說明 |
|------|------|
| 場景 | Admin 手動觸發各種 pipeline 操作（不等排程） |
| Frontend route | `/admin/pipeline` |
| 操作列表 | 以下全是 `POST` 到 **`/api/admin/pipeline/{action}`** |

| Action | 用途 | Request body | Response |
|--------|------|-------------|----------|
| `sync` | 從 GitHub 同步 Obsidian content | 空 | 202 `{status: "submitted"}` |
| `notion-sync` | 從 Notion 同步 task/goal/project | 空 | 202 |
| `reconcile` | 比對各資料源，修正不一致 | 空 | 202 |
| `collect` | 抓取所有 enabled RSS feeds | `{schedule: "daily"}` (optional) | 202 |
| `generate` | AI 生成內容（摘要等） | 空 | 202 |
| `digest` | 建立 weekly/monthly digest | `{start_date, end_date}` (required) | 202 |
| `bookmark` | 處理 bookmark 佇列 | 空 | 202 |

| **BUG** | Frontend 打 `/api/pipeline/{action}`，缺少 `/admin` prefix → 全部 404 |
| 對齊狀態 | `[BUG]` Frontend 需修正路徑為 `/api/admin/pipeline/{action}` |

---

# G. Admin — 知識組織

## G1. Topic 管理

| 項目 | 說明 |
|------|------|
| 場景 | Admin 管理知識主題分類（Go, AI, 系統設計...） |
| Frontend route | 無獨立 admin 頁面（？）— topic 的 CRUD 在哪做？ |
| Backend CRUD | `POST/PUT/DELETE /api/admin/topics` |
| Create request | `{slug, name, description, icon, sort_order}` |
| 語意 | Topic 是最高層級的分類，content 透過 content_topics 多對多關聯 |
| Frontend 預期 | 應有 topic 管理 UI（至少能新增、改名、排序） |
| 對齊狀態 | `[待確認]` topic 管理在哪做？editor 裡的 topic selector 背後有 CRUD 嗎？ |

## G2. Tag 管理 + Alias 系統

| 項目 | 說明 |
|------|------|
| 場景 | Admin 管理 canonical tags 和 alias 對照（如 "golang" → "go", "JS" → "javascript"） |
| Frontend route | `/admin/tags` |
| Backend 分兩層 | |
| — Tags | `GET/POST/PUT/DELETE /api/admin/tags` — canonical tags（slug + name） |
| — Aliases | `GET /api/admin/aliases` — 未映射的 raw tags；每個 alias 可以 map/confirm/reject |
| Alias 操作 | |
| — Map | `POST /api/admin/aliases/{id}/map` + `{tag_id}` — 把 alias 映射到 canonical tag |
| — Confirm | `POST /api/admin/aliases/{id}/confirm` — 確認已有的映射 |
| — Reject | `POST /api/admin/aliases/{id}/reject` — 拒絕（標記為不要的 tag） |
| — Delete | `DELETE /api/admin/aliases/{id}` |
| 批量操作 | |
| — Backfill | `POST /api/admin/tags/backfill` — 掃描所有筆記，resolve tags，回傳 `{notes_processed, tags_mapped, tags_unmapped}` |
| — Merge | `POST /api/admin/tags/merge` + `{source_id, target_id}` — 合併 tag，回傳 `{aliases_moved, notes_moved, events_moved}` |
| Frontend 預期 | 兩個 tab/section：Canonical Tags (CRUD) + Unmapped Aliases (map/confirm/reject)。Backfill 和 merge 是進階操作 |
| 對齊狀態 | `[待確認]` 有做 alias 管理嗎？backfill/merge 有 UI 嗎？ |

---

# H. Admin — Notion 整合

## H1. Notion Source 管理

| 項目 | 說明 |
|------|------|
| 場景 | Admin 連接 Notion database，設定同步角色 |
| Frontend route | `/admin/notion-sources` |
| 流程 | 1. Discover → 2. Connect → 3. Set Role → 4. Auto-sync |
| Discover | `GET /api/admin/notion-sources/discover` — 列出 Notion workspace 中可連接的 database |
| Create | `POST /api/admin/notion-sources` — 連接特定 database |
| Set Role | `PUT /api/admin/notion-sources/{id}/role` + `{role: "task|goal|project|note"}` |
| Toggle | `POST /api/admin/notion-sources/{id}/toggle` — enable/disable |
| 語意 | 每個 Notion database 有一個 **role**，決定它同步到哪個 feature（task/goal/project/note） |
| Frontend 預期 | 列出已連接的 sources，每個顯示 role + enabled 狀態 + last synced 時間。有 discover 按鈕找新 database |
| 對齊狀態 | `[待確認]` discover 有做嗎？role 選擇 UI？ |

## H2. Task 管理（Notion 同步）

| 項目 | 說明 |
|------|------|
| 場景 | Admin 管理 todo（雙向同步 Notion） |
| Frontend route | `/admin/tasks` |
| Backend API | `GET /api/admin/tasks` (全部), `GET /api/admin/tasks/pending` (未完成) |
| Create | `POST /api/admin/tasks` + `{title, project_slug?, due?, priority?, energy?, my_day?, notes?}` |
| Update | `PUT /api/admin/tasks/{id}` + `{status?, due?, priority?, energy?, my_day?, project_slug?, notes?}` |
| Complete | `POST /api/admin/tasks/{id}/complete` + `{notes?}` — 回傳 `{is_recurring, next_recurrence}` |
| My Day | `POST /api/admin/tasks/batch-my-day` + `{task_ids[], clear?}` — 批次設定今日任務 |
| Daily Summary | `GET /api/admin/today/summary` — 今日完成數、pending 數、提示 |
| 語意 | Task 建立後會同步回 Notion；Complete 後如果是 recurring task 會自動建下一個 |
| Frontend 預期 | Task list (filter by status/project) + "My Day" 視圖 + 完成按鈕 + batch my-day selector |
| 對齊狀態 | `[待確認]` my-day 功能有做嗎？batch 操作？recurring 回饋顯示？ |

## H3. Goal 管理（Notion 同步）

| 項目 | 說明 |
|------|------|
| 場景 | Admin 追蹤目標進度 |
| Frontend route | `/admin/goals` |
| Backend API | `GET /api/admin/goals`, `PUT /api/admin/goals/{id}/status` |
| Update request | `{status: "not-started|in-progress|done|abandoned"}` |
| 語意 | Goals 從 Notion 同步來，前端只能改 status，不能 CRUD |
| Frontend 預期 | 唯讀列表 + status 下拉選單 |
| 對齊狀態 | `[待確認]` |

---

# I. Admin — 專案管理

## I1. Admin 專案 CRUD

| 項目 | 說明 |
|------|------|
| 場景 | Admin 管理專案資訊（跟 public 頁面不同，這裡可以 CRUD） |
| Frontend route | `/admin/projects`, `/admin/project-editor`, `/admin/project-editor/:id` |
| Backend CRUD | `GET/POST/PUT/DELETE /api/admin/projects` |
| Create 欄位 | `{slug, title, description, long_description, role, tech_stack[], highlights[], problem, solution, architecture, results, github_url, live_url, featured, public, sort_order, status}` |
| Status 值 | `planned`, `in-progress`, `on-hold`, `completed`, `maintained`, `archived` |
| `public` flag | 只有 `public=true` 的專案才會出現在 public `/api/projects` |
| `featured` flag | 標記為精選，可在首頁突出顯示 |
| Frontend 預期 | Project editor 要有這些欄位：基本資訊 + case study 欄位 (problem/solution/results) + flags (public/featured) |
| 對齊狀態 | `[待確認]` project editor 有全部欄位嗎？特別是 case study section？ |

---

# J. Admin — 監控與洞察

## J1. Dashboard

| 項目 | 說明 |
|------|------|
| 場景 | Admin 進入 admin 首頁，看到系統全局狀態 |
| Frontend route | `/admin` |
| Backend API | `GET /api/admin/stats` |
| Response 包含 | contents (by status/type), collected (by status), feeds (total/enabled), flow_runs (by status), projects (by status), reviews (pending), notes (total/by_type), activity (last 24h/7d), sources (total/enabled), tags (canonical/aliases/unconfirmed) |
| Frontend 預期 | 概覽卡片：content 數量、pending reviews、recent activity、feed 健康度 |
| 定位 | **系統全局視角** — 「我的平台整體狀態如何？」 |
| 對齊狀態 | `[待確認]` dashboard 打了哪些 API？顯示了哪些 section？ |

## J2. Today 頁面

| 項目 | 說明 |
|------|------|
| 場景 | Admin 每天早上看今日計畫 |
| Frontend route | `/admin/today` |
| Backend API | `GET /api/admin/today/summary` + `GET /api/admin/tasks/pending` + `GET /api/admin/insights` + `GET /api/admin/session-notes` |
| 語意 | **個人每日視角** — 「我今天要做什麼？」 |
| 定位差異 | Dashboard = 系統狀態; Today = 個人工作日 |
| Frontend 預期 | 今日任務 (my-day tasks) + daily summary + 最新 insights + 今日 session notes |
| 對齊狀態 | `[待確認]` today 頁面跟 dashboard 的定位區分是否如上述？打了哪些 API？ |

## J3. Flow Runs 監控

| 項目 | 說明 |
|------|------|
| 場景 | Admin 監控 AI flow 執行狀態 |
| Frontend route | `/admin/flow-runs` |
| Backend API | `GET /api/admin/flow-runs?page=1&per_page=20&status=failed&flow_name=content_polish` |
| Filter params | `status` (pending/running/completed/failed), `flow_name` |
| 詳情 | `GET /api/admin/flow-runs/{id}` — 含 input/output JSON, error message |
| 重試 | `POST /api/admin/flow-runs/{id}/retry` — 重新執行失敗的 flow |
| Frontend 預期 | 列表 (filter by status/name) + 詳情 modal/page + retry 按鈕 (只對 failed) |
| 對齊狀態 | `[待確認]` 有 filter 嗎？有 retry 嗎？有詳情頁嗎？ |

## J4. Activity / Changelog

| 項目 | 說明 |
|------|------|
| 場景 | Admin 看最近的系統活動記錄 |
| Frontend route | `/admin/activity` |
| Backend API | `GET /api/admin/activity/sessions` (按 session 分組), `GET /api/admin/activity/changelog` (timeline) |
| 語意 | Sessions = 按開發 session 分組的活動；Changelog = 按時間排列的所有變更 |
| Frontend 預期 | 兩個 view/tab：Session 視圖 + Timeline 視圖 |
| 對齊狀態 | `[待確認]` 有兩種視圖嗎？ |

## J5. Session Notes

| 項目 | 說明 |
|------|------|
| 場景 | Admin 看 AI 生成的 session 筆記（每日摘要、weekly review 等） |
| Backend API | `GET /api/admin/session-notes?date=2026-03-27&type=plan&days=7` |
| Query params | `date` (YYYY-MM-DD), `type` (plan/reflection/context/metrics/insight), `days` (1-30) |
| 語意 | Session notes 是 AI flow 自動產生的結構化筆記 |
| 使用方 | `/admin/today` 和 `/admin/planning` 都讀這個 API |
| 對齊狀態 | `[待確認]` |

## J6. Insights 管理

| 項目 | 說明 |
|------|------|
| 場景 | Admin 審核和管理 AI 發現的 pattern/hypothesis |
| Frontend route | `/admin/insights` |
| Backend API | `GET /api/admin/insights?status=unverified&limit=10` |
| Status flow | `unverified` → `verified` (確認有效) / `invalidated` (確認無效) → `archived` |
| Update | `PUT /api/admin/insights/{id}` + `{status?, append_evidence?, conclusion?}` |
| Response 特殊欄位 | `hypothesis`, `evidence[]`, `source_dates[]`, `conclusion` — insight 是有假說+驗證的結構 |
| 語意 | Insights 是 session notes 的子類型，但多了 hypothesis/evidence/conclusion 的結構。獨立頁面的意義在於「主動管理假說驗證流程」 |
| 對齊狀態 | `[待確認]` 有做 status 切換嗎？evidence append 嗎？conclusion 編輯嗎？如果只是 read-only list，可以考慮合併回 today 頁面 |

## J7. Planning 頁面

| 項目 | 說明 |
|------|------|
| 場景 | Admin 看每日計畫的歷史和分析 |
| Frontend route | `/admin/planning` |
| Backend API | `GET /api/admin/session-notes?type=plan` (讀 plan type 的 session notes) |
| 語意 | 跟 Today 不同 — Planning 是看「計畫的歷史軌跡」，Today 是「今天的 plan」 |
| 無 dedicated API | Backend 沒有 planning 專屬 endpoint，用 session-notes 的 type filter |
| 對齊狀態 | `[待確認]` 這個頁面的實際用途是什麼？只讀 session-notes 夠嗎？ |

## J8. Stats — Drift Report

| 項目 | 說明 |
|------|------|
| 場景 | Admin 看「我實際做的事」vs「我的目標」是否偏移 |
| Backend API | `GET /api/admin/stats/drift?days=30` |
| Frontend 位置 | Dashboard 的一部分？還是獨立頁面？ |
| 對齊狀態 | `[待確認]` drift report 顯示在哪？ |

## J9. Stats — Learning Dashboard

| 項目 | 說明 |
|------|------|
| 場景 | Admin 看學習進度（筆記數、趨勢、top tags） |
| Backend API | `GET /api/admin/stats/learning` |
| Response | `{notes: {total, last_week, last_month, by_type}, activity: {this_week, last_week, trend}, top_tags: [{name, count}]}` |
| 對齊狀態 | `[待確認]` 有做 learning dashboard UI 嗎？在哪個頁面？ |

---

# K. Admin — Tracking

## K1. Tracking Topics

| 項目 | 說明 |
|------|------|
| 場景 | Admin 追蹤特定搜尋主題或指標 |
| Frontend route | `/admin/tracking` |
| Backend CRUD | `GET/POST/PUT/DELETE /api/admin/tracking` |
| Create request | `{name, keywords[], sources[], enabled?, schedule?}` |
| 語意 | 目前只有 topic metadata CRUD，**沒有 data point 記錄功能** |
| 問題 | 這是半成品嗎？還是只是「我要追蹤哪些主題」的設定頁？ |
| 對齊狀態 | `[待確認]` 前端做了什麼？只有 CRUD form？有做 data visualization 嗎？ |

---

# L. Admin — 檔案上傳

## L1. Upload to R2

| 項目 | 說明 |
|------|------|
| 場景 | Admin 在 editor 裡上傳圖片 |
| Backend API | `POST /api/admin/upload` |
| Request format | `multipart/form-data`, field name = `file` |
| 限制 | Max 5MB, JPEG/PNG/WebP/GIF |
| Response | `{data: {url: "https://cdn.example.com/uploads/uuid.jpg"}}` |
| Frontend 預期 | Editor 裡的圖片上傳 → 取得 URL → 插入 markdown `![](url)` 或設為 cover_image |
| 對齊狀態 | `[待確認]` upload 有做嗎？用在哪？ |

---

# M. Webhook（外部觸發，Frontend 不直接呼叫）

## M1. GitHub Webhook

| 項目 | 說明 |
|------|------|
| API | `POST /api/webhook/github` |
| 觸發者 | GitHub（push, pull_request 事件） |
| 用途 | 當 Obsidian repo 有新 commit 時自動同步 content |
| Frontend | **不需要做任何事** — 這是 server-to-server |

## M2. Notion Webhook

| 項目 | 說明 |
|------|------|
| API | `POST /api/webhook/notion` |
| 觸發者 | Notion（database change 事件） |
| 用途 | 當 Notion database 有變更時自動同步 task/goal/project |
| Frontend | **不需要做任何事** |

---

# N. 已確認的問題清單

## Bugs

| # | 問題 | 嚴重度 | 修正方 |
|---|------|--------|--------|
| BUG-1 | Pipeline API path 缺 `/admin` — 全部 404 | CRITICAL | Frontend |
| BUG-2 | Collected curate 操作完全缺失 | HIGH | Frontend |

## 路由/定位疑問

| # | 問題 | 需要 Frontend 回答 |
|---|------|-------------------|
| Q-1 | Build logs 是 public 還是 admin-only？（Backend 提供 public API，Frontend route 放在 admin） | route 位置是故意的嗎？ |
| Q-2 | Essay/Bookmark/Digest 需要 public 頁面嗎？ | 計畫做嗎？ |
| Q-3 | Knowledge Graph 計畫做 UI 嗎？ | 做 / defer / 砍 service？ |
| Q-4 | Search 要獨立頁面嗎？（Backend 搜全站，Frontend 只搜 articles） | 要擴大搜尋範圍嗎？ |
| Q-5 | Dashboard vs Today 定位差異？ | 實際上有區分嗎？ |
| Q-6 | Planning 頁面實際用途？ | 跟 Today 重疊嗎？ |
| Q-7 | Tracking 是半成品嗎？ | 有 data point 記錄功能嗎？ |
| Q-8 | Insights 獨立頁面的價值？ | 值得保留還是合併？ |
| Q-9 | Topic admin CRUD UI 在哪？ | 有做嗎？ |

---

# O. Frontend 逐條確認表

請對每個功能填入狀態和說明：

| 編號 | 功能 | 狀態 | 說明 |
|------|------|------|------|
| A1 | 首頁 | | |
| A2 | 文章列表 + 搜尋 | | |
| A3 | 文章詳情 + Related | | |
| A4 | 專案列表 | | |
| A5 | 專案詳情 (case study) | | |
| A6 | TIL | | |
| A7 | Notes | | |
| A8 | Build Logs | | |
| A9 | Tag 瀏覽 | | |
| A10 | Topic 頁面 | | |
| A11 | 全站搜尋 | | |
| A12 | Knowledge Graph | | |
| A13 | RSS head link | | |
| A14 | Sitemap / robots.txt | | |
| B1 | OAuth 登入 | | |
| B2 | Token refresh + rotation | | |
| C1 | Content 建立 (editor) | | |
| C2 | Content 編輯 | | |
| C3 | Content 發布 | | |
| C4 | Visibility toggle | | |
| C5 | Content 刪除 | | |
| C6 | Admin content list + filters | | |
| D1 | Review 佇列 | | |
| D2 | Review approve/reject/edit | | |
| E1 | AI Polish flow | | |
| F1 | Feed 管理 | | |
| F2 | Collected items (含 curate) | | |
| F3 | Pipeline 手動觸發 | | |
| G1 | Topic CRUD | | |
| G2 | Tag + Alias 管理 | | |
| H1 | Notion Source 管理 | | |
| H2 | Task 管理 (my-day, batch) | | |
| H3 | Goal 管理 | | |
| I1 | Project CRUD (含 case study) | | |
| J1 | Dashboard | | |
| J2 | Today 頁面 | | |
| J3 | Flow Runs 監控 | | |
| J4 | Activity / Changelog | | |
| J5 | Session Notes | | |
| J6 | Insights 管理 | | |
| J7 | Planning 頁面 | | |
| J8 | Drift Report | | |
| J9 | Learning Dashboard | | |
| K1 | Tracking Topics | | |
| L1 | Upload | | |
