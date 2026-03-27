# Frontend 回覆：Backend ↔ Frontend 對齊

> 回覆日期：2026-03-27
> 回覆方：Frontend (Angular)
> 對應文件：`ALIGNMENT-2026-03-27.md`

---

## 已修正（本次 commit）

| # | 問題 | 修正 |
|---|------|------|
| BUG-1 | Pipeline path 缺 `/admin` | `pipeline.service.ts:58` 改為 `/api/admin/pipeline/${action}` + 測試同步更新 |
| MISMATCH-1 | Build-log routes 在 admin children | 搬到 public routes（`/build-logs`, `/build-logs/:slug`）|
| BUG-2 | Collected curate 缺實作 | `collected.service.ts` 加 `curateItem()`，collected UI 加 BookmarkPlus 按鈕 |
| — | Search TYPE_ROUTE_MAP | `build-log` route 從 `/admin/build-logs` 改為 `/build-logs` |

---

## 全功能對齊表

| # | 功能 | 狀態 | 說明 |
|---|------|------|------|
| A1 | 首頁 | OK | `GET /api/projects` (featured) + `GET /api/contents/by-type/article` (6 篇) + `GET /api/contents` (18 篇 mixed feed) |
| A2 | 文章列表 + 搜尋 | OK | 無搜尋用 `/api/contents?type=article`；有搜尋用 `/api/search` |
| A3 | 文章詳情 + Related | 不一致 | slug 正確。**Related API 未呼叫** — `getRelated()` 存在但 article-detail 沒用 |
| A4 | 專案列表 | OK | 有 status filter，featured 只在首頁用 |
| A5 | 專案詳情 (case study) | OK | 所有 case study 欄位有渲染（problem/solution/architecture/results） |
| A6 | TIL | OK | 用 `GET /api/contents/by-type/til` |
| A7 | Notes | OK | 用 `GET /api/contents/by-type/note` |
| A8 | Build Logs | **已修正** | 原在 admin children，已搬到 public routes |
| A9 | Tag 瀏覽 | OK | `/tags/:tag` 存在，mixed type 統一 grid |
| A10 | Topic 頁面 | 未實作 | service 有 method，無 route/page |
| A11 | 全站搜尋 | OK（有限） | header dropdown widget，非獨立頁面 |
| A12 | Knowledge Graph | 未實作 | service method 存在，零使用。Defer Phase 2 |
| A13 | RSS head link | OK（需確認 proxy） | `index.html` 用 `/feed.xml`，Backend 是 `/api/feed/rss` |
| A14 | Sitemap / robots.txt | OK（需確認 proxy） | `robots.txt` 用 `/sitemap.xml`，Backend 是 `/api/feed/sitemap` |
| B1 | OAuth 登入 | OK | BFF proxy → fragment tokens → memory Signal |
| B2 | Token refresh | OK | token rotation + race condition 防護 |
| C1 | Content 建立 | 不一致 | 缺 type selector（hardcoded article）、topic、visibility、review_level |
| C2 | Content 編輯 | OK | 送全部欄位 |
| C3 | Content 發布 | OK | editor toolbar 有 Publish |
| C4 | Visibility toggle | OK | contents list 有 inline toggle |
| C5 | Content 刪除 | 未實作 | `ContentService.remove()` 存在但零 UI |
| C6 | Admin content list | OK（部分） | 有 visibility + type filter，缺 status filter |
| D1 | Review 佇列 | OK | 顯示 review_level badge |
| D2 | Review 操作 | OK（缺 edit） | approve ✓、reject + notes ✓、edit ✗ |
| E1 | AI Polish flow | OK | 完整 3-step：trigger → poll → approve |
| F1 | Feed 管理 | OK | CRUD + filter_config + manual fetch |
| F2 | Collected items | **已修正** | 原缺 curate，已補 service + UI |
| F3 | Pipeline 手動觸發 | **已修正** | 原缺 `/admin` prefix，已修正路徑 |
| G1 | Topic CRUD | 未實作 | 無 admin page |
| G2 | Tag + Alias 管理 | OK | CRUD + map/confirm/reject + backfill + merge |
| H1 | Notion Source 管理 | OK | discover + connect + role + toggle |
| H2 | Task 管理 | OK（部分） | my-day ✓、complete ✓。缺 batch my-day UI、recurring 回饋 |
| H3 | Goal 管理 | OK | read-only + status dropdown |
| I1 | Project CRUD | 不一致 | 缺 case study 欄位（problem/solution/architecture/results）在 editor form |
| J1 | Dashboard | OK | 8+ APIs，10 stat cards |
| J2 | Today 頁面 | OK | my-day tasks + insights + planning + daily summary |
| J3 | Flow Runs | OK | filter + detail + retry + auto-refresh |
| J4 | Activity | OK | sessions + changelog 兩種視圖 |
| J5 | Session Notes | 無獨立頁面 | 被 Today/Planning 消費 |
| J6 | Insights 管理 | OK | verify/invalidate + evidence + archive |
| J7 | Planning 頁面 | OK | 30 天 metrics，session-notes 夠用 |
| J8 | Drift Report | OK | Dashboard section |
| J9 | Learning Dashboard | OK | Dashboard section |
| K1 | Tracking Topics | OK | CRUD，無 data points（設計如此） |
| L1 | Upload | OK | `POST /api/admin/upload`，用在 editor cover_image |

---

## 待決策項目

見 `DESIGN-DECISIONS.md`，共 7 個設計問題待 user 回覆。

---

## 待修項目（按優先級）

| 優先級 | 項目 | 工作量 |
|--------|------|--------|
| P1 | C1: Editor type selector + topic selector + visibility/review_level | 中 |
| P1 | G1: Topic admin CRUD 頁面 | 中 |
| P2 | A3: Related articles 接上 API | 小 |
| P2 | I1: Project editor 補 case study 欄位 | 小 |
| P2 | C5: Content delete UI | 小 |
| P2 | C6: Content list 補 status filter | 小 |
| P3 | D2: Review edit 操作 | 小 |
| P3 | H2: Batch my-day + recurring 回饋 | 中 |
| P3 | F3: Digest 日期參數 | 小 |
