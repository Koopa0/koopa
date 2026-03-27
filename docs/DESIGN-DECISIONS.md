# 待決策設計問題

> 產出日期：2026-03-27
> 來源：Backend ↔ Frontend 對齊報告
> 用法：逐條回覆 `[A]`/`[B]`/`[C]` 或自訂答案

---

## D1: Essay 要不要獨立頁面？

### 背景

系統有 7 種 content type。`essay` 是「個人想法、非技術反思」，跟 `article`（深度技術文章）的差別在於：
- article：「Go error handling 完整指南」「PostgreSQL JSONB 效能調校」
- essay：「為什麼我離開大公司」「遠端工作一年的反思」

### 現狀

- Backend 支援 `essay` type，API 沒問題
- Frontend **沒有 `/essays` 頁面**
- 訪客如果想看 essay，目前唯一途徑是透過 `/tags/:tag` 碰巧看到
- Article editor 的 type 是 hardcoded `article`，所以也無法建立 essay（這是另一個 bug，會另外修）

### 選項

| 選項 | 做法 | 效果 |
|------|------|------|
| **A: 獨立頁面** | 建 `/essays` list + `/essays/:slug` detail | 導航列加 Essay 入口，跟 Articles 平行 |
| **B: 統一在 Articles** | `/articles` 同時顯示 article + essay，用 tab 或 filter 切換 | 訪客在同一個地方看所有長文 |
| **C: 不做** | 暫時不處理 essay | 等有足夠 essay 內容再決定 |

### 建議

如果你預期短期內會寫 essay → B（最少工作量，articles 頁加個 type filter 就好）。
如果 essay 跟 article 的調性差很多、不想混在一起 → A。
如果目前沒有 essay → C。

---

## D2: 要不要獨立 Search 頁面？

### 背景

Backend `GET /api/search?q=keyword` 搜尋**全站所有 published content**（articles, TILs, notes, essays, build-logs, bookmarks, digests），回傳結果帶 `type` 欄位。

### 現狀

- Frontend 搜尋是 header 裡的 dropdown widget（按 ⌘K 觸發）
- 搜尋結果有 type-aware routing（點 article → `/articles/:slug`，點 TIL → `/til/:slug`）
- **沒有 `/search` 獨立頁面**
- 搜尋結果在 dropdown 裡顯示，沒有分頁

### 選項

| 選項 | 做法 | 效果 |
|------|------|------|
| **A: 獨立頁面** | 建 `/search?q=keyword` 頁面，有分頁、type filter、完整結果卡片 | 完整搜尋體驗，SEO 友善 |
| **B: 強化現有 dropdown** | dropdown 加分頁、顯示更多結果、加 type filter | 不改架構，但搜尋體驗更好 |
| **C: 維持現狀** | 現有 ⌘K dropdown 已經夠用 | 零工作量 |

### 建議

看內容量。如果 content < 100 篇，dropdown 夠用 → C。
如果 content > 100 篇或你在意 SEO（搜尋結果頁可以被 Google 索引）→ A。

---

## D3: Bookmark 要不要 public 頁面？

### 背景

`bookmark` = 你推薦的外部文章 + 你的評語。來源是 RSS collected items 被 curate 後產生。

### 現狀

- Backend 支援 bookmark type
- Frontend 沒有 `/bookmarks` 頁面
- 搜尋 dropdown 的 TYPE_ROUTE_MAP 有 `bookmark → '/bookmarks'`，但這個 route 不存在（會 404）

### 選項

| 選項 | 做法 | 效果 |
|------|------|------|
| **A: 獨立頁面** | 建 `/bookmarks` list（卡片式，每張帶評語 + 外部連結） | 類似「推薦閱讀」或「資源庫」 |
| **B: 不做 public，只在 admin** | bookmark 只在 admin 管理 | 訪客看不到你的推薦 |
| **C: 不做** | 暫不處理 | 等 curate 功能補上、有足夠 bookmark 後再決定 |

### 建議

Bookmark 的價值在於「帶有你觀點的推薦」。如果你的定位是知識引擎，推薦閱讀很有意義 → A。
但前提是 curate 功能先修好（BUG-2），否則沒有 bookmark 可以顯示。先 C，curate 修好後再做 A。

---

## D4: Digest 要不要 public 頁面？

### 背景

`digest` = 週報/月報，彙整一段時間的精華。由 AI DigestGenerate flow 產生。

### 現狀

- Backend 支援 digest type
- Frontend 沒有 `/digests` 頁面
- 搜尋 dropdown 的 TYPE_ROUTE_MAP 有 `digest → '/digests'`，但 route 不存在

### 選項

| 選項 | 做法 | 效果 |
|------|------|------|
| **A: 獨立頁面** | 建 `/digests` list + detail | 類似 newsletter archive |
| **B: 不做** | digest 只在 admin 可見 | 等你開始穩定產出 digest 後再決定 |

### 建議

Digest 是「穩定輸出後的產物」。如果你還沒開始定期產出 weekly digest → B。
等 DigestGenerate flow 跑穩、有 5+ 篇 digest 後再做 A。

---

## D5: Topic 要不要 public 瀏覽頁？

### 背景

Topic 是高層級知識領域（Go, AI, 系統設計, 前端），比 tag 更高層。一個 content 可屬於多個 topic。

### 現狀

- Backend API 有 `GET /api/topics`（列表）和 `GET /api/topics/{slug}`（含該 topic 下的 content）
- Frontend `topic.service.ts` 有對應 method，但**沒有 route 也沒有頁面**
- Topics 目前只出現在 content 卡片上當 metadata label
- 導航列沒有 Topic 入口

### 選項

| 選項 | 做法 | 效果 |
|------|------|------|
| **A: 獨立頁面** | 建 `/topics` list + `/topics/:slug` detail（列出該 topic 下所有 content） | 訪客可按知識領域瀏覽，類似「分類頁」 |
| **B: 只在導航/首頁顯示** | 首頁或導航列加 topic pills/chips，點擊導到 topic detail 頁 | 輕量方案，不需要 topic list 頁 |
| **C: 不做** | topic 維持 metadata 角色 | 等 content 量夠多再做分類瀏覽 |

### 建議

Topic 是你知識引擎的核心組織方式。如果你有 5+ 個 topic 且每個 topic 下有 3+ 篇 content → A 或 B。
如果 topic 還沒建幾個 → C。

---

## D6: RSS/Sitemap URL 是否有 proxy？

### 背景（需要 Backend 確認）

| 項目 | Frontend 用的 URL | Backend API |
|------|-------------------|-------------|
| RSS | `https://koopa0.dev/feed.xml` (index.html) | `GET /api/feed/rss` |
| Sitemap | `https://koopa0.dev/sitemap.xml` (robots.txt) | `GET /api/feed/sitemap` |

### 問題

這兩組 URL 不一樣。是否有 nginx/CDN proxy 把 `/feed.xml` → `/api/feed/rss`？
如果沒有，訪客和搜尋引擎會拿到 404。

### 選項

| 選項 | 做法 |
|------|------|
| **A: 有 proxy** | 不用改，確認 proxy 規則存在即可 |
| **B: 沒有 proxy** | Frontend 改成 `/api/feed/rss` 和 `/api/feed/sitemap` |

---

## D7: Related Articles 要不要接上？

### 背景

Backend 有 `GET /api/contents/related/{slug}?limit=5`，基於 pgvector embedding 做語義相似推薦。Frontend `content.service.ts` 有 `getRelated()` method。但 article-detail component **沒有呼叫它**，related 區塊空的。

### 選項

| 選項 | 做法 |
|------|------|
| **A: 接上** | article-detail 呼叫 related API，渲染推薦區塊。工作量約 1 小時 |
| **B: 不接** | 等 embedding 資料品質穩定後再接 |

### 建議

如果 content 已經有 embedding → A（一小時的活，顯著提升文章頁體驗）。
如果 embedding 還沒跑完或品質不穩 → B。

---

## 回覆格式

直接在每個 D 後面標你的選擇：

```
D1: B
D2: C
D3: C（等 curate 修好）
D4: B
D5: C
D6: A（有 nginx proxy）
D7: A
```
