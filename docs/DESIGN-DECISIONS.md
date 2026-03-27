# koopa0.dev — 頁面架構盤點與設計決策

> 產出日期：2026-03-27
> 用途：盤點現有頁面、釐清設計意圖、找出缺口、決定下一步
> 回覆方式：每個決策標 `[A]`/`[B]`/`[C]` 或自訂答案

---

## 一、這個網站的定位

首頁 hero 寫的是：

> **Production systems that perform under pressure**
> Backend architecture, performance optimization, and system design.

About 頁寫的是：

> This site is my personal knowledge engine — input, process, output.

所以定位是：**Go Backend Consultant 的個人品牌 + 知識引擎**。不是純部落格，是一個展示能力、組織知識、對外輸出的系統。

---

## 二、現有頁面全覽

### 公開頁面（訪客看到的）

導航列：`Home` · `Writing ▾ (Articles, TIL)` · `Projects` · `About` · `⌘K 搜尋`

| Route | 頁面 | 做什麼 | 內容來源 |
|-------|------|--------|---------|
| `/` | 首頁 | Hero + Featured Projects + Tech Stack + Latest Feed (6 篇 mixed) + Contact CTA | projects + contents |
| `/articles` | 文章列表 | 3 欄 grid、inline 搜尋（debounce 300ms）、tag filter、分頁 (12/頁) | `GET /api/contents?type=article` |
| `/articles/:slug` | 文章詳情 | TOC 側欄、syntax highlight、copy code、**related 區塊（空的，API 沒接）** | `GET /api/contents/{slug}` |
| `/projects` | 專案列表 | status filter (all/completed/in-progress/maintained/archived) | `GET /api/projects` |
| `/projects/:slug` | 專案詳情 | Case study 格式：problem → solution → architecture → results | `GET /api/projects/{slug}` |
| `/til` | TIL 列表 | tag filter，一次載 100 篇 | `GET /api/contents/by-type/til` |
| `/til/:slug` | TIL 詳情 | 短篇內容 | `GET /api/contents/{slug}` |
| `/notes` | 筆記列表 | 同 TIL 結構 | `GET /api/contents/by-type/note` |
| `/notes/:slug` | 筆記詳情 | | `GET /api/contents/{slug}` |
| `/build-logs` | Build Log 列表 | **剛從 admin 搬出來** | `GET /api/contents/by-type/build-log` |
| `/build-logs/:slug` | Build Log 詳情 | | `GET /api/contents/{slug}` |
| `/tags/:tag` | Tag 過濾頁 | 顯示所有帶此 tag 的 content（混合 type，統一 grid） | `GET /api/contents?tag=xxx` |
| `/about` | 關於 | 照片 + Bio + Skills (3 類) + Contact (4 管道) + Person Schema | 靜態 |
| `/privacy` | 隱私政策 | 靜態 | — |
| `/terms` | 使用條款 | 靜態 | — |
| `/login` | 登入 | Google OAuth | — |

### 不存在但 Backend 支援的公開頁面

| Route | 對應 content type | Backend API | 設計意圖 |
|-------|-------------------|-------------|---------|
| `/essays` | `essay` — 個人想法、非技術反思 | `GET /api/contents/by-type/essay` | 跟 article 區別：article 是技術深度文，essay 是個人觀點 |
| `/bookmarks` | `bookmark` — 推薦外部文章 + 你的評語 | `GET /api/contents/by-type/bookmark` | 你覺得值得讀的外部文章，附上你的觀點。來源是 RSS collected items 被 curate 後產生 |
| `/digests` | `digest` — 週報/月報 | `GET /api/contents/by-type/digest` | AI DigestGenerate flow 產出的定期彙整。類似 newsletter archive |
| `/topics` | 知識領域分類 | `GET /api/topics` | 高層級分類（Go、AI、系統設計），比 tag 更有結構。Backend 有 API，Frontend service 有 method，但沒頁面 |
| `/search` | 全站搜尋 | `GET /api/search?q=keyword` | Backend 搜所有 type。目前只有 header ⌘K dropdown，無獨立頁面 |
| `/knowledge-graph` | 知識關聯圖 | `GET /api/knowledge-graph` | pgvector embedding 建的語義網路。節點 = content/topic，邊 = 相似度 |

### Admin 頁面

Sidebar 分 6 組，共 18 個頁面：

| 分組 | 頁面 | 做什麼 |
|------|------|--------|
| **概覽** | Dashboard | 系統全局：10 張 stat card + drift report + learning dashboard + quick sync |
| | Today | 今日執行：My Day tasks + overdue + insights + planning heatmap |
| | Insights | 假說追蹤：verify/invalidate/append evidence |
| | Flow Runs | AI flow 監控：filter + detail + retry |
| **分析** | Planning | 計畫歷史：14 天趨勢 + day-of-week heatmap |
| **Pipeline** | Pipeline | 手動觸發 7 個操作 |
| | RSS Feeds | Feed CRUD + filter config + manual fetch |
| | Collected | RSS 收集審核：feedback + ignore + **curate（剛補上）** |
| | Review Queue | 內容審核：approve/reject |
| | Contents | 內容管理：type/visibility filter + edit/toggle |
| | Tags | Tag CRUD + Alias map/confirm/reject + backfill/merge |
| **Notion** | Projects | 專案列表 → 連到 project-editor |
| | Tasks | 任務：All/My Day view + create/edit/complete |
| | Goals | 目標：read-only + status dropdown |
| | Sources | Notion database discover/connect/role |
| **知識** | Activity | 活動紀錄：sessions + changelog 兩種視圖 |
| | Build Logs | **已搬到 public，這裡的 sidebar link 需更新** |

---

## 三、7 種 Content Type 的完整圖

系統有 7 種 content type，共用同一張 `contents` 表和同一套生命週期（draft → review → published）。
但前端頁面覆蓋度不一致：

| Type | 是什麼 | 例子 | 有 public 頁面？ | 有 admin 建立方式？ | 導航可達？ |
|------|--------|------|-----------------|-------------------|-----------|
| `article` | 深度技術文章 (1000-5000 字) | 「Go error handling 完整指南」 | ✅ `/articles` | ✅ editor | ✅ Writing → Articles |
| `essay` | 個人想法、非技術反思 | 「為什麼我離開大公司」 | ❌ | ❌ editor hardcoded article | ❌ |
| `build-log` | 專案開發紀錄 | 「koopa0.dev Week 3」 | ✅ `/build-logs` (剛修) | ❌ editor hardcoded article | ❌ 不在導航 |
| `til` | Today I Learned (100-500 字) | 「TIL: psql \watch」 | ✅ `/til` | ❌ editor hardcoded article | ✅ Writing → TIL |
| `note` | 技術筆記片段 | 「PostgreSQL JSONB 速查」 | ✅ `/notes` | ❌ editor hardcoded article | ❌ 不在導航 |
| `bookmark` | 推薦外部文章 + 評語 | 「Uber Go style guide 值得看」 | ❌ | ❌ curate 剛修好但不走 editor | ❌ |
| `digest` | 週報/月報 | 「2026 第 12 週」 | ❌ | ❌ AI flow 產生 | ❌ |

**核心問題**：
1. Editor 只能建 article（type hardcoded），其他 6 種 type 要嘛靠 AI flow、要嘛靠 Obsidian sync、要嘛沒辦法建
2. 有 public 頁面的 type 不一定在導航列裡
3. 沒 public 頁面的 type 在搜尋 dropdown 裡有 route mapping，但 route 不存在 → 點了會 404

---

## 四、設計決策

以下每個決策我列了：**這東西是什麼 → 目前長什麼樣 → 選項 → 我的建議**。

---

### D1: Writing 導航要怎麼組織？

**問題的本質**：現在 Writing dropdown 只有 Articles 和 TIL。但系統有 7 種 content type，其中 4 種有 public 頁面。

**目前的導航結構**：
```
Writing ▾
├── Articles      → /articles (只有 type=article)
└── TIL           → /til
```

**看不到的頁面**：
- `/notes` — 有頁面但不在導航裡
- `/build-logs` — 有頁面（剛搬出來）但不在導航裡
- essay, bookmark, digest — 沒有頁面

**選項**：

| 選項 | 做法 | 導航結果 |
|------|------|---------|
| **A: 擴充 Writing** | 把已有頁面全加進去 | `Writing ▾ → Articles · TIL · Notes · Build Logs` |
| **B: 分兩組** | Writing 放長文，Learning 放短篇 | `Writing ▾ → Articles · Essays` / `Learning ▾ → TIL · Notes · Build Logs` |
| **C: 維持現狀** | 只加 Notes（最有價值的缺口） | `Writing ▾ → Articles · TIL · Notes` |
| **D: 不動** | 等內容量夠再整理 | 不變 |

**建議**：看你想展示什麼。A 最完整但導航會長。C 是最小改動。

---

### D2: Essay 要不要獨立頁面？

**Essay 是什麼**：「個人想法、非技術反思」。跟 article 的差別：

| | Article | Essay |
|---|---------|-------|
| 內容 | 技術深度文 | 個人觀點、反思 |
| 讀者 | 想學技術的人 | 想了解你這個人的 |
| 例子 | 「Go error handling 完整指南」 | 「為什麼我離開大公司」 |
| 調性 | 教學、客觀 | 個人、主觀 |

**目前狀態**：Backend 支援。Frontend 沒頁面、editor 不能建 essay、搜尋 dropdown mapping `essay → '/essays'` 但 route 不存在。

**選項**：

| 選項 | 做法 | 對訪客的影響 |
|------|------|-------------|
| **A: 獨立 `/essays`** | 新頁面，導航加入口 | 技術文和個人文分開，讀者各取所需 |
| **B: 併入 `/articles`** | articles 頁加 type tab：「技術文章 / 個人隨筆」 | 同一個地方看所有長文，但有 filter 區分 |
| **C: 暫不做** | 等有 essay 內容再決定 | 訪客看不到 essay |

**建議**：你目前有寫 essay 嗎？如果有 → B（工作量最小，加個 tab）。如果還沒有 → C。

---

### D3: Bookmark 要不要 public 頁面？

**Bookmark 是什麼**：你推薦的外部文章，附上你的評語。資料流是：

```
RSS feeds → collected items → [admin 按 Curate] → bookmark content → publish → 訪客看到
```

**目前狀態**：Curate 按鈕剛補上。但 curate 後產生的 bookmark content 沒有 public 頁面可以看。

**其他人怎麼做**：
- 很多開發者有「推薦閱讀」頁面（像 Hacker News 的個人版）
- 符合知識引擎定位：不只產出自己的內容，也 curate 外部好內容

**選項**：

| 選項 | 做法 | 對訪客的影響 |
|------|------|-------------|
| **A: 建 `/bookmarks` 頁** | 卡片式列表：每張有外部連結 + 你的評語 + topic/tag | 訪客可以看你推薦什麼，了解你關注的領域 |
| **B: 暫不做** | 等 curate 跑穩、有 10+ bookmark 後再建頁面 | Bookmark 暫時只在 admin 可見 |

**建議**：先 B，等有內容再做。頁面沒內容比沒頁面更糟。

---

### D4: Digest 要不要 public 頁面？

**Digest 是什麼**：AI 自動產生的週報/月報，彙整一段時間內你做了什麼、學了什麼、推薦了什麼。

```
AI DigestGenerate flow → content type=digest → publish → 訪客看到
```

**目前狀態**：Frontend pipeline 頁面可以手動觸發 digest 生成（但不帶日期參數）。沒有 public 頁面。

**這個功能的價值**：
- 對訪客：像 newsletter archive，看你每週的精華
- 對你：自動回顧，不需要手動寫週報
- 前提：DigestGenerate flow 要穩定、定期跑

**選項**：

| 選項 | 做法 |
|------|------|
| **A: 建 `/digests` 頁** | 等 flow 穩定後建。類似 newsletter archive |
| **B: 暫不做** | 等 DigestGenerate flow 跑穩再決定 |

**建議**：B。Digest 是「系統穩定後的產物」，現階段先把 pipeline 跑通。

---

### D5: Topic 瀏覽頁

**Topic 是什麼**：高層級知識領域，例如 Go、AI、系統設計、前端。跟 tag 的差別：

| | Topic | Tag |
|---|-------|-----|
| 粒度 | 粗（10-20 個） | 細（幾百個） |
| 例子 | 「Go」「系統設計」 | 「pgvector」「error-handling」 |
| 管理 | Admin 手動 CRUD | 自動提取 + alias 映射 |
| 用途 | 知識架構的骨幹 | 內容的標籤 |

**目前狀態**：
- Backend API 有 `GET /api/topics` 和 `GET /api/topics/{slug}`（回傳該 topic 下所有 content）
- Frontend `topic.service.ts` 有對應 method
- **但沒有頁面，也不在導航裡**
- Topic 只出現在 content 卡片上當 metadata label，點了沒反應

**這個功能對知識引擎的意義**：Topic 是你組織知識的核心維度。沒有 topic 頁面，訪客只能按 type 瀏覽（articles / til / notes），不能按領域瀏覽（Go 相關的所有東西）。

**選項**：

| 選項 | 做法 | 效果 |
|------|------|------|
| **A: 完整頁面** | `/topics` list + `/topics/:slug` detail | 訪客按知識領域探索，點「Go」看所有 Go 相關 content |
| **B: 輕量入口** | 首頁或導航加 topic pills，點擊到 detail 頁 | 不需要 list 頁，直接進入某個 topic |
| **C: 暫不做** | topic 維持 metadata 角色 | 等 content 和 topic 夠多再做 |

**建議**：看你目前 topic 和 content 的量。量夠 → A（是知識引擎的核心功能）。量不夠 → C。

---

### D6: 搜尋要不要獨立頁面？

**目前的搜尋**：Header 裡的 ⌘K dropdown widget。

```
訪客按 ⌘K → 輸入關鍵字 → dropdown 顯示結果 → 點擊導到對應頁面
```

- 搜尋結果有 type-aware routing（article → `/articles/:slug`，TIL → `/til/:slug`）
- **沒有分頁**（如果結果很多，dropdown 會很長）
- **不是獨立頁面**（URL 不變，不能分享搜尋結果）

**Backend 能力**：`GET /api/search?q=keyword` 搜全站所有 published content（7 種 type），有分頁，用 PostgreSQL full-text search。

**選項**：

| 選項 | 做法 | 效果 |
|------|------|------|
| **A: 建 `/search?q=xxx`** | 獨立頁面，有分頁、type filter、完整卡片 | 可分享搜尋 URL、SEO 友善、大量結果好用 |
| **B: 強化 dropdown** | dropdown 加分頁和更多結果 | 不改架構，體驗稍改善 |
| **C: 維持現狀** | ⌘K dropdown 夠用 | 零工作量 |

**建議**：看內容量。< 100 篇 → C。> 100 篇 → A。

---

### D7: Related Articles 要不要接上？

**是什麼**：文章詳情頁底部的「相關推薦」區塊。Backend 用 pgvector embedding 算語義相似度。

**目前狀態**：
- Backend API 存在：`GET /api/contents/related/{slug}?limit=5`
- Frontend service method 存在：`content.service.ts` 的 `getRelated()`
- 文章詳情頁**有 Related 區塊但沒資料**（API 沒呼叫）

**這個功能的價值**：讀完一篇文章 → 看到 5 篇相關的 → 繼續閱讀。標準的 engagement 提升手段。

**選項**：

| 選項 | 做法 | 工作量 |
|------|------|--------|
| **A: 接上** | article-detail 加一個 API call + 渲染推薦卡片 | 約 1 小時 |
| **B: 暫不接** | 等 embedding 品質確認後再接 | — |

**前提問題**：Content 已經有跑 embedding 嗎？如果有 → A。沒有 → B。

---

### D8: RSS / Sitemap URL Proxy

**問題**：Frontend 和 Backend 的 URL 不一樣。

| 項目 | Frontend 寫的 | Backend 實際路徑 |
|------|--------------|-----------------|
| RSS | `https://koopa0.dev/feed.xml` | `/api/feed/rss` |
| Sitemap | `https://koopa0.dev/sitemap.xml` | `/api/feed/sitemap` |

如果沒有 nginx/CDN proxy 把 `/feed.xml` → `/api/feed/rss`，RSS 訂閱者和 Google 爬蟲會拿到 404。

**你只需要回答**：部署環境有沒有這個 proxy 規則？

| 選項 | 做法 |
|------|------|
| **A: 有 proxy** | 不用改 |
| **B: 沒有 proxy** | Frontend 改成直接用 `/api/feed/rss` 和 `/api/feed/sitemap` |

---

## 五、整體觀察

### 做得好的
- 公開頁面的品質不錯：article detail 有 TOC + syntax highlight + copy code
- Project detail 有完整 case study 格式
- Admin 功能很完整：18 個頁面覆蓋了 content lifecycle、pipeline、monitoring
- Auth 實作很安全：fragment tokens + memory Signal + token rotation

### 主要缺口
1. **Editor 只能建 article** — 這是最大的單點問題，6 種 type 都建不了
2. **導航不完整** — notes 和 build-logs 有頁面但不在導航裡，訪客找不到
3. **搜尋 dropdown 有 6 個 route mapping 指向不存在的頁面** — 會 404
4. **Topic 沒有前端存在感** — 是知識引擎的核心概念，但前端幾乎看不到

### 建議的推進順序

不管上面的決策怎麼選，這些是確定要做的：

| 順序 | 項目 | 理由 |
|------|------|------|
| 1 | Editor 加 type selector | 不修這個，essay/til/note/bookmark/digest 都不能手動建 |
| 2 | 導航加 Notes + Build Logs | 有頁面但找不到 = 白做了 |
| 3 | 搜尋 dropdown 修 404 route mapping | essay/bookmark/digest 沒頁面的 type 不要放在 route map 裡 |

---

## 回覆格式

```
D1: A/B/C/D
D2: A/B/C
D3: A/B
D4: A/B
D5: A/B/C
D6: A/B/C
D7: A/B
D8: A/B
```
