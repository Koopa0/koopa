# koopa0.dev — 個人知識引擎平台設計

> 這不是一個部落格。這是一個可輸入、可輸出的個人知識系統。
> Obsidian 是大腦，AI Pipeline 是編輯團隊，網站是出版物，資料收集工具是耳目。

---

## 核心理念

koopa0.dev 是 Koopa 的個人品牌平台，同時也是一個知識引擎。它有三個面向：

1. **輸入（Input）** — 主動收集資料、追蹤技術動態、整理新知，幫助 Koopa 持續學習
2. **處理（Process）** — AI Pipeline 根據 Koopa 的思路和 prompt，將原始資料轉化為有結構的內容
3. **輸出（Output）** — 以多種格式呈現想法、知識和作品，對自己有用（知識管理），對訪客有價值（學習資源）

平台的價值不在於「發了多少篇文章」，而在於「這個人怎麼思考、怎麼學習、怎麼解決問題」。

---

## 系統架構總覽

```
┌─────────────────────────────────────────────────────────┐
│                    資料收集層 (Input)                     │
│                                                         │
│  Obsidian Vault    Notion         外部資料源              │
│  (知識庫/筆記)     (規劃/任務)    (RSS/API/爬蟲)          │
│       │               │               │                 │
│       └───────────┬────┴───────────────┘                 │
│                   ▼                                      │
│  ┌─────────────────────────────────────┐                 │
│  │     Content Pipeline (AI 處理)      │                 │
│  │                                     │                 │
│  │  Go Genkit Flow:                    │                 │
│  │  - Obsidian vault 變更偵測          │                 │
│  │  - 外部資料爬取與整理               │                 │
│  │  - AI 摘要/擴寫/分類/標籤           │                 │
│  │  - Prompt 模板管理                  │                 │
│  │                                     │                 │
│  │  Rust (可選，特定場景):             │                 │
│  │  - 高效能文字處理                   │                 │
│  │  - Markdown AST 操作               │                 │
│  │                                     │                 │
│  │  Python (可選，特定場景):           │                 │
│  │  - 爬蟲 prototype                  │                 │
│  │  - NLP 前處理                      │                 │
│  └──────────────┬──────────────────────┘                 │
│                 ▼                                        │
│  ┌─────────────────────────────────────┐                 │
│  │         審核層 (Review)             │                 │
│  │                                     │                 │
│  │  分級制：                           │                 │
│  │  - 直接發佈：Obsidian publish:true  │                 │
│  │  - 需審核：AI 生成的草稿            │                 │
│  │  - 需審核：外部資料整理             │                 │
│  │  - 可全自動：TIL / 短筆記           │                 │
│  └──────────────┬──────────────────────┘                 │
│                 ▼                                        │
│  ┌─────────────────────────────────────┐                 │
│  │         Go API (核心服務)           │                 │
│  │                                     │                 │
│  │  - RESTful JSON API                 │                 │
│  │  - PostgreSQL 持久化               │                 │
│  │  - JWT Auth                        │                 │
│  │  - Webhook 接收端                  │                 │
│  │  - 排程任務管理                    │                 │
│  └──────────────┬──────────────────────┘                 │
│                 ▼                                        │
│  ┌─────────────────────────────────────┐                 │
│  │       Angular 前端 (輸出)           │                 │
│  │                                     │                 │
│  │  - SSR + 靜態頁面                  │                 │
│  │  - Topic 主題式架構                │                 │
│  │  - Admin 管理 + Review Queue       │                 │
│  │  - 個人品牌展示                    │                 │
│  └─────────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────┘
```

---

## 一、資料收集層 (Input)

### 1.1 Obsidian Vault（主要知識庫）

Obsidian 是 Koopa 的第一手知識來源。所有思考、學習、筆記都從這裡開始。

**整合方式：**
- Vault Watcher 服務（Go）監控指定目錄的檔案變更
- 解析 frontmatter metadata 決定內容類型和發佈狀態
- 支援 Obsidian 的 `[[wiki-link]]` 語法轉換

**Frontmatter 規範：**
```yaml
---
title: "文章標題"
topics: [backend-engineering, golang]
tags: [go, concurrency, goroutine]
type: article | til | note | essay | build-log | bookmark
status: draft | review | published
publish: true | false
created: 2026-03-08
updated: 2026-03-08
source: ""  # 如果是外部資料整理，標記來源
---
```

**同步策略：**
- `publish: true` + `status: published` → 直接同步到 API，發佈
- `publish: true` + `status: review` → 同步到 API，進入 review queue
- `publish: false` → 不同步，留在 Obsidian
- 檔案刪除 → 軟刪除（不從資料庫真正移除，標記為 archived）

### 1.2 Notion（規劃與任務）

Notion 作為專案規劃和任務追蹤工具。

**整合方式：**
- Notion API 定期拉取特定 database
- 主要用途：同步專案進度到網站的 Projects 頁面
- 不作為內容主要來源

### 1.3 外部資料收集（主動學習）

這是平台的「耳目」— 主動幫 Koopa 收集新知識。

**資料來源：**

| 來源 | 收集方式 | 頻率 | 產出 |
|------|---------|------|------|
| RSS Feeds | 訂閱技術部落格、newsletter | 每小時 | 新文章摘要 |
| GitHub Trending | API 爬取 | 每日 | 值得關注的新專案 |
| Hacker News | API 爬取 top stories | 每 6 小時 | 熱門討論摘要 |
| Reddit (特定 subreddit) | API | 每日 | 社群動態 |
| 特定技術官方部落格 | RSS/爬蟲 | 即時 | 版本更新、重要公告 |
| arXiv/Papers | API | 每週 | AI/Systems 相關論文摘要 |
| 自訂關鍵字追蹤 | 多平台搜尋 | 每日 | 特定主題的最新資訊 |

**處理流程：**
```
外部資料源 → 爬取/API 拉取 → AI 摘要 + 相關性評分
                                      │
                    ┌─────────────────┴──────────────────┐
                    ▼                                    ▼
            高相關性 (> 0.7)                       低相關性
            進入 Review Queue                      存入資料庫備查
            通知 Koopa 審閱                        不發佈
                    │
                    ▼
            Koopa 審閱後：
            - 加入個人觀點 → 發佈為 Bookmark/Curated
            - 觸發深入研究 → 在 Obsidian 開新筆記
            - 忽略 → 標記為已讀
```

**Koopa 的自訂追蹤主題（可配置）：**
- Go 生態系更新（新版本、重要 library）
- Angular 官方公告
- Rust 生態系
- 分散式系統設計
- AI/LLM 應用開發
- 自訂關鍵字

---

## 二、Content Pipeline (AI 處理層)

### 2.1 Go Genkit Flow 架構

Genkit 是 AI 工作流的核心框架。每種內容處理是一個 Flow。

**Flow 類型：**

```
Flow: obsidian-sync
  觸發：Vault Watcher 偵測到檔案變更
  步驟：
    1. 讀取 markdown + frontmatter
    2. 解析 wiki-link，轉換為網站內部連結
    3. 提取 tags（AI 輔助補充）
    4. 計算閱讀時間
    5. 根據 status 決定：直接發佈 or 進入 review queue
    6. 同步到 API

Flow: external-data-collect
  觸發：排程（cron）
  步驟：
    1. 從各資料源拉取最新內容
    2. 去重（與已收集的比對）
    3. AI 生成摘要（2-3 句話）
    4. 計算與 Koopa 追蹤主題的相關性分數
    5. 高相關性 → 通知 + 進入 review queue
    6. 所有資料存入資料庫

Flow: content-generate
  觸發：手動 or 定期（根據 Obsidian 筆記累積量）
  步驟：
    1. 讀取 Koopa 最近的 Obsidian 筆記（同主題）
    2. 根據 prompt 模板，AI 整理成文章草稿
    3. 保留 Koopa 的原始觀點，AI 負責結構化和補充
    4. 進入 review queue
    5. Koopa 編輯/核准後發佈

Flow: topic-digest
  觸發：每週排程
  步驟：
    1. 聚合本週所有收集的外部資料（同主題）
    2. AI 生成週報式摘要
    3. 包含 Koopa 的 Obsidian 筆記中相關的想法
    4. 進入 review queue → 發佈為 "Weekly Digest"
```

### 2.2 Prompt 模板管理

AI 的輸出品質取決於 prompt 設計。Prompt 模板應該：

- 儲存在 Git repo 中（版本控制）
- 反映 Koopa 的寫作風格和思考方式
- 可以按主題/格式分類
- 包含 few-shot examples（從 Koopa 已發佈的內容中提取）

**範例 prompt 結構：**
```
角色：你是 Koopa 的寫作助理。Koopa 是全端開發工程師，偏好簡潔直接的表達。
風格：技術精確、避免廢話、有個人觀點、繁體中文
輸入：{Obsidian 筆記原文}
任務：將這些筆記整理成一篇結構化的 {type} 文章
要求：
- 保留 Koopa 的原始觀點和用詞
- 補充必要的上下文和解釋
- 加入程式碼範例（如果適合）
- 產出 frontmatter + markdown
```

### 2.3 審核分級制

| 等級 | 條件 | 流程 |
|------|------|------|
| **自動發佈** | Obsidian `publish: true` + `status: published` | 直接同步，不需審核 |
| **輕度審核** | TIL、短筆記、Bookmark | 進入 queue，可批次核准 |
| **標準審核** | AI 整理的文章草稿 | 進入 queue，需逐篇審閱編輯 |
| **嚴格審核** | 外部資料摘要、週報 | 進入 queue，需確認事實正確性 |

---

## 三、Go API 設計

### 3.1 資料模型

```
Content (統一內容模型)
├── id: UUID
├── slug: string (URL-friendly)
├── title: string
├── content: text (markdown 原文)
├── excerpt: string (摘要)
├── type: enum (article, til, note, essay, build-log, bookmark, digest)
├── status: enum (draft, review, published, archived)
├── topics: string[] (主題分類)
├── tags: string[] (細粒度標籤)
├── source: string? (外部來源 URL)
├── source_type: enum? (obsidian, notion, ai-generated, external, manual)
├── series_id: string? (系列文章)
├── series_order: int?
├── review_level: enum (auto, light, standard, strict)
├── ai_metadata: jsonb? (AI 處理的 metadata)
├── reading_time: int
├── published_at: timestamp?
├── created_at: timestamp
├── updated_at: timestamp

Topic (主題)
├── id: UUID
├── slug: string
├── name: string
├── description: string
├── icon: string? (lucide icon name)
├── content_count: int (衍生)
├── sort_order: int

Project (專案 / Case Study)
├── id: UUID
├── slug: string
├── title: string
├── description: string
├── long_description: text?
├── role: string
├── tech_stack: string[]
├── highlights: string[]
├── problem: text?
├── solution: text?
├── architecture: text?
├── results: text?
├── github_url: string?
├── live_url: string?
├── build_log_ids: string[]
├── featured: boolean
├── sort_order: int
├── created_at: timestamp
├── updated_at: timestamp

CollectedData (收集的外部資料)
├── id: UUID
├── source_url: string
├── source_name: string (e.g., "Hacker News", "Go Blog")
├── title: string
├── original_content: text?
├── ai_summary: text?
├── relevance_score: float (0-1)
├── topics: string[]
├── status: enum (unread, read, curated, ignored)
├── curated_content_id: UUID? (如果被整理成內容)
├── collected_at: timestamp

ReviewQueue (審核佇列)
├── id: UUID
├── content_id: UUID → Content
├── review_level: enum
├── status: enum (pending, approved, rejected, edited)
├── reviewer_notes: text?
├── submitted_at: timestamp
├── reviewed_at: timestamp?

TrackingTopic (追蹤主題配置)
├── id: UUID
├── name: string
├── keywords: string[]
├── sources: string[] (指定資料源)
├── enabled: boolean
├── schedule: string (cron expression)
```

### 3.2 API Endpoints

**公開 API（訪客）：**
```
GET  /api/contents                    # 所有已發佈內容（分頁、篩選）
GET  /api/contents/:slug              # 單篇內容
GET  /api/contents/type/:type         # 按類型篩選
GET  /api/topics                      # 所有主題
GET  /api/topics/:slug                # 主題下的所有內容
GET  /api/projects                    # 所有專案
GET  /api/projects/:slug              # 單一專案
GET  /api/search?q=keyword            # 全文搜尋（跨所有類型）
GET  /api/feed/rss                    # RSS Feed
GET  /api/feed/sitemap                # Sitemap XML
```

**管理 API（需 Auth）：**
```
# 內容管理
POST   /api/admin/contents             # 建立內容
PUT    /api/admin/contents/:id         # 更新內容
DELETE /api/admin/contents/:id         # 刪除內容（軟刪除）
POST   /api/admin/contents/:id/publish # 發佈

# 審核佇列
GET    /api/admin/review               # 取得待審核清單
POST   /api/admin/review/:id/approve   # 核准
POST   /api/admin/review/:id/reject    # 退回
PUT    /api/admin/review/:id/edit      # 編輯後核准

# 收集的資料
GET    /api/admin/collected             # 取得收集的資料（分頁）
POST   /api/admin/collected/:id/curate  # 將收集資料轉為內容
POST   /api/admin/collected/:id/ignore  # 忽略

# 專案管理
POST   /api/admin/projects             # 建立專案
PUT    /api/admin/projects/:id         # 更新專案
DELETE /api/admin/projects/:id         # 刪除

# 主題管理
POST   /api/admin/topics               # 建立主題
PUT    /api/admin/topics/:id           # 更新
DELETE /api/admin/topics/:id           # 刪除

# 追蹤主題配置
GET    /api/admin/tracking              # 取得追蹤配置
POST   /api/admin/tracking              # 新增追蹤主題
PUT    /api/admin/tracking/:id          # 更新
DELETE /api/admin/tracking/:id          # 刪除

# 統計
GET    /api/admin/stats                 # Dashboard 統計資料
```

**Pipeline API（內部服務間通信）：**
```
POST /api/pipeline/sync                # Obsidian 同步觸發
POST /api/pipeline/collect             # 觸發一次資料收集
POST /api/pipeline/generate            # 觸發 AI 內容生成
POST /api/pipeline/digest              # 觸發週報生成

# Webhook 接收
POST /api/webhook/obsidian             # Obsidian vault 變更通知
POST /api/webhook/notion               # Notion 變更通知
POST /api/webhook/github               # GitHub 事件
```

### 3.3 統一回應格式

```json
{
  "data": { ... },
  "meta": {
    "total": 42,
    "page": 1,
    "per_page": 20,
    "total_pages": 3
  }
}
```

**錯誤格式：**
```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Content not found"
  }
}
```

---

## 四、Angular 前端架構

### 4.1 Topic 主題式架構

從「按格式分類」轉為「按主題分類」。

**資訊架構：**
```
首頁 (/)
├── Hero — 個人介紹 + CTA
├── Latest Feed — 所有類型混合，按時間排序
├── Featured Projects
└── Topics 概覽

Topics (/topics)
├── /topics/backend-engineering
├── /topics/system-design
├── /topics/frontend
├── /topics/learning
└── ...（每個主題頁顯示該主題下所有內容，不分格式）

Writing（依格式瀏覽）
├── /articles — 長文
├── /build-logs — 開發紀錄
├── /til — 每日學習
├── /notes — 筆記片段
├── /essays — 個人想法/非技術
├── /bookmarks — 推薦資源 + 個人評語
└── /digests — 週報/月報

Projects (/projects)
├── /projects/:slug — Case Study 格式

About (/about)
├── 敘事式個人介紹
├── 技術觀點和價值觀
├── 連結到 Projects（用作品說話）
└── PDF 履歷下載（可選）

Uses (/uses)
└── 開發工具和環境

Admin (/admin)
├── Dashboard — 統計
├── Review Queue — 待審核內容
├── Content Editor — 內容編輯
├── Collected Data — 收集的外部資料
├── Tracking Config — 追蹤主題設定
└── Project Editor — 專案編輯
```

### 4.2 新增的內容類型

| 類型 | 說明 | 範例 |
|------|------|------|
| `essay` | 非技術性的個人想法、反思 | 「我對 AI 輔助開發的看法」 |
| `bookmark` | 推薦的外部資源 + Koopa 的一句評語 | 「這篇 distributed systems 文章值得讀，因為...」 |
| `digest` | 週報/月報，聚合一段時間的學習 | 「本週技術速覽」 |

### 4.3 Admin 新增功能

**Review Queue：**
- 待審核內容清單，按審核等級排序
- 一鍵核准 / 批次核准
- 內嵌編輯器，可直接修改後發佈
- 顯示 AI 生成的內容來源（哪些 Obsidian 筆記、哪個 prompt）

**Collected Data Dashboard：**
- 外部收集的資料瀏覽
- 按相關性分數排序
- 可以標記為已讀 / 轉為內容 / 忽略
- 顯示資料來源和 AI 摘要

**Tracking Config：**
- 管理追蹤主題和關鍵字
- 啟用/停用特定資料源
- 調整收集頻率

---

## 五、About 頁面重新設計

### 5.1 敘事式架構

不再列學經歷，改為：

```
Section 1: 開場 — 一段話介紹自己（不是 "我是 XXX 工程師"，而是 "我為什麼寫程式")
Section 2: 我關注的問題 — 你在意什麼技術問題、什麼驅動你學習
Section 3: 我的方法 — 你怎麼解決問題、你的技術品味
Section 4: 作品（連結到 Projects）— 不說技能，讓作品說話
Section 5: 聯絡方式 — 簡單的社群連結
可選: PDF 履歷下載按鈕（給需要正式履歷的人）
```

### 5.2 技術不是列表，是觀點

與其說「我會 Go」，不如說「我選 Go 是因為...」。
與其說「我會 Angular」，不如說「我用 Angular 建構了...」。

---

## 六、技術決策

### 6.1 為什麼用 Go 做 API 和 Pipeline

- Koopa 的主力後端語言
- Genkit 原生支援 Go
- 單一二進位部署，適合 VPS/container
- 高併發適合爬蟲和 webhook 處理

### 6.2 為什麼 Markdown 存原文

- Obsidian 原生格式
- 前端 render，後端只存原文
- 版本控制友善
- 可以支援多種輸出格式（HTML, RSS, PDF）

### 6.3 為什麼 Topic 架構

- 訪客按興趣瀏覽，不關心「這是 article 還是 TIL」
- 同一主題的不同格式內容可以互相連結
- Koopa 的知識自然是按主題組織的

---

## 七、執行階段

### Phase A: Go API 基礎 (Koopa 開發)
- 資料模型 + PostgreSQL migration
- 公開 API endpoints（Content, Topic, Project, Search）
- 管理 API endpoints（CRUD + Auth）
- 統一回應格式

### Phase B: Obsidian 整合 (Koopa 開發)
- Vault Watcher 服務
- Frontmatter 解析
- 同步 flow（publish/review/draft）
- Wiki-link 轉換

### Phase C: Angular 前端適配 (Claude Code)
- 從 mock 資料切換到 API
- Topic 主題式架構
- About 頁面重寫（敘事式）
- 移除 Resume 頁面（或改為 PDF 下載）

### Phase D: AI Pipeline (Koopa 開發)
- Genkit Flow 基礎架構
- external-data-collect flow
- content-generate flow
- Prompt 模板管理

### Phase E: Admin 擴充 (Claude Code)
- Review Queue UI
- Collected Data Dashboard
- Tracking Config 管理介面

### Phase F: 資料收集工具 (Koopa 開發)
- RSS 訂閱管理
- GitHub/HN/Reddit API 整合
- 相關性評分演算法
- 排程管理（cron）
- 通知機制

### Phase G: 進階功能 (共同)
- Weekly Digest 自動生成
- 內容之間的知識圖譜/關聯
- 搜尋優化（全文搜尋 + 語意搜尋）
- 訪客互動（如果需要）

---

## 八、設計原則

1. **Obsidian-first** — 所有內容的源頭是 Obsidian，網站是呈現層
2. **AI 輔助，人類把關** — AI 做繁重的整理工作，Koopa 保有最終控制權
3. **主題驅動** — 內容按主題組織，格式是次要的
4. **漸進式** — 先把核心跑起來（API + Obsidian 同步），再加 AI 和資料收集
5. **用作品說話** — 不列學經歷，讓網站本身和內容展示能力
6. **對自己有用** — 這首先是 Koopa 的知識管理工具，其次才是對外展示

---

## 九、目前前端已完成的功能

以下是 Angular 前端目前的狀態（使用 mock 資料）：

**已完成的頁面：**
- 首頁（Hero + Mixed Feed + Featured Projects + Tech Stack + Contact CTA）
- Articles 列表 + 詳情（含 Series 導覽 + Related Articles）
- Projects 列表 + 詳情（Case Study 格式：Problem/Solution/Architecture/Results）
- Build Log 列表 + 詳情
- TIL 列表 + 詳情
- Notes 列表 + 詳情（含分類 tab）
- About（待重寫為敘事式）
- Uses
- Resume（待移除或改為 PDF 下載）
- Error / 404 頁面
- Admin Dashboard + Article Editor + Project Editor

**已完成的基礎設施：**
- SSR (Angular SSR + Express)
- SEO（meta tags, JSON-LD, sitemap, RSS feed）
- 搜尋（跨內容類型）
- 動態 Sitemap / RSS
- Back to top, Table of Contents
- 響應式設計（深色主題）
- Tag 系統

**待做（等 API 完成後）：**
- 從 mock 資料切換到 API 呼叫
- Topic 主題式架構（新增 Topic model + 頁面）
- Review Queue UI
- Collected Data Dashboard
- About 頁面重寫
- 新增 essay, bookmark, digest 內容類型頁面
- 移除 Resume 或改為簡單 PDF 下載
