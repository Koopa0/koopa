<p align="center">
  <img src="frontend/public/logo-title.png" alt="koopa0.dev" width="320">
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>繁體中文</strong>
</p>

一個用 Go 打造的後端系統，將 Notion、Obsidian 和 RSS 整合成統一平台 — AI 透過 52 個 MCP 工具作為系統的一級使用者。

這不是部落格平台，也不是又一個 PKM 應用程式。這是我每天實際在用的個人基礎設施 — 規劃任務、追蹤學習、收集與策展文章、發佈值得分享的內容。多個 AI 環境（Claude Web、Claude Code、Cowork）連接到同一個 Go server 和 PostgreSQL，透過結構化的 artifact 協調運作，而不是每次對話都從零開始。

---

## 為什麼做這個

我每天要處理的東西很多 — 任務、學習目標、技術閱讀、Obsidian 筆記、要寫的文章。量一直在增長，我需要的是一個跟得上節奏的系統，而不只是一堆 app 的組合。

Notion 和 Obsidian 各自都很好用，我現在也還在用 — Notion 管任務和目標，Obsidian 寫技術筆記。但我想要的工作流程不存在於任何單一工具裡：跨所有來源的語義搜尋、AI 驅動的每日規劃循環、從 RSS 訂閱到策展書籤的自動化內容管線、能隨時間自我驗證的假說追蹤。資料散落在彼此無法溝通的工具之間，手動串接的方式無法擴展。

所以我建了底下那一層。一個 Go server 搭配 PostgreSQL，將這些工具作為資料來源整合，透過 Genkit 執行 13 個 AI flow，並開放 52 個 MCP 工具讓 AI 操作整個系統。Notion 雙向同步任務和目標。Obsidian 同步筆記並產生向量嵌入以支援語義搜尋。RSS 訂閱經過加權關鍵字相關性評分後浮出供審閱。所有資料匯入同一個資料庫，AI 幫忙驅動整個循環 — 規劃、執行、反思、調整。

這個架構帶來一個附帶效果：當多個 AI 環境連接到同一個後端，「每次 session 都從零開始」的問題自然消失了。Claude Web 規劃我的一天、Claude Code 接手任務、Cowork 執行內容管線 — 它們讀寫的是同一份資料。session 之間不會遺失任何上下文。

---

## 架構

系統由三個層級、四個 AI 消費者和三條資料流組成。

<p align="center">
  <img src="docs/images/architecture.svg" alt="Architecture" width="720">
</p>

### 三個層級

**Notion + Obsidian** 是輸入層 — 我原本就在用的工具，現在作為資料來源接入，而不是孤立的 silo。Notion 透過 webhook 和排程同步提供任務、目標和專案。Obsidian 透過 git push 和 GitHub webhook 提供技術筆記。兩者都沒有被取代，而是獲得了一個能做到它們單獨做不到的事情的後端。

**PostgreSQL** 是處理層 — 一個資料庫承載所有資料。透過 tsvector + GIN 實現全文搜尋，透過 pgvector + HNSW 實現語義搜尋，再用 Reciprocal Rank Fusion 合併結果。原始素材在這裡變得可查詢、可搜尋、可關聯。

**Go server + Angular 前端** 是輸出層 — 一個 MCP server 為 AI 環境開放 52 個工具（橫跨 10 個領域）、一條 Genkit 管線執行 13 個 AI flow、一個 Angular SSR 前端將成品發佈到網站。

### 四個 AI 消費者

每個都連接到同一個 MCP server，但透過 `sections` 參數拉取不同的資料子集：

| 消費者             | 角色                         | 典型工具                                                                        |
| ------------------ | ---------------------------- | ------------------------------------------------------------------------------- |
| Claude Web（日常） | 晨間規劃、晚間反思、週報     | `morning_context`、`save_session_note`、`my_day`                      |
| Claude Web（學習） | 學習 session、知識搜尋、閱讀 | `log_learning_session`、`retrieval_queue`、`search_knowledge`、`read_oreilly_chapter` |
| Claude Code        | 開發、build log、專案追蹤    | `project_context`、`log_dev_session`、`search_tasks`                        |
| Cowork             | 內容管線、RSS 管理、系統維運 | `create_content`、`publish_content`、`trigger_pipeline`                         |

### 三條資料流

<p align="center">
  <img src="docs/images/data-flow.svg" alt="Data Flow" width="720">
</p>

**Obsidian → 網站**：vault → git push → GitHub webhook → `notes` 表（原始素材）→ AI 標籤 + 嵌入 → 策展 → `contents` 表 → 發佈 → 網站。

**RSS → 網站**：訂閱源 → 排程抓取 → 加權關鍵字相關性評分 → `collected_data` 表 → 管理員審閱：策展（→ 書籤）/ 忽略 / 回饋（→ 改善評分）。每個 feed 有過濾設定（排除路徑、標題模式、標籤過濾）。

**Notion → 系統**：workspace → webhook / cron → 依角色分流：`task` → 任務表、`goal` → 目標表、`project` → 專案表。雙向同步 — 在前端完成任務，後端寫回 Notion。

---

## 核心概念

理解這六個概念，就理解了系統的 80%。

### Content — 成品

發佈到網站上的東西就是一筆 content 記錄。七種類型共用一張表和一個生命週期：`article`（深度技術文章）、`essay`（個人思考/非技術）、`build-log`（專案開發紀錄）、`til`（Today I Learned）、`note`（技術片段）、`bookmark`（策展的外部文章 + 評論）、`digest`（週報/月報）。

生命週期：**draft** → **review** → **published**。Content = 你願意署名並讓別人看到的東西。

### Notes — 兩種不同的東西

這是最容易搞混的地方。**Obsidian notes** 存在 `notes` 表 — 原始素材、僅管理員可見、數量可達數百到數千筆，攜帶向量嵌入供語義搜尋使用。**Content 類型的 `note`** 存在 `contents` 表 — 打磨過的技術片段、發佈到網站、可能只有幾十筆。關係：Obsidian note（原始）→ 判斷值得分享 → 打磨 → content（成品）→ 發佈。

### Topic & Tag — 知識組織

**Topic** 是高層級的知識領域（Go、System Design、AI）— 10-20 個，手動管理。**Tag** 是細粒度的標籤（pgvector、error-handling）— 從 Obsidian 筆記自動提取。Tag 有別名系統，將不同寫法對應到正規形式（`golang` → `go`、`JS` → `javascript`）。未知的原始 tag 會建立未映射的別名，等待管理員映射、確認或拒絕。

### Session Note — AI 的工作日誌

由 AI flow 自動生成，不是使用者手寫的，不公開。五種類型：`plan`（每日）、`reflection`（每週）、`context`（session 結束時）、`metrics`（定期資料快照）、`insight`（假說紀錄 — 見下方）。

### Insight — 假說追蹤

一種帶有「假說 → 驗證」結構的 session note。AI 發現模式後記錄下來，附帶可證偽條件，系統隨時間追蹤證據，直到假說被驗證、否定或歸檔。例如：「90% 的 relevance score < 0.3 的文章被忽略」→ 跨 session 收集證據 → 確認 → 調整閾值。

### Project — 你的工作

專案有獨立的表，帶有案例研究欄位（問題 / 方案 / 架構 / 成果）— 專案頁面讀起來像作品集，而不只是一份清單。專案連結到 content 記錄（build-log、article）和任務，從 Notion 同步或手動建立。

---

## MCP 設計

MCP（Model Context Protocol）是 AI 環境與系統互動的方式。52 個工具，橫跨 10 個領域。

### 十個領域

| 領域              | 工具數 | 用途                                                     |
| ----------------- | ------ | -------------------------------------------------------- |
| Daily Workflow    | 8      | 早晚 PDCA 循環：規劃、執行、反思、調整                  |
| Task Management   | 5      | 任務 CRUD、批次 My Day、Notion 雙向同步                  |
| Knowledge Search  | 5      | 跨源搜尋、主題合成、語義相似度                           |
| Content Pipeline  | 5      | 內容 CRUD、發佈、佇列、RSS 書籤                          |
| RSS / Feed Mgmt   | 6      | 訂閱 CRUD、收集統計、RSS 摘要                            |
| Project & Goal    | 5      | 專案上下文、目標進度、狀態更新                           |
| Learning Analytics| 10     | 開發/學習 session 記錄、標籤統計、涵蓋矩陣、弱點趨勢、mastery map、concept gaps、variation map |
| O'Reilly 整合     | 3      | 搜尋、書籍目錄、章節閱讀（條件啟用）                     |
| System & Infra    | 3      | 系統狀態、管線觸發、活動事件                             |
| Spaced Retrieval  | 2      | FSRS 間隔複習、到期佇列（條件啟用）                      |

完整工具參考（含參數和風險等級）：[`docs/MCP-TOOLS-REFERENCE.md`](docs/MCP-TOOLS-REFERENCE.md)

### 設計原則

| 原則                             | 意義                                                                             |
| -------------------------------- | -------------------------------------------------------------------------------- |
| 一個工具、一個動作、一個風險等級 | 不做多工器模式（`manage_X(action=...)`）。工具名稱就是意圖                       |
| 不做 AI 呼叫 AI                  | 如果消費者已經是 LLM，server 端就不再經過另一個 LLM                              |
| Schema 強制                      | Session note 有必填 metadata — insight 必須有假說 + 可證偽條件                   |
| 聚合檢視凍結在 4 個              | morning / reflection / delta / weekly 是便利包。新功能只加手術刀型工具           |
| 先收斂再擴展                     | 加工具之前問：「有幾個 session 因為缺這個工具而劣化？」 0 → backlog，3+ → 立即做 |
| 描述品質 > 工具數量              | 49 個描述清晰的工具勝過 25 個語意模糊的                                          |

### 組合範例

這些工具是積木 — 你可以組合成任何符合需求的工作流程：

- **早晨**：`morning_context` → 審閱 insight → 決定計劃 → `save_session_note(type=plan)` → `my_day`
- **開發中**：發現問題 → `create_task` + `save_session_note(type=context)`
- **傍晚**：`reflection_context` → 驗證假說 → `update_insight` → `save_session_note(type=metrics)`
- **學習**：`retrieval_queue` → 練習回憶 → `log_retrieval_attempt(rating)` → FSRS 自動排程下次複習
- **知識工作**：`search_knowledge`（四路並行：content 全文 + Obsidian 文字 + Obsidian 語義 + 去重，以 RRF 排序）→ `synthesize_topic` → `create_content`

### 關鍵技術細節

**搜尋是四路並行的**：content 全文搜尋 + Obsidian 文字搜尋 + Obsidian 語義搜尋（pgvector 嵌入）+ 去重。結果以 Reciprocal Rank Fusion 排序。

**`morning_context` 支援 `sections` 參數**：不同 AI 環境拉取不同的資料子集。Claude Code 只需要 tasks + plan + build_logs（約 1/4 的資料量），避免浪費 token。

**學習使用 FSRS 實現間隔複習**：複習一筆 TIL 時，系統記錄你的回憶品質（1–4），並依遺忘曲線模型計算下次複習日期。Card 在首次複習時自動建立，無需手動設定。佇列優先排出逾期的 card，再補上過去一週未複習過的 TIL。

**學習使用受控詞彙**：35+ 標準化標籤（two-pointers、sliding-window、dp...）+ 結果標籤（ac-independent、ac-with-hints...）+ 弱點標籤（weakness:xxx）。標準化防止查詢碎片化。

---

## AI 管線

13 個 Genkit flow，全部使用 Claude。每次執行都記錄在 `flow_runs` — 可監控、可重試。

**內容處理**：潤稿、自動標籤、摘要生成、文法檢查、品質評分、策略建議、書籤提取、build log 結構化。

**定期報告**：晨間簡報（每日計劃）、每日開發日誌、週報、digest 生成（週/月報）。

**專案追蹤**：分析近期活動、自動更新專案狀態。

---

## 技術棧

| 層級     | 技術                                            |
| -------- | ----------------------------------------------- |
| 後端     | Go 1.26+、net/http（stdlib routing）            |
| 資料庫   | PostgreSQL、pgx/v5、sqlc                        |
| 搜尋     | tsvector + GIN（全文）、pgvector + HNSW（語義） |
| AI 管線  | Genkit Go（13 flows）、Claude                   |
| 訊息佇列 | NATS（Core + JetStream）                        |
| 快取     | Ristretto（in-memory）                          |
| 前端     | Angular 21、Tailwind CSS v4、SSR                |
| 儲存     | Cloudflare R2                                   |
| 整合     | Notion API、GitHub Webhook、Obsidian vault      |
| 協議     | MCP（Model Context Protocol）                   |

---

## 授權

本 repository 包含個人內容與基礎設施。保留所有權利。
