<p align="center">
  <img src="frontend/public/logo-title.png" alt="koopa0.dev" width="320">
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>繁體中文</strong>
</p>

<p align="center">
  <p align="center">
    <img src="https://img.shields.io/badge/Go-00ADD8?style=flat&logo=go&logoColor=white" alt="Go"/>
    <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
    <img src="https://img.shields.io/badge/Angular-DD0031?style=flat&logo=angular&logoColor=white" alt="Angular"/>
    <img src="https://img.shields.io/badge/MCP-Claude-7F77DD?style=flat" alt="MCP"/>
    <img src="https://img.shields.io/badge/pgvector-768d-378ADD?style=flat" alt="pgvector"/>
    <img src="https://img.shields.io/badge/FSRS-spaced_repetition-1D9E75?style=flat" alt="FSRS"/>
  </p>
</p>

一個用 Go 打造的後端系統，將 Notion、Obsidian 和 RSS 整合成統一平台 — AI 透過 23 個 MCP 工具作為系統的一級使用者。
這不是部落格平台，也不是又一個 PKM 應用程式。這是我每天實際在用的個人基礎設施 — 規劃任務、追蹤學習、收集與策展文章、發佈值得分享的內容。多個 AI 環境（Claude Web、Claude Code、Cowork）連接到同一個 Go server 和 PostgreSQL，透過結構化的 artifact 協調運作，而不是每次對話都從零開始。

---

**koopa0.dev** 是一個個人作業系統，在這裡 AI 不是附加功能 — 它是原生公民。多個 Claude 實例在同一個知識系統中協作，各自擁有明確的角色定義、能力邊界和正式的通訊協議，共同幫助使用者追蹤目標、管理任務、指導學習、產出內容、做出決策。

它不是部落格。它不是待辦事項 app。它是一個**可輸入、可處理、可輸出的知識系統**，AI 貫穿在每一層。

<p align="center">
  <img src="docs/images/architecture.svg" width="720" alt="系統架構"/>
</p>

## 運作方式

傳統的 AI 整合遵循「請求—回應」模式：你問，AI 答。koopa0.dev 翻轉了這個關係。五個 AI 角色在同一個知識系統中運作，透過正式的 IPC（Inter-Participant Communication）協議進行協調。

**HQ** 是 CEO — 負責決策、分配工作、追蹤組織進度。**Content Studio** 掌管內容策略，從選題到寫作到品質把關。**Research Lab** 執行深度分析，產出結構化報告。**Learning Studio** 擔任認知教練，運用刻意練習原則引導技能發展。**Claude Code** 作為開發代理，直接在程式碼庫中實作功能和修復問題。

這些角色不只是被動回應指令。它們發出 **Directives**（帶優先級的指令，完整生命週期：issued → acknowledged → resolved）、提交 **Reports**（既可回覆指令，也可自發提報）、撰寫 **Journal**（計畫、上下文快照、反思、量化指標）、追蹤 **Insights**（帶有明確失效條件的假說）。每次互動都遵循協議 — 這不是角色扮演，而是一個有能力約束的組織架構。

## 知識生命週期

koopa0.dev 中的一切都流經三個階段：輸入、處理、輸出。

<p align="center">
  <img src="docs/images/data-flow.svg" width="720" alt="知識生命週期"/>
</p>

**輸入**從多個來源捕獲知識。Obsidian 知識庫同步筆記、LeetCode 解題和閱讀註記。RSS 訂閱按排程抓取，使用 HTTP ETag 優化。Notion 同步專案和目標。GitHub Webhook 呈現開發活動。而每個 Claude 角色都透過 MCP 貢獻任務、觀察和決策。

**處理**是原始輸入變成結構化知識的地方。Genkit 驅動的 AI 管道負責分類、摘要和評分。標籤正規化引擎將 raw tags 經過 alias 解析為正規分類。pgvector embedding（768 維）與 PostgreSQL 全文搜尋共同驅動雙引擎語意搜尋。由 wikilink 構成的知識圖譜則映射筆記之間的關係。

**輸出**有多種形式。公開的 Angular SSR 網站呈現文章、Build Log、TIL 和專案作品集。私有的 Admin 工作空間提供每日計畫、任務管理、目標追蹤、學習分析、內容審核和 RSS 策展的儀表板。每一份知識也都可以被任何 AI 角色透過 MCP 查詢 — 系統自我回饋。

## 功能

### PARA + GTD 任務與目標管理

koopa0.dev 將兩個經典生產力框架融合為統一系統。PARA 提供結構層級 — **Areas**（持續性的責任領域）、**Goals**（有明確成果和可選截止日的目標）、**Milestones**（目標內的二元檢查點）、**Projects**（有交付物的短期努力）。GTD 提供執行流程 — **Capture**（零摩擦收件匣）、**Clarify**（升級為可執行的 todo）、**Organize**（歸屬專案、連結目標）、**Reflect**（晨間 briefing、週回顧）、**Engage**（每日計畫承諾）。

**Daily Plan** 不是簡單的待辦清單。每個計畫項目記錄誰選的、為什麼選、在優先序中的位置。沒有自動延遞 — 昨天未完成的工作會在晨間 briefing 中浮現，但你必須主動決定延遞或放棄每一項。強迫你面對未完成的工作是一個功能，不是 bug。

### 學習引擎

系統中最深的模組，以認知科學研究為基礎（Dunlosky et al. 2013、Ericsson 的刻意練習、Bjork 的期望困難理論）。

<p align="center">
  <img src="docs/images/learning-engine.svg" width="720" alt="學習引擎"/>
</p>

**概念本體**將知識組織為按領域（LeetCode、日語、系統設計）和類型（pattern、skill、principle）分類的層級樹。**學習項目** — 個別問題、文法點或章節 — 獨立於筆記存在，並形成自己的關係圖譜（easier/harder variant、prerequisite、follow-up）。

核心記錄模型有三層。**Session** 是一段有宣告模式的計時學習區塊（retrieval、practice、mixed、review、reading）。在 session 中，每個 **Attempt** 記錄對一個項目的一次嘗試 — 結果（獨立解決、需要提示、放棄）、耗時、卡住的地方、使用的方法。每次嘗試產生 **Observations** — 連結到具體概念的微觀認知信號。觀察分為 weakness（含嚴重程度：minor/moderate/critical）、improvement 或 mastery。

觀察進入信心閘門管道。高信心信號（由行為直接證明）自動記錄。低信心信號（AI 推斷）需使用者確認後才進入分析 — 保持數據乾淨。追蹤八種認知弱點類型：模式辨識失敗、約束分析不足、方法選擇混淆、狀態轉換混淆、邊界情況盲點、實作落差、複雜度誤算、迴圈條件不穩定。

基於 FSRS 的間隔重複引擎為內容（文章回憶）和學習項目（題目保持）排程複習，由四級評分（Again / Hard / Good / Easy）驅動。

### 智慧 RSS 訂閱

Feed 管理支援排程、優先級和過濾規則。抓取管道使用 HTTP ETag 和 Last-Modified 標頭提升效率，連續失敗自動停用。AI 相關性評分器根據關鍵字權重計算每篇文章的分數。策展工作流將項目從 unread → read → curated（升級為書籤或文章）或 ignored。Topic Monitor 主動監控符合關注主題的新內容。

### 內容管理與發佈

七種內容類型各有用途：Article（深度技術文章）、Essay（觀點隨筆）、Build Log（開發記錄）、TIL（每日學習）、Note（技術筆記）、Bookmark（推薦資源附評語）、Digest（週報精選彙整）。內容在生命週期中流轉（draft → review → published → archived），搭配從自動發佈到嚴格人工審核的 AI 審核分級。

## MCP 工具設計

koopa0.dev 透過 MCP 暴露 23 個以工作流為導向的工具，組織為五層。

**Context Suppliers** 提供情境感知 — `morning_context` 在一次呼叫中組裝開始新一天所需的所有上下文；`learning_dashboard` 呈現弱點趨勢、掌握程度和複習排程；`search_knowledge` 提供跨所有內容類型的統一搜尋。

**Commitment Gateway** 實施兩步承諾模式。`propose_commitment` 讓 AI 建議目標、專案、里程碑、指令、洞察或學習計畫 — 但永遠不直接建立。只有使用者確認後，`commit_proposal` 才會持久化實體。AI 不會替你許下承諾。

**Lifecycle Transitions** 管理狀態機 — `advance_work` 推動任務經過 clarify/start/complete/defer/drop；`plan_day` 建構每日承諾；`manage_plan` 處理學習計畫操作。

**Direct Recording** 以最低摩擦捕獲低風險資料 — `capture_inbox` 捕捉念頭、`write_journal` 記錄反思、`start_session` / `record_attempt` / `end_session` 驅動學習記錄管道。

**Content Management** 處理發佈工作流 — `manage_content` 管理完整內容生命週期、`manage_feeds` 管理 RSS 訂閱操作。

一個核心設計原則是**語意成熟度評估**。在建立任何實體之前，系統會以四級量表（M0 模糊 → M1 成形 → M2 結構化 → M3 可執行）評估輸入的成熟度。如果你說「我想把英文變強」（M0），AI 會留在對話中幫你具體化目標，而不是急著建立一個半成品實體。

## 設計哲學

**AI 是協作者，不是工具。** 系統的設計前提是 AI 角色是組織成員，有明確的職責定義，而不是黏在 CRUD app 上的聊天機器人。IPC 協議 — directives、reports、journals、insights — 存在的原因是協調需要結構。

**讓困難成為功能。** Daily Plan 沒有自動延遞。學習觀察有信心閘門。實體建立前有成熟度評估。這些摩擦點是刻意的 — 它們強迫你有意識地參與自己的知識系統，而不是被動地堆積。

**以工作流為導向，不是 CRUD。** MCP 介面暴露語意操作（`morning_context`、`propose_commitment`、`advance_work`）而非原始資料庫存取。每個工具封裝一個有意義的工作流步驟，而不是一個資料表操作。

## 技術選擇

| 層       | 選擇                                         |
| -------- | -------------------------------------------- |
| 後端     | Go（stdlib-first）、PostgreSQL、pgx/v5、sqlc |
| AI 管道  | Genkit（Go）、pgvector                       |
| 前端     | Angular（SSR）、Tailwind CSS                 |
| AI 協作  | Claude（Cowork + Code）、MCP                 |
| 間隔重複 | FSRS 演算法                                  |
| 搜尋     | 全文（tsvector）+ 語意（pgvector 768d）      |

---

## 授權

本 repository 包含個人內容與基礎設施。保留所有權利。
