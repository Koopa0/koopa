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

**koopa0.dev** 是一個個人作業系統，多個 AI 角色共享同一套顯式建模的語意運行時 — 目標、專案、任務、學習狀態、內容、決策 — 並透過正式協議協調，幫助一個人追蹤目標、管理工作、刻意學習、產出內容、做出更好的決策。

它不是部落格。它不是待辦事項 app。它不是套了資料庫的 LLM wrapper。它是一個知識引擎，**AI 之所以理解你的工作，是因為工作被結構化地建模了**，而不是因為你在 prompt 裡描述得夠好。

<p align="center">
  <img src="docs/images/architecture.svg" width="720" alt="系統架構"/>
</p>

## 為什麼要做這個

大多數 AI 整合遵循無狀態模式：每次對話從零開始。AI 對你正在做什麼、學了什麼、承諾了什麼、延遲了什麼，沒有結構化的理解。它只能依賴你當下告訴它的東西。

koopa0.dev 採取不同的路線。系統維護一套你整個運作上下文的顯式語意模型 — 你的目標和里程碑、專案和任務、學習 session 和認知觀察、內容管道和審核狀態、每日承諾和它們的結局。每個 AI 角色都透過 MCP 讀取和寫入這個共享模型。當 Learning Studio 開始一個 session，它已經知道你在哪些概念上掙扎過、哪些項目到了間隔複習的時間、你正在執行哪個學習計畫。當 HQ 組裝你的晨間 briefing，它看到的是昨天未解決的 daily plan、待處理的 directives、目標進度 — 不是因為你總結了它們，而是因為狀態就在那裡。

這就是這個系統與「有記憶的聊天機器人」的差別。AI 不是「記得你上週提過一個專案」。它讀的是專案的當前狀態、連結的目標、未完成的任務、近期活動 — 全部來自結構化 schema。理解是精確的，不是重建的。

## 運作方式

角色模型是可擴展的 — 每個 participant 是一等公民，帶有宣告的 platform 和一組 capability flags 來定義它能做什麼（發出指令、接收任務、提交報告、撰寫日誌）。目前的運作配置使用五個角色，透過正式的 IPC（Inter-Participant Communication）協議協調：

**HQ** 是 CEO — 負責決策、分配工作、追蹤組織進度。**Content Studio** 掌管內容策略，從選題到寫作到品質把關。**Research Lab** 執行深度分析，產出結構化報告。**Learning Studio** 擔任認知教練，運用刻意練習原則引導技能發展。**Claude Code** 作為開發代理，直接在程式碼庫中實作功能和修復問題。

這些角色不只是被動回應指令。它們發出 **Directives**（帶優先級的指令，完整生命週期：issued → acknowledged → resolved）、提交 **Reports**（既可回覆指令，也可自發提報）、撰寫 **Journal**（計畫、上下文快照、反思、量化指標）、追蹤 **Insights**（帶有明確失效條件的假說）。

關鍵區分：**Directive** 不是 task。「研究 NATS exactly-once 語意並提交報告」是 HQ 對 Research Lab 的 directive — 它帶有優先級、需要被確認、由報告來解決。**Task** 是屬於某個專案的具體、可完成的工作單元。它們是不同的實體，有不同的生命週期，因為它們代表的是本質上不同的東西。系統顯式地建模這個區分，所以 AI 角色永遠不會把一個調查請求和一個待辦事項搞混。

## 共享語意運行時

更深層的創新不是「多個 Claude 實例協作」。Multi-agent 設置很常見。真正重要的是，每個角色都在同一套語意模型中運作，概念有精確、不重疊的定義：

**Goal vs. Project vs. Task。** Goal 是你想達成的結果（「Q3 前通過 CKA 考試」）。Project 是一個有交付物的有界努力，可能服務於某個 goal（「建立練習叢集並完成 50 題模擬考」）。Task 是 project 內部的原子工作單元（「用 Calico CNI 設定 kind cluster」）。這些不是可互換的標籤 — 它們有不同的 schema、不同的生命週期、不同的關係。當 AI 看到一個 task，它知道它屬於哪個 project、那個 project 服務於哪個 goal、goal 的 milestone 清單完成了多少。

**Directive vs. Task。** Directive 從 HQ 流向部門。Task 存在於 project 內。遠看它們很像，但語意不同：directive 需要確認並由報告解決；task 透過狀態機推進（clarify → start → complete → defer → drop）。混淆它們就是失去「調查這個」和「做這個」之間的區分。

**Attempt vs. Plan completion。** 在一個 session 中解了一道 LeetCode 題（一次 attempt）和在你的學習計畫中完成它，不是同一件事。Attempt 記錄的是認知上發生了什麼 — 你在哪裡卡住、哪些概念薄弱、花了多長時間。Plan completion 是一個獨立的生命週期事件，需要連結到具體的 attempt 作為審計軌跡。你可以嘗試一道題三次，才算在計畫中完成。系統同時建模兩者，所以 Learning Studio 可以區分「練習過但還不夠穩」和「已完成」。

**Journal vs. Insight。** Journal entry 是個人記錄 — 計畫、反思、上下文快照。Insight 是一個可追蹤的假說，帶有明確的失效條件。「我覺得我的模式辨識失敗來自於沒有先讀約束條件」是一個 insight — 它從 unverified 開始，隨時間可以被驗證或推翻。它們是不同的東西，系統用不同方式對待。

這種顯式性讓 AI 能做的不只是聊天。當語意模型是精確的，AI 就能推理你的狀態，而不是猜測。

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

koopa0.dev 將兩個經典生產力框架融合為統一系統。PARA 提供結構層級 — **Areas**（持續性的責任領域，如「Backend」或「Learning」）、**Goals**（有明確成果和可選截止日的目標）、**Milestones**（目標內的二元檢查點 — 目標進度 = 已完成里程碑 / 總里程碑）、**Projects**（有交付物的短期努力）。GTD 提供執行流程 — **Capture**（零摩擦收件匣）、**Clarify**（升級為可執行的 todo）、**Organize**（歸屬專案、連結目標）、**Reflect**（晨間 briefing、週回顧）、**Engage**（每日計畫承諾）。

**Daily Plan** 值得特別說明。每個計畫項目記錄誰選的、為什麼選、在優先序中的位置。沒有自動延遞 — 昨天未完成的工作會在晨間 briefing 中浮現，但你必須主動決定延遞或放棄每一項。

為什麼這很重要：自動延遞很方便，但它默默侵蝕你跟自己承諾的關係。當未完成的項目自動滾到下一天，你會停止注意它們。你失去了「我一直在過度承諾」或「這個任務一直被延遲 — 也許它根本不該在清單上」這樣的信號。強迫每日清算不舒服，但它讓你的計畫保持誠實。系統的設計讓忽略昨天的殘留不是預設選項 — 面對它們才是。

### 學習引擎

系統中最深的模組，以認知科學研究為基礎（Dunlosky et al. 2013、Ericsson 的刻意練習、Bjork 的期望困難理論）。

<p align="center">
  <img src="docs/images/learning-engine.svg" width="720" alt="學習引擎"/>
</p>

**概念本體**將知識組織為按領域（LeetCode、日語、系統設計）和類型（pattern、skill、principle）分類的層級樹。**學習項目** — 個別問題、文法點或章節 — 獨立於筆記存在，並形成自己的關係圖譜（easier/harder variant、prerequisite、follow-up）。

核心記錄模型有三層。**Session** 是一段有宣告模式的計時學習區塊（retrieval、practice、mixed、review、reading）。在 session 中，每個 **Attempt** 記錄對一個項目的一次嘗試 — 結果（獨立解決、需要提示、放棄）、耗時、卡住的地方、使用的方法。每次嘗試產生 **Observations** — 連結到具體概念的微觀認知信號。

觀察分為 **weakness**（含嚴重程度：minor/moderate/critical）、**improvement** 或 **mastery**。追蹤八種認知弱點類型：模式辨識失敗、約束分析不足、方法選擇混淆、狀態轉換混淆、邊界情況盲點、實作落差、複雜度誤算、迴圈條件不穩定。

觀察進入信心閘門管道。高信心信號 — 由行為直接證明的，如「嘗試了 20 分鐘仍無法辨識模式」 — 自動記錄。低信心信號 — AI 推斷的，如「根據錯誤類型，可能有狀態轉換弱點」 — 需使用者確認後才進入分析數據。

為什麼這個閘門重要：沒有它，AI 推斷的觀察會累積噪音。久而久之，概念掌握地圖會反映 AI 猜測的東西，而不是實際發生的事。信心閘門保持分析基礎的乾淨，所以當 Learning Studio 說「你的 sliding window 模式辨識已退化 — 這裡有三個項目需要複習」，這個判斷是基於已驗證的信號，不是猜測。

基於 FSRS 的間隔重複引擎為內容（文章回憶）和學習項目（題目保持）排程複習，由四級評分（Again / Hard / Good / Easy）驅動。

### 智慧 RSS 訂閱

Feed 管理支援排程、優先級和過濾規則。抓取管道使用 HTTP ETag 和 Last-Modified 標頭提升效率，連續失敗自動停用。AI 相關性評分器根據關鍵字權重計算每篇文章的分數。策展工作流將項目從 unread → read → curated（升級為書籤或文章）或 ignored。Topic Monitor 主動監控符合關注主題的新內容。

### 內容管理與發佈

七種內容類型各有用途：Article（深度技術文章）、Essay（觀點隨筆）、Build Log（開發記錄）、TIL（每日學習）、Note（技術筆記）、Bookmark（推薦資源附評語）、Digest（週報精選彙整）。內容在生命週期中流轉（draft → review → published → archived），搭配從自動發佈到嚴格人工審核的 AI 審核分級。

## MCP 工具設計

koopa0.dev 透過 MCP 暴露 23 個以工作流為導向的工具，組織為五層。

這些工具背後的設計原則是：MCP 應該暴露**語意操作**，而不是資料庫存取。CRUD 風格的 MCP 會給 AI `create_task`、`update_goal`、`insert_observation` 這樣的工具。這在機械上可以運作，但它迫使 AI 理解系統的不變量 — 哪些狀態轉換是合法的、什麼時候需要 proposal、成熟度評估如何運作。每個 AI 角色都得重新實作相同的業務邏輯，而錯誤會破壞資料模型。

相反，koopa0.dev 的工具封裝完整的工作流步驟。`advance_work` 知道 task 的合法狀態轉換並強制執行。`propose_commitment` 知道 goals、projects 和 directives 在建立前需要人類確認。`record_attempt` 知道如何提取觀察並套用信心閘門。智慧在工具裡，不在 prompt 裡。

**Context Suppliers** 提供情境感知 — `morning_context` 在一次呼叫中組裝開始新一天所需的所有上下文；`learning_dashboard` 呈現弱點趨勢、掌握程度和複習排程；`search_knowledge` 提供跨所有內容類型的統一搜尋。

**Commitment Gateway** 實施兩步承諾模式。`propose_commitment` 讓 AI 起草目標、專案、里程碑、指令、洞察或學習計畫 — 但永遠不直接建立。只有使用者確認後，`commit_proposal` 才會持久化實體。

這很重要，因為承諾會塑造行為。如果 AI 可以靜默地建立目標或發出指令，系統會逐漸充滿使用者沒有有意識選擇的實體。Proposal-first 確保系統中的每個目標都是你真正決定要追求的、每個指令都是你真正發出的、每個學習計畫都是你真正承諾的。系統保護你對自己議程的擁有權。

一個相關的機制是**語意成熟度評估**。在提案任何實體之前，系統以四級量表評估輸入的成熟度：M0（模糊 —「我想把英文變強」）、M1（成形 —「我想提升閱讀理解」）、M2（結構化 —「我想每天讀一篇 NHK 文章並追蹤生字」）、M3（可執行 — 可以建立帶里程碑的目標了）。在 M0，AI 會留在對話中幫你具體化想法，而不是建立一個半成品實體來污染系統。目標不是捕捉所有東西 — 而是捕捉準備好被捕捉的東西。

**Lifecycle Transitions** 管理狀態機 — `advance_work` 推動任務經過 clarify/start/complete/defer/drop；`plan_day` 建構每日承諾；`manage_plan` 處理學習計畫操作。

**Direct Recording** 以最低摩擦捕獲低風險資料 — `capture_inbox` 捕捉念頭、`write_journal` 記錄反思、`start_session` / `record_attempt` / `end_session` 驅動學習記錄管道。

**Content Management** 處理發佈工作流 — `manage_content` 管理完整內容生命週期、`manage_feeds` 管理 RSS 訂閱操作。

## 設計哲學

### AI 透過結構理解你，不是透過 prompt

AI 個人化的傳統路線是 context window 和記憶 — 餵給 AI 足夠的對話歷史，它就會「認識」你。koopa0.dev 採取根本不同的立場：AI 理解你的工作、學習和優先事項，是因為這些東西**被顯式地建模在語意 schema 中**。AI 不是從零散的聊天訊息推斷你正在準備 Kubernetes 認證。它讀的是一個帶里程碑、連結專案、追蹤進度的目標實體。理解是結構性的、可查詢的、在所有角色間共享的。

這就是讓系統成為多個 AI 代理穩定運作上下文的原因。任何 Claude 實例 — 無論是做晨間 briefing 的 HQ、執行練習 session 的 Learning Studio、還是規劃下週文章的 Content Studio — 讀的都是同一套結構化狀態。角色之間沒有漂移，沒有「我記得你好像提到過…」— 只有模型。

### 系統保護你的擁有權

koopa0.dev 不是在嘗試自動化你的判斷。它是在給你更好的工具來行使判斷。所有圍繞摩擦的設計決策 — proposal-first 承諾、信心閘門觀察、無自動延遞、成熟度評估 — 都是為了讓你維持決策者的角色，而不是淪為 AI 建議的被動批准者。

底層信念：一個替你做決定的系統，最終會讓你在做決定這件事上變得更差。一個呈現結構化資訊然後等你下決定的系統，會讓你隨時間變得更好，因為你一直在對真實數據練習判斷。

### 工作流語意優於原始存取

MCP 層暴露的是 `morning_context` 和 `advance_work` 這樣的操作，不是 `SELECT * FROM tasks`。每個工具封裝工作流中一個有意義的步驟 — 合法轉換、必填欄位、副作用、不變量檢查 — 讓 AI 角色與系統的語意互動，而不是與儲存互動。這保持資料模型的一致性，不論哪個角色在行動，也意味著系統的規則在一個地方執行，而不是分散在 prompt 指示中。

## 這啟用了什麼

幾件當 AI 在共享語意運行時中運作而非在聊天視窗中才能做到的事：

**知道發生了什麼的晨間 briefing。** HQ 不會問你昨天做了什麼。它讀昨天的 daily plan，檢查哪些項目完成了、延遲了、或放棄了，浮現待處理的 directives，展示目標對里程碑的進度。Briefing 從狀態生成，不是從你的回憶。

**基於證據的學習教練。** Learning Studio 不會泛泛地建議「多練 sliding window 的題」。它看到你最近三次 sliding window 項目的嘗試產生了中等嚴重程度的模式辨識失敗觀察，你對這個概念的掌握分數在兩週內下降了，有兩個項目的間隔複習已過期。教練建議是具體的，因為證據是具體的。

**由知識缺口驅動的內容策略。** Content Studio 可以交叉比對你的學習觀察和已發佈的文章，找出你已經建立深度但還沒寫過的主題 — 或者你持續遇到弱點、一篇深度文章可能幫助鞏固的主題。

**誠實的週回顧。** 系統不只展示你完成了什麼，還展示你一直在延遲什麼、哪些目標停滯了、哪些學習計畫變成不活躍、哪些洞察仍未驗證。這不是 AI 的判斷 — 這是結構化數據清楚地呈現，讓你自己判斷。

## 技術

| 層       | 選擇                                         |
| -------- | -------------------------------------------- |
| 後端     | Go（stdlib-first）、PostgreSQL、pgx/v5、sqlc |
| AI 管道  | Genkit（Go）、pgvector                       |
| 前端     | Angular（SSR）、Tailwind CSS                 |
| AI 協作  | Claude（Cowork + Code）、MCP                 |
| 間隔重複 | FSRS 演算法                                  |
| 搜尋     | 全文（tsvector）+ 語意（pgvector 768d）      |

## 授權

本 repository 包含個人內容與基礎設施。保留所有權利。
