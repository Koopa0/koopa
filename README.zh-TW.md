<p align="center">
  <img src="frontend/public/logo-title.png" alt="koopa" width="320">
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>繁體中文</strong>
</p>

<p align="center">
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26.1+-00ADD8?style=flat&logo=go&logoColor=white" alt="Go 1.26.1+"/></a>
  <a href="https://goreportcard.com/report/github.com/Koopa0/koopa"><img src="https://goreportcard.com/badge/github.com/Koopa0/koopa" alt="Go Report Card"/></a>
  <a href="https://github.com/Koopa0/koopa/actions/workflows/ci.yml"><img src="https://github.com/Koopa0/koopa/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Angular-DD0031?style=flat&logo=angular&logoColor=white" alt="Angular"/>
  <img src="https://img.shields.io/badge/MCP-Claude-7F77DD?style=flat" alt="MCP"/>
  <img src="https://img.shields.io/badge/pgvector-1536d-378ADD?style=flat" alt="pgvector"/>
  <img src="https://img.shields.io/badge/FSRS-spaced_repetition-1D9E75?style=flat" alt="FSRS"/>
</p>

**koopa** 是一個預設私有的個人作業系統，讓多個 AI agent 共享同一套語意運行時 — AI 讀取的是你的狀態，不是你的 prompt。

早上 8 點，Studio HQ 撰寫今天的 briefing，它讀的是昨天未完成的 daily plan、這週的目標進度、到期未複習的 learning target，還有夜裡 ingest pipeline 評分過的 RSS 重點。你還沒打一個字。下午 2 點，Content Studio 檢查內容管道 — 等待審核的 draft、沒有覆蓋的 topic、久未更新的文章 — 需要你注意時就提交一份報告。每個 agent 跑在各自的 cron 上，每個都產出可保存的 artifact，每一次寫入都歸屬到做事的 agent。你醒來、讀 briefing、決定要執行什麼、拒絕什麼。系統不替你決定。它給你結構，讓你決定得更快。

## 為什麼要做這個

大多數 AI 整合是無狀態的：每次對話從零開始、每個 agent 都是新鮮的失憶者、人類把時間花在重複解釋脈絡。你加的 agent 越多 — 編輯器裡的 Claude Code、scheduler 上的 Cowork agent、背景跑的 summarizer — 問題就越嚴重。每個 agent 產出別人看不到的東西，堆積出一堆沒人讀的斷裂報告。

koopa 採不同立場：**AI 理解你的工作，是因為工作被結構化地建模了**。目標、專案、todo、learning attempt、daily plan、content draft、認知觀察 — 全都是一等公民實體，有精確的 schema 和各自的 lifecycle。每個 agent 透過 MCP 讀寫同一份語意儲存。Learning Studio 開啟一次練習 session 時，它已經知道你上週在哪些 concept 上卡住、哪些 learning target 的間隔複習過期了、你在執行哪個 plan。HQ 組裝晨間 briefing 時，它讀昨天的 daily plan 並浮現未完成的項目 — 不是因為你總結了，而是因為狀態就在那裡。

這不是帶記憶的聊天機器人。AI 讀的是一個 goal 的 milestones、連結的 projects、近期 activity — 全部來自結構化 schema，所有 agent 共用。理解是精確的，不是重建的。

## 運作方式

五個運作角色透過正式的跨 agent 協議協調：

**HQ** 是 CEO — 決策、分派、晨間 briefing。**Content Studio** 主掌內容管道，從選題到發佈。**Research Lab** 做深度分析、產出結構化報告。**Learning Studio** 是認知教練，運用刻意練習原則。**Claude Code** 是開發 agent，直接在程式碼庫中實作功能、修 bug。

每個 agent 帶有一組 capability flag，server 透過 Go 編譯期 wrapper 檢查 — 如果 caller 沒有對應的 capability，你連呼叫 mutation method 的 code 都編不過。Capability 集合很小：`SubmitTasks`、`ReceiveTasks`、`PublishArtifacts`。HQ 可以提交 task 但不接收。Learning Studio 可以接收和發佈但不提交。Registry 是一個 Go literal，啟動時對資料庫做投影；新增 agent = 改 Go literal + 重啟。

三個結構性 invariant 讓系統的保證不是口號，是真的強制：

**完成必有產出。** 一個 task 不可能進 `completed` 卻沒有至少一個 response message **和**至少一個 artifact — 由資料庫 trigger 強制，不是慣例。task 一旦 completed，artifact 必定存在。

**發佈是 atomic 的。** 內容不可能意外洩漏到公開面 — `status='published'`、`is_public=true`、`published_at=now()` 在同一個操作裡設定，由 joint CHECK 保護。

**每一次 mutation 都有 actor。** 每一次對被覆蓋實體的寫入都透過 AFTER trigger 產生一筆 `activity_events`，帶著造成這個寫入的 agent 名稱。應用層程式碼無法直接 insert 這張表 — audit log 是結構性的，不是自律性的。

### 自主運行 + 一道 gate

Agent 在各自的 scheduler 上跑 — HQ 早 8 點、Content Studio 下午 2 點、Research Lab 做產業掃描。它們可以提議目標、建議專案、互相提交 task。但**它們不能直接建立高承諾實體**。Goal、project、milestone、hypothesis、learning plan、directive — 全部走兩步式的 `propose_commitment` → `commit_proposal`，帶簽名 token。Agent 起草；你確認。你議程的所有權留在你身上。

底層的設計選擇：AI 能自主運行，**正是因為**有這道 proposal gate。沒有這道 gate，自主運行只會讓你的系統淹沒在你從沒決定要承諾的實體裡。有了 gate，自主運行才有用 — agent 浮現選項，你保留決策權。

## 共享語意運行時

系統建模四個 bounded context。每一個都有自己的詞彙、自己的 lifecycle、與其他三個不重疊的精確定義：

**Commitment** — PARA + GTD。Area（持續性責任領域）、goal（帶可選 deadline 的結果）、milestone（二元進度檢查點）、project（執行載具）、todo（個人 GTD 項目）、daily plan item（今天的承諾）。Daily plan **沒有 auto-carryover**：昨天未完成的工作會在晨間 briefing 中浮現，但不會自動滾到今天。面對未完成是 feature — auto-carryover 會默默侵蝕你跟自己承諾的關係。

**Knowledge** — 五種第一方內容類型（`article`、`essay`、`build-log`、`til`、`digest`）走 editorial lifecycle（`draft → review → published → archived`）；Zettelkasten note 在獨立表，帶六種 sub-kind（`solve-note`、`concept-note`、`debug-postmortem`、`decision-log`、`reading-note`、`musing`）和 maturity lifecycle（`seed → stub → evergreen → needs_revision → archived`）；bookmark 是外部 URL 加個人評語；RSS feed 帶排程抓取，連續失敗自動停用。

**Learning** — concept ontology、learning target（個別題目 / 章節 / 練習）、帶宣告模式的 session、帶結果分類的 attempt、帶 confidence label 的 observation、帶排序 entry 的 learning plan。系統最深的一塊，以刻意練習和間隔重複研究為基礎（FSRS 演算法排程複習、Ericsson 的 attempt 結構、Bjork 的 desirable difficulty）。

**Coordination** — agent、task、task message、artifact、agent note。Task lifecycle 是 `submitted → working → completed | canceled`，加一個 revision cycle。`agent_notes` 是自述的 narrative（計畫、脈絡快照、反思）— **不是 agent 之間的訊息通道**。Research Lab 要跟 HQ 溝通推理，走 `task_message`，不是 note。

詞彙切分是承重的。`task` 是跨 agent 工作；`todo` 是個人 GTD。`agent_note` 是私人 memory；`note` 是 Zettelkasten 知識物件。混淆它們會破壞系統的保證。

## 知識檢索

每一份知識都可以被任何 agent 透過 MCP 查詢。`search_knowledge` 跑**混合檢索** — PostgreSQL 全文搜尋（tsvector 配 websearch 語法，GIN 索引）**加**pgvector 語意搜尋（1536 維 `gemini-embedding-2-preview`，Matryoshka 截斷，HNSW 索引）— 用 reciprocal rank fusion 合併結果。Agent 同時找得到關鍵字匹配的內容和語意匹配的內容，不需要先選策略。

Agent note 可按 kind、作者、日期範圍，以及全文查詢。跨 session 的脈絡是可回收的：「找我上個月寫關於 embedding pipeline 的 note」是一次 tool call，不是翻 log。

## 設計哲學

**AI 透過結構理解你，不是透過 prompt。** Context window 和 memory file 是 AI 個人化的傳統路線。koopa 採相反立場：AI 理解你的工作是因為工作被顯式地建模在語意 schema 裡，每個 agent 讀的方式都一樣。代理之間沒有漂移、沒有「我好像記得你提過⋯」— 只有模型。

**你的擁有權是設計保住的。** Proposal-first commitment、confidence-labeled observation、無 auto-carryover、實體建立前的成熟度評估 — 每一個摩擦選擇都是為了讓你維持決策者的角色，不是讓你淪為 AI 建議的被動批准者。一個替你做決定的系統，最終會讓你做決定變差。一個呈現結構化資訊然後等你下決定的系統，會讓你隨時間變得更好。

**工作流語意，不是原始資料庫存取。** MCP tool 暴露的是 `morning_context`、`advance_work`、`record_attempt` 這類操作，不是 `SELECT * FROM todos`。每個 tool 封裝一個有意義的工作流步驟 — 合法轉換、必填欄位、不變量檢查。規則活在 tool 層，不是散落在各個 agent 的 prompt 指示裡。

## 這啟用了什麼

四個無狀態聊天機器人做不到的能力，兩邊各兩個：

**Agent 看到同一份狀態。** HQ 早 8 點寫 briefing 時讀到的 daily_plan、open todos、goal progress，跟 Content Studio 前一天下午 2 點讀到的是同一份。沒有「我剛剛跟另一個 agent 說了什麼」；只有 schema。

**Scheduler-driven agent 可組合。** Research Lab 夜裡的產業掃描寫一筆 `tasks` 帶著 artifact；Content Studio 隔天下午讀到，建議一個文章主題；HQ 在你的晨間 briefing 浮現這個建議。每個 agent 都在各自的 cron 上獨立跑 — 協調靠的是共享狀態，不是 message bus。

**基於昨天的晨間 briefing。** HQ 不會問你昨天做了什麼。它讀昨天的 daily plan、檢查哪些完成 / 延遲 / 放棄、浮現未完成的 todo、展示目標對 milestone 的進度。Briefing 從狀態生成，不是從你的回憶。

**基於證據的學習教練。** Learning Studio 不會泛泛地建議「多練習」。它看到你最近三次 sliding-window target 的 attempt 產生中等嚴重的 pattern-recognition 失敗、你對這個 concept 的掌握在兩週內下降、有兩個 target 的間隔複習過期。教練建議是具體的，因為證據是具體的 — 而且每一筆 observation 都帶 confidence label，控制它是否對主視圖有貢獻，還是只在 `confidence_filter=all` 下浮現。

## 範圍與邊界

這是設計上的單使用者系統。沒有 RBAC、沒有 multi-tenant、沒有「分享給同事」— 一個人，多個 AI agent。Admin UI 是私有的；公開網站只顯示一部分內容（article、build log、TIL、專案作品集），而且只有在人類明確發佈之後。Task、goal、attempt、agent note 永遠私有。如果你想要團隊 wiki 或 Notion clone，不是這個。

## 技術

| 層          | 選擇                                                       |
| ----------- | ---------------------------------------------------------- |
| 後端        | Go 1.26+（stdlib-first）、PostgreSQL 17、pgx/v5、sqlc      |
| Embedding   | `gemini-embedding-2-preview`（1536d Matryoshka）+ pgvector |
| 搜尋        | Hybrid（tsvector websearch + pgvector HNSW，RRF 合併）     |
| 前端        | Angular 21（SSR）、Tailwind CSS v4                         |
| AI 協作     | Claude（Cowork + Code）、MCP（30+ 個工作流工具）           |
| 間隔重複    | FSRS 演算法（關閉 short-term steps）                       |
| Cache       | Ristretto（in-memory，單機）                               |
| Object 儲存 | Cloudflare R2（S3 相容）                                   |

---

## 授權

本 repository 包含個人內容與基礎設施。保留所有權利。
