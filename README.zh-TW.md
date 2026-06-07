<p align="center">
  <img src="frontend/public/koopa.png" alt="koopa" width="320">
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>繁體中文</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-private%20portfolio-555?style=flat" alt="Status: private portfolio"/>
  <img src="https://img.shields.io/badge/license-All%20Rights%20Reserved-555?style=flat" alt="License: All Rights Reserved"/>
  <img src="https://img.shields.io/badge/Go-1.26.1+-00ADD8?style=flat&logo=go&logoColor=white" alt="Go 1.26.1+"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Angular-22-DD0031?style=flat&logo=angular&logoColor=white" alt="Angular 22"/>
  <img src="https://img.shields.io/badge/MCP-Claude-7F77DD?style=flat" alt="MCP"/>
  <img src="https://img.shields.io/badge/pgvector-1536d-378ADD?style=flat" alt="pgvector"/>
</p>

> **狀態：私人作品集 / source-visible 參考 — 目前還不是 open source。**
> 見 [LICENSE](LICENSE)：保留所有權利。本 repository 公開是為了作品集與參考閱讀，
> 目前**不開放**外部使用、fork 或貢獻。沒有 CONTRIBUTING / SECURITY / issue
> 流程 — 這是設計上的單管理員系統，不是社群專案。

**koopa** 是一個預設私有的個人作業系統，讓多個 AI agent 共享同一套語意運行時 — AI 讀取的是你的狀態，不是你的 prompt。

早上 8 點。你問 HQ 今天怎麼安排。它不會反問你手上有什麼 — 它讀昨天未完成的 daily plan、這週的目標進度、上幾次 session 標記為弱項的 learning target，還有夜裡 ingest pipeline 收集的 RSS 重點，然後遞給你一份 briefing。你掃過一遍，定下今天的 plan，開始動工。一整天裡 agent 各守本分：HQ 規劃、Learning Studio 教練一場練習 session、任何 agent 都能搜尋語料庫或跟你協作一篇 note — 全都在跟你的對話裡。沒有任何高風險的事在你背後發生：每一個 goal、project、milestone、發佈的文章，都是**你**的決定，在 admin UI 裡做的。Agent 浮現結構；你下判斷。

## 為什麼要做這個

大多數 AI 整合是無狀態的：每次對話從零開始、每個 agent 都是新鮮的失憶者、人類把時間花在重複解釋脈絡。你加的 agent 越多 — 編輯器裡的 Claude Code、scheduler 上的 Cowork agent、背景跑的 summarizer — 問題就越嚴重。每個 agent 產出的東西，別人從來看不到。

koopa 採不同立場：**AI 理解你的工作，是因為工作被結構化地建模了**。目標、專案、todo、learning attempt、daily plan、content draft、認知觀察 — 全都是一等公民實體，有精確的 schema 和各自的 lifecycle。每個 agent 透過 MCP 讀寫同一份語意儲存。Learning Studio 開啟一次練習 session 時，它已經知道你上週在哪些 concept 上卡住、你正在執行哪個 plan。HQ 組裝晨間 briefing 時，它讀昨天的 daily plan 並浮現未完成的項目 — 不是因為你總結了，而是因為狀態就在那裡。

這不是帶記憶的聊天機器人。AI 讀的是一個 goal 的 milestones、連結的 projects、近期 activity — 全部來自結構化 schema，所有 agent 共用。理解是精確的，不是重建的。

## 運作方式

actor 的軸線是**流程 vs. 決策**，不是人類 vs. agent：

- **Cowork agent 驅動流程**，透過一組小巧的 MCP 工具，在跟你的對話裡完成。
- **你是唯一的決策者，_也是_唯一的 router。** 沒有 agent→agent 的分派，也沒有 agent→agent 的狀態通道。協調靠的是資料庫裡的共享狀態，不是 message bus。
- **Admin UI 是你確認、決定、檢視的地方** — 它擁有每一次高承諾寫入。

功能上，這些 agent 是一個**規劃者**、一個**學習教練**、一扇**搜尋窗口**、一個**note 共同作者**。它們跑在宣告好的節奏上 — HQ 早 8 點、其他各按自己釘在 Go agent registry（`internal/agent/registry.go::BuiltinAgents()`）裡的 schedule — 但**執行由外部的 Cowork/Desktop runner 驅動，不是這個 repo 自己跑的**；backend 持有的是 registry metadata、schema，以及記錄每次外部執行的 `process_runs` audit 表。

把守寫入的是身分，不是 capability token。每一次 MCP call 都透過 `as` 欄位自我表明身分；server 對著 registry 解析它，套用三軸授權（`internal/mcp/authz.go`）：一個 **author** 白名單（人類永遠被允許）、**registration**（已知、非匿名的 caller），以及 **self**（你只能操作自己的 row）。未知的 caller 對每一個會 mutation 的工具都 fail closed。

兩個結構性 invariant 是真的，不是口號：

**發佈是 atomic 的。** 內容不可能意外洩漏到公開面 — `status='published'`、`is_public=true`、`published_at=now()` 在同一個操作裡設定，由 joint CHECK 保護。

**每一次 mutation 都有 actor。** 每一次對被覆蓋實體的寫入，都透過 AFTER trigger 產生一筆 `activity_events`，帶著造成這個寫入的 agent 名稱。應用層程式碼無法直接 insert 這張表 — audit log 是結構性的，不是自律性的。

### 自主運行 + 一道 gate

Agent 可以把一個 raw todo 丟進你的 inbox、起草一篇 note、跑一次搜尋、推薦下一個 learning target — 都是有用、低風險的流程。但**它們不能建立高承諾實體**。Goal、project、milestone、hypothesis、learning plan、learning domain，以及已發佈的內容，**只能透過 admin UI**（已驗證的 HTTP）由你建立。Agent 在對話裡浮現選項；你 commit 它。

底層的設計選擇：AI 能自主運行，**正是因為**承諾的表面是你的。沒有這道邊界，自主運行只會讓你的系統淹沒在你從沒決定要保留的實體裡。有了它，自主運行才有用 — agent 浮現選項，你保留決策權。一個替你做決定的系統，最終會讓你做決定變差。

## 共享語意運行時

系統建模三個 bounded context。每一個都有自己的詞彙、自己的 lifecycle、彼此不重疊的定義：

**Commitment** — PARA + GTD。Area（持續性責任領域）、goal（帶可選 deadline 的結果）、milestone（二元進度檢查點）、project（執行載具）、todo（個人 GTD 項目）、daily plan item（今天的承諾）。Daily plan **沒有 auto-carryover**：昨天未完成的工作會在晨間 briefing 中浮現，但不會自動滾到今天。面對未完成是 feature — auto-carryover 會默默侵蝕你跟自己承諾的關係。

**Knowledge** — 五種第一方內容類型（`article`、`essay`、`build-log`、`til`、`digest`）走 editorial lifecycle（`draft → review → published → archived`）；Zettelkasten note 在獨立表，帶六種 sub-kind（`solve-note`、`concept-note`、`debug-postmortem`、`decision-log`、`reading-note`、`musing`）和 maturity lifecycle（`seed → stub → evergreen → needs_revision → archived`）；RSS feed 帶排程抓取，連續失敗自動停用。內容在 admin UI 裡撰寫；agent 透過 MCP 協作 note。

**Learning** — concept ontology、learning target（個別題目 / 章節 / 練習）、帶宣告模式的 session、帶結果分類的 attempt、帶 confidence label 的 observation、帶排序 entry 的 learning plan。這是一個**以 concept 掌握度和弱項複習為核心的教練**，建立在刻意練習的基礎上（Ericsson 的 attempt 結構、Bjork 的 desirable difficulty）— **不是** Anki 那種間隔重複產品。沒有 due-queue、沒有複習排程器；訊號是從觀察到的 attempt 推導出的掌握度與弱項。

詞彙切分是承重的。一個 `note` 是 Zettelkasten 知識物件，是你私有的，有自己的 maturity lifecycle；它跟已發佈的 `content` 不是同一回事。混淆它們會破壞系統的保證。

## 知識檢索

已發布的 content 與 Zettelkasten note 可被任何 agent 透過 MCP 用 `search_knowledge` 查詢。**今天它跑的是 PostgreSQL 全文搜尋**（tsvector 配 websearch 語法、GIN 索引）覆蓋 content 與 note。pgvector schema、HNSW 索引、embedder package 都已就位，但 document embedding 的**寫入 / 回填管線**以及 **reciprocal rank fusion 合併路徑都還沒啟用**。完整 hybrid lexical + semantic + RRF 路徑屬於**規劃中**，等 embedder 寫入 / 回填管線落地後再啟用。

## Agent 工具集

十一個 MCP 工具 — 刻意做得小。agent 能做的每一件事都是一個工作流步驟，帶合法轉換與不變量檢查，絕不是原始的 table 存取：

| 工具 | 它做什麼 |
|---|---|
| `brief` | 唯讀的規劃狀態拉取。`mode=morning` 是晨間 briefing（逾期 / 今天 / 已承諾 / 即將到來的 todo、active goal、未驗證的 hypothesis、RSS 重點、內容管道）；`mode=reflection` 是一天結束時 plan-vs-actual 的回顧。 |
| `search_knowledge` | 跨 content 與 note 搜尋 — agent 通往「你知道什麼」的窗口。 |
| `capture_inbox` | 把一個 raw todo 丟進你的 GTD inbox；之後再由你釐清。 |
| `plan_day` | 把今天的 plan 設定為一次 atomic 的整體替換。沒有 auto-carryover。 |
| `start_session` / `record_attempt` / `end_session` | 學習 session lifecycle：開始、記錄 attempt + observation、以摘要結束。 |
| `learning_read` | 唯讀的學習分析（`view = overview \| next_target \| attempts \| session_progress`）。 |
| `manage_plan` | 學習 plan 課綱（`action = add_entries \| remove_entries \| update_entry \| reorder \| progress`）。 |
| `create_note` / `update_note` | 協作 Zettelkasten — 內文與連結。Maturity 由你在 admin UI 裡設定。 |

`brief` 與 `learning_read` 永遠唯讀；它們不會長出 mutation。其餘所有高承諾的事 — goal、project、milestone、hypothesis、plan 啟動、內容撰寫與發佈、note maturity、feed 維護 — 都活在 admin UI 裡，不在 agent 的表面上。

## 設計哲學

**AI 透過結構理解你，不是透過 prompt。** Context window 和 memory file 是 AI 個人化的傳統路線。koopa 採相反立場：AI 理解你的工作是因為工作被顯式地建模在語意 schema 裡，每個 agent 讀的方式都一樣。代理之間沒有漂移、沒有「我好像記得你提過⋯」— 只有模型。

**你的擁有權是設計保住的。** 只能在 admin UI 建立承諾、confidence-labeled observation、無 auto-carryover — 每一個摩擦選擇都是為了讓你維持決策者的角色，不是讓你淪為 AI 建議的被動批准者。一個呈現結構化資訊然後等你下決定的系統，會讓你隨時間變得更好。

**工作流語意，不是原始資料庫存取。** MCP tool 暴露的是 `brief`、`plan_day`、`record_attempt` 這類操作，不是 `SELECT * FROM todos`。每個 tool 封裝一個有意義的步驟 — 合法轉換、必填欄位、不變量檢查。規則活在 tool 層，不是散落在各個 agent 的 prompt 指示裡。

## 這啟用了什麼

**Agent 看到同一份狀態。** HQ 寫晨間 briefing 時讀到的 daily plan、open todo、goal progress，跟任何其他 agent 讀到的是同一份。沒有「我剛剛跟另一個 agent 說了什麼」；只有 schema。

**基於昨天的晨間 briefing。** HQ 不會問你昨天做了什麼。它讀昨天的 daily plan、檢查哪些完成 / 延遲 / 放棄、浮現未完成的 todo、展示目標對 milestone 的進度。Briefing 從狀態生成，不是從你的回憶。

**基於證據的學習教練。** Learning Studio 不會泛泛地建議「多練習」。它看到你最近三次 sliding-window target 的 attempt 產生中等嚴重的 pattern-recognition 失敗、你對這個 concept 的掌握在兩週內下降。教練建議是具體的，因為證據是具體的 — 而且每一筆 observation 都帶 confidence label，控制它是否對主視圖有貢獻，還是只在 `confidence_filter=all` 下浮現。

**一條被 audit 的軌跡。** 因為每一次 mutation 都寫一筆帶 actor 的 `activity_events`，整個系統有一份單一、結構性的歷史 — 誰在什麼時候改了什麼 — 沒有任何 agent 能退出。

## 範圍與邊界

這是設計上的單管理員系統。沒有 RBAC、沒有 multi-tenant、沒有「分享給同事」— 一個人，多個 AI agent。Admin UI 是私有的；公開網站只顯示一部分內容（article、build log、TIL、專案作品集），而且只有在你明確發佈之後。Goal、attempt、note 永遠私有。如果你想要團隊 wiki 或 Notion clone，不是這個。

## 技術

| 層            | 選擇                                                                                                                                          |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| 後端          | Go 1.26+（stdlib-first）、PostgreSQL 17、pgx/v5、sqlc                                                                                         |
| 搜尋（今天）  | PostgreSQL FTS（tsvector + websearch + GIN）                                                                                                  |
| 搜尋（規劃中）| Hybrid lexical + pgvector HNSW + RRF 合併 — schema、index、merge code 都已就位；待 embedder 寫入 / 回填管線                                   |
| Embedding     | 目標 `gemini-embedding-2-preview`（1536d Matryoshka）；pgvector 欄位與 HNSW 索引已就位；尚無 production 寫入路徑（見「搜尋」）                |
| 排程          | Agent 節奏在 `internal/agent/registry.go::BuiltinAgents()` 宣告；執行由外部 Cowork/Desktop runner 驅動；以 `process_runs` 留 audit          |
| 前端          | Angular 22（SSR、zoneless、Signal Forms）、Tailwind CSS v4                                                                                    |
| AI 協作       | Claude（Cowork + Code）、MCP（11 個工作流工具）                                                                                               |
| Cache         | Ristretto（in-memory，單機）                                                                                                                  |
| Object 儲存   | Cloudflare R2（S3 相容）                                                                                                                      |

---

## 授權

**保留所有權利（All Rights Reserved）** — 見 [LICENSE](LICENSE)。

本 repository 公開只為作品集與參考閱讀。未授予任何明示或默示的使用、複製、修改、合併、發佈、散佈、轉授權或販售本軟體 / 文件 / 任何部分的權利。在 GitHub 上瀏覽不構成任何權利授予。

這是設計上的單管理員系統，不是社群專案。目前沒有 CONTRIBUTING、SECURITY 或 issue 樣板流程，也不接受外部貢獻。如需特定使用授權，請與版權持有者聯絡。
