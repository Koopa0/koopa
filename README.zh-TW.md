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

> **狀態：私人作品集 / source-visible 參考 — 不是 open source。**
> 見 [LICENSE](LICENSE)：保留所有權利。本 repository 公開是為了作品集與參考閱讀，
> 不開放外部使用、fork 或貢獻。這是設計上的單管理員系統，不是社群專案。

**koopa** 是一個預設私有的個人作業系統，讓多個 AI agent 共享同一套語意運行時 — AI 讀取的是你的狀態，不是你的 prompt。

早上 8 點。你問今天怎麼安排。規劃者不會反問你手上有什麼 — 它讀昨天未完成的 daily plan、這週的目標進度、安靜下來的 project，還有夜裡 ingest pipeline 收集的 RSS 重點，然後遞給你一份 briefing。你掃過一遍，定下今天的 plan，開始動工。一整天裡 agent 各守本分：規劃者規劃當天、起草一份 goal 或 project 提案、任何 agent 都能搜尋語料庫，完成的文章被推進你的審核佇列 — 全都在跟你的對話裡。沒有任何高風險的事在你背後發生：每一個 goal、project、milestone、發佈的文章，都是**你**的決定，在 admin UI 裡做的。Agent 浮現結構；你下判斷。

## 為什麼存在

大多數 AI 整合是無狀態的：每次對話從零開始、每個 agent 都是新鮮的失憶者，你把時間花在重複解釋脈絡。你加的 agent 越多 — 編輯器裡的 Claude Code、scheduler 上的 Cowork agent、背景跑的 summarizer — 問題就越嚴重，因為每個 agent 產出的東西，別人從來看不到。

koopa 改成把工作本身建模。Area、goal、project、milestone、todo、daily plan、content、閱讀書架 — 全都是一等公民實體，有精確的 schema 和各自的 lifecycle，存在同一份儲存裡，每個 agent 都透過 MCP 讀取，並透過有界的工作流步驟寫入。規劃者組裝晨間 briefing 時，它讀昨天的 daily plan 並浮現未完成的項目 — 不是因為你總結了，而是因為狀態就在那裡。它提一個新 goal 時，草稿帶著排好的 milestone，惰性地落進你的 triage 佇列。理解是查詢出來的，不是重建出來的；agent 之間沒有漂移，也沒有「我好像記得你提過⋯」。

## 運作方式

actor 的軸線是**流程 vs. 決策**，不是人類 vs. agent：

- **Agent 驅動流程**，透過一組小巧的 MCP 工具，在跟你的對話裡完成。
- **你是唯一的決策者，_也是_唯一的 router。** 協調靠的是資料庫裡的共享狀態，不是 message bus — agent 透過 schema 讀到彼此造成的效果。
- **Admin UI 是你確認、決定、檢視的地方** — 它擁有每一次高承諾寫入。

實際的工作名冊（`internal/agent/registry.go::BuiltinAgents()`）：

| 身分 | 執行環境 | 角色 |
|---|---|---|
| `planner` | Claude Cowork | 晨間 briefing、候選日計畫、inbox capture、搜尋、PARA 提案 |
| `koopa0-dev` / `go-spec` | Claude Code | 這個 repo 的開發 session |
| `codex` | Codex CLI | 開發協作者 — repo 工作與 cross-review session |
| `hermes` | Claude Code（排程） | 按指派的 cron job 整理個人 Obsidian vault |
| `human` | — | Koopa：唯一的決策者、唯一的 router |

Cowork agent 跑在宣告好的節奏上 — 規劃者早 8 點，釘在 registry 裡 — 但執行由外部 runner 驅動，不是這個 repo 自己跑的；backend 持有的是 registry metadata、schema，以及記錄每次外部執行的 `process_runs` audit 表。

把守寫入的是**身分**。每一次 MCP call 都透過 `as` 欄位自我表明身分；server 對著 registry 解析它，套用三軸授權（`internal/mcp/authz.go`）：一個 **author** 白名單（人類永遠被允許）、**registration**（已知、非匿名的 caller），以及 **self**（你只能操作自己的 row）。未知的 caller 對每一個會 mutation 的工具都 fail closed。

兩個結構性 invariant 成立：

**發佈是 atomic 的。** `status='published'`、`is_public=true`、`published_at=now()` 在同一個操作裡、在一條 joint CHECK constraint 下設定，所以內容不會意外洩漏到公開面。

**每一次 mutation 都有 actor。** 每一次對被覆蓋實體的寫入，都透過 AFTER trigger 產生一筆 `activity_events`，帶著造成這個寫入的 agent 名稱。應用層程式碼無法直接 insert 這張表 — audit log 是結構性的，不是自律性的。

### 有閘門的自主

Agent 可以把一個 raw todo 丟進你的 inbox、起草一份惰性的 area / goal / project 提案、把完成的文章推進你的審核佇列、跑一次搜尋 — 都是有用、低風險的流程。啟用一個提案、建立 milestone、發佈內容 — **只能透過 admin UI**（已驗證的 HTTP）由你完成。Agent 在對話裡浮現選項並起草成惰性草稿；你 commit 它。

正是那道邊界讓自主變得有用：agent 能自己跑，**正是因為**承諾的表面是你的。沒有它，自主只會讓系統淹沒在你從沒決定要保留的實體裡。一個替你做決定的系統，最終會讓你做決定變差。

## 共享語意運行時

系統建模三個 bounded context，每一個都有自己的詞彙與 lifecycle：

**Commitment** — PARA + GTD。Area（持續性責任領域）、goal（帶可選 deadline 的結果）、milestone（二元進度檢查點）、project（執行載具）、todo（個人 GTD 項目）、daily plan item（今天的承諾）。Agent 把 area、goal、project 起草成**惰性提案**（`status=proposed`），只在你的 triage 佇列裡浮現；你逐項啟用或拒絕。Daily plan **沒有 auto-carryover**：昨天未完成的工作會在晨間 briefing 中浮現，但不會自動滾到今天。面對未完成是 feature — 默默 carryover 會侵蝕你跟自己承諾的關係。

**Knowledge** — 五種第一方內容類型（`article`、`essay`、`build-log`、`til`、`digest`）走 editorial lifecycle（`draft → review → published → archived`，外加 `review → changes_requested → review` 的改稿迴路）；一個閱讀書架（書 + 一份帶日期的反思 diary）和一個 ヨルシカ 歌曲書架（歌曲 + 反思）；RSS feed 帶排程抓取，連續失敗自動停用。內容在 admin UI 裡撰寫；agent 可用 `propose_content` 推進完成稿、用 `list_content` 看處置、用 `revise_content` 改被退回的稿 — 由你 publish 或帶修改原因退件。閱讀與歌曲書架在 MCP 上是唯讀的。

詞彙切分是承重的。一個 proposed 的 area / goal / project 在你啟用前完全惰性；已發佈的 `content` 有自己的 editorial lifecycle，只有 owner 能 publish。把草稿提案跟已啟用的 commitment 混為一談會破壞系統的保證。

## 知識檢索

任何 agent 都能透過 MCP 用 `search_knowledge` 查詢語料庫 — 已發佈的 content、閱讀書架、歌曲書架 — 背後是 hybrid 檢索：PostgreSQL 全文搜尋（tsvector 配 websearch 語法、GIN 索引）加上 pgvector 語意搜尋（HNSW、cosine），每個 corpus 各自以 reciprocal-rank fusion 融合。背景的 reconciler 會在新的 row 落地後自動產生 embedding（`gemini-embedding-2`），語意側保持最新而不碰任何 request path；沒有設定 `GEMINI_API_KEY` 時，搜尋以 FTS-only 運作。

## Agent 工具集

十六個 MCP 工具 — 刻意做得小。agent 能做的每一件事都是一個工作流步驟，帶合法轉換與不變量檢查，絕不是原始的 table 存取：

| 工具 | 它做什麼 |
|---|---|
| `brief` | 唯讀的規劃狀態拉取。`mode=morning` 是每日 briefing（逾期 / 今天 / 已承諾 / 即將到來的 todo、active goal、RSS 重點、內容管道）；`mode=reflection` 是一天結束時 plan-vs-actual 的回顧。 |
| `search_knowledge` | 跨 content、閱讀書架、歌曲書架的 hybrid 搜尋 — agent 通往語料庫的窗口。 |
| `list_readings` / `get_reading` | 唯讀地看閱讀書架 — 你在讀的書與反思 diary。 |
| `project_progress` | 唯讀的 PARA momentum / 停滯情報，對 project、goal、area 即時計算，只計入 owner 的活動。 |
| `review_period` | 唯讀的時間窗回顧 — 你在一段日期區間內完成了什麼（todo、milestone、目標推進、領域冷熱、發佈內容），只計入 owner 活動；週報 / 月報反思的原料。 |
| `capture_inbox` | 把一個 raw todo 丟進你的 GTD inbox；之後再由你釐清。 |
| `plan_day` | 把今天的 plan 設定為一次 atomic 的整體替換。沒有 auto-carryover。 |
| `propose_area` / `propose_goal` / `propose_project` | 起草一份惰性的 PARA 提案（`status=proposed`），讓你在 admin triage 啟用或拒絕。 |
| `list_tasks` / `resolve_task` | 讀回 agent 建立的 todo 的處置，並自清它已處理完的。 |
| `propose_content` | 把完成的內容推進 editorial 審核佇列（`status=review`）；由你 publish 或退回要求修改。 |
| `list_content` / `revise_content` | 讀回 agent 提的內容的處置 — 包含你退件時寫的修改原因 — 並把被退回的稿子改好、送回 review。 |

`brief`、`search_knowledge`、`list_readings`、`get_reading`、`list_tasks`、`list_content`、`project_progress`、`review_period` 是唯讀的；會 mutation 的工具各自封裝一個工作流步驟，帶必填欄位與合法轉換，所以規則活在 tool 層，不是散落在各個 agent 的 prompt 指示裡。

## 這帶來什麼

**Agent 看到同一份狀態。** 規劃者寫晨間 briefing 時讀到的 daily plan、open todo、goal progress，跟任何其他 agent 讀到的是同一份 — 沒有「我剛剛跟另一個 agent 說了什麼」，只有 schema。

**基於昨天的 briefing。** 規劃者讀昨天的 daily plan、檢查哪些完成 / 延遲 / 放棄、展示目標對 milestone 的進度 — 從狀態生成，不是從你的回憶。

**基於真實活動的 momentum。** `project_progress` 算出哪些 project、area 安靜了下來，只計入 owner 的活動 — agent 與 system 的寫入永遠不算進度 — 所以一個只有 agent 碰過的 project，在你親自動手之前仍顯示為停滯。

**一條被 audit 的軌跡。** 因為每一次 mutation 都寫一筆帶 actor 的 `activity_events`，整個系統有一份單一、結構性的歷史 — 誰在什麼時候改了什麼 — 沒有任何 agent 能退出。

## 範圍與限制

這是設計上的單管理員系統：沒有 RBAC、沒有 multi-tenant、沒有「分享給同事」— 一個人，多個 AI agent。Admin UI 是私有的；公開網站只顯示一部分內容（article、build log、TIL、專案作品集），而且只有在你明確發佈之後。Goal 與閱讀書架永遠私有。私人 Zettelkasten 知識活在 Obsidian；koopa0.dev 是發布層。如果你想要團隊 wiki 或 Notion clone，不是這個。

## 技術棧

| 層            | 選擇                                                                          |
| ------------- | ----------------------------------------------------------------------------- |
| 後端          | Go 1.26+（stdlib-first）、PostgreSQL 17、pgx/v5、sqlc                          |
| 搜尋          | Hybrid：PostgreSQL FTS（tsvector + websearch + GIN）+ pgvector 語意（HNSW、cosine），RRF 融合；未設 `GEMINI_API_KEY` 時 FTS-only |
| Embedding     | `gemini-embedding-2`（1536d Matryoshka）；背景 reconciler 維持搜尋語料庫的 embedding 最新 |
| 排程          | Agent 節奏在 `internal/agent/registry.go` 宣告；執行由外部 Cowork/Desktop runner 驅動；以 `process_runs` 留 audit |
| 前端          | Angular 22（SSR、zoneless、Signal Forms）、Tailwind CSS v4                     |
| AI 協作       | Claude（Cowork + Code）、Codex CLI、MCP（16 個工作流工具）                     |
| Cache         | Ristretto（in-memory，單機）                                                   |
| Object 儲存   | Cloudflare R2（S3 相容）                                                       |

---

## 授權

**保留所有權利（All Rights Reserved）** — 見 [LICENSE](LICENSE)。

本 repository 公開只為作品集與參考閱讀。未授予任何明示或默示的使用、複製、修改、合併、發佈、散佈、轉授權或販售本軟體 / 文件 / 任何部分的權利。在 GitHub 上瀏覽不構成任何權利授予。

這是設計上的單管理員系統，不是社群專案。目前沒有 CONTRIBUTING、SECURITY 或 issue 樣板流程，也不接受外部貢獻。如需特定使用授權，請與版權持有者聯絡。
