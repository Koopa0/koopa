# koopa0.dev — README 撰寫簡報

> 本文件是提供給 Claude Web 的上下文簡報，目的是讓它理解 koopa0.dev 的設計思想、功能架構和產品定位，進而產出一份精美的 README（含 SVG 架構圖）。README 應該是產品介紹風格（類似 Google 開源專案的 README），著重功能價值，不涉及程式碼組織或實作細節。

---

## 一句話定義

**koopa0.dev 是一個 AI 協作式個人知識引擎** — 它讓 AI 助手（主要是 Claude）透過 MCP（Model Context Protocol）與你的知識系統深度互動，為你追蹤目標、管理任務、指導學習、產出內容、做決策。

它不是部落格。它不是 to-do app。它是一個**可輸入、可處理、可輸出的個人作業系統**，而 AI 是它的原生公民。

---

## 核心思想

### 1. AI 是協作者，不是工具

傳統的 AI 整合是「人問，AI 答」。koopa0.dev 的模型是**多個 AI 角色（participants）在一個共享系統中協作**：

- **HQ**（Studio 總部）：CEO 角色，負責決策、分配工作、追蹤進度
- **Content Studio**：內容策略師，負責選題、撰寫、品質把關
- **Research Lab**：研究分析師，負責深度研究和結構化報告
- **Learning Studio**：學習教練，運用認知科學指導刻意練習
- **Developer**（koopa0.dev）：開發代理，負責程式碼實作

每個角色都有明確的**能力邊界**（capability flags）：誰可以下指令、誰可以接收指令、誰可以寫報告、誰可以被分配任務。這不是角色扮演 — 這是一個有能力約束的組織架構。

### 2. IPC（Inter-Participant Communication）協議

角色之間透過正式的通訊協議互動：

- **Directives**（指令）：從 HQ → 部門。有優先級（P0/P1/P2），需要被確認（acknowledged），最終透過報告解決（resolved）。完整的三階段生命週期：`issued → acknowledged → resolved`。
- **Reports**（報告）：從部門 → HQ。可以是指令回覆，也可以是自發性報告。
- **Journal**（日誌）：自我記錄。四種類型：plan（計畫）、context（上下文快照）、reflection（反思）、metrics（量化指標）。
- **Insights**（洞察）：可追蹤的假說。每個洞察都有假說陳述和失效條件，狀態從 unverified → verified 或 invalidated。

### 3. 知識的生命週期：輸入 → 處理 → 輸出

**輸入層**：
- Obsidian 知識庫同步：筆記、LeetCode 解題、讀書筆記自動同步到系統
- RSS 訂閱管道：自動抓取、AI 評分相關性、表面化待策展項目
- 外部來源同步：Notion 專案/目標、GitHub 活動事件

**處理層**：
- AI Pipeline（Genkit）：自動分類、摘要、品質評分、審核分級
- 標籤正規化管道：raw_tags → tag_aliases → canonical tags
- 語意搜尋：pgvector 768d embedding + 全文搜尋雙引擎
- 知識圖譜：筆記之間的 wikilink 構成知識網絡

**輸出層**：
- 公開網站：Angular SSR，主題式內容呈現（技術文章、Build Log、TIL、書籤）
- 個人品牌展示：專案作品集、Case Study
- AI 可查詢的知識系統：任何 AI 角色都可以透過 MCP 搜尋和引用知識庫

---

## 功能架構

### 📋 PARA + GTD 任務與目標管理

koopa0.dev 將兩個經典生產力框架融合為一體：

**PARA（Projects, Areas, Resources, Archives）**：
- **Areas**（責任領域）：持續性的關注範圍（如 Backend、Learning、Studio）。沒有完成狀態 — 只有要維持的標準。
- **Goals**（目標）：有明確成果和可選截止日的規劃目標。可屬於某個 Area。
- **Milestones**（里程碑）：目標的二元進度檢查點（完成/未完成）。目標進度 = 已完成里程碑 / 總里程碑。
- **Projects**（專案）：有明確交付物的短期努力。可服務於某個 Goal，也可以是純粹的 Area 維護。

**GTD（Getting Things Done）五步驟**：
- **Capture**（捕捉）：任何想法透過 `capture_inbox` 零摩擦捕捉進 inbox
- **Clarify**（釐清）：inbox 任務經過釐清後，補上專案/截止日/優先級，升級為 todo
- **Organize**（組織）：任務歸屬到專案，連結到目標，標記能量等級和優先級
- **Reflect**（反思）：每日晨間 briefing 和晚間反思，Weekly Review 審視 someday 清單
- **Engage**（執行）：Daily Plan 承諾今天要做的事，追蹤 planned → done / deferred / dropped

**Daily Plan** 是每日執行的核心：
- 不是簡單的 to-do list — 每個計畫項目記錄誰選的、為什麼選、排序位置
- 沒有自動延遞 — 昨天沒完成的事會被呈現出來，但使用者必須主動決定延遞或放棄
- 這是刻意的設計：**強迫面對未完成的工作是一個功能，不是 bug**

### 🧠 Learning Engine（學習引擎）

這是系統最深的功能模組，基於認知科學研究設計：

**概念本體（Concept Ontology）**：
- **Concepts**：學習概念的分類樹。每個概念有 domain（如 leetcode、japanese、system-design）和 kind（pattern、skill、principle）
- 概念之間有層級關係（parent-child），支援從抽象到具體的組織
- 概念與標籤系統橋接但獨立 — 標籤做內容分類，概念做學習分析

**學習項目（Learning Items）**：
- 學習的目標對象（一道 LeetCode 題、一個文法點、一個章節）
- 獨立於筆記存在 — 題目存在先於你為它寫筆記
- 項目之間有關聯圖譜：easier/harder variant、prerequisite、follow-up、same-pattern

**學習計畫（Learning Plans）**：
- 有序的學習課程安排，連結計畫到學習項目
- 狀態生命週期：draft → active → completed / paused / abandoned
- 每個計畫項目追蹤完成狀態，且**必須連結到具體的嘗試記錄**作為完成的審計軌跡

**Session → Attempt → Observation 三層模型**：

1. **Session**（學習會話）：有明確開始和結束的學習時段。有模式（retrieval、practice、mixed、review、reading）。同一時間只能有一個進行中的 session。

2. **Attempt**（嘗試）：對一個學習項目的一次嘗試。記錄結果（solved_independent / solved_with_hint / solved_after_solution / completed / completed_with_support / incomplete / gave_up）、耗時、卡住的地方、使用的方法。一個項目可以有多次嘗試。

3. **Observation**（認知觀察）：每次嘗試產生的微觀認知信號。連結到具體的概念，分為三種信號：
   - **weakness**：這個概念出了問題（附嚴重程度：minor/moderate/critical）
   - **improvement**：相較過去有明顯進步
   - **mastery**：展示了獨立且流暢的應用能力

觀察有**信心等級**：高信心的（直接由行為證明）自動記錄；低信心的（AI 推斷）需要使用者確認後才記錄。

**弱點偵測框架**（8 種認知信號）：
- Pattern Recognition Failure — 看不出題目屬於哪個模式
- Constraint Analysis Weakness — 沒有先分析約束條件
- Approach Selection Confusion — 知道方法但選不出最合適的
- State Transition Confusion — 狀態定義和轉換出錯
- Edge Case Blindness — 不考慮邊界情況
- Implementation Gap — 思路對但寫不出程式碼
- Complexity Miscalculation — 複雜度分析錯誤
- Loop Condition Instability — 迴圈邊界問題

**間隔重複（Spaced Repetition）**：
- 基於 FSRS 演算法的複習排程
- 支援兩種複習目標：內容型（文章/筆記回憶）和學習項目型（題目/練習保持）
- 每次複習記錄評分（Again / Hard / Good / Easy），驅動下次排程

**學習引擎的設計哲學**：
- 源自 Dunlosky et al. (2013) meta-analysis、Ericsson Deliberate Practice、Bjork Desirable Difficulties
- 核心洞見：**讓學習過程變難，反而提升長期保留和遷移能力**
- 六大引擎：Retrieval Practice、Distributed Practice、Interleaved Practice、Elaborative Interrogation、Self-Explanation、Deliberate Practice

### 📡 RSS 智慧訂閱

- 訂閱管理：新增/停用/移除 feed，每個 feed 有排程、優先級、過濾規則
- 自動抓取管道：HTTP ETag/Last-Modified 優化，連續失敗自動停用
- AI 相關性評分：基於關鍵字權重計算每篇文章的相關分數
- 策展工作流：unread → read → curated（轉為書籤/文章）或 ignored
- Topic Monitor：主動監控特定主題的新內容

### 📝 內容管理與發佈

**七種內容類型**：
- Article（深度技術文章）、Essay（觀點隨筆）、Build Log（開發記錄）、TIL（每日學習）、Note（技術筆記）、Bookmark（推薦資源 + 評語）、Digest（週報/精選彙整）

**內容生命週期**：draft → review → published → archived

**AI 審核分級**：
- auto：自動發佈（低風險內容如書籤）
- light：輕度審核
- standard：標準審核（預設）
- strict：嚴格審核（需人工批准）

**語意搜尋**：pgvector embedding（768 維）+ PostgreSQL 全文搜尋雙引擎，支援跨語言搜尋。

### 🎯 前端功能

**公開網站**（Angular SSR）：
- 內容瀏覽：按類型（文章、隨筆、Build Log、TIL、書籤）或主題瀏覽
- 專案作品集：Featured 專案展示、Case Study 格式
- 搜尋：全文 + 語意搜尋
- 主題頁：按知識領域組織的內容聚合

**私有工作空間**（Admin Dashboard）：
- **Today**：每日計畫視圖 — 今天承諾要做的事
- **Dashboard**：總覽 — 目標進度、任務狀態、近期活動
- **Inbox**：GTD 捕捉箱 — 未釐清的想法和待辦
- **Tasks**：全任務管理 — 狀態流轉、能量/優先級篩選
- **Goals**：目標與里程碑追蹤
- **Learn**：學習儀表板 — 弱點分析、間隔複習、session 管理
- **Reflect**：晚間反思 — 計畫 vs 實際、每日回顧
- **Contents**：內容管理 — 草稿、審核、發佈
- **Studio**：AI 輔助創作
- **Feeds**：RSS 訂閱和策展
- **System**：系統健康、管道狀態

---

## MCP 工具設計哲學

koopa0.dev 透過 MCP（Model Context Protocol）讓 AI 助手與系統互動。這不是 CRUD API — 這是**以工作流為導向的語意介面**。

### 23 個工作流驅動的工具，分為 5 層

**第一層：Context Suppliers（上下文提供）**
- `morning_context`：晨間 briefing — 一次呼叫取得今天需要的所有上下文
- `reflection_context`：晚間反思上下文
- `search_knowledge`：跨所有內容類型的統一搜尋
- `goal_progress`：目標進度追蹤
- `learning_dashboard`：學習分析儀表板（弱點、掌握度、複習排程、時間線）
- `system_status`：系統健康狀態
- `session_delta`：上次 session 以來的變化
- `weekly_summary`：週報

**第二層：Commitment Gateway（承諾閘道）**
- `propose_commitment`：提案（目標、專案、里程碑、指令、洞察、學習計畫）— AI 永遠不會直接建立高風險實體
- `commit_proposal`：使用者確認後提交

**第三層：Lifecycle Transitions（生命週期轉換）**
- `advance_work`：任務狀態機（clarify / start / complete / defer / drop）
- `plan_day`：每日計畫
- `acknowledge_directive`：確認指令
- `file_report`：提交報告
- `manage_plan`：學習計畫管理（新增/移除/更新項目、重排、更新計畫狀態、查看進度）

**第四層：Direct Recording（直接記錄）**
- `capture_inbox`：零摩擦捕捉到 inbox
- `write_journal`：寫日誌
- `start_session`：開始學習 session
- `record_attempt`：記錄一次學習嘗試（含認知觀察）
- `end_session`：結束學習 session
- `track_insight`：追蹤洞察狀態變化

**第五層：Content Management（內容管理）**
- `manage_content`：內容生命週期（建立、更新、發佈、書籤化 RSS）
- `manage_feeds`：RSS 訂閱管理

### 關鍵設計原則

1. **Two-Step Commitment**：高風險實體（目標、專案、指令）永遠走 propose → 使用者確認 → commit 的流程。AI 不會自作主張替你建立承諾。

2. **Semantic Maturity Assessment**：AI 在建立任何實體前，會評估輸入的成熟度（M0 模糊 → M1 成形 → M2 結構化 → M3 可執行）。如果使用者說「我想把英文變強」（M0），AI 會留在對話中而不是急著建實體。

3. **No Auto-Carryover**：昨天沒完成的任務不會自動延到今天。你必須看到它、面對它、做決定。

4. **Observation Confidence**：AI 對學習弱點的觀察分高/低信心。低信心的推斷需要使用者確認才記錄，避免噪音污染分析數據。

---

## 架構拓撲（供 README SVG 架構圖參考）

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Cowork                             │
│  ┌──────────┐ ┌───────────────┐ ┌─────────────┐ ┌────────────┐ │
│  │    HQ    │ │Content Studio │ │Research Lab │ │Learning    │ │
│  │(決策/分配)│ │(內容策略/寫作) │ │(深度研究)   │ │Studio      │ │
│  │          │ │               │ │             │ │(學習教練)   │ │
│  └────┬─────┘ └──────┬────────┘ └──────┬──────┘ └─────┬──────┘ │
│       │              │                 │               │        │
│       └──────────────┴────────┬────────┴───────────────┘        │
│                               │ IPC Protocol                     │
│                    (Directives / Reports / Journal)               │
└───────────────────────────────┼──────────────────────────────────┘
                                │
                         ┌──────┴──────┐
                         │  MCP Server  │
                         │ (23 Tools)   │
                         └──────┬──────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                       │
    ┌─────┴──────┐     ┌───────┴───────┐      ┌───────┴───────┐
    │  Claude     │     │  Angular SSR  │      │  Knowledge    │
    │  Code       │     │  Frontend     │      │  Database     │
    │ (開發代理)   │     │               │      │  (PostgreSQL) │
    └────────────┘     │  ┌─────────┐  │      │               │
                        │  │ Public  │  │      │ PARA + GTD    │
                        │  │ Website │  │      │ Learning      │
                        │  ├─────────┤  │      │ IPC           │
                        │  │ Admin   │  │      │ Content       │
                        │  │Workspace│  │      │ RSS           │
                        │  └─────────┘  │      │ Knowledge     │
                        └───────────────┘      │ Graph         │
                                               └───────────────┘
```

**資料流向**：

```
Obsidian Vault ──sync──► Notes ──pipeline──► Tags, Embeddings, Knowledge Graph
RSS Feeds ──fetch──► Feed Entries ──AI scoring──► Curated Bookmarks/Articles
Notion ──sync──► Projects, Goals
GitHub ──webhook──► Activity Events ──resolution──► Project Activity

Claude Cowork ──MCP──► Tasks, Directives, Reports, Journal, Insights
Learning Session ──MCP──► Attempts ──observations──► Concept Mastery Map
                                                      ↓
                                                 FSRS Engine
                                                      ↓
                                                 Review Cards ──schedule──► Spaced Retrieval
```

---

## 技術選擇（僅供 README 技術棧 badge 參考，不需深入說明）

| 層 | 選擇 |
|----|------|
| 後端 | Go, PostgreSQL, pgx/v5, sqlc |
| AI | Genkit (Go), pgvector |
| 前端 | Angular (SSR), Tailwind CSS |
| AI 協作 | Claude (Cowork + Code), MCP |
| 間隔重複 | FSRS Algorithm |
| 搜尋 | Full-text (tsvector) + Semantic (pgvector) |

---

## README 風格指引

1. **產品導向**：像介紹一個產品一樣寫，不是像解釋一個 codebase
2. **功能價值優先**：強調「做什麼」和「為什麼」，不是「怎麼做」
3. **SVG 架構圖**：用精美的 SVG 畫出系統拓撲（多角色協作、資料流向、功能模組）
4. **不要程式碼片段**：不需要展示任何 Go 或 TypeScript 代碼
5. **不要目錄結構**：不需要列出 `internal/` 或 `cmd/` 的結構
6. **不要 API 端點**：不需要列出 HTTP routes
7. **可以有**：技術棧 badges、功能亮點 bullet points、設計哲學段落、系統架構圖
8. **語言**：英文為主，因為是 GitHub README
9. **風格參考**：Google 的開源 README（如 Kubernetes、gVisor）— 簡潔、有架構圖、功能導向
10. **長度**：中等長度，不過長但內容充實

---

## 最後的產品定位

koopa0.dev 的獨特之處不在於它用了什麼技術，而在於它的**互動模式**：

- 傳統知識管理工具：人操作 → 工具響應
- koopa0.dev：**多個 AI 角色在同一個知識系統中協作，各有職責和能力邊界，透過正式的 IPC 協議協調，共同幫助使用者達成目標**

這是一個**以 AI 為原生公民的個人知識引擎**。AI 不是附加的聊天機器人 — 它是系統架構的核心組成部分。
