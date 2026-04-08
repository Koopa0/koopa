# koopa0.dev — 系統語意文件

> 本文件定義 koopa0.dev 的領域模型、設計思想和語意契約。
> 所有 AI participant 應閱讀此文件以理解系統全貌，再根據自身角色判斷需要什麼能力。
> 本文件不描述 MCP 工具 — 只描述系統是什麼、為什麼這樣設計。

---

## 系統是什麼

koopa0.dev 是一個 **AI 協作式個人知識引擎**。它不是部落格，不是 CMS，不是 to-do app。

它是一個可輸入、可處理、可輸出的個人作業系統，而 AI 是原生公民。多個 AI 角色在同一個知識系統中協作，各自有明確的角色、能力邊界和正式的通訊協議。

三大面向：
1. **輸入** — Obsidian 知識庫同步、RSS 訂閱抓取、外部來源整合（Notion、GitHub）
2. **處理** — AI Pipeline 分類/摘要/評分、標籤正規化、語意搜尋、知識圖譜
3. **輸出** — 公開網站（Angular SSR）呈現內容與作品集、私有工作空間追蹤一切

---

## 設計原則

### AI 是協作者，不是工具
傳統 AI 整合是「人問 AI 答」。koopa0.dev 的模型是多個 AI 角色在共享系統中協作，透過 IPC 協議協調。AI 不是附加的聊天機器人 — 它是組織架構的核心。

### 擁有權保留（Ownership-Preserving）
系統不替你做決定。高風險實體（目標、專案、指令）永遠走 提案 → 使用者確認 → 提交 的流程。昨天沒完成的任務不會自動延到今天 — 你必須面對它、做決定。

### 以工作流為導向，不是 CRUD
系統對外暴露的是語意操作（「開始新的一天」「記錄一次嘗試」「推進任務狀態」），不是原始資料表操作。每個操作封裝一個有意義的工作流步驟。

### 讓困難成為功能
學習觀察有信心閘門。實體建立前有成熟度評估。Daily Plan 沒有自動延遞。這些摩擦點是刻意設計 — 強迫有意識地參與，而不是被動堆積。

---

## 組織架構：Participants 和 IPC

### Participant 身份模型

系統中的每個參與者（人或 AI）都是一個 `participant`，隸屬於某個 `platform`：

| Platform | 說明 |
|----------|------|
| `claude-cowork` | Claude Desktop Cowork — 多專案虛擬工作室 |
| `claude-code` | Claude Code CLI — 開發代理 |
| `claude-web` | Claude Web — 一般對話 |
| `human` | 人類直接操作 |

每個 participant 有**能力旗標**，決定它能做什麼：

| 能力 | 說明 |
|------|------|
| `can_issue_directives` | 可以對其他 participant 發出指令 |
| `can_receive_directives` | 可以被其他 participant 指派指令 |
| `can_write_reports` | 可以提交報告 |
| `task_assignable` | 可以被分配任務 |
| `can_own_schedules` | 可以擁有排程 |

能力旗標是組織安全層 — 系統信任 participant 的自我識別（`as: "hq"`），但在每次操作時驗證能力。

### IPC 協議

角色之間透過四種正式的通訊管道互動：

**Directives（指令）**
從有 `can_issue_directives` 的角色發出，到有 `can_receive_directives` 的角色。不能自己發給自己。
- 有優先級：P0（立即）、P1（今天）、P2（本週）
- 三階段生命週期：`issued → acknowledged → resolved`
- 解決時可連結到最終交付的報告（`resolution_report_id`）
- 必須先 acknowledged 才能 resolved

**Reports（報告）**
從有 `can_write_reports` 的角色提交。可以是指令的回覆（`in_response_to`），也可以是自發性報告。
- 一個指令可以有多個報告（進度更新 + 最終交付）
- 沒有 target 欄位 — 指令驅動的報告由指令來源閱讀，自發報告由 HQ 在晨間 briefing 閱讀

**Journal（日誌）**
自我記錄，不跨角色。每個 participant 記自己的日誌。
- `plan`：每日計畫和選擇理由
- `context`：session 結束時的上下文快照
- `reflection`：回顧和反思
- `metrics`：量化指標快照（主要由 AI 自動生成）

**Insights（洞察）**
可追蹤的假說。不是感想，不是日誌 — 是有明確失效條件的預測。
- 每個 insight 必須有 `hypothesis`（假說）和 `invalidation_condition`（失效條件）
- 狀態：`unverified → verified | invalidated → archived`
- 例：「每次做 graph 題都卡在 DFS termination condition」是 insight；「今天效率不錯」不是

---

## 領域模型

### PARA：責任結構

**Areas（責任領域）**
持續性的關注範圍。沒有完成狀態 — 只有要維持的標準。
- 例：Backend、Learning、Studio
- Goals 和 Projects 都透過 FK 指向 Area

**Goals（目標）**
有明確成果和可選截止日的規劃目標。可屬於某個 Area，也可以不屬於。
- 狀態：`not-started → in-progress → done | abandoned | on-hold`
- `on-hold` = 暫停但可恢復（不同於 `abandoned` 是終止）
- 可有可選的 `quarter`（目標季度）和 `deadline`

**Milestones（里程碑）**
目標的二元進度檢查點。完成/未完成，沒有中間狀態。
- 由 `completed_at IS NOT NULL` 判斷是否完成
- 目標進度 = 已完成里程碑 / 總里程碑（諮詢性的，不自動更新目標狀態）
- 有 `position` 表示預期達成順序
- Milestones 和 Projects 是 Goal 下的兄弟關係

**Projects（專案）**
有明確交付物的短期努力。可服務於 Goal，也可以是純 Area 維護。
- 狀態：`planned → in-progress → on-hold | completed | maintained | archived`
- 包含作品集/Case Study 欄位（problem、solution、architecture、results）用於公開展示
- 有 `expected_cadence` 追蹤開發活動頻率

### GTD：執行流程

**Tasks（任務）**
工作項目，遵循 GTD 生命週期。
- `inbox`：已捕捉但未釐清（缺少 project/due/priority）
- `todo`：已釐清，可行動
- `in-progress`：執行中
- `done`：已完成（`completed_at` 必須有值）
- `someday`：有興趣但現在不行動，Weekly Review 時審視

每個任務有：
- `assignee`：誰執行（FK to participant，預設 human）
- `created_by`：誰建立的（FK to participant）
- `energy`：high / medium / low（GTD engage-by-energy）
- `priority`：high / medium / low
- 可選的 recurrence（interval + unit）

**Daily Plan Items（每日計畫項目）**
不是簡單的 my_day boolean — 是有完整語意的每日承諾記錄。
- 每個項目記錄：`plan_date`、`task_id`、`selected_by`（誰選的）、`position`（優先序）、`reason`（為什麼選）
- 狀態：`planned → done | deferred | dropped`
- 一個任務同一天只能出現一次（unique constraint）
- **沒有自動延遞** — 昨天 planned 但沒完成的會被呈現，但使用者必須主動決定

**Task Skips（任務跳過記錄）**
記錄循環任務的每次跳過，區分 `auto-expired`（cron 偵測到逾期）和 `manual`（使用者手動跳過）。

### 語意成熟度評估

系統在建立任何承諾性實體之前，會評估輸入的成熟度：

| Level | 名稱 | 指標 | 允許動作 |
|-------|------|------|----------|
| M0 | 模糊 | 沒有成果、探索性的（「也許」「想想看」） | 留在對話，不寫入任何東西 |
| M1 | 成形 | 有方向但缺細節（沒截止日、沒範圍） | 只允許捕捉到 inbox |
| M2 | 結構化 | 有成果 + 粗略範圍，缺部分欄位 | 提案，AI 填預設值，使用者審核 |
| M3 | 可執行 | 具體成果、有時間限制、所有關鍵欄位齊全 | 提案，快速批准路徑 |

**不確定時選低的**。「我想把英文變強」是 M0，不是 M1。

---

## 知識層

### Contents（內容）
已完成的內容產物。七種類型共享一張表和一個生命週期。
- 類型：`article`、`essay`、`build-log`、`til`、`note`、`bookmark`、`digest`
- 狀態：`draft → review → published → archived`
- 審核分級：`auto`（自動發佈）、`light`、`standard`、`strict`（需人工批准）
- 雙引擎搜尋：tsvector 全文搜尋 + pgvector 768d 語意搜尋
- 支援 series（系列文章）

### Notes（筆記）
從外部知識庫（目前是 Obsidian）同步的筆記。
- 有 maturity 追蹤：`seed → evergreen | stub | archived`（Zettelkasten 成熟度）
- 支援 LeetCode 特有欄位（`difficulty`、`leetcode_id`）
- 支援書籍筆記（`book`、`chapter`）
- 筆記之間有 wikilink 邊（`note_links` table）構成知識圖譜

### Tags（標籤）
正規化的標籤系統。
- `tags`：正規標籤（controlled vocabulary）
- `tag_aliases`：raw tag → canonical tag 的映射管道
- 層級結構（`parent_id`）
- 透過 junction tables 連結到 contents、notes、events

### Topics（主題）
高層級知識領域（10-20 個，手動管理）。
- 例：Go、AI、System Design、PostgreSQL
- 透過 junction tables 連結到 contents 和 feeds
- 與 Areas 正交 — Area 是責任領域，Topic 是知識領域

---

## RSS 訂閱系統

### Feeds（訂閱源）
RSS/Atom 訂閱管理。
- 有排程、優先級（normal/high/low）、過濾規則
- HTTP ETag / Last-Modified 條件抓取
- 連續失敗計數，超過閾值自動停用
- 每個 feed 連結到一或多個 topics

### Feed Entries（訂閱項目）
管道抓取的 RSS 文章。
- AI 相關性評分（`relevance_score`）
- 策展生命週期：`unread → read → curated | ignored`
- curated 項目可連結到 content 記錄（bookmark 或 article）
- Topics 從 feed 繼承（查詢時 JOIN，不是快照）

### Topic Monitors（主題監控）
主動監控特定主題的新內容。每個 topic 最多一個 monitor，有搜尋關鍵字和排程。

---

## 學習引擎

學習引擎回答的問題不是「我學了什麼」（那是 notes 和 contents），而是「為什麼我在 binary search 上很弱」、「哪些嘗試支持這個判斷」、「接下來應該練什麼」。

### Concepts（概念本體）
學習概念的分類樹，獨立於 tag 系統。
- `domain`：leetcode、japanese、system-design、go、english、reading...
- `kind`：pattern（策略框架）、skill（可練習能力）、principle（理論基礎）
- 層級結構（`parent_id`），同 domain 內
- 可選橋接到 tag 系統（`tag_id`）
- **Mastery 是衍生狀態**，從 attempt_observations 聚合計算，不存在概念表上

### Items（學習項目）
學習的目標對象 — 一道 LeetCode 題、一個文法點、一個章節。
- 獨立於筆記存在（items 先於 notes）
- 有 domain 和 difficulty
- 可連結到 note（item-level 摘要）和 content（罕見情況）
- metadata 存放 domain-specific 資料（problem_url、jlpt_level 等）

### Item Relations（項目關係圖）
項目之間的有向關係。
- `easier_variant` / `harder_variant`：難度變體
- `prerequisite`：先決條件
- `follow_up`：自然下一步
- `same_pattern` / `similar_structure`：模式/結構相似
- 方向慣例：source 是參考點，target 是關聯項目

### Item Concepts（項目-概念連結）
哪個學習項目練習哪些概念。
- `primary`：核心概念
- `secondary`：輔助概念
- 慣例：每個 item 一個 primary

### Sessions（學習會話）
有明確開始和結束的學習時段。
- `domain`：學習領域
- `session_mode`：retrieval、practice、mixed、review、reading
- **同一時間只能有一個進行中的 session**（`ended_at IS NULL`）
- 結束時可產生 journal 記錄（`journal_id`）
- 可連結到 daily plan item（`daily_plan_item_id`）

### Attempts（嘗試）
對一個學習項目的一次嘗試。
- `attempt_number`：第 N 次嘗試（1 = 首次，2+ = 重訪）
- `outcome` 有兩種範式：
  - **解題類**（LeetCode、文法練習）：`solved_independent`、`solved_with_hint`、`solved_after_solution`
  - **沉浸類**（閱讀、聽力）：`completed`、`completed_with_support`
  - **通用**：`incomplete`、`gave_up`
- 記錄 `duration_minutes`、`stuck_at`（卡住的地方）、`approach_used`（使用的方法）
- 可連結到 note（attempt-level 工作筆記，不同於 item-level 摘要）

### Attempt Observations（認知觀察）
學習分析的核心。每個觀察連結一次嘗試到一個概念。
- `signal_type`：
  - `weakness`：這個概念出了問題（附 severity: minor/moderate/critical）
  - `improvement`：相較過去有進步
  - `mastery`：展示獨立流暢的應用
- `category`：觀察維度（Go-validated convention，不是 DB enum）
  - LeetCode: pattern-recognition, constraint-analysis, edge-cases, implementation, complexity-analysis, approach-selection
  - Japanese: conjugation-accuracy, particle-selection, listening-comprehension, vocabulary-recall
  - System Design: tradeoff-analysis, bottleneck-diagnosis, capacity-estimation

**信心閘門**：
- 高信心（直接記錄）：概念已存在、信號被行為直接證明、category 符合慣例
- 低信心（使用者確認後記錄）：需要新建概念、信號是推斷的、category 是新的

### Plans（學習計畫）
有序的學習課程安排。
- 狀態：`draft → active → completed | paused | abandoned`
- 連結到 goal（可選）和 domain
- 有 `target_count`（目標題數，advisory）

### Plan Items（計畫項目）
計畫中的每個學習項目。
- 狀態：`planned → completed | skipped | substituted`
- 完成時**必須**連結到具體的 attempt（`completed_by_attempt_id`）和 reason — 這是審計軌跡
- 支援 phase 分組（如 "phase-1-arrays"）
- substituted 項目指向替代品（`substituted_by`）

### Review Cards + Review Logs（間隔重複）
基於 FSRS 演算法的複習排程。
- 兩種複習目標：content-based 和 learning-item-based（exactly one）
- `card_state`：FSRS 不透明狀態（Stability、Difficulty、Reps、Lapses）
- `due`：下次複習日（反正規化，用於索引查詢）
- 四級評分：1=Again、2=Hard、3=Good、4=Easy

---

## AI Pipeline

### Flow Runs（AI 管道執行記錄）
Genkit AI flow 的執行歷史。
- 每行 = 一次 flow 執行（classify、summarize、review 等）
- 支援重試（`attempt` / `max_attempts`）
- 狀態：`pending → running → completed | failed`

---

## 排程系統

### Participant Schedules（排程）
participant 擁有的定期執行指令。
- `trigger_type`：cron / interval / manual
- `execution_backend`：cowork_desktop / claude_code / github_actions / koopa_native
- `expected_outputs`：預期產出（如 `journal:plan`、`report`）
- `missed_run_policy`：skip / run_once_on_wake / queue_all

### Schedule Runs（排程執行歷史）
Append-only 的執行記錄，用於趨勢分析和故障診斷。

---

## 系統健康

### Reconcile Runs（調和執行）
週期性比對 Obsidian vault、Notion、DB 的一致性。追蹤 drift 趨勢。

### Events（統一事件日誌）
來自所有來源（GitHub、Notion、Obsidian sync、MCP、cron）的統一事件流。

---

## 資料流全景

```
Obsidian Vault ──sync──► Notes ──pipeline──► Tags, Embeddings, Knowledge Graph
RSS Feeds ──fetch──► Feed Entries ──AI scoring──► Curated → Bookmarks/Articles
Notion ──sync──► Projects, Goals
GitHub ──webhook──► Events ──resolution──► Project Activity

AI Participants ──IPC──► Directives, Reports, Journal, Insights
                ──tasks──► Tasks ──daily plan──► Daily Plan Items
                ──learning──► Sessions → Attempts → Observations → Concept Mastery
                                                                        ↓
                                                                   FSRS Engine
                                                                        ↓
                                                                   Review Cards → Spaced Retrieval
```
