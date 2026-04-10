# koopa0.dev MCP Architecture

> AI-native 個人知識引擎的完整設計文件
> 給 Claude Desktop 使用方、第三方審查者、以及任何需要理解系統的人
> Last updated: 2026-04-07

---

## 1. 系統是什麼

koopa0.dev 是一個 **可輸入、可輸出的個人知識系統**。不是部落格，不是 CMS。

三大面向：
1. **輸入** — Obsidian 知識庫、RSS 訂閱、外部 API
2. **處理** — AI Pipeline 整理、分類、生成草稿、審核
3. **輸出** — Angular SSR 網站展示 + MCP 工具暴露給 AI agent

核心哲學：
- **Obsidian-first** — 內容源頭是 Obsidian，網站是呈現層
- **AI 輔助，人類把關** — 審核分級制
- **對自己有用** — 首先是知識管理工具，其次是對外展示
- **用作品說話** — 不列學經歷，讓作品展示能力

---

## 2. Domain Model

### 2.1 PARA Framework（組織架構）

[Tiago Forte 的 PARA](https://fortelabs.com/blog/para/) 是資訊組織的四層結構：

```
Projects  — 有明確目標和截止日的短期努力
Areas     — 需要持續維護的長期責任領域
Resources — 未來可能有用的參考資料
Archives  — 不再活躍的前三類
```

在 koopa0.dev 中的映射：

| PARA | Schema | 說明 |
|------|--------|------|
| **Projects** | `projects` | 有 slug、status、tech_stack、deadline。每個 project 可連結一個 goal |
| **Areas** | `areas` | 責任領域（engineering, japanese, career, health...）。Goals 和 Projects 都歸屬 Area |
| **Resources** | `contents`, `notes`, `feeds`, `feed_entries`, `tags`, `topics` | 所有知識資源 |
| **Archives** | Status-based | `project.status = 'archived'`, `goal.status = 'abandoned'` — 不刪除，狀態歸檔 |

**Area 是一級 entity**（不是標籤）：
```
Area: engineering
  └── Goal: 成為 Go GDE
        └── Milestone: 發表 3 篇深度 Go 文章
        └── Project: koopa0.dev
              └── Content: "Go Generics 完全指南" (article)
              └── Task: 重構 auth middleware
```

### 2.2 GTD Framework（任務管理）

[David Allen 的 GTD](https://gettingthingsdone.com/) 是任務處理的五步流程：

```
Capture → Clarify → Organize → Reflect → Engage
```

在 koopa0.dev 中的映射：

| GTD 步驟 | MCP Tool | 說明 |
|----------|----------|------|
| **Capture** | `capture_inbox` | 快速捕獲到 inbox，只需 title |
| **Clarify** | `advance_work(clarify)` | inbox → todo，補上 project/due/priority/energy |
| **Organize** | `plan_day` | 從 todo 選任務排入每日計劃 |
| **Reflect** | `morning_context` / `reflection_context` / `weekly_summary` | 晨間計劃、晚間回顧、週回顧 |
| **Engage** | `advance_work(start/complete)` | 開始做 / 完成 |

**Task 生命週期：**
```
inbox ──clarify──→ todo ──start──→ in-progress ──complete──→ done
  │                  │
  └──defer──→ someday (定期回顧)
```

**Daily Planning：**
```
morning_context（看到什麼需要做）
  → 選擇任務
  → plan_day（排入今天計劃）
  → 做事 + advance_work(complete)
  → reflection_context（回顧 planned vs actual）
  → write_journal(kind=reflection)
```

**每個 task 有：**
- `assignee` — 誰來做（human, 或 AI participant）
- `created_by` — 誰建立的（追蹤來源）
- `energy` — high/medium/low（GTD 的 Engage by energy）
- `priority` — high/medium/low（task）, p0/p1/p2（directive）
- `due` — 截止日

### 2.3 Goal Tracking（目標管理）

**不是 OKR。** 是二元里程碑制：

```
Goal: 成為 Go GDE
  ├── Milestone: 發表 3 篇深度 Go 文章 ── done ✓
  ├── Milestone: 在社群演講一次 ── not done
  └── Milestone: 開源一個有影響力的 Go 專案 ── not done
```

| 概念 | 說明 | vs OKR |
|------|------|--------|
| Goal | 方向性目標，有 area、quarter、deadline | 類似 Objective |
| Milestone | **二元檢查點**（done / not-done） | **不是** Key Result（沒有 target_value / current_value） |

Goal status: `not-started` → `in-progress` → `done` / `abandoned` / `on-hold`

**Milestone → Goal 是 advisory（展示進度），不自動推導 Goal status。** 策略性決定由人做。

### 2.4 Learning Engine（學習分析）

為系統化學習設計的完整分析引擎：

```
Domain (e.g., leetcode, japanese, system-design)
  └── Learning Session (一次學習活動)
        └── Attempt (一題一記錄)
              ├── Outcome (solved_independent / solved_with_hint / gave_up...)
              ├── Duration, stuck_at, approach_used
              └── Observations (認知信號)
                    └── Concept × Signal (weakness / improvement / mastery)
```

**核心概念：**

| Entity | 說明 |
|--------|------|
| **Session** | 一次學習活動。有 domain 和 mode（practice/retrieval/mixed/review/reading） |
| **Attempt** | 對一個 learning item 的一次嘗試。記錄 outcome、duration、approach |
| **Observation** | 嘗試中觀察到的認知信號。哪個 concept 展現了 weakness/improvement/mastery |
| **Concept** | 知識本體節點。kind = pattern / skill / principle。有 parent-child 階層 |
| **Learning Item** | 學習目標（如一道 LeetCode 題）。domain-agnostic |
| **Item Relations** | 題目間的關係（easier_variant, harder_variant, prerequisite, same_pattern） |
| **Review Card** | FSRS spaced repetition 排程卡片 |

**Session Mode 決定 Outcome Mapping：**

| 語義輸入 | practice/retrieval | reading |
|----------|-------------------|---------|
| "got it" | solved_independent | completed |
| "needed help" | solved_with_hint | completed_with_support |
| "saw answer" | solved_after_solution | — |
| "didn't finish" | incomplete | incomplete |
| "gave up" | gave_up | gave_up |

**Learning Dashboard 6 Views：**

| View | 回答什麼問題 |
|------|-------------|
| overview | 最近學了什麼？多頻繁？ |
| mastery | 哪些概念已掌握？哪些還弱？ |
| weaknesses | 弱點的模式是什麼？（跨 category 分析） |
| retrieval | 今天該複習什麼？（FSRS due queue） |
| timeline | 學習趨勢是上升還是下降？ |
| variations | 做過的題目之間有什麼關係？ |

### 2.5 IPC（跨 Participant 協調）

系統中有多個 AI participant，各有不同角色和能力：

```
Platform: claude-cowork
  ├── hq              — CEO，決策 + 委派（can_issue_directives）
  ├── content-studio  — 內容策略、寫作、發布
  ├── research-lab    — 深度研究、結構化報告
  └── learning-studio — 學習教練、spaced repetition

Platform: claude-code
  ├── koopa0.dev      — 本專案開發
  └── go-spec         — Go spec 設定專案

Platform: claude-web
  └── claude          — 一般對話

Platform: human
  └── human           — Koopa 本人
```

**IPC 機制：**

| Entity | 方向 | 說明 |
|--------|------|------|
| **Directive** | source → target | 指令。source 必須有 `can_issue_directives`，target 必須有 `can_receive_directives` |
| **Report** | source → (optional directive) | 回報。source 必須有 `can_write_reports` |
| **Journal** | self | 自己的日記（plan/context/reflection/metrics） |
| **Insight** | self → shared | 假說追蹤。經過 propose → commit → verify/invalidate 生命週期 |

**Directive 生命週期：**
```
issued → acknowledged → resolved
              │              │
              └── resolved_at + resolution_report_id
```
- `acknowledged_at` — target 收到了
- `resolved_at` — 工作完成（需先 acknowledged）
- `resolution_report_id` — 最終交付物的 report

**Directive vs Task 判斷準則：**
- 產出是**報告**（需要判斷力）→ Directive
- 產出是**狀態變更**（執行性工作）→ Task

---

## 3. Tool Inventory（22 tools）

### 3.1 按工作流分組

| 工作流 | Tools | 使用場景 |
|--------|-------|----------|
| **Daily Lifecycle** | `morning_context`, `plan_day`, `advance_work`, `reflection_context`, `write_journal` | 每天的計劃→執行→回顧 |
| **Capture & Commit** | `capture_inbox`, `propose_commitment`, `commit_proposal` | 捕獲想法、建立承諾 |
| **Goal Review** | `goal_progress` | 定期檢視目標進度 |
| **Learning** | `start_session`, `record_attempt`, `end_session`, `learning_dashboard` | 結構化學習 + 分析 |
| **IPC** | `file_report`, `acknowledge_directive`, `track_insight` | 跨 participant 協調 |
| **Knowledge** | `search_knowledge`, `manage_content`, `manage_feeds` | 知識搜尋 + 內容管理 |
| **System** | `system_status` | 系統健康檢查 |
| **Cross-session** | `session_delta`, `weekly_summary` | 跨 session 上下文 + 週回顧 |

### 3.2 完整 Tool 表

| # | Tool | Input | Output | Annotation |
|---|------|-------|--------|------------|
| 1 | `morning_context` | sections?, date? | overdue_tasks, today_tasks, committed_tasks, upcoming_tasks, active_goals, unacked_directives, unresolved_directives, pending_reports, insights, rss, plan_history | readOnly |
| 2 | `reflection_context` | date? | planned_items, completed/deferred/planned counts, completion_rate, today_journals | readOnly |
| 3 | `search_knowledge` | query, content_type?, project?, limit? | contents[] with excerpt + similarity | readOnly |
| 4 | `goal_progress` | area?, status? | goals[] with milestone_total/milestone_done, area_name, projects[] | readOnly |
| 5 | `learning_dashboard` | domain?, view?, days? | view-specific data (see §2.4) | readOnly |
| 6 | `system_status` | scope? | overview (pipeline stats, feed health) | readOnly |
| 7 | `capture_inbox` | title, description?, project?, assignee?, energy?, due? | task (status=inbox) | additive |
| 8 | `propose_commitment` | type (goal/project/milestone/directive/insight/learning_plan), fields | preview + warnings + proposal_token | readOnly |
| 9 | `commit_proposal` | proposal_token, modifications? | type + id + message | additive |
| 10 | `advance_work` | task_id, action (clarify/start/complete/defer), project?, due?, priority?, energy? | task + plan_item_updated? | destructive |
| 11 | `plan_day` | items[{task_id, position}], date? | items[] | additiveIdempotent |
| 12 | `file_report` | content, source?, in_response_to? | report | additive |
| 13 | `acknowledge_directive` | directive_id | acknowledged + directive | additiveIdempotent |
| 14 | `track_insight` | insight_id, action (verify/invalidate/archive/add_evidence), evidence? | insight | additiveIdempotent |
| 15 | `start_session` | domain, mode, daily_plan_item_id? | session | additive |
| 16 | `record_attempt` | session_id, item{title, external_id?, difficulty?}, outcome, duration?, stuck_at?, approach?, observations[]?, metadata?, fsrs_rating?, related_items[]? | attempt + observations_recorded + plan_context + relations_linked + fsrs_review_failed | additive |
| 16a | `learning_dashboard` | view (overview/mastery/weaknesses/retrieval/timeline/variations), domain?, days?, confidence_filter? (mastery/weaknesses only) | view-specific payload | readOnly |
| 16b | `attempt_history` | one of {item{title, domain?}, concept_slug, session_id} | mode + resolved + attempts[] | readOnly |
| 17 | `end_session` | session_id, reflection? | session + attempts[] + duration | additive |
| 18 | `write_journal` | kind (plan/context/reflection/metrics), content, metadata? | entry | additive |
| 19 | `manage_content` | action (create/update/publish), title?, body?, content_type?, content_id?, project? | id + title + status | additive |
| 20 | `manage_feeds` | action (list/add/update/remove), url?, name?, feed_id?, enabled? | feed(s) | additive |
| 21 | `session_delta` | since? (YYYY-MM-DD, default 24h) | tasks_created, tasks_completed, journal_entries, session_count | readOnly |
| 22 | `weekly_summary` | week_of? (Monday YYYY-MM-DD) | tasks_completed, journal_entries, sessions, mastery | readOnly |

---

## 4. Trust Model — Caller Self-Identification

### 為什麼不用密碼學驗證 identity?

MCP 的 caller 不是隨機的 HTTP client — 它是被使用者授權的、有 system prompt 指導的 AI agent。
信任邊界不在 transport layer（哪個 connection），而在 application layer（這個 participant 有沒有權限）。

```
傳統 API:  caller 可能是惡意的 → JWT / certificate 驗證 identity
MCP:       caller 是被授權的 AI → prompt 定義 identity → capability 限制操作
```

### 實作：`as` 參數

每個 tool call 都可以帶 `as` 欄位宣告自己的 participant identity：

```json
{ "as": "hq", "title": "審查 PR #123", ... }
```

- Server 信任 `as` 值（和 MCP 的 trust model 一致）
- Server 用 capability flags 驗證該 participant 是否有權限做這個操作
- 如果沒有 `as`，fallback 到 server 的 `KOOPA_MCP_PARTICIPANT` env（default: `"human"`）

### Project Instructions 約定

每個 Cowork project 的 instructions 必須包含：
```
你是 hq（Studio HQ — CEO, decisions, delegation）。
在所有 MCP tool call 中傳入 as: "hq"。
你可以 issue directives 和 write reports。
```

---

## 5. 場景設計（按 Participant 角色）

### 5.1 HQ（Studio CEO）— 最常用

**晨間啟動：**
```
morning_context(as:"hq") → 看到 overdue tasks + unacked directives + pending reports
  → acknowledge_directive(as:"hq", ...)
  → plan_day(as:"hq", items:[...])
  → 如有新想法 → capture_inbox(as:"hq", title:"...")
  → 如有重要決策 → propose_commitment(as:"hq", type:insight, ...)
```

**委派工作：**
```
propose_commitment(as:"hq", type:directive, fields:{source:"hq", target:"content-studio", content:"寫一篇 Go generics 文章"})
  → commit_proposal(as:"hq", proposal_token:"...")
  → 等 content-studio 收到（acknowledge_directive）
  → 等 content-studio 回報（file_report）
```

**週回顧：**
```
weekly_summary → 看完成了什麼
goal_progress → 目標進度
learning_dashboard(view=mastery) → 學習成果
write_journal(kind=reflection) → 寫反思
```

### 4.2 Content Studio（內容策略）

**收到指令後：**
```
morning_context → 看到 unacked directives
acknowledge_directive → 標記收到
  → 研究 + 寫作
manage_content(action=create) → 建立草稿
manage_content(action=update) → 修改
manage_content(action=publish) → 發布
file_report(in_response_to=directive_id) → 回報完成
```

### 4.3 Learning Studio（學習教練）

**LeetCode 練習：**
```
start_session(domain=leetcode, mode=practice)
  → record_attempt(item={title: "Two Sum"}, outcome="got it",
      observations=[{concept: "hash-map", signal: "mastery", category: "data-structure"}])
  → record_attempt(item={title: "3Sum"}, outcome="needed help",
      observations=[{concept: "two-pointer", signal: "weakness", category: "algorithm"}])
  → end_session(reflection="需要多練 two-pointer")
```

**複習：**
```
learning_dashboard(domain=leetcode, view=retrieval) → 看到哪些到期
start_session(domain=leetcode, mode=retrieval)
  → 逐題練習 + record_attempt
  → end_session
```

**分析：**
```
learning_dashboard(view=mastery) → 掌握程度
learning_dashboard(view=weaknesses) → 弱點分析
learning_dashboard(view=variations) → 題目關聯
```

### 4.4 Research Lab（深度研究）

```
morning_context → 看到 directives
acknowledge_directive → 收到
  → 研究（可能花數小時）
file_report(content="完整研究報告...", in_response_to=directive_id)
```

### 4.5 Human（Koopa 本人）

```
capture_inbox → 隨時捕獲想法
advance_work → 手動管理任務狀態
write_journal → 記錄想法
session_delta → 「上次之後發生了什麼？」
```

---

## 6. 決策原則

### 5.1 Semantic Maturity（語意成熟度）

AI 建立 entity 前，必須評估使用者輸入的成熟度：

| Level | 指標 | 允許動作 |
|-------|------|----------|
| M0 Vague | 沒有明確目標（"也許"、"想想看"） | **不寫任何東西**，留在對話 |
| M1 Forming | 有方向但缺具體（沒 deadline、沒 scope） | `capture_inbox` only |
| M2 Structured | 有目標 + 粗略 scope，缺部分欄位 | `propose_commitment` |
| M3 Actionable | 具體、有時限、所有欄位齊全 | `propose_commitment`（快速路徑） |

**不確定時，選低一級。** M0-M1 的想法不該變成 entity。

### 5.2 Proposal-first（提議先行）

高風險 entity 必須兩步建立：

| Entity | 直接建立？ | 提議先行？ |
|--------|----------|----------|
| Task (inbox) | ✅ | — |
| Journal | ✅ | — |
| Daily plan item | ✅ | — |
| Goal | — | ✅ 必須 |
| Project | — | ✅ 必須 |
| Milestone | — | ✅ 必須 |
| Directive | — | ✅ 必須 |
| Insight | — | ✅ 必須 |
| Area | — | — | 人工建立，seed data |
| Participant | — | — | 人工建立，seed data |

### 5.3 No Auto-Carryover

`morning_context` 呈現昨天未完成的計劃項目，但 **不會自動延遲**。使用者決定：
- 重新排入今天 → `plan_day`
- 標記放棄 → 留為 planned（yesterday），不做處理
- 延遲到 someday → `advance_work(defer)`

**強迫面對未完成的工作是功能，不是 bug。**

---

## 7. 技術架構

```
┌─────────────────────┐     ┌──────────────────────┐
│  Angular Frontend   │────→│  cmd/app/ (HTTP)      │
│  (SSR + Admin)      │     │  Content/Project/     │
└─────────────────────┘     │  Topic/Feed/Tag CRUD  │
                            └──────────┬───────────┘
                                       │
┌─────────────────────┐                │  PostgreSQL (pgx/v5)
│  Claude Desktop     │     ┌──────────┴───────────┐
│  (Cowork Projects)  │────→│  cmd/mcp/ (MCP)       │
│  hq, content-studio │     │  22 workflow tools    │
│  research-lab, etc. │     │  stdio / HTTP         │
└─────────────────────┘     └──────────┬───────────┘
                                       │
┌─────────────────────┐                │
│  Claude Code        │────→│  same cmd/mcp/ (stdio)│
│  (koopa0.dev dev)   │     └──────────────────────┘
└─────────────────────┘
```

- **Backend:** Go 1.26+, net/http 1.22+ routing, pgx/v5, sqlc
- **Schema:** 46 tables, PostgreSQL, PARA + GTD domain model
- **MCP Transport:** stdio（Claude Code）or Streamable HTTP + OAuth（Claude Desktop）

---

## 8. 開放討論：場景需求

以下場景尚未有對應工具，歡迎各 participant 提出需求：

| 場景 | 目前狀態 | 可能的工具 |
|------|----------|----------|
| 日文學習 session（非 LeetCode） | `start_session(domain=japanese, mode=reading)` 可用，但沒有日文特化的 observation categories | 可加 domain-specific category presets |
| 內容排程發布 | `manage_content(publish)` 是即時的，沒有排程 | `schedule_publish(content_id, date)` |
| 跨 participant 知識共享 | 每個 participant 看到自己的 session，無法看到別人的 | read-only cross-participant views |
| Goal cascade（目標連鎖） | milestone 完成不影響 goal status | optional auto-progress rules |
| Habit tracking | 重複任務有 `recurrence_rule`，但沒有 streak 計算 | `habit_streak(task_id)` |
| Content review 自動分派 | `review_queue` 表存在，但沒有 MCP tool 操作 | `review_content(content_id, action)` |

---

## 9. 審查指南

第三方審查者請關注：

1. **Tool 粒度** — 22 tools 的數量是否恰當？有無 merge/split 建議？
2. **Maturity 評估** — M0-M3 的判斷是否足夠精確？邊界案例？
3. **Proposal flow** — stateless HMAC token（10min TTL）vs DB-stored proposals？
4. **Learning model** — Observation confidence（high/low）的判斷標準是否清晰？
5. **IPC model** — Directive/Report 的 capability 驗證是否足夠？
6. **Missing workflows** — 有哪些日常使用場景沒有被工具覆蓋？
7. **Security** — participant resolution（server-level env var）是否足夠？

完整決策原則：`.claude/rules/mcp-decision-policy.md`
Schema 簽核：`docs/SCHEMA-V2-FINAL-SIGNOFF.md`
