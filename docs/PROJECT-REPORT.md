# koopa0.dev — Project Report

> 這份報告是專案的完整語意地圖，用於讓 Claude Web 理解系統後撰寫 README。
> 報告涵蓋：系統定位、設計哲學、架構全貌、Domain Model、MCP 設計、AI 協作模型、技術棧、以及各層的設計決策。
> Last updated: 2026-04-08

---

## 1. 系統定位

koopa0.dev 不是部落格，不是 CMS。它是一個 **AI-native 個人知識引擎**。

三大面向：
- **輸入** — Obsidian 知識庫同步、RSS 訂閱、外部 API 收集
- **處理** — Go Genkit AI Pipeline 整理、分類、生成草稿、審核分級
- **輸出** — Angular SSR 網站展示 + MCP 工具暴露給 AI agent

核心思想：
- **Obsidian-first** — 內容源頭是 Obsidian vault，網站是呈現層
- **AI 輔助，人類把關** — 審核分級制（auto/light/standard/strict）
- **對自己有用** — 首先是知識管理工具，其次是對外展示
- **用作品說話** — 不列學經歷，讓作品和內容展示能力

使用者：Koopa — 一人 Go 工程師，正在準備 Google Senior 面試、經營 Koopa Studio（pre-revenue freelance 工作室）、持續擴展技術深度。

---

## 2. 設計哲學

### 對人的哲學
- **Ownership-preserving** — 系統不替使用者做決定，而是保護使用者的 agency。未完成事項不會自動延遲（forced confrontation）。AI 提案但不直接寫入（proposal-first）。
- **Learning-first** — 學習是系統的核心用途之一。製造 desirable difficulties（適度困難提升長期記憶）。FSRS 間隔重複排程內建。
- **Structured over casual** — 每個值得記住的東西都有結構化記錄。Journal、attempt、observation、insight 都有明確的 schema 和 lifecycle。

### 對 AI 的哲學
- **AI 是 coach，不是替代品** — AI 追蹤弱點、引導思考、記錄觀察，但不替使用者做學習、做決策、做執行。
- **Semantic maturity assessment** — AI 在建立 entity 前評估輸入的成熟度（M0-M3），避免把模糊想法變成承諾。
- **Trust model** — MCP 信任 AI caller 的 identity（via `as` parameter），用 capability flags 限制操作。不是 cryptographic trust，是 organizational trust。

### 對 code 的哲學
- **Standard library first** — 不用 HTTP framework（net/http 1.22+ routing）、不用 ORM（sqlc + pgx）、不用 assertion library（go-cmp + stdlib testing）
- **Package-by-feature** — 不用 service/repository/handler 層。每個 feature 是一個 package，包含 types + handler + store + query。
- **Design before mechanics** — 先理解概念（WHY），再寫程式碼（WHAT）。

---

## 3. Domain Model

### 3.1 PARA Framework（組織架構）

Tiago Forte 的 PARA 方法映射到系統：

```
Areas     → areas 表 — 持續責任領域（engineering, japanese, career, health...）
Projects  → projects 表 — 有明確目標的短期努力，歸屬 Area，可連結 Goal
Resources → contents, notes, feeds, feed_entries — 知識資源
Archives  → Status-based — project.status='archived', goal.status='abandoned'
```

Area 是一級 entity，不是標籤：
```
Area: engineering
  └── Goal: 成為 Go GDE
        ├── Milestone: 發表 3 篇深度 Go 文章
        ├── Project: koopa0.dev
        │     ├── Content: "Go Generics 完全指南"
        │     └── Task: 重構 auth middleware
        └── Learning Plan: LeetCode 200 題計劃
              └── Plan Items → Attempts → Observations
```

### 3.2 GTD Framework（任務管理）

David Allen 的 GTD 五步映射：

| GTD 步驟 | MCP Tool | Schema |
|----------|----------|--------|
| Capture | `capture_inbox` | tasks(status=inbox) |
| Clarify | `advance_work(clarify)` | inbox → todo |
| Organize | `plan_day` | daily_plan_items |
| Reflect | `morning_context` / `reflection_context` | journal entries |
| Engage | `advance_work(start/complete)` | task lifecycle |

Task lifecycle: `inbox → todo → in-progress → done`，旁支 `someday`（定期回顧）。
Daily plan: 每日選擇任務排入計劃，不自動延遲（no auto-carryover）。

### 3.3 Goal Tracking（目標管理）

**不是 OKR。** 是二元里程碑制：

- **Goal** — 方向性目標，有 area、quarter、deadline
- **Milestone** — 二元檢查點（done / not-done），不是量化 KR
- **Milestone → Goal 是 advisory** — 里程碑完成不自動推導 goal status

### 3.4 Learning Engine（學習分析）

基於 Dunlosky meta-analysis、Ericsson Deliberate Practice、Bjork Desirable Difficulties 的結構化學習引擎：

```
Domain (leetcode, japanese, system-design, go...)
  └── Learning Session (domain + mode)
        └── Attempt (item × outcome)
              ├── Outcome (solved_independent / solved_with_hint / gave_up...)
              └── Observations (concept × signal)
                    └── weakness / improvement / mastery
```

| Entity | 說明 |
|--------|------|
| Session | 一次學習活動。mode: practice/retrieval/mixed/review/reading |
| Attempt | 對一個 learning item 的一次嘗試 |
| Observation | 認知信號 — 哪個 concept 展現了 weakness/improvement/mastery |
| Concept | 知識本體節點 — pattern/skill/principle，有 parent-child hierarchy |
| Learning Item | 學習目標（LeetCode 題、書本章節）|
| Learning Plan | 有序的學習課程（如 LeetCode 200 題計劃），連結 goal |
| Review Card | FSRS 間隔重複排程卡片 |

**Learning Plan 的 bifurcated lifecycle:**
- Shell（title, domain, goal）via `propose_commitment` — proposal-first
- Items（add/remove/reorder/complete/skip/substitute）via `manage_plan` — direct-commit
- Plan item completion 由 Claude 做語意判斷，不由 threshold 自動觸發
- 同一 item 在不同 plan 中的完成狀態獨立

**FSRS 整合:** go-fsrs/v4 library。每次 `record_attempt` 後自動更新 review card。Lazy card creation（第一次 review 時建卡）。

### 3.5 IPC（跨 Participant 協調）

系統有多個 AI participant，各有不同角色和能力：

```
Platform: claude-cowork
  ├── hq              — CEO，決策 + 委派
  ├── content-studio  — 內容策略、寫作、發布
  ├── research-lab    — 深度研究、結構化報告
  └── learning-studio — 學習教練、spaced repetition

Platform: claude-code
  └── koopa0.dev      — 本專案開發

Platform: human
  └── human           — Koopa 本人
```

IPC 機制：
- **Directive** — source → target 指令。需要判斷力的工作（產出是報告）。三階段 lifecycle: issued → acknowledged → resolved。
- **Report** — 回報。可連結 directive，可同時 resolve directive。
- **Journal** — 自我記錄（plan/context/reflection/metrics）。
- **Insight** — 假說追蹤。有 hypothesis + invalidation_condition，lifecycle: unverified → verified/invalidated。

**Directive vs Task 判斷準則：**
- 產出是**報告**（需要判斷力）→ Directive
- 產出是**狀態變更**（執行性工作）→ Task

---

## 4. MCP Server（23 tools）

MCP v2 將 49 個 v1 CRUD tools 重寫為 23 個 workflow-driven tools，分 5 層：

### Layer 1: Context Suppliers (readOnly, 8 tools)
`morning_context`, `reflection_context`, `search_knowledge`, `goal_progress`, `learning_dashboard`, `system_status`, `session_delta`, `weekly_summary`

### Layer 2: Commitment Gateway (2 tools)
`propose_commitment` (readOnly — preview + token) → `commit_proposal` (additive — write to DB)
支援 6 種 entity type: goal, project, milestone, directive, insight, learning_plan

### Layer 3: Lifecycle Transitions (5 tools)
`advance_work` (task state machine), `manage_plan` (6-action multiplexer, hard ceiling), `track_insight`, `acknowledge_directive`, `file_report` (含 directive resolution)

### Layer 4: Direct Recording (6 tools)
`capture_inbox`, `plan_day`, `write_journal`, `start_session`, `record_attempt`, `end_session`

### Layer 5: Content Management (2 tools)
`manage_content`, `manage_feeds`

**設計原則：**
- Proposal-first for commitment entities（goal/project/milestone/directive/insight/learning_plan）
- Direct-commit for ephemeral captures（task/journal/session/attempt）
- Semantic maturity assessment: M0 (vague, stay in conversation) → M3 (actionable, fast approval)
- HMAC-signed stateless tokens for proposals (10min TTL)
- `as` parameter for caller identity on every tool call
- Capability flags enforce permission boundaries

---

## 5. Admin API（HTTP endpoints for frontend）

`internal/admin/` package 提供 16+ aggregate HTTP endpoints，使用 `internal/api/` shared helpers：

| Category | Endpoints | 用途 |
|----------|-----------|------|
| Today | GET today, POST plan, POST resolve | 每日工作面 |
| Inbox | GET inbox, POST capture, POST clarify | GTD 捕獲與澄清 |
| Goals | GET overview, GET detail, propose, commit, milestones | 目標管理 |
| Projects | GET overview, GET detail | 專案追蹤 |
| Tasks | GET backlog, POST advance | 任務生命週期 |
| Library | GET pipeline | 內容管道 |

**設計原則：**
- Aggregate views — 前端不需要打多個 API 拼畫面
- Semantic commands — `advance(action="complete")` 而非 `PATCH status`
- Backend 計算 derived fields — context_line, health, days_remaining

---

## 6. 技術棧

| 層 | 技術 |
|----|------|
| 前端 | Angular 21, Tailwind CSS v4, SSR |
| 後端 | Go 1.26+, net/http 1.22+ routing, pgx/v5, sqlc |
| AI | Genkit Go (Google AI), Dotprompt templates |
| SRS | go-fsrs/v4 (FSRS spaced repetition) |
| Cache | Ristretto (in-memory) |
| Messaging | NATS (Core + JetStream) |
| Logging | log/slog (std lib) |
| Tracing | OpenTelemetry (progressive) |
| Testing | std testing + go-cmp, testcontainers-go |
| Linting | golangci-lint v2 (zero tolerance) |
| Schema | PostgreSQL 46+ tables, vector(768) for semantic search |
| MCP | MCP Go SDK, stdio + Streamable HTTP transport |
| Deploy | Docker, VPS |

---

## 7. Schema 概覽（46+ tables）

Schema 設計原則：每個 column 都有 COMMENT，每個 lifecycle 都有 CHECK constraint，每個 FK 都有 explicit ON DELETE。

**核心 entity groups:**

| Group | Tables | 說明 |
|-------|--------|------|
| Identity | platform, participant | AI/human actor 與 capability flags |
| PARA | areas, goals, milestones, projects | 組織架構 |
| Content | contents, topics, tags, notes, feeds, feed_entries | 知識資源 |
| GTD | tasks, daily_plan_items, task_skips, journal | 任務管理 |
| IPC | directives, reports, insights | 跨 participant 協調 |
| Learning | concepts, items, sessions, attempts, attempt_observations, item_relations | 學習分析 |
| SRS | review_cards, review_logs | FSRS 間隔重複 |
| Plans | plans, plan_items | 學習計劃 |
| Pipeline | flow_runs, review_queue, sources | AI pipeline + reconciliation |
| Scheduling | participant_schedules, schedule_runs | 排程系統 |

**關鍵 schema decisions:**
- `directives` 有三階段 lifecycle (issued → acknowledged → resolved)，`resolved_at` + `resolution_report_id` + `chk_resolved_requires_ack`
- `plan_items` 有 `completed_by_attempt_id` FK for completion audit trail
- `review_cards` 用 `chk_review_target_exactly_one` 確保每張卡只 target 一個 entity (content XOR learning_item)
- `attempt_observations` 的 `concept_id` 用 ON DELETE RESTRICT — observations 是不可替代的歷史分析資料

---

## 8. 專案結構

```
/
├── cmd/
│   ├── app/        → HTTP API server (net/http, admin endpoints)
│   └── mcp/        → MCP server (23 workflow tools)
├── internal/
│   ├── admin/      → Admin v2 aggregate HTTP handlers (16 endpoints)
│   ├── api/        → Shared HTTP helpers (Encode, Decode, Error, HandleError)
│   ├── auth/       → JWT + Google OAuth
│   ├── content/    → Content CRUD + search + knowledge graph
│   ├── daily/      → Daily plan items
│   ├── directive/  → IPC directives + participant capabilities
│   ├── db/         → sqlc-generated code (NEVER edit)
│   ├── feed/       → RSS feed management + collector
│   ├── goal/       → Goals + milestones
│   ├── insight/    → Hypothesis tracking
│   ├── journal/    → Session logs
│   ├── learning/   → Sessions, attempts, observations, FSRS integration
│   ├── mcp/        → MCP tool handlers (23 tools)
│   ├── note/       → Obsidian note sync
│   ├── plan/       → Learning plans
│   ├── project/    → Project portfolio
│   ├── report/     → IPC reports
│   ├── review/     → Content review queue
│   ├── stats/      → System statistics
│   ├── tag/        → Tag management + aliases
│   ├── task/       → GTD task lifecycle
│   └── topic/      → Knowledge domain topics
├── migrations/     → PostgreSQL schema (001_initial.up.sql, ~1900 lines)
├── prompts/        → Genkit dotprompt templates
├── frontend/       → Angular 21 SSR + Tailwind v4
├── docs/           → Architecture docs, participant instructions, API specs
├── sqlc.yaml       → sqlc configuration
└── CLAUDE.md       → Project instructions for Claude Code
```

**Package-by-feature:** 每個 feature package 包含 `<feature>.go`（types）、`handler.go`（HTTP）、`store.go`（DB）、`query.sql`（sqlc）、`<feature>_test.go`（tests）。

---

## 9. AI 協作模型

### Participant Roles

| Participant | Platform | 職責 |
|-------------|----------|------|
| hq | claude-cowork | CEO — 決策、委派、不做執行 |
| content-studio | claude-cowork | 內容策略、寫作、發布 |
| research-lab | claude-cowork | 深度研究、結構化報告 |
| learning-studio | claude-cowork | 學習教練、弱點追蹤 |
| koopa0.dev | claude-code | 本專案開發 |
| human | human | Koopa 本人 |

### Decision Policy (MCP)

| Input maturity | Action |
|----------------|--------|
| M0 (vague: "也許"、"想想看") | Stay in conversation. Do NOT write anything. |
| M1 (forming: direction but no specifics) | `capture_inbox` only |
| M2 (structured: outcome + scope) | `propose_commitment` |
| M3 (actionable: all fields present) | `propose_commitment` (fast path) |

### Proposal-first Entities
goal, project, milestone, directive, insight, learning_plan — 必須 propose → preview → user confirm → commit。

### Direct-commit Entities
task (inbox), journal, daily plan item, attempt, session start — 低風險 append-only。

---

## 10. 開發分工

| 負責人 | 範圍 |
|--------|------|
| Koopa | Go API、AI Pipeline、Obsidian 整合、資料收集、架構決策 |
| Claude Code | Angular 前端、API 對接、Admin UI、MCP 實作、code review |
| Claude Cowork | 內容策略、研究、學習教練、日常運營（via MCP） |

---

## 11. 內容類型

| Type | 說明 | 典型長度 |
|------|------|----------|
| article | 深度技術文章 | 1500-3000 字 |
| essay | 個人觀點 | 800-1500 字 |
| build-log | 開發記錄 | 500-1500 字 |
| til | 每日學習 | 200-500 字 |
| note | 技術筆記 | 不定 |
| bookmark | 推薦資源 + 評語 | 50-200 字 |
| digest | 週報/月報 | 500-1000 字 |

---

## 12. 語言規範

- 文件和 UI 文字：繁體中文
- 程式碼（變數、函式）：English
- Git commits：English (Conventional Commits)
- MCP tool names：English (snake_case)
