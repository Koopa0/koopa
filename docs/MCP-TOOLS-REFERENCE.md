# koopa0-knowledge MCP Tools Reference

> 45 tools across 4 domains. Last audit: 2026-03-26.
> Server: single Go binary (`/Users/koopa/blog/backend/`) + PostgreSQL.
> Changes from audit: `get_platform_stats` removed (drift → `get_goal_progress`), `disable_feed` + `enable_feed` merged → `update_feed`.

---

## Quick Navigation

| Domain | Tools | Purpose |
|--------|-------|---------|
| [Daily Workflow](#domain-1-daily-workflow-11-tools) | 11 | PDCA 循環：規劃、執行、回顧、調整 |
| [Knowledge & Content](#domain-2-knowledge--content-13-tools) | 13 | 知識搜尋、內容 CRUD、O'Reilly、RSS 收藏 |
| [Development & Learning](#domain-3-development--learning-8-tools) | 8 | 開發記錄、學習記錄、專案管理、學習分析 |
| [System & Infrastructure](#domain-4-system--infrastructure-13-tools) | 13 | 系統監控、RSS feed 管理、目標追蹤、週報 |

---

## Domain 1: Daily Workflow (11 tools)

每日 PDCA 循環的核心。Morning planning → execution → evening reflection → next morning。

### 1. `get_morning_context`

| 屬性 | 值 |
|------|-----|
| **一句話** | 早晨規劃一站式：一次拉回所有規劃所需資料 |
| **風險** | readOnly |
| **主要環境** | HQ（全量）、Cowork（sections 過濾）、Claude Code（`["tasks","plan","build_logs"]`）、Learning（`["tasks","plan"]`） |
| **實作** | `internal/mcp/morning_context.go`（1,135 行） |

**參數**：
- `sections` — 可選子集：tasks, activity, build_logs, projects, goals, insights, reflection, planning_history, rss, plan, completions
- `activity_days` — activity lookback（default 3）
- `build_log_days` — build log lookback（default 7）

**返回資料**：overdue_tasks, today_tasks, my_day_tasks, upcoming_tasks, planning_history, latest_reflection, latest_plan, projects, goals, insights, rss_highlights, build_logs, pipeline_health, content_pipeline, agent_tasks, daily_summary, today_completions

**觸發情境**：
- 「早安」「good morning」「今天有什麼事」
- Session start（任何環境）
- `/checkin`（Claude Code）

**備註**：sections 參數是關鍵設計 — 避免每個環境都拉全量。Claude Code 只需 3 個 section（~1/4 的資料量）。

---

### 2. `get_reflection_context`

| 屬性 | 值 |
|------|-----|
| **一句話** | 晚間回顧一站式：today's plan vs actual completions |
| **風險** | readOnly |
| **主要環境** | HQ |
| **實作** | `internal/mcp/reflection_context.go`（272 行） |

**參數**：
- `date` — 回顧哪天（default today，YYYY-MM-DD）

**返回資料**：today_plan, today_completions, my_day_status, daily_summary, unverified_insights, planning_history, yesterday_adjustments

**觸發情境**：
- 「今天回顧」「reflection」「how did today go」
- 晚間 PDCA Check 階段

**備註**：和 `get_morning_context` 是對稱的 morning/evening bookend。底層共用 `buildPlanningHistory()` 等 6 個 helper。

---

### 3. `get_session_delta`

| 屬性 | 值 |
|------|-----|
| **一句話** | 上次 session 到現在的所有變化（gap fill） |
| **風險** | readOnly |
| **主要環境** | HQ、Cowork |
| **實作** | `internal/mcp/delta_tools.go`（324 行） |

**參數**：
- `since` — 起算時間（default: 上次 claude session note 的時間）

**返回資料**：tasks_completed, tasks_created, tasks_became_overdue, build_logs, insight_changes, session_notes, metrics_trend

**觸發情境**：
- 「上次之後有什麼變化」「catch me up」「what happened since last time」
- 隔了一天以上沒開 HQ

**備註**：和 `get_morning_context` 有 ~30% 資料重疊，但語意不同：delta 專注「差異」，morning 專注「全貌」。delta 追蹤 task flow（哪些是新建的、哪些變 overdue），morning 沒有這個維度。

---

### 4. `save_session_note`

| 屬性 | 值 |
|------|-----|
| **一句話** | 跨環境 context 橋樑：寫入 5 種類型的 session note |
| **風險** | additive（建立新記錄） |
| **主要環境** | 所有環境 |
| **實作** | `internal/note/` |

**參數**：
- `note_type` — **required**：plan \| reflection \| context \| metrics \| insight
- `content` — **required**：note 內容（markdown）
- `source` — **required**：claude \| claude-code \| manual
- `metadata` — type-specific required fields（見下）
- `date` — override date（default today）

**Metadata 要求**：
| Type | Required metadata |
|------|-------------------|
| plan | `reasoning`（why this plan）, `committed_task_ids` and/or `committed_items` |
| metrics | `tasks_planned`, `tasks_completed`, `adjustments` |
| insight | `hypothesis`, `invalidation_condition` |
| reflection | 無 required |
| context | 無 required |

**觸發情境**：
- Morning planning 結束後 → plan note
- Evening reflection → reflection + metrics notes
- 發現 pattern → insight note
- 任何需要跨環境傳遞的 context → context note
- Bug report workflow → context note（搭配 create_task）

**備註**：Schema enforcement 是防止低品質資料的關鍵設計。insight 必須有 hypothesis + invalidation_condition，確保每個假說都是可證偽的。

---

### 5. `get_session_notes`

| 屬性 | 值 |
|------|-----|
| **一句話** | 讀取指定日期/類型的 session notes |
| **風險** | readOnly |
| **主要環境** | 所有環境 |
| **實作** | `internal/note/` |

**參數**：
- `note_type` — 可選 filter：plan \| reflection \| context \| metrics \| insight
- `days` — lookback 天數（default 1，max 30）
- `date` — 指定日期（default today）

**觸發情境**：
- Learning session start → 讀 HQ 的 plan note
- Claude Code `/checkin` → 讀 plan note
- 回顧過去幾天的 insights → `get_session_notes(note_type="insight", days=7)`

---

### 6. `create_task`

| 屬性 | 值 |
|------|-----|
| **一句話** | 在 Notion 建立新任務 |
| **風險** | additive |
| **主要環境** | HQ、Cowork（delegation）、Claude Code（follow-up） |
| **實作** | `internal/task/` |

**參數**：
- `title` — **required**
- `project` — slug/alias/title
- `due` — YYYY-MM-DD
- `priority` — Low \| Medium \| High
- `energy` — Low \| High（**不接受 Medium**）
- `assignee` — human \| claude-code \| cowork
- `my_day` — bool
- `notes` — description text

**觸發情境**：
- 「add a task」「remind me to」「幫我建一個任務」
- Bug report → `create_task(assignee="claude-code")`
- Morning planning → 新增缺少的任務

---

### 7. `complete_task`

| 屬性 | 值 |
|------|-----|
| **一句話** | 標記任務完成，recurring task 自動推進 due date |
| **風險** | **destructive**（recurring due date 推進不可逆） |
| **主要環境** | 所有環境 |
| **實作** | `internal/task/` |

**參數**：
- `task_id` — UUID（二擇一）
- `task_title` — fuzzy match（二擇一）
- `notes` — completion notes

**返回**：`remaining_my_day_tasks`（剩餘 My Day 任務）

**觸發情境**：
- 「done」「completed」「做完了」「這題寫完了」「OK next」

**備註**：Always confirm the specific task before calling。Recurring task 完成後會自動設定下次 due date，這個操作不可逆。

---

### 8. `update_task`

| 屬性 | 值 |
|------|-----|
| **一句話** | 更新任務的任何屬性 |
| **風險** | idempotent |
| **主要環境** | HQ、Cowork |
| **實作** | `internal/task/` |

**參數**：
- `task_id` / `task_title` — 識別任務（二擇一）
- `new_title`, `due`, `priority`, `energy`, `project`, `my_day`, `status`, `notes`, `assignee` — 只更新提供的欄位

**備註**：`notes` 是 append 到 description，不是覆蓋。完成任務用 `complete_task`，不要用 `update_task(status="Done")`。

---

### 9. `search_tasks`

| 屬性 | 值 |
|------|-----|
| **一句話** | 搜尋/列出任務（取代了原本的 `get_pending_tasks`） |
| **風險** | readOnly |
| **主要環境** | 所有環境 |
| **實作** | `internal/task/` |

**參數**：
- `query` — fuzzy match title + description
- `status` — pending \| done \| all（default: all）
- `assignee` — human \| claude-code \| cowork \| all
- `project` — slug/alias/title
- `completed_after` / `completed_before` — YYYY-MM-DD
- `limit` — default 50

**常用組合**：
- 原本的 `get_pending_tasks` → `search_tasks(status="pending")`
- Claude Code 的待辦 → `search_tasks(status="pending", assignee="claude-code")`
- 查已完成 → `search_tasks(query="refactor", status="done", completed_after="2026-03-01")`

---

### 10. `batch_my_day`

| 屬性 | 值 |
|------|-----|
| **一句話** | 批次設定 Notion My Day tasks |
| **風險** | idempotent |
| **主要環境** | HQ |
| **實作** | `internal/task/` |

**參數**：
- `task_ids` — UUID array
- `clear` — bool（先清除之前的 My Day selections）

**觸發情境**：
- Morning planning 結束，使用者確認今日計畫後一次性設定

---

### 11. `get_active_insights`

| 屬性 | 值 |
|------|-----|
| **一句話** | 查看假說追蹤：unverified pattern observations 和 hypotheses |
| **風險** | readOnly |
| **主要環境** | HQ |
| **實作** | `internal/session/` |

**參數**：
- `status` — unverified（default）\| verified \| invalidated \| archived \| all
- `project` — filter by project
- `limit` — default 10

**觸發情境**：
- Morning planning → 檢查有沒有待驗證的假說
- Evening reflection → 今天的資料是否支持/反駁某個假說
- Weekly review → 整理所有 insights

**備註**：Insights 有獨立 lifecycle（unverified → verified/invalidated → archived），14 天後 auto-archive。和 `update_insight` 配對使用。

---

## Domain 2: Knowledge & Content (13 tools)

知識搜尋、內容管理、O'Reilly 學習資源、RSS 收藏。

### 12. `search_knowledge`

| 屬性 | 值 |
|------|-----|
| **一句話** | 全域知識搜尋：搜尋所有 content types + Obsidian notes |
| **風險** | readOnly |
| **主要環境** | 所有環境 |
| **實作** | `internal/content/` + `internal/obsidian/`（4 路並行搜尋） |

**參數**：
- `query` — **required**
- `content_type` — article \| essay \| build-log \| til \| note \| bookmark \| digest \| obsidian-note
- `project` — slug/alias/title
- `after` / `before` — YYYY-MM-DD（**exclusive**，不包含指定日期）
- `source` — leetcode \| book \| course \| discussion \| practice \| video（Obsidian note filter）
- `context` — project name in frontmatter（Obsidian note filter）
- `book` — book title（Obsidian note filter）
- `limit` — default 10

**搜尋引擎**：4 路並行 — content DB full-text + Obsidian text search + Obsidian semantic search (embedding) + dedup

**常用組合**：
- Spaced retrieval → `search_knowledge(content_type="til", after="3d ago", before="7d ago")`
- 找 LeetCode 筆記 → `search_knowledge(query="binary search", content_type="obsidian-note", source="leetcode")`
- 找過去寫過的文章 → `search_knowledge(query="value semantics")`

---

### 13. `synthesize_topic` ⚠️

| 屬性 | 值 |
|------|-----|
| **一句話** | 跨源知識合成 + gap analysis（**高 token 成本**） |
| **風險** | readOnly |
| **主要環境** | HQ、Cowork |
| **實作** | `internal/mcp/content_tools.go`（176 行） |
| **狀態** | ⚠️ 待觀察使用頻率（2026-04-09 telemetry review） |

**參數**：
- `query` — **required**
- `max_sources` — default 15
- `include_gap_analysis` — bool（default true）

**它做什麼**（不使用 LLM，純 DB aggregation）：
1. 呼叫 `searchKnowledge()`（4 路並行）
2. 如果結果 < 5，fallback 逐詞搜尋
3. 按 source type 分成 4 類：PracticalExperience / ExternalKnowledge / TheoreticalBasis / CommonPatterns
4. Gap analysis：哪些類別缺少內容（靜態模板）

**使用時機**：`search_knowledge` 返回 5+ 結果且需要跨源 synthesis 時。1-2 結果用 `search_knowledge` 就夠了。

**待觀察原因**：LLM consumer 做分類可能比 rigid 規則更準確。保留的理由是「一次呼叫拿到跨源結果 + gap analysis，比 consumer 自己分多次 search 高效」。

---

### 14. `get_content_detail`

| 屬性 | 值 |
|------|-----|
| **一句話** | 用 slug 拉取完整內容（body + metadata） |
| **風險** | readOnly |
| **主要環境** | HQ（editorial review）、Learning（spaced retrieval） |
| **實作** | `internal/content/` |

**參數**：
- `slug` — **required**

**觸發情境**：`search_knowledge` 找到結果後，需要讀完整內容時。

---

### 15. `create_content`

| 屬性 | 值 |
|------|-----|
| **一句話** | 建立內容草稿（7 種 content type） |
| **風險** | additive |
| **主要環境** | Cowork（content pipeline）、Claude Code（build-log fallback） |
| **實作** | `internal/content/` |

**參數**：
- `title` — **required**
- `body` — **required**（markdown）
- `content_type` — **required**：article \| essay \| build-log \| til \| note \| bookmark \| digest
- `tags` — string array
- `project` — slug/alias/title

**備註**：建立的是 draft status。Coding session 用 `log_dev_session`（更結構化），不要直接用 create_content。

---

### 16. `update_content`

| 屬性 | 值 |
|------|-----|
| **一句話** | 更新 draft/review 內容的任何屬性 |
| **風險** | idempotent |
| **主要環境** | Cowork |
| **實作** | `internal/content/` |

**參數**：
- `content_id` — **required**
- `title`, `body`, `content_type`, `tags`, `project` — 只更新提供的欄位

---

### 17. `publish_content`

| 屬性 | 值 |
|------|-----|
| **一句話** | 發布內容（status → published，不可逆） |
| **風險** | **destructive** |
| **主要環境** | Cowork（需 user 確認） |
| **實作** | `internal/content/` |

**參數**：
- `content_id` — **required**

**備註**：Always confirm with user before calling。和 create/update 分開是「one tool, one risk level」原則的體現。

---

### 18. `list_content_queue`

| 屬性 | 值 |
|------|-----|
| **一句話** | 查看內容佇列：drafts、review、published、scheduled |
| **風險** | readOnly |
| **主要環境** | Cowork |
| **實作** | `internal/content/` |

**參數**：
- `view` — queue（default，draft + review）\| calendar（published 7d + scheduled）\| recent（published）
- `content_type`, `status`, `limit` — optional filters

---

### 19. `get_decision_log`

| 屬性 | 值 |
|------|-----|
| **一句話** | 拉取所有 decision-log 類型的 Obsidian notes（不需要 search query） |
| **風險** | readOnly |
| **主要環境** | Claude Code（架構決策前） |
| **實作** | `internal/note/`（37 行） |

**參數**：
- `project` — optional filter
- `limit` — default 20

**為什麼不能用 search_knowledge 取代**：
- `search_knowledge` 必須提供 query（空 query 報錯）
- `search_knowledge` 不能按 Obsidian note type 過濾
- `get_decision_log` 返回全部 decision-log，不需要搜尋詞

**觸發情境**：「上次為什麼選 X？」「之前有沒有類似的設計決策？」

---

### 20. `bookmark_rss_item`

| 屬性 | 值 |
|------|-----|
| **一句話** | 把 RSS collected item 轉成 bookmark content record（atomic 6-step operation） |
| **風險** | additive |
| **主要環境** | Cowork |
| **實作** | `internal/mcp/system_tools.go`（70 行） |

**參數**：
- `collected_id` — **required**
- `notes` — 個人評語
- `tags` — 額外 tags

**它做什麼（6 步）**：
1. 取得 collected item 資料
2. 驗證 item 未被 curated
3. 建立 bookmark content（auto-copy topics → tags, embed original content）
4. 設定 ReviewLevel = ReviewLight
5. 建立 content record
6. 更新 collected item status → curated，設定 curated_content_id FK

**為什麼不能用 `create_content` 取代**：`create_content` 只做第 5 步。其他 5 步（metadata 複製、FK linking、status 更新）都是 `bookmark_rss_item` 獨有的。

---

### 21-23. O'Reilly 三件組

#### 21. `search_oreilly_content`

| 屬性 | 值 |
|------|-----|
| **一句話** | 搜尋 O'Reilly Learning 的書/影片/課程 |
| **風險** | readOnly |
| **主要環境** | Learning |

**參數**：`query`（required）, `formats`（book/video/article/course）, `publishers`, `authors`, `limit`

#### 22. `get_oreilly_book_detail`

| 屬性 | 值 |
|------|-----|
| **一句話** | 取得書的章節目錄和結構 |
| **風險** | readOnly |
| **主要環境** | Learning |

**參數**：`archive_id`（required，from search results）

#### 23. `read_oreilly_chapter`

| 屬性 | 值 |
|------|-----|
| **一句話** | 讀取完整章節內容（plain text） |
| **風險** | readOnly |
| **主要環境** | Learning |

**參數**：`archive_id`（required）, `filename`（required，from book detail chapters list）

**三件組 pipeline**：search → detail（看目錄）→ read（讀章節）。Progressive disclosure 設計。

---

### 24. `get_rss_highlights`

| 屬性 | 值 |
|------|-----|
| **一句話** | 最近收集的 RSS 精選文章 |
| **風險** | readOnly |
| **主要環境** | Cowork（content pipeline 起點）、HQ |
| **實作** | `internal/collected/` |

**參數**：
- `days` — lookback（default 7）
- `limit` — default 20
- `sort_by` — relevance \| recent

---

## Domain 3: Development & Learning (8 tools)

開發記錄、學習記錄、專案管理、學習分析。

### 25. `log_dev_session`

| 屬性 | 值 |
|------|-----|
| **一句話** | 記錄 coding session 為 build-log（含跨環境 context bridge） |
| **風險** | additive |
| **主要環境** | Claude Code（top 1 tool） |
| **實作** | `internal/content/` |

**參數**：
- `project` — **required**
- `session_type` — **required**：feature \| refactor \| bugfix \| research \| infra
- `title` — **required**
- `body` — **required**（markdown）
- `tags` — string array
- `plan_summary` — 從 .claude/plans/ 摘要（**context bridge to HQ**）
- `review_summary` — reviewer findings 摘要（**context bridge to HQ**）
- `tier` — tier-1 \| tier-2 \| tier-3
- `diff_stats` — e.g., "+120 -30"

**觸發情境**：coding session 結束時，或 development-lifecycle auto-commit 後。

**備註**：`plan_summary` 和 `review_summary` 是跨環境 context bridge 的關鍵 — HQ 不需要看 git diff，只需要讀摘要就能在 weekly review 理解開發進度。

---

### 26. `log_learning_session`

| 屬性 | 值 |
|------|-----|
| **一句話** | 記錄學習成果（LeetCode / book / course），含 canonical tag validation |
| **風險** | additive |
| **主要環境** | Learning |
| **實作** | `internal/content/` |

**參數**：
- `project` — **required**（e.g., "leetcode"）
- `source` — **required**：leetcode \| book \| course \| discussion \| practice \| video
- `title` — **required**
- `body` — **required**（markdown）
- `topic` — **required**（主題標籤）
- `tags` — **controlled vocabulary**：
  - Topic tags：array, string, hash-table, two-pointers, sliding-window, binary-search, stack, queue, linked-list, tree, binary-tree, bst, graph, bfs, dfs, heap, trie, union-find, dp, greedy, backtracking, bit-manipulation, math, matrix, interval, topological-sort, sorting, design, simulation, prefix-sum, divide-and-conquer, segment-tree, binary-indexed-tree
  - Result：ac-independent \| ac-with-hints \| ac-after-solution \| incomplete
  - Weakness/Improvement：`weakness:xxx`, `improvement:xxx`
- `difficulty` — easy \| medium \| hard
- `problem_url` — e.g., LeetCode URL

**備註**：Canonical tag validation 是 Learning Analytics（coverage_matrix, tag_summary, weakness_trend）的基礎。Free-text tags 會讓分析查詢碎片化。

---

### 27. `get_project_context`

| 屬性 | 值 |
|------|-----|
| **一句話** | 單一 project 的完整 context（details + activity + notes） |
| **風險** | readOnly |
| **主要環境** | Claude Code（Tier 3 feature 前） |
| **實作** | `internal/project/` |

**參數**：
- `project` — **required**（slug/alias/title）

---

### 28. `list_projects`

| 屬性 | 值 |
|------|-----|
| **一句話** | 列出所有 active projects 概覽 |
| **風險** | readOnly |
| **主要環境** | HQ、Cowork |
| **實作** | `internal/project/` |

**參數**：`limit`

---

### 29. `update_project_status`

| 屬性 | 值 |
|------|-----|
| **一句話** | 更新 project status + optional review notes |
| **風險** | idempotent |
| **主要環境** | HQ（weekly review） |
| **實作** | `internal/project/` |

**參數**：
- `project` — **required**（slug/alias/title）
- `status` — **required**
- `review_notes` — optional
- `expected_cadence` — optional（e.g., "daily", "weekly"）

---

### 30-32. Learning Analytics 三件組

#### 30. `get_coverage_matrix`

| 屬性 | 值 |
|------|-----|
| **一句話** | Topic × Result 矩陣：哪些練了、成績如何 |
| **風險** | readOnly |
| **主要環境** | Learning（Adaptive Coaching 核心） |

**參數**：`project`（required）, `days`（lookback）

**返回**：per-topic count, last practice date, result distribution（ac-independent / ac-with-hints / ac-after-solution / incomplete）

#### 31. `get_tag_summary`

| 屬性 | 值 |
|------|-----|
| **一句話** | Tag 頻率統計，支援 prefix filter |
| **風險** | readOnly |
| **主要環境** | Learning |

**參數**：`project`（required）, `tag_prefix`（e.g., "weakness:"）, `days`

**常用**：`get_tag_summary(project="leetcode", tag_prefix="weakness:")` → 所有 weakness tags 的出現次數

#### 32. `get_weakness_trend`

| 屬性 | 值 |
|------|-----|
| **一句話** | 單一 weakness tag 的時間序列 + trend（improving / stable / declining） |
| **風險** | readOnly |
| **主要環境** | Learning |

**參數**：`project`（required）, `tag`（required, e.g., "weakness:pattern-recognition"）, `days`（default 60）

**三件組使用流程**：`get_tag_summary` 找出高頻 weakness → `get_weakness_trend` 看趨勢 → `get_coverage_matrix` 看整體分佈 → 決定今天練什麼。

---

## Domain 4: System & Infrastructure (13 tools)

系統監控、RSS feed 管理、目標追蹤、insight lifecycle、週報。

### 33. `get_system_status`

| 屬性 | 值 |
|------|-----|
| **一句話** | 系統 observability：flow runs、feed health、pipeline summaries |
| **風險** | readOnly |
| **主要環境** | Cowork |
| **實作** | `internal/flowrun/` + `internal/flow/` |

**參數**：
- `scope` — summary（default）\| pipelines（per-flow aggregation）\| flows（recent individual runs）
- `hours` — lookback（default 24）
- `flow_name` — filter specific flow
- `status` — filter by run status

---

### 34. `get_collection_stats`

| 屬性 | 值 |
|------|-----|
| **一句話** | RSS 收集品質統計：per-feed item counts、avg relevance scores |
| **風險** | readOnly |
| **主要環境** | Cowork |
| **實作** | `internal/collected/`（raw SQL） |

**參數**：
- `feed_id` — optional（single feed filter）
- `days` — lookback（default 30，max 90）

**返回**：per-feed（total_items, avg_score, last_collected_at）+ global（total_items, total_feeds, avg_score, unread_count, curated_count）

**和 `get_system_status` 的差異**：
- `get_system_status` = infra layer（jobs 有沒有正常跑？）→ 查 `flow_runs` table
- `get_collection_stats` = data quality layer（收了什麼？品質如何？）→ 查 `collected_data` table

---

### 35. `get_weekly_summary`

| 屬性 | 值 |
|------|-----|
| **一句話** | 週報：per-project completions、metrics trends、project health、goal alignment |
| **風險** | readOnly |
| **主要環境** | HQ（weekly review） |
| **實作** | `internal/session/` 或 `internal/stats/` |

**參數**：
- `weeks_back` — 0（this week，default）\| 1（last week）
- `compare_previous` — bool（include previous week + delta）

---

### 36. `get_goal_progress`

| 屬性 | 值 |
|------|-----|
| **一句話** | 目標進度：per-goal on_track status、related projects、task completion rate |
| **風險** | readOnly |
| **主要環境** | HQ（weekly review） |
| **實作** | `internal/goal/` |

**參數**：
- `area` — filter by area（e.g., "Career", "Learning"）
- `status` — filter by goal status
- `days` — task lookback（default 30）
- `include_drift` — bool（**新增：原 `get_platform_stats` 的 drift analysis 搬到這裡**）

**備註**：`include_drift=true` 提供 per-area goal-to-activity drift%，原本是 `get_platform_stats` 的獨有功能。

---

### 37. `update_goal_status`

| 屬性 | 值 |
|------|-----|
| **一句話** | 更新目標狀態 |
| **風險** | idempotent |
| **主要環境** | HQ |

**參數**：
- `goal_title` — **required**
- `status` — **required**：not-started（Dream）\| in-progress（Active）\| done（Achieved）\| abandoned

---

### 38. `update_insight`

| 屬性 | 值 |
|------|-----|
| **一句話** | 更新 insight 狀態或追加證據 |
| **風險** | idempotent |
| **主要環境** | HQ（evening reflection） |
| **實作** | `internal/session/` 或 `internal/note/` |

**參數**：
- `insight_id` — **required**（integer）
- `status` — verified \| invalidated \| archived
- `append_evidence` — 追加支持證據
- `append_counter_evidence` — 追加反駁證據
- `conclusion` — 結論

**觸發情境**：Evening reflection 時，今天的資料支持或反駁某個假說。

---

### 39. `get_learning_progress` ⚠️

| 屬性 | 值 |
|------|-----|
| **一句話** | 學習指標：note growth trends、weekly activity comparison、top tags |
| **風險** | readOnly |
| **主要環境** | Learning、HQ |
| **實作** | `internal/stats/`（handler 25 行 + store 111 行 = 136 行） |
| **狀態** | ⚠️ 有 P1 bug（只計 Obsidian notes，未 aggregate TIL）。修復後收兩週 telemetry |

**返回**：
- `notes`：total, last_week, last_month, by_type（e.g., `{"leetcode": 45, "book": 12}`）
- `activity`：this_week vs last_week + trend（up/down/stable）
- `top_tags`：top 10 tags by frequency

**獨有資料**：`by_type` 分佈和 `top_tags` 在其他 tool 拿不到。

**待修 P1 bug**：目前只查 `obsidian_notes` table，未 aggregate `contents` table 的 TIL entries。導致資料不完整，使用頻率 telemetry 可能被 bug 壓低。

---

### 40. `get_recent_activity`

| 屬性 | 值 |
|------|-----|
| **一句話** | 近期開發活動事件（GitHub commits、PRs、Obsidian syncs、Notion changes） |
| **風險** | readOnly |
| **主要環境** | HQ |
| **實作** | `internal/activity/` |

**參數**：
- `source` — github \| obsidian \| notion
- `project` — slug/alias/title
- `days` — lookback

**和 `get_morning_context` 的差異**：morning_context 包含 activity 但不能按 source 過濾。`get_recent_activity` 提供 surgical query：「只看 GitHub activity for koopa0.dev in the last 3 days」。

---

### 41-44. Feed 管理

#### 41. `add_feed`

| 屬性 | 值 |
|------|-----|
| **一句話** | 新增 RSS/Atom feed 訂閱 |
| **風險** | additive |

**參數**：`url`（required）, `name`（required）, `schedule`（daily/weekly）, `topics`

#### 42. `update_feed`

| 屬性 | 值 |
|------|-----|
| **一句話** | 更新 feed 屬性（啟用/停用） |
| **風險** | idempotent |

**參數**：`feed_id`（required）, `enabled`（bool）

**備註**：合併了原本的 `disable_feed` + `enable_feed`。純 boolean toggle，不是 multiplexer pattern。

#### 43. `remove_feed`

| 屬性 | 值 |
|------|-----|
| **一句話** | 永久刪除 feed 訂閱（不可逆） |
| **風險** | **destructive** |

**參數**：`feed_id`（required）

#### 44. `list_feeds`

| 屬性 | 值 |
|------|-----|
| **一句話** | 列出所有 RSS feed 訂閱 |
| **風險** | readOnly |

**參數**：無

---

### 45. `trigger_pipeline`

| 屬性 | 值 |
|------|-----|
| **一句話** | 手動觸發背景 pipeline（rss_collector / notion_sync） |
| **風險** | **destructive**（non-cancellable side effect） |
| **主要環境** | Cowork、Claude Code |
| **實作** | `internal/pipeline/` |

**參數**：
- `pipeline` — **required**：rss_collector \| notion_sync

**Rate limit**：每 pipeline 每 5 分鐘一次。

**觸發情境**：
- 剛加了新 feed，想立刻收
- Deploy 了新的 scoring logic，想立刻測
- Debug collection issues

---

## Audit Decision Log

### 已移除

| Tool | 移除原因 | 替代方案 |
|------|----------|----------|
| `get_platform_stats` | 和 weekly_summary + system_status + learning_progress 三重重疊。10 類 count 統計無獨立價值 | Drift analysis → `get_goal_progress(include_drift=true)`。其他 counts 各自的 domain tool 已覆蓋 |
| `disable_feed` | 和 `enable_feed` 完全相同程式碼，只差 boolean 值 | → `update_feed(feed_id, enabled: bool)` |
| `enable_feed` | 同上 | 同上 |
| `search_notes`（更早移除） | 80% 場景被 `search_knowledge` 覆蓋 | `search_knowledge(content_type="obsidian-note")` |
| `generate_social_excerpt`（更早移除） | 已 deprecated | 直接讓 LLM consumer 生成 |
| `get_pending_tasks`（更早移除） | 被更 flexible 的 search 取代 | `search_tasks(status="pending")` |

### 確定保留（調查後消除疑慮）

| Tool | 調查結果 | 保留理由 |
|------|----------|----------|
| `bookmark_rss_item` | 6-step atomic operation | `create_content` 只能做 1/6 步 |
| `get_decision_log` | search_knowledge 不支援空 query 和 note type filter | 37 行 code，成本極低 |
| `get_session_delta` | 和 morning_context 底層共用 helper 但語意不同 | 追蹤 task flow（新建/overdue）是 morning 沒有的維度 |
| `get_collection_stats` | 和 system_status 不同層（data quality vs infra health） | 查不同 table，回答不同問題 |
| `synthesize_topic` | 不使用 LLM，純 DB aggregation | 不違反 AI-calls-AI principle |

### 待觀察（附帶行動）

| Tool | 行動 | Review date |
|------|------|-------------|
| `synthesize_topic` | 等 telemetry | 2026-04-09 |
| `get_learning_progress` | 先修 P1 bug（aggregate TIL），修完後收兩週乾淨 telemetry | 修 bug → 收 telemetry → 2026-04-09 review |

---

## Risk Level Quick Reference

### Destructive（確認後才呼叫）
`publish_content`, `remove_feed`, `trigger_pipeline`, `complete_task`（recurring due date 推進）

### Idempotent（安全重複呼叫）
`update_task`, `update_content`, `batch_my_day`, `update_feed`, `update_goal_status`, `update_project_status`, `update_insight`

### Additive（建立新記錄）
`create_task`, `save_session_note`, `log_dev_session`, `log_learning_session`, `create_content`, `add_feed`, `bookmark_rss_item`

### Read-Only（無副作用）
其餘 24 個 tools
