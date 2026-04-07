# MCP Tools Reference (v2)

> koopa0-knowledge MCP server — 22 workflow-driven tools
> Last updated: 2026-04-07

## 概覽

MCP v2 將 49 個 v1 CRUD tools 重寫為 22 個 workflow-driven tools。
工具按工作流組織，不按 entity CRUD。

**Transport:**
- `stdio` — Claude Code 本地使用
- `http` — Claude Desktop Cowork / 遠端連線（Streamable HTTP + OAuth）

---

## Tool Inventory

### Query Tools（6 tools, readOnly）

| Tool | 用途 | 何時使用 |
|------|------|----------|
| `morning_context` | 每日計劃：逾期任務、今日任務、承諾計劃項目、近期計劃歷史 | 使用者開始新的一天 |
| `reflection_context` | 晚間回顧：計劃 vs 實際完成、日記條目 | 使用者想回顧今天 |
| `search_knowledge` | 跨類型搜尋：articles, build logs, TILs, notes | 使用者搜尋過去的知識 |
| `goal_progress` | 活躍目標 + 里程碑進度、area、quarter、deadline | 目標檢視、週計劃 |
| `learning_dashboard` | 學習分析 — 6 個 views（見下方） | 使用者查看學習狀態 |
| `system_status` | 系統健康：pipeline stats, feed health, flow runs | 使用者問「系統還好嗎？」 |

### Capture & Structuring Tools（3 tools）

| Tool | 用途 | Annotation |
|------|------|------------|
| `capture_inbox` | 快速任務捕獲到 inbox（只需 title） | additive |
| `propose_commitment` | 提議建立 goal/project/milestone/directive/insight — **不寫入 DB**，回傳 token | readOnly |
| `commit_proposal` | 用 token 提交提議，寫入 DB | additive |

### Execution Tools（4 tools）

| Tool | 用途 | Annotation |
|------|------|------------|
| `advance_work` | 任務狀態轉換：clarify (inbox→todo), start, complete, defer | destructive |
| `plan_day` | 設定每日計劃項目（冪等：重新計劃會替換） | additiveIdempotent |
| `file_report` | 建立報告，可連結 directive | additive |
| `acknowledge_directive` | 標記 directive 已收到 | additiveIdempotent |

### Learning Tools（3 tools）

| Tool | 用途 | Annotation |
|------|------|------------|
| `start_session` | 開始學習 session（domain + mode） | additive |
| `record_attempt` | 記錄嘗試（接受語義 outcome: "got it", "needed help", "gave up"） | additive |
| `end_session` | 結束 session，可附帶 reflection journal | additive |

### Reflection Tools（2 tools）

| Tool | 用途 | Annotation |
|------|------|------------|
| `write_journal` | 日記：plan, context, reflection, metrics | additive |
| `track_insight` | 更新 insight：verify, invalidate, archive, add_evidence | additiveIdempotent |

### Content & Feed Tools（2 tools）

| Tool | 用途 | Annotation |
|------|------|------------|
| `manage_content` | 內容生命週期：create, update, publish | additive |
| `manage_feeds` | RSS feed 管理：list, add, update, remove（conditional） | additive |

### Cross-session Tools（2 tools, readOnly）

| Tool | 用途 | 何時使用 |
|------|------|----------|
| `session_delta` | 上次 session 之後發生了什麼：任務、日記、學習 session | session 開始時銜接上下文 |
| `weekly_summary` | 週回顧：完成任務、日記、learning sessions、concept mastery | 週末回顧 |

---

## learning_dashboard Views

`learning_dashboard` 透過 `view` 參數支援 6 種分析視圖：

| View | 資料 | 用途 |
|------|------|------|
| `overview`（預設） | 近期 sessions 列表 | 快速查看學習活動 |
| `mastery` | 每 concept 的 weakness/improvement/mastery 信號計數 | 了解哪些概念已掌握 |
| `weaknesses` | 跨 pattern 弱點分析（category + severity） | 找出需要加強的領域 |
| `retrieval` | 到期的 spaced review items（FSRS） | 決定今天要複習什麼 |
| `timeline` | sessions + attempt 統計，按日分組 | 看學習趨勢 |
| `variations` | problem 關係圖（easier/harder variants, prerequisites） | 探索相關題目 |

共通參數：`domain`（過濾）、`days`（回溯天數，預設 30）

---

## Proposal/Commit Flow

高風險 entity（goal, project, milestone, directive, insight）採用兩步驟建立：

```
1. propose_commitment(type, fields)
   → 回傳 preview + warnings + proposal_token
   → 不寫 DB

2. 使用者確認後：
   commit_proposal(proposal_token)
   → 寫入 DB
   → 回傳 entity ID
```

Token 有效期 10 分鐘，HMAC-SHA256 簽名防篡改。

---

## Outcome Semantic Mapping

`record_attempt` 接受自然語言 outcome，自動映射為 schema enum：

| 語義輸入 | practice/retrieval mode | reading mode |
|----------|------------------------|--------------|
| "got it", "solved it" | solved_independent | completed |
| "needed help" | solved_with_hint | completed_with_support |
| "saw answer" | solved_after_solution | — |
| "didn't finish" | incomplete | incomplete |
| "gave up", "stuck" | gave_up | gave_up |

也接受 raw enum 值（`solved_independent` 等）。

---

## Participant Resolution — Caller Self-Identification

每個 tool call 都可以帶 `as` 欄位宣告 caller identity：
```json
{ "as": "hq", "title": "審查 PR #123", ... }
```

- Server 信任 `as`（MCP trust model），用 capability flags 驗證權限
- 沒有 `as` 時，fallback 到 `KOOPA_MCP_PARTICIPANT` env（default: `"human"`）
- 每個 Cowork project 的 instructions 指定：`在所有 tool call 中傳入 as: "hq"`

完整 trust model 說明見 `docs/MCP-ARCHITECTURE.md` §4。

---

## 決策原則

完整決策原則見 `.claude/rules/mcp-decision-policy.md`，重點：

- **Intent-first**：AI 評估使用者意圖信號，不做場景分類
- **Semantic maturity**：M0 (vague) → M1 (forming) → M2 (structured) → M3 (actionable)
- **Capture pollution prevention**：inbox 只放具體工作捕獲，不放想法或感覺
- **No auto-carryover**：morning_context 呈現未完成項目但不自動延遲
